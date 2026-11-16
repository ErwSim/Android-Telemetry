// Mock "tracking" view (contract §9): built from the generated `net.dns` and `net.usage`, with a
// deterministic blocking policy (level + manual rules) evaluated at the instant of each query, so
// that the counts stay consistent when the level or a rule is changed ("mixed" domains).
import type { MockEvent } from './gen.ts';
import { ALL_APPS } from './catalog.ts';

export type Level = 'permissive' | 'balanced' | 'strict';
const RANK: Record<Level, number> = { permissive: 0, balanced: 1, strict: 2 };
export const LEVELS: { key: Level; name: string; description: string }[] = [
  { key: 'permissive', name: 'Permissive', description: 'Blocks advertising, ad trackers and known malicious domains. Lets Google and Samsung system telemetry through.' },
  { key: 'balanced', name: 'Balanced', description: 'Adds Google, Samsung and Meta telemetry and audience measurement. Keeps push notifications (FCM), the connectivity check and updates.' },
  { key: 'strict', name: 'Strict', description: 'Also blocks optional background services (Samsung profiling, Meta Graph, game optimisation). May disable features: try it for a few days.' },
];

interface Publisher {
  key: string;
  name: string;
  suffixes: string[];
}
const PUBLISHERS: Publisher[] = [
  { key: 'ads', name: 'Advertising and audience measurement', suffixes: ['doubleclick.net', 'googlesyndication.com', 'googletagmanager.com', 'google-analytics.com', 'sdkmetrics.cc', 'unknown-cdn.biz', 'fastcleaner-cdn.top', 'samsungads.com'] },
  { key: 'google', name: 'Google', suffixes: ['google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'googlevideo.com', 'ytimg.com', 'ggpht.com', 'youtube.com', 'app-measurement.com', 'gvt1.com'] },
  { key: 'samsung', name: 'Samsung', suffixes: ['samsung.com', 'samsungcloud.com', 'samsungapps.com', 'samsungdm.com', 'samsungosp.com', 'ospserver.net', 'gos-gsp.io'] },
  { key: 'meta', name: 'Meta', suffixes: ['facebook.com', 'facebook.net', 'fbcdn.net', 'instagram.com', 'cdninstagram.com', 'whatsapp.net', 'whatsapp.com'] },
  { key: 'microsoft', name: 'Microsoft', suffixes: ['microsoft.com', 'live.com', 'office.com', 'msftconnecttest.com'] },
  { key: 'amazon', name: 'Amazon', suffixes: ['amazon.com', 'amazonaws.com', 'amazon.co.uk'] },
  { key: 'tiktok', name: 'TikTok / ByteDance', suffixes: ['tiktok.com', 'tiktokv.com', 'byteoversea.com', 'bytedance.com'] },
];
const OTHER = { key: 'other', name: 'Others', suffixes: [] as string[] };

const matches = (host: string, s: string) => host === s || host.endsWith(`.${s}`);
export function publisherOf(host: string): string {
  const h = host.toLowerCase();
  for (const p of PUBLISHERS) if (p.suffixes.some((s) => matches(h, s))) return p.key;
  return OTHER.key;
}
const PUB_NAME = new Map([...PUBLISHERS, OTHER].map((p) => [p.key, p.name]));

/** List rules: minimum level that blocks the domain, and the list name. */
interface Rule {
  min: Level;
  list: string;
}
const EXACT_RULES: Record<string, Rule> = {
  'cfg.fastcleaner-cdn.top': { min: 'permissive', list: 'Watchpost: suspicious domains' },
  'cfg.wallpapers-hd.xyz': { min: 'permissive', list: 'Watchpost: suspicious domains' },
  'sms-relay.cheap-gw.top': { min: 'permissive', list: 'Watchpost: suspicious domains' },
  'api.smsbomber-gw.cc': { min: 'permissive', list: 'Watchpost: suspicious domains' },
  'ads.unknown-cdn.biz': { min: 'permissive', list: 'Watchpost: suspicious domains' },
  'track.sdkmetrics.cc': { min: 'permissive', list: 'Watchpost: suspicious domains' },
  'app-measurement.com': { min: 'balanced', list: 'Watchpost: Google telemetry' },
  'ogs.google.com': { min: 'strict', list: 'Watchpost: Google telemetry' },
  'assistant.google.com': { min: 'strict', list: 'Watchpost: optional Google services' },
  'diagmon-eu.samsungdm.com': { min: 'balanced', list: 'Watchpost: Samsung telemetry' },
  'dc.diagmon.samsung.com': { min: 'balanced', list: 'Watchpost: Samsung telemetry' },
  'config.samsungads.com': { min: 'balanced', list: 'Watchpost: Samsung telemetry' },
  'rubin-eu.samsungapps.com': { min: 'balanced', list: 'Watchpost: Samsung telemetry' },
  'gos-api.gos-gsp.io': { min: 'strict', list: 'Watchpost: Samsung telemetry' },
  'vas.samsungapps.com': { min: 'strict', list: 'Watchpost: Samsung telemetry' },
  'eu-ie-contact.samsungcloud.com': { min: 'strict', list: 'Watchpost: Samsung telemetry' },
  'connect.facebook.net': { min: 'balanced', list: 'Watchpost: Meta tracking' },
  'crashlogs.whatsapp.net': { min: 'balanced', list: 'Watchpost: Meta tracking' },
  'graph.facebook.com': { min: 'strict', list: 'Watchpost: Meta tracking' },
};
function ruleOf(host: string): Rule | undefined {
  const r = EXACT_RULES[host];
  if (r) return r;
  if (publisherOf(host) === 'ads') return { min: 'permissive', list: 'AdGuard DNS filter' };
  return undefined;
}

/** Essential domains: blocking them requires `force`. */
export const ESSENTIAL: Record<string, string[]> = {
  'mtalk.google.com': ['Push notifications (Firebase Cloud Messaging) will no longer arrive, or arrive very late: messaging apps, email, bank alerts.'],
  'fcm.googleapis.com': ['Push notifications (Firebase Cloud Messaging) will no longer arrive, or arrive very late.'],
  'connectivitycheck.gstatic.com': ['Android\'s connectivity check will fail: Wi-Fi will be flagged "no Internet" and the phone may switch to mobile data.'],
  'update.googleapis.com': ['Google Play services and system updates will no longer be offered.'],
};

export interface Override {
  t: number;
  domain: string;
  action: 'block' | 'allow' | 'default';
}
export interface TrackState {
  adguard: boolean;
  /** AdGuard unreachable but already stored aggregates served (contract §9, clarifications) */
  stored: boolean;
  levelChanges: { t: number; level: Level }[];
  overrides: Override[];
}

export function initialTrackState(now: number): TrackState {
  const t0 = now - 8 * 86_400_000;
  return {
    adguard: process.env['MOCK_ADGUARD'] !== '0',
    stored: false,
    // Permissive level until D-2, then balanced: Samsung telemetry shows up as "mixed" over 7 days.
    levelChanges: [
      { t: t0, level: 'permissive' },
      { t: now - 2 * 86_400_000 - 3 * 3_600_000, level: 'balanced' },
    ],
    overrides: [
      { t: t0, domain: 'graph.instagram.com', action: 'block' },
      { t: t0, domain: 'config.samsungads.com', action: 'allow' },
    ],
  };
}

const vis = (st: TrackState): boolean => st.adguard || st.stored;

export const currentLevel = (st: TrackState): Level => (st.levelChanges[st.levelChanges.length - 1] as { level: Level }).level;

function levelAt(st: TrackState, t: number): Level {
  let l = (st.levelChanges[0] as { level: Level }).level;
  for (const c of st.levelChanges) if (c.t <= t) l = c.level;
  return l;
}
function overrideAt(st: TrackState, domain: string, t: number): 'block' | 'allow' | undefined {
  let o: 'block' | 'allow' | undefined;
  for (const x of st.overrides) {
    if (x.domain !== domain || x.t > t) continue;
    o = x.action === 'default' ? undefined : x.action;
  }
  return o;
}

interface Decision {
  blocked: boolean;
  reason: string;
}
function decide(st: TrackState, domain: string, t: number): Decision {
  const o = overrideAt(st, domain, t);
  if (o === 'block') return { blocked: true, reason: `FilteredBlackList: ||${domain}^ (Watchpost manual rule)` };
  if (o === 'allow') return { blocked: false, reason: `NotFilteredWhiteList: @@||${domain}^ (Watchpost manual rule)` };
  const r = ruleOf(domain);
  if (r && RANK[levelAt(st, t)] >= RANK[r.min]) return { blocked: true, reason: `FilteredBlackList: ${r.list}` };
  return { blocked: false, reason: 'NotFilteredNotFound' };
}

interface DomAgg {
  domain: string;
  publisher: string;
  queries: number;
  blocked: number;
  allowed: number;
  reason: string;
  apps: Map<string, number>;
}

interface Range {
  from: number;
  to: number;
}

function aggregate(events: MockEvent[], st: TrackState, r: Range): Map<string, DomAgg> {
  const m = new Map<string, DomAgg>();
  for (const e of events) {
    if (e.type !== 'net.dns' || e.t < r.from || e.t > r.to) continue;
    const host = e.data['hostname'];
    if (typeof host !== 'string' || !host) continue;
    const pkg = typeof e.data['package'] === 'string' ? e.data['package'] : '?';
    const n = typeof e.data['count'] === 'number' && e.data['count'] >= 1 ? e.data['count'] : 1;
    let a = m.get(host);
    if (!a) {
      a = { domain: host, publisher: publisherOf(host), queries: 0, blocked: 0, allowed: 0, reason: '', apps: new Map() };
      m.set(host, a);
    }
    a.queries += n;
    if (vis(st)) {
      const d = decide(st, host, e.t);
      if (d.blocked) a.blocked += n;
      else a.allowed += n;
      a.reason = d.reason;
    }
    a.apps.set(pkg, (a.apps.get(pkg) ?? 0) + n);
  }
  return m;
}

const labelOf = { get: (pkg: string): string | undefined => ALL_APPS.find((a) => a.package === pkg)?.label };

function usageByApp(events: MockEvent[], r: Range): Map<string, { tx: number; rx: number }> {
  const m = new Map<string, { tx: number; rx: number }>();
  for (const e of events) {
    if (e.type !== 'net.usage' || e.t < r.from || e.t > r.to || !Array.isArray(e.data['apps'])) continue;
    for (const a of e.data['apps'] as Record<string, unknown>[]) {
      const pkg = String(a['package']);
      const cur = m.get(pkg) ?? { tx: 0, rx: 0 };
      cur.tx += Number(a['tx_bytes'] ?? 0);
      cur.rx += Number(a['rx_bytes'] ?? 0);
      m.set(pkg, cur);
    }
  }
  return m;
}

export function summary(events: MockEvent[], st: TrackState, r: Range) {
  const doms = aggregate(events, st, r);
  const usage = usageByApp(events, r);
  const pubs = new Map<string, { queries: number; blocked: number; allowed: number; domains: number; apps: Set<string>; tx: number; rx: number }>();
  const appPub = new Map<string, Map<string, number>>(); // app -> publisher -> queries
  for (const d of doms.values()) {
    let p = pubs.get(d.publisher);
    if (!p) {
      p = { queries: 0, blocked: 0, allowed: 0, domains: 0, apps: new Set(), tx: 0, rx: 0 };
      pubs.set(d.publisher, p);
    }
    p.queries += d.queries;
    p.blocked += d.blocked;
    p.allowed += d.allowed;
    p.domains++;
    for (const [pkg, n] of d.apps) {
      p.apps.add(pkg);
      const am = appPub.get(pkg) ?? new Map<string, number>();
      am.set(d.publisher, (am.get(d.publisher) ?? 0) + n);
      appPub.set(pkg, am);
    }
  }
  // An application's bytes split between publishers in proportion to its queries (indicative).
  for (const [pkg, am] of appPub) {
    const u = usage.get(pkg);
    if (!u) continue;
    const total = [...am.values()].reduce((a, b) => a + b, 0);
    for (const [pub, n] of am) {
      const p = pubs.get(pub);
      if (p) {
        p.tx += (u.tx * n) / total;
        p.rx += (u.rx * n) / total;
      }
    }
  }
  const publishers = [...pubs.entries()]
    .sort((a, b) => b[1].queries - a[1].queries)
    .map(([key, p]) => ({
      key,
      name: PUB_NAME.get(key) ?? key,
      queries: p.queries,
      ...(vis(st) ? { blocked: p.blocked, allowed: p.allowed } : {}),
      domains: p.domains,
      apps: p.apps.size,
      tx_bytes: Math.round(p.tx),
      rx_bytes: Math.round(p.rx),
    }));
  const q = publishers.reduce((a, p) => a + p.queries, 0);
  const b = publishers.reduce((a, p) => a + (p.blocked ?? 0), 0);
  return {
    adguard: st.adguard,
    ...(st.adguard ? { level: currentLevel(st) } : {}),
    levels: LEVELS,
    totals: vis(st) ? { queries: q, blocked: b, allowed: q - b } : { queries: q },
    publishers,
  };
}

export function domains(events: MockEvent[], st: TrackState, r: Range, f: { publisher?: string | null; status?: string | null; q?: string | null; limit: number; offset: number }) {
  const q = (f.q ?? '').trim().toLowerCase();
  let list = [...aggregate(events, st, r).values()];
  if (f.publisher) list = list.filter((d) => d.publisher === f.publisher);
  if (q) list = list.filter((d) => d.domain.includes(q));
  if (vis(st) && f.status === 'blocked') list = list.filter((d) => d.blocked > 0);
  if (vis(st) && f.status === 'allowed') list = list.filter((d) => d.allowed > 0);
  list.sort((a, b) => b.queries - a.queries || a.domain.localeCompare(b.domain));
  const page = list.slice(f.offset, f.offset + f.limit);
  const out = page.map((d) => {
    const ov = vis(st) ? overrideAt(st, d.domain, Date.now()) : undefined;
    return {
      domain: d.domain,
      publisher: d.publisher,
      queries: d.queries,
      ...(vis(st)
        ? { blocked: d.blocked, allowed: d.allowed, status: d.blocked === 0 ? 'allowed' : d.allowed === 0 ? 'blocked' : 'mixed', reason: d.reason, ...(ov ? { override: ov } : {}) }
        : {}),
      apps: [...d.apps.entries()].sort((a, b) => b[1] - a[1]).map(([pkg, count]) => ({ package: pkg, count })),
    };
  });
  const next = f.offset + f.limit < list.length ? `c${f.offset + f.limit}` : undefined;
  return next ? { domains: out, next_cursor: next } : { domains: out };
}

export function appsView(events: MockEvent[], st: TrackState, r: Range, publisher: string | null) {
  const usage = usageByApp(events, r);
  interface Counts {
    n: number;
    b: number;
    a: number;
  }
  const byApp = new Map<string, { total: Counts; per: Map<string, Counts> }>();
  for (const e of events) {
    if (e.type !== 'net.dns' || e.t < r.from || e.t > r.to) continue;
    const host = e.data['hostname'];
    if (typeof host !== 'string' || !host) continue;
    if (publisher && publisherOf(host) !== publisher) continue;
    const pkg = typeof e.data['package'] === 'string' ? e.data['package'] : '?';
    let a = byApp.get(pkg);
    if (!a) {
      a = { total: { n: 0, b: 0, a: 0 }, per: new Map() };
      byApp.set(pkg, a);
    }
    const n = typeof e.data['count'] === 'number' && e.data['count'] >= 1 ? e.data['count'] : 1;
    const dec = vis(st) ? decide(st, host, e.t) : undefined;
    const c = a.per.get(host) ?? { n: 0, b: 0, a: 0 };
    for (const x of [a.total, c]) {
      x.n += n;
      if (dec?.blocked) x.b += n;
      else if (dec) x.a += n;
    }
    a.per.set(host, c);
  }
  const apps = [...byApp.entries()]
    .sort((x, y) => y[1].total.n - x[1].total.n)
    .map(([pkg, a]) => {
      const u = usage.get(pkg);
      const label = labelOf.get(pkg);
      return {
        package: pkg,
        ...(label ? { label } : {}),
        queries: a.total.n,
        ...(vis(st) ? { blocked: a.total.b, allowed: a.total.a } : {}),
        ...(u ? { tx_bytes: u.tx, rx_bytes: u.rx } : {}),
        top_domains: [...a.per.entries()]
          .sort((x, y) => y[1].n - x[1].n)
          .slice(0, 6)
          .map(([domain, c]) => ({ domain, count: c.n, ...(vis(st) ? { status: c.b === 0 ? 'allowed' : c.a === 0 ? 'blocked' : 'mixed' } : {}) })),
      };
    });
  return { apps };
}
