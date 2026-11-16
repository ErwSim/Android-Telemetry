// Vue « pistage » factice (contrat §9) : construite à partir des `net.dns` et `net.usage` générés, avec une
// politique de blocage déterministe (niveau + règles manuelles) évaluée à l'instant de chaque requête, pour
// que les décomptes restent cohérents quand on change le niveau ou une règle (domaines « mixtes »).
import type { MockEvent } from './gen.ts';
import { ALL_APPS } from './catalog.ts';

export type Level = 'permissif' | 'equilibre' | 'strict';
const RANK: Record<Level, number> = { permissif: 0, equilibre: 1, strict: 2 };
export const LEVELS: { key: Level; name: string; description: string }[] = [
  { key: 'permissif', name: 'Permissif', description: 'Bloque la publicité, les traqueurs publicitaires et les domaines malveillants connus. Laisse passer la télémétrie système de Google et de Samsung.' },
  { key: 'equilibre', name: 'Équilibré', description: 'Ajoute la télémétrie et la mesure d’audience de Google, de Samsung et de Meta. Conserve les notifications push (FCM), le test de connectivité et les mises à jour.' },
  { key: 'strict', name: 'Strict', description: 'Bloque aussi les services d’arrière-plan facultatifs (profilage Samsung, Graph de Meta, optimisation de jeux). Peut désactiver des fonctions : à essayer quelques jours.' },
];

interface Publisher {
  key: string;
  name: string;
  suffixes: string[];
}
const PUBLISHERS: Publisher[] = [
  { key: 'ads', name: 'Publicité et mesure d’audience', suffixes: ['doubleclick.net', 'googlesyndication.com', 'googletagmanager.com', 'google-analytics.com', 'sdkmetrics.cc', 'unknown-cdn.biz', 'fastcleaner-cdn.top', 'samsungads.com'] },
  { key: 'google', name: 'Google', suffixes: ['google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'googlevideo.com', 'ytimg.com', 'ggpht.com', 'youtube.com', 'app-measurement.com', 'gvt1.com'] },
  { key: 'samsung', name: 'Samsung', suffixes: ['samsung.com', 'samsungcloud.com', 'samsungapps.com', 'samsungdm.com', 'samsungosp.com', 'ospserver.net', 'gos-gsp.io'] },
  { key: 'meta', name: 'Meta', suffixes: ['facebook.com', 'facebook.net', 'fbcdn.net', 'instagram.com', 'cdninstagram.com', 'whatsapp.net', 'whatsapp.com'] },
  { key: 'microsoft', name: 'Microsoft', suffixes: ['microsoft.com', 'live.com', 'office.com', 'msftconnecttest.com'] },
  { key: 'amazon', name: 'Amazon', suffixes: ['amazon.com', 'amazonaws.com', 'amazon.fr'] },
  { key: 'tiktok', name: 'TikTok / ByteDance', suffixes: ['tiktok.com', 'tiktokv.com', 'byteoversea.com', 'bytedance.com'] },
];
const OTHER = { key: 'other', name: 'Autres', suffixes: [] as string[] };

const matches = (host: string, s: string) => host === s || host.endsWith(`.${s}`);
export function publisherOf(host: string): string {
  const h = host.toLowerCase();
  for (const p of PUBLISHERS) if (p.suffixes.some((s) => matches(h, s))) return p.key;
  return OTHER.key;
}
const PUB_NAME = new Map([...PUBLISHERS, OTHER].map((p) => [p.key, p.name]));

/** Règles de liste : niveau minimal qui bloque le domaine, et nom de la liste. */
interface Rule {
  min: Level;
  list: string;
}
const EXACT_RULES: Record<string, Rule> = {
  'cfg.fastcleaner-cdn.top': { min: 'permissif', list: 'Vigie : domaines suspects' },
  'cfg.wallpapers-hd.xyz': { min: 'permissif', list: 'Vigie : domaines suspects' },
  'sms-relay.cheap-gw.top': { min: 'permissif', list: 'Vigie : domaines suspects' },
  'api.smsbomber-gw.cc': { min: 'permissif', list: 'Vigie : domaines suspects' },
  'ads.unknown-cdn.biz': { min: 'permissif', list: 'Vigie : domaines suspects' },
  'track.sdkmetrics.cc': { min: 'permissif', list: 'Vigie : domaines suspects' },
  'app-measurement.com': { min: 'equilibre', list: 'Vigie : télémétrie Google' },
  'ogs.google.com': { min: 'strict', list: 'Vigie : télémétrie Google' },
  'assistant.google.com': { min: 'strict', list: 'Vigie : services Google facultatifs' },
  'diagmon-eu.samsungdm.com': { min: 'equilibre', list: 'Vigie : télémétrie Samsung' },
  'dc.diagmon.samsung.com': { min: 'equilibre', list: 'Vigie : télémétrie Samsung' },
  'config.samsungads.com': { min: 'equilibre', list: 'Vigie : télémétrie Samsung' },
  'rubin-eu.samsungapps.com': { min: 'equilibre', list: 'Vigie : télémétrie Samsung' },
  'gos-api.gos-gsp.io': { min: 'strict', list: 'Vigie : télémétrie Samsung' },
  'vas.samsungapps.com': { min: 'strict', list: 'Vigie : télémétrie Samsung' },
  'eu-ie-contact.samsungcloud.com': { min: 'strict', list: 'Vigie : télémétrie Samsung' },
  'connect.facebook.net': { min: 'equilibre', list: 'Vigie : pistage Meta' },
  'crashlogs.whatsapp.net': { min: 'equilibre', list: 'Vigie : pistage Meta' },
  'graph.facebook.com': { min: 'strict', list: 'Vigie : pistage Meta' },
};
function ruleOf(host: string): Rule | undefined {
  const r = EXACT_RULES[host];
  if (r) return r;
  if (publisherOf(host) === 'ads') return { min: 'permissif', list: 'AdGuard DNS filter' };
  return undefined;
}

/** Domaines indispensables : les bloquer exige `force`. */
export const ESSENTIAL: Record<string, string[]> = {
  'mtalk.google.com': ['Les notifications push (Firebase Cloud Messaging) n’arriveront plus, ou avec un grand retard : messageries, courriel, alertes bancaires.'],
  'fcm.googleapis.com': ['Les notifications push (Firebase Cloud Messaging) n’arriveront plus, ou avec un grand retard.'],
  'connectivitycheck.gstatic.com': ['Le test de connectivité d’Android échouera : le Wi-Fi sera signalé « sans Internet » et le téléphone pourra basculer sur les données mobiles.'],
  'update.googleapis.com': ['Les mises à jour de Google Play Services et du système ne seront plus proposées.'],
};

export interface Override {
  t: number;
  domain: string;
  action: 'block' | 'allow' | 'default';
}
export interface TrackState {
  adguard: boolean;
  /** AdGuard injoignable mais agrégats déjà stockés servis (contrat §9, précisions) */
  stored: boolean;
  levelChanges: { t: number; level: Level }[];
  overrides: Override[];
}

export function initialTrackState(now: number): TrackState {
  const t0 = now - 8 * 86_400_000;
  return {
    adguard: process.env['MOCK_ADGUARD'] !== '0',
    stored: false,
    // Niveau permissif jusqu'à J-2, puis équilibré : la télémétrie Samsung apparaît « mixte » sur 7 jours.
    levelChanges: [
      { t: t0, level: 'permissif' },
      { t: now - 2 * 86_400_000 - 3 * 3_600_000, level: 'equilibre' },
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
  if (o === 'block') return { blocked: true, reason: `FilteredBlackList: ||${domain}^ (règle manuelle Vigie)` };
  if (o === 'allow') return { blocked: false, reason: `NotFilteredWhiteList: @@||${domain}^ (règle manuelle Vigie)` };
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
  const appPub = new Map<string, Map<string, number>>(); // app -> éditeur -> requêtes
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
  // Octets d'une application répartis entre éditeurs au prorata de ses requêtes (indicatif).
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
