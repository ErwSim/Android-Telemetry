// Serveur factice de l'API console (contrat §6). Lancé par `npm run mock`.
//   --port 8787        port d'écoute (défaut 8787, ou MOCK_PORT)
//   --static dist      sert aussi la console construite, avec une CSP stricte et le repli SPA
// Identifiants : admin / vigie (MOCK_USER, MOCK_PASSWORD).
// Contrôle de test : POST /__mock/control { wazuh?, expire?, fail?, latency_ms? }
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { DEVICE_MAIN, DEVICE_OLD, generate, liveEvent, type MockEvent } from './gen.ts';
import { makeRng } from './rng.ts';

const args = process.argv.slice(2);
const argVal = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const PORT = Number(argVal('--port') ?? process.env['MOCK_PORT'] ?? 8787);
const STATIC_DIR = argVal('--static') ?? process.env['MOCK_STATIC'];
const USER = process.env['MOCK_USER'] ?? 'admin';
const PASSWORD = process.env['MOCK_PASSWORD'] ?? 'vigie';
const COOKIE = 'vigie_session';
// CSP imposée par le vrai serveur : à ajuster ici si le build change (voir README).
const CSP =
  process.env['MOCK_CSP'] ??
  [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self' https://tile.openstreetmap.org",
    "worker-src 'self'",
    "font-src 'self'",
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');

const NOW = Date.now();
const gen = generate(NOW);
const events: MockEvent[] = gen.events;
const byId = new Map(events.map((e) => [e.id, e]));
const sessions = new Map<string, string>();
const control: { wazuh: boolean; fail: string[]; latency_ms: number } = {
  wazuh: process.env['MOCK_WAZUH'] !== '0',
  fail: [],
  latency_ms: 0,
};
const liveRng = makeRng(NOW % 99991);
const liveBoot = 'live' + String(NOW % 1000);
let seqCounter = (events[events.length - 1]?.seq ?? 18000) + 1;
const lastLoc = (() => {
  const l = [...events].reverse().find((e) => e.type === 'location.fix' && typeof e.data['lat'] === 'number' && typeof e.data['lon'] === 'number');
  return { lat: Number(l?.data['lat'] ?? 48.8603), lon: Number(l?.data['lon'] ?? 2.379) };
})();

// ---------------------------------------------------------------- utilitaires
type Res = http.ServerResponse;
function sendJson(res: Res, status: number, body: unknown): void {
  const s = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(s) });
  res.end(s);
}
const err = (res: Res, status: number, code: string, message: string) => sendJson(res, status, { error: code, message });

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c: Buffer) => {
      b += c.toString('utf8');
      if (b.length > 1e6) req.destroy();
    });
    req.on('end', () => resolve(b));
  });
}

function sessionUser(req: http.IncomingMessage): string | undefined {
  const raw = req.headers.cookie ?? '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === COOKIE) return sessions.get(v.join('='));
  }
  return undefined;
}

const toEvent = (e: MockEvent) => {
  const rest: Partial<MockEvent> = { ...e };
  delete rest.t;
  return rest;
};

function parseTime(v: string | null, dflt: number): number {
  if (!v) return dflt;
  const t = Date.parse(v);
  return Number.isNaN(t) ? dflt : t;
}

function deviceEvents(deviceId: string | null): MockEvent[] {
  if (deviceId && deviceId !== DEVICE_MAIN.device_id) return [];
  return events;
}

function matchQ(e: MockEvent, q: string): boolean {
  return e.type.includes(q) || JSON.stringify(e.data).toLowerCase().includes(q);
}

// ---------------------------------------------------------------- statistiques
const BUCKET_MS = { minute: 60_000, hour: 3_600_000, day: 86_400_000 } as const;

function timeline(u: URL) {
  const from = parseTime(u.searchParams.get('from'), NOW - 86_400_000);
  const to = parseTime(u.searchParams.get('to'), Date.now());
  const bucket = (u.searchParams.get('bucket') ?? 'hour') as keyof typeof BUCKET_MS;
  const by = u.searchParams.get('by') ?? 'domain';
  const step = BUCKET_MS[bucket] ?? BUCKET_MS.hour;
  const start = Math.floor(from / step) * step;
  const n = Math.min(5000, Math.floor((to - start) / step) + 1);
  const buckets = Array.from({ length: Math.max(0, n) }, (_, i) => new Date(start + i * step).toISOString());
  const series = new Map<string, number[]>();
  for (const e of deviceEvents(u.searchParams.get('device_id'))) {
    if (e.t < from || e.t > to) continue;
    const key = by === 'type' ? e.type : by === 'sev' ? String(e.sev) : e.type.split('.')[0] ?? e.type;
    const i = Math.floor((e.t - start) / step);
    if (i < 0 || i >= n) continue;
    let arr = series.get(key);
    if (!arr) {
      arr = new Array<number>(n).fill(0);
      series.set(key, arr);
    }
    arr[i] = (arr[i] ?? 0) + 1;
  }
  return { buckets, series: [...series.entries()].map(([key, counts]) => ({ key, counts })) };
}

function top(u: URL) {
  const from = parseTime(u.searchParams.get('from'), NOW - 86_400_000);
  const to = parseTime(u.searchParams.get('to'), Date.now());
  const kind = u.searchParams.get('kind') ?? 'event_type';
  const limit = Math.min(500, Number(u.searchParams.get('limit') ?? 20) || 20);
  const m = new Map<string, { count: number; bytes?: number }>();
  const add = (k: unknown, bytes?: number) => {
    if (typeof k !== 'string' || !k) return;
    const cur = m.get(k) ?? { count: 0 };
    cur.count++;
    if (bytes !== undefined) cur.bytes = (cur.bytes ?? 0) + bytes;
    m.set(k, cur);
  };
  for (const e of deviceEvents(u.searchParams.get('device_id'))) {
    if (e.t < from || e.t > to) continue;
    const d = e.data;
    switch (kind) {
      case 'dns_hostname': if (e.type === 'net.dns') add(d['hostname']); break;
      case 'dns_package': if (e.type === 'net.dns') add(d['package']); break;
      case 'connect_dest': if (e.type === 'net.connect') add(`${String(d['ip'])}:${String(d['port'])}`); break;
      case 'connect_package': if (e.type === 'net.connect') add(d['package']); break;
      case 'foreground_package': if (e.type === 'app.foreground' && d['event'] === 'resumed') add(d['package']); break;
      case 'notification_package': if (e.type === 'app.notification' && d['event'] === 'posted') add(d['package']); break;
      case 'event_type': add(e.type); break;
      case 'usage_package':
        if (e.type === 'net.usage' && Array.isArray(d['apps'])) {
          for (const a of d['apps'] as Record<string, unknown>[]) add(a['package'], Number(a['rx_bytes'] ?? 0) + Number(a['tx_bytes'] ?? 0));
        }
        break;
      default: break;
    }
  }
  const items = [...m.entries()]
    .map(([key, v]) => ({ key, ...v }))
    .sort((a, b) => (kind === 'usage_package' ? (b.bytes ?? 0) - (a.bytes ?? 0) : b.count - a.count))
    .slice(0, limit);
  return { items };
}

function postureHistory(deviceId: string | null) {
  const posts = deviceEvents(deviceId).filter((e) => e.type === 'security.posture');
  const last = posts[posts.length - 1];
  const changes: { ts: string; field: string; old?: unknown; new?: unknown }[] = [];
  for (let i = 1; i < posts.length; i++) {
    const a = (posts[i - 1] as MockEvent).data;
    const b = (posts[i] as MockEvent).data;
    for (const k of Object.keys(b)) {
      if (k === 'patch_age_days') continue;
      if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) changes.push({ ts: (posts[i] as MockEvent).ts, field: k, old: a[k], new: b[k] });
    }
  }
  changes.reverse();
  return { current: last?.data ?? {}, ...(last ? { ts: last.ts } : {}), changes };
}

function apps(deviceId: string | null) {
  const inv = deviceEvents(deviceId).filter((e) => e.type === 'app.inventory');
  if (inv.length === 0) return { apps: [] };
  const latestTs = (inv[inv.length - 1] as MockEvent).ts;
  // Le dernier lot complet : les parties partageant l'horodatage (à 2 s près) de la dernière partie 1.
  const lastFirst = [...inv].reverse().find((e) => e.data['part'] === 1) as MockEvent;
  const parts = inv.filter((e) => e.t >= lastFirst.t && e.t < lastFirst.t + 60_000);
  const list = parts.flatMap((e) => (Array.isArray(e.data['apps']) ? (e.data['apps'] as unknown[]) : []));
  return { ts: parts[0]?.ts ?? latestTs, apps: list };
}

function alerts(u: URL) {
  if (!control.wazuh) return { wazuh: false, alerts: [] };
  const from = parseTime(u.searchParams.get('from'), 0);
  const to = parseTime(u.searchParams.get('to'), Date.now());
  const min = Number(u.searchParams.get('level_min') ?? 0) || 0;
  const limit = Math.min(1000, Number(u.searchParams.get('limit') ?? 100) || 100);
  const rule = (e: MockEvent): { id: string; level: number; desc: string } | undefined => {
    switch (e.type) {
      case 'agent.tamper': return { id: '100110', level: 12, desc: "Vigie : altération de l'agent détectée" };
      case 'security.ca_cert': return { id: '100140', level: 10, desc: "Vigie : certificat d'AC utilisateur ajouté ou retiré" };
      case 'net.cell_security': return { id: '100150', level: 9, desc: 'Vigie : indice d’attaque sur le réseau cellulaire (IMSI catcher possible)' };
      case 'net.ble_tracker': return { id: '100160', level: 8, desc: 'Vigie : traceur Bluetooth inconnu à proximité durablement' };
      case 'security.keyguard': return e.data['event'] === 'unlock_failed' && e.sev >= 3 ? { id: '100120', level: 10, desc: 'Vigie : plusieurs échecs de déverrouillage consécutifs' } : undefined;
      case 'sensor.microphone': return e.sev >= 2 ? { id: '100170', level: 11, desc: 'Vigie : microphone utilisé par une application sans interaction' } : undefined;
      case 'app.permission_changed': return e.sev >= 2 ? { id: '100130', level: 8, desc: 'Vigie : permission sensible accordée à une application récente' } : undefined;
      case 'security.log': return e.sev >= 2 ? { id: '100180', level: 7, desc: 'Vigie : activité de sécurité système notable' } : undefined;
      default: return undefined;
    }
  };
  const out: { ts: string; level: number; rule_id: string; description: string; type: string; device_id: string }[] = [];
  for (let i = events.length - 1; i >= 0 && out.length < limit; i--) {
    const e = events[i] as MockEvent;
    if (e.t < from || e.t > to) continue;
    const r = rule(e);
    if (!r || r.level < min) continue;
    out.push({ ts: e.ts, level: r.level, rule_id: r.id, description: r.desc, type: e.type, device_id: e.device_id });
  }
  return { wazuh: true, alerts: out };
}

function locations(u: URL) {
  const from = parseTime(u.searchParams.get('from'), NOW - 86_400_000);
  const to = parseTime(u.searchParams.get('to'), Date.now());
  const max = Math.max(2, Number(u.searchParams.get('max_points') ?? 2000) || 2000);
  const pts = deviceEvents(u.searchParams.get('device_id')).filter(
    (e) => e.type === 'location.fix' && e.t >= from && e.t <= to && typeof e.data['lat'] === 'number' && typeof e.data['lon'] === 'number',
  );
  const step = Math.max(1, Math.ceil(pts.length / max));
  const sampled = step === 1 ? pts : pts.filter((_, i) => i % step === 0 || i === pts.length - 1);
  return {
    points: sampled.map((e) => ({ ts: e.ts, lat: e.data['lat'], lon: e.data['lon'], acc_m: e.data['acc_m'], speed_mps: e.data['speed_mps'], provider: e.data['provider'] })),
  };
}

function eventsQuery(u: URL) {
  const sp = u.searchParams;
  const prefixes = (sp.get('type') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const sevMin = Number(sp.get('sev_min') ?? 0) || 0;
  const from = parseTime(sp.get('from'), 0);
  const to = parseTime(sp.get('to'), Date.now() + 1000);
  const q = (sp.get('q') ?? '').toLowerCase();
  const limit = Math.min(500, Math.max(1, Number(sp.get('limit') ?? 100) || 100));
  const list = deviceEvents(sp.get('device_id'));
  const cur = sp.get('cursor');
  let i = list.length - 1;
  if (cur) {
    const n = Number(cur.replace(/^c/, ''));
    if (Number.isInteger(n)) i = Math.min(n - 1, list.length - 1);
  }
  const out: ReturnType<typeof toEvent>[] = [];
  let next: string | undefined;
  for (; i >= 0; i--) {
    const e = list[i] as MockEvent;
    if (e.t > to) continue;
    if (e.t < from) break;
    if (e.sev < sevMin) continue;
    if (prefixes.length && !prefixes.some((p) => e.type.startsWith(p))) continue;
    if (q && !matchQ(e, q)) continue;
    if (out.length >= limit) {
      next = `c${i + 1}`;
      break;
    }
    out.push(toEvent(e));
  }
  return next ? { events: out, next_cursor: next } : { events: out };
}

function devices() {
  const lastOf = (type: string) => [...events].reverse().find((e) => e.type === type);
  const hb = lastOf('agent.heartbeat');
  const loc = [...events].reverse().find((e) => e.type === 'location.fix' && typeof e.data['lat'] === 'number' && typeof e.data['lon'] === 'number');
  const post = lastOf('security.posture');
  const lastSeen = events[events.length - 1]?.ts;
  return {
    devices: [
      {
        ...DEVICE_MAIN,
        ...(lastSeen ? { last_seen: lastSeen } : {}),
        ...(hb ? { last_heartbeat: hb.data } : {}),
        ...(loc ? { last_location: { ts: loc.ts, lat: loc.data['lat'], lon: loc.data['lon'], acc_m: loc.data['acc_m'] } } : {}),
        ...(post ? { last_posture: post.data } : {}),
      },
      { ...DEVICE_OLD, last_seen: new Date(NOW - 41 * 86_400_000).toISOString() },
    ],
  };
}

// ---------------------------------------------------------------- SSE
const streams = new Set<{ res: Res; deviceId: string | null }>();
function broadcast(e: MockEvent): void {
  const msg = `id: ${e.id}\ndata: ${JSON.stringify(toEvent(e))}\n\n`;
  for (const s of streams) {
    if (s.deviceId && s.deviceId !== e.device_id) continue;
    s.res.write(msg);
  }
}
function scheduleLive(): void {
  setTimeout(() => {
    const e = liveEvent(liveRng, Date.now(), seqCounter++, liveBoot, lastLoc);
    events.push(e);
    byId.set(e.id, e);
    broadcast(e);
    scheduleLive();
  }, 1500 + Math.random() * 3500).unref();
}
scheduleLive();
setInterval(() => {
  for (const s of streams) s.res.write(': ping\n\n');
}, 15_000).unref();

// ---------------------------------------------------------------- statique
const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.map': 'application/json', '.woff2': 'font/woff2',
};
function serveStatic(req: http.IncomingMessage, res: Res, pathname: string): boolean {
  if (!STATIC_DIR) return false;
  const root = path.resolve(STATIC_DIR);
  const rel = decodeURIComponent(pathname).replace(/^\/+/, '');
  let file = path.join(root, rel);
  if (!file.startsWith(root)) return false;
  const hasExt = path.extname(rel) !== '';
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    if (hasExt) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
      return true;
    }
    file = path.join(root, 'index.html'); // repli SPA
  }
  const body = fs.readFileSync(file);
  res.writeHead(200, {
    'Content-Type': MIME[path.extname(file)] ?? 'application/octet-stream',
    'Content-Security-Policy': CSP,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': file.endsWith('index.html') ? 'no-cache' : 'public, max-age=3600',
  });
  res.end(req.method === 'HEAD' ? undefined : body);
  return true;
}

// ---------------------------------------------------------------- routeur
const server = http.createServer((req, res) => {
  void (async () => {
    const u = new URL(req.url ?? '/', 'http://x');
    const p = u.pathname;
    const method = req.method ?? 'GET';

    if (p === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
      return;
    }
    if (p === '/__mock/control' && method === 'POST') {
      const b = JSON.parse((await readBody(req)) || '{}') as { wazuh?: boolean; expire?: boolean; fail?: string[]; latency_ms?: number };
      if (typeof b.wazuh === 'boolean') control.wazuh = b.wazuh;
      if (b.expire) sessions.clear();
      if (Array.isArray(b.fail)) control.fail = b.fail;
      if (typeof b.latency_ms === 'number') control.latency_ms = b.latency_ms;
      sendJson(res, 200, control);
      return;
    }
    if (!p.startsWith('/api/console/')) {
      if (serveStatic(req, res, p)) return;
      err(res, 404, 'not_found', 'Introuvable');
      return;
    }
    const route = p.slice('/api/console'.length);
    if (control.latency_ms) await new Promise((r) => setTimeout(r, control.latency_ms));

    if (method !== 'GET' && method !== 'HEAD' && req.headers['x-requested-with'] !== 'vigie') {
      err(res, 403, 'csrf', 'En-tête X-Requested-With manquant');
      return;
    }
    if (route === '/login' && method === 'POST') {
      let b: { username?: string; password?: string } = {};
      try {
        b = JSON.parse((await readBody(req)) || '{}') as typeof b;
      } catch {
        err(res, 400, 'bad_request', 'JSON invalide');
        return;
      }
      if (b.username === USER && b.password === PASSWORD) {
        const tok = randomBytes(24).toString('hex');
        sessions.set(tok, USER);
        res.writeHead(204, { 'Set-Cookie': `${COOKIE}=${tok}; Path=/; HttpOnly; SameSite=Strict` });
        res.end();
      } else err(res, 401, 'invalid_credentials', 'Identifiants invalides');
      return;
    }
    const user = sessionUser(req);
    if (route === '/logout' && method === 'POST') {
      const raw = req.headers.cookie ?? '';
      for (const part of raw.split(';')) {
        const [k, ...v] = part.trim().split('=');
        if (k === COOKIE) sessions.delete(v.join('='));
      }
      res.writeHead(204, { 'Set-Cookie': `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0` });
      res.end();
      return;
    }
    if (!user) {
      err(res, 401, 'unauthorized', 'Session absente ou expirée');
      return;
    }
    if (control.fail.some((f) => route.startsWith(f))) {
      err(res, 500, 'internal', 'Erreur simulée par le serveur factice');
      return;
    }
    if (route === '/me') return sendJson(res, 200, { username: user });
    if (route === '/devices') return sendJson(res, 200, devices());
    if (route === '/events') return sendJson(res, 200, eventsQuery(u));
    if (route.startsWith('/events/')) {
      const e = byId.get(decodeURIComponent(route.slice('/events/'.length)));
      return e ? sendJson(res, 200, toEvent(e)) : err(res, 404, 'not_found', 'Événement introuvable');
    }
    if (route === '/locations') return sendJson(res, 200, locations(u));
    if (route === '/stats/timeline') return sendJson(res, 200, timeline(u));
    if (route === '/stats/top') return sendJson(res, 200, top(u));
    if (route === '/apps') return sendJson(res, 200, apps(u.searchParams.get('device_id')));
    if (route === '/posture') return sendJson(res, 200, postureHistory(u.searchParams.get('device_id')));
    if (route === '/alerts') return sendJson(res, 200, alerts(u));
    if (route === '/stream') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
      res.write('retry: 3000\n\n');
      const s = { res, deviceId: u.searchParams.get('device_id') };
      streams.add(s);
      req.on('close', () => streams.delete(s));
      return;
    }
    err(res, 404, 'not_found', `Route inconnue : ${route}`);
  })().catch((e: unknown) => {
    console.error(e);
    if (!res.headersSent) err(res, 500, 'internal', 'Erreur interne du serveur factice');
    else res.end();
  });
});

server.listen(PORT, '127.0.0.1', () => {
  const n = events.length;
  console.log(`[mock] API console sur http://127.0.0.1:${PORT}/api/console (${n} événements, ${gen.appCount} apps)`);
  console.log(`[mock] connexion : ${USER} / ${PASSWORD}${STATIC_DIR ? ` — console statique : ${STATIC_DIR}` : ''}`);
});
