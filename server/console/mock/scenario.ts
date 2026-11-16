// Scénarios du serveur factice pour la version 1.2 : détections, profils de risque, usage des opérations
// sensibles, changements de rôle.
//   --scenario mixed    (défaut) parc varié : les huit types de détection, les trois combinaisons de risque,
//                       `app.ops` présent, des changements de rôle dont un inquiétant ;
//   --scenario healthy  « téléphone sain » : aucune détection, aucune application à risque élevé, `app.ops` absent ;
//   --scenario fraud    « fraude au SMS » : une application hors boutique installée il y a 40 h envoie près de
//                       2 000 SMS par jour sans que rien ne s'affiche ; `app.ops` présent.
// Les événements sont ajoutés aux données générées par gen.ts (mêmes identifiants, mêmes types que le vrai agent
// et le vrai collecteur), si bien que /events, /stream, /apps, /stats et /tracking en tiennent compte.
import type { MockApp } from './catalog.ts';
import { ALL_APPS } from './catalog.ts';
import type { MockEvent } from './gen.ts';
import { profileOf } from './risk.ts';
import { hex, makeRng, pick, ulid, type Rng } from './rng.ts';

export type Scenario = 'mixed' | 'healthy' | 'fraud';

export function parseScenario(v: string | undefined): Scenario {
  return v === 'healthy' || v === 'fraud' || v === 'mixed' ? v : 'mixed';
}

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

const P = (...n: string[]) => n.map((x) => `android.permission.${x}`);

export const WALLPAPERS: MockApp = {
  package: 'com.wallpapers.superhd',
  label: 'Super Wallpapers HD',
  system: false,
  installer: 'com.google.android.packageinstaller',
  version_name: '2.4.0',
  perms: P('SEND_SMS', 'READ_PHONE_STATE', 'READ_CONTACTS'),
  hosts: [['cfg.wallpapers-hd.xyz', 3], ['sms-relay.cheap-gw.top', 5], ['api.smsbomber-gw.cc', 4], ['cdn.wallpapers-static.net', 2]],
  dnsWeight: 0,
  mibPerHour: 0,
  firstInstallDaysAgo: 2,
  lastUpdateDaysAgo: 2,
};

export const SYNC_HELPER: MockApp = {
  package: 'com.sync.helper.svc',
  label: 'Sync Helper',
  system: false,
  installer: 'com.android.shell',
  version_name: '1.0.3',
  perms: P('ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'RECORD_AUDIO', 'READ_CONTACTS'),
  hosts: [['upload.sync-helper.info', 5], ['smtp.mail-relay-eu.net', 2]],
  dnsWeight: 0,
  mibPerHour: 0,
  firstInstallDaysAgo: 4,
  lastUpdateDaysAgo: 4,
};

/** Domaines de la liste de menaces (bloqués par AdGuard) : voir `EXACT_RULES` de tracking.ts. */
export const THREAT_DOMAINS = ['cfg.wallpapers-hd.xyz', 'sms-relay.cheap-gw.top', 'api.smsbomber-gw.cc'];

interface Ctx {
  events: MockEvent[];
  rng: Rng;
  now: number;
  device: string;
  horizon: number;
  /** fenêtres sans aucun événement (téléphone éteint) : le scénario n'y ajoute rien */
  silent: { start: number; end: number }[];
}

function mk(c: Ctx, t: number, type: string, sev: number, data: Record<string, unknown>): MockEvent | undefined {
  if (t > c.horizon || c.silent.some((w) => t >= w.start && t < w.end)) return undefined;
  const e: MockEvent = {
    id: ulid(c.rng, t),
    ts: new Date(t).toISOString(),
    seq: 0,
    boot_id: 'scen' + hex(c.rng, 4),
    elapsed_ms: 123_456_789,
    type,
    sev,
    data,
    received_at: new Date(t + 400).toISOString(),
    device_id: c.device,
    t,
  };
  c.events.push(e);
  return e;
}

/** Charge d'un événement `detect.*` (contrat §11.3) : `package`, `label`, fenêtre, preuve, résumé. */
export function detectionData(a: { package?: string; label?: string }, windowEnd: number, windowMs: number, evidence: Record<string, unknown>, summary: string, withWindow = true): Record<string, unknown> {
  return {
    ...(a.package ? { package: a.package } : {}),
    ...(a.label ? { label: a.label } : {}),
    ...(withWindow ? { window_from: new Date(windowEnd - windowMs).toISOString(), window_to: new Date(windowEnd).toISOString() } : {}),
    evidence,
    summary,
  };
}

const MIB = 1_048_576;

// ----------------------------------------------------------------------------------------- application

function addAppEverywhere(c: Ctx, app: MockApp, installAt: number): void {
  // Inventaire : l'application apparaît dans la dernière partie de chaque inventaire postérieur à l'installation.
  for (const e of c.events) {
    if (e.type !== 'app.inventory' || e.t < installAt) continue;
    const parts = e.data['parts'];
    if (e.data['part'] !== parts || !Array.isArray(e.data['apps'])) continue;
    (e.data['apps'] as Record<string, unknown>[]).push({
      package: app.package,
      label: app.label,
      version_name: app.version_name,
      version_code: 100000 + app.package.length * 111,
      ...(app.installer ? { installer: app.installer } : {}),
      system: false,
      enabled: true,
      suspended: false,
      hidden: false,
      target_sdk: app.package === SYNC_HELPER.package ? 28 : 35,
      first_install: new Date(installAt).toISOString(),
      last_update: new Date(installAt).toISOString(),
      signer_sha256: hex(makeRng(app.package.length * 7919), 32),
      granted_dangerous: app.perms,
    });
  }
  mk(c, installAt, 'app.installed', 1, {
    package: app.package,
    version_name: app.version_name,
    version_code: 100000 + app.package.length * 111,
    ...(app.installer ? { installer: app.installer } : {}),
    signer_sha256: hex(makeRng(app.package.length * 7919), 32),
  });
  // Trafic DNS et connexions : quelques requêtes par heure depuis l'installation ; volumes dans net.usage.
  const first = Math.ceil(installAt / HOUR) * HOUR;
  for (let h = first; h < c.horizon; h += HOUR) {
    const n = 3 + Math.floor(c.rng() * 8);
    for (let i = 0; i < n; i++) {
      const t = h + Math.floor(c.rng() * HOUR);
      const total = app.hosts.reduce((s, [, w]) => s + w, 0);
      let r = c.rng() * total;
      let host = app.hosts[0]?.[0] ?? 'example.invalid';
      for (const [hh, w] of app.hosts) {
        r -= w;
        if (r <= 0) {
          host = hh;
          break;
        }
      }
      mk(c, t, 'net.dns', 0, { package: app.package, uid: 10400, hostname: host, addresses: ['203.0.113.7'], address_count: 1 });
      if (c.rng() < 0.5) mk(c, t + 300, 'net.connect', 0, { package: app.package, uid: 10400, ip: '203.0.113.7', port: 443 });
    }
  }
  for (const e of c.events) {
    if (e.type !== 'net.usage' || e.t < installAt || !Array.isArray(e.data['apps'])) continue;
    (e.data['apps'] as Record<string, unknown>[]).push({ package: app.package, uid: 10400, rx_bytes: Math.round(0.05 * MIB), tx_bytes: Math.round(0.2 * MIB), transport: 'wifi' });
  }
}

function riskEvent(c: Ctx, t: number, app: MockApp, override?: { score: number; reasons: string[] }): void {
  const p = profileOf(app);
  const score = override?.score ?? p.score;
  const reasons = override?.reasons ?? p.reasons;
  const level = app.system || app.package === 'io.github.erwsim.vigie' ? 'low' : score >= 65 ? 'high' : score >= 35 ? 'medium' : 'low';
  mk(c, t, 'app.risk', 0, {
    package: app.package,
    label: app.label,
    version_code: 100000 + app.package.length * 111,
    ...(p.installer ? { installer: p.installer } : {}),
    from_store: p.from_store,
    score,
    level,
    reasons,
  });
}

// ----------------------------------------------------------------------------------------- opérations

type OpRow = { package: string; op: string; count: number; background_count: number; last_ts: string };

function opsEvent(c: Ctx, hourEnd: number, rows: Omit<OpRow, 'last_ts'>[]): void {
  const withTs: OpRow[] = rows.map((r) => ({ ...r, last_ts: new Date(hourEnd - Math.floor(c.rng() * 50) * MIN - MIN).toISOString() }));
  mk(c, hourEnd + 20_000, 'app.ops', 0, { from: new Date(hourEnd - HOUR).toISOString(), to: new Date(hourEnd).toISOString(), apps: withTs });
}

/** Usages courants et anodins : l'appli SMS par défaut, l'appareil photo, les appels, la messagerie. */
function benignOps(c: Ctx, from: number, to: number): void {
  for (let h = Math.ceil(from / HOUR) * HOUR; h < to; h += HOUR) {
    const hod = new Date(h).getUTCHours();
    if (hod < 7 || hod > 22) continue;
    const rows: Omit<OpRow, 'last_ts'>[] = [];
    if (c.rng() < 0.25) rows.push({ package: 'com.samsung.android.messaging', op: 'send_sms', count: 1 + Math.floor(c.rng() * 3), background_count: 0 });
    if (c.rng() < 0.35) rows.push({ package: 'com.samsung.android.messaging', op: 'read_sms', count: 4 + Math.floor(c.rng() * 20), background_count: Math.floor(c.rng() * 3) });
    if (c.rng() < 0.15) rows.push({ package: 'com.samsung.android.dialer', op: 'call_phone', count: 1 + Math.floor(c.rng() * 2), background_count: 0 });
    if (c.rng() < 0.3) rows.push({ package: 'com.samsung.android.dialer', op: 'read_contacts', count: 2 + Math.floor(c.rng() * 6), background_count: 0 });
    if (c.rng() < 0.2) rows.push({ package: 'com.whatsapp', op: 'read_contacts', count: 1 + Math.floor(c.rng() * 3), background_count: 1 });
    if (c.rng() < 0.08) rows.push({ package: 'com.sec.android.app.camera', op: 'camera', count: 1 + Math.floor(c.rng() * 4), background_count: 0 });
    if (c.rng() < 0.08) rows.push({ package: 'com.sec.android.app.camera', op: 'record_audio', count: 1, background_count: 0 });
    if (c.rng() < 0.1) rows.push({ package: 'com.whatsapp', op: 'record_audio', count: 1 + Math.floor(c.rng() * 2), background_count: 0 });
    if (c.rng() < 0.4) rows.push({ package: 'com.google.android.apps.maps', op: 'fine_location', count: 10 + Math.floor(c.rng() * 30), background_count: Math.floor(c.rng() * 12) });
    if (rows.length > 0) opsEvent(c, h + HOUR, rows);
  }
}

// ----------------------------------------------------------------------------------------- scénarios

/**
 * Applique un scénario aux événements générés : ajoute ou retire des événements, et renumérote `seq`.
 * Renvoie les applications ajoutées (le catalogue sert aux libellés du pistage).
 */
export function applyScenario(events: MockEvent[], scenario: Scenario, now: number, device: string, silent: { start: number; end: number }[]): MockApp[] {
  const c: Ctx = { events, rng: makeRng(1202), now, device, horizon: now - 20_000, silent };
  const todayStart = Math.floor(now / DAY) * DAY;
  const t0 = todayStart - 6 * DAY;
  const extra: MockApp[] = [];

  // « Sain » et « fraude » : l'application « Fast Cleaner Pro » du jeu de base (cheval de Troie bancaire) n'existe pas.
  if (scenario !== 'mixed') stripApp(events, 'com.fastcleaner.pro');

  const installWall = now - 40 * HOUR;
  const installSync = now - 4 * DAY;
  const fastInstall = todayStart - 5 * DAY + 11 * HOUR + 2 * MIN;

  if (scenario === 'fraud' || scenario === 'mixed') {
    extra.push(WALLPAPERS);
    addAppEverywhere(c, WALLPAPERS, installWall);
  }
  if (scenario === 'mixed') {
    extra.push(SYNC_HELPER);
    addAppEverywhere(c, SYNC_HELPER, installSync);
  }

  // ---------- Profils de risque : un par application dès le premier inventaire, puis aux changements ----------
  for (const a of ALL_APPS) {
    if (a.package !== 'com.fastcleaner.pro') riskEvent(c, t0 + 4 * HOUR + 6 * MIN, a);
  }
  if (scenario === 'mixed') {
    const fast = ALL_APPS.find((a) => a.package === 'com.fastcleaner.pro');
    if (fast) {
      riskEvent(c, fastInstall + 10_000, fast, { score: 61, reasons: ['sideloaded', 'unknown_installer', 'boot_receiver', 'notification_listener'] });
      riskEvent(c, fastInstall + 40_000, fast); // après l'octroi des permissions SMS et micro
    }
  }
  if (scenario === 'mixed') riskEvent(c, installSync + 30_000, SYNC_HELPER);
  if (scenario === 'mixed' || scenario === 'fraud') {
    riskEvent(c, installWall + 15_000, WALLPAPERS);
    mk(c, installWall + 50_000, 'app.permission_changed', 2, { package: WALLPAPERS.package, permission: 'android.permission.SEND_SMS', granted: true });
  }

  // ---------- Changements de rôle ----------
  mk(c, t0 + 2 * HOUR, 'app.role', 1, { role: 'browser', old: 'com.sec.android.app.sbrowser', new: 'com.android.chrome' });
  mk(c, t0 + 2 * HOUR + 40_000, 'app.role', 1, { role: 'assistant', old: 'com.samsung.android.bixby.agent', new: 'com.google.android.googlequicksearchbox' });
  if (scenario === 'mixed') {
    const when = todayStart - 4 * DAY + 9 * HOUR;
    mk(c, when, 'app.role', 2, { role: 'call_screening', new: 'com.fastcleaner.pro' });
    // Les relevés d'applications par défaut suivants le montrent aussi.
    for (const e of events) if (e.type === 'app.special_access' && e.t >= when && isDefaults(e.data['default_apps'])) (e.data['default_apps'] as Record<string, unknown>)['call_screening'] = 'com.fastcleaner.pro';
  }
  if (scenario === 'fraud') {
    // Elle tente de devenir l'application SMS par défaut ; l'utilisateur ne l'accepte pas : aucun changement de rôle.
  }

  // ---------- Détections ----------
  const det = (t: number, type: string, sev: number, app: { package?: string; label?: string }, evidence: Record<string, unknown>, summary: string, windowMs = HOUR, withWindow = true) =>
    mk(c, t, type, sev, detectionData(app, t - 2 * MIN, windowMs, evidence, summary, withWindow));
  /** Détection à fenêtre « jour » (UTC), comme les règles quotidiennes du collecteur. */
  const detDay = (t: number, type: string, sev: number, app: { package?: string; label?: string }, evidence: Record<string, unknown>, summary: string) => {
    const day = Math.floor(t / DAY) * DAY;
    return mk(c, t, type, sev, detectionData(app, day + DAY, DAY, evidence, summary));
  };
  const W = { package: WALLPAPERS.package, label: WALLPAPERS.label };
  const FAST_APP = { package: 'com.fastcleaner.pro', label: 'Fast Cleaner Pro' };
  const SYNC = { package: SYNC_HELPER.package, label: SYNC_HELPER.label };
  const LIST = 'Liste : Vigie : domaines suspects';
  const SMS_APPS = ['com.samsung.android.messaging'];

  if (scenario === 'fraud' || scenario === 'mixed') {
    det(installWall + 2 * MIN, 'detect.new_app_risky', 3, W, { trigger: 'high_risk', score: 88, level: 'high', reasons: ['combo_sms_fraud', 'sms_send', 'boot_receiver', 'sideloaded', 'unknown_installer'], installer: WALLPAPERS.installer, installed_at: new Date(installWall).toISOString(), from_store: false }, `Application à risque élevé installée : ${WALLPAPERS.label} (score 88 ; combo_sms_fraud, sms_send, boot_receiver, sideloaded, unknown_installer)`, 2 * MIN);
    THREAT_DOMAINS.forEach((dom, i) => {
      detDay(now - 38 * HOUR + i * MIN, 'detect.threat_domain', 3, W, { domain: dom, requests: 9 + i * 7, blocked: true, reason: LIST }, `${WALLPAPERS.label} a demandé ${dom} (${9 + i * 7} fois), bloqué par une liste de menaces (Vigie : domaines suspects)`);
    });
    det(now - 28 * HOUR, 'detect.fanout', 2, W, { addresses: 214, connections: 530, threshold: 100, ports: [443, 8443], sample: ['203.0.113.7:443', '198.51.100.22:443', '192.0.2.81:8443'] }, `${WALLPAPERS.label} s'est connectée à 214 adresses distinctes en une heure (seuil 100)`);
    // 1 984 SMS en deux jours civils, presque tous en arrière-plan, par une application qui n'est pas l'appli SMS par défaut.
    const sums = new Map<number, { sent: number; bg: number }>();
    for (const [t, n, bg] of [[now - 30 * HOUR, 412, 405], [now - 29 * HOUR, 733, 721], [now - 3 * HOUR, 839, 664]] as const) {
      const k = Math.floor(t / DAY);
      const cur = sums.get(k) ?? { sent: 0, bg: 0 };
      cur.sent += n;
      cur.bg += bg;
      sums.set(k, cur);
    }
    for (const [k, v] of sums) {
      const t = Math.min(now - 10 * MIN, (k + 1) * DAY - 2 * HOUR);
      detDay(t, 'detect.sms_abuse', 3, W, { reason: 'not_default_sms_app', sent: v.sent, background: v.bg, read_contacts: 3, default_sms_app: SMS_APPS }, `${WALLPAPERS.label}, qui n'est pas l'application SMS par défaut, a envoyé ${v.sent} SMS dans la journée (dont ${v.bg} en arrière-plan)`);
    }
    det(now - 31 * HOUR, 'detect.upload_spike', 2, W, { tx_bytes: 38 * MIB, threshold_bytes: 8 * MIB, median_bytes: Math.round(0.2 * MIB), history_hours: 31, learning: false }, `${WALLPAPERS.label} a envoyé 38 Mio en une heure (seuil 8 Mio ; médiane horaire sur 14 jours : 0,2 Mio)`);
  }

  if (scenario === 'mixed') {
    ['ads.unknown-cdn.biz', 'track.sdkmetrics.cc'].forEach((dom, i) => {
      detDay(todayStart - 5 * DAY + 12 * HOUR + i * MIN, 'detect.threat_domain', 2, FAST_APP, { domain: dom, requests: 5 + i, blocked: true, reason: LIST }, `Fast Cleaner Pro a demandé ${dom}, bloqué par une liste de menaces`);
    });
    det(todayStart - 2 * DAY + 3 * HOUR, 'detect.upload_spike', 2, FAST_APP, { tx_bytes: 183 * MIB, threshold_bytes: Math.round(1.2 * 8 * MIB), median_bytes: Math.round(1.2 * MIB), history_hours: 60, learning: false }, 'Fast Cleaner Pro a envoyé 183 Mio en une heure (médiane horaire sur 14 jours : 1,2 Mio)');
    detDay(todayStart - 4 * DAY + 3 * HOUR + 2 * MIN, 'detect.sensor_background', 2, FAST_APP, { op: 'record_audio', background_count: 2, count: 2 }, 'Fast Cleaner Pro a utilisé le micro 2 fois en arrière-plan dans la journée (seuil 1)');
    detDay(now - 2 * DAY - 5 * HOUR, 'detect.sensor_background', 2, SYNC, { op: 'record_audio', background_count: 14, count: 14 }, 'Sync Helper a utilisé le micro 14 fois en arrière-plan dans la journée (seuil 3)');
    detDay(now - 3 * DAY, 'detect.mail_ports', 2, SYNC, { connections: 42, addresses: 1, ports: [587], sample: ['203.0.113.55:587'] }, "Sync Helper, qui n'est pas un client de messagerie connu, s'est connectée 42 fois au port d'envoi de courriel 587 de 1 serveur(s)");
    detDay(now - 20 * HOUR, 'detect.dns_bypass', 2, { package: 'com.android.chrome', label: 'Chrome' }, { connections: 12, resolvers: ['8.8.8.8:443'], providers: ['Google DNS'] }, "Chrome s'adresse directement à un résolveur DNS public (Google DNS, 8.8.8.8:443)");
    det(now - 6 * HOUR, 'detect.dns_bypass', 2, SYNC, { unresolved_ips: 83, connections: 140 }, "Sync Helper s'est connectée à 83 adresses jamais résolues par le DNS du téléphone");
    // Capacité obtenue peu après l'installation (détection `new_app_risky`, déclencheur « capability »).
    det(installSync + 12 * MIN, 'detect.new_app_risky', 2, SYNC, { trigger: 'capability', capability: 'permission:CALL_PHONE', installed_at: new Date(installSync).toISOString(), minutes_after_install: 10, installer: 'com.android.shell', level: 'high', score: 79 }, 'Sync Helper, installée il y a 10 min, a obtenu : appels téléphoniques', 2 * MIN);
    // Texte hostile venu du téléphone et du réseau : nom d'application, domaine, motif (affichés comme du texte).
    detDay(now - 12 * HOUR, 'detect.threat_domain', 2, { package: 'com.hostile.app', label: '<img src=x onerror=window.__pwn=1>\u202Etxt.exe' }, { domain: '<script>window.__pwn=2</script>.top', requests: 3, blocked: true, reason: 'Liste : <b>gras</b> [lien](javascript:alert(1))' }, '<img src=x onerror=window.__pwn=3> a demandé un domaine de menace');
    // Type inconnu de la console et détection sans fenêtre : repli lisible.
    det(now - 9 * HOUR, 'detect.quantum_leak', 2, { package: 'com.google.android.apps.photos', label: 'Photos' }, { qubits: 12, note: 'type hors catalogue' }, 'Fuite quantique simulée (type inconnu de la console)', HOUR, false);
  }

  // ---------- Usage des opérations sensibles (expérimental : absent du scénario sain) ----------
  if (scenario === 'mixed' || scenario === 'fraud') {
    benignOps(c, t0 + 6 * HOUR, now - HOUR);
    if (scenario === 'fraud') {
      // Rafale d'envois de SMS en arrière-plan : mêmes fenêtres que les détections.
      for (const [t, n, bg] of [[now - 30 * HOUR, 412, 405], [now - 29 * HOUR, 733, 721], [now - 3 * HOUR, 839, 664]] as const) {
        opsEvent(c, Math.ceil(t / HOUR) * HOUR, [{ package: WALLPAPERS.package, op: 'send_sms', count: n, background_count: bg }, { package: WALLPAPERS.package, op: 'read_contacts', count: 3, background_count: 3 }]);
      }
    } else {
      opsEvent(c, Math.ceil((now - 30 * HOUR) / HOUR) * HOUR, [{ package: WALLPAPERS.package, op: 'send_sms', count: 412, background_count: 405 }]);
      opsEvent(c, Math.ceil((now - 29 * HOUR) / HOUR) * HOUR, [{ package: WALLPAPERS.package, op: 'send_sms', count: 733, background_count: 721 }]);
      opsEvent(c, Math.ceil((now - 3 * HOUR) / HOUR) * HOUR, [{ package: WALLPAPERS.package, op: 'send_sms', count: 839, background_count: 664 }]);
      opsEvent(c, Math.ceil((now - 2 * DAY - 5 * HOUR) / HOUR) * HOUR, [{ package: SYNC_HELPER.package, op: 'record_audio', count: 14, background_count: 14 }, { package: SYNC_HELPER.package, op: 'fine_location', count: 120, background_count: 120 }]);
      opsEvent(c, Math.ceil((todayStart - 4 * DAY + 3 * HOUR + 12 * MIN) / HOUR) * HOUR, [{ package: 'com.fastcleaner.pro', op: 'record_audio', count: 2, background_count: 2 }, { package: 'com.fastcleaner.pro', op: 'read_sms', count: 47, background_count: 47 }]);
    }
  }

  events.sort((a, b) => a.t - b.t || (a.id < b.id ? -1 : 1));
  events.forEach((e, i) => (e.seq = 18000 + i));
  return extra;
}

/** Retire toute trace d'une application : événements, inventaire, volumes, accès spéciaux. */
function stripApp(events: MockEvent[], pkg: string): void {
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i] as MockEvent;
    if (e.data['package'] === pkg || (e.type === 'security.log' && JSON.stringify(e.data).includes(pkg))) {
      events.splice(i, 1);
      continue;
    }
    if ((e.type === 'app.inventory' || e.type === 'net.usage') && Array.isArray(e.data['apps'])) e.data['apps'] = (e.data['apps'] as { package?: string }[]).filter((a) => a.package !== pkg);
    if (e.type === 'app.special_access') {
      for (const k of ['accessibility_services', 'notification_listeners', 'overlay_apps', 'unknown_sources_apps']) {
        if (Array.isArray(e.data[k])) e.data[k] = (e.data[k] as string[]).filter((x) => !x.startsWith(pkg));
      }
    }
  }
}

function isDefaults(v: unknown): boolean {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Détections de remplissage (tous types) pour tester la pagination par curseur. */
export function fillerDetections(c: { rng: Rng; now: number; device: string }, n: number): Omit<MockEvent, 'seq' | 'boot_id' | 'elapsed_ms'>[] {
  const apps = ALL_APPS.filter((a) => !a.system && a.dnsWeight > 0);
  const out: Omit<MockEvent, 'seq' | 'boot_id' | 'elapsed_ms'>[] = [];
  for (let i = 0; i < n; i++) {
    const t = c.now - Math.floor(c.rng() * 5 * DAY) - 10 * MIN;
    const a = pick(c.rng, apps);
    const kind = pick(c.rng, ['fanout', 'dns_bypass'] as const);
    const data =
      kind === 'fanout'
        ? detectionData(a, t, HOUR, { addresses: 101 + Math.floor(c.rng() * 40), connections: 300, threshold: 100, ports: [443], sample: [] }, `${a.label} s'est connectée à plus de 100 adresses en 1 h`)
        : detectionData(a, t, HOUR, { connections: 8, resolvers: ['8.8.8.8:443'], providers: ['Google DNS'] }, `${a.label} s'adresse directement à un résolveur DNS public`);
    out.push({ id: ulid(c.rng, t), ts: new Date(t).toISOString(), type: `detect.${kind}`, sev: 1, data, received_at: new Date(t + 400).toISOString(), device_id: c.device, t });
  }
  return out;
}
