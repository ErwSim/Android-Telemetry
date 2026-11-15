// Génération déterministe de sept jours de télémétrie réaliste pour le serveur factice.
import { ALL_APPS, APPS, ROUTE_PLACES, type MockApp } from './catalog.ts';
import { between, gauss, hex, makeRng, pick, ulid, weighted, type Rng } from './rng.ts';

export interface MockEvent {
  id: string;
  ts: string;
  seq: number;
  boot_id: string;
  elapsed_ms: number;
  type: string;
  sev: number;
  data: Record<string, unknown>;
  received_at: string;
  device_id: string;
  /** epoch ms, interne */
  t: number;
}

export interface MockDevice {
  device_id: string;
  name: string;
  enrolled_at: string;
  agent_version: string;
  revoked: boolean;
}

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

export const DEVICE_MAIN: MockDevice = {
  device_id: 'dev_8f3a1c2e9b7d',
  name: 's25',
  enrolled_at: '',
  agent_version: '1.0.0',
  revoked: false,
};
export const DEVICE_OLD: MockDevice = {
  device_id: 'dev_41d0aa7c5e22',
  name: 'ancien-s23',
  enrolled_at: '',
  agent_version: '0.9.2',
  revoked: true,
};

interface Window {
  start: number;
  end: number;
}

export interface Generated {
  events: MockEvent[];
  silent: Window[];
  nofix: Window[];
  devices: MockDevice[];
  appCount: number;
}

type LatLon = { lat: number; lon: number };

const lerp = (a: number, b: number, f: number) => a + (b - a) * f;
function along(path: LatLon[], f: number): LatLon {
  if (path.length === 1) return path[0] as LatLon;
  const segs = path.length - 1;
  const x = Math.min(0.999999, Math.max(0, f)) * segs;
  const i = Math.floor(x);
  const a = path[i] as LatLon;
  const b = path[i + 1] as LatLon;
  return { lat: lerp(a.lat, b.lat, x - i), lon: lerp(a.lon, b.lon, x - i) };
}

export const COLLECTORS = { location: 'running', connectivity: 'running', dns: 'running', connect: 'running', usage: 'running', apps: 'running', posture: 'running', security_log: 'running', ble_tracker: 'unavailable', notifications: 'disabled' };

export function generate(now: number, seed = 20261115): Generated {
  const rng = makeRng(seed);
  const dev = DEVICE_MAIN.device_id;
  const todayStart = Math.floor(now / DAY) * DAY;
  const t0 = todayStart - 6 * DAY; // sept jours : J-6 00:00 UTC jusqu'à maintenant
  const events: MockEvent[] = [];
  let bootId = hex(rng, 8);
  let bootStart = t0 - 3 * HOUR;

  DEVICE_MAIN.enrolled_at = new Date(t0 - 2 * DAY).toISOString();
  DEVICE_OLD.enrolled_at = new Date(now - 120 * DAY).toISOString();

  // Fenêtres sans aucun événement (téléphone éteint / agent arrêté) et sans position seulement.
  const silent: Window[] = [
    { start: todayStart - 3 * DAY + 3 * HOUR + 10 * MIN, end: todayStart - 3 * DAY + 7 * HOUR + 40 * MIN },
    { start: todayStart - 1 * DAY + 14 * HOUR, end: todayStart - 1 * DAY + 16 * HOUR + 10 * MIN },
  ];
  const nofix: Window[] = [{ start: todayStart - 2 * DAY + 18 * HOUR + 30 * MIN, end: todayStart - 2 * DAY + 19 * HOUR + 15 * MIN }];
  const inWin = (t: number, ws: Window[]) => ws.some((w) => t >= w.start && t < w.end);
  const isSilent = (t: number) => inWin(t, silent);

  const horizon = now - 20_000;
  const push = (t: number, type: string, sev: number, data: Record<string, unknown>, opts: { force?: boolean; receivedDelayMs?: number } = {}) => {
    if (t < t0 || t > horizon) return;
    if (!opts.force && isSilent(t)) return;
    const ts = new Date(t).toISOString();
    events.push({
      id: ulid(rng, t),
      ts,
      seq: 0,
      boot_id: bootId,
      elapsed_ms: Math.max(0, Math.round(t - bootStart)),
      type,
      sev,
      data,
      received_at: new Date(t + (opts.receivedDelayMs ?? Math.round(between(rng, 200, 4000)))).toISOString(),
      device_id: dev,
      t,
    });
  };

  // ---------- Plan de journée : lieux et trajets ----------
  const P = ROUTE_PLACES;
  type Leg = { from: number; to: number; kind: 'stay' | 'travel'; place?: LatLon; path?: LatLon[]; underground?: boolean; label: string };
  const legs: Leg[] = [];
  for (let d = 0; d < 7; d++) {
    const ds = t0 + d * DAY;
    const dow = new Date(ds).getUTCDay(); // 0 dimanche
    const weekend = dow === 0 || dow === 6;
    const at = (h: number, m = 0) => ds + h * HOUR + m * MIN;
    const metro = [P.home, P.bastille, P.chatelet, P.concorde, P.etoile, P.ladefense];
    const underground = d % 2 === 0;
    if (!weekend) {
      legs.push({ from: at(0), to: at(6, 50), kind: 'stay', place: P.home, label: 'domicile' });
      legs.push({ from: at(6, 50), to: at(7, 40), kind: 'travel', path: metro, underground, label: 'trajet aller' });
      legs.push({ from: at(7, 40), to: at(11, 45), kind: 'stay', place: P.ladefense, label: 'travail' });
      legs.push({ from: at(11, 45), to: at(11, 55), kind: 'travel', path: [P.ladefense, P.lunch], label: 'déjeuner' });
      legs.push({ from: at(11, 55), to: at(12, 45), kind: 'stay', place: P.lunch, label: 'déjeuner' });
      legs.push({ from: at(12, 45), to: at(12, 55), kind: 'travel', path: [P.lunch, P.ladefense], label: 'retour' });
      legs.push({ from: at(12, 55), to: at(17, 0), kind: 'stay', place: P.ladefense, label: 'travail' });
      legs.push({ from: at(17, 0), to: at(17, 50), kind: 'travel', path: [...metro].reverse(), underground, label: 'trajet retour' });
      if (dow === 5) {
        legs.push({ from: at(17, 50), to: at(19, 30), kind: 'stay', place: P.home, label: 'domicile' });
        legs.push({ from: at(19, 30), to: at(19, 42), kind: 'travel', path: [P.home, P.bar], label: 'sortie' });
        legs.push({ from: at(19, 42), to: at(23, 0), kind: 'stay', place: P.bar, label: 'bar' });
        legs.push({ from: at(23, 0), to: at(23, 12), kind: 'travel', path: [P.bar, P.home], label: 'retour' });
        legs.push({ from: at(23, 12), to: at(24), kind: 'stay', place: P.home, label: 'domicile' });
      } else legs.push({ from: at(17, 50), to: at(24), kind: 'stay', place: P.home, label: 'domicile' });
    } else if (dow === 6) {
      legs.push({ from: at(0), to: at(9, 30), kind: 'stay', place: P.home, label: 'domicile' });
      legs.push({ from: at(9, 30), to: at(10, 25), kind: 'travel', path: [P.home, P.chatelet, P.rerStop, P.versailles], label: 'vers Versailles' });
      legs.push({ from: at(10, 25), to: at(14, 30), kind: 'stay', place: P.versailles, label: 'Versailles' });
      legs.push({ from: at(14, 30), to: at(15, 25), kind: 'travel', path: [P.versailles, P.rerStop, P.chatelet, P.home], label: 'retour' });
      legs.push({ from: at(15, 25), to: at(24), kind: 'stay', place: P.home, label: 'domicile' });
    } else {
      legs.push({ from: at(0), to: at(10, 20), kind: 'stay', place: P.home, label: 'domicile' });
      legs.push({ from: at(10, 20), to: at(10, 50), kind: 'travel', path: [P.home, P.park], label: 'vers le parc' });
      legs.push({ from: at(10, 50), to: at(13, 30), kind: 'stay', place: P.park, label: 'parc' });
      legs.push({ from: at(13, 30), to: at(14, 0), kind: 'travel', path: [P.park, P.home], label: 'retour' });
      legs.push({ from: at(14, 0), to: at(24), kind: 'stay', place: P.home, label: 'domicile' });
    }
  }
  const legAt = (t: number) => legs.find((l) => t >= l.from && t < l.to);

  // ---------- Positions ----------
  const placeOf = (t: number): { pos: LatLon; moving: boolean; indoors: boolean; speed: number } | undefined => {
    const l = legAt(t);
    if (!l) return undefined;
    if (l.kind === 'stay' && l.place) {
      return {
        pos: { lat: l.place.lat + gauss(rng) * 0.00006, lon: l.place.lon + gauss(rng) * 0.00009 },
        moving: false,
        indoors: l.label !== 'parc',
        speed: 0,
      };
    }
    if (l.path) {
      const f = (t - l.from) / (l.to - l.from);
      const p = along(l.path, f);
      if (l.underground && f > 0.12 && f < 0.78) return undefined; // pas de fix sous terre
      return { pos: { lat: p.lat + gauss(rng) * 0.00003, lon: p.lon + gauss(rng) * 0.00004 }, moving: true, indoors: false, speed: between(rng, 3, 14) };
    }
    return undefined;
  };

  for (let t = t0; t <= horizon; ) {
    const l = legAt(t);
    const step = l?.kind === 'travel' ? 30_000 : l?.label === 'domicile' && new Date(t).getUTCHours() < 6 ? 30 * MIN : 10 * MIN;
    if (!inWin(t, nofix)) {
      const s = placeOf(t);
      if (s) {
        const acc = s.moving ? between(rng, 4, 18) : s.indoors ? between(rng, 18, 140) : between(rng, 6, 25);
        const provider = s.moving || !s.indoors ? 'gps' : weighted(rng, [['network', 3], ['fused', 2], ['gps', 1]] as const);
        const fixTs = t - Math.round(between(rng, 200, 1500));
        push(t, 'location.fix', 0, {
          lat: +s.pos.lat.toFixed(6),
          lon: +s.pos.lon.toFixed(6),
          acc_m: +acc.toFixed(1),
          alt_m: +between(rng, 30, 70).toFixed(1),
          speed_mps: +s.speed.toFixed(2),
          bearing_deg: Math.round(between(rng, 0, 359)),
          provider,
          mock: false,
          fix_ts: new Date(fixTs).toISOString(),
        });
      }
    }
    t += step;
  }
  push(nofix[0]!.start, 'location.provider', 1, { provider: 'gps', enabled: false });
  push(nofix[0]!.end, 'location.provider', 1, { provider: 'gps', enabled: true });

  // ---------- Heartbeats, batterie, écran ----------
  const collectors = COLLECTORS;
  let battery = 78;
  for (let t = t0; t <= horizon; t += 15 * MIN) {
    const h = new Date(t).getUTCHours();
    const charging = h >= 22 || h < 6;
    battery = Math.max(6, Math.min(100, battery + (charging ? 4 : -1.2) + gauss(rng) * 0.5));
    const afterOutage = t >= silent[1]!.end && t < silent[1]!.end + 20 * MIN;
    push(t + Math.round(between(rng, 0, 20_000)), 'agent.heartbeat', 0, {
      battery_pct: Math.round(battery),
      charging,
      uptime_ms: Math.max(0, Math.round(t - bootStart)),
      queue_depth: afterOutage ? Math.round(between(rng, 300, 620)) : Math.round(between(rng, 0, 14)),
      queue_bytes: afterOutage ? Math.round(between(rng, 300_000, 900_000)) : Math.round(between(rng, 0, 22_000)),
      dropped_total: t > silent[1]!.end ? 41 : 0,
      device_owner: true,
      collectors,
      last_upload_ts: new Date(t - Math.round(between(rng, 5_000, 70_000))).toISOString(),
    });
    if (rng() < 0.5) {
      push(t + 40_000, 'device.battery', 0, {
        pct: Math.round(battery),
        plugged: charging ? 'ac' : 'none',
        status: charging ? 'charging' : 'discharging',
        temperature_c: +between(rng, 27, 36).toFixed(1),
        health: 'good',
      });
    }
  }
  for (let t = t0; t <= horizon; t += between(rng, 25, 70) * MIN) {
    const h = new Date(t).getUTCHours();
    if (h < 6 && rng() < 0.85) continue;
    push(t, 'device.screen', 0, { state: weighted(rng, [['on', 3], ['unlocked', 3], ['off', 4]] as const) });
  }

  // ---------- Réseau : connectivité, Wi-Fi, cellulaire ----------
  const wifiHome = { ssid: 'Freebox-A1B2C3', bssid: '24:a4:3c:11:22:33', security: 'WPA3' };
  const wifiWork = { ssid: 'CORP-WIFI', bssid: '00:1a:2b:3c:4d:5e', security: 'WPA2-Enterprise' };
  let lastNet = '';
  for (let t = t0; t <= horizon; t += 5 * MIN) {
    const l = legAt(t);
    const where = l?.kind === 'travel' ? 'cell' : l?.place === P.home ? 'home' : l?.place === P.ladefense ? 'work' : 'cell';
    if (where !== lastNet) {
      lastNet = where;
      const wifi = where === 'home' ? wifiHome : where === 'work' ? wifiWork : undefined;
      if (wifi) {
        push(t, 'net.wifi', 0, { event: 'connected', ...wifi, rssi: -Math.round(between(rng, 42, 64)), freq_mhz: pick(rng, [2437, 5180, 5500]), standard: 'wifi6' });
      } else {
        push(t, 'net.wifi', 0, { event: 'disconnected', ssid: 'Freebox-A1B2C3' });
      }
      push(t + 2_000, 'net.connectivity', 0, {
        transports: wifi ? ['wifi'] : ['cellular'], validated: true, metered: !wifi, vpn: false, private_dns_active: true,
        private_dns_server: 'dns.exemple.fr', dns_servers: wifi ? ['192.168.1.1'] : ['10.1.2.3'], interface: wifi ? 'wlan0' : 'rmnet_data1',
      });
    }
    if (where === 'cell' && t % (15 * MIN) < 5 * MIN) {
      push(t, 'net.cell', 0, { tech: pick(rng, ['5G NSA', 'LTE', 'LTE']), mcc: '208', mnc: '15', tac: 24123, ci: Math.round(between(rng, 1e6, 9e6)), pci: Math.round(between(rng, 1, 500)), band: pick(rng, ['n78', 'B3', 'B7', 'B20']), signal_dbm: -Math.round(between(rng, 72, 108)), roaming: false, operator: 'Free' });
    }
  }
  push(todayStart - 2 * DAY + 18 * HOUR + 52 * MIN, 'net.cell_security', 2, { kind: 'downgrade_2g', detail: 'Rétrogradation LTE → GSM sans perte de couverture LTE (cellule 208-15-31337)' });
  push(todayStart - 1 * DAY + 9 * HOUR + 20 * MIN, 'net.ble_tracker', 2, { address: 'c4:11:22:5f:9a:0e', kind: 'unknown', rssi: -61, first_seen: new Date(todayStart - DAY + 8 * HOUR + 35 * MIN).toISOString(), sightings: 14 });
  push(todayStart - 1 * DAY + 11 * HOUR, 'net.ble_tracker', 2, { address: 'c4:11:22:5f:9a:0e', kind: 'unknown', rssi: -58, first_seen: new Date(todayStart - DAY + 8 * HOUR + 35 * MIN).toISOString(), sightings: 31 });
  for (let d = 0; d < 7; d++) {
    push(t0 + d * DAY + 8 * HOUR, 'net.bluetooth', 0, { event: 'connected', name: 'Galaxy Buds3 Pro', address: '88:ee:d6:44:55:66', type: 'headset' });
    push(t0 + d * DAY + 9 * HOUR + 10 * MIN, 'net.bluetooth', 0, { event: 'disconnected', name: 'Galaxy Buds3 Pro', address: '88:ee:d6:44:55:66', type: 'headset' });
  }
  push(todayStart - 4 * DAY + 13 * HOUR, 'net.wifi_scan', 0, {
    aps: [
      { ssid: 'CORP-WIFI', bssid: '00:1a:2b:3c:4d:5e', rssi: -52, freq_mhz: 5180, security: 'WPA2-Enterprise' },
      { ssid: 'eduroam', bssid: '00:1a:2b:3c:4d:5f', rssi: -66, freq_mhz: 2437, security: 'WPA2-Enterprise' },
      { ssid: 'FreeWifi_secure', bssid: 'de:ad:be:ef:00:01', rssi: -78, freq_mhz: 2412, security: 'WPA2' },
    ],
  });

  // ---------- DNS, connexions, volumes ----------
  const dnsApps = APPS.filter((a) => a.dnsWeight > 0).map((a) => [a, a.dnsWeight] as const);
  const hostFor = (a: MockApp) => weighted(rng, a.hosts.map(([h, w]) => [h, w] as const));
  const addrOf = (host: string) => {
    let h = 0;
    for (const c of host) h = (h * 33 + c.charCodeAt(0)) | 0;
    return `${[142, 172, 31, 157, 104, 52, 34][Math.abs(h) % 7]}.${Math.abs(h >> 4) % 250}.${Math.abs(h >> 12) % 250}.${(Math.abs(h >> 20) % 250) + 1}`;
  };
  const usageByHour = new Map<number, Map<string, { rx: number; tx: number; transport: string }>>();
  for (let hStart = Math.floor(t0 / HOUR) * HOUR; hStart <= horizon; hStart += HOUR) {
    const hod = new Date(hStart).getUTCHours();
    const level = hod < 6 ? 0.12 : hod < 8 ? 0.6 : hod < 23 ? 1 : 0.3;
    const n = Math.round(between(rng, 45, 120) * level);
    const where = legAt(hStart + 30 * MIN);
    const transport = where?.kind === 'travel' || where?.label === 'Versailles' || where?.label === 'parc' ? 'cellular' : 'wifi';
    for (let i = 0; i < n; i++) {
      const t = hStart + Math.floor(rng() * HOUR);
      const app = weighted(rng, dnsApps);
      if (app.package === 'com.fastcleaner.pro' && t < todayStart - 5 * DAY) continue;
      if (app.package === 'io.github.erwsim.vigie' && t < todayStart - 5 * DAY) continue;
      const host = hostFor(app);
      const addrs = [addrOf(host)];
      push(t, 'net.dns', 0, { package: app.package, uid: 10000 + (app.package.length * 37) % 400, hostname: host, addresses: addrs, address_count: addrs.length });
      if (rng() < 0.55) {
        push(t + Math.round(between(rng, 50, 900)), 'net.connect', 0, { package: app.package, uid: 10000 + (app.package.length * 37) % 400, ip: addrs[0], port: weighted(rng, [[443, 9], [80, 1], [5228, 1.5], [853, 0.3]] as const) });
      }
    }
    // Volumes horaires (net.usage)
    const m = new Map<string, { rx: number; tx: number; transport: string }>();
    for (const a of APPS) {
      if (a.mibPerHour <= 0) continue;
      const chance = Math.min(1, level * (a.mibPerHour > 30 ? 0.25 : 0.7));
      if (rng() > chance) continue;
      const mib = a.mibPerHour * between(rng, 0.2, 1.8) * level;
      const rx = Math.round(mib * 1048576 * 0.88);
      const tx = Math.round(mib * 1048576 * 0.12);
      m.set(a.package, { rx, tx, transport });
    }
    usageByHour.set(hStart, m);
    const hEnd = hStart + HOUR;
    if (hEnd <= horizon) {
      push(hEnd + 30_000, 'net.usage', 0, {
        from: new Date(hStart).toISOString(),
        to: new Date(hEnd).toISOString(),
        apps: [...m.entries()].map(([pkg, v]) => ({ package: pkg, uid: 10000 + (pkg.length * 37) % 400, rx_bytes: v.rx, tx_bytes: v.tx, transport: v.transport })),
      });
    }
  }

  // ---------- Applications ----------
  const inventory = (t: number) => {
    const apps = ALL_APPS.map((a) => ({
      package: a.package,
      label: a.label,
      version_name: a.version_name,
      version_code: 100000 + a.package.length * 111,
      installer: a.installer,
      system: a.system,
      enabled: a.enabled ?? true,
      suspended: a.suspended ?? false,
      hidden: false,
      target_sdk: a.system ? 36 : 35,
      first_install: new Date(t - a.firstInstallDaysAgo * DAY).toISOString(),
      last_update: new Date(t - a.lastUpdateDaysAgo * DAY).toISOString(),
      signer_sha256: hex(makeRng(a.package.length * 7919 + a.package.charCodeAt(4)), 32),
      granted_dangerous: a.perms,
    }));
    const parts = Math.ceil(apps.length / 20);
    for (let i = 0; i < parts; i++) {
      push(t + i * 2_000, 'app.inventory', 0, { part: i + 1, parts, apps: apps.slice(i * 20, (i + 1) * 20) });
    }
  };
  for (let d = 0; d < 7; d++) inventory(t0 + d * DAY + 4 * HOUR + 5 * MIN);
  push(todayStart - 5 * DAY + 11 * HOUR + 2 * MIN, 'app.installed', 1, { package: 'com.fastcleaner.pro', version_name: '3.2.1', version_code: 321, signer_sha256: hex(rng, 32) });
  push(todayStart - 5 * DAY + 11 * HOUR + 2 * MIN + 20_000, 'app.permission_changed', 2, { package: 'com.fastcleaner.pro', permission: 'android.permission.RECORD_AUDIO', granted: true });
  push(todayStart - 5 * DAY + 11 * HOUR + 2 * MIN + 30_000, 'app.permission_changed', 2, { package: 'com.fastcleaner.pro', permission: 'android.permission.READ_SMS', granted: true });
  push(todayStart - 6 * DAY + 10 * HOUR, 'app.installed', 1, { package: 'org.fdroid.fdroid', version_name: '1.21.1', version_code: 1021001, installer: 'com.android.shell', signer_sha256: hex(rng, 32) });
  for (const [d, pkg, ver] of [[4, 'com.whatsapp', '2.25.33.76'], [3, 'com.android.chrome', '142.0.7444.102'], [2, 'com.spotify.music', '9.0.96.1022'], [1, 'com.google.android.gms', '25.44.31'], [0, 'io.github.erwsim.vigie', '1.0.0']] as const) {
    push(todayStart - d * DAY + 2 * HOUR + Math.round(rng() * HOUR), 'app.updated', 0, { package: pkg, version_name: ver, version_code: 100000 + pkg.length * 111, installer: 'com.android.vending', signer_sha256: hex(makeRng(pkg.length), 32) });
  }
  push(todayStart - 3 * DAY + 20 * HOUR, 'app.removed', 1, { package: 'com.old.flashlight', version_name: '2.0', installer: 'com.android.vending' });
  push(todayStart - 4 * DAY + 20 * HOUR, 'app.permission_changed', 1, { package: 'com.instagram.android', permission: 'android.permission.ACCESS_FINE_LOCATION', granted: false });
  const specialAccess = (t: number, extra = false) =>
    push(t, 'app.special_access', extra ? 2 : 0, {
      accessibility_services: ['com.google.android.marvin.talkback/.TalkBackService', ...(extra ? ['com.fastcleaner.pro/.CleanerAccessibilityService'] : [])],
      notification_listeners: ['com.samsung.android.app.watchmanager/.NotificationService', ...(extra ? ['com.fastcleaner.pro/.NotifListener'] : [])],
      device_admins: ['io.github.erwsim.vigie/.admin.AdminReceiver'],
      overlay_apps: ['com.facebook.orca', ...(extra ? ['com.fastcleaner.pro'] : [])],
      unknown_sources_apps: ['org.fdroid.fdroid', ...(extra ? ['com.fastcleaner.pro'] : [])],
      usage_access_apps: ['com.samsung.android.forest', 'io.github.erwsim.vigie'],
      vpn_apps: [],
      default_apps: { browser: 'com.android.chrome', sms: 'com.samsung.android.messaging', dialer: 'com.samsung.android.dialer', launcher: 'com.sec.android.app.launcher', assistant: 'com.google.android.googlequicksearchbox' },
    });
  for (let d = 0; d < 7; d++) specialAccess(t0 + d * DAY + 4 * HOUR + 8 * MIN, t0 + d * DAY >= todayStart - 5 * DAY + 11 * HOUR);
  specialAccess(todayStart - 5 * DAY + 11 * HOUR + 3 * MIN, true);
  for (let i = 0; i < 160; i++) {
    const t = t0 + rng() * (horizon - t0);
    const app = pick(rng, APPS);
    push(t, 'app.foreground', 0, { package: app.package, class: `${app.package}.MainActivity`, event: pick(rng, ['resumed', 'paused']) });
  }
  for (let i = 0; i < 90; i++) {
    const t = t0 + rng() * (horizon - t0);
    const app = pick(rng, APPS.filter((a) => ['com.whatsapp', 'org.thoughtcrime.securesms', 'com.google.android.gm', 'com.facebook.katana', 'com.spotify.music'].includes(a.package)));
    push(t, 'app.notification', 0, { package: app.package, event: pick(rng, ['posted', 'removed']), category: pick(rng, ['msg', 'email', 'social', 'transport']), channel: 'default', ongoing: false });
  }

  // ---------- Capteurs ----------
  const sensorSession = (t: number, kind: 'camera' | 'mic', pkg: string, durMs: number, sev = 0) => {
    if (kind === 'camera') {
      push(t, 'sensor.camera', sev, { camera_id: '0', in_use: true, package: pkg });
      push(t + durMs, 'sensor.camera', 0, { camera_id: '0', in_use: false, package: pkg });
    } else {
      push(t, 'sensor.microphone', sev, { recording: true, source: 'voice_communication', package: pkg, silenced: false });
      push(t + durMs, 'sensor.microphone', 0, { recording: false, source: 'voice_communication', package: pkg, silenced: false });
    }
  };
  for (let d = 0; d < 7; d++) {
    sensorSession(t0 + d * DAY + 12 * HOUR + Math.round(rng() * HOUR), 'camera', 'com.sec.android.app.camera', 40_000);
    if (d % 2 === 0) sensorSession(t0 + d * DAY + 18 * HOUR + Math.round(rng() * HOUR), 'mic', 'com.whatsapp', 8 * MIN);
  }
  sensorSession(todayStart - 5 * DAY + 3 * HOUR + 12 * MIN, 'mic', 'com.fastcleaner.pro', 95_000, 2);
  sensorSession(todayStart - 4 * DAY + 2 * HOUR + 41 * MIN, 'mic', 'com.fastcleaner.pro', 140_000, 2);
  sensorSession(todayStart - 2 * DAY + 20 * HOUR, 'camera', 'org.thoughtcrime.securesms', 5 * MIN);

  // ---------- Sécurité ----------
  const base = {
    security_patch: '2026-09-01', encrypted: true, lock_secure: true, adb_enabled: false, adb_wifi_enabled: false, dev_options: false,
    unknown_sources: true, private_dns_mode: 'hostname', private_dns_host: 'dns.exemple.fr', always_on_vpn: false, device_owner: true,
    verified_boot_state: 'green', user_ca_certs: [] as string[], play_protect: true, usb_data_signaling: false,
  };
  const caFp = hex(makeRng(77), 32);
  const postureAt = (t: number) => {
    const age = Math.floor((t - Date.parse('2026-09-01T00:00:00Z')) / DAY);
    let s = { ...base, patch_age_days: age };
    if (t >= todayStart - 4 * DAY + 14 * HOUR && t < todayStart - 3 * DAY + 9 * HOUR) s = { ...s, dev_options: true, adb_enabled: true };
    if (t >= todayStart - 5 * DAY + 11 * HOUR + 5 * MIN && t < todayStart - 4 * DAY + 16 * HOUR) s = { ...s, user_ca_certs: [caFp] };
    if (t < todayStart - 5 * DAY) s = { ...s, play_protect: true, private_dns_mode: 'opportunistic', private_dns_host: '' };
    return s;
  };
  const postureTimes = [t0 + 4 * HOUR + 10 * MIN, todayStart - 5 * DAY + 11 * HOUR + 5 * MIN, todayStart - 4 * DAY + 14 * HOUR + MIN, todayStart - 4 * DAY + 16 * HOUR, todayStart - 3 * DAY + 9 * HOUR + 5 * MIN, todayStart - 5 * DAY + 5 * HOUR];
  for (let d = 1; d < 7; d++) postureTimes.push(t0 + d * DAY + 4 * HOUR + 10 * MIN);
  for (const t of postureTimes) push(t, 'security.posture', 0, postureAt(t));
  push(todayStart - 5 * DAY + 11 * HOUR + 4 * MIN, 'security.ca_cert', 2, { event: 'added', sha256: caFp, subject: 'CN=Free Proxy Root CA, O=Free Proxy Ltd' });
  push(todayStart - 4 * DAY + 16 * HOUR, 'security.ca_cert', 2, { event: 'removed', sha256: caFp, subject: 'CN=Free Proxy Root CA, O=Free Proxy Ltd' });
  const kg = todayStart - 2 * DAY + 23 * HOUR + 50 * MIN;
  push(kg, 'security.keyguard', 2, { event: 'unlock_failed', failed_attempts: 1 });
  push(kg + 9_000, 'security.keyguard', 2, { event: 'unlock_failed', failed_attempts: 2 });
  push(kg + 21_000, 'security.keyguard', 3, { event: 'unlock_failed', failed_attempts: 3 });
  push(kg + 45_000, 'security.keyguard', 0, { event: 'unlock_succeeded', failed_attempts: 0 });
  push(todayStart - 6 * DAY + 14 * HOUR, 'security.keyguard', 2, { event: 'unlock_failed', failed_attempts: 1 });
  const logTags: [string, Record<string, unknown>][] = [
    ['keyguard_dismissed', {}],
    ['keyguard_dismiss_auth_attempt', { success: 1, strength: 1 }],
    ['adb_shell_command', { command: 'pm list packages' }],
    ['app_process_start', { name: 'com.whatsapp', start_time: 123456, uid: 10201, pid: 8841, seinfo: 'default' }],
    ['key_generated', { success: 1, key_id: 'vigie_client_key', uid: 10250 }],
    ['media_mount', { mount_point: '/storage/emulated', volume_label: 'internal' }],
    ['crypto_self_test_completed', { result: 1 }],
    ['user_restriction_set', { admin_package: 'io.github.erwsim.vigie', restriction: 'no_debugging_features' }],
    ['password_complexity_required', { admin_package: 'io.github.erwsim.vigie', complexity: 3 }],
  ];
  for (let i = 0; i < 140; i++) {
    const t = t0 + rng() * (horizon - t0);
    const [tag, fields] = pick(rng, logTags);
    push(t, 'security.log', tag === 'adb_shell_command' ? 1 : 0, { tag, level: 3, log_id: 1000 + i, fields });
  }
  push(todayStart - 4 * DAY + 14 * HOUR + 2 * MIN, 'security.log', 2, { tag: 'adb_shell_interactive', level: 4, log_id: 2201, fields: {} });
  push(todayStart - 4 * DAY + 14 * HOUR + 3 * MIN, 'security.log', 1, { tag: 'adb_shell_command', level: 4, log_id: 2202, fields: { command: 'dpm list-owners' } });
  push(todayStart - 5 * DAY + 11 * HOUR + 4 * MIN, 'security.log', 2, { tag: 'cert_authority_installed', level: 4, log_id: 2210, fields: { success: 1, subject: 'CN=Free Proxy Root CA' } });
  const policy = (t: number, data: Record<string, unknown>, sev = 0) => push(t, 'security.policy', sev, { ok: true, ...data });
  const polStart = t0 + 5 * HOUR;
  policy(polStart, { action: 'private_dns_set', target: 'dns.exemple.fr', profile: 'balanced' });
  policy(polStart + 1_000, { action: 'network_logging', target: 'on' });
  policy(polStart + 2_000, { action: 'security_logging', target: 'on' });
  policy(polStart + 3_000, { action: 'restriction_set', target: 'no_install_unknown_sources_globally', profile: 'balanced' });
  ['com.samsung.android.bixby.agent', 'com.samsung.android.arzone', 'com.facebook.appmanager', 'com.facebook.services', 'com.samsung.android.aremoji', 'com.samsung.android.scloud'].forEach((p, i) => policy(polStart + 4_000 + i * 700, { action: 'package_disabled', target: p, profile: 'balanced' }));
  policy(polStart + 10_000, { action: 'package_disabled', target: 'com.samsung.android.rubin.app', profile: 'strict', ok: false, error: 'SecurityException: package protected by profile balanced' }, 1);
  policy(todayStart - 3 * DAY + 9 * HOUR + 30 * MIN, { action: 'permission_denied', target: 'com.instagram.android:ACCESS_FINE_LOCATION', profile: 'balanced' });
  policy(todayStart - 1 * DAY + 10 * HOUR, { action: 'package_enabled', target: 'com.samsung.android.arzone', profile: 'balanced' });
  policy(todayStart - 1 * DAY + 10 * HOUR + 4 * MIN, { action: 'package_disabled', target: 'com.samsung.android.arzone', profile: 'balanced' });

  // ---------- Agent et appareil ----------
  push(t0 + 5 * HOUR - 30_000, 'agent.started', 0, { reason: 'boot', agent_version: '1.0.0' });
  const [sd, sd2] = silent as [Window, Window];
  push(sd.start - 3_000, 'agent.stopped', 1, { reason: 'shutdown', agent_version: '1.0.0' }, { force: true });
  push(sd.start - 2_000, 'device.shutdown', 0, { reason: 'userrequested' }, { force: true });
  bootId = hex(rng, 8);
  bootStart = sd.end - 40_000;
  push(sd.end + 5_000, 'device.boot', 0, { reason: 'cold' }, { force: true });
  push(sd.end + 20_000, 'agent.started', 0, { reason: 'boot', agent_version: '1.0.0' }, { force: true });
  push(sd.end + 25_000, 'device.inventory', 0, { manufacturer: 'samsung', model: 'SM-S936B', android_release: '16', sdk_int: 36, security_patch: '2026-09-01', build_fingerprint: 'samsung/e2sxeea/e2s:16/BP2A.250605.031.A3/S936BXXS3AYI2:user/release-keys', one_ui: '8.0', kernel: '6.6.77-android15-8-abS936BXXS3AYI2', bootloader: 'S936BXXS3AYI2', verified_boot_state: 'green', total_storage_bytes: 256_000_000_000, total_ram_bytes: 12_000_000_000 }, { force: true });
  push(sd2.end + 8_000, 'agent.tamper', 3, { kind: 'force_stop_detected', detail: "Arrêt forcé de l'agent détecté (aucune pulsation pendant 2 h 10 min)" }, { force: true });
  push(sd2.end + 12_000, 'agent.started', 0, { reason: 'restart_after_force_stop', agent_version: '1.0.0' }, { force: true });
  push(sd2.end + 40_000, 'agent.buffer_overflow', 2, { dropped: 41, oldest_ts: new Date(sd2.start - 8 * MIN).toISOString(), newest_ts: new Date(sd2.start - 2 * MIN).toISOString() }, { force: true });
  push(todayStart - 2 * DAY + 12 * HOUR, 'agent.collector_error', 1, { collector: 'ble_tracker', error: 'BLUETOOTH_SCAN permission denied' });
  push(todayStart - 3 * DAY + 10 * HOUR, 'agent.config_changed', 0, { key: 'collector.net_dns', old: false, new: true });
  push(todayStart - 1 * DAY + 20 * HOUR, 'agent.config_changed', 0, { key: 'upload.wifi_only_large', old: false, new: true });
  for (let d = 0; d < 7; d++) {
    push(t0 + d * DAY + 4 * HOUR + 12 * MIN, 'device.storage', 0, { free_bytes: 118_000_000_000 - d * 400_000_000, total_bytes: 256_000_000_000 });
    if (d % 3 === 0) push(t0 + d * DAY + 4 * HOUR + 15 * MIN, 'device.inventory', 0, { manufacturer: 'samsung', model: 'SM-S936B', android_release: '16', sdk_int: 36, security_patch: '2026-09-01', one_ui: '8.0', kernel: '6.6.77-android15-8', verified_boot_state: 'green', total_storage_bytes: 256_000_000_000, total_ram_bytes: 12_000_000_000 });
  }
  push(todayStart - 2 * DAY + 15 * HOUR, 'device.thermal', 1, { status: 'moderate' });
  push(todayStart - 6 * DAY + 20 * HOUR, 'device.power_save', 0, { enabled: true });
  push(todayStart - 6 * DAY + 22 * HOUR, 'device.power_save', 0, { enabled: false });
  push(todayStart - 5 * DAY + 8 * HOUR, 'device.timezone_changed', 0, { tz: 'Europe/Paris' });
  push(todayStart - 3 * DAY + 14 * HOUR, 'device.usb', 0, { connected: true, configured: true, functions: ['adb'] });
  push(todayStart - 3 * DAY + 14 * HOUR + 12 * MIN, 'device.usb', 0, { connected: false, configured: false, functions: [] });
  push(todayStart - 3 * DAY + 8 * HOUR, 'net.hotspot', 0, { enabled: false });
  push(todayStart - 1 * DAY + 13 * HOUR, 'net.nfc', 0, { enabled: true });
  // Un type inconnu du catalogue : l'interface doit afficher le JSON brut sans planter.
  push(todayStart - 1 * DAY + 17 * HOUR, 'experimental.future_probe', 1, { weird: { nested: [1, 2, { x: null }] }, note: 'type hors catalogue' });
  // Un événement dont `data` est partiel.
  push(todayStart - 1 * DAY + 17 * HOUR + 5 * MIN, 'location.fix', 0, { lat: 48.86 });
  push(todayStart - 1 * DAY + 17 * HOUR + 6 * MIN, 'net.dns', 0, {});

  // Tri chronologique + numéros de séquence.
  events.sort((a, b) => a.t - b.t || (a.id < b.id ? -1 : 1));
  events.forEach((e, i) => (e.seq = 18000 + i));
  return { events, silent, nofix, devices: [DEVICE_MAIN, DEVICE_OLD], appCount: ALL_APPS.length };
}

/** Génère un événement « en direct » pour le flux SSE. */
export function liveEvent(rng: Rng, t: number, seq: number, bootId: string, lastPos: LatLon): MockEvent {
  const dev = DEVICE_MAIN.device_id;
  const kind = weighted(rng, [['dns', 9], ['connect', 4], ['loc', 2], ['hb', 0.6], ['sec', 0.5], ['cat', 0.2]] as const);
  let type = 'net.dns';
  let sev = 0;
  let data: Record<string, unknown>;
  const app = weighted(rng, APPS.filter((a) => a.dnsWeight > 0).map((a) => [a, a.dnsWeight] as const));
  if (kind === 'dns') {
    const host = weighted(rng, app.hosts.map(([h, w]) => [h, w] as const));
    data = { package: app.package, uid: 10100, hostname: host, addresses: ['142.250.74.202'], address_count: 1 };
  } else if (kind === 'connect') {
    type = 'net.connect';
    data = { package: app.package, uid: 10100, ip: '142.250.74.202', port: 443 };
  } else if (kind === 'loc') {
    type = 'location.fix';
    lastPos.lat += gauss(rng) * 0.00002;
    lastPos.lon += gauss(rng) * 0.00003;
    data = { lat: +lastPos.lat.toFixed(6), lon: +lastPos.lon.toFixed(6), acc_m: +between(rng, 8, 60).toFixed(1), speed_mps: 0, provider: 'fused', mock: false, fix_ts: new Date(t).toISOString() };
  } else if (kind === 'hb') {
    type = 'agent.heartbeat';
    data = { battery_pct: Math.round(between(rng, 40, 90)), charging: false, uptime_ms: 123456789, queue_depth: Math.round(between(rng, 0, 12)), queue_bytes: Math.round(between(rng, 0, 20000)), dropped_total: 41, device_owner: true, collectors: COLLECTORS, last_upload_ts: new Date(t - 30_000).toISOString() };
  } else if (kind === 'sec') {
    type = 'security.log';
    sev = 1;
    data = { tag: 'keyguard_dismiss_auth_attempt', level: 3, log_id: Math.round(rng() * 1e5), fields: { success: 1 } };
  } else {
    type = 'net.cell_security';
    sev = 2;
    data = { kind: 'identifier_disclosure', detail: 'Demande d’identité (IMSI) en clair reçue de la cellule 208-15-4412' };
  }
  return { id: ulid(rng, t), ts: new Date(t).toISOString(), seq, boot_id: bootId, elapsed_ms: 123456789, type, sev, data, received_at: new Date(t + 300).toISOString(), device_id: dev, t };
}
