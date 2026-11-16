// Detections (contract §11.3): translation of the types, "what was observed" sentence, evidence items,
// explanations and what to do, aggregations. Pure functions.
//
// The contract does not fix the keys of `evidence`: each reading tries a few plausible names and the sentence
// falls back on the collector's `summary` when the evidence is not enough. Everything that comes from the phone or
// the network (names of applications, packages, domains) is text: never interpreted.
import type { DataObject, Detection, DetectionMute, WatchpostEvent } from '../api/types.ts';
import { isRecord } from './data.ts';
import { fmtBytes, fmtDate, fmtNumber, fmtTime, parseTs } from './format.ts';
import { cleanText } from './text.ts';
import { opInfo } from './ops.ts';
import { levelInfo, reasonInfo } from './risk.ts';
import { roleLabel } from './roles.ts';

export const DETECTION_TYPES = [
  'detect.threat_domain',
  'detect.upload_spike',
  'detect.fanout',
  'detect.mail_ports',
  'detect.dns_bypass',
  'detect.sms_abuse',
  'detect.sensor_background',
  'detect.new_app_risky',
  // §11.4: detections that do not depend on `app.ops`
  'detect.sms_permission',
  'detect.default_app_changed',
  'detect.flood',
  'detect.inventory_mismatch',
] as const;

export type DetectionType = (typeof DETECTION_TYPES)[number];

export function isDetectionType(t: string): boolean {
  return t.startsWith('detect.');
}

export interface TypeInfo {
  label: string;
  /** why it is suspicious */
  why: string;
  /** possible innocent explanations */
  innocent: string[];
  /** what to do (without the links, added by the screen) */
  actions: string[];
  /** agent guard that answers this risk (contract §11.1) */
  guard?: string;
  /** the detection carries domains: offer blocking in Tracking */
  domains?: boolean;
  /** it is a review ("is this intended?") and not the observation of a behaviour */
  review?: boolean;
  /** can be muted (§11.4); false for `sms_abuse`, `default_app_changed` and `flood` (no application) */
  mutable?: boolean;
}

const TYPES: Record<DetectionType, TypeInfo> = {
  'detect.threat_domain': {
    label: 'Threat-list domain',
    why: 'AdGuard Home blocks lists of known threats (phishing, malware, command-and-control servers). An application trying to reach these domains is a classic sign of infection: it is looking for its command server or a fraud site. The block worked and the request did not go through, but the application tried.',
    innocent: [
      'A legitimate domain wrongly added to a list, or recently bought by someone else.',
      'A dubious advertising library embedded in an otherwise honest application.',
      'A suspicious link that you opened yourself in a browser or a messaging app.',
    ],
    actions: [
      "Look at the application's risk profile on its detail page.",
      'In Tracking, check that the domain is indeed blocked, and block it by hand if it is not.',
      'Uninstall the application if you did not choose it or do not use it.',
    ],
    domains: true,
  },
  'detect.upload_spike': {
    label: 'Unusual data upload',
    why: "A volume sent far above the usual can be a leak (photos, contacts, messages) or the application being used as a relay. Watchpost compares it with the application's hourly median over 14 days.",
    innocent: [
      'You sent a video or photos, or started a cloud backup.',
      'First use after installation or update: initial synchronisation.',
    ],
    actions: [
      'Remember what you were doing at that time (backup, video sharing).',
      "Look in Network at the destinations the application contacted.",
      "If nothing explains it, revoke the application's access to data or uninstall it.",
    ],
  },
  'detect.fanout': {
    label: 'Connections to a very large number of addresses',
    why: 'Talking to hundreds of different addresses within an hour is unusual for an ordinary application: network scanning, participation in a botnet, unwanted peer-to-peer, or a relay for a mass mailing.',
    innocent: [
      'A browser, a video player or a game that fetches content from many servers.',
      'A peer-to-peer client (BitTorrent) that you use on purpose.',
    ],
    actions: [
      "Open the application's detail page: risk profile and contacted domains.",
      'If you do not recognise it, uninstall it.',
    ],
  },
  'detect.mail_ports': {
    label: 'Connection to a mail server',
    why: 'Ports 25, 465 and 587 are used to send mail. An application that is not a known mail client and that connects to them may be sending spam or phishing from your connection.',
    innocent: [
      'A little-known mail, invoicing or backup application that you configured yourself.',
      'An administration or development tool.',
    ],
    actions: [
      'Check that you configured a mail account in this application.',
      'Otherwise, uninstall it and look at its domains in Tracking.',
    ],
  },
  'detect.dns_bypass': {
    label: "Bypass of the phone's DNS",
    why: "By contacting a public DNS resolver directly (DNS-over-HTTPS or DNS-over-TLS) or addresses never requested through the phone's DNS, the application avoids AdGuard Home's filters and Watchpost's visibility of domains. Malware does this so as not to be blocked.",
    innocent: [
      'A browser with "secure DNS" enabled or a privacy application.',
      'An application that contains hard-coded IP addresses (game, connected camera, enterprise application).',
    ],
    actions: [
      'Check on its detail page whether the application has a high risk profile.',
      'Uninstall the application if it has no legitimate reason to bypass DNS.',
    ],
  },
  'detect.sms_abuse': {
    label: 'Abnormal SMS sending',
    why: 'Malware can send thousands of SMS messages (phishing, premium-rate numbers) without displaying anything. Sending SMS from an application other than your messaging app is abnormal, and a high volume costs money, exposes your number and can get it blocked by the carrier.',
    innocent: [
      'An application you gave this right to: verification code, alarm, ride-sharing, delivery.',
      'An alternative SMS application that is not the one set as default.',
    ],
    actions: [
      'Uninstall the application right away if you did not authorise it to send SMS.',
      'Remove its SMS permission in Settings, Apps.',
      'Check your bill and your sent SMS with your carrier.',
    ],
    guard: 'sms',
    mutable: false,
  },
  'detect.sensor_background': {
    label: 'Microphone or camera in the background',
    why: "The microphone or camera used while the application is not on screen: listening or taking pictures without your knowledge, as spyware does.",
    innocent: [
      'A call or a video conference in progress, reduced to a floating window.',
      'A voice recorder, a voice assistant or a music recognition that you started.',
    ],
    actions: [
      'Remember what you were doing at that time.',
      "Remove the application's microphone or camera permission, or uninstall it if you do not know it.",
      'See the Security page, Camera and microphone tab.',
    ],
  },
  'detect.new_app_risky': {
    label: 'Recent risky application',
    why: 'An application with a high risk from its installation (for example SMS, automatic start, installation outside a store), or a very recent application that obtains a sensitive capability, is the signature of malware that has just been installed.',
    innocent: [
      'An application from outside a store that you installed on purpose (F-Droid, enterprise application, technical tool).',
      'A legitimate application that asks for a lot of permissions.',
    ],
    actions: [
      "Read the reasons of the risk profile on the application's detail page.",
      'Uninstall it if you do not recognise it.',
    ],
    guard: 'quarantine',
  },
  'detect.sms_permission': {
    label: 'SMS sending permission to review',
    why: 'This application holds the right to send SMS without going through your messaging app, although it is neither the default SMS app nor a system application. This is a review, not proof of abuse: SMS fraud software needs this right, and Watchpost does not see the sending itself without the experimental "Sensitive operations usage" collector. Only one review per application, at the first observation.',
    innocent: [
      'An application you chose for this: verification code, alarm, ride-sharing, delivery, bank.',
      'An alternative messaging app installed next to the default one.',
      'A right already present when Watchpost was installed (initial inventory), without the application having done anything.',
    ],
    actions: [
      'Ask yourself whether this is intended: does this application have a reason to send SMS?',
      'If not: remove its SMS permission (Settings, Apps) or uninstall it.',
      'If so: nothing to do, or mute this review for this application.',
      'In every case, the real protection is the Watchpost app\'s SMS guard: it refuses SMS sending to all applications except your list.',
    ],
    guard: 'sms',
    review: true,
  },
  'detect.default_app_changed': {
    label: 'Default application changed',
    why: "The default application of a sensitive role (SMS, phone, keyboard, assistant) has changed. For the SMS role, this is the classic route of SMS trojans: getting designated as the default SMS app gives them sending, reading and interception of SMS, and bypasses permission refusals. For the dialer, the keyboard or the assistant, the new application sees calls, typing or the screen.",
    innocent: [
      'You just installed another messaging app, another dialer or another keyboard and chose it yourself.',
      'An Android update or reset that restored the default choice.',
    ],
    actions: [
      'Remember whether you made this choice. If not: Settings, Apps, Default apps: put the previous application back.',
      "Open the new application's detail page: risk profile and reasons.",
      'Uninstall it if you do not recognise it.',
    ],
    guard: 'sms',
    mutable: false,
  },
  'detect.flood': {
    label: 'Too many detections in one day',
    why: 'Beyond 200 detections per device per day, the collector keeps only one more, this one. Such a volume is not normal: the device is sending inconsistent data (faulty agent, wrong clock) or it is compromised and someone is fabricating events to drown the real alerts.',
    innocent: [
      "An agent fault or a phone clock that is far off.",
      'The catch-up of a very long history sent all at once after an interruption.',
    ],
    actions: [
      "Look at the device's state on the Overview (lost events, collectors in error) and the event log of the day.",
      'If nothing explains it, consider the phone compromised: change the command passphrase in the app and, if needed, revoke the device then enroll it again (collector command line).',
    ],
    mutable: false,
  },
  'detect.inventory_mismatch': {
    label: 'Application wrongly declared "system"',
    why: 'The inventory declares "system" an application whose installer or history show that it was installed. System applications are scored with a risk capped at low and spared by some guards: posing as a system application allows escaping the risk profile and the guards of the Watchpost app.',
    innocent: [
      'A preinstalled application updated from a store, whose installer changed.',
      'A phone whose inventory is incomplete after a restart or a reinstallation of the agent.',
    ],
    actions: [
      "Open the application's detail page: installer, signature, installation date.",
      'If you do not recognise it as an application of your phone, uninstall it.',
    ],
    mutable: false,
  },
};

/** Fallback information for a type unknown to this version of the console. */
const UNKNOWN: TypeInfo = {
  label: '',
  why: "This detection type is not known to this version of the console: the collector's description and evidence are displayed as they are.",
  innocent: [],
  actions: ['Look at the detail page of the application concerned, if it is known.'],
};

export function typeInfo(type: string): TypeInfo {
  const e = Object.prototype.hasOwnProperty.call(TYPES, type) ? TYPES[type as DetectionType] : undefined;
  return e ?? { ...UNKNOWN, label: type };
}

/** Types that can never be muted (§11.4): `sms_abuse`, `default_app_changed`; `flood` has no application. */
export function isMutable(d: Pick<Detection, 'type' | 'package'>): boolean {
  return !!d.package && typeInfo(d.type).mutable !== false && d.type !== 'detect.muted' && d.type !== 'detect.unmuted';
}

/** Server events of muting: these are not detections (§11.4). */
export function isMuteEvent(type: string): boolean {
  return type === 'detect.muted' || type === 'detect.unmuted';
}

export function detectionLabel(type: string): string {
  return typeInfo(type).label;
}

// ------------------------------------------------------------------------------------------- severity

/** Severity on the 0 to 3 scale of events; also accepts a word (`low`, `medium`, `high`, `critical`). */
export function normSeverity(v: unknown): number {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.max(0, Math.min(3, Math.trunc(v)));
  if (typeof v === 'string') {
    switch (v.toLowerCase()) {
      case 'info':
        return 0;
      case 'low':
        return 1;
      case 'medium':
        return 2;
      case 'high':
      case 'critical':
        return 3;
      default: {
        const n = Number(v);
        return Number.isFinite(n) ? Math.max(0, Math.min(3, Math.trunc(n))) : 0;
      }
    }
  }
  return 0;
}

export interface SeverityCounts {
  critical: number;
  warning: number;
  notable: number;
  info: number;
  total: number;
}

/** Number of detections by severity: 3 critical, 2 warning, 1 notable, 0 info. */
export function countBySeverity(all: readonly { severity: number; muted?: boolean | undefined }[]): SeverityCounts {
  const list = all.filter((d) => !d.muted);
  const c: SeverityCounts = { critical: 0, warning: 0, notable: 0, info: 0, total: list.length };
  for (const d of list) {
    const s = normSeverity(d.severity);
    if (s >= 3) c.critical++;
    else if (s === 2) c.warning++;
    else if (s === 1) c.notable++;
    else c.info++;
  }
  return c;
}

// ------------------------------------------------------------------------------------- API reading

function isoOrUndef(v: unknown): string | undefined {
  return typeof v === 'string' && parseTs(v) ? v : undefined;
}

/** Normalises an item of `GET /detections`; undefined if the identifier, the time or the type is missing. */
export function normalizeDetection(raw: unknown): Detection | undefined {
  if (!isRecord(raw)) return undefined;
  const id = raw['id'];
  const ts = raw['ts'];
  const type = raw['type'];
  if (typeof id !== 'string' || id === '' || typeof type !== 'string' || type === '' || typeof ts !== 'string') return undefined;
  const ev = isRecord(raw['evidence']) ? raw['evidence'] : {};
  const d: Detection = { id, ts, type, severity: normSeverity(raw['severity'] ?? raw['sev']), evidence: ev };
  if (typeof raw['package'] === 'string' && raw['package'] !== '') d.package = raw['package'];
  if (typeof raw['label'] === 'string' && raw['label'] !== '') d.label = raw['label'];
  if (typeof raw['summary'] === 'string' && raw['summary'] !== '') d.summary = raw['summary'];
  const wf = isoOrUndef(raw['window_from']) ?? isoOrUndef(ev['window_from']);
  const wt = isoOrUndef(raw['window_to']) ?? isoOrUndef(ev['window_to']);
  if (wf) d.window_from = wf;
  if (wt) d.window_to = wt;
  if (typeof raw['device_id'] === 'string') d.device_id = raw['device_id'];
  if (typeof raw['updated_at'] === 'string' && parseTs(raw['updated_at'])) d.updated_at = raw['updated_at'];
  if (raw['recurring'] === true || ev['recurring'] === true) d.recurring = true;
  if (raw['muted'] === true) d.muted = true;
  return d;
}

export function parseDetectionsResponse(raw: unknown): { detections: Detection[]; next_cursor?: string } {
  const arr = isRecord(raw) ? raw['detections'] : Array.isArray(raw) ? raw : [];
  const detections = (Array.isArray(arr) ? arr : []).map(normalizeDetection).filter((d): d is Detection => !!d);
  const next = isRecord(raw) && typeof raw['next_cursor'] === 'string' && raw['next_cursor'] !== '' ? raw['next_cursor'] : undefined;
  return next ? { detections, next_cursor: next } : { detections };
}

/** Detection received live: server `detect.*` event of the SSE stream (the detection is in `data`). */
export function detectionFromEvent(ev: WatchpostEvent): Detection | undefined {
  if (!isDetectionType(ev.type) || isMuteEvent(ev.type)) return undefined;
  const d = ev.data;
  // An update (`update: true`, `detection_id`) is a new version of an existing detection: same identifier.
  const updated = d['update'] === true && typeof d['detection_id'] === 'string' && d['detection_id'] !== '';
  return normalizeDetection({
    id: updated ? d['detection_id'] : ev.id,
    ...(updated ? { updated_at: ev.ts } : {}),
    ...(d['recurring'] === true ? { recurring: true } : {}),
    ...(d['muted'] === true ? { muted: true } : {}),
    ts: ev.ts,
    type: ev.type,
    package: d['package'],
    label: d['label'],
    severity: ev.sev,
    summary: d['summary'],
    evidence: d['evidence'],
    window_from: d['window_from'],
    window_to: d['window_to'],
    device_id: ev.device_id,
  });
}

/**
 * Adds detections at the head (newest first), without duplicates, ordered by decreasing `ts`. A detection's
 * identifier is that of its server event: it is the same in the API list and in the SSE stream.
 * (A single window can carry several detections of one application, for example one threat domain
 * per detection: so we do not deduplicate on the window.)
 */
export function mergeDetections(existing: readonly Detection[], incoming: readonly Detection[], opts: { replace?: boolean } = {}): Detection[] {
  const seen = new Set(existing.map((d) => d.id));
  const fresh: Detection[] = [];
  const replaced = new Map<string, Detection>();
  for (const d of incoming) {
    if (seen.has(d.id)) {
      // Update received live: the stream's version is newer than the list's.
      if (opts.replace) replaced.set(d.id, d);
      continue;
    }
    seen.add(d.id);
    fresh.push(d);
  }
  if (fresh.length === 0 && replaced.size === 0) return existing as Detection[];
  const base = replaced.size ? existing.map((e) => (replaced.has(e.id) ? { ...e, ...(replaced.get(e.id) as Detection), ts: e.ts } : e)) : existing;
  return [...fresh, ...base].sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
}

/** Detections that count for the verdict: muted ones are computed but neither alerted nor counted. */
export function active<T extends { muted?: boolean | undefined }>(list: readonly T[]): T[] {
  return list.filter((d) => !d.muted);
}

export interface DetectionFilter {
  type?: string | undefined;
  pkg?: string | undefined;
  sevMin?: number | undefined;
  from?: string | undefined;
  to?: string | undefined;
}

export function matchesDetection(d: Detection, f: DetectionFilter): boolean {
  if (f.type && d.type !== f.type) return false;
  if (f.pkg && d.package !== f.pkg) return false;
  if (f.sevMin && d.severity < f.sevMin) return false;
  const t = parseTs(d.ts)?.getTime();
  if (t !== undefined) {
    if (f.from && t < Date.parse(f.from)) return false;
    if (f.to && t > Date.parse(f.to)) return false;
  }
  return true;
}

// ------------------------------------------------------------------------------------------- evidence

function pick(ev: DataObject, keys: readonly string[]): unknown {
  for (const k of keys) if (ev[k] !== undefined && ev[k] !== null) return ev[k];
  return undefined;
}
function pickNum(ev: DataObject, keys: readonly string[]): number | undefined {
  const v = pick(ev, keys);
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}
function pickStrList(ev: DataObject, keys: readonly string[]): string[] {
  const v = pick(ev, keys);
  if (Array.isArray(v)) return v.filter((x): x is string | number => typeof x === 'string' || typeof x === 'number').map((x) => cleanText(String(x), 255)).filter(Boolean);
  if (typeof v === 'string' && v !== '') return [cleanText(v, 255)];
  return [];
}
function pickBool(ev: DataObject, keys: readonly string[]): boolean | undefined {
  const v = pick(ev, keys);
  return typeof v === 'boolean' ? v : undefined;
}

const plural = (n: number, one: string, many: string) => (n > 1 ? many : one);

/** Domains cited by a detection (`domains`), cleaned; empty if the evidence carries none. */
export function detectionDomains(d: Detection): string[] {
  return pickStrList(d.evidence, ['domains', 'domain', 'hostnames', 'blocked_domains', 'examples']).slice(0, 50);
}

/** Readable name of the application: cleaned label, else package, else neutral wording. */
export function appNameOf(d: Pick<Detection, 'label' | 'package'>): string {
  return cleanText(d.label, 80) || cleanText(d.package, 120) || 'An application';
}

/**
 * What was observed, in one sentence. Relies on the evidence when it is readable; otherwise on the collector's
 * `summary`, otherwise on the type's label.
 */
export function observation(d: Detection): string {
  const who = appNameOf(d);
  const ev = d.evidence;
  const fallback = () => cleanText(d.summary, 300) || `${detectionLabel(d.type)}: ${who}`;
  switch (d.type) {
    case 'detect.threat_domain': {
      const list = detectionDomains(d);
      const n = pickNum(ev, ['domain_count', 'domains_count', 'count', 'n']) ?? (list.length || undefined);
      if (n === undefined) return fallback();
      // The collector emits one detection per domain (`domain`, `requests`); grouped evidence (`domains`) is also read.
      const req = pickNum(ev, ['requests']);
      if (n === 1 && list.length === 1) {
        return `${who} tried to reach the domain ${list[0]} from the threat list${req !== undefined ? ` (${fmtNumber(req)} ${plural(req, 'request', 'requests')})` : ''}`;
      }
      return `${who} tried to reach ${fmtNumber(n)} ${plural(n, 'domain', 'domains')} from the threat list${req !== undefined ? ` (${fmtNumber(req)} ${plural(req, 'request', 'requests')})` : ''}`;
    }
    case 'detect.upload_spike': {
      const sent = pickNum(ev, ['tx_bytes', 'bytes', 'sent_bytes', 'upload_bytes']);
      if (sent === undefined) return fallback();
      const base = pickNum(ev, ['median_bytes', 'baseline_bytes', 'median_tx_bytes']);
      const ratio = pickNum(ev, ['ratio', 'factor', 'multiple']) ?? (base && base > 0 ? sent / base : undefined);
      const limit = pickNum(ev, ['threshold_bytes']);
      const learning = pickBool(ev, ['learning']) === true;
      return `${who} sent ${fmtBytes(sent)} in one hour${ratio !== undefined && ratio >= 1.5 ? `, ${fmtNumber(ratio, ratio < 10 ? 1 : 0)} times more than usual` : ''}${base !== undefined ? ` (median: ${fmtBytes(base)})` : learning && limit !== undefined ? ` (above the threshold of ${fmtBytes(limit)}; not enough history yet for a median)` : ''}`;
    }
    case 'detect.fanout': {
      const n = pickNum(ev, ['addresses', 'distinct_ips', 'distinct', 'destinations', 'count']);
      if (n === undefined) return fallback();
      return `${who} connected to ${fmtNumber(n)} different addresses in one hour`;
    }
    case 'detect.mail_ports': {
      const ports = pickStrList(ev, ['ports']);
      const n = pickNum(ev, ['connections', 'count']);
      const p = ports.length ? ` (port${ports.length > 1 ? 's' : ''} ${ports.join(', ')})` : '';
      if (n === undefined && ports.length === 0) return fallback();
      return `${who} ${n !== undefined ? `opened ${fmtNumber(n)} ${plural(n, 'connection', 'connections')}` : 'connects'} to mail servers${p}, without being a known mail client`;
    }
    case 'detect.dns_bypass': {
      const prov = pickStrList(ev, ['providers']);
      const res = prov.length > 0 ? prov : pickStrList(ev, ['resolvers', 'resolver']);
      const unresolved = pickNum(ev, ['unresolved_ips', 'unresolved', 'unresolved_count']);
      if (res.length > 0) return `${who} contacted ${res.length > 1 ? 'public DNS resolvers' : 'a public DNS resolver'} (${res.slice(0, 3).join(', ')}): its DNS queries escape the phone's filtering`;
      if (unresolved !== undefined) return `${who} connected to ${fmtNumber(unresolved)} ${plural(unresolved, 'address', 'addresses')} that the phone had never requested from its DNS`;
      return fallback();
    }
    case 'detect.sms_abuse': {
      const n = pickNum(ev, ['sent', 'count', 'sms_count', 'send_sms']);
      if (n === undefined) return fallback();
      const bg = pickNum(ev, ['background', 'background_count']);
      const notDefault = ev['reason'] === 'not_default_sms_app' || pickBool(ev, ['default_sms_app', 'is_default_sms', 'is_default']) === false;
      const volume = ev['reason'] === 'volume';
      const rej = pickNum(ev, ['rejected']);
      return `${who} sent ${fmtNumber(n)} SMS${bg !== undefined && bg > 0 ? `, of which ${fmtNumber(bg)} in the background` : ''}${rej ? `, and tried to send ${fmtNumber(rej)} more, refused by the system` : ''}${notDefault ? ' although it is not the default SMS app' : volume ? ': an abnormal volume' : ''}`;
    }
    case 'detect.sensor_background': {
      // Collector format: one detection per application and per day, with `microphone_background` and `camera_background`;
      // old format: `op` and `background_count`.
      const mic = pickNum(ev, ['microphone_background']);
      const cam = pickNum(ev, ['camera_background']);
      if (mic !== undefined || cam !== undefined) {
        const parts: string[] = [];
        if (mic) parts.push(`the microphone ${fmtNumber(mic)} ${plural(mic, 'time', 'times')}`);
        if (cam) parts.push(`the camera ${fmtNumber(cam)} ${plural(cam, 'time', 'times')}`);
        if (parts.length > 0) return `${who} used ${parts.join(' and ')} in the background`;
      }
      const op = typeof ev['op'] === 'string' ? ev['op'] : undefined;
      const n = pickNum(ev, ['background_count', 'count']);
      if (n === undefined) return fallback();
      const what = op === 'camera' ? 'the camera' : op === 'record_audio' ? 'the microphone' : op ? opInfo(op).label.toLowerCase() : 'the microphone or the camera';
      return `${who} used ${what} ${fmtNumber(n)} ${plural(n, 'time', 'times')} in the background`;
    }
    case 'detect.new_app_risky': {
      // Collector format: `high_risk` (bool) and `capabilities` (codes); old format: `trigger` and `capability`.
      const caps = pickStrList(ev, ['capabilities']).map(capabilityLabel);
      const one = typeof ev['capability'] === 'string' ? capabilityLabel(ev['capability']) : undefined;
      if (one) caps.push(one);
      const level = typeof ev['level'] === 'string' ? ev['level'] : undefined;
      const high = ev['high_risk'] === true || ev['trigger'] === 'high_risk' || (ev['high_risk'] === undefined && ev['trigger'] === undefined && level === 'high');
      if (high && caps.length > 0) return `${who} was just installed with a high risk profile and has already obtained: ${caps.join(', ')}`;
      if (high) return `${who} was just installed with a high risk profile`;
      if (caps.length > 0) return `${who}, installed less than 24 h ago, obtained a sensitive capability: ${caps.join(', ')}`;
      return fallback();
    }
    case 'detect.sms_permission':
      return `${who} can send SMS without going through your messaging app; is this intended?`;
    case 'detect.default_app_changed': {
      const role = typeof ev['role'] === 'string' ? ev['role'] : undefined;
      const old = typeof ev['old'] === 'string' && ev['old'] !== '' ? cleanText(ev['old'], 120) : undefined;
      if (!role) return fallback();
      return `${who} became ${role === 'sms' ? 'the default SMS app' : `the default "${roleLabel(role)}" role`}${old ? ` (in place of ${old})` : ''}`;
    }
    case 'detect.inventory_mismatch':
      return `${who} is declared a system application by the inventory, although its installer or history say otherwise`;
    case 'detect.flood': {
      // Collector format: `suppressed` (extra detections not recorded) and `limit`; old format: `count`.
      const cap = pickNum(ev, ['limit', 'cap', 'max']) ?? 200;
      const more = pickNum(ev, ['suppressed', 'dropped']);
      const n = pickNum(ev, ['count', 'total']);
      return `More than ${fmtNumber(cap)} detections in one day on this device${more !== undefined ? `: ${fmtNumber(more)} more not recorded` : n !== undefined ? ` (${fmtNumber(n)} produced)` : ''}`;
    }
    default:
      return fallback();
  }
}

/** Capabilities tracked by `detect.new_app_risky` (collector keys); an unknown key is displayed as is. */
const CAPABILITY_LABELS: Record<string, string> = {
  accessibility: 'accessibility service',
  notification_listener: 'reading notifications',
  device_admin: 'device administrator',
  unknown_sources: 'installing other applications',
  overlay: 'drawing over other applications',
  vpn: 'VPN',
  'role:sms': 'default SMS app',
  'role:dialer': 'default Phone app',
  'role:assistant': 'default assistant',
  'role:call_screening': 'call screening',
  'permission:SEND_SMS': 'sending SMS',
  'permission:READ_SMS': 'reading SMS',
  'permission:RECEIVE_SMS': 'receiving SMS',
  'permission:RECEIVE_MMS': 'receiving MMS',
  'permission:READ_CALL_LOG': 'call log',
  'permission:PROCESS_OUTGOING_CALLS': 'outgoing calls',
  'permission:CALL_PHONE': 'phone calls',
};

export function capabilityLabel(code: string): string {
  return Object.prototype.hasOwnProperty.call(CAPABILITY_LABELS, code) ? (CAPABILITY_LABELS[code] as string) : cleanText(code, 80);
}

const SOURCE_VALUES: Record<string, string> = {
  permission_changed: 'permission granted',
  inventory: 'application inventory',
};

const REASON_VALUES: Record<string, string> = {
  not_default_sms_app: 'not the default SMS app',
  volume: 'daily volume exceeded',
  high_risk: 'high risk profile',
  capability: 'sensitive capability obtained',
  doh_resolver: 'public DNS resolver',
  unresolved_ips: 'addresses never resolved',
};

export interface EvidenceItem {
  label: string;
  value: string;
}

const EVIDENCE_LABELS: Record<string, string> = {
  microphone_background: 'Microphone in the background',
  microphone_count: 'Microphone (total)',
  camera_background: 'Camera in the background',
  camera_count: 'Camera (total)',
  ops: 'Operations',
  high_risk: 'High risk profile',
  capabilities: 'Capabilities obtained',
  minutes_to_first_capability: 'Minutes before the first capability',
  hours: 'Hours concerned',
  first_hour: 'First hour',
  peak_hour: 'Peak hour',
  role: 'Role',
  old: 'Previous application',
  new: 'New application',
  limit: 'Cap',
  suppressed: 'Extra detections, not recorded',
  since: 'Since',
  until: 'Until',
  source: 'Origin',
  granted: 'Capabilities granted',
  permission: 'Permission',
  domain: 'Domain',
  requests: 'Requests',
  blocked: 'Blocked by AdGuard',
  reason: 'Reason',
  addresses: 'Distinct addresses',
  providers: 'Providers',
  sent: 'SMS sent',
  rejected: 'Refused by the system',
  background: 'Of which in the background',
  read_contacts: 'Contact reads',
  history_hours: 'Hours of history',
  learning: 'Insufficient history',
  screen_on_minutes: 'Minutes with screen on',
  minutes_after_install: 'Minutes after installation',
  installer: 'Installer',
  from_store: 'From a store',
  domains: 'Domains',
  domain_count: 'Number of domains',
  list: 'Threat list',
  lists: 'Threat lists',
  tx_bytes: 'Bytes sent over the hour',
  median_bytes: 'Hourly median over 14 days',
  ratio: 'Factor relative to the median',
  threshold_bytes: 'Threshold',
  distinct_ips: 'Distinct addresses',
  threshold: 'Threshold',
  sample: 'Examples',
  ports: 'Ports',
  connections: 'Connections',
  destinations: 'Destinations',
  resolvers: 'Resolvers',
  unresolved_ips: 'Addresses never resolved',
  count: 'Count',
  background_count: 'Of which in the background',
  default_sms_app: 'Default SMS app',
  op: 'Operation',
  level: 'Risk level',
  score: 'Score',
  reasons: 'Reasons',
  capability: 'Capability obtained',
  installed_at: 'Installed on',
  trigger: 'Trigger',
};

const DATE_KEYS = new Set(['installed_at', 'first_hour', 'peak_hour', 'since', 'until']);
const BYTES_KEYS = new Set(['tx_bytes', 'median_bytes', 'threshold_bytes', 'rx_bytes', 'bytes']);

function scalar(v: unknown): string | undefined {
  if (typeof v === 'string') return v === '' ? undefined : cleanText(v, 255);
  if (typeof v === 'number' && Number.isFinite(v)) return fmtNumber(v, Number.isInteger(v) ? 0 : 2);
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  return undefined;
}

/** Readable evidence items: known keys translated, other keys displayed as is (text). */
export function evidenceItems(d: Detection): EvidenceItem[] {
  const out: EvidenceItem[] = [];
  for (const [k, v] of Object.entries(d.evidence)) {
    if (k === 'window_from' || k === 'window_to') continue;
    const label = Object.prototype.hasOwnProperty.call(EVIDENCE_LABELS, k) ? (EVIDENCE_LABELS[k] as string) : k;
    let value: string | undefined;
    if (typeof v === 'number' && BYTES_KEYS.has(k)) value = fmtBytes(v);
    else if (k === 'op' && typeof v === 'string') value = opInfo(v).label;
    else if ((k === 'reason' || k === 'trigger') && typeof v === 'string') value = REASON_VALUES[v] ?? scalar(v);
    else if (k === 'capability' && typeof v === 'string') value = capabilityLabel(v);
    else if (k === 'reasons' && Array.isArray(v)) value = v.filter((x): x is string => typeof x === 'string').map((x) => reasonInfo(x).label).join(', ') || undefined;
    else if (DATE_KEYS.has(k) && typeof v === 'string') value = parseTs(v) ? `${fmtDate(v)} ${fmtTime(v)}` : scalar(v);
    else if (k === 'role' && typeof v === 'string') value = roleLabel(v);
    else if (k === 'level' && typeof v === 'string') value = levelInfo(v).label;
    else if (k === 'source' && typeof v === 'string') value = SOURCE_VALUES[v] ?? scalar(v);
    else if (k === 'granted' && Array.isArray(v)) value = v.filter((x): x is string => typeof x === 'string').map((x) => reasonInfo(x).label).join(', ') || undefined;
    else if (k === 'blocked' && typeof v === 'number') {
      out.push({ label: 'Blocks counted by AdGuard', value: fmtNumber(v) });
      continue;
    } else if (k === 'capabilities' && Array.isArray(v)) value = v.filter((x): x is string => typeof x === 'string').map(capabilityLabel).join(', ') || undefined;
    else if (k === 'risk' && isRecord(v)) {
      // risk profile of the new application (default_app_changed): flattened
      for (const [rk, rv] of Object.entries(v)) {
        if (rk === 'reasons' && Array.isArray(rv)) out.push({ label: 'Risk: reasons', value: rv.filter((x): x is string => typeof x === 'string').map((x) => reasonInfo(x).label).join(', ') });
        else if (scalar(rv) !== undefined) out.push({ label: `Risk: ${rk === 'score' ? 'score' : rk === 'level' ? 'level' : rk}`, value: scalar(rv) as string });
      }
      continue;
    }
    else if (Array.isArray(v)) {
      const items = v.map((x) => scalar(x) ?? (isRecord(x) ? safeJson(x) : '')).filter(Boolean);
      value = items.length ? items.join(', ') : undefined;
    } else if (isRecord(v)) value = safeJson(v);
    else value = scalar(v);
    if (value !== undefined) out.push({ label, value });
  }
  return out;
}

function safeJson(v: unknown): string {
  try {
    return cleanText(JSON.stringify(v), 255);
  } catch {
    return '';
  }
}

// ------------------------------------------------------------------------------------------- period

/** "15/11/2026 from 14:00 to 15:00" or, if the window spans a day, "from ... to ..."; undefined without a window. */
export function fmtWindow(from: string | undefined, to: string | undefined): string | undefined {
  const a = parseTs(from);
  const b = parseTs(to);
  if (!a || !b) return undefined;
  const hm = (d: Date) => new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit' }).format(d);
  if (fmtDate(a) === fmtDate(b)) return `${fmtDate(a)} from ${hm(a)} to ${hm(b)}`;
  return `from ${fmtDate(a)} ${hm(a)} to ${fmtDate(b)} ${hm(b)}`;
}

/** A detection is "recent" if it is less than 24 h old. */
export function isRecent(d: Detection, now: Date, hours = 24): boolean {
  const t = parseTs(d.ts)?.getTime();
  return t !== undefined && now.getTime() - t < hours * 3600_000;
}

export interface Headline {
  tone: 'ok' | 'warn' | 'bad';
  text: string;
}

/** One-line summary: "Nothing to report" or "2 critical, 1 warning". */
export function headline(c: SeverityCounts, truncated = false): Headline {
  if (c.total === 0) return { tone: 'ok', text: 'Nothing to report' };
  const parts: string[] = [];
  if (c.critical) parts.push(`${fmtNumber(c.critical)} ${plural(c.critical, 'critical', 'critical')}`);
  if (c.warning) parts.push(`${fmtNumber(c.warning)} ${plural(c.warning, 'warning', 'warnings')}`);
  if (c.notable) parts.push(`${fmtNumber(c.notable)} ${plural(c.notable, 'notable', 'notable')}`);
  if (c.info) parts.push(`${fmtNumber(c.info)} ${plural(c.info, 'info', 'info')}`);
  const tone = c.critical > 0 ? 'bad' : c.warning > 0 || c.notable > 0 ? 'warn' : 'ok';
  return { tone, text: `${parts.join(', ')}${truncated ? ' or more' : ''}` };
}

export interface AppDetections {
  package: string;
  label?: string;
  count: number;
  maxSeverity: number;
  types: string[];
}

/** Applications concerned, the most worrying first (maximum severity, then number of detections). */
export function groupByPackage(list: readonly Detection[]): AppDetections[] {
  const m = new Map<string, AppDetections>();
  for (const d of list) {
    if (!d.package || d.muted) continue;
    let g = m.get(d.package);
    if (!g) {
      g = { package: d.package, count: 0, maxSeverity: 0, types: [] };
      m.set(d.package, g);
    }
    if (d.label && !g.label) g.label = d.label;
    g.count++;
    g.maxSeverity = Math.max(g.maxSeverity, normSeverity(d.severity));
    if (!g.types.includes(d.type)) g.types.push(d.type);
  }
  return [...m.values()].sort((a, b) => b.maxSeverity - a.maxSeverity || b.count - a.count || a.package.localeCompare(b.package));
}

/**
 * What the detections do not monitor on this phone, to be stated under the verdict: `detect.sms_abuse` and
 * `detect.sensor_background` rely only on `app.ops`, an experimental collector that is off by default. Without
 * it, a mass SMS sending by a discreet application produces NO detection (SMS does not go
 * through the IP network): "Nothing to report" must not let anyone believe otherwise. `state` is the collector's state
 * in the last heartbeat (`running`, `disabled`, `unavailable`, absent if unknown).
 */
export function opsBlindSpot(state: string | undefined): string | null {
  return monitoringScope(state).blind;
}

export interface MonitoringScope {
  /** what is monitored in all cases */
  watched: string;
  /** what is not; null when the `app_ops` collector is running */
  blind: string | null;
  /** note on `app_ops` when it is running: running does not prove that data is arriving */
  ops: string | null;
  /** the real protection */
  guard: string;
}

/**
 * What the detections do and do not monitor on this phone (contract §11.4), to be stated under the verdict, green included.
 * Without the experimental `app_ops` collector, the SMS sending itself is not seen (it does not go through the IP network);
 * what remains monitored is holding the sending permission and the change of default SMS app. The SMS guard of
 * the Watchpost app is the real protection: a detection signals, the guard prevents.
 */
export function monitoringScope(state: string | undefined): MonitoringScope {
  const why =
    state === 'disabled'
      ? 'is disabled in the Watchpost app'
      : state === 'unavailable'
        ? 'is unavailable on this phone (DUMP permission not granted, or reading impossible)'
        : 'is not reported by this phone';
  const watched =
    'Monitored in all cases: applications that hold the permission to send SMS without being your messaging app, the change of default SMS app (or phone, keyboard, assistant), threat domains, large data uploads, unusual connections and new risky applications.';
  const guard =
    'The real protection is the SMS guard of the Watchpost app, to be set on the phone: a detection signals, the guard prevents.';
  if (state === 'running') {
    return {
      watched,
      blind: null,
      ops: 'SMS sending and background microphone or camera use are monitored by the experimental "Sensitive operations usage" collector ("running" does not prove that data is arriving: see Applications, Sensitive operations).',
      guard,
    };
  }
  return {
    watched,
    blind: `Not monitored here: SMS sending itself and background microphone or camera use. The experimental "Sensitive operations usage" collector ${why}; without it, an application that sent thousands of SMS would produce no sending detection.`,
    ops: null,
    guard,
  };
}

// ------------------------------------------------------------------------------------------- mutes (§11.4)

/** Reads `GET /detections/mutes`: `{ mutes: [...] }`, or a bare array; items without a type or package are ignored. */
export function parseMutes(raw: unknown): DetectionMute[] {
  const arr = Array.isArray(raw) ? raw : isRecord(raw) ? (raw['mutes'] ?? raw['items'] ?? []) : [];
  const out: DetectionMute[] = [];
  for (const it of Array.isArray(arr) ? arr : []) {
    if (!isRecord(it) || typeof it['type'] !== 'string' || typeof it['package'] !== 'string' || it['type'] === '' || it['package'] === '') continue;
    const m: DetectionMute = { type: it['type'], package: it['package'] };
    for (const k of ['label', 'reason', 'device_id', 'created_by'] as const) if (typeof it[k] === 'string' && it[k] !== '') m[k] = it[k] as string;
    const when = it['created_at'] ?? it['since'] ?? it['ts'];
    if (typeof when === 'string' && parseTs(when)) m.created_at = when;
    out.push(m);
  }
  return out;
}

export function isCovered(d: Pick<Detection, 'type' | 'package'>, mutes: readonly DetectionMute[]): boolean {
  return !!d.package && mutes.some((m) => m.type === d.type && m.package === d.package);
}

/** Marks as muted the detections covered by a current mute (even those created before it). */
export function applyMutes(list: readonly Detection[], mutes: readonly DetectionMute[]): Detection[] {
  if (mutes.length === 0) return list as Detection[];
  return list.map((d) => (d.muted || !isCovered(d, mutes) ? d : { ...d, muted: true }));
}

/** Useful message for the failure of a mute or of lifting it. */
export function muteErrorMessage(e: { status: number; code: string; message: string }): string {
  if (e.status === 0) return e.message;
  if (e.code === 'not_mutable' || e.status === 400 || e.status === 422) return `This detection cannot be muted: ${e.message}`;
  if (e.status === 404) return 'This collector does not yet support muting detections (contract §11.4).';
  return e.message;
}
