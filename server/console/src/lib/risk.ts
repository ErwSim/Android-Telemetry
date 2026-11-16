// Application risk profile (contract §11.2, `app.risk`): translation of reason codes, levels,
// combinations, tolerant reading of the `GET /apps/risk` response. Pure functions.
import type { AppRisk, AppRiskResponse, RiskLevel } from '../api/types.ts';
import { isRecord } from './data.ts';

export type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'info';

export interface ReasonInfo {
  code: string;
  label: string;
  /** what it means, in plain words */
  explain: string;
  /** why it can be normal */
  innocent?: string;
  tone: Tone;
  /** `combo_*`: combination of capabilities typical of a kind of malware */
  combo: boolean;
  /** true if the code belongs to the closed list of contract §11.2 */
  known: boolean;
}

type Entry = Omit<ReasonInfo, 'code' | 'known' | 'combo'> & { combo?: boolean };

/** Closed list of contract §11.2, in the contract's order. */
const REASONS: Record<string, Entry> = {
  sideloaded: {
    label: 'Installed outside a store',
    explain: 'The application was not installed from the Play Store or the Galaxy Store: an APK file opened by hand, from a browser or through ADB. Stores run checks that this route bypasses.',
    innocent: 'Normal for F-Droid, a technical tool or an enterprise application that you installed yourself.',
    tone: 'warn',
  },
  unknown_installer: {
    label: 'Unknown installer',
    explain: 'The program that installed the application is not known to Watchpost: it is impossible to tell where it came from.',
    innocent: 'A preinstalled application or one restored from a backup may have no installer at all.',
    tone: 'warn',
  },
  no_launcher_icon: {
    label: 'No icon in the application list',
    explain: 'The application does not appear in the launcher: you cannot see it, and it is harder to uninstall. Spyware and malware often hide this way.',
    innocent: 'Normal for a system service, a component or an extension (keyboard, theme, module).',
    tone: 'warn',
  },
  sms_send: {
    label: 'Can send SMS',
    explain: 'SMS sending permission: the application can send messages without your knowledge, to premium-rate numbers or for phishing from your number, without displaying anything.',
    innocent: 'Normal for your messaging app, or for an application that sends a verification code you requested.',
    tone: 'warn',
  },
  sms_read: {
    label: 'Can read SMS',
    explain: 'SMS reading or receiving permission: the application can read your messages, including the one-time codes sent by your bank.',
    innocent: 'Normal for a messaging app or for an application that reads the verification code itself (authentication).',
    tone: 'warn',
  },
  calls: {
    label: 'Can place or manage calls',
    explain: 'Call permissions: the application can dial numbers (premium-rate ones for example), answer calls or read the call log.',
    innocent: 'Normal for a dialer, a messaging app that offers calls or a call screening app that you chose.',
    tone: 'info',
  },
  accessibility_service: {
    label: 'Accessibility service',
    explain: 'The application can read everything displayed on the screen and act in your place (tap, type text). This is the favourite tool of banking trojans.',
    innocent: 'Normal for a screen reader, a password manager or an assistive tool that you enabled.',
    tone: 'warn',
  },
  notification_listener: {
    label: 'Reads all notifications',
    explain: 'Notification access: the application sees your messages and your one-time codes and can delete them before you see them.',
    innocent: 'Normal for a smartwatch, a messaging assistant or a notification forwarding application that you installed.',
    tone: 'warn',
  },
  device_admin: {
    label: 'Device administrator',
    explain: 'The application has administration rights: locking the screen, enforcing rules, sometimes opposing its own uninstallation.',
    innocent: 'Normal for a business management application or a phone locator.',
    tone: 'warn',
  },
  overlay: {
    label: 'Drawing over other applications',
    explain: "The application can draw over other applications: for example a fake login page in front of your bank's.",
    innocent: 'Normal for a chat bubble, a screen recorder or a blue light filter.',
    tone: 'warn',
  },
  install_packages: {
    label: 'Can install other applications',
    explain: 'The application can download then install other APKs: this is the entry point for other malware.',
    innocent: 'Normal for an alternative app store (F-Droid), a browser or a file manager.',
    tone: 'warn',
  },
  vpn_service: {
    label: 'VPN service',
    explain: "The phone's network traffic can go through this application, which sees or redirects everything that goes out.",
    innocent: 'Normal for a VPN or an ad blocker that you installed and enabled.',
    tone: 'info',
  },
  boot_receiver: {
    label: 'Starts with the phone',
    explain: 'The application launches by itself at power-on, without you opening it: necessary for a permanent service, but also for spyware or background sending.',
    innocent: 'Very common: messaging apps, synchronisation, security applications.',
    tone: 'info',
  },
  background_location: {
    label: 'Background location',
    explain: 'The application can know your location even when it is not on screen: permanent tracking of your movements.',
    innocent: 'Normal for navigation, location sharing that you chose with relatives or a running application.',
    tone: 'info',
  },
  mic_camera_background: {
    label: 'Microphone or camera in the background',
    explain: 'The application can use the microphone or the camera when it is not on screen: listening or taking pictures without your knowledge.',
    innocent: 'Normal for a call in progress, a voice recorder or a voice assistant.',
    tone: 'warn',
  },
  old_target_sdk: {
    label: 'Built for an old Android version',
    explain: 'The application targets an old Android version: it escapes protections introduced since (permissions granted more easily, broader file access).',
    innocent: 'Common for old applications that were simply not updated.',
    tone: 'info',
  },
  debuggable: {
    label: 'Application in debug mode',
    explain: 'The application is marked "debuggable": this is not a normal published build, and other programs can read or modify its execution.',
    innocent: 'Normal for a development application that you build yourself.',
    tone: 'warn',
  },
  combo_banking_trojan: {
    label: 'Banking trojan profile',
    explain: 'Accessibility, drawing over the screen and reading SMS or notifications combined: this is the classic combination of banking trojans (fake pages in front of your bank, reading codes, validating in your place).',
    tone: 'bad',
    combo: true,
  },
  combo_sms_fraud: {
    label: 'SMS fraud profile',
    explain: 'Can send SMS, starts with the phone and is not your messaging app: the profile of software that sends thousands of phishing or premium-rate SMS in the background, without displaying anything.',
    tone: 'bad',
    combo: true,
  },
  combo_stalkerware: {
    label: 'Stalkerware profile',
    explain: 'No visible icon, access to location or microphone, and starting with the phone: the profile of stalkerware installed to monitor you.',
    tone: 'bad',
    combo: true,
  },
};

export const REASON_CODES: readonly string[] = Object.keys(REASONS);
const GRANTED_SUFFIX = ':granted';

/** Reasons that are capabilities which can be requested without being granted; the others describe a state (installer, icon...). */
export const CAPABILITY_CODES: ReadonlySet<string> = new Set([
  'sms_send',
  'sms_read',
  'calls',
  'accessibility_service',
  'notification_listener',
  'device_admin',
  'overlay',
  'install_packages',
  'vpn_service',
  'background_location',
  'mic_camera_background',
]);

/**
 * State of a reason according to `granted`: `granted`, `declared` (requested, not granted: refused by a guard, or
 * not yet granted), or `unknown` (the agent does not distinguish: profile without a `granted` list).
 */
export function grantState(r: Pick<AppRisk, 'granted'>, code: string): 'granted' | 'declared' | 'unknown' {
  if (!r.granted || !CAPABILITY_CODES.has(code)) return 'unknown';
  return r.granted.includes(code) ? 'granted' : 'declared';
}

export const COMBO_CODES: readonly string[] = REASON_CODES.filter((c) => REASONS[c]?.combo);

/** Translates a reason code. An unknown code is displayed as is, without an invented explanation. */
export function reasonInfo(code: string): ReasonInfo {
  const e = Object.prototype.hasOwnProperty.call(REASONS, code) ? REASONS[code] : undefined;
  if (!e) {
    return {
      code,
      label: code,
      explain: 'This code is not known to this version of the console: it is displayed as the phone sent it.',
      tone: 'neutral',
      combo: false,
      known: false,
    };
  }
  return { code, label: e.label, explain: e.explain, ...(e.innocent ? { innocent: e.innocent } : {}), tone: e.tone, combo: e.combo === true, known: true };
}

/** Combinations (`combo_*`) present in a list of reasons, in the contract's order. */
export function combosOf(reasons: readonly string[]): string[] {
  return COMBO_CODES.filter((c) => reasons.includes(c));
}

/** Ordered reasons: combinations first, then decreasing severity, then contract order; unknown ones last. */
export function orderReasons(reasons: readonly string[]): ReasonInfo[] {
  const rank = (r: ReasonInfo): number => (r.combo ? 0 : r.tone === 'warn' ? 1 : r.tone === 'info' ? 2 : 3);
  const uniq = [...new Set(reasons)];
  return uniq
    .map((c, i) => ({ r: reasonInfo(c), i }))
    .sort((a, b) => rank(a.r) - rank(b.r) || a.i - b.i)
    .map((x) => x.r);
}

// ------------------------------------------------------------------------------------------- levels

export interface LevelInfo {
  key: RiskLevel;
  label: string;
  tone: Tone;
}

const LEVELS: Record<RiskLevel, LevelInfo> = {
  low: { key: 'low', label: 'Low', tone: 'ok' },
  medium: { key: 'medium', label: 'Medium', tone: 'warn' },
  high: { key: 'high', label: 'High', tone: 'bad' },
};

/** Announced level; if the value is unknown or absent, falls back on the score (< 30 low, < 70 medium: contract §11.2). */
export function levelInfo(level: string | undefined, score?: number): LevelInfo {
  if (level === 'low' || level === 'medium' || level === 'high') return LEVELS[level];
  const s = score ?? 0;
  return s >= 70 ? LEVELS.high : s >= 30 ? LEVELS.medium : LEVELS.low;
}

export const LEVEL_RANK: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2 };

// ------------------------------------------------------------------------------------- API reading

function clampScore(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) ? Math.max(0, Math.min(100, Math.round(v))) : 0;
}

/** Normalises an item of `/apps/risk` (flat fields or under `data`); undefined if the package is missing. */
export function normalizeRisk(raw: unknown): AppRisk | undefined {
  if (!isRecord(raw)) return undefined;
  const d = isRecord(raw['data']) ? { ...raw['data'], ...(typeof raw['ts'] === 'string' ? { ts: raw['ts'] } : {}) } : raw;
  const pkg = d['package'];
  if (typeof pkg !== 'string' || pkg === '') return undefined;
  const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '') : []);
  // §11.4: `reasons` = declared capabilities; `granted` = those actually granted. A ":granted" suffix (on a
  // reason or in the parallel list) is removed: it only serves to distinguish intent from state.
  const base = (c: string): string => (c.endsWith(GRANTED_SUFFIX) ? c.slice(0, -GRANTED_SUFFIX.length) : c);
  const rawReasons = strs(d['reasons']);
  const reasons = [...new Set(rawReasons.map(base))];
  const hasGranted = Array.isArray(d['granted']) || rawReasons.some((c) => c.endsWith(GRANTED_SUFFIX));
  const granted = [...new Set([...strs(d['granted']).map(base), ...rawReasons.filter((c) => c.endsWith(GRANTED_SUFFIX)).map(base)])];
  const out: AppRisk = {
    package: pkg,
    score: clampScore(d['score']),
    level: typeof d['level'] === 'string' ? d['level'] : '',
    reasons,
  };
  if (hasGranted) out.granted = granted;
  if (typeof d['label'] === 'string' && d['label'] !== '') out.label = d['label'];
  if (typeof d['version_code'] === 'number') out.version_code = d['version_code'];
  if (typeof d['installer'] === 'string') out.installer = d['installer'];
  if (typeof d['from_store'] === 'boolean') out.from_store = d['from_store'];
  if (typeof d['ts'] === 'string') out.ts = d['ts'];
  return out;
}

/** Reads the `GET /apps/risk` response (`{ apps: [...] }`, or a bare array), sorted by decreasing score. */
export function parseRiskResponse(raw: unknown): AppRiskResponse {
  const arr = Array.isArray(raw) ? raw : isRecord(raw) ? (raw['apps'] ?? raw['risks'] ?? raw['items'] ?? []) : [];
  const apps = (Array.isArray(arr) ? arr : []).map(normalizeRisk).filter((x): x is AppRisk => !!x);
  const out: AppRiskResponse = { apps: sortByScore(apps) };
  if (isRecord(raw) && typeof raw['ts'] === 'string') out.ts = raw['ts'];
  return out;
}

/** Decreasing score; for equal scores, more reasons first, then name. */
export function sortByScore(list: readonly AppRisk[]): AppRisk[] {
  const name = (a: AppRisk) => (a.label ?? a.package).toLowerCase();
  return [...list].sort((a, b) => b.score - a.score || b.reasons.length - a.reasons.length || name(a).localeCompare(name(b), 'en'));
}

export interface RiskCounts {
  high: number;
  medium: number;
  low: number;
  total: number;
  withCombo: number;
}

export function riskCounts(list: readonly AppRisk[]): RiskCounts {
  const c: RiskCounts = { high: 0, medium: 0, low: 0, total: list.length, withCombo: 0 };
  for (const a of list) {
    c[levelInfo(a.level, a.score).key]++;
    if (combosOf(a.reasons).length > 0) c.withCombo++;
  }
  return c;
}

/** Filter: minimum level, combinations only, text (name or package). */
export function filterRisk(
  list: readonly AppRisk[],
  f: { level: RiskLevel | 'all'; comboOnly: boolean; q: string },
): AppRisk[] {
  const q = f.q.trim().toLowerCase();
  const min = f.level === 'all' ? 0 : LEVEL_RANK[f.level];
  return list.filter(
    (a) =>
      LEVEL_RANK[levelInfo(a.level, a.score).key] >= min &&
      (!f.comboOnly || combosOf(a.reasons).length > 0) &&
      (!q || a.package.toLowerCase().includes(q) || (a.label ?? '').toLowerCase().includes(q)),
  );
}
