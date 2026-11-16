import type { WatchpostEvent } from '../api/types.ts';
import { fmtBytes, fmtDuration, fmtNumber, fmtValue } from './format.ts';
import { bool, list, num, obj, str, strList } from './data.ts';
import { cleanText } from './text.ts';
import { commandLabel, refusalInfo } from './commands.ts';
import { detectionFromEvent, detectionLabel, isDetectionType, observation } from './detections.ts';
import { levelInfo } from './risk.ts';
import { roleLabel } from './roles.ts';
import { LEVEL_FALLBACK } from './tracking.ts';

export const SEV_LABELS = ['Info', 'Notable', 'Warning', 'Critical'] as const;

export function sevLabel(sev: number): string {
  return SEV_LABELS[Math.max(0, Math.min(3, Math.trunc(sev)))] ?? 'Info';
}

export function domainOf(type: string): string {
  const i = type.indexOf('.');
  return i < 0 ? type : type.slice(0, i);
}

export const DOMAIN_LABELS: Record<string, string> = {
  agent: 'Agent',
  device: 'Device',
  location: 'Location',
  net: 'Network',
  app: 'Applications',
  sensor: 'Sensors',
  security: 'Security',
  command: 'Commands',
  detect: 'Detections',
  tracking: 'Tracking',
};

export function domainLabel(d: string): string {
  return DOMAIN_LABELS[d] ?? d;
}

/** Stable colour index for a domain (CSS variables --series-N). */
const DOMAIN_ORDER = ['net', 'location', 'app', 'device', 'security', 'agent', 'sensor', 'net.dns', 'net.connect'];
export function seriesIndex(key: string): number {
  const i = DOMAIN_ORDER.indexOf(key);
  return i >= 0 ? (i === 7 ? 0 : i === 8 ? 1 : i) : 9 + (hash(key) % 2);
}
function hash(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

export const TYPE_LABELS: Record<string, string> = {
  'agent.started': 'Agent started',
  'agent.stopped': 'Agent stopped',
  'agent.heartbeat': 'Heartbeat',
  'agent.buffer_overflow': 'Buffer full',
  'agent.collector_error': 'Collector error',
  'agent.config_changed': 'Setting changed',
  'agent.tamper': 'Tampering detected',
  'device.inventory': 'Device inventory',
  'device.boot': 'Boot',
  'device.shutdown': 'Shutdown',
  'device.screen': 'Screen',
  'device.battery': 'Battery',
  'device.power_save': 'Power saving',
  'device.storage': 'Storage',
  'device.thermal': 'Thermal',
  'device.time_changed': 'Time changed',
  'device.timezone_changed': 'Time zone changed',
  'device.usb': 'USB',
  'device.airplane_mode': 'Airplane mode',
  'location.fix': 'Location',
  'location.provider': 'Location provider',
  'net.connectivity': 'Connectivity',
  'net.wifi': 'Wi-Fi',
  'net.wifi_scan': 'Wi-Fi scan',
  'net.cell': 'Mobile network',
  'net.cell_security': 'Cellular security',
  'net.dns': 'DNS query',
  'net.connect': 'Connection',
  'net.usage': 'Usage volumes',
  'net.bluetooth': 'Bluetooth',
  'net.ble_tracker': 'BLE tracker',
  'net.hotspot': 'Hotspot',
  'net.nfc': 'NFC',
  'app.inventory': 'App inventory',
  'app.installed': 'App installed',
  'app.updated': 'App updated',
  'app.removed': 'App removed',
  'app.foreground': 'App in foreground',
  'app.permission_changed': 'Permission changed',
  'app.special_access': 'Special access',
  'app.notification': 'Notification',
  'sensor.camera': 'Camera',
  'sensor.microphone': 'Microphone',
  'security.log': 'Security log',
  'security.posture': 'Security posture',
  'security.keyguard': 'Lock',
  'security.ca_cert': 'CA certificate',
  'security.policy': 'Policy applied',
  'command.result': 'Command result',
  'command.issued': 'Command issued',
  'command.cancelled': 'Command cancelled',
  'app.risk': 'Risk profile',
  'app.role': 'Default role changed',
  'app.ops': 'Sensitive operations',
  'detect.threat_domain': 'Detection: threat domain',
  'detect.upload_spike': 'Detection: unusual upload',
  'detect.fanout': 'Detection: many connections',
  'detect.mail_ports': 'Detection: mail ports',
  'detect.dns_bypass': 'Detection: DNS bypassed',
  'detect.sms_abuse': 'Detection: abnormal SMS',
  'detect.sensor_background': 'Detection: microphone or camera',
  'detect.new_app_risky': 'Detection: risky application',
  'detect.sms_permission': 'Detection: SMS permission',
  'detect.default_app_changed': 'Detection: default application changed',
  'detect.flood': 'Detection: too many detections',
  'detect.inventory_mismatch': 'Detection: fake system application',
  'detect.muted': 'Detection muted',
  'detect.unmuted': 'Mute lifted',
  'tracking.level_changed': 'Blocking level changed',
  'tracking.override': 'Blocking rule changed',
};

export function typeLabel(type: string): string {
  return TYPE_LABELS[type] ?? type;
}

const onOff = (b: boolean | undefined) => (b === undefined ? '?' : b ? 'enabled' : 'disabled');

/** One-line summary of an event. Never throws: falls back to scalar fields. */
export function describeEvent(ev: WatchpostEvent): string {
  const d = ev.data ?? {};
  try {
    switch (ev.type) {
      case 'agent.started':
      case 'agent.stopped':
        return [str(d, 'reason'), str(d, 'agent_version') && `v${str(d, 'agent_version')}`].filter(Boolean).join(' · ');
      case 'agent.heartbeat': {
        const parts = [];
        const b = num(d, 'battery_pct');
        if (b !== undefined) parts.push(`battery ${fmtNumber(b)} %${bool(d, 'charging') ? ' (charging)' : ''}`);
        const q = num(d, 'queue_depth');
        if (q !== undefined) parts.push(`buffer ${fmtNumber(q)} evt`);
        if (bool(d, 'device_owner') !== undefined) parts.push(`Device Owner ${bool(d, 'device_owner') ? 'yes' : 'no'}`);
        return parts.join(' · ');
      }
      case 'agent.buffer_overflow':
        return `${fmtNumber(num(d, 'dropped'))} events purged`;
      case 'agent.collector_error':
        return `${str(d, 'collector') ?? '?'}: ${str(d, 'error') ?? 'error'}`;
      case 'agent.config_changed':
        return `${str(d, 'key') ?? '?'}: ${fmtValue(d['old'])} → ${fmtValue(d['new'])}`;
      case 'agent.tamper':
        return `${str(d, 'kind') ?? '?'}${str(d, 'detail') ? ` — ${str(d, 'detail')}` : ''}`;
      case 'device.inventory':
        return [str(d, 'manufacturer'), str(d, 'model'), str(d, 'android_release') && `Android ${str(d, 'android_release')}`, str(d, 'one_ui') && `One UI ${str(d, 'one_ui')}`]
          .filter(Boolean)
          .join(' · ');
      case 'device.boot':
      case 'device.shutdown':
        return str(d, 'reason') ?? '';
      case 'device.screen':
        return str(d, 'state') ?? '';
      case 'device.battery':
        return `${fmtNumber(num(d, 'pct'))} % · ${str(d, 'plugged') ?? '?'} · ${str(d, 'status') ?? ''}${num(d, 'temperature_c') !== undefined ? ` · ${fmtNumber(num(d, 'temperature_c'), 1)} °C` : ''}`;
      case 'device.power_save':
      case 'device.airplane_mode':
      case 'net.hotspot':
      case 'net.nfc':
        return onOff(bool(d, 'enabled'));
      case 'device.storage':
        return `${fmtBytes(num(d, 'free_bytes'))} free of ${fmtBytes(num(d, 'total_bytes'))}`;
      case 'device.thermal':
        return str(d, 'status') ?? '';
      case 'device.time_changed':
        return `offset ${fmtDuration(Math.abs(num(d, 'delta_ms') ?? 0))}`;
      case 'device.timezone_changed':
        return str(d, 'tz') ?? '';
      case 'device.usb':
        return `${bool(d, 'connected') ? 'connected' : 'disconnected'}${strList(d, 'functions').length ? ` · ${strList(d, 'functions').join(', ')}` : ''}`;
      case 'location.fix': {
        const lat = num(d, 'lat');
        const lon = num(d, 'lon');
        if (lat === undefined || lon === undefined) return 'incomplete location';
        return `${fmtNumber(lat, 5)}, ${fmtNumber(lon, 5)}${num(d, 'acc_m') !== undefined ? ` · ±${fmtNumber(num(d, 'acc_m'))} m` : ''}${bool(d, 'mock') ? ' · MOCK' : ''}`;
      }
      case 'location.provider':
        return `${str(d, 'provider') ?? '?'} ${onOff(bool(d, 'enabled'))}`;
      case 'net.connectivity': {
        const t = strList(d, 'transports').join('+') || 'no transport';
        return `${t}${bool(d, 'validated') === false ? ' · not validated' : ''}${bool(d, 'vpn') ? ' · VPN' : ''}${bool(d, 'private_dns_active') ? ' · private DNS' : ''}`;
      }
      case 'net.wifi':
        return `${str(d, 'event') ?? '?'} · ${str(d, 'ssid') ?? 'unknown SSID'}${num(d, 'rssi') !== undefined ? ` · ${num(d, 'rssi')} dBm` : ''}${str(d, 'security') ? ` · ${str(d, 'security')}` : ''}`;
      case 'net.wifi_scan':
        return `${list(d, 'aps').length} networks`;
      case 'net.cell':
        return `${str(d, 'tech') ?? '?'} · ${str(d, 'operator') ?? `${str(d, 'mcc') ?? '?'}/${str(d, 'mnc') ?? '?'}`}${num(d, 'signal_dbm') !== undefined ? ` · ${num(d, 'signal_dbm')} dBm` : ''}${bool(d, 'roaming') ? ' · roaming' : ''}`;
      case 'net.cell_security':
        return `${str(d, 'kind') ?? '?'}${str(d, 'detail') ? ` — ${str(d, 'detail')}` : ''}`;
      case 'net.dns':
        return `${str(d, 'package') ?? '?'} → ${str(d, 'hostname') ?? '?'}`;
      case 'net.connect':
        return `${str(d, 'package') ?? '?'} → ${str(d, 'ip') ?? '?'}:${num(d, 'port') ?? '?'}`;
      case 'net.usage': {
        const apps = list<Record<string, unknown>>(d, 'apps');
        const total = apps.reduce((a, x) => a + (typeof x['rx_bytes'] === 'number' ? x['rx_bytes'] : 0) + (typeof x['tx_bytes'] === 'number' ? x['tx_bytes'] : 0), 0);
        return `${apps.length} apps · ${fmtBytes(total)}`;
      }
      case 'net.bluetooth':
        return `${str(d, 'event') ?? '?'}${str(d, 'name') ? ` · ${str(d, 'name')}` : ''}${str(d, 'address') ? ` · ${str(d, 'address')}` : ''}`;
      case 'net.ble_tracker':
        return `${str(d, 'kind') ?? 'unknown'} · ${str(d, 'address') ?? '?'} · ${num(d, 'sightings') ?? '?'} sightings`;
      case 'app.inventory':
        return `part ${num(d, 'part') ?? '?'}/${num(d, 'parts') ?? '?'} · ${list(d, 'apps').length} apps`;
      case 'app.installed':
      case 'app.updated':
      case 'app.removed':
        return `${str(d, 'package') ?? '?'}${str(d, 'version_name') ? ` ${str(d, 'version_name')}` : ''}${str(d, 'installer') ? ` · via ${str(d, 'installer')}` : ''}`;
      case 'app.foreground':
        return `${str(d, 'package') ?? '?'} ${str(d, 'event') ?? ''}`;
      case 'app.permission_changed':
        return `${str(d, 'package') ?? '?'} · ${shortPermission(str(d, 'permission'))} ${bool(d, 'granted') ? 'granted' : 'revoked'}`;
      case 'app.special_access':
        return `accessibility ${strList(d, 'accessibility_services').length} · notif. listeners ${strList(d, 'notification_listeners').length} · admins ${strList(d, 'device_admins').length} · VPN ${strList(d, 'vpn_apps').length}`;
      case 'app.notification':
        return describeNotification(d);
      case 'command.result':
        return describeCommandResult(d);
      case 'command.issued':
      case 'command.cancelled':
        return `${commandLabel(str(d, 'type') ?? '?')}${str(d, 'command_id') ? ` · ${str(d, 'command_id')}` : ''}`;
      case 'app.risk': {
        const lv = levelInfo(str(d, 'level'), num(d, 'score'));
        const n = strList(d, 'reasons').length;
        return `${str(d, 'label') ? `${cleanText(str(d, 'label'), 80)} · ` : ''}${cleanText(str(d, 'package'), 120) || '?'} · ${lv.label.toLowerCase()} risk${num(d, 'score') !== undefined ? ` (${num(d, 'score')}/100)` : ''} · ${n} reason${n > 1 ? 's' : ''}`;
      }
      case 'app.role':
        return `${roleLabel(str(d, 'role') ?? '?')}: ${cleanText(str(d, 'old'), 120) || 'none'} → ${cleanText(str(d, 'new'), 120) || 'none'}`;
      case 'app.ops': {
        const rows = list<Record<string, unknown>>(d, 'apps');
        const total = rows.reduce((a, x) => a + (typeof x['count'] === 'number' ? x['count'] : 0), 0);
        return `${rows.length} sensitive operation use${rows.length > 1 ? 's' : ''} · ${fmtNumber(total)} call${total > 1 ? 's' : ''}`;
      }
      case 'detect.muted':
      case 'detect.unmuted': {
        // §11.4: server event; `type`, `package`, `reason`, `user` (fields not fixed: read tolerantly).
        const what = str(d, 'type') ? detectionLabel(str(d, 'type') as string) : 'detection';
        return `${ev.type === 'detect.muted' ? 'Muted' : 'Mute lifted'}: ${what} for ${cleanText(str(d, 'package'), 255) || '?'}${str(d, 'reason') ? ` · reason: ${cleanText(str(d, 'reason'), 200)}` : ''}${str(d, 'user') ? ` · by ${cleanText(str(d, 'user'), 60)}` : ''}`;
      }
      case 'tracking.level_changed':
        return describeLevelChange(d);
      case 'tracking.override':
        return describeOverride(d);
      case 'sensor.camera':
        return `${bool(d, 'in_use') ? 'in use' : 'released'} · camera ${str(d, 'camera_id') ?? (num(d, 'camera_id') ?? '?')}${str(d, 'package') ? ` · ${str(d, 'package')}` : ''}`;
      case 'sensor.microphone':
        return `${bool(d, 'recording') ? 'recording' : 'stopped'}${str(d, 'source') ? ` · ${str(d, 'source')}` : ''}${str(d, 'package') ? ` · ${str(d, 'package')}` : ''}${bool(d, 'silenced') ? ' · silenced' : ''}`;
      case 'security.log': {
        const f = obj(d, 'fields');
        const extra = f
          ? Object.entries(f)
              .slice(0, 3)
              .map(([k, v]) => `${k}=${fmtValue(v)}`)
              .join(' ')
          : '';
        return `${str(d, 'tag') ?? '?'}${extra ? ` · ${extra}` : ''}`;
      }
      case 'security.posture':
        return 'posture snapshot';
      case 'security.keyguard':
        return `${str(d, 'event') ?? '?'}${num(d, 'failed_attempts') !== undefined ? ` · ${num(d, 'failed_attempts')} failures` : ''}`;
      case 'security.ca_cert':
        return `${str(d, 'event') ?? '?'} · ${str(d, 'subject') ?? str(d, 'sha256')?.slice(0, 16) ?? '?'}`;
      case 'security.policy':
        return `${str(d, 'action') ?? '?'}${str(d, 'target') ? ` · ${str(d, 'target')}` : ''}${bool(d, 'ok') === false ? ` · FAILED${str(d, 'error') ? ` (${str(d, 'error')})` : ''}` : ''}`;
      default:
        if (isDetectionType(ev.type)) {
          const det = detectionFromEvent(ev);
          return det ? observation(det) : `${detectionLabel(ev.type)}`;
        }
        return genericSummary(d);
    }
  } catch {
    return genericSummary(d);
  }
}

const levelName = (k: string | undefined): string => (k ? (LEVEL_FALLBACK[k]?.name ?? cleanText(k, 40)) : 'unknown');
const ACTION_NAMES: Record<string, string> = { block: 'block', allow: 'allow', default: 'back to default setting' };

/** `tracking.level_changed` (contract §9): `old` (absent if the state matched no level), `new`, `changes`, `user`. */
function describeLevelChange(d: Record<string, unknown>): string {
  const by = str(d, 'user') ? ` · by ${cleanText(str(d, 'user'), 60)}` : '';
  const ch = Array.isArray(d['changes']) ? d['changes'].length : num(d, 'changes');
  return `Blocking level: ${levelName(str(d, 'old'))} → ${levelName(str(d, 'new'))}${ch ? ` · ${ch} list${ch > 1 ? 's' : ''} changed` : ''}${by}`;
}

/** `tracking.override` (contract §9): `domain`, `action`, `forced`, `previous`, `user`. */
function describeOverride(d: Record<string, unknown>): string {
  const action = str(d, 'action') ?? '?';
  const prev = str(d, 'previous');
  const by = str(d, 'user') ? ` · by ${cleanText(str(d, 'user'), 60)}` : '';
  const head = ACTION_NAMES[action] ?? cleanText(action, 40);
  return `${head.charAt(0).toUpperCase()}${head.slice(1)} of "${cleanText(str(d, 'domain'), 255) || '?'}"${bool(d, 'forced') ? ' · forced (essential domain)' : ''}${prev ? ` · previous rule: ${ACTION_NAMES[prev] ?? cleanText(prev, 40)}` : ''}${by}`;
}

const NOTIFICATION_EVENTS: Record<string, string> = { posted: 'posted', removed: 'removed' };

/**
 * Notification: application, event, then title and text if present. These two fields come from
 * any application: they are cleaned (control characters, bidirectional) and never
 * interpreted. `redacted`: a numeric code of 4 to 8 digits was masked by the phone.
 */
export function describeNotification(d: Record<string, unknown>): string {
  const title = cleanText(d['title']);
  const text = cleanText(d['text']);
  const ev = str(d, 'event');
  const head = `${str(d, 'package') ?? '?'} ${ev ? (NOTIFICATION_EVENTS[ev] ?? ev) : ''}`.trim();
  const content = title && text ? `${title} — ${text}` : title || text;
  const parts = [head];
  if (content) parts.push(`"${content}"`);
  else if (!bool(d, 'ongoing')) parts.push(str(d, 'category') ?? '');
  if (bool(d, 'redacted')) parts.push('content hidden (numeric code)');
  return parts.filter(Boolean).join(' · ');
}

function describeCommandResult(d: Record<string, unknown>): string {
  const status = str(d, 'status');
  const statusLabel = status === 'executed' ? 'executed' : status === 'failed' ? 'failed' : status === 'refused' ? 'refused' : (status ?? '?');
  const detail = str(d, 'detail');
  const why = status === 'refused' ? refusalInfo(detail)?.title : detail;
  return `${commandLabel(str(d, 'type') ?? '?')} · ${statusLabel}${why ? ` (${why})` : ''}${bool(d, 'signed') ? ' · signed' : ''}`;
}

function genericSummary(d: Record<string, unknown>): string {
  return Object.entries(d)
    .filter(([, v]) => v === null || ['string', 'number', 'boolean'].includes(typeof v))
    .slice(0, 4)
    .map(([k, v]) => `${k}=${fmtValue(v)}`)
    .join(' · ');
}

export function shortPermission(p: string | undefined): string {
  if (!p) return '?';
  return p.replace(/^android\.permission(-group)?\./, '');
}

export const PERMISSION_LABELS: Record<string, string> = {
  CAMERA: 'Camera',
  RECORD_AUDIO: 'Microphone',
  ACCESS_FINE_LOCATION: 'Precise location',
  ACCESS_COARSE_LOCATION: 'Approximate location',
  ACCESS_BACKGROUND_LOCATION: 'Background location',
  READ_CONTACTS: 'Read contacts',
  WRITE_CONTACTS: 'Modify contacts',
  READ_CALENDAR: 'Read calendar',
  WRITE_CALENDAR: 'Modify calendar',
  READ_PHONE_STATE: 'Phone state',
  READ_PHONE_NUMBERS: 'Phone numbers',
  CALL_PHONE: 'Place calls',
  READ_CALL_LOG: 'Call log',
  WRITE_CALL_LOG: 'Modify call log',
  SEND_SMS: 'Send SMS',
  READ_SMS: 'Read SMS',
  RECEIVE_SMS: 'Receive SMS',
  READ_EXTERNAL_STORAGE: 'Read storage',
  WRITE_EXTERNAL_STORAGE: 'Write to storage',
  READ_MEDIA_IMAGES: 'Photos',
  READ_MEDIA_VIDEO: 'Videos',
  READ_MEDIA_AUDIO: 'Audio',
  POST_NOTIFICATIONS: 'Notifications',
  BODY_SENSORS: 'Body sensors',
  ACTIVITY_RECOGNITION: 'Physical activity',
  BLUETOOTH_CONNECT: 'Bluetooth (connect)',
  BLUETOOTH_SCAN: 'Bluetooth (scan)',
  NEARBY_WIFI_DEVICES: 'Nearby Wi-Fi devices',
};

export function permissionLabel(p: string): string {
  const s = shortPermission(p);
  return PERMISSION_LABELS[s] ?? s;
}

/** Common names of installers. */
export function installerLabel(installer: string | undefined): string {
  switch (installer) {
    case undefined:
    case '':
      return 'Unknown / preinstalled';
    case 'com.android.vending':
      return 'Play Store';
    case 'com.sec.android.app.samsungapps':
      return 'Galaxy Store';
    case 'com.android.shell':
      return 'ADB';
    case 'com.google.android.packageinstaller':
    case 'com.android.packageinstaller':
      return 'Package installer';
    case 'com.google.android.apps.nbu.files':
      return 'Files by Google';
    case 'com.android.chrome':
      return 'Chrome';
    case 'org.fdroid.fdroid':
      return 'F-Droid';
    default:
      return installer;
  }
}

const TRUSTED_INSTALLERS = new Set(['com.android.vending', 'com.sec.android.app.samsungapps']);
/** User application installed outside the Play Store / Galaxy Store. */
export function isSideloaded(a: { system?: boolean; installer?: string }): boolean {
  if (a.system) return false;
  return !a.installer || !TRUSTED_INSTALLERS.has(a.installer);
}
