import type { VigieEvent } from '../api/types.ts';
import { fmtBytes, fmtDuration, fmtNumber, fmtValue } from './format.ts';
import { bool, list, num, obj, str, strList } from './data.ts';
import { cleanText } from './text.ts';
import { commandLabel, refusalInfo } from './commands.ts';

export const SEV_LABELS = ['Info', 'Notable', 'Avertissement', 'Critique'] as const;

export function sevLabel(sev: number): string {
  return SEV_LABELS[Math.max(0, Math.min(3, Math.trunc(sev)))] ?? 'Info';
}

export function domainOf(type: string): string {
  const i = type.indexOf('.');
  return i < 0 ? type : type.slice(0, i);
}

export const DOMAIN_LABELS: Record<string, string> = {
  agent: 'Agent',
  device: 'Appareil',
  location: 'Position',
  net: 'Réseau',
  app: 'Applications',
  sensor: 'Capteurs',
  security: 'Sécurité',
  command: 'Commandes',
};

export function domainLabel(d: string): string {
  return DOMAIN_LABELS[d] ?? d;
}

/** Index de couleur stable pour un domaine (variables CSS --series-N). */
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
  'agent.started': "Démarrage de l'agent",
  'agent.stopped': "Arrêt de l'agent",
  'agent.heartbeat': 'Pulsation',
  'agent.buffer_overflow': 'Tampon saturé',
  'agent.collector_error': 'Erreur de collecteur',
  'agent.config_changed': 'Réglage modifié',
  'agent.tamper': 'Altération détectée',
  'device.inventory': "Inventaire de l'appareil",
  'device.boot': 'Démarrage',
  'device.shutdown': 'Extinction',
  'device.screen': 'Écran',
  'device.battery': 'Batterie',
  'device.power_save': "Économiseur d'énergie",
  'device.storage': 'Stockage',
  'device.thermal': 'Thermique',
  'device.time_changed': 'Heure modifiée',
  'device.timezone_changed': 'Fuseau modifié',
  'device.usb': 'USB',
  'device.airplane_mode': 'Mode avion',
  'location.fix': 'Position',
  'location.provider': 'Fournisseur de position',
  'net.connectivity': 'Connectivité',
  'net.wifi': 'Wi-Fi',
  'net.wifi_scan': 'Scan Wi-Fi',
  'net.cell': 'Réseau mobile',
  'net.cell_security': 'Sécurité cellulaire',
  'net.dns': 'Requête DNS',
  'net.connect': 'Connexion',
  'net.usage': "Volumes d'usage",
  'net.bluetooth': 'Bluetooth',
  'net.ble_tracker': 'Traceur BLE',
  'net.hotspot': 'Point d’accès',
  'net.nfc': 'NFC',
  'app.inventory': 'Inventaire des apps',
  'app.installed': 'App installée',
  'app.updated': 'App mise à jour',
  'app.removed': 'App supprimée',
  'app.foreground': 'App au premier plan',
  'app.permission_changed': 'Permission modifiée',
  'app.special_access': 'Accès spéciaux',
  'app.notification': 'Notification',
  'sensor.camera': 'Caméra',
  'sensor.microphone': 'Microphone',
  'security.log': 'Journal de sécurité',
  'security.posture': 'Posture de sécurité',
  'security.keyguard': 'Verrouillage',
  'security.ca_cert': "Certificat d'AC",
  'security.policy': 'Politique appliquée',
  'command.result': 'Résultat de commande',
  'command.issued': 'Commande émise',
  'command.cancelled': 'Commande annulée',
};

export function typeLabel(type: string): string {
  return TYPE_LABELS[type] ?? type;
}

const onOff = (b: boolean | undefined) => (b === undefined ? '?' : b ? 'activé' : 'désactivé');

/** Résumé d'une ligne pour un événement. Ne jette jamais : repli sur les champs scalaires. */
export function describeEvent(ev: VigieEvent): string {
  const d = ev.data ?? {};
  try {
    switch (ev.type) {
      case 'agent.started':
      case 'agent.stopped':
        return [str(d, 'reason'), str(d, 'agent_version') && `v${str(d, 'agent_version')}`].filter(Boolean).join(' · ');
      case 'agent.heartbeat': {
        const parts = [];
        const b = num(d, 'battery_pct');
        if (b !== undefined) parts.push(`batterie ${fmtNumber(b)} %${bool(d, 'charging') ? ' (charge)' : ''}`);
        const q = num(d, 'queue_depth');
        if (q !== undefined) parts.push(`tampon ${fmtNumber(q)} évt`);
        if (bool(d, 'device_owner') !== undefined) parts.push(`Device Owner ${bool(d, 'device_owner') ? 'oui' : 'non'}`);
        return parts.join(' · ');
      }
      case 'agent.buffer_overflow':
        return `${fmtNumber(num(d, 'dropped'))} événements purgés`;
      case 'agent.collector_error':
        return `${str(d, 'collector') ?? '?'} : ${str(d, 'error') ?? 'erreur'}`;
      case 'agent.config_changed':
        return `${str(d, 'key') ?? '?'} : ${fmtValue(d['old'])} → ${fmtValue(d['new'])}`;
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
        return `${fmtBytes(num(d, 'free_bytes'))} libres sur ${fmtBytes(num(d, 'total_bytes'))}`;
      case 'device.thermal':
        return str(d, 'status') ?? '';
      case 'device.time_changed':
        return `décalage ${fmtDuration(Math.abs(num(d, 'delta_ms') ?? 0))}`;
      case 'device.timezone_changed':
        return str(d, 'tz') ?? '';
      case 'device.usb':
        return `${bool(d, 'connected') ? 'connecté' : 'déconnecté'}${strList(d, 'functions').length ? ` · ${strList(d, 'functions').join(', ')}` : ''}`;
      case 'location.fix': {
        const lat = num(d, 'lat');
        const lon = num(d, 'lon');
        if (lat === undefined || lon === undefined) return 'position incomplète';
        return `${fmtNumber(lat, 5)}, ${fmtNumber(lon, 5)}${num(d, 'acc_m') !== undefined ? ` · ±${fmtNumber(num(d, 'acc_m'))} m` : ''}${bool(d, 'mock') ? ' · SIMULÉE' : ''}`;
      }
      case 'location.provider':
        return `${str(d, 'provider') ?? '?'} ${onOff(bool(d, 'enabled'))}`;
      case 'net.connectivity': {
        const t = strList(d, 'transports').join('+') || 'aucun transport';
        return `${t}${bool(d, 'validated') === false ? ' · non validé' : ''}${bool(d, 'vpn') ? ' · VPN' : ''}${bool(d, 'private_dns_active') ? ' · DNS privé' : ''}`;
      }
      case 'net.wifi':
        return `${str(d, 'event') ?? '?'} · ${str(d, 'ssid') ?? 'SSID inconnu'}${num(d, 'rssi') !== undefined ? ` · ${num(d, 'rssi')} dBm` : ''}${str(d, 'security') ? ` · ${str(d, 'security')}` : ''}`;
      case 'net.wifi_scan':
        return `${list(d, 'aps').length} réseaux`;
      case 'net.cell':
        return `${str(d, 'tech') ?? '?'} · ${str(d, 'operator') ?? `${str(d, 'mcc') ?? '?'}/${str(d, 'mnc') ?? '?'}`}${num(d, 'signal_dbm') !== undefined ? ` · ${num(d, 'signal_dbm')} dBm` : ''}${bool(d, 'roaming') ? ' · itinérance' : ''}`;
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
        return `${str(d, 'kind') ?? 'inconnu'} · ${str(d, 'address') ?? '?'} · ${num(d, 'sightings') ?? '?'} détections`;
      case 'app.inventory':
        return `partie ${num(d, 'part') ?? '?'}/${num(d, 'parts') ?? '?'} · ${list(d, 'apps').length} apps`;
      case 'app.installed':
      case 'app.updated':
      case 'app.removed':
        return `${str(d, 'package') ?? '?'}${str(d, 'version_name') ? ` ${str(d, 'version_name')}` : ''}${str(d, 'installer') ? ` · via ${str(d, 'installer')}` : ''}`;
      case 'app.foreground':
        return `${str(d, 'package') ?? '?'} ${str(d, 'event') ?? ''}`;
      case 'app.permission_changed':
        return `${str(d, 'package') ?? '?'} · ${shortPermission(str(d, 'permission'))} ${bool(d, 'granted') ? 'accordée' : 'retirée'}`;
      case 'app.special_access':
        return `accessibilité ${strList(d, 'accessibility_services').length} · écoute notif. ${strList(d, 'notification_listeners').length} · admins ${strList(d, 'device_admins').length} · VPN ${strList(d, 'vpn_apps').length}`;
      case 'app.notification':
        return describeNotification(d);
      case 'command.result':
        return describeCommandResult(d);
      case 'command.issued':
      case 'command.cancelled':
        return `${commandLabel(str(d, 'type') ?? '?')}${str(d, 'command_id') ? ` · ${str(d, 'command_id')}` : ''}`;
      case 'sensor.camera':
        return `${bool(d, 'in_use') ? 'utilisée' : 'libérée'} · caméra ${str(d, 'camera_id') ?? (num(d, 'camera_id') ?? '?')}${str(d, 'package') ? ` · ${str(d, 'package')}` : ''}`;
      case 'sensor.microphone':
        return `${bool(d, 'recording') ? 'enregistrement' : 'arrêt'}${str(d, 'source') ? ` · ${str(d, 'source')}` : ''}${str(d, 'package') ? ` · ${str(d, 'package')}` : ''}${bool(d, 'silenced') ? ' · silencé' : ''}`;
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
        return 'instantané de posture';
      case 'security.keyguard':
        return `${str(d, 'event') ?? '?'}${num(d, 'failed_attempts') !== undefined ? ` · ${num(d, 'failed_attempts')} échecs` : ''}`;
      case 'security.ca_cert':
        return `${str(d, 'event') ?? '?'} · ${str(d, 'subject') ?? str(d, 'sha256')?.slice(0, 16) ?? '?'}`;
      case 'security.policy':
        return `${str(d, 'action') ?? '?'}${str(d, 'target') ? ` · ${str(d, 'target')}` : ''}${bool(d, 'ok') === false ? ` · ÉCHEC${str(d, 'error') ? ` (${str(d, 'error')})` : ''}` : ''}`;
      default:
        return genericSummary(d);
    }
  } catch {
    return genericSummary(d);
  }
}

const NOTIFICATION_EVENTS: Record<string, string> = { posted: 'publiée', removed: 'retirée' };

/**
 * Notification : application, événement, puis titre et texte s'ils existent. Ces deux champs viennent de
 * n'importe quelle application : ils sont nettoyés (caractères de contrôle, bidirectionnel) et ne sont jamais
 * interprétés. `redacted` : un code numérique de 4 à 8 chiffres a été masqué par le téléphone.
 */
export function describeNotification(d: Record<string, unknown>): string {
  const title = cleanText(d['title']);
  const text = cleanText(d['text']);
  const ev = str(d, 'event');
  const head = `${str(d, 'package') ?? '?'} ${ev ? (NOTIFICATION_EVENTS[ev] ?? ev) : ''}`.trim();
  const content = title && text ? `${title} — ${text}` : title || text;
  const parts = [head];
  if (content) parts.push(`« ${content} »`);
  else if (!bool(d, 'ongoing')) parts.push(str(d, 'category') ?? '');
  if (bool(d, 'redacted')) parts.push('contenu masqué (code numérique)');
  return parts.filter(Boolean).join(' · ');
}

function describeCommandResult(d: Record<string, unknown>): string {
  const status = str(d, 'status');
  const statusLabel = status === 'executed' ? 'exécutée' : status === 'failed' ? 'échec' : status === 'refused' ? 'refusée' : (status ?? '?');
  const detail = str(d, 'detail');
  const why = status === 'refused' ? refusalInfo(detail)?.title : detail;
  return `${commandLabel(str(d, 'type') ?? '?')} · ${statusLabel}${why ? ` (${why})` : ''}${bool(d, 'signed') ? ' · signée' : ''}`;
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
  CAMERA: 'Caméra',
  RECORD_AUDIO: 'Microphone',
  ACCESS_FINE_LOCATION: 'Position précise',
  ACCESS_COARSE_LOCATION: 'Position approximative',
  ACCESS_BACKGROUND_LOCATION: 'Position en arrière-plan',
  READ_CONTACTS: 'Lire les contacts',
  WRITE_CONTACTS: 'Modifier les contacts',
  READ_CALENDAR: "Lire l'agenda",
  WRITE_CALENDAR: "Modifier l'agenda",
  READ_PHONE_STATE: "État du téléphone",
  READ_PHONE_NUMBERS: 'Numéros de téléphone',
  CALL_PHONE: 'Passer des appels',
  READ_CALL_LOG: "Journal d'appels",
  WRITE_CALL_LOG: "Modifier le journal d'appels",
  SEND_SMS: 'Envoyer des SMS',
  READ_SMS: 'Lire les SMS',
  RECEIVE_SMS: 'Recevoir des SMS',
  READ_EXTERNAL_STORAGE: 'Lire le stockage',
  WRITE_EXTERNAL_STORAGE: 'Écrire sur le stockage',
  READ_MEDIA_IMAGES: 'Photos',
  READ_MEDIA_VIDEO: 'Vidéos',
  READ_MEDIA_AUDIO: 'Audio',
  POST_NOTIFICATIONS: 'Notifications',
  BODY_SENSORS: 'Capteurs corporels',
  ACTIVITY_RECOGNITION: 'Activité physique',
  BLUETOOTH_CONNECT: 'Bluetooth (connexion)',
  BLUETOOTH_SCAN: 'Bluetooth (scan)',
  NEARBY_WIFI_DEVICES: 'Appareils Wi-Fi proches',
};

export function permissionLabel(p: string): string {
  const s = shortPermission(p);
  return PERMISSION_LABELS[s] ?? s;
}

/** Noms usuels des installateurs. */
export function installerLabel(installer: string | undefined): string {
  switch (installer) {
    case undefined:
    case '':
      return 'Inconnu / préinstallée';
    case 'com.android.vending':
      return 'Play Store';
    case 'com.sec.android.app.samsungapps':
      return 'Galaxy Store';
    case 'com.android.shell':
      return 'ADB';
    case 'com.google.android.packageinstaller':
    case 'com.android.packageinstaller':
      return 'Installateur de paquets';
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
/** Application utilisateur installée hors Play Store / Galaxy Store. */
export function isSideloaded(a: { system?: boolean; installer?: string }): boolean {
  if (a.system) return false;
  return !a.installer || !TRUSTED_INSTALLERS.has(a.installer);
}
