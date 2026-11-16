// Profil de risque factice (contrat §11.2, `app.risk`) : codes de raison de la liste fermée, score et niveau.
import type { MockApp } from './catalog.ts';

export type Level = 'low' | 'medium' | 'high';

export interface RiskProfile {
  score: number;
  level: Level;
  reasons: string[];
  /** capacités accordées parmi les raisons (contrat §11.4) : le reste est déclaré mais non accordé */
  granted: string[];
  from_store: boolean;
  installer?: string;
}

const WEIGHT: Record<string, number> = {
  sideloaded: 12,
  unknown_installer: 8,
  no_launcher_icon: 15,
  sms_send: 18,
  sms_read: 12,
  calls: 8,
  accessibility_service: 20,
  notification_listener: 15,
  device_admin: 15,
  overlay: 12,
  install_packages: 12,
  vpn_service: 8,
  boot_receiver: 5,
  background_location: 8,
  mic_camera_background: 10,
  old_target_sdk: 5,
  debuggable: 10,
  combo_banking_trojan: 30,
  combo_sms_fraud: 30,
  combo_stalkerware: 25,
};

/** Profils choisis à la main pour les applications qui racontent une histoire. */
const EXPLICIT: Record<string, { score: number; reasons: string[]; granted?: string[] }> = {
  'com.fastcleaner.pro': {
    score: 96,
    reasons: ['combo_banking_trojan', 'accessibility_service', 'overlay', 'notification_listener', 'sms_read', 'install_packages', 'sideloaded', 'unknown_installer', 'boot_receiver', 'mic_camera_background'],
    // Le micro et la caméra en arrière-plan sont demandés mais pas accordés (refus de la garde) : le score reste élevé.
    granted: ['accessibility_service', 'overlay', 'notification_listener', 'sms_read', 'install_packages', 'boot_receiver'],
  },
  'com.wallpapers.superhd': { score: 88, reasons: ['combo_sms_fraud', 'sms_send', 'boot_receiver', 'sideloaded', 'unknown_installer'], granted: ['sms_send', 'boot_receiver'] },
  'com.sync.helper.svc': {
    score: 79,
    reasons: ['combo_stalkerware', 'no_launcher_icon', 'background_location', 'mic_camera_background', 'boot_receiver', 'sideloaded', 'old_target_sdk'],
    // Quarantaine : rien n'est accordé de ce qui touche à la position, au micro ou à la caméra.
    granted: ['boot_receiver'],
  },
  'org.fdroid.fdroid': { score: 41, reasons: ['sideloaded', 'install_packages', 'boot_receiver'] },
  'com.google.android.apps.messaging': { score: 38, reasons: ['sms_send', 'sms_read', 'boot_receiver'] },
  'com.waze': { score: 36, reasons: ['background_location', 'mic_camera_background', 'boot_receiver', 'quantum_overlay'] },
  'com.facebook.katana': { score: 27, reasons: ['boot_receiver', 'background_location', 'calls'] },
  'com.whatsapp': { score: 19, reasons: ['calls', 'boot_receiver'] },
  'io.github.erwsim.watchpost': { score: 18, reasons: ['device_admin', 'boot_receiver', 'background_location', 'mic_camera_background'] },
  'com.samsung.android.messaging': { score: 15, reasons: ['sms_send', 'sms_read', 'boot_receiver'] },
  'com.samsung.android.dialer': { score: 12, reasons: ['calls', 'boot_receiver'] },
  'com.google.android.marvin.talkback': { score: 14, reasons: ['accessibility_service'] },
  'com.google.android.gms': { score: 22, reasons: ['background_location', 'mic_camera_background', 'boot_receiver', 'vpn_service'] },
};

const levelOf = (score: number): Level => (score >= 65 ? 'high' : score >= 35 ? 'medium' : 'low');

/** Raisons déduites des permissions et de l'installateur, pour les applications sans profil choisi. */
function derive(a: MockApp): string[] {
  const r: string[] = [];
  const has = (p: string) => a.perms.some((x) => x.endsWith(`.${p}`));
  if (!a.system && (!a.installer || (a.installer !== 'com.android.vending' && a.installer !== 'com.sec.android.app.samsungapps'))) r.push('sideloaded');
  if (has('SEND_SMS')) r.push('sms_send');
  if (has('READ_SMS') || has('RECEIVE_SMS')) r.push('sms_read');
  if (has('CALL_PHONE') || has('READ_CALL_LOG')) r.push('calls');
  if (has('ACCESS_BACKGROUND_LOCATION')) r.push('background_location');
  if (has('RECORD_AUDIO') && has('CAMERA') && !a.system) r.push('mic_camera_background');
  return r;
}

export function profileOf(a: MockApp): RiskProfile {
  const e = EXPLICIT[a.package];
  const reasons = e ? e.reasons : derive(a);
  let score = e ? e.score : Math.min(100, reasons.reduce((s, c) => s + (WEIGHT[c] ?? 0), 0) + 3);
  const capped = a.system || a.package === 'io.github.erwsim.watchpost';
  if (capped) score = Math.min(score, 25);
  const level = capped ? 'low' : levelOf(score);
  const fromStore = a.system ? true : a.installer === 'com.android.vending' || a.installer === 'com.sec.android.app.samsungapps';
  return { score, level, reasons, granted: e?.granted ?? reasons, from_store: fromStore, ...(a.installer ? { installer: a.installer } : {}) };
}
