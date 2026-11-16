// Commandes à distance (contrat §8) : construction du `payload`, validité, signature des commandes sensibles.
//
// Le navigateur construit `payload` (une chaîne JSON sérialisée UNE seule fois : ce sont ces octets exacts qui
// sont signés puis relayés), génère l'identifiant ULID et signe les commandes sensibles par WebCrypto :
//   K   = PBKDF2-HMAC-SHA256(code, sel = "vigie-cmd-v1:" + device_id, 600 000 itérations, 32 octets)
//   sig = base64(HMAC-SHA256(K, octets UTF-8 de payload))
// Le code et K ne sont jamais stockés ni envoyés : ils n'existent que dans les variables locales de
// `signPayload` le temps du calcul.
import { ulid } from './ulid.ts';

export type CommandType = 'ring' | 'vibrate' | 'stop_ring' | 'locate' | 'lock' | 'clear_lock_message' | 'wipe';

export const COMMAND_TYPES: readonly CommandType[] = ['ring', 'vibrate', 'stop_ring', 'locate', 'lock', 'clear_lock_message', 'wipe'];
const SENSITIVE_TYPES: ReadonlySet<string> = new Set<CommandType>(['lock', 'clear_lock_message', 'wipe']);

export function isCommandType(v: string): v is CommandType {
  return (COMMAND_TYPES as readonly string[]).includes(v);
}
export function isSensitive(type: string): boolean {
  return SENSITIVE_TYPES.has(type);
}

export const COMMAND_LABELS: Record<CommandType, string> = {
  ring: 'Sonner',
  vibrate: 'Vibrer',
  stop_ring: 'Arrêter la sonnerie',
  locate: 'Localiser maintenant',
  lock: 'Verrouiller avec message',
  clear_lock_message: 'Effacer le message',
  wipe: 'Effacer le téléphone',
};

export function commandLabel(type: string): string {
  return isCommandType(type) ? COMMAND_LABELS[type] : type;
}

export const HOUR_MS = 3_600_000;
export const DAY_MS = 86_400_000;

export const LIMITS = {
  ringDefault: 60,
  ringMax: 300,
  vibrateDefault: 10,
  vibrateMax: 60,
  messageMax: 200,
  codeMin: 12,
  /** durée de validité par défaut : 1 h (simple), 7 jours (sensible) */
  validitySimpleMs: HOUR_MS,
  validitySensitiveMs: 7 * DAY_MS,
  validityMaxMs: 30 * DAY_MS,
} as const;

export interface CommandParams {
  duration_s?: number;
  vibrate?: boolean;
  message?: string;
}

/** Caractère de contrôle (C0, DEL, C1) autre que le saut de ligne. */
export function hasForbiddenControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c < 0x20 && c !== 0x0a) || (c >= 0x7f && c <= 0x9f)) return true;
  }
  return false;
}

/** Message d'erreur en français si les paramètres sont hors bornes, sinon undefined. */
export function validateParams(type: CommandType, p: CommandParams): string | undefined {
  const dur = (v: number | undefined, max: number): string | undefined =>
    v !== undefined && (!Number.isInteger(v) || v < 1 || v > max) ? `La durée doit être un nombre entier de secondes entre 1 et ${max}.` : undefined;
  switch (type) {
    case 'ring':
      return dur(p.duration_s, LIMITS.ringMax);
    case 'vibrate':
      return dur(p.duration_s, LIMITS.vibrateMax);
    case 'lock':
      // Contrat §8 : 200 unités UTF-16 au plus, aucun caractère de contrôle sauf le saut de ligne.
      if (p.message !== undefined && p.message.length > LIMITS.messageMax) return `Le message ne doit pas dépasser ${LIMITS.messageMax} caractères.`;
      if (p.message !== undefined && hasForbiddenControl(p.message)) return 'Le message ne doit contenir aucun caractère de contrôle (seul le saut de ligne est permis).';
      return undefined;
    default:
      return undefined;
  }
}

export function defaultValidityMs(type: CommandType): number {
  return isSensitive(type) ? LIMITS.validitySensitiveMs : LIMITS.validitySimpleMs;
}

export interface PayloadInput {
  id: string;
  deviceId: string;
  type: CommandType;
  params?: CommandParams;
  issuedAt: Date;
  validityMs: number;
}

/**
 * Construit le `payload` : l'ordre des clés est celui du contrat. Les paramètres inutiles sont omis
 * (`params` vaut `{}` pour une commande sans paramètre).
 */
export function buildPayload(i: PayloadInput): string {
  const params = i.params ?? {};
  const err = validateParams(i.type, params);
  if (err) throw new Error(err);
  if (!Number.isFinite(i.validityMs) || i.validityMs <= 0 || i.validityMs > LIMITS.validityMaxMs) {
    throw new Error('La durée de validité doit être comprise entre 1 ms et 30 jours.');
  }
  const out: Record<string, unknown> = {};
  switch (i.type) {
    case 'ring':
      out['duration_s'] = params.duration_s ?? LIMITS.ringDefault;
      out['vibrate'] = params.vibrate ?? true;
      break;
    case 'vibrate':
      out['duration_s'] = params.duration_s ?? LIMITS.vibrateDefault;
      break;
    case 'lock':
      if (params.message !== undefined && params.message.trim() !== '') out['message'] = params.message;
      break;
    default:
      break;
  }
  const payload = {
    v: 1,
    id: i.id,
    device_id: i.deviceId,
    type: i.type,
    params: out,
    issued_at: i.issuedAt.toISOString(),
    expires_at: new Date(i.issuedAt.getTime() + i.validityMs).toISOString(),
  };
  return JSON.stringify(payload);
}

// ----------------------------------------------------------------------------------------- signature

export class CryptoUnavailableError extends Error {
  constructor() {
    super("WebCrypto n'est pas disponible : la console doit être ouverte en HTTPS (ou sur localhost) pour signer une commande.");
    this.name = 'CryptoUnavailableError';
  }
}

export function canSign(): boolean {
  return typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.subtle !== 'undefined';
}

const PBKDF2_ITERATIONS = 600_000;
const enc = new TextEncoder();

/** K = PBKDF2-HMAC-SHA256(code, "vigie-cmd-v1:" + device_id, 600 000, 32 octets). Exposé pour les tests. */
export async function deriveKeyBytes(code: string, deviceId: string): Promise<Uint8Array<ArrayBuffer>> {
  if (!canSign()) throw new CryptoUnavailableError();
  const base = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(`vigie-cmd-v1:${deviceId}`), iterations: PBKDF2_ITERATIONS },
    base,
    256,
  );
  return new Uint8Array(bits);
}

export function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** sig = base64(HMAC-SHA256(K, UTF-8(payload))). La clé dérivée est effacée de la mémoire dès qu'elle est importée. */
export async function signPayload(code: string, deviceId: string, payload: string): Promise<string> {
  const k = await deriveKeyBytes(code, deviceId);
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  } finally {
    k.fill(0);
  }
  const mac = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  return toBase64(new Uint8Array(mac));
}

export function codeProblem(code: string): string | undefined {
  const n = Array.from(code).length;
  if (n === 0) return undefined;
  if (n < LIMITS.codeMin) return `Le code de commande compte au moins ${LIMITS.codeMin} caractères (${n} saisis).`;
  return undefined;
}

// ---------------------------------------------------------------------------- états et motifs de refus

export type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'info';

export interface StatusInfo {
  label: string;
  tone: Tone;
  /** vrai tant que la commande peut encore évoluer */
  active: boolean;
  help: string;
}

export function statusInfo(status: string): StatusInfo {
  switch (status) {
    case 'pending':
      return { label: 'En attente', tone: 'info', active: true, help: "Le serveur la garde : le téléphone ne l'a pas encore récupérée. Elle peut être annulée." };
    case 'delivered':
      return {
        label: 'Remise',
        tone: 'info',
        active: true,
        help: "Remise au téléphone, résultat attendu ; elle ne peut plus être annulée. Si le résultat n'arrive pas, le serveur la renvoie après 5 minutes (3 fois au plus) : elle peut rester « Remise » un moment.",
      };
    case 'executed':
      return { label: 'Exécutée', tone: 'ok', active: false, help: 'Le téléphone a exécuté la commande.' };
    case 'failed':
      return { label: 'Échec', tone: 'bad', active: false, help: "Le téléphone a essayé mais n'y est pas arrivé." };
    case 'refused':
      return { label: 'Refusée', tone: 'warn', active: false, help: 'Le téléphone a refusé la commande (motif ci-dessous).' };
    case 'expired':
      return { label: 'Expirée', tone: 'neutral', active: false, help: "Le téléphone ne l'a pas récupérée avant son expiration : elle ne sera jamais exécutée." };
    case 'cancelled':
      return { label: 'Annulée', tone: 'neutral', active: false, help: "Annulée avant d'être remise : elle ne sera jamais exécutée." };
    default:
      return { label: status, tone: 'neutral', active: false, help: 'État inconnu de cette version de la console.' };
  }
}

export interface Refusal {
  /** libellé court */
  title: string;
  /** explication complète */
  help: string;
  tone: Tone;
}

/** Traduit le `detail` d'un `command.result` refusé (motifs du contrat §8). */
export function refusalInfo(detail: string | undefined): Refusal | undefined {
  if (!detail) return undefined;
  switch (detail) {
    case 'disabled':
      return {
        title: 'Canal désactivé',
        tone: 'warn',
        help: "Le canal de commandes est désactivé dans l'application, ou, pour un effacement, « Autoriser l'effacement à distance » n'y est pas activé (c'est éteint par défaut).",
      };
    case 'malformed':
      return { title: 'Commande illisible', tone: 'warn', help: "Le téléphone n'a pas pu lire la commande (format ou identifiant incohérent)." };
    case 'wrong_device':
      return { title: 'Autre appareil', tone: 'warn', help: 'La commande désigne un autre appareil que celui-ci.' };
    case 'unknown_type':
      return { title: 'Commande inconnue', tone: 'warn', help: "Cette version de l'agent ne connaît pas ce type de commande." };
    case 'no_code_configured':
      return {
        title: 'Aucun code défini',
        tone: 'warn',
        help: "Aucun code de commande n'est défini dans l'application du téléphone : il faut le choisir sur le téléphone avant de pouvoir verrouiller ou effacer à distance.",
      };
    case 'bad_signature':
      return {
        title: 'Signature invalide (code incorrect ?)',
        tone: 'bad',
        help: "La signature ne correspond pas au code défini dans l'application : le code saisi ici n'est probablement pas le bon (ou le nom de l'appareil a changé). Seul le téléphone peut le constater, le serveur ne connaît pas le code. Attention : 5 signatures invalides en une heure bloquent toutes les commandes sensibles pendant une heure.",
      };
    case 'expired':
      return { title: 'Expirée', tone: 'warn', help: "La commande était périmée à son arrivée sur le téléphone (tolérance d'horloge de 5 minutes)." };
    case 'replay':
      return { title: 'Déjà exécutée', tone: 'warn', help: "Le téléphone a déjà exécuté une commande portant cet identifiant : elle n'est pas rejouée." };
    case 'bad_params':
      return { title: 'Paramètres hors bornes', tone: 'warn', help: 'Les paramètres de la commande sont hors des bornes acceptées par le téléphone.' };
    case 'not_device_owner':
      return {
        title: "Vigie n'est pas Device Owner",
        tone: 'warn',
        help: "Verrouiller, effacer le message ou effacer le téléphone exigent que l'agent soit Device Owner (activation par ADB) : l'agent tourne ici en mode dégradé.",
      };
    case 'locked_out':
      return {
        title: 'Commandes sensibles bloquées',
        tone: 'bad',
        help: "Après 5 signatures invalides en une heure, le téléphone refuse toute commande sensible pendant une heure. Attendez, puis réessayez avec le bon code.",
      };
    default:
      return { title: 'Motif non reconnu', tone: 'neutral', help: detail };
  }
}

// ----------------------------------------------------------------------------------- canal de commandes

export interface CommandChannel {
  connected?: boolean;
  mode?: 'stream' | 'poll' | 'unknown' | string;
  last_contact?: string;
}

export interface ChannelState {
  key: 'connected' | 'polling' | 'offline' | 'unknown';
  label: string;
  tone: Tone;
  /** explication du délai à prévoir */
  hint: string;
}

/** Au-delà de ce délai sans contact, un agent en interrogation (toutes les 1 à 15 min) est considéré hors ligne. */
export const POLL_STALE_MS = 20 * 60_000;

/**
 * État du canal. En mode `poll`, `connected` ne dit rien (le collecteur réel le laisse à faux : il n'y a pas de
 * connexion ouverte) : on juge sur la fraîcheur de `last_contact`.
 */
export function channelState(ch: CommandChannel | undefined, now: Date = new Date()): ChannelState {
  if (!ch) {
    return { key: 'unknown', label: 'État inconnu', tone: 'neutral', hint: "Le collecteur ne renseigne pas l'état du canal de commandes." };
  }
  if (ch.mode === 'poll') {
    const t = Date.parse(ch.last_contact ?? '');
    const fresh = Number.isFinite(t) && now.getTime() - t < POLL_STALE_MS;
    return ch.connected || fresh
      ? { key: 'polling', label: 'Interrogation périodique', tone: 'ok', hint: "Le téléphone vient chercher les commandes toutes les 1 à 15 minutes : une commande peut attendre jusqu'au prochain passage." }
      : { key: 'offline', label: 'Hors ligne', tone: 'bad', hint: "Le téléphone n'a pas interrogé le serveur récemment (interrogation périodique, toutes les 1 à 15 minutes). Les commandes restent en attente jusqu'à son retour ou leur expiration." };
  }
  if (ch.connected) {
    return { key: 'connected', label: 'Connecté', tone: 'ok', hint: 'Connexion permanente : les commandes sont remises presque immédiatement.' };
  }
  return {
    key: 'offline',
    label: 'Hors ligne',
    tone: 'bad',
    hint: "Le téléphone n'est pas connecté au canal de commandes (éteint, hors réseau, canal désactivé dans l'application ou agent arrêté). Les commandes restent en attente jusqu'à son retour ou leur expiration.",
  };
}

/** Résumé d'une ligne des paramètres d'une commande pour l'historique. */
export function paramsSummary(type: string, params: Record<string, unknown> | undefined): string {
  const p = params ?? {};
  switch (type) {
    case 'ring': {
      const d = typeof p['duration_s'] === 'number' ? p['duration_s'] : undefined;
      return `${d !== undefined ? `${d} s` : 'durée par défaut'}${p['vibrate'] === false ? ', sans vibration' : ', avec vibration'}`;
    }
    case 'vibrate':
      return typeof p['duration_s'] === 'number' ? `${p['duration_s']} s` : '';
    case 'lock':
      return typeof p['message'] === 'string' && p['message'] ? `message : « ${p['message']} »` : 'sans message';
    default:
      return '';
  }
}

export interface Prepared {
  id: string;
  payload: string;
  issuedAt: Date;
}

/** Identifiant et payload d'une nouvelle commande (la signature se calcule ensuite, si elle est requise). */
export function prepareCommand(deviceId: string, type: CommandType, params: CommandParams, validityMs: number, now: Date = new Date()): Prepared {
  const id = ulid(now.getTime());
  return { id, payload: buildPayload({ id, deviceId, type, params, issuedAt: now, validityMs }), issuedAt: now };
}

/**
 * Commandes refusées pour signature invalide dans la dernière heure (le téléphone bloque les commandes sensibles
 * à la cinquième). Se base sur l'heure du résultat, sinon de la création.
 */
export function badSignatureCount(cmds: { status: string; detail?: string | undefined; result_at?: string | undefined; created_at?: string | undefined }[], now: Date = new Date()): number {
  const since = now.getTime() - HOUR_MS;
  return cmds.filter((c) => {
    if (c.status !== 'refused' || c.detail !== 'bad_signature') return false;
    const t = Date.parse(c.result_at ?? c.created_at ?? '');
    return Number.isFinite(t) && t >= since;
  }).length;
}

// ------------------------------------------------------------------------- horloge et erreurs d'envoi

/** Écart d'horloge au-delà duquel le serveur refuse `issued_at` (10 min) : on prévient un peu avant. */
export const SKEW_WARN_MS = 8 * 60_000;

export function clockProblem(skewMs: number | undefined): string | undefined {
  if (skewMs === undefined || Math.abs(skewMs) < SKEW_WARN_MS) return undefined;
  const min = Math.round(Math.abs(skewMs) / 60_000);
  return `L'horloge de cet ordinateur est décalée d'environ ${min} minutes par rapport au serveur (${skewMs > 0 ? 'en retard' : 'en avance'}) : le serveur refusera les commandes (écart de 10 minutes au plus). Corrigez la date et l'heure de cet appareil.`;
}

/** Message utile pour l'échec de `POST /commands`. */
export function commandErrorMessage(e: { status: number; code: string; message: string }): string {
  if (e.code === 'invalid_validity' && /issued_at|10 minutes/.test(e.message)) {
    return "Horloge de cet ordinateur décalée : l'heure d'émission de la commande est à plus de 10 minutes de l'heure du serveur. Corrigez la date et l'heure de cet appareil, puis recommencez.";
  }
  switch (e.code) {
    case 'rate_limited':
      return `Limite atteinte (20 commandes par heure, 10 en attente par appareil) : ${e.message}`;
    case 'device_revoked':
      return 'Cet appareil est révoqué : aucune commande ne peut lui être envoyée.';
    case 'duplicate_id':
      return 'Identifiant de commande déjà utilisé : recommencez.';
    case 'signature_required':
    case 'invalid_signature':
    case 'signature_not_allowed':
      return `Signature refusée par le serveur (${e.message}).`;
    case 'bad_params':
    case 'invalid_payload':
    case 'invalid_validity':
      return `Commande invalide : ${e.message}`;
    default:
      return e.status === 429 ? `Limite atteinte : ${e.message}` : e.message;
  }
}
