// Remote commands (contract §8): building the `payload`, validity, signing of sensitive commands.
//
// The browser builds `payload` (a JSON string serialised ONCE: these exact bytes are
// signed then relayed), generates the ULID identifier and signs sensitive commands with WebCrypto:
//   K   = PBKDF2-HMAC-SHA256(passphrase, salt = "watchpost-cmd-v1:" + device_id, 600,000 iterations, 32 bytes)
//   sig = base64(HMAC-SHA256(K, UTF-8 bytes of payload))
// The passphrase and K are never stored or sent: they only exist in the local variables of
// `signPayload` for the duration of the computation.
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
  ring: 'Ring',
  vibrate: 'Vibrate',
  stop_ring: 'Stop ringing',
  locate: 'Locate now',
  lock: 'Lock with message',
  clear_lock_message: 'Clear the message',
  wipe: 'Erase the phone',
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
  /** default validity: 1 h (simple), 7 days (lock), 15 min (erase) */
  validitySimpleMs: HOUR_MS,
  validitySensitiveMs: 7 * DAY_MS,
  validityMaxMs: 30 * DAY_MS,
  /** erase: 15 min by default and 24 h at most (contract §8) */
  validityWipeMs: 15 * 60_000,
  validityWipeMaxMs: DAY_MS,
} as const;

export interface CommandParams {
  duration_s?: number;
  vibrate?: boolean;
  message?: string;
}

/**
 * Control character (C0, DEL, C1) other than the line feed, or Unicode line/paragraph separator
 * (U+2028, U+2029): the collector refuses the same ones (`bad_params`), so better to say so before signing.
 */
export function hasForbiddenControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c < 0x20 && c !== 0x0a) || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029) return true;
  }
  return false;
}

/** Error message if the parameters are out of bounds, otherwise undefined. */
export function validateParams(type: CommandType, p: CommandParams): string | undefined {
  const dur = (v: number | undefined, max: number): string | undefined =>
    v !== undefined && (!Number.isInteger(v) || v < 1 || v > max) ? `The duration must be a whole number of seconds between 1 and ${max}.` : undefined;
  switch (type) {
    case 'ring':
      return dur(p.duration_s, LIMITS.ringMax);
    case 'vibrate':
      return dur(p.duration_s, LIMITS.vibrateMax);
    case 'lock':
      // Contract §8: at most 200 UTF-16 units, no control character except the line feed.
      if (p.message !== undefined && p.message.length > LIMITS.messageMax) return `The message must not exceed ${LIMITS.messageMax} characters.`;
      if (p.message !== undefined && hasForbiddenControl(p.message)) return 'The message must not contain any control character (only the line feed is allowed).';
      return undefined;
    default:
      return undefined;
  }
}

export function defaultValidityMs(type: CommandType): number {
  if (type === 'wipe') return LIMITS.validityWipeMs;
  return isSensitive(type) ? LIMITS.validitySensitiveMs : LIMITS.validitySimpleMs;
}

/** Maximum validity: 24 h for an erase, 30 days for the others. */
export function maxValidityMs(type: CommandType): number {
  return type === 'wipe' ? LIMITS.validityWipeMaxMs : LIMITS.validityMaxMs;
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
 * Builds the `payload`: the key order is the contract's. Unneeded parameters are omitted
 * (`params` is `{}` for a command without parameters).
 */
export function buildPayload(i: PayloadInput): string {
  const params = i.params ?? {};
  const err = validateParams(i.type, params);
  if (err) throw new Error(err);
  if (!Number.isFinite(i.validityMs) || i.validityMs <= 0 || i.validityMs > maxValidityMs(i.type)) {
    throw new Error(i.type === 'wipe' ? 'The validity of an erase cannot exceed 24 hours.' : 'The validity duration must be between 1 ms and 30 days.');
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
    super('WebCrypto is not available: the console must be opened over HTTPS (or on localhost) to sign a command.');
    this.name = 'CryptoUnavailableError';
  }
}

export function canSign(): boolean {
  return typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.subtle !== 'undefined';
}

const PBKDF2_ITERATIONS = 600_000;
const enc = new TextEncoder();

/** K = PBKDF2-HMAC-SHA256(passphrase, "watchpost-cmd-v1:" + device_id, 600,000, 32 bytes). Exposed for tests. */
export async function deriveKeyBytes(code: string, deviceId: string): Promise<Uint8Array<ArrayBuffer>> {
  if (!canSign()) throw new CryptoUnavailableError();
  const base = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(`watchpost-cmd-v1:${deviceId}`), iterations: PBKDF2_ITERATIONS },
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

/** sig = base64(HMAC-SHA256(K, UTF-8(payload))). The derived key is wiped from memory as soon as it is imported. */
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
  if (n < LIMITS.codeMin) return `The command passphrase must be at least ${LIMITS.codeMin} characters long (${n} entered).`;
  return undefined;
}

// ---------------------------------------------------------------------------- states and refusal reasons

export type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'info';

export interface StatusInfo {
  label: string;
  tone: Tone;
  /** true while the command can still change */
  active: boolean;
  help: string;
}

/** Caveat on a signed command: the server is not the only one to hold the command. */
export const SIGNED_CAVEAT =
  'This only commits the server: a signed command remains executable by the phone until its expiry date if a copy exists (compromised server, retained copy). Only changing the command passphrase in the phone app makes it void.';

/**
 * `delivered`: the command had been handed to the phone (`delivered_at` set). `signed`: sensitive command,
 * for which "cancelled" and "expired" are only the server's state (contract §8).
 */
export function statusInfo(status: string, delivered = false, signed = false): StatusInfo {
  if (status === 'expired' && delivered) {
    // Delivered then no report: we do not know what the phone did with it. An erase, in particular,
    // powers the phone off ten seconds after trying to send its result.
    return {
      label: 'Expired without a response',
      tone: 'warn',
      active: false,
      help: 'It had been handed to the phone, but no result came back before it expired: it may have been executed without the report reaching the server (this is the probable case for an erase).',
    };
  }
  switch (status) {
    case 'pending':
      return { label: 'Pending', tone: 'info', active: true, help: 'The server holds it: the phone has not fetched it yet. It can be cancelled.' };
    case 'delivered':
      return {
        label: 'Delivered',
        tone: 'info',
        active: true,
        help: 'Handed to the phone, result awaited; it can no longer be cancelled. If the result does not arrive, the server sends it again after 5 minutes (3 times at most): it may stay "Delivered" for a while.',
      };
    case 'executed':
      return { label: 'Executed', tone: 'ok', active: false, help: 'The phone executed the command.' };
    case 'failed':
      return { label: 'Failed', tone: 'bad', active: false, help: 'The phone tried but did not manage to.' };
    case 'refused':
      return { label: 'Refused', tone: 'warn', active: false, help: 'The phone refused the command (reason below).' };
    case 'expired':
      return signed
        ? { label: 'Expired (server side)', tone: 'neutral', active: false, help: `The server no longer delivers it. ${SIGNED_CAVEAT}` }
        : { label: 'Expired', tone: 'neutral', active: false, help: 'The phone did not fetch it before it expired: it will never be executed.' };
    case 'cancelled':
      return signed
        ? { label: 'Cancelled (server side)', tone: 'neutral', active: false, help: `Cancelled before being delivered: the server will no longer deliver it. ${SIGNED_CAVEAT}` }
        : { label: 'Cancelled', tone: 'neutral', active: false, help: 'Cancelled before being delivered: it will never be executed.' };
    default:
      return { label: status, tone: 'neutral', active: false, help: 'State unknown to this version of the console.' };
  }
}

export interface Refusal {
  /** short label */
  title: string;
  /** full explanation */
  help: string;
  tone: Tone;
}

/** Translates the `detail` of a refused `command.result` (reasons of contract §8). */
export function refusalInfo(detail: string | undefined): Refusal | undefined {
  if (!detail) return undefined;
  switch (detail) {
    case 'disabled':
      return {
        title: 'Channel disabled',
        tone: 'warn',
        help: 'The command channel is disabled in the app or, for an erase, "Allow remote erase" is not enabled there (it is off by default).',
      };
    case 'malformed':
      return { title: 'Unreadable command', tone: 'warn', help: 'The phone could not read the command (inconsistent format or identifier).' };
    case 'wrong_device':
      return { title: 'Other device', tone: 'warn', help: 'The command names a different device than this one.' };
    case 'unknown_type':
      return { title: 'Unknown command', tone: 'warn', help: 'This version of the agent does not know this type of command.' };
    case 'no_code_configured':
      return {
        title: 'No passphrase set',
        tone: 'warn',
        help: 'No command passphrase is set in the phone app: it must be chosen on the phone before locking or erasing remotely.',
      };
    case 'bad_signature':
      return {
        title: 'Invalid signature (wrong passphrase?)',
        tone: 'bad',
        help: 'The signature does not match the passphrase set in the app: the passphrase entered here is probably not the right one (or the device name changed). Only the phone can tell, the server does not know the passphrase. Warning: 5 invalid signatures within an hour block all sensitive commands for an hour.',
      };
    case 'expired':
      return { title: 'Expired', tone: 'warn', help: 'The command was already out of date when it reached the phone (clock tolerance of 5 minutes).' };
    case 'replay':
      return { title: 'Already executed', tone: 'warn', help: 'The phone already executed a command with this identifier: it is not replayed.' };
    case 'bad_params':
      return { title: 'Parameters out of bounds', tone: 'warn', help: "The command's parameters are outside the bounds accepted by the phone." };
    case 'not_device_owner':
      return {
        title: 'Watchpost is not Device Owner',
        tone: 'warn',
        help: 'Locking, clearing the message or erasing the phone require the agent to be Device Owner (activated through ADB): the agent is running here in degraded mode.',
      };
    case 'locked_out':
      return {
        title: 'Sensitive commands blocked',
        tone: 'bad',
        help: 'After 5 invalid signatures within an hour, the phone refuses every sensitive command for an hour. Wait, then try again with the right passphrase.',
      };
    default:
      return { title: 'Unrecognised reason', tone: 'neutral', help: detail };
  }
}

// ----------------------------------------------------------------------------------- command channel

export interface CommandChannel {
  connected?: boolean;
  mode?: 'stream' | 'poll' | 'unknown' | string;
  last_contact?: string;
}

export interface ChannelState {
  key: 'connected' | 'polling' | 'offline' | 'unknown';
  label: string;
  tone: Tone;
  /** explanation of the delay to expect */
  hint: string;
}

/** Beyond this delay without contact, a polling agent (every 1 to 15 min) is considered offline. */
export const POLL_STALE_MS = 20 * 60_000;

/**
 * Channel state. In `poll` mode, `connected` says nothing (the real collector leaves it false: there is no
 * open connection): we judge by the freshness of `last_contact`.
 */
export function channelState(ch: CommandChannel | undefined, now: Date = new Date()): ChannelState {
  if (!ch) {
    return { key: 'unknown', label: 'Unknown state', tone: 'neutral', hint: 'The collector does not report the state of the command channel.' };
  }
  if (ch.mode === 'poll') {
    const t = Date.parse(ch.last_contact ?? '');
    const fresh = Number.isFinite(t) && now.getTime() - t < POLL_STALE_MS;
    return ch.connected || fresh
      ? { key: 'polling', label: 'Periodic polling', tone: 'ok', hint: 'The phone fetches commands every 1 to 15 minutes: a command may wait until the next visit.' }
      : { key: 'offline', label: 'Offline', tone: 'bad', hint: 'The phone has not polled the server recently (periodic polling, every 1 to 15 minutes). Commands stay pending until it comes back or they expire.' };
  }
  if (ch.connected) {
    return { key: 'connected', label: 'Connected', tone: 'ok', hint: 'Permanent connection: commands are delivered almost immediately.' };
  }
  return {
    key: 'offline',
    label: 'Offline',
    tone: 'bad',
    hint: 'The phone is not connected to the command channel (powered off, out of network, channel disabled in the app or agent stopped). Commands stay pending until it comes back or they expire.',
  };
}

/** One-line summary of a command's parameters for the history. */
export function paramsSummary(type: string, params: Record<string, unknown> | undefined): string {
  const p = params ?? {};
  switch (type) {
    case 'ring': {
      const d = typeof p['duration_s'] === 'number' ? p['duration_s'] : undefined;
      return `${d !== undefined ? `${d} s` : 'default duration'}${p['vibrate'] === false ? ', without vibration' : ', with vibration'}`;
    }
    case 'vibrate':
      return typeof p['duration_s'] === 'number' ? `${p['duration_s']} s` : '';
    case 'lock':
      return typeof p['message'] === 'string' && p['message'] ? `message: "${p['message']}"` : 'no message';
    default:
      return '';
  }
}

export interface Prepared {
  id: string;
  payload: string;
  issuedAt: Date;
}

/** Identifier and payload of a new command (the signature is computed afterwards, if required). */
export function prepareCommand(deviceId: string, type: CommandType, params: CommandParams, validityMs: number, now: Date = new Date()): Prepared {
  const id = ulid(now.getTime());
  return { id, payload: buildPayload({ id, deviceId, type, params, issuedAt: now, validityMs }), issuedAt: now };
}

/**
 * Commands refused for an invalid signature in the last hour (the phone blocks sensitive commands
 * at the fifth). Based on the result time, otherwise on the creation time.
 */
export function badSignatureCount(cmds: { status: string; detail?: string | undefined; result_at?: string | undefined; created_at?: string | undefined }[], now: Date = new Date()): number {
  const since = now.getTime() - HOUR_MS;
  return cmds.filter((c) => {
    if (c.status !== 'refused' || c.detail !== 'bad_signature') return false;
    const t = Date.parse(c.result_at ?? c.created_at ?? '');
    return Number.isFinite(t) && t >= since;
  }).length;
}

// ------------------------------------------------------------------------- clock and sending errors

/** Clock offset beyond which the server refuses `issued_at` (10 min), and maximum correction applied. */
export const SKEW_WARN_MS = 10 * 60_000;
/** Below this, the measured offset (`Date` header, to the second, plus network delay) is only noise. */
const SKEW_NOISE_MS = 30_000;

/**
 * Issue time (`issued_at`) of a command. This browser's clock is authoritative, corrected by the offset measured
 * against the server (`skewMs` = server − browser) when it is plausible: the phone refuses (`expired`) a
 * command issued more than 5 min in its future whereas the server tolerates 10, so a computer
 * 5 to 10 min ahead produced commands accepted by the server then refused by the phone.
 * Beyond 10 min the offset is never followed (the server will refuse, and the user is warned): a compromised
 * server must not be able to get a command dated in the future signed, which would stay valid long after.
 */
export function issueTime(nowMs: number, skewMs: number | undefined): Date {
  if (skewMs === undefined || !Number.isFinite(skewMs)) return new Date(nowMs);
  const a = Math.abs(skewMs);
  return new Date(a >= SKEW_NOISE_MS && a <= SKEW_WARN_MS ? nowMs + Math.round(skewMs) : nowMs);
}

export function clockProblem(skewMs: number | undefined): string | undefined {
  if (skewMs === undefined || Math.abs(skewMs) <= SKEW_WARN_MS) return undefined;
  const min = Math.round(Math.abs(skewMs) / 60_000);
  return `This computer's clock is about ${min} minutes off from the server (${skewMs > 0 ? 'behind' : 'ahead'}): the server will refuse commands (offset of 10 minutes at most). Correct the date and time of this device.`;
}

/** Useful message for the failure of `POST /commands`. */
export function commandErrorMessage(e: { status: number; code: string; message: string }): string {
  if (e.code === 'invalid_validity' && /^issued_at|10 minutes/.test(e.message)) {
    return "This computer's clock is off: the command's issue time is more than 10 minutes from the server's time. Correct the date and time of this device, then try again.";
  }
  switch (e.code) {
    case 'rate_limited':
      return `Limit reached (20 commands per hour, 10 pending per device): ${e.message}`;
    case 'device_revoked':
      return 'This device is revoked: no command can be sent to it.';
    case 'duplicate_id':
      return 'Command identifier already used: try again.';
    case 'signature_required':
    case 'invalid_signature':
    case 'signature_not_allowed':
      return `Signature refused by the server (${e.message}).`;
    case 'bad_params':
    case 'invalid_payload':
    case 'invalid_validity':
      return `Invalid command: ${e.message}`;
    default:
      return e.status === 429 ? `Limit reached: ${e.message}` : e.message;
  }
}
