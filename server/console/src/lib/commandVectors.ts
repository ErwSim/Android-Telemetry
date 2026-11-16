// Hard signature cases (contract §8), produced by the console's REAL code (`buildPayload`,
// `signPayload`): accents, emoji, quotes, line feeds, bidirectional text in the message; non-ASCII,
// decomposed (NFD) or space-padded command passphrases. They are used twice:
//   - frozen in `fixtures/command-vectors.json`, they are replayed by the agent's Kotlin verifier
//     (`android/core/src/test/.../ConsoleVectorsTest.kt`) and by the Go collector (`internal/command`);
//   - generated for a real device and the current time (`scripts/command-vectors.ts`), they go through the real
//     collector up to the real Kotlin channel (`CrossCommandsTest`).
import { buildPayload, isSensitive, signPayload, DAY_MS, HOUR_MS, type CommandParams, type CommandType } from './commands.ts';
import { ulid } from './ulid.ts';

export interface CommandVector {
  name: string;
  /** command passphrase; null for a simple (unsigned) command */
  code: string | null;
  device_id: string;
  type: CommandType;
  /** issue time (ms): the command is valid at this instant */
  now_ms: number;
  payload: string;
  sig: string | null;
  /** what the agent must retain once the command is accepted */
  expect: { message?: string | null; duration_s?: number; vibrate?: boolean };
}

export const VECTOR_CODES = {
  contract: 'correct horse battery staple',
  nonAscii: 'pässwörd-código-密码-🔑🔑',
  decomposed: 'nin\u0303o ju\u0308ngling 2026 !', // decomposed (NFD): n + U+0303, u + U+0308
  spaced: '  spaces around & "quotes" \\ \' <> %  ',
} as const;

const MESSAGES = {
  mixed: 'Handy verloren 🙂 — «bitte anrufen» unter "+1 555 0100"\nline 2 \\ it\'s a test',
  emoji200: '🙂'.repeat(100),
  padded: '  \n spaces and line feeds around \n  ',
  bidi: 'مرحبا بالعالم — שלום עולם — ‮override‬ — 👨‍👩‍👧‍👦 — z̶a̶l̶g̶o̶',
  hostile: '{"type":"wipe","params":{}} </script><img src=x onerror=alert(1)> \\u0000 %00  ­',
  accents200: 'ü'.repeat(200),
} as const;

interface Case {
  name: string;
  code: string | null;
  type: CommandType;
  params?: CommandParams;
  validityMs?: number;
  expect: CommandVector['expect'];
}

const CASES: Case[] = [
  { name: 'lock: accents, emoji, quotes, line feed, backslash', code: VECTOR_CODES.contract, type: 'lock', params: { message: MESSAGES.mixed }, expect: { message: MESSAGES.mixed } },
  { name: 'lock: 100 emoji (200 UTF-16 units), non-ASCII passphrase', code: VECTOR_CODES.nonAscii, type: 'lock', params: { message: MESSAGES.emoji200 }, expect: { message: MESSAGES.emoji200 } },
  { name: 'lock: message padded with spaces and line feeds, decomposed (NFD) passphrase', code: VECTOR_CODES.decomposed, type: 'lock', params: { message: MESSAGES.padded }, expect: { message: MESSAGES.padded.trim() } },
  { name: 'lock: Arabic, Hebrew, bidirectional mark, composed emoji, diacritics; space-padded passphrase', code: VECTOR_CODES.spaced, type: 'lock', params: { message: MESSAGES.bidi }, expect: { message: MESSAGES.bidi } },
  { name: 'lock: message that looks like JSON and HTML', code: VECTOR_CODES.contract, type: 'lock', params: { message: MESSAGES.hostile }, expect: { message: MESSAGES.hostile } },
  { name: 'lock: 200 accented letters, 30-day validity', code: VECTOR_CODES.nonAscii, type: 'lock', params: { message: MESSAGES.accents200 }, validityMs: 30 * DAY_MS, expect: { message: MESSAGES.accents200 } },
  { name: 'lock: no message', code: VECTOR_CODES.contract, type: 'lock', params: { message: '   ' }, expect: { message: null } },
  { name: 'clear_lock_message: decomposed (NFD) passphrase', code: VECTOR_CODES.decomposed, type: 'clear_lock_message', expect: {} },
  { name: 'wipe: space-padded passphrase', code: VECTOR_CODES.spaced, type: 'wipe', validityMs: DAY_MS, expect: {} },
  { name: 'ring: 300 s without vibration (simple)', code: null, type: 'ring', params: { duration_s: 300, vibrate: false }, expect: { duration_s: 300, vibrate: false } },
  { name: 'vibrate: default value (simple)', code: null, type: 'vibrate', expect: { duration_s: 10 } },
  { name: 'locate (simple)', code: null, type: 'locate', expect: {} },
  { name: 'stop_ring (simple)', code: null, type: 'stop_ring', expect: {} },
];

/** Deterministic byte sequence (xorshift32) to freeze the identifiers of the versioned test set. */
export function seededRandom(seed: number): (n: number) => Uint8Array {
  let x = seed >>> 0 || 1;
  return (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      x ^= x << 13;
      x >>>= 0;
      x ^= x >>> 17;
      x ^= x << 5;
      x >>>= 0;
      out[i] = x & 0xff;
    }
    return out;
  };
}

/** Builds and signs each case for `deviceId`, issued at `nowMs`. `random`: source of the identifiers (ULID). */
export async function buildVectors(deviceId: string, nowMs: number, random?: (n: number) => Uint8Array): Promise<CommandVector[]> {
  const out: CommandVector[] = [];
  for (const c of CASES) {
    const id = random ? ulid(nowMs, random) : ulid(nowMs);
    const validityMs = c.validityMs ?? (isSensitive(c.type) ? 7 * DAY_MS : HOUR_MS);
    const payload = buildPayload({ id, deviceId, type: c.type, ...(c.params ? { params: c.params } : {}), issuedAt: new Date(nowMs), validityMs });
    const sig = c.code === null ? null : await signPayload(c.code, deviceId, payload);
    out.push({ name: c.name, code: c.code, device_id: deviceId, type: c.type, now_ms: nowMs, payload, sig, expect: c.expect });
  }
  return out;
}

/** Device and instant of the versioned test set (those of the contract §8 vector). */
export const FIXTURE_DEVICE = 'dev_0123456789abcdef';
export const FIXTURE_NOW_MS = Date.UTC(2026, 10, 16, 10, 0, 0);
export const FIXTURE_SEED = 0x77617463;
