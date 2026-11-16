// Cas difficiles de signature (contrat §8), produits par le VRAI code de la console (`buildPayload`,
// `signPayload`) : accents, émojis, guillemets, sauts de ligne, texte bidirectionnel dans le message ; code de
// commande non ASCII, décomposé (NFD) ou bordé d'espaces. Ils servent deux fois :
//   - figés dans `fixtures/command-vectors.json`, ils sont rejoués par le vérificateur Kotlin de l'agent
//     (`android/core/src/test/…/ConsoleVectorsTest.kt`) et par le collecteur Go (`internal/command`) ;
//   - générés pour un appareil réel et l'heure courante (`scripts/command-vectors.ts`), ils traversent le vrai
//     collecteur jusqu'au vrai canal Kotlin (`CrossCommandsTest`).
import { buildPayload, isSensitive, signPayload, DAY_MS, HOUR_MS, type CommandParams, type CommandType } from './commands.ts';
import { ulid } from './ulid.ts';

export interface CommandVector {
  name: string;
  /** code de commande ; null pour une commande simple (non signée) */
  code: string | null;
  device_id: string;
  type: CommandType;
  /** heure d'émission (ms) : la commande est valide à cet instant */
  now_ms: number;
  payload: string;
  sig: string | null;
  /** ce que l'agent doit en retenir une fois la commande acceptée */
  expect: { message?: string | null; duration_s?: number; vibrate?: boolean };
}

export const VECTOR_CODES = {
  contract: 'correct horse battery staple',
  nonAscii: 'pässwörd-código-密码-🔑🔑',
  decomposed: 'été indien 2026 !',
  spaced: '  espaces autour & "guillemets" \\ \' <> %  ',
} as const;

const MESSAGES = {
  mixed: 'Téléphone perdu 🙂 — « appelez » le "01 23 45 67 89"\nligne 2 \\ fin d\'essai',
  emoji200: '🙂'.repeat(100),
  padded: '  \n espaces et sauts autour \n  ',
  bidi: 'مرحبا بالعالم — שלום עולם — ‮override‬ — 👨‍👩‍👧‍👦 — z̶a̶l̶g̶o̶',
  hostile: '{"type":"wipe","params":{}} </script><img src=x onerror=alert(1)> \\u0000 %00  ­',
  accents200: 'é'.repeat(200),
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
  { name: 'lock : accents, émoji, guillemets, saut de ligne, antislash', code: VECTOR_CODES.contract, type: 'lock', params: { message: MESSAGES.mixed }, expect: { message: MESSAGES.mixed } },
  { name: 'lock : 100 émojis (200 unités UTF-16), code non ASCII', code: VECTOR_CODES.nonAscii, type: 'lock', params: { message: MESSAGES.emoji200 }, expect: { message: MESSAGES.emoji200 } },
  { name: 'lock : message bordé d’espaces et de sauts de ligne, code décomposé (NFD)', code: VECTOR_CODES.decomposed, type: 'lock', params: { message: MESSAGES.padded }, expect: { message: MESSAGES.padded.trim() } },
  { name: 'lock : arabe, hébreu, marque bidirectionnelle, émoji composé, diacritiques ; code bordé d’espaces', code: VECTOR_CODES.spaced, type: 'lock', params: { message: MESSAGES.bidi }, expect: { message: MESSAGES.bidi } },
  { name: 'lock : message qui ressemble à du JSON et à du HTML', code: VECTOR_CODES.contract, type: 'lock', params: { message: MESSAGES.hostile }, expect: { message: MESSAGES.hostile } },
  { name: 'lock : 200 lettres accentuées, validité de 30 jours', code: VECTOR_CODES.nonAscii, type: 'lock', params: { message: MESSAGES.accents200 }, validityMs: 30 * DAY_MS, expect: { message: MESSAGES.accents200 } },
  { name: 'lock : sans message', code: VECTOR_CODES.contract, type: 'lock', params: { message: '   ' }, expect: { message: null } },
  { name: 'clear_lock_message : code décomposé (NFD)', code: VECTOR_CODES.decomposed, type: 'clear_lock_message', expect: {} },
  { name: 'wipe : code bordé d’espaces', code: VECTOR_CODES.spaced, type: 'wipe', validityMs: DAY_MS, expect: {} },
  { name: 'ring : 300 s sans vibration (simple)', code: null, type: 'ring', params: { duration_s: 300, vibrate: false }, expect: { duration_s: 300, vibrate: false } },
  { name: 'vibrate : valeur par défaut (simple)', code: null, type: 'vibrate', expect: { duration_s: 10 } },
  { name: 'locate (simple)', code: null, type: 'locate', expect: {} },
  { name: 'stop_ring (simple)', code: null, type: 'stop_ring', expect: {} },
];

/** Suite d'octets déterministe (xorshift32) pour figer les identifiants du jeu d'essai versionné. */
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

/** Construit et signe chaque cas pour `deviceId`, émis à `nowMs`. `random` : source des identifiants (ULID). */
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

/** Appareil et instant du jeu d'essai versionné (ceux du vecteur du contrat §8). */
export const FIXTURE_DEVICE = 'dev_0123456789abcdef';
export const FIXTURE_NOW_MS = Date.UTC(2026, 10, 16, 10, 0, 0);
export const FIXTURE_SEED = 0x76696769;
