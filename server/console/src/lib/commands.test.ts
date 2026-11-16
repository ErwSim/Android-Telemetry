import { describe, expect, it } from 'vitest';
import {
  buildPayload,
  channelState,
  badSignatureCount,
  codeProblem,
  defaultValidityMs,
  deriveKeyBytes,
  isSensitive,
  paramsSummary,
  prepareCommand,
  refusalInfo,
  signPayload,
  statusInfo,
  toHex,
  validateParams,
} from './commands.ts';
import { ULID_RE, ulid } from './ulid.ts';

// Vecteur de test du contrat §8.
const CODE = 'correct horse battery staple';
const DEVICE = 'dev_0123456789abcdef';
const K_HEX = '072a4a8b76845668eff857e6412bd6bde57cf158cf89b2fb9c844a7d66037492';
const PAYLOAD =
  '{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef","type":"lock","params":{"message":"Téléphone perdu, appelez le 01 23 45 67 89"},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-23T10:00:00.000Z"}';
const SIG = 'GWiiJjYxiBHlG1lba410Zxb0kDHsINh4nS9u/GE/OaE=';

describe('signature des commandes sensibles (vecteur du contrat §8)', () => {
  it('dérive K à l’octet près', async () => {
    expect(toHex(await deriveKeyBytes(CODE, DEVICE))).toBe(K_HEX);
  });

  it('signe le payload du contrat (accents en UTF-8)', async () => {
    expect(await signPayload(CODE, DEVICE, PAYLOAD)).toBe(SIG);
  });

  it('reconstruit exactement le payload du contrat', () => {
    const p = buildPayload({
      id: '01JCQ8Z3K4M5N6P7Q8R9S0T1V2',
      deviceId: DEVICE,
      type: 'lock',
      params: { message: 'Téléphone perdu, appelez le 01 23 45 67 89' },
      issuedAt: new Date('2026-11-16T10:00:00.000Z'),
      validityMs: defaultValidityMs('lock'),
    });
    expect(p).toBe(PAYLOAD);
  });

  it('la signature dépend du code, de l’appareil et des octets du payload', async () => {
    expect(await signPayload(`${CODE}!`, DEVICE, PAYLOAD)).not.toBe(SIG);
    expect(await signPayload(CODE, 'dev_autre', PAYLOAD)).not.toBe(SIG);
    expect(await signPayload(CODE, DEVICE, PAYLOAD.replace('é', 'e'))).not.toBe(SIG);
  });

  it('encode le code en UTF-8 (un code accentué ne vaut pas sa version latin-1)', async () => {
    const a = toHex(await deriveKeyBytes('éééééééééééé', DEVICE));
    const b = toHex(await deriveKeyBytes('eeeeeeeeeeee', DEVICE));
    expect(a).not.toBe(b);
    expect(a).toHaveLength(64);
  });
});

describe('construction du payload', () => {
  const base = { id: '01JCQ8Z3K4M5N6P7Q8R9S0T1V2', deviceId: DEVICE, issuedAt: new Date('2026-11-16T10:00:00.000Z') };

  it('sonnerie : valeurs par défaut du contrat et ordre des clés', () => {
    const p = buildPayload({ ...base, type: 'ring', validityMs: defaultValidityMs('ring') });
    expect(p).toBe(
      '{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef","type":"ring","params":{"duration_s":60,"vibrate":true},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-16T11:00:00.000Z"}',
    );
  });

  it('commande sans paramètre : params vaut {}', () => {
    const p = JSON.parse(buildPayload({ ...base, type: 'stop_ring', validityMs: 3_600_000 })) as { params: unknown };
    expect(p.params).toEqual({});
  });

  it('verrouillage sans message : pas de clé message', () => {
    const p = JSON.parse(buildPayload({ ...base, type: 'lock', params: { message: '   ' }, validityMs: 3_600_000 })) as { params: unknown };
    expect(p.params).toEqual({});
  });

  it('validité : 1 h (simple), 7 jours (sensible), 30 jours au plus', () => {
    expect(defaultValidityMs('locate')).toBe(3_600_000);
    expect(defaultValidityMs('wipe')).toBe(7 * 86_400_000);
    expect(() => buildPayload({ ...base, type: 'locate', validityMs: 31 * 86_400_000 })).toThrow();
    expect(() => buildPayload({ ...base, type: 'locate', validityMs: 0 })).toThrow();
    const ok = JSON.parse(buildPayload({ ...base, type: 'wipe', validityMs: 30 * 86_400_000 })) as { expires_at: string };
    expect(ok.expires_at).toBe('2026-12-16T10:00:00.000Z');
  });

  it('refuse les paramètres hors bornes', () => {
    expect(validateParams('ring', { duration_s: 0 })).toBeDefined();
    expect(validateParams('ring', { duration_s: 301 })).toBeDefined();
    expect(validateParams('ring', { duration_s: 300 })).toBeUndefined();
    expect(validateParams('ring', { duration_s: 1.5 })).toBeDefined();
    expect(validateParams('vibrate', { duration_s: 61 })).toBeDefined();
    expect(validateParams('vibrate', { duration_s: 60 })).toBeUndefined();
    expect(validateParams('lock', { message: 'x'.repeat(200) })).toBeUndefined();
    expect(validateParams('lock', { message: 'x'.repeat(201) })).toBeDefined();
    expect(() => buildPayload({ ...base, type: 'ring', params: { duration_s: 999 }, validityMs: 1000 })).toThrow();
  });

  it('classe les commandes sensibles', () => {
    for (const t of ['lock', 'clear_lock_message', 'wipe']) expect(isSensitive(t)).toBe(true);
    for (const t of ['ring', 'vibrate', 'stop_ring', 'locate', 'autre']) expect(isSensitive(t)).toBe(false);
  });

  it('prepareCommand : l’id du payload est l’id de la commande', () => {
    const c = prepareCommand(DEVICE, 'locate', {}, 3_600_000, new Date('2026-11-16T10:00:00.000Z'));
    expect(c.id).toMatch(ULID_RE);
    expect((JSON.parse(c.payload) as { id: string }).id).toBe(c.id);
  });

  it('exige un code de 12 caractères au moins', () => {
    expect(codeProblem('')).toBeUndefined();
    expect(codeProblem('trop court')).toBeDefined();
    expect(codeProblem('exactement 12')).toBeUndefined();
  });
});

describe('ULID', () => {
  it('26 caractères de Crockford, horodatage lisible et ordre chronologique', () => {
    const rnd = (n: number) => new Uint8Array(n).fill(7);
    const a = ulid(1_700_000_000_000, rnd);
    const b = ulid(1_700_000_000_001, rnd);
    expect(a).toMatch(ULID_RE);
    expect(a < b).toBe(true);
    expect(a.slice(10)).toBe('7'.repeat(16));
    expect(ulid(0, rnd).slice(0, 10)).toBe('0000000000');
  });
  it('deux appels diffèrent', () => {
    expect(ulid()).not.toBe(ulid());
  });
});

describe('états, motifs de refus et canal', () => {
  it('traduit chaque motif du contrat', () => {
    for (const d of ['disabled', 'malformed', 'wrong_device', 'unknown_type', 'no_code_configured', 'bad_signature', 'expired', 'replay', 'bad_params', 'not_device_owner', 'locked_out']) {
      const r = refusalInfo(d);
      expect(r?.title, d).toBeTruthy();
      expect(r?.title, d).not.toBe(d);
    }
    expect(refusalInfo('bad_signature')?.help).toContain('le serveur ne connaît pas le code');
    expect(refusalInfo('locked_out')?.help).toContain('une heure');
    expect(refusalInfo('nouveau_motif')?.help).toBe('nouveau_motif');
    expect(refusalInfo(undefined)).toBeUndefined();
  });

  it('états : actifs tant que pending ou delivered', () => {
    expect(statusInfo('pending').active).toBe(true);
    expect(statusInfo('delivered').active).toBe(true);
    for (const s of ['executed', 'failed', 'refused', 'expired', 'cancelled', 'inconnu']) expect(statusInfo(s).active).toBe(false);
    expect(statusInfo('executed').label).toBe('Exécutée');
  });

  it('canal : connecté, interrogation, hors ligne, inconnu', () => {
    expect(channelState({ connected: true, mode: 'stream' }).key).toBe('connected');
    expect(channelState({ connected: true, mode: 'poll' }).key).toBe('polling');
    expect(channelState({ connected: false, mode: 'poll' }).key).toBe('offline');
    expect(channelState({ connected: false, mode: 'stream' }).key).toBe('offline');
    expect(channelState({ connected: false, mode: 'unknown' }).key).toBe('offline');
    expect(channelState(undefined).key).toBe('unknown');
  });

  it('résume les paramètres', () => {
    expect(paramsSummary('ring', { duration_s: 30, vibrate: false })).toBe('30 s, sans vibration');
    expect(paramsSummary('vibrate', { duration_s: 5 })).toBe('5 s');
    expect(paramsSummary('lock', { message: 'Rendez-moi' })).toContain('Rendez-moi');
    expect(paramsSummary('lock', {})).toBe('sans message');
    expect(paramsSummary('wipe', undefined)).toBe('');
  });
});

describe('signatures invalides récentes', () => {
  const now = new Date('2026-11-16T12:00:00.000Z');
  it('ne compte que les bad_signature de la dernière heure', () => {
    const n = badSignatureCount(
      [
        { status: 'refused', detail: 'bad_signature', result_at: '2026-11-16T11:30:00.000Z' },
        { status: 'refused', detail: 'bad_signature', result_at: '2026-11-16T10:30:00.000Z' },
        { status: 'refused', detail: 'expired', result_at: '2026-11-16T11:59:00.000Z' },
        { status: 'executed', result_at: '2026-11-16T11:59:00.000Z' },
        { status: 'refused', detail: 'bad_signature', created_at: '2026-11-16T11:59:00.000Z' },
        { status: 'refused', detail: 'bad_signature' },
      ],
      now,
    );
    expect(n).toBe(2);
  });
});
