import { describe, expect, it } from 'vitest';
import {
  buildPayload,
  channelState,
  clockProblem,
  commandErrorMessage,
  hasForbiddenControl,
  badSignatureCount,
  codeProblem,
  defaultValidityMs,
  deriveKeyBytes,
  isSensitive,
  maxValidityMs,
  issueTime,
  paramsSummary,
  prepareCommand,
  refusalInfo,
  signPayload,
  statusInfo,
  toHex,
  validateParams,
} from './commands.ts';
import { ULID_RE, ulid } from './ulid.ts';

// Test vector of contract §8.
const CODE = 'correct horse battery staple';
const DEVICE = 'dev_0123456789abcdef';
const K_HEX = '05fd656216f9ae34c3be8e6afcfa857c535e9e0ef438ab6c2de7130891abdb8b';
const PAYLOAD =
  '{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef","type":"lock","params":{"message":"Lost phone — please call +1 555 0100"},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-23T10:00:00.000Z"}';
const SIG = 'VVQ7B/b3fOzaG+sWd7Fqi7NKVRzdu5L3+NEIKurMXdE=';

describe('signature of sensitive commands (contract §8 vector)', () => {
  it('derives K byte for byte', async () => {
    expect(toHex(await deriveKeyBytes(CODE, DEVICE))).toBe(K_HEX);
  });

  it('signs the contract payload (em dash in UTF-8)', async () => {
    expect(await signPayload(CODE, DEVICE, PAYLOAD)).toBe(SIG);
  });

  it('rebuilds the contract payload exactly', () => {
    const p = buildPayload({
      id: '01JCQ8Z3K4M5N6P7Q8R9S0T1V2',
      deviceId: DEVICE,
      type: 'lock',
      params: { message: 'Lost phone — please call +1 555 0100' },
      issuedAt: new Date('2026-11-16T10:00:00.000Z'),
      validityMs: defaultValidityMs('lock'),
    });
    expect(p).toBe(PAYLOAD);
  });

  it('the signature depends on the passphrase, the device and the payload bytes', async () => {
    expect(await signPayload(`${CODE}!`, DEVICE, PAYLOAD)).not.toBe(SIG);
    expect(await signPayload(CODE, 'dev_other', PAYLOAD)).not.toBe(SIG);
    expect(await signPayload(CODE, DEVICE, PAYLOAD.replace('—', '-'))).not.toBe(SIG);
  });

  it('encodes the passphrase in UTF-8 (an accented passphrase differs from its plain version)', async () => {
    const a = toHex(await deriveKeyBytes('üüüüüüüüüüüü', DEVICE));
    const b = toHex(await deriveKeyBytes('uuuuuuuuuuuu', DEVICE));
    expect(a).not.toBe(b);
    expect(a).toHaveLength(64);
  });
});

describe('payload building', () => {
  const base = { id: '01JCQ8Z3K4M5N6P7Q8R9S0T1V2', deviceId: DEVICE, issuedAt: new Date('2026-11-16T10:00:00.000Z') };

  it('ring: contract defaults and key order', () => {
    const p = buildPayload({ ...base, type: 'ring', validityMs: defaultValidityMs('ring') });
    expect(p).toBe(
      '{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef","type":"ring","params":{"duration_s":60,"vibrate":true},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-16T11:00:00.000Z"}',
    );
  });

  it('command without parameters: params is {}', () => {
    const p = JSON.parse(buildPayload({ ...base, type: 'stop_ring', validityMs: 3_600_000 })) as { params: unknown };
    expect(p.params).toEqual({});
  });

  it('lock without a message: no message key', () => {
    const p = JSON.parse(buildPayload({ ...base, type: 'lock', params: { message: '   ' }, validityMs: 3_600_000 })) as { params: unknown };
    expect(p.params).toEqual({});
  });

  it('validity: 1 h (simple), 7 days (lock), 15 min (erase); 30 days at most, 24 h for an erase', () => {
    expect(defaultValidityMs('locate')).toBe(3_600_000);
    expect(defaultValidityMs('lock')).toBe(7 * 86_400_000);
    expect(defaultValidityMs('clear_lock_message')).toBe(7 * 86_400_000);
    expect(defaultValidityMs('wipe')).toBe(15 * 60_000);
    expect(maxValidityMs('wipe')).toBe(86_400_000);
    expect(maxValidityMs('lock')).toBe(30 * 86_400_000);
    expect(() => buildPayload({ ...base, type: 'locate', validityMs: 31 * 86_400_000 })).toThrow();
    expect(() => buildPayload({ ...base, type: 'locate', validityMs: 0 })).toThrow();
    const ok = JSON.parse(buildPayload({ ...base, type: 'lock', validityMs: 30 * 86_400_000 })) as { expires_at: string };
    expect(ok.expires_at).toBe('2026-12-16T10:00:00.000Z');
    // Erase: 24 h at most (contract §8)
    const wipe24 = JSON.parse(buildPayload({ ...base, type: 'wipe', validityMs: 86_400_000 })) as { expires_at: string };
    expect(wipe24.expires_at).toBe('2026-11-17T10:00:00.000Z');
    expect(() => buildPayload({ ...base, type: 'wipe', validityMs: 86_400_001 })).toThrow(/24 hours/);
    expect(() => buildPayload({ ...base, type: 'wipe', validityMs: 7 * 86_400_000 })).toThrow();
    const wipe15 = JSON.parse(buildPayload({ ...base, type: 'wipe', validityMs: defaultValidityMs('wipe') })) as { expires_at: string };
    expect(wipe15.expires_at).toBe('2026-11-16T10:15:00.000Z');
  });

  it('"cancelled" and "expired" of a signed command only commit the server (contract §8)', () => {
    for (const s of ['cancelled', 'expired']) {
      const signed = statusInfo(s, false, true);
      expect(signed.label).toContain('server side');
      expect(signed.help).toContain('only commits the server');
      expect(signed.help).toContain('changing the command passphrase');
      expect(signed.help).not.toContain('never be executed');
      // a simple command keeps the original claim
      expect(statusInfo(s, false, false).help).toContain('never be executed');
    }
    // delivered then expired: always "without a response", signed or not
    expect(statusInfo('expired', true, true).label).toBe('Expired without a response');
  });

  it('refuses out-of-bounds parameters', () => {
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

  it('classifies sensitive commands', () => {
    for (const t of ['lock', 'clear_lock_message', 'wipe']) expect(isSensitive(t)).toBe(true);
    for (const t of ['ring', 'vibrate', 'stop_ring', 'locate', 'other']) expect(isSensitive(t)).toBe(false);
  });

  it('prepareCommand: the payload id is the command id', () => {
    const c = prepareCommand(DEVICE, 'locate', {}, 3_600_000, new Date('2026-11-16T10:00:00.000Z'));
    expect(c.id).toMatch(ULID_RE);
    expect((JSON.parse(c.payload) as { id: string }).id).toBe(c.id);
  });

  it('requires a passphrase of at least 12 characters', () => {
    expect(codeProblem('')).toBeUndefined();
    expect(codeProblem('too short')).toBeDefined();
    expect(codeProblem('twelve chars')).toBeUndefined();
  });
});

describe('ULID', () => {
  it('26 Crockford characters, readable timestamp and chronological order', () => {
    const rnd = (n: number) => new Uint8Array(n).fill(7);
    const a = ulid(1_700_000_000_000, rnd);
    const b = ulid(1_700_000_000_001, rnd);
    expect(a).toMatch(ULID_RE);
    expect(a < b).toBe(true);
    expect(a.slice(10)).toBe('7'.repeat(16));
    expect(ulid(0, rnd).slice(0, 10)).toBe('0000000000');
  });
  it('two calls differ', () => {
    expect(ulid()).not.toBe(ulid());
  });
});

describe('states, refusal reasons and channel', () => {
  it('translates each reason of the contract', () => {
    for (const d of ['disabled', 'malformed', 'wrong_device', 'unknown_type', 'no_code_configured', 'bad_signature', 'expired', 'replay', 'bad_params', 'not_device_owner', 'locked_out']) {
      const r = refusalInfo(d);
      expect(r?.title, d).toBeTruthy();
      expect(r?.title, d).not.toBe(d);
    }
    expect(refusalInfo('bad_signature')?.help).toContain('the server does not know the passphrase');
    expect(refusalInfo('locked_out')?.help).toContain('an hour');
    expect(refusalInfo('new_reason')?.help).toBe('new_reason');
    expect(refusalInfo(undefined)).toBeUndefined();
  });

  it('states: active while pending or delivered', () => {
    expect(statusInfo('pending').active).toBe(true);
    expect(statusInfo('delivered').active).toBe(true);
    for (const s of ['executed', 'failed', 'refused', 'expired', 'cancelled', 'unknown']) expect(statusInfo(s).active).toBe(false);
    expect(statusInfo('executed').label).toBe('Executed');
  });

  it('channel: connected, polling, offline, unknown', () => {
    expect(channelState({ connected: true, mode: 'stream' }).key).toBe('connected');
    const now = new Date('2026-11-16T12:00:00.000Z');
    expect(channelState({ connected: true, mode: 'poll' }, now).key).toBe('polling');
    // Real collector: when polling `connected` stays false, the freshness of the last contact decides.
    expect(channelState({ connected: false, mode: 'poll', last_contact: '2026-11-16T11:55:00.000Z' }, now).key).toBe('polling');
    expect(channelState({ connected: false, mode: 'poll', last_contact: '2026-11-16T11:00:00.000Z' }, now).key).toBe('offline');
    expect(channelState({ connected: false, mode: 'poll' }, now).key).toBe('offline');
    expect(channelState({ connected: false, mode: 'stream' }).key).toBe('offline');
    expect(channelState({ connected: false, mode: 'unknown' }).key).toBe('offline');
    expect(channelState(undefined).key).toBe('unknown');
  });

  it('summarises the parameters', () => {
    expect(paramsSummary('ring', { duration_s: 30, vibrate: false })).toBe('30 s, without vibration');
    expect(paramsSummary('vibrate', { duration_s: 5 })).toBe('5 s');
    expect(paramsSummary('lock', { message: 'Return it to me' })).toContain('Return it to me');
    expect(paramsSummary('lock', {})).toBe('no message');
    expect(paramsSummary('wipe', undefined)).toBe('');
  });
});

describe('recent invalid signatures', () => {
  const now = new Date('2026-11-16T12:00:00.000Z');
  it('counts only the bad_signature of the last hour', () => {
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

describe('expired command', () => {
  it('never delivered: it will never be executed', () => {
    expect(statusInfo('expired').help).toContain('never be executed');
    expect(statusInfo('expired', false).tone).toBe('neutral');
  });
  it('delivered then without a response: the console does not claim it was not executed', () => {
    const st = statusInfo('expired', true);
    expect(st.label).toBe('Expired without a response');
    expect(st.tone).toBe('warn');
    expect(st.help).toContain('may have been executed');
    expect(st.help).not.toContain('never be executed');
    expect(st.active).toBe(false);
  });
  it('the other states do not depend on delivery', () => {
    expect(statusInfo('executed', true)).toEqual(statusInfo('executed'));
    expect(statusInfo('cancelled', true)).toEqual(statusInfo('cancelled'));
  });
});

describe('contract §8: collector clarifications', () => {
  it('lock message: control characters forbidden except the line feed', () => {
    expect(hasForbiddenControl('line 1\nline 2')).toBe(false);
    expect(hasForbiddenControl('a\tb')).toBe(true);
    expect(hasForbiddenControl('a\u0007b')).toBe(true);
    expect(hasForbiddenControl('a\u0085b')).toBe(true);
    // Unicode line and paragraph separators: the collector refuses them too (bad_params).
    expect(hasForbiddenControl('a\u2028b')).toBe(true);
    expect(validateParams('lock', { message: 'a\u2029b' })).toContain('control');
    expect(validateParams('lock', { message: 'a\u0000b' })).toContain('control');
    expect(validateParams('lock', { message: 'Return it to me\nmy phone' })).toBeUndefined();
  });
  it('message of 200 UTF-16 units: an emoji counts for two', () => {
    expect(validateParams('lock', { message: `${'x'.repeat(198)}😀` })).toBeUndefined();
    expect(validateParams('lock', { message: `${'x'.repeat(199)}😀` })).toBeDefined();
  });
  it('clock offset: warns beyond the 10-minute limit (below it, issued_at is corrected)', () => {
    expect(clockProblem(undefined)).toBeUndefined();
    expect(clockProblem(5 * 60_000)).toBeUndefined();
    expect(clockProblem(-9 * 60_000)).toBeUndefined();
    expect(clockProblem(-11 * 60_000)).toContain('ahead');
    expect(clockProblem(2 * 3_600_000)).toContain('120 minutes');
  });
  it('issued_at follows the server time when the offset is plausible, never beyond 10 minutes', () => {
    const now = Date.UTC(2026, 10, 16, 10, 0, 0);
    // Computer 7 min ahead (server − browser = −7 min): without correction, the server accepts
    // (±10 min) but the phone refuses "expired" (issued more than 5 min in its future).
    expect(issueTime(now, -7 * 60_000).getTime()).toBe(now - 7 * 60_000);
    expect(issueTime(now, 9 * 60_000).getTime()).toBe(now + 9 * 60_000);
    // Measurement noise: ignored.
    expect(issueTime(now, 1_500).getTime()).toBe(now);
    expect(issueTime(now, undefined).getTime()).toBe(now);
    expect(issueTime(now, Number.NaN).getTime()).toBe(now);
    // A server (compromised or misconfigured) announcing a distant time is not followed: no signed
    // command dated in the future.
    expect(issueTime(now, 365 * 86_400_000).getTime()).toBe(now);
    expect(issueTime(now, -11 * 60_000).getTime()).toBe(now);
    const p = JSON.parse(prepareCommand(DEVICE, 'lock', {}, defaultValidityMs('lock'), issueTime(now, -7 * 60_000)).payload) as { issued_at: string; expires_at: string };
    expect(p.issued_at).toBe('2026-11-16T09:53:00.000Z');
    expect(p.expires_at).toBe('2026-11-23T09:53:00.000Z');
  });
  it('sending error: clock, limits, revocation', () => {
    expect(commandErrorMessage({ status: 400, code: 'invalid_validity', message: 'issued_at must be within 10 minutes of the server time' })).toContain('clock is off');
    expect(commandErrorMessage({ status: 400, code: 'invalid_validity', message: 'expires_at must follow issued_at' })).toContain('Invalid command');
    expect(commandErrorMessage({ status: 429, code: 'rate_limited', message: 'too many' })).toContain('20 commands per hour');
    expect(commandErrorMessage({ status: 409, code: 'device_revoked', message: 'x' })).toContain('revoked');
  });
});
