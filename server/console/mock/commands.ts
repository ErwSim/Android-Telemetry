// Mock remote commands (contract §8): the collector (validation, queue, cancellation, limits) and a simulated
// agent that fetches the commands, verifies the signature like the real agent, then "executes" with delays.
//
// The mock's command passphrase (MOCK_COMMAND_CODE, default "correct horse battery staple") plays the role of the
// passphrase chosen in the Android app: only the mock derives the key K from it; the mock "server" never verifies
// the signature (like the real collector): only the simulated agent checks it.
import { createHmac, pbkdf2Sync, timingSafeEqual } from 'node:crypto';
import { makeRng, ulid } from './rng.ts';

export const COMMAND_CODE = process.env['MOCK_COMMAND_CODE'] ?? 'correct horse battery staple';
const TYPES = ['ring', 'vibrate', 'stop_ring', 'locate', 'lock', 'clear_lock_message', 'wipe'] as const;
type Type = (typeof TYPES)[number];
const SENSITIVE = new Set<string>(['lock', 'clear_lock_message', 'wipe']);
const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const DAY = 86_400_000;

export type Status = 'pending' | 'delivered' | 'executed' | 'failed' | 'refused' | 'expired' | 'cancelled';
export interface Command {
  id: string;
  device_id: string;
  type: string;
  params: Record<string, unknown>;
  signed: boolean;
  status: Status;
  created_at: string;
  created_by: string;
  expires_at: string;
  delivered_at?: string;
  result_at?: string;
  detail?: string;
  /** internal: payload and signature as received */
  payload: string;
  sig?: string;
}

export interface AgentSim {
  /** `stream`: permanently connected; `poll`: visits every 6 s; `offline`: unreachable */
  channel: 'stream' | 'poll' | 'offline';
  /** command channel disabled in the app */
  disabled: boolean;
  wipe_allowed: boolean;
  code_configured: boolean;
  device_owner: boolean;
  /** `locate` fails (no fix) */
  locate_fail: boolean;
  deliver_ms: number;
  exec_ms: number;
}

export const agent: AgentSim = {
  channel: 'stream',
  disabled: false,
  wipe_allowed: false,
  code_configured: true,
  device_owner: true,
  locate_fail: false,
  deliver_ms: 1000,
  exec_ms: 1400,
};

/** Simulated offset of the server's clock (ms), to test the refusal of `issued_at` (contract §8, clarifications). */
export const clock = { skew_ms: 0 };
export const serverNow = (): number => Date.now() + clock.skew_ms;

export const commands: Command[] = [];
let lastContact = Date.now();
const seen: string[] = []; // identifiers already executed (last 500)
let badSig: number[] = [];

let keyCache: { deviceId: string; k: Buffer } | undefined;
function keyFor(deviceId: string): Buffer {
  if (keyCache?.deviceId !== deviceId) keyCache = { deviceId, k: pbkdf2Sync(COMMAND_CODE, `watchpost-cmd-v1:${deviceId}`, 600_000, 32, 'sha256') };
  return keyCache.k;
}

export interface Hooks {
  /** adds an event coming from the agent (command.result, location.fix...) to the log and the SSE stream */
  emit: (type: string, sev: number, data: Record<string, unknown>) => void;
  deviceKnown: (id: string) => 'ok' | 'unknown' | 'revoked';
  /** the agent got a fix: a new location arrives */
  liveFix: () => void;
}
let hooks: Hooks | undefined;
export function init(h: Hooks, now: number): void {
  hooks = h;
  seedHistory(now);
  setInterval(tick, 400).unref();
}

export function channel(): { connected: boolean; mode: string; last_contact: string } {
  if (agent.channel === 'offline') return { connected: false, mode: 'stream', last_contact: new Date(lastContact).toISOString() };
  // Like the real collector: when polling there is no open connection, `connected` stays false.
  return { connected: agent.channel === 'stream', mode: agent.channel, last_contact: new Date(agent.channel === 'stream' ? Date.now() - 800 : lastContact).toISOString() };
}

// -------------------------------------------------------------------------------------- collector API
export interface Failure {
  status: number;
  error: string;
  message: string;
}

const publicView = (c: Command) => {
  const { payload: _p, sig: _s, ...rest } = c;
  void _p;
  void _s;
  return rest;
};

export function list(deviceId: string | null, limit: number) {
  return {
    commands: commands
      .filter((c) => !deviceId || c.device_id === deviceId)
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
      .slice(0, limit)
      .map(publicView),
  };
}

export function create(body: unknown, user: string): { id: string } | Failure {
  const bad = (error: string, message: string, status = 400): Failure => ({ status, error, message });
  if (!body || typeof body !== 'object') return bad('bad_request', 'Invalid body');
  const b = body as { device_id?: unknown; payload?: unknown; sig?: unknown };
  if (typeof b.device_id !== 'string' || typeof b.payload !== 'string') return bad('bad_request', 'device_id and payload (string) are required');
  let p: Record<string, unknown>;
  try {
    p = JSON.parse(b.payload) as Record<string, unknown>;
  } catch {
    return bad('invalid_payload', 'payload is not JSON');
  }
  if (!p || typeof p !== 'object' || p['v'] !== 1) return bad('invalid_payload', 'payload: v must be 1');
  const id = p['id'];
  if (typeof id !== 'string' || !ULID_RE.test(id)) return bad('invalid_payload', 'payload: id must be a ULID');
  if (p['device_id'] !== b.device_id) return bad('invalid_payload', 'payload: inconsistent device_id');
  const known = hooks?.deviceKnown(b.device_id);
  if (known === 'unknown') return bad('device_not_found', 'Unknown device', 404);
  if (known === 'revoked') return bad('device_revoked', 'Device revoked', 409);
  const type = p['type'];
  if (typeof type !== 'string' || !(TYPES as readonly string[]).includes(type)) return bad('unknown_type', `Unknown command type: ${String(type)}`);
  const params = (p['params'] ?? {}) as Record<string, unknown>;
  if (typeof params !== 'object' || Array.isArray(params)) return bad('bad_params', 'params must be an object');
  const dur = (max: number, dflt: number) => {
    const d = params['duration_s'] ?? dflt;
    return typeof d === 'number' && Number.isInteger(d) && d >= 1 && d <= max;
  };
  if (type === 'ring' && (!dur(300, 60) || (params['vibrate'] !== undefined && typeof params['vibrate'] !== 'boolean'))) return bad('bad_params', 'ring: duration_s between 1 and 300');
  if (type === 'vibrate' && !dur(60, 10)) return bad('bad_params', 'vibrate: duration_s between 1 and 60');
  if (type === 'lock' && params['message'] !== undefined && (typeof params['message'] !== 'string' || Array.from(params['message']).length > 200)) return bad('bad_params', 'lock: message of 200 characters at most');
  const issued = Date.parse(String(p['issued_at']));
  const expires = Date.parse(String(p['expires_at']));
  if (Number.isNaN(issued) || Number.isNaN(expires)) return bad('invalid_payload', 'invalid issued_at / expires_at');
  if (Math.abs(issued - serverNow()) > 10 * 60_000) return bad('invalid_validity', 'issued_at must be within 10 minutes of the server time');
  if (expires <= issued || expires - issued > 30 * DAY) return bad('bad_validity', 'Validity: 30 days at most');
  if (expires <= Date.now()) return bad('bad_validity', 'The command has already expired');
  const sensitive = SENSITIVE.has(type);
  const hasSig = typeof b.sig === 'string' && b.sig !== '';
  if (sensitive && !hasSig) return bad('signature_required', 'A sensitive command requires a signature');
  if (!sensitive && b.sig !== undefined && b.sig !== '') return bad('signature_unexpected', 'A simple command carries no signature');
  if (commands.some((c) => c.id === id)) return bad('duplicate_id', 'Identifier already used', 409);
  const recent = commands.filter((c) => c.device_id === b.device_id && Date.parse(c.created_at) > Date.now() - 3_600_000).length;
  if (recent >= 20) return bad('rate_limited', 'Limit of 20 commands per hour reached', 429);
  if (commands.filter((c) => c.device_id === b.device_id && c.status === 'pending').length >= 10) return bad('rate_limited', 'Already 10 commands pending for this device', 429);
  commands.push({
    id,
    device_id: b.device_id,
    type,
    params,
    signed: hasSig,
    status: 'pending',
    created_at: new Date().toISOString(),
    created_by: user,
    expires_at: new Date(expires).toISOString(),
    payload: b.payload,
    ...(hasSig ? { sig: b.sig as string } : {}),
  });
  return { id };
}

export function cancel(id: string): 'ok' | 'notfound' | 'conflict' {
  const c = commands.find((x) => x.id === id);
  if (!c) return 'notfound';
  if (c.status !== 'pending') return 'conflict';
  c.status = 'cancelled';
  c.result_at = new Date().toISOString();
  return 'ok';
}

// -------------------------------------------------------------------------------------- simulated agent
const scheduled = new Set<string>();
let lastPoll = 0;

function tick(): void {
  const now = Date.now();
  for (const c of commands) {
    if (c.status === 'pending' && Date.parse(c.expires_at) <= now) {
      c.status = 'expired';
      c.result_at = new Date(now).toISOString();
    }
  }
  if (agent.channel === 'offline') return;
  if (agent.channel === 'poll') {
    if (now - lastPoll < 6000) return;
    lastPoll = now;
    lastContact = now;
  } else lastContact = now;
  for (const c of commands) {
    if (c.status !== 'pending' || scheduled.has(c.id)) continue;
    scheduled.add(c.id);
    setTimeout(() => {
      if (c.status !== 'pending') return;
      c.status = 'delivered';
      c.delivered_at = new Date().toISOString();
      setTimeout(() => execute(c), agent.exec_ms);
    }, agent.deliver_ms);
  }
}

function result(c: Command, status: 'executed' | 'failed' | 'refused', detail?: string): void {
  c.status = status;
  c.result_at = new Date().toISOString();
  if (detail) c.detail = detail;
  const sev = status === 'refused' ? (detail === 'bad_signature' || detail === 'locked_out' ? 3 : 1) : status === 'executed' && (c.type === 'lock' || c.type === 'wipe') ? 2 : 0;
  hooks?.emit('command.result', sev, { command_id: c.id, type: c.type, status, ...(detail ? { detail } : {}), signed: c.signed });
}

/** The agent's checks, in the order of contract §8. */
function execute(c: Command): void {
  if (c.status !== 'delivered') return;
  const refuse = (d: string) => result(c, 'refused', d);
  if (agent.disabled) return refuse('disabled');
  let p: Record<string, unknown>;
  try {
    p = JSON.parse(c.payload) as Record<string, unknown>;
  } catch {
    return refuse('malformed');
  }
  if (p['v'] !== 1 || p['id'] !== c.id) return refuse('malformed');
  if (p['device_id'] !== c.device_id) return refuse('wrong_device');
  if (!(TYPES as readonly string[]).includes(String(p['type']))) return refuse('unknown_type');
  const type = p['type'] as Type;
  const sensitive = SENSITIVE.has(type);
  if (sensitive) {
    if (!agent.code_configured) return refuse('no_code_configured');
    const now = Date.now();
    badSig = badSig.filter((t) => t > now - 3_600_000);
    if (badSig.length >= 5) return refuse('locked_out');
    const expected = createHmac('sha256', keyFor(c.device_id)).update(c.payload, 'utf8').digest();
    let got = Buffer.alloc(0);
    try {
      got = Buffer.from(c.sig ?? '', 'base64');
    } catch {
      /* unreadable signature: compared as invalid */
    }
    if (got.length !== expected.length || !timingSafeEqual(got, expected)) {
      badSig.push(now);
      return refuse('bad_signature');
    }
  }
  if (type === 'wipe' && !agent.wipe_allowed) return refuse('disabled');
  if (Date.now() > Date.parse(String(p['expires_at'])) + 5 * 60_000) return refuse('expired');
  if (seen.includes(c.id)) return refuse('replay');
  seen.push(c.id);
  if (seen.length > 500) seen.shift();
  if (sensitive && !agent.device_owner) return refuse('not_device_owner');
  if (type === 'locate') {
    if (agent.locate_fail) return result(c, 'failed', 'no_fix');
    result(c, 'executed');
    // The location arrives after acquisition: the mock pushes it into the SSE stream.
    setTimeout(() => hooks?.liveFix(), 2500);
    return;
  }
  result(c, 'executed');
}

function seedHistory(now: number): void {
  const dev = 'dev_8f3a1c2e9b7d';
  const mk = (ago: number, type: string, params: Record<string, unknown>, signed: boolean, status: Status, detail?: string, valid = 3_600_000): Command => {
    const t = now - ago;
    const id = ulid(makeRng(t % 100003), t);
    return {
      id,
      device_id: dev,
      type,
      params,
      signed,
      status,
      created_at: new Date(t).toISOString(),
      created_by: 'admin',
      expires_at: new Date(t + valid).toISOString(),
      delivered_at: new Date(t + 1500).toISOString(),
      result_at: new Date(t + 4000).toISOString(),
      ...(detail ? { detail } : {}),
      payload: '{}',
    };
  };
  commands.push(
    mk(2 * DAY + 3_600_000, 'ring', { duration_s: 30, vibrate: true }, false, 'executed'),
    mk(DAY + 7_200_000, 'locate', {}, false, 'executed'),
    mk(DAY + 3_600_000, 'lock', { message: 'Lost phone — please call +1 555 0100' }, true, 'refused', 'bad_signature', 7 * DAY),
    mk(DAY, 'vibrate', { duration_s: 10 }, false, 'expired'),
  );
  const exp = commands[commands.length - 1] as Command;
  delete exp.delivered_at;
  exp.status = 'expired';
}
