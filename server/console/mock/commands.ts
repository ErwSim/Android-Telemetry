// Commandes à distance factices (contrat §8) : le collecteur (validation, file, annulation, limites) et un agent
// simulé qui récupère les commandes, vérifie la signature comme le vrai agent, puis « exécute » avec des délais.
//
// Le code de commande du mock (MOCK_COMMAND_CODE, défaut « correct horse battery staple ») joue le rôle du code
// choisi dans l'app Android : seul le mock en dérive la clé K ; le « serveur » du mock ne vérifie jamais la
// signature (comme le vrai collecteur) : seul l'agent simulé la contrôle.
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
  /** interne : payload et signature tels que reçus */
  payload: string;
  sig?: string;
}

export interface AgentSim {
  /** `stream` : connecté en permanence ; `poll` : passe toutes les 6 s ; `offline` : injoignable */
  channel: 'stream' | 'poll' | 'offline';
  /** canal de commandes désactivé dans l'app */
  disabled: boolean;
  wipe_allowed: boolean;
  code_configured: boolean;
  device_owner: boolean;
  /** `locate` échoue (pas de fix) */
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

/** Décalage simulé de l'horloge du serveur (ms), pour tester le refus d'`issued_at` (contrat §8, précisions). */
export const clock = { skew_ms: 0 };
export const serverNow = (): number => Date.now() + clock.skew_ms;

export const commands: Command[] = [];
let lastContact = Date.now();
const seen: string[] = []; // identifiants déjà exécutés (500 derniers)
let badSig: number[] = [];

let keyCache: { deviceId: string; k: Buffer } | undefined;
function keyFor(deviceId: string): Buffer {
  if (keyCache?.deviceId !== deviceId) keyCache = { deviceId, k: pbkdf2Sync(COMMAND_CODE, `watchpost-cmd-v1:${deviceId}`, 600_000, 32, 'sha256') };
  return keyCache.k;
}

export interface Hooks {
  /** ajoute un événement venant de l'agent (command.result, location.fix…) au journal et au flux SSE */
  emit: (type: string, sev: number, data: Record<string, unknown>) => void;
  deviceKnown: (id: string) => 'ok' | 'unknown' | 'revoked';
  /** l'agent a obtenu un fix : une nouvelle position arrive */
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
  // Comme le vrai collecteur : en interrogation il n'y a pas de connexion ouverte, `connected` reste faux.
  return { connected: agent.channel === 'stream', mode: agent.channel, last_contact: new Date(agent.channel === 'stream' ? Date.now() - 800 : lastContact).toISOString() };
}

// -------------------------------------------------------------------------------------- API collecteur
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
  if (!body || typeof body !== 'object') return bad('bad_request', 'Corps invalide');
  const b = body as { device_id?: unknown; payload?: unknown; sig?: unknown };
  if (typeof b.device_id !== 'string' || typeof b.payload !== 'string') return bad('bad_request', 'device_id et payload (chaîne) sont requis');
  let p: Record<string, unknown>;
  try {
    p = JSON.parse(b.payload) as Record<string, unknown>;
  } catch {
    return bad('invalid_payload', 'payload n’est pas du JSON');
  }
  if (!p || typeof p !== 'object' || p['v'] !== 1) return bad('invalid_payload', 'payload : v doit valoir 1');
  const id = p['id'];
  if (typeof id !== 'string' || !ULID_RE.test(id)) return bad('invalid_payload', 'payload : id doit être un ULID');
  if (p['device_id'] !== b.device_id) return bad('invalid_payload', 'payload : device_id incohérent');
  const known = hooks?.deviceKnown(b.device_id);
  if (known === 'unknown') return bad('device_not_found', 'Appareil inconnu', 404);
  if (known === 'revoked') return bad('device_revoked', 'Appareil révoqué', 409);
  const type = p['type'];
  if (typeof type !== 'string' || !(TYPES as readonly string[]).includes(type)) return bad('unknown_type', `Type de commande inconnu : ${String(type)}`);
  const params = (p['params'] ?? {}) as Record<string, unknown>;
  if (typeof params !== 'object' || Array.isArray(params)) return bad('bad_params', 'params doit être un objet');
  const dur = (max: number, dflt: number) => {
    const d = params['duration_s'] ?? dflt;
    return typeof d === 'number' && Number.isInteger(d) && d >= 1 && d <= max;
  };
  if (type === 'ring' && (!dur(300, 60) || (params['vibrate'] !== undefined && typeof params['vibrate'] !== 'boolean'))) return bad('bad_params', 'ring : duration_s entre 1 et 300');
  if (type === 'vibrate' && !dur(60, 10)) return bad('bad_params', 'vibrate : duration_s entre 1 et 60');
  if (type === 'lock' && params['message'] !== undefined && (typeof params['message'] !== 'string' || Array.from(params['message']).length > 200)) return bad('bad_params', 'lock : message de 200 caractères au plus');
  const issued = Date.parse(String(p['issued_at']));
  const expires = Date.parse(String(p['expires_at']));
  if (Number.isNaN(issued) || Number.isNaN(expires)) return bad('invalid_payload', 'issued_at / expires_at invalides');
  if (Math.abs(issued - serverNow()) > 10 * 60_000) return bad('invalid_validity', "issued_at doit être à moins de 10 minutes de l'heure du serveur");
  if (expires <= issued || expires - issued > 30 * DAY) return bad('bad_validity', 'Validité : 30 jours au plus');
  if (expires <= Date.now()) return bad('bad_validity', 'La commande est déjà expirée');
  const sensitive = SENSITIVE.has(type);
  const hasSig = typeof b.sig === 'string' && b.sig !== '';
  if (sensitive && !hasSig) return bad('signature_required', 'Une commande sensible exige une signature');
  if (!sensitive && b.sig !== undefined && b.sig !== '') return bad('signature_unexpected', 'Une commande simple ne porte pas de signature');
  if (commands.some((c) => c.id === id)) return bad('duplicate_id', 'Identifiant déjà utilisé', 409);
  const recent = commands.filter((c) => c.device_id === b.device_id && Date.parse(c.created_at) > Date.now() - 3_600_000).length;
  if (recent >= 20) return bad('rate_limited', 'Limite de 20 commandes par heure atteinte', 429);
  if (commands.filter((c) => c.device_id === b.device_id && c.status === 'pending').length >= 10) return bad('rate_limited', 'Déjà 10 commandes en attente pour cet appareil', 429);
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

// -------------------------------------------------------------------------------------- agent simulé
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

/** Les vérifications de l'agent, dans l'ordre du contrat §8. */
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
      /* signature illisible : comparée comme invalide */
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
    // La position arrive après l'acquisition : le mock la pousse dans le flux SSE.
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
    mk(DAY + 3_600_000, 'lock', { message: 'Téléphone perdu, appelez le 01 23 45 67 89' }, true, 'refused', 'bad_signature', 7 * DAY),
    mk(DAY, 'vibrate', { duration_s: 10 }, false, 'expired'),
  );
  const exp = commands[commands.length - 1] as Command;
  delete exp.delivered_at;
  exp.status = 'expired';
}
