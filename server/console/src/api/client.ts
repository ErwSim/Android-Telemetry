// Client HTTP de l'API console. Chemins relatifs (même hôte que la console), cookie de session.

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** Corps JSON de l'erreur (champs supplémentaires, par exemple le détail d'un 409). */
  readonly body: Record<string, unknown> | undefined;
  constructor(status: number, code: string, message: string, body?: Record<string, unknown>) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

const BASE = '/api/console';

// Décalage entre l'horloge du serveur (en-tête `Date` des réponses, précision d'une seconde) et celle de ce
// navigateur : `issued_at` d'une commande doit être à moins de 10 min de l'heure du serveur (contrat §8).
let serverSkewMs: number | undefined;
/** serveur − navigateur, en ms, d'après la dernière réponse ; undefined si inconnu. */
export function clockSkewMs(): number | undefined {
  return serverSkewMs;
}

type Listener = () => void;
const unauthorizedListeners = new Set<Listener>();

/** Appelé quand une requête (hors connexion) reçoit 401 : la session a expiré. */
export function onUnauthorized(fn: Listener): () => void {
  unauthorizedListeners.add(fn);
  return () => unauthorizedListeners.delete(fn);
}

/** Signale une session expirée détectée hors de `request` (flux SSE). */
export function signalUnauthorized(): void {
  unauthorizedListeners.forEach((fn) => fn());
}

export type Query = Record<string, string | number | boolean | undefined | null>;

export function buildQuery(q?: Query): string {
  if (!q) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null || v === '') continue;
    p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

async function parseError(res: Response): Promise<ApiError> {
  let code = `http_${res.status}`;
  let message = res.statusText || `Erreur ${res.status}`;
  let extra: Record<string, unknown> | undefined;
  try {
    const body: unknown = await res.json();
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      extra = body as Record<string, unknown>;
      if (typeof extra['error'] === 'string') code = extra['error'];
      if (typeof extra['message'] === 'string') message = extra['message'];
    }
  } catch {
    /* corps non JSON */
  }
  return new ApiError(res.status, code, message, extra);
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
  signal?: AbortSignal;
  /** Ne pas déclencher le retour à la connexion sur 401 (utilisé par /login et /me). */
  noAuthRedirect?: boolean;
}

export async function request<T>(path: string, query?: Query, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json' };
  const init: RequestInit = { method, headers, credentials: 'same-origin' };
  if (opts.signal) init.signal = opts.signal;
  if (method !== 'GET') headers['X-Requested-With'] = 'vigie';
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}${buildQuery(query)}`, init);
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network', 'Serveur injoignable. Vérifiez la connexion.');
  }
  const dateHeader = res.headers.get('Date');
  if (dateHeader) {
    const t = Date.parse(dateHeader);
    if (Number.isFinite(t)) serverSkewMs = t - Date.now();
  }
  if (res.status === 401 && !opts.noAuthRedirect) {
    unauthorizedListeners.forEach((fn) => fn());
  }
  if (!res.ok) throw await parseError(res);
  if (res.status === 204) return undefined as T;
  try {
    return (await res.json()) as T;
  } catch {
    throw new ApiError(res.status, 'bad_response', 'Réponse du serveur illisible.');
  }
}

export const STREAM_URL = `${BASE}/stream`;
