// HTTP client of the console API. Relative paths (same host as the console), session cookie.

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** JSON body of the error (extra fields, for example the detail of a 409). */
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

// Offset between the server's clock (`Date` header of the responses, one-second precision) and that of this
// browser: a command's `issued_at` must be within 10 min of the server's time (contract §8).
let serverSkewMs: number | undefined;
/** server − browser, in ms, from the last response; undefined if unknown. */
export function clockSkewMs(): number | undefined {
  return serverSkewMs;
}

type Listener = () => void;
const unauthorizedListeners = new Set<Listener>();

/** Called when a request (other than login) receives 401: the session has expired. */
export function onUnauthorized(fn: Listener): () => void {
  unauthorizedListeners.add(fn);
  return () => unauthorizedListeners.delete(fn);
}

/** Reports an expired session detected outside `request` (SSE stream). */
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
  let message = res.statusText || `Error ${res.status}`;
  let extra: Record<string, unknown> | undefined;
  try {
    const body: unknown = await res.json();
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      extra = body as Record<string, unknown>;
      if (typeof extra['error'] === 'string') code = extra['error'];
      if (typeof extra['message'] === 'string') message = extra['message'];
    }
  } catch {
    /* non-JSON body */
  }
  return new ApiError(res.status, code, message, extra);
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
  signal?: AbortSignal;
  /** Do not trigger the return to the login page on 401 (used by /login and /me). */
  noAuthRedirect?: boolean;
}

export async function request<T>(path: string, query?: Query, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json' };
  const init: RequestInit = { method, headers, credentials: 'same-origin' };
  if (opts.signal) init.signal = opts.signal;
  if (method !== 'GET') headers['X-Requested-With'] = 'watchpost';
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}${buildQuery(query)}`, init);
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network', 'Server unreachable. Check the connection.');
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
    throw new ApiError(res.status, 'bad_response', 'Unreadable server response.');
  }
}

export const STREAM_URL = `${BASE}/stream`;
