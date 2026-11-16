import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './endpoints.ts';
import { ApiError } from './client.ts';
import type { RemoteCommand } from './types.ts';
import { statusInfo } from '../lib/commands.ts';

export interface CommandList {
  commands: RemoteCommand[] | undefined;
  error: ApiError | undefined;
  loading: boolean;
  reload: () => void;
}

const FAST_MS = 2500;
const SLOW_MS = 20_000;

/**
 * Historique des commandes, rafraîchi en direct : toutes les 2,5 s tant qu'une commande est `pending` ou
 * `delivered` (son état évolue), toutes les 20 s sinon. `reload()` force une lecture immédiate (par exemple à la
 * réception d'un `command.result` par le flux SSE).
 */
export function useCommandList(deviceId: string | undefined, limit = 50): CommandList {
  const [state, setState] = useState<{ key: string; commands?: RemoteCommand[]; error?: ApiError }>({ key: '' });
  const [tick, setTick] = useState(0);
  const key = deviceId ? `${deviceId}:${limit}` : '';
  const active = state.key === key && (state.commands ?? []).some((c) => statusInfo(c.status).active);
  const ctrl = useRef<AbortController | null>(null);

  const fetchNow = useCallback(() => {
    if (!deviceId) return;
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    api
      .commands({ device_id: deviceId, limit }, c.signal)
      .then((r) => {
        if (!c.signal.aborted) setState({ key, commands: r.commands });
      })
      .catch((e: unknown) => {
        if (c.signal.aborted) return;
        const error = e instanceof ApiError ? e : new ApiError(0, 'unknown', e instanceof Error ? e.message : String(e));
        // Une erreur passagère n'efface pas la liste déjà affichée.
        setState((s) => (s.key === key ? { key, ...(s.commands ? { commands: s.commands } : {}), error } : { key, error }));
      });
  }, [deviceId, limit, key]);

  useEffect(() => {
    fetchNow();
    return () => ctrl.current?.abort();
  }, [fetchNow, tick]);

  useEffect(() => {
    if (!deviceId) return;
    const t = window.setInterval(fetchNow, active ? FAST_MS : SLOW_MS);
    return () => window.clearInterval(t);
  }, [deviceId, active, fetchNow]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  const cur = state.key === key ? state : undefined;
  return { commands: cur?.commands, error: cur?.error, loading: !!deviceId && !cur, reload };
}
