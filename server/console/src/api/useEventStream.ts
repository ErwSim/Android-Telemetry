import { useEffect, useRef, useState } from 'react';
import { api } from './endpoints.ts';
import { ApiError, buildQuery, signalUnauthorized, STREAM_URL } from './client.ts';
import type { VigieEvent } from './types.ts';
import { isRecord } from '../lib/data.ts';

export type StreamStatus = 'off' | 'connecting' | 'open' | 'error';

export function parseStreamEvent(raw: string): VigieEvent | undefined {
  try {
    const v: unknown = JSON.parse(raw);
    if (!isRecord(v) || typeof v['id'] !== 'string' || typeof v['type'] !== 'string' || typeof v['ts'] !== 'string') return undefined;
    return {
      ...(v as unknown as VigieEvent),
      sev: typeof v['sev'] === 'number' ? v['sev'] : 0,
      data: isRecord(v['data']) ? v['data'] : {},
    };
  } catch {
    return undefined;
  }
}

/** Abonnement SSE (`/stream`). Reconnexion automatique gérée par EventSource ; 401 → retour à la connexion. */
export function useEventStream(enabled: boolean, deviceId: string | undefined, onEvent: (e: VigieEvent) => void): StreamStatus {
  const key = enabled && typeof EventSource !== 'undefined' ? `on:${deviceId ?? ''}` : null;
  const [st, setSt] = useState<{ key: string; status: StreamStatus }>({ key: '', status: 'off' });
  const cb = useRef(onEvent);
  useEffect(() => {
    cb.current = onEvent;
  });

  useEffect(() => {
    if (key === null) return;
    const es = new EventSource(`${STREAM_URL}${buildQuery({ device_id: deviceId })}`, { withCredentials: true });
    const handle = (m: MessageEvent<string>) => {
      const ev = parseStreamEvent(m.data);
      if (ev) cb.current(ev);
    };
    es.onopen = () => setSt({ key, status: 'open' });
    es.onmessage = handle;
    es.addEventListener('event', handle as EventListener);
    es.onerror = () => {
      setSt({ key, status: 'error' });
      // EventSource ne donne pas le code HTTP : on vérifie si la session est encore valide.
      void api.me().catch((e: unknown) => {
        if (e instanceof ApiError && e.status === 401) signalUnauthorized();
      });
    };
    return () => es.close();
  }, [key, deviceId]);

  if (key === null) return 'off';
  return st.key === key ? st.status : 'connecting';
}
