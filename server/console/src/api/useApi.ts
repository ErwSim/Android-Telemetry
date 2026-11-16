import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError } from './client.ts';

export interface ApiState<T> {
  data: T | undefined;
  error: ApiError | undefined;
  loading: boolean;
  reload: () => void;
}

interface Settled<T> {
  key: string;
  tick: number;
  data?: T;
  error?: ApiError;
}

/**
 * Loading of a resource. `fetcher` is re-run when `key` changes (a serialisable value describing
 * the parameters) or after `reload()`. Stale responses are ignored and in-flight requests cancelled.
 * Passing `null` as the key disables loading. During a reload, the previous data for the
 * same key stay visible.
 */
export function useApi<T>(key: string | null, fetcher: (signal: AbortSignal) => Promise<T>): ApiState<T> {
  const [settled, setSettled] = useState<Settled<T> | undefined>();
  const [tick, setTick] = useState(0);
  const fetcherRef = useRef(fetcher);
  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  useEffect(() => {
    if (key === null) return;
    const ctrl = new AbortController();
    fetcherRef
      .current(ctrl.signal)
      .then((data) => {
        if (!ctrl.signal.aborted) setSettled({ key, tick, data });
      })
      .catch((e: unknown) => {
        if (ctrl.signal.aborted) return;
        const error = e instanceof ApiError ? e : new ApiError(0, 'unknown', e instanceof Error ? e.message : String(e));
        setSettled({ key, tick, error });
      });
    return () => ctrl.abort();
  }, [key, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  const current = key !== null && settled?.key === key ? settled : undefined;
  return {
    data: current?.data,
    error: current && current.tick === tick ? current.error : undefined,
    loading: key !== null && (!current || current.tick !== tick),
    reload,
  };
}
