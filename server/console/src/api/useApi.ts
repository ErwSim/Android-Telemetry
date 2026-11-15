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
 * Chargement d'une ressource. `fetcher` est ré-exécuté quand `key` change (valeur sérialisable décrivant
 * les paramètres) ou après `reload()`. Les réponses obsolètes sont ignorées et les requêtes en vol annulées.
 * Passer `null` comme clé désactive le chargement. Pendant un rechargement, les données précédentes de la
 * même clé restent visibles.
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
