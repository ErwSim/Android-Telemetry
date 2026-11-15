import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError } from './client.ts';

export interface ApiState<T> {
  data: T | undefined;
  error: ApiError | undefined;
  loading: boolean;
  reload: () => void;
}

/**
 * Chargement d'une ressource. `fetcher` est ré-exécuté quand `key` change (valeur sérialisable décrivant
 * les paramètres). Les réponses obsolètes sont ignorées et les requêtes en vol annulées.
 * Passer `null` comme clé désactive le chargement.
 */
export function useApi<T>(
  key: string | null,
  fetcher: (signal: AbortSignal) => Promise<T>,
): ApiState<T> {
  const [state, setState] = useState<{ data: T | undefined; error: ApiError | undefined; loading: boolean; key: string | null }>({
    data: undefined,
    error: undefined,
    loading: key !== null,
    key,
  });
  const [tick, setTick] = useState(0);
  const fetcherRef = useRef(fetcher);
  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  useEffect(() => {
    if (key === null) {
      setState({ data: undefined, error: undefined, loading: false, key });
      return;
    }
    const ctrl = new AbortController();
    setState((s) => ({ data: s.key === key ? s.data : undefined, error: undefined, loading: true, key }));
    fetcherRef
      .current(ctrl.signal)
      .then((data) => {
        if (!ctrl.signal.aborted) setState({ data, error: undefined, loading: false, key });
      })
      .catch((e: unknown) => {
        if (ctrl.signal.aborted) return;
        const err = e instanceof ApiError ? e : new ApiError(0, 'unknown', e instanceof Error ? e.message : String(e));
        setState({ data: undefined, error: err, loading: false, key });
      });
    return () => ctrl.abort();
  }, [key, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data: state.key === key ? state.data : undefined, error: state.error, loading: state.loading, reload };
}
