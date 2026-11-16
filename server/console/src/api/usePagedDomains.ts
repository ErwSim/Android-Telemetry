import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './endpoints.ts';
import { ApiError } from './client.ts';
import type { TrackingDomain } from './types.ts';
import { mergeDomains } from '../lib/tracking.ts';

export interface DomainParams {
  device_id: string;
  from: string;
  to: string;
  publisher?: string | undefined;
  status?: string | undefined;
  q?: string | undefined;
}

export interface PagedDomains {
  domains: TrackingDomain[];
  loading: boolean;
  loadingMore: boolean;
  error: ApiError | undefined;
  hasMore: boolean;
  loadMore: () => void;
  reload: () => void;
}

/** Domaines suivis, paginés par curseur (du plus demandé au moins demandé). `null` désactive. */
export function usePagedDomains(params: DomainParams | null, pageSize = 50): PagedDomains {
  const [domains, setDomains] = useState<TrackingDomain[]>([]);
  const [cursor, setCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(params !== null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<ApiError | undefined>();
  const [tick, setTick] = useState(0);
  const key = params ? JSON.stringify(params) : null;
  const ctrl = useRef<AbortController | null>(null);
  const paramsRef = useRef(params);
  useEffect(() => {
    paramsRef.current = params;
  });

  useEffect(() => {
    ctrl.current?.abort();
    const p = paramsRef.current;
    if (key === null || !p) {
      setDomains([]);
      setCursor(undefined);
      setLoading(false);
      return;
    }
    const c = new AbortController();
    ctrl.current = c;
    setLoading(true);
    setError(undefined);
    api
      .trackingDomains({ ...p, limit: pageSize }, c.signal)
      .then((r) => {
        if (c.signal.aborted) return;
        setDomains(r.domains);
        setCursor(r.next_cursor || undefined);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if (c.signal.aborted) return;
        setDomains([]);
        setCursor(undefined);
        setError(e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e)));
        setLoading(false);
      });
    return () => c.abort();
  }, [key, tick, pageSize]);

  const loadMore = useCallback(() => {
    const p = paramsRef.current;
    if (!p || !cursor || loadingMore) return;
    const c = new AbortController();
    ctrl.current = c;
    setLoadingMore(true);
    api
      .trackingDomains({ ...p, limit: pageSize, cursor }, c.signal)
      .then((r) => {
        if (c.signal.aborted) return;
        setDomains((prev) => mergeDomains(prev, r.domains));
        setCursor(r.next_cursor || undefined);
        setLoadingMore(false);
      })
      .catch((e: unknown) => {
        if (c.signal.aborted) return;
        setError(e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e)));
        setLoadingMore(false);
      });
  }, [cursor, loadingMore, pageSize]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { domains, loading, loadingMore, error, hasMore: !!cursor, loadMore, reload };
}
