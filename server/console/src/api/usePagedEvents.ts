import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './endpoints.ts';
import { ApiError } from './client.ts';
import type { WatchpostEvent } from './types.ts';

export interface EventsParams {
  device_id?: string | undefined;
  type?: string | undefined;
  sev_min?: number | undefined;
  q?: string | undefined;
  from: string;
  to: string;
}

export interface PagedEvents {
  events: WatchpostEvent[];
  loading: boolean;
  loadingMore: boolean;
  error: ApiError | undefined;
  hasMore: boolean;
  loadMore: () => void;
  reload: () => void;
}

/** Liste d'événements paginée par curseur (du plus récent au plus ancien). `null` désactive. */
export function usePagedEvents(params: EventsParams | null, pageSize = 100): PagedEvents {
  const [events, setEvents] = useState<WatchpostEvent[]>([]);
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
      setEvents([]);
      setCursor(undefined);
      setLoading(false);
      return;
    }
    const c = new AbortController();
    ctrl.current = c;
    setLoading(true);
    setError(undefined);
    api
      .events({ ...p, limit: pageSize }, c.signal)
      .then((r) => {
        if (c.signal.aborted) return;
        setEvents(r.events);
        setCursor(r.next_cursor || undefined);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if (c.signal.aborted) return;
        setEvents([]);
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
      .events({ ...p, limit: pageSize, cursor }, c.signal)
      .then((r) => {
        if (c.signal.aborted) return;
        setEvents((prev) => {
          const seen = new Set(prev.map((e) => e.id));
          return [...prev, ...r.events.filter((e) => !seen.has(e.id))];
        });
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
  return { events, loading, loadingMore, error, hasMore: !!cursor, loadMore, reload };
}
