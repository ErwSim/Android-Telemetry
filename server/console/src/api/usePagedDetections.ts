import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './endpoints.ts';
import { ApiError } from './client.ts';
import type { Detection } from './types.ts';
import { matchesDetection, mergeDetections } from '../lib/detections.ts';

export interface DetectionParams {
  device_id?: string | undefined;
  type?: string | undefined;
  /** filtre par application : transmis au collecteur ET appliqué ici (le contrat §11.3 ne le prévoit pas) */
  package?: string | undefined;
  from: string;
  to: string;
}

export interface PagedDetections {
  detections: Detection[];
  loading: boolean;
  loadingMore: boolean;
  error: ApiError | undefined;
  hasMore: boolean;
  /** vrai si la première page n'est pas la liste complète (curseur renvoyé) */
  loadMore: () => void;
  reload: () => void;
  /** ajoute une détection reçue en direct (déjà filtrée par l'appelant) */
  addLive: (d: Detection) => void;
}

/** Nombre maximal de pages enchaînées automatiquement quand un filtre côté client vide la page reçue. */
const MAX_AUTO_PAGES = 6;

/**
 * Détections paginées par curseur (du plus récent au plus ancien). `null` désactive. Le filtre de type et
 * d'application est aussi appliqué ici : un collecteur qui l'ignorerait ne ferait pas apparaître de lignes en trop.
 */
export function usePagedDetections(params: DetectionParams | null, pageSize = 50): PagedDetections {
  const [detections, setDetections] = useState<Detection[]>([]);
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
      setDetections([]);
      setCursor(undefined);
      setLoading(false);
      return;
    }
    const c = new AbortController();
    ctrl.current = c;
    setLoading(true);
    setError(undefined);
    const filter = { type: p.type, pkg: p.package };
    void (async () => {
      try {
        let acc: Detection[] = [];
        let cur: string | undefined;
        for (let i = 0; i < MAX_AUTO_PAGES; i++) {
          const r = await api.detections({ ...p, limit: pageSize, ...(cur ? { cursor: cur } : {}) }, c.signal);
          if (c.signal.aborted) return;
          acc = mergeDetections(acc, r.detections.filter((d) => matchesDetection(d, filter)));
          cur = r.next_cursor;
          if (!cur || acc.length > 0) break;
        }
        if (c.signal.aborted) return;
        setDetections(acc);
        setCursor(cur);
        setLoading(false);
      } catch (e: unknown) {
        if (c.signal.aborted) return;
        setDetections([]);
        setCursor(undefined);
        setError(e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e)));
        setLoading(false);
      }
    })();
    return () => c.abort();
  }, [key, tick, pageSize]);

  const loadMore = useCallback(() => {
    const p = paramsRef.current;
    if (!p || !cursor || loadingMore) return;
    const c = new AbortController();
    ctrl.current = c;
    setLoadingMore(true);
    const filter = { type: p.type, pkg: p.package };
    api
      .detections({ ...p, limit: pageSize, cursor }, c.signal)
      .then((r) => {
        if (c.signal.aborted) return;
        setDetections((prev) => mergeDetections(prev, r.detections.filter((d) => matchesDetection(d, filter))));
        setCursor(r.next_cursor);
        setLoadingMore(false);
      })
      .catch((e: unknown) => {
        if (c.signal.aborted) return;
        setError(e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e)));
        setLoadingMore(false);
      });
  }, [cursor, loadingMore, pageSize]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  const addLive = useCallback((d: Detection) => setDetections((prev) => mergeDetections(prev, [d])), []);
  return { detections, loading, loadingMore, error, hasMore: !!cursor, loadMore, reload, addLive };
}
