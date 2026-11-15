// Détection des trous dans une trace de positions et classification de leur cause probable.

export interface TimedPoint {
  /** epoch ms */
  t: number;
}

export interface Gap {
  /** index du dernier point avant le trou */
  fromIdx: number;
  /** index du premier point après le trou */
  toIdx: number;
  start: number;
  end: number;
  durationMs: number;
}

export function median(values: number[]): number {
  if (values.length === 0) return 0;
  const s = [...values].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? (s[m] ?? 0) : ((s[m - 1] ?? 0) + (s[m] ?? 0)) / 2;
}

/**
 * Trous : deux points consécutifs séparés de plus de `thresholdMs`.
 * Les points sont supposés triés par temps croissant.
 */
export function detectGaps(points: TimedPoint[], thresholdMs: number): Gap[] {
  const gaps: Gap[] = [];
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1];
    const b = points[i];
    if (!a || !b) continue;
    const d = b.t - a.t;
    if (d > thresholdMs) gaps.push({ fromIdx: i - 1, toIdx: i, start: a.t, end: b.t, durationMs: d });
  }
  return gaps;
}

/**
 * Seuil effectif : le seuil choisi, relevé à 3 fois l'intervalle médian pour ne pas déclarer de trous
 * quand le serveur a sous-échantillonné la trace.
 */
export function effectiveThreshold(points: TimedPoint[], baseMs: number): number {
  const deltas: number[] = [];
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1];
    const b = points[i];
    if (a && b) deltas.push(b.t - a.t);
  }
  return Math.max(baseMs, 3 * median(deltas));
}

/** Découpe en segments continus (suites d'index [début, fin] inclus) séparés par les trous. */
export function splitSegments(count: number, gaps: Gap[]): [number, number][] {
  if (count === 0) return [];
  const segs: [number, number][] = [];
  let start = 0;
  for (const g of gaps) {
    segs.push([start, g.fromIdx]);
    start = g.toIdx;
  }
  segs.push([start, count - 1]);
  return segs;
}

export type GapKind = 'silent' | 'nofix' | 'unknown';

export interface Activity {
  /** début de chaque tranche, epoch ms */
  starts: number[];
  bucketMs: number;
  /** nombre d'événements (toutes catégories) par tranche */
  totals: number[];
}

/**
 * - `silent` : aucun événement reçu pendant le trou (hors ligne, éteint ou agent arrêté) ;
 * - `nofix` : le téléphone a émis des événements mais aucune position ;
 * - `unknown` : trou plus court que la granularité de la chronologie.
 */
export function classifyGap(gap: Gap, act: Activity | undefined): GapKind {
  if (!act || act.starts.length === 0) return 'unknown';
  let inside = 0;
  let active = 0;
  // Les tranches des extrémités contiennent les événements émis juste avant/après le trou : on les écarte
  // quand le trou est assez long pour qu'il en reste.
  const margin = gap.durationMs > 3 * act.bucketMs ? act.bucketMs : 0;
  const lo = gap.start + margin;
  const hi = gap.end - margin;
  for (let i = 0; i < act.starts.length; i++) {
    const s = act.starts[i] ?? 0;
    const e = s + act.bucketMs;
    if (s >= lo && e <= hi) {
      inside++;
      if ((act.totals[i] ?? 0) > 0) active++;
    }
  }
  if (inside === 0) return 'unknown';
  return active / inside < 0.2 ? 'silent' : 'nofix';
}

export const GAP_LABELS: Record<GapKind, string> = {
  silent: 'Aucun événement reçu (hors ligne, éteint ou agent arrêté)',
  nofix: 'Téléphone actif mais sans position (pas de fix)',
  unknown: 'Cause indéterminée',
};
