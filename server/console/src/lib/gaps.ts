// Detection of gaps in a location track and classification of their probable cause.

export interface TimedPoint {
  /** epoch ms */
  t: number;
}

export interface Gap {
  /** index of the last point before the gap */
  fromIdx: number;
  /** index of the first point after the gap */
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
 * Gaps: two consecutive points separated by more than `thresholdMs`.
 * Points are assumed sorted by increasing time.
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
 * Effective threshold: the chosen threshold, raised to 3 times the median interval so as not to declare gaps
 * when the server has downsampled the track.
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

/** Splits into continuous segments (runs of indexes [start, end] inclusive) separated by the gaps. */
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
  /** start of each bucket, epoch ms */
  starts: number[];
  bucketMs: number;
  /** number of events (all categories) per bucket */
  totals: number[];
}

/**
 * - `silent`: no event received during the gap (offline, powered off or agent stopped);
 * - `nofix`: the phone emitted events but no location;
 * - `unknown`: gap shorter than the timeline's granularity.
 */
export function classifyGap(gap: Gap, act: Activity | undefined): GapKind {
  if (!act || act.starts.length === 0) return 'unknown';
  let inside = 0;
  let active = 0;
  // The end buckets contain events emitted just before/after the gap: we discard them
  // when the gap is long enough for some to remain.
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
  silent: 'No event received (offline, powered off or agent stopped)',
  nofix: 'Phone active but without a location (no fix)',
  unknown: 'Undetermined cause',
};
