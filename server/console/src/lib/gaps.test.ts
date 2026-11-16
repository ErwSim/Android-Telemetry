import { describe, expect, it } from 'vitest';
import { classifyGap, detectGaps, effectiveThreshold, median, splitSegments } from './gaps.ts';

const MIN = 60_000;
const pts = (...minutes: number[]) => minutes.map((m) => ({ t: m * MIN }));

describe('detectGaps', () => {
  it('detects gaps above the threshold, not those equal to it', () => {
    const p = pts(0, 5, 10, 40, 45, 75, 76);
    const g = detectGaps(p, 25 * MIN);
    expect(g.map((x) => [x.fromIdx, x.toIdx, x.durationMs / MIN])).toEqual([
      [2, 3, 30],
      [4, 5, 30],
    ]);
    expect(detectGaps(pts(0, 30), 30 * MIN)).toEqual([]);
  });
  it('returns nothing for 0 or 1 point', () => {
    expect(detectGaps([], MIN)).toEqual([]);
    expect(detectGaps(pts(3), MIN)).toEqual([]);
  });
});

describe('effectiveThreshold', () => {
  it('raises the threshold when the track is downsampled', () => {
    const p = pts(0, 20, 40, 60, 80);
    expect(effectiveThreshold(p, 15 * MIN)).toBe(60 * MIN);
    expect(effectiveThreshold(pts(0, 1, 2, 3), 15 * MIN)).toBe(15 * MIN);
  });
  it('median', () => {
    expect(median([])).toBe(0);
    expect(median([3, 1, 2])).toBe(2);
    expect(median([4, 1, 2, 3])).toBe(2.5);
  });
});

describe('splitSegments', () => {
  it('splits into continuous segments', () => {
    const g = detectGaps(pts(0, 5, 10, 60, 65, 130), 30 * MIN);
    expect(splitSegments(6, g)).toEqual([
      [0, 2],
      [3, 4],
      [5, 5],
    ]);
    expect(splitSegments(3, [])).toEqual([[0, 2]]);
    expect(splitSegments(0, [])).toEqual([]);
  });
});

describe('classifyGap', () => {
  const gap = { fromIdx: 0, toIdx: 1, start: 60 * MIN, end: 180 * MIN, durationMs: 120 * MIN };
  const buckets = (totals: number[]) => ({
    starts: totals.map((_, i) => i * 60 * MIN),
    bucketMs: 60 * MIN,
    totals,
  });
  it('silent: no event during the gap', () => {
    expect(classifyGap(gap, buckets([5, 0, 0, 7]))).toBe('silent');
  });
  it('nofix: the phone emitted events', () => {
    expect(classifyGap(gap, buckets([5, 4, 6, 7]))).toBe('nofix');
  });
  it('discards the edge buckets for a long gap (events just before the cut)', () => {
    const long = { fromIdx: 0, toIdx: 1, start: 30 * MIN, end: 450 * MIN, durationMs: 420 * MIN };
    // buckets 0..7 of one hour: 0 and 7 active (edges), 1..6 empty
    expect(classifyGap(long, buckets([9, 0, 0, 0, 0, 0, 0, 9]))).toBe('silent');
  });
  it('unknown: no timeline or gap shorter than a bucket', () => {
    expect(classifyGap(gap, undefined)).toBe('unknown');
    expect(classifyGap({ ...gap, start: 10 * MIN, end: 30 * MIN }, buckets([5, 5]))).toBe('unknown');
  });
});
