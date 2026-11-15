import { describe, expect, it } from 'vitest';
import { classifyGap, detectGaps, effectiveThreshold, median, splitSegments } from './gaps.ts';

const MIN = 60_000;
const pts = (...minutes: number[]) => minutes.map((m) => ({ t: m * MIN }));

describe('detectGaps', () => {
  it("détecte les écarts supérieurs au seuil, pas ceux qui l'égalent", () => {
    const p = pts(0, 5, 10, 40, 45, 75, 76);
    const g = detectGaps(p, 25 * MIN);
    expect(g.map((x) => [x.fromIdx, x.toIdx, x.durationMs / MIN])).toEqual([
      [2, 3, 30],
      [4, 5, 30],
    ]);
    expect(detectGaps(pts(0, 30), 30 * MIN)).toEqual([]);
  });
  it('ne renvoie rien pour 0 ou 1 point', () => {
    expect(detectGaps([], MIN)).toEqual([]);
    expect(detectGaps(pts(3), MIN)).toEqual([]);
  });
});

describe('effectiveThreshold', () => {
  it("relève le seuil quand la trace est sous-échantillonnée", () => {
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
  it('découpe en segments continus', () => {
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
  it('silent : aucun événement pendant le trou', () => {
    expect(classifyGap(gap, buckets([5, 0, 0, 7]))).toBe('silent');
  });
  it('nofix : le téléphone a émis des événements', () => {
    expect(classifyGap(gap, buckets([5, 4, 6, 7]))).toBe('nofix');
  });
  it('écarte les tranches de bord pour un trou long (événements juste avant la coupure)', () => {
    const long = { fromIdx: 0, toIdx: 1, start: 30 * MIN, end: 450 * MIN, durationMs: 420 * MIN };
    // tranches 0..7 d'une heure : 0 et 7 actives (bords), 1..6 vides
    expect(classifyGap(long, buckets([9, 0, 0, 0, 0, 0, 0, 9]))).toBe('silent');
  });
  it("unknown : pas de chronologie ou trou plus court qu'une tranche", () => {
    expect(classifyGap(gap, undefined)).toBe('unknown');
    expect(classifyGap({ ...gap, start: 10 * MIN, end: 30 * MIN }, buckets([5, 5]))).toBe('unknown');
  });
});
