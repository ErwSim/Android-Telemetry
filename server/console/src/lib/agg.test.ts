import { describe, expect, it } from 'vitest';
import { countKeys, groupPermissions, mergeTop, stackSeries, timelineTotals, vendorShare } from './agg.ts';

describe('countKeys', () => {
  it('sorts by frequency then alphabetical order and ignores empty ones', () => {
    expect(countKeys(['b', 'a', 'b', undefined, 'c', 'a', 'b'])).toEqual([
      { key: 'b', count: 3 },
      { key: 'a', count: 2 },
      { key: 'c', count: 1 },
    ]);
    expect(countKeys(['x', 'y', 'z'], 2)).toHaveLength(2);
  });
});

describe('mergeTop', () => {
  it('adds up counters and bytes per key', () => {
    const m = mergeTop([{ key: 'a', count: 2, bytes: 10 }, { key: 'b', count: 1 }], [{ key: 'a', count: 3 }, { key: 'b', count: 5, bytes: 4 }]);
    expect(m).toEqual([
      { key: 'b', count: 6, bytes: 4 },
      { key: 'a', count: 5, bytes: 10 },
    ]);
  });
});

describe('vendorShare', () => {
  it('splits Google / Samsung / others for DNS names', () => {
    const s = vendorShare(
      [
        { key: 'app-measurement.com', count: 10 },
        { key: 'play.googleapis.com', count: 5 },
        { key: 'eu-api.samsungcloud.com', count: 4 },
        { key: 'news.example', count: 1 },
        { key: 'notgoogle.com', count: 2 },
      ],
      'host',
    );
    expect(s).toEqual({ google: 15, samsung: 4, other: 3, total: 22 });
  });
  it('classifies packages and weights by bytes', () => {
    const s = vendorShare(
      [
        { key: 'com.google.android.gms', count: 1, bytes: 100 },
        { key: 'com.samsung.android.mobileservice', count: 1, bytes: 50 },
        { key: 'com.whatsapp', count: 1, bytes: 25 },
      ],
      'package',
      'bytes',
    );
    expect(s).toEqual({ google: 100, samsung: 50, other: 25, total: 175 });
  });
});

describe('groupPermissions', () => {
  it('groups by permission, the most widespread first', () => {
    const g = groupPermissions([
      { package: 'a', granted_dangerous: ['CAMERA', 'MIC'] },
      { package: 'b', granted_dangerous: ['CAMERA'] },
      { package: 'c' },
    ]);
    expect(g.map((x) => [x.permission, x.apps.length])).toEqual([
      ['CAMERA', 2],
      ['MIC', 1],
    ]);
  });
});

describe('timeline', () => {
  const t = {
    buckets: ['2026-11-15T10:00:00Z', '2026-11-15T11:00:00Z'],
    series: [
      { key: 'net', counts: [3, 1] },
      { key: 'app', counts: [1, 0] },
    ],
  };
  it('totals per bucket', () => {
    expect(timelineTotals(t).totals).toEqual([4, 1]);
  });
  it('stacks the series in the requested order', () => {
    const s = stackSeries(t, ['app']);
    expect(s.keys).toEqual(['app', 'net']);
    expect(s.cumulative).toEqual([
      [1, 0],
      [4, 1],
    ]);
    expect(s.sums).toEqual([1, 4]);
    expect(s.x[0]).toBe(Date.parse('2026-11-15T10:00:00Z') / 1000);
  });
});
