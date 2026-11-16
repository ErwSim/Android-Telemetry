import type { AppInfo, TimelineResponse, TopItem } from '../api/types.ts';
import { classifyHost, classifyPackage, type Vendor } from './vendors.ts';

export interface Counted {
  key: string;
  count: number;
}

/** Count of keys, sorted by decreasing frequency then alphabetically. */
export function countKeys(keys: (string | undefined)[], limit = Infinity): Counted[] {
  const m = new Map<string, number>();
  for (const k of keys) {
    if (!k) continue;
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
    .slice(0, limit);
}

/** Merges several rankings by adding `count` and `bytes` per key. */
export function mergeTop(...lists: TopItem[][]): TopItem[] {
  const m = new Map<string, TopItem>();
  for (const l of lists) {
    for (const it of l) {
      const cur = m.get(it.key);
      if (cur) {
        cur.count += it.count;
        if (it.bytes !== undefined) cur.bytes = (cur.bytes ?? 0) + it.bytes;
      } else {
        m.set(it.key, { ...it });
      }
    }
  }
  return [...m.values()].sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

export interface VendorShare {
  google: number;
  samsung: number;
  other: number;
  total: number;
}

/** Google / Samsung / others split weighted by `count` (or `bytes` if `by === 'bytes'`). */
export function vendorShare(
  items: TopItem[],
  kind: 'host' | 'package',
  by: 'count' | 'bytes' = 'count',
): VendorShare {
  const out: VendorShare = { google: 0, samsung: 0, other: 0, total: 0 };
  for (const it of items) {
    const v: Vendor = kind === 'host' ? classifyHost(it.key) : classifyPackage(it.key);
    const w = by === 'bytes' ? (it.bytes ?? 0) : it.count;
    out[v] += w;
    out.total += w;
  }
  return out;
}

export interface PermissionGroup {
  permission: string;
  apps: AppInfo[];
}

/** Granted dangerous permissions, grouped by permission (the most widespread first). */
export function groupPermissions(apps: AppInfo[]): PermissionGroup[] {
  const m = new Map<string, AppInfo[]>();
  for (const a of apps) {
    for (const p of a.granted_dangerous ?? []) {
      const arr = m.get(p);
      if (arr) arr.push(a);
      else m.set(p, [a]);
    }
  }
  return [...m.entries()]
    .map(([permission, as]) => ({ permission, apps: as }))
    .sort((a, b) => b.apps.length - a.apps.length || a.permission.localeCompare(b.permission));
}

/** Total events per bucket. */
export function timelineTotals(t: TimelineResponse): { starts: number[]; totals: number[] } {
  const starts = t.buckets.map((b) => new Date(b).getTime());
  const totals = t.buckets.map((_, i) => t.series.reduce((acc, s) => acc + (s.counts[i] ?? 0), 0));
  return { starts, totals };
}

export interface StackedData {
  /** epoch seconds (uPlot format) */
  x: number[];
  /** cumulative sums per series, in the order of `keys` */
  cumulative: number[][];
  keys: string[];
  /** total per series */
  sums: number[];
}

/** Stacks the series (the first at the bottom). Keys absent from `order` follow by decreasing volume. */
export function stackSeries(t: TimelineResponse, order: string[] = []): StackedData {
  const sums = new Map(t.series.map((s) => [s.key, s.counts.reduce((a, b) => a + b, 0)]));
  const keys = [
    ...order.filter((k) => sums.has(k)),
    ...[...sums.keys()].filter((k) => !order.includes(k)).sort((a, b) => (sums.get(b) ?? 0) - (sums.get(a) ?? 0)),
  ];
  const x = t.buckets.map((b) => Math.floor(new Date(b).getTime() / 1000));
  const running = new Array<number>(x.length).fill(0);
  const cumulative: number[][] = [];
  for (const k of keys) {
    const s = t.series.find((s2) => s2.key === k);
    for (let i = 0; i < x.length; i++) running[i] = (running[i] ?? 0) + (s?.counts[i] ?? 0);
    cumulative.push([...running]);
  }
  return { x, cumulative, keys, sums: keys.map((k) => sums.get(k) ?? 0) };
}

/** Count per installer (missing installer grouped under "(none)"). */
export function countByInstaller(apps: AppInfo[]): Counted[] {
  return countKeys(apps.map((a) => a.installer || '(none)'));
}
