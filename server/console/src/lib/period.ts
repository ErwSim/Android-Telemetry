import type { Bucket } from '../api/types.ts';
import { startOfDay } from './format.ts';

export type PeriodKey = 'today' | '24h' | '7d' | '30d' | 'custom';

export const PERIOD_LABELS: Record<PeriodKey, string> = {
  today: 'Today',
  '24h': '24 h',
  '7d': '7 days',
  '30d': '30 days',
  custom: 'Custom',
};

export interface Period {
  key: PeriodKey;
  from: Date;
  to: Date;
}

const H = 3600_000;

export function resolvePeriod(key: PeriodKey, now: Date, custom?: { from: Date; to: Date }): Period {
  switch (key) {
    case 'today':
      return { key, from: startOfDay(now), to: now };
    case '24h':
      return { key, from: new Date(now.getTime() - 24 * H), to: now };
    case '7d':
      return { key, from: new Date(now.getTime() - 7 * 24 * H), to: now };
    case '30d':
      return { key, from: new Date(now.getTime() - 30 * 24 * H), to: now };
    case 'custom':
      if (custom && custom.from < custom.to) return { key, from: custom.from, to: custom.to };
      return { key: '24h', from: new Date(now.getTime() - 24 * H), to: now };
  }
}

export function periodRange(p: Period): { from: string; to: string } {
  return { from: p.from.toISOString(), to: p.to.toISOString() };
}

/** Step of the activity timeline according to the duration (at most ~400 bars). */
export function chooseBucket(from: Date, to: Date): Bucket {
  const span = to.getTime() - from.getTime();
  if (span <= 6 * H) return 'minute';
  if (span <= 16 * 24 * H) return 'hour';
  return 'day';
}

export function bucketMs(b: Bucket): number {
  return b === 'minute' ? 60_000 : b === 'hour' ? H : 24 * H;
}
