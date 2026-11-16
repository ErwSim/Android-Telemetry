import { describe, expect, it } from 'vitest';
import {
  fmtBytes,
  fmtDateTime,
  fmtDistance,
  fmtDuration,
  fmtNumber,
  fmtRelative,
  fmtSpeedKmh,
  fmtValue,
  parseTs,
  toLocalInput,
} from './format.ts';

const nbsp = ' ';

describe('parseTs', () => {
  it('accepts RFC 3339, epoch ms and epoch s', () => {
    expect(parseTs('2026-11-15T21:43:03.974Z')?.toISOString()).toBe('2026-11-15T21:43:03.974Z');
    expect(parseTs(1_763_243_000_000)?.getTime()).toBe(1_763_243_000_000);
    expect(parseTs(1_763_243_000)?.getTime()).toBe(1_763_243_000_000);
  });
  it('returns undefined for an invalid value', () => {
    expect(parseTs('not a date')).toBeUndefined();
    expect(parseTs(undefined)).toBeUndefined();
    expect(parseTs('')).toBeUndefined();
    expect(parseTs(Number.NaN)).toBeUndefined();
  });
});

describe('fmtDateTime', () => {
  it('formats in English in the requested time zone', () => {
    expect(fmtDateTime('2026-11-15T21:43:03Z', 'Europe/Paris')).toBe('15/11/2026, 22:43:03');
    expect(fmtDateTime('2026-07-01T10:00:00Z', 'Europe/Paris')).toBe('01/07/2026, 12:00:00');
  });
  it('shows a dash for a missing or invalid date', () => {
    expect(fmtDateTime(undefined)).toBe('—');
    expect(fmtDateTime('x')).toBe('—');
  });
});

describe('fmtRelative', () => {
  const now = new Date('2026-11-15T12:00:00Z');
  it('expresses the past in English', () => {
    expect(fmtRelative('2026-11-15T11:57:00Z', now)).toBe('3 minutes ago');
    expect(fmtRelative('2026-11-15T09:00:00Z', now)).toBe('3 hours ago');
    expect(fmtRelative('2026-11-13T12:00:00Z', now)).toBe('2 days ago');
    expect(fmtRelative('2026-11-15T11:59:50Z', now)).toBe('just now');
  });
});

describe('fmtBytes', () => {
  it('uses binary units', () => {
    expect(fmtBytes(0)).toBe(`0${nbsp}B`);
    expect(fmtBytes(1023)).toBe(`1,023${nbsp}B`);
    expect(fmtBytes(1536)).toBe(`1.5${nbsp}KiB`);
    expect(fmtBytes(5 * 1024 * 1024)).toBe(`5${nbsp}MiB`);
    expect(fmtBytes(undefined)).toBe('—');
  });
});

describe('fmtDuration', () => {
  it('picks readable units', () => {
    expect(fmtDuration(45_000)).toBe(`45${nbsp}s`);
    expect(fmtDuration(12 * 60_000)).toBe(`12${nbsp}min`);
    expect(fmtDuration((2 * 60 + 5) * 60_000)).toBe(`2${nbsp}h${nbsp}05`);
    expect(fmtDuration(3 * 86_400_000 + 4 * 3_600_000)).toBe(`3${nbsp}d${nbsp}4${nbsp}h`);
    expect(fmtDuration(-1)).toBe('—');
  });
});

describe('fmtDistance / fmtSpeedKmh / fmtNumber / fmtValue', () => {
  it('formats distances and speeds', () => {
    expect(fmtDistance(850)).toBe(`850${nbsp}m`);
    expect(fmtDistance(12_400)).toBe(`12.4${nbsp}km`);
    expect(fmtSpeedKmh(10)).toBe(`36${nbsp}km/h`);
  });
  it('handles missing values', () => {
    expect(fmtNumber(undefined)).toBe('—');
    expect(fmtValue(undefined)).toBe('—');
    expect(fmtValue(true)).toBe('yes');
    expect(fmtValue(['a'])).toBe('["a"]');
  });
});

describe('toLocalInput', () => {
  it('produces the datetime-local format in local time', () => {
    expect(toLocalInput(new Date(2026, 10, 5, 7, 4))).toBe('2026-11-05T07:04');
  });
});
