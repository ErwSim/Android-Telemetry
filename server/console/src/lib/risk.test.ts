import { describe, expect, it } from 'vitest';
import {
  COMBO_CODES,
  REASON_CODES,
  combosOf,
  filterRisk,
  grantState,
  levelInfo,
  normalizeRisk,
  orderReasons,
  parseRiskResponse,
  reasonInfo,
  riskCounts,
  sortByScore,
} from './risk.ts';

describe('reason codes (closed list of contract §11.2)', () => {
  it('translates each of the 20 codes into English, with an explanation', () => {
    expect(REASON_CODES).toHaveLength(20);
    for (const code of REASON_CODES) {
      const r = reasonInfo(code);
      expect(r.known).toBe(true);
      expect(r.label).not.toBe(code);
      expect(r.explain.length).toBeGreaterThan(30);
    }
    expect(reasonInfo('sms_send').label).toBe('Can send SMS');
  });

  it('the three combinations are spotted and first', () => {
    expect(COMBO_CODES).toEqual(['combo_banking_trojan', 'combo_sms_fraud', 'combo_stalkerware']);
    for (const c of COMBO_CODES) expect(reasonInfo(c).combo).toBe(true);
    expect(reasonInfo('overlay').combo).toBe(false);
    const ordered = orderReasons(['boot_receiver', 'sms_send', 'combo_sms_fraud', 'sideloaded']).map((r) => r.code);
    expect(ordered[0]).toBe('combo_sms_fraud');
    expect(ordered).toHaveLength(4);
  });

  it('an unknown code is displayed as is, without an invented explanation', () => {
    const r = reasonInfo('quantum_overlay');
    expect(r.known).toBe(false);
    expect(r.label).toBe('quantum_overlay');
    expect(r.tone).toBe('neutral');
    // and does not fall on a name inherited from Object
    expect(reasonInfo('constructor').known).toBe(false);
    expect(reasonInfo('__proto__').label).toBe('__proto__');
    expect(orderReasons(['zzz', 'sms_send']).map((x) => x.code)).toEqual(['sms_send', 'zzz']);
  });

  it('deduplicates and spots the combinations in the contract order', () => {
    expect(combosOf(['combo_stalkerware', 'x', 'combo_banking_trojan'])).toEqual(['combo_banking_trojan', 'combo_stalkerware']);
    expect(combosOf([])).toEqual([]);
    expect(orderReasons(['sms_send', 'sms_send'])).toHaveLength(1);
  });
});

describe('levels', () => {
  it('takes the announced level, otherwise deduces it from the score', () => {
    expect(levelInfo('high', 3).label).toBe('High');
    expect(levelInfo('low', 99).tone).toBe('ok');
    expect(levelInfo('mystery', 70).key).toBe('high');
    expect(levelInfo(undefined, 40).key).toBe('medium');
    expect(levelInfo('', 10).key).toBe('low');
  });
});

describe('reading /apps/risk', () => {
  const raw = {
    apps: [
      { package: 'a', score: 40, level: 'medium', reasons: ['sideloaded'] },
      { package: 'b', score: 95, level: 'high', reasons: ['combo_sms_fraud', 'sms_send', 'boot_receiver'], label: 'B', from_store: false, installer: 'x' },
      { package: 'c', score: 40, level: 'medium', reasons: ['sideloaded', 'boot_receiver'] },
      { package: 'd', score: 2, level: 'low', reasons: [] },
    ],
  };

  it('sorts by decreasing score then by number of reasons', () => {
    expect(parseRiskResponse(raw).apps.map((a) => a.package)).toEqual(['b', 'c', 'a', 'd']);
  });

  it('accepts a bare array, fields under data, and ignores invalid items', () => {
    expect(parseRiskResponse([{ package: 'x', score: 10, level: 'low', reasons: [] }]).apps).toHaveLength(1);
    const n = normalizeRisk({ ts: '2026-11-16T10:00:00Z', data: { package: 'p', score: 300, level: 'high', reasons: ['a', 3, ''] } });
    expect(n).toMatchObject({ package: 'p', score: 100, reasons: ['a'], ts: '2026-11-16T10:00:00Z' });
    expect(parseRiskResponse({ apps: [null, 5, { score: 3 }, { package: '' }] }).apps).toEqual([]);
    expect(parseRiskResponse(null).apps).toEqual([]);
    expect(parseRiskResponse({}).apps).toEqual([]);
  });

  it('counts per level and per combination', () => {
    const apps = parseRiskResponse(raw).apps;
    expect(riskCounts(apps)).toEqual({ high: 1, medium: 2, low: 1, total: 4, withCombo: 1 });
    expect(riskCounts([])).toEqual({ high: 0, medium: 0, low: 0, total: 0, withCombo: 0 });
  });

  it('filters by level, combination and text', () => {
    const apps = parseRiskResponse(raw).apps;
    expect(filterRisk(apps, { level: 'medium', comboOnly: false, q: '' }).map((a) => a.package)).toEqual(['b', 'c', 'a']);
    expect(filterRisk(apps, { level: 'all', comboOnly: true, q: '' }).map((a) => a.package)).toEqual(['b']);
    expect(filterRisk(apps, { level: 'all', comboOnly: false, q: ' B ' }).map((a) => a.package)).toEqual(['b']);
  });

  it('sortByScore does not modify its input', () => {
    const l = parseRiskResponse(raw).apps;
    const copy = [...l].reverse();
    sortByScore(copy);
    expect(copy[0]?.package).toBe('d');
  });
});

describe('declared and granted capabilities (§11.4)', () => {
  const base = { package: 'p', score: 80, level: 'high' };
  it('reads the parallel `granted` list, with or without the ":granted" suffix', () => {
    const a = normalizeRisk({ ...base, reasons: ['sms_send', 'sideloaded', 'accessibility_service'], granted: ['sms_send'] });
    expect(a?.reasons).toEqual(['sms_send', 'sideloaded', 'accessibility_service']);
    expect(a?.granted).toEqual(['sms_send']);
    const b = normalizeRisk({ ...base, reasons: ['sms_send', 'sideloaded'], granted: ['sms_send:granted'] });
    expect(b?.granted).toEqual(['sms_send']);
    const c = normalizeRisk({ ...base, reasons: ['sms_send:granted', 'overlay'] });
    expect(c?.reasons).toEqual(['sms_send', 'overlay']);
    expect(c?.granted).toEqual(['sms_send']);
  });
  it('without a `granted` list (older agent): no invented distinction', () => {
    const a = normalizeRisk({ ...base, reasons: ['sms_send'] });
    expect(a?.granted).toBeUndefined();
    expect(grantState(a as never, 'sms_send')).toBe('unknown');
    expect(normalizeRisk({ ...base, reasons: [], granted: [] })?.granted).toEqual([]);
  });
  it('distinguishes granted, requested only, and state (installer, icon...) which is not a capability', () => {
    const r = { granted: ['sms_send'] };
    expect(grantState(r, 'sms_send')).toBe('granted');
    expect(grantState(r, 'accessibility_service')).toBe('declared');
    expect(grantState(r, 'sideloaded')).toBe('unknown');
    expect(grantState(r, 'combo_sms_fraud')).toBe('unknown');
    expect(grantState(r, 'unknown_code')).toBe('unknown');
    expect(grantState({ granted: [] }, 'sms_send')).toBe('declared');
  });
});
