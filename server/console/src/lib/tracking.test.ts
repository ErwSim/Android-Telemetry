import { describe, expect, it } from 'vitest';
import type { Publisher, TrackingApp, TrackingDomain } from '../api/types.ts';
import {
  availableActions,
  blockedPct,
  domainStatus,
  effectiveOverride,
  filterApps,
  hasStatusData,
  levelTexts,
  mergeDomains,
  parseConflict,
  reasonLabel,
  sortPublishers,
  splitApps,
  totalsOf,
  trackingErrorMessage,
} from './tracking.ts';

describe('blocking levels', () => {
  it('fills in missing texts and orders permissive, balanced, strict', () => {
    const t = levelTexts([{ key: 'strict' }, { key: 'permissive', description: 'My text' }, { key: 'balanced', name: 'Balanced' }]);
    expect(t.map((l) => l.key)).toEqual(['permissive', 'balanced', 'strict']);
    expect(t[0]?.description).toBe('My text');
    expect(t[0]?.name).toBe('Permissive');
    expect(t[2]?.description).toContain('Some applications');
  });
  it('without a list from the collector, offers the three levels', () => {
    expect(levelTexts(undefined).map((l) => l.key)).toEqual(['permissive', 'balanced', 'strict']);
  });
  it('keeps an unknown level at the end, without losing it', () => {
    const t = levelTexts([{ key: 'paranoid' }, { key: 'strict' }]);
    expect(t.map((l) => l.key)).toEqual(['strict', 'paranoid']);
    expect(t[1]?.name).toBe('paranoid');
  });
});

describe('reasons and statuses', () => {
  it('translates AdGuard Home tokens and keeps the list name', () => {
    expect(reasonLabel('FilteredBlackList: AdGuard DNS filter')).toBe('Blocklist: AdGuard DNS filter');
    expect(reasonLabel('FilteredBlackList')).toBe('Blocklist');
    expect(reasonLabel('NotFilteredWhiteList: @@||x.com^')).toBe('Allowed by a rule: @@||x.com^');
    expect(reasonLabel('NotFilteredNotFound')).toBe('No list blocks it');
  });
  it('displays a free-form reason as is', () => {
    expect(reasonLabel('Watchpost list: Samsung telemetry')).toBe('Watchpost list: Samsung telemetry');
    expect(reasonLabel(undefined)).toBeUndefined();
    expect(reasonLabel('')).toBeUndefined();
  });
  it('statuses', () => {
    expect(domainStatus('blocked').label).toBe('Blocked');
    expect(domainStatus('allowed').label).toBe('Allowed');
    expect(domainStatus('mixed').label).toBe('Mixed');
    expect(domainStatus(undefined).label).toBe('Not assessed');
  });
});

describe('aggregations', () => {
  const pubs: Publisher[] = [
    { key: 'a', name: 'Others', queries: 10, blocked: 2, allowed: 8, domains: 3, apps: 2 },
    { key: 'g', name: 'Google', queries: 100, blocked: 40, allowed: 60, domains: 20, apps: 5, tx_bytes: 10 },
    { key: 'v', name: 'Empty', queries: 0 },
  ];
  it('blocked share', () => {
    expect(blockedPct({ queries: 100, blocked: 40, allowed: 60 })).toBe(40);
    expect(blockedPct({ queries: 0, blocked: 0, allowed: 0 })).toBe(0);
    expect(blockedPct({ queries: 50 })).toBeUndefined();
    expect(blockedPct({ queries: 10, blocked: 10 })).toBe(100);
  });
  it('totals: the collector\'s, otherwise the sum of the publishers', () => {
    expect(totalsOf({ queries: 5, blocked: 1, allowed: 4 }, pubs)).toEqual({ queries: 5, blocked: 1, allowed: 4 });
    expect(totalsOf(undefined, pubs)).toEqual({ queries: 110, blocked: 42, allowed: 68 });
    expect(totalsOf(undefined, [{ key: 'x', name: 'X', queries: 3 }])).toEqual({ queries: 3 });
  });
  it('sorts the publishers and discards empty ones', () => {
    expect(sortPublishers(pubs).map((p) => p.key)).toEqual(['g', 'a']);
  });
  it('merges domain pages without duplicates', () => {
    const d = (domain: string): TrackingDomain => ({ domain, queries: 1 });
    expect(mergeDomains([d('a'), d('b')], [d('b'), d('c')]).map((x) => x.domain)).toEqual(['a', 'b', 'c']);
  });
  it('effective rule: the local change wins', () => {
    const d: TrackingDomain = { domain: 'x.com', queries: 1, override: 'block' };
    expect(effectiveOverride(d, new Map())).toBe('block');
    expect(effectiveOverride(d, new Map([['x.com', 'allow' as const]]))).toBe('allow');
    expect(effectiveOverride(d, new Map([['x.com', 'default' as const]]))).toBeUndefined();
    expect(effectiveOverride({ domain: 'y.com', queries: 1 }, new Map())).toBeUndefined();
  });
  it('applications of a domain: the most demanding then the rest', () => {
    const s = splitApps([{ package: 'a', count: 1 }, { package: 'b', count: 9 }, { package: 'c', count: 5 }, { package: 'd', count: 2 }], 2);
    expect(s.shown.map((x) => x.package)).toEqual(['b', 'c']);
    expect(s.more).toBe(2);
    expect(splitApps(undefined)).toEqual({ shown: [], more: 0 });
  });
  it('filters applications by name or package', () => {
    const apps: TrackingApp[] = [
      { package: 'com.a', label: 'Alpha', queries: 1 },
      { package: 'com.b', label: 'Beta', queries: 5 },
    ];
    expect(filterApps(apps, '').map((a) => a.package)).toEqual(['com.b', 'com.a']);
    expect(filterApps(apps, 'alp').map((a) => a.package)).toEqual(['com.a']);
    expect(filterApps(apps, 'COM.B').map((a) => a.package)).toEqual(['com.b']);
  });
});

describe('409 essential domain', () => {
  it('takes up the message and the detailed consequences', () => {
    const c = parseConflict({ message: 'Essential domain', body: { error: 'essential', impacts: ['Push notifications', 'Updates'] } });
    expect(c.message).toBe('Essential domain');
    expect(c.impacts).toEqual(['Push notifications', 'Updates']);
  });
  it('reads the collector format: breaks = [{ domain, breaks }]', () => {
    const c = parseConflict({
      message: 'blocking x would break…',
      body: { error: 'essential_domain', breaks: [{ domain: 'mtalk.google.com', breaks: 'push notifications' }, { domain: 'a.example' }] },
    });
    expect(c.impacts).toEqual(['mtalk.google.com: push notifications']);
  });
  it('accepts a string and ignores what is not text', () => {
    expect(parseConflict({ message: 'm', body: { breaks: 'The notifications' } }).impacts).toEqual(['The notifications']);
    expect(parseConflict({ message: 'm', body: { impacts: [1, { a: 1 }] } }).impacts).toEqual([]);
    expect(parseConflict({ message: 'm', body: undefined }).impacts).toEqual([]);
  });
});

describe('actions offered for a domain', () => {
  it('allowed domain: block; with a rule: reset to default', () => {
    expect(availableActions('allowed', undefined)).toEqual(['block']);
    expect(availableActions('allowed', 'block')).toEqual(['default']);
    expect(availableActions('allowed', 'allow')).toEqual(['block', 'default']);
  });
  it('blocked domain: allow', () => {
    expect(availableActions('blocked', undefined)).toEqual(['allow']);
    expect(availableActions('blocked', 'block')).toEqual(['allow', 'default']);
    expect(availableActions('blocked', 'allow')).toEqual(['default']);
  });
  it('mixed domain or without status: both choices', () => {
    expect(availableActions('mixed', undefined)).toEqual(['block', 'allow']);
    expect(availableActions(undefined, undefined)).toEqual(['block', 'allow']);
    expect(availableActions('mixed', 'block')).toEqual(['allow', 'default']);
  });
});

describe('errors and status data', () => {
  it('translates the collector codes', () => {
    for (const code of ['adguard_unavailable', 'adguard_error', 'levels_not_configured']) {
      const m = trackingErrorMessage({ status: 503, code, message: 'raw' });
      expect(m).not.toBe('raw');
    }
    expect(trackingErrorMessage({ status: 409, code: 'corrupt_rules', message: 'block altered' })).toContain('block altered');
    expect(trackingErrorMessage({ status: 500, code: 'other', message: 'raw' })).toBe('raw');
  });
  it('status counts present or not', () => {
    expect(hasStatusData(undefined)).toBe(false);
    expect(hasStatusData({ queries: 5, blocked: 0, allowed: 0 })).toBe(false);
    expect(hasStatusData({ queries: 5, blocked: 1, allowed: 4 })).toBe(true);
  });
});
