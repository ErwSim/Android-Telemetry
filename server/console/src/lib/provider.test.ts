import { describe, expect, it } from 'vitest';
import { countProviders, providerInfo } from './provider.ts';

describe('location providers', () => {
  it('recognises gps, network, fused and flags those going through Google', () => {
    expect(providerInfo('gps')).toMatchObject({ key: 'gps', google: false });
    expect(providerInfo('network')).toMatchObject({ key: 'network', google: true });
    expect(providerInfo('FUSED')).toMatchObject({ key: 'fused', google: true });
  });
  it('missing or unknown value: kept as is', () => {
    expect(providerInfo(undefined).key).toBe('unknown');
    expect(providerInfo('other').label).toBe('other');
  });
  it('counts per provider', () => {
    const c = countProviders([{ provider: 'gps' }, { provider: 'network' }, { provider: 'gps' }, {}]);
    expect(c.map((x) => [x.key, x.count])).toEqual([
      ['gps', 2],
      ['network', 1],
      ['unknown', 1],
    ]);
  });
});
