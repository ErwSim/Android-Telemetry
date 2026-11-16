import { describe, expect, it } from 'vitest';
import { countProviders, providerInfo } from './provider.ts';

describe('fournisseurs de position', () => {
  it('reconnaît gps, network, fused et signale ceux qui passent par Google', () => {
    expect(providerInfo('gps')).toMatchObject({ key: 'gps', google: false });
    expect(providerInfo('network')).toMatchObject({ key: 'network', google: true });
    expect(providerInfo('FUSED')).toMatchObject({ key: 'fused', google: true });
  });
  it('valeur absente ou inconnue : conservée telle quelle', () => {
    expect(providerInfo(undefined).key).toBe('unknown');
    expect(providerInfo('autre').label).toBe('autre');
  });
  it('compte par fournisseur', () => {
    const c = countProviders([{ provider: 'gps' }, { provider: 'network' }, { provider: 'gps' }, {}]);
    expect(c.map((x) => [x.key, x.count])).toEqual([
      ['gps', 2],
      ['network', 1],
      ['unknown', 1],
    ]);
  });
});
