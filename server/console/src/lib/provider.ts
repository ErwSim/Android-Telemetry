// Location providers (contract §2 `location.fix.provider`, §10 location modes).

export type ProviderKey = 'gps' | 'network' | 'fused' | 'passive' | 'unknown';

export interface ProviderInfo {
  key: ProviderKey;
  label: string;
  /** short label for the legend */
  short: string;
  /** what this provider implies for privacy */
  note: string;
  /** goes through Google Play Services */
  google: boolean;
}

export function providerInfo(provider: string | undefined): ProviderInfo {
  switch (provider?.toLowerCase()) {
    case 'gps':
      return { key: 'gps', label: 'GPS', short: 'GPS', note: 'Satellites only: nothing goes to Google.', google: false };
    case 'network':
      return {
        key: 'network',
        label: 'Network (Wi-Fi and cell towers)',
        short: 'Network',
        note: 'Location estimated from nearby Wi-Fi networks and cell towers: this provider goes through Google Play Services.',
        google: true,
      };
    case 'fused':
      return {
        key: 'fused',
        label: 'Fused',
        short: 'Fused',
        note: 'Combines GPS, Wi-Fi, cell towers and sensors: this provider is the one of Google Play Services.',
        google: true,
      };
    case 'passive':
      return { key: 'passive', label: 'Passive', short: 'Passive', note: 'Reuses the locations requested by other applications.', google: false };
    default:
      return { key: 'unknown', label: provider ? provider : 'Unknown', short: 'Unknown', note: '', google: false };
  }
}

/** Number of locations per provider, from the most frequent to the rarest. */
export function countProviders(points: { provider?: string | undefined }[]): { key: ProviderKey; label: string; count: number }[] {
  const m = new Map<ProviderKey, { label: string; count: number }>();
  for (const p of points) {
    const i = providerInfo(p.provider);
    const cur = m.get(i.key) ?? { label: i.short, count: 0 };
    cur.count++;
    m.set(i.key, cur);
  }
  return [...m.entries()].map(([key, v]) => ({ key, ...v })).sort((a, b) => b.count - a.count);
}
