// Fournisseurs de position (contrat §2 `location.fix.provider`, §10 modes de localisation).

export type ProviderKey = 'gps' | 'network' | 'fused' | 'passive' | 'unknown';

export interface ProviderInfo {
  key: ProviderKey;
  label: string;
  /** libellé court pour la légende */
  short: string;
  /** ce que ce fournisseur implique pour la vie privée */
  note: string;
  /** passe par les Services Google Play */
  google: boolean;
}

export function providerInfo(provider: string | undefined): ProviderInfo {
  switch (provider?.toLowerCase()) {
    case 'gps':
      return { key: 'gps', label: 'GPS', short: 'GPS', note: 'Satellites seuls : rien ne part chez Google.', google: false };
    case 'network':
      return {
        key: 'network',
        label: 'Réseau (Wi-Fi et antennes)',
        short: 'Réseau',
        note: 'Position estimée d’après les Wi-Fi et antennes voisins : ce fournisseur passe par les Services Google Play.',
        google: true,
      };
    case 'fused':
      return {
        key: 'fused',
        label: 'Fusionné',
        short: 'Fusionné',
        note: 'Combine GPS, Wi-Fi, antennes et capteurs : ce fournisseur est celui des Services Google Play.',
        google: true,
      };
    case 'passive':
      return { key: 'passive', label: 'Passif', short: 'Passif', note: 'Reprend les positions demandées par d’autres applications.', google: false };
    default:
      return { key: 'unknown', label: provider ? provider : 'Inconnu', short: 'Inconnu', note: '', google: false };
  }
}

/** Nombre de positions par fournisseur, du plus fréquent au plus rare. */
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
