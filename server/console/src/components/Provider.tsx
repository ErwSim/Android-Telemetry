import { providerInfo, type ProviderKey } from '../lib/provider.ts';

/** Pastille du fournisseur : disque plein (GPS), anneau creux (réseau), disque violet (fusionné) : pas que la couleur. */
export function ProviderDot({ provider }: { provider: string | undefined }) {
  const i = providerInfo(provider);
  return <span className={`prov-dot prov-${i.key}`} aria-hidden="true" />;
}

export function ProviderLegend({ keys = ['gps', 'network', 'fused'] }: { keys?: ProviderKey[] }) {
  return (
    <ul className="prov-legend" aria-label="Fournisseurs de position">
      {keys.map((k) => (
        <li key={k}>
          <ProviderDot provider={k} />
          {providerInfo(k).label}
        </li>
      ))}
    </ul>
  );
}
