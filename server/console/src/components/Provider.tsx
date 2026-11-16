import { providerInfo, type ProviderKey } from '../lib/provider.ts';

/** Provider dot: filled disc (GPS), hollow ring (network), purple disc (fused): not colour alone. */
export function ProviderDot({ provider }: { provider: string | undefined }) {
  const i = providerInfo(provider);
  return <span className={`prov-dot prov-${i.key}`} aria-hidden="true" />;
}

export function ProviderLegend({ keys = ['gps', 'network', 'fused'] }: { keys?: ProviderKey[] }) {
  return (
    <ul className="prov-legend" aria-label="Location providers">
      {keys.map((k) => (
        <li key={k}>
          <ProviderDot provider={k} />
          {providerInfo(k).label}
        </li>
      ))}
    </ul>
  );
}
