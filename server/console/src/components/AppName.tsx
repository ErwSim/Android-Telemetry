import { classifyPackage } from '../lib/vendors.ts';
import { VendorBadge } from './ui.tsx';

export function AppName({ pkg, label, block = false }: { pkg: string; label?: string | undefined; block?: boolean }) {
  return (
    <span className={`app-name${block ? ' block' : ''}`}>
      {label ? <strong>{label}</strong> : null}
      {label ? <br /> : null}
      <span className={label ? 'muted mono break' : 'mono break'}>{pkg}</span>
      <VendorBadge vendor={classifyPackage(pkg)} />
    </span>
  );
}
