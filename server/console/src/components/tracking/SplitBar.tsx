import { fmtNumber, fmtPct } from '../../lib/format.ts';

/** Barre bloquées / autorisées. Le texte porte l'information (la couleur seule ne suffit pas). */
export function SplitBar({ blocked, allowed }: { blocked: number | undefined; allowed: number | undefined }) {
  if (blocked === undefined && allowed === undefined) return <span className="muted">—</span>;
  const b = blocked ?? 0;
  const a = allowed ?? 0;
  const total = b + a;
  const pb = total > 0 ? (b / total) * 100 : 0;
  const label = `${fmtNumber(b)} bloquées (${fmtPct(pb)}), ${fmtNumber(a)} autorisées`;
  return (
    <span className="split" role="img" aria-label={label} title={label}>
      <span className="split-blocked" style={{ width: `${pb}%` }} />
      <span className="split-allowed" style={{ width: `${100 - pb}%` }} />
    </span>
  );
}

export function PublisherChip({ pkey, name }: { pkey: string | undefined; name: string | undefined }) {
  if (!pkey || pkey === 'other') return name ? <span className="muted">{name}</span> : null;
  const cls = pkey === 'google' || pkey === 'samsung' ? `vendor vendor-${pkey}` : 'badge badge-neutral';
  return <span className={cls}>{name ?? pkey}</span>;
}
