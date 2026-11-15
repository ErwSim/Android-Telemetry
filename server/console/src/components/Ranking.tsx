import type { TopItem } from '../api/types.ts';
import { fmtBytes, fmtNumber } from '../lib/format.ts';
import { classifyHost, classifyPackage } from '../lib/vendors.ts';
import { Bar, VendorBadge } from './ui.tsx';

export function Ranking({
  items,
  kind,
  metric = 'count',
  labelOf,
  onSelect,
  selected,
  limit = 15,
  emptyText = 'Aucune donnée.',
}: {
  items: TopItem[];
  kind: 'host' | 'package' | 'plain';
  metric?: 'count' | 'bytes';
  labelOf?: (key: string) => string | undefined;
  onSelect?: (key: string) => void;
  selected?: string | undefined;
  limit?: number;
  emptyText?: string;
}) {
  const sorted = [...items].sort((a, b) => (metric === 'bytes' ? (b.bytes ?? 0) - (a.bytes ?? 0) : b.count - a.count)).slice(0, limit);
  if (sorted.length === 0) return <p className="muted">{emptyText}</p>;
  const val = (it: TopItem) => (metric === 'bytes' ? (it.bytes ?? 0) : it.count);
  const max = Math.max(...sorted.map(val), 1);
  return (
    <ol className="rank">
      {sorted.map((it) => {
        const vendor = kind === 'host' ? classifyHost(it.key) : kind === 'package' ? classifyPackage(it.key) : 'other';
        const label = labelOf?.(it.key);
        const name = (
          <>
            {label ? (
              <>
                <strong>{label}</strong> <span className="muted mono break">{it.key}</span>
              </>
            ) : (
              <span className={kind === 'plain' ? 'mono break' : 'break'}>{it.key}</span>
            )}
            <VendorBadge vendor={vendor} />
          </>
        );
        return (
          <li key={it.key}>
            <span className="rank-name">
              {onSelect ? (
                <button type="button" className={`linkish${selected === it.key ? ' is-sel' : ''}`} onClick={() => onSelect(it.key)} aria-pressed={selected === it.key}>
                  {name}
                </button>
              ) : (
                name
              )}
            </span>
            <span className="rank-val">
              {metric === 'bytes' ? fmtBytes(it.bytes) : fmtNumber(it.count)}
              {metric === 'count' && it.bytes !== undefined ? <span className="muted"> · {fmtBytes(it.bytes)}</span> : null}
            </span>
            <Bar value={val(it)} max={max} tone={vendor} />
          </li>
        );
      })}
    </ol>
  );
}
