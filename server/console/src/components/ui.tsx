import { useId, type ReactNode } from 'react';
import type { ApiState } from '../api/useApi.ts';
import type { Status } from '../lib/posture.ts';
import { sevLabel } from '../lib/events.ts';
import { VENDOR_LABELS, type Vendor } from '../lib/vendors.ts';

export function Card({
  title,
  actions,
  children,
  className = '',
  id,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  id?: string;
}) {
  const hid = useId();
  return (
    <section className={`card ${className}`} aria-labelledby={title ? hid : undefined} id={id}>
      {(title || actions) && (
        <header className="card-head">
          {title && (
            <h2 id={hid} className="card-title">
              {title}
            </h2>
          )}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}

export function Loading({ label = 'Chargement…' }: { label?: string }) {
  return (
    <div className="state state-loading" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function Empty({ children = 'Aucune donnée sur cette période.' }: { children?: ReactNode }) {
  return <div className="state state-empty">{children}</div>;
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="state state-error" role="alert">
      <strong>Erreur.</strong> {message}
      {onRetry && (
        <button type="button" className="btn btn-sm" onClick={onRetry}>
          Réessayer
        </button>
      )}
    </div>
  );
}

/** Gère les trois états d'une requête ; `children` ne reçoit que des données présentes. */
export function Async<T>({
  state,
  children,
  isEmpty,
  empty,
  loadingLabel,
}: {
  state: ApiState<T>;
  children: (data: T) => ReactNode;
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
  loadingLabel?: string;
}) {
  if (state.error) return <ErrorBox message={state.error.message} onRetry={state.reload} />;
  if (state.data === undefined) return state.loading ? <Loading label={loadingLabel ?? 'Chargement…'} /> : null;
  if (isEmpty?.(state.data)) return <Empty>{empty}</Empty>;
  return (
    <div className={state.loading ? 'is-refreshing' : undefined} aria-busy={state.loading}>
      {children(state.data)}
    </div>
  );
}

export type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'info';

export function Badge({ tone = 'neutral', children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge badge-${tone}`} title={title}>
      {children}
    </span>
  );
}

const SEV_TONE: Tone[] = ['neutral', 'info', 'warn', 'bad'];
export function SevBadge({ sev }: { sev: number }) {
  const i = Math.max(0, Math.min(3, Math.trunc(sev)));
  return (
    <Badge tone={SEV_TONE[i] ?? 'neutral'} title={`Sévérité ${i} : ${sevLabel(i)}`}>
      {i} · {sevLabel(i)}
    </Badge>
  );
}

export function LevelBadge({ level }: { level: number }) {
  const tone: Tone = level >= 12 ? 'bad' : level >= 8 ? 'warn' : level >= 5 ? 'info' : 'neutral';
  return <Badge tone={tone}>Niveau {level}</Badge>;
}

export function VendorBadge({ vendor }: { vendor: Vendor }) {
  if (vendor === 'other') return null;
  return <span className={`vendor vendor-${vendor}`}>{VENDOR_LABELS[vendor]}</span>;
}

const STATUS_TEXT: Record<Status, string> = { ok: 'OK', warn: 'Attention', bad: 'Alerte', unknown: 'Info' };
export function StatusPill({ status }: { status: Status }) {
  const tone: Tone = status === 'ok' ? 'ok' : status === 'warn' ? 'warn' : status === 'bad' ? 'bad' : 'neutral';
  return <Badge tone={tone}>{STATUS_TEXT[status]}</Badge>;
}

export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: Tone }) {
  return (
    <div className={`stat${tone ? ` stat-${tone}` : ''}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export function Tabs<K extends string>({
  tabs,
  value,
  onChange,
  label,
}: {
  tabs: { key: K; label: string }[];
  value: K;
  onChange: (k: K) => void;
  label: string;
}) {
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t) => (
        <button
          key={t.key}
          type="button"
          role="tab"
          aria-selected={value === t.key}
          className={`tab${value === t.key ? ' is-active' : ''}`}
          onClick={() => onChange(t.key)}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

/** Barre horizontale proportionnelle (classements). */
export function Bar({ value, max, tone }: { value: number; max: number; tone?: Vendor }) {
  const pct = max > 0 ? Math.max(2, Math.min(100, (value / max) * 100)) : 0;
  return (
    <span className="bar" aria-hidden="true">
      <span className={`bar-fill${tone && tone !== 'other' ? ` bar-${tone}` : ''}`} style={{ width: `${pct}%` }} />
    </span>
  );
}

export function KV({ items }: { items: { k: string; v: ReactNode }[] }) {
  return (
    <dl className="kv">
      {items.map((it) => (
        <div key={it.k} className="kv-row">
          <dt>{it.k}</dt>
          <dd>{it.v}</dd>
        </div>
      ))}
    </dl>
  );
}
