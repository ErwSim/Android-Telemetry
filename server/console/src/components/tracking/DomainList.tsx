import { Fragment, useState } from 'react';
import { api } from '../../api/endpoints.ts';
import { ApiError } from '../../api/client.ts';
import type { PagedDomains } from '../../api/usePagedDomains.ts';
import type { TrackingDomain } from '../../api/types.ts';
import { ACTION_LABELS, availableActions, domainStatus, effectiveOverride, overrideLabel, parseConflict, reasonLabel, splitApps, trackingErrorMessage, type Conflict, type TrackAction } from '../../lib/tracking.ts';
import { fmtNumber } from '../../lib/format.ts';
import { cleanText } from '../../lib/text.ts';
import { Dialog } from '../Dialog.tsx';
import { Badge, Empty, ErrorBox, Loading } from '../ui.tsx';
import { PublisherChip } from './SplitBar.tsx';

interface Pending {
  domain: string;
  action: TrackAction;
  conflict?: Conflict;
}

export function DomainList({
  paged,
  degraded,
  showStatus,
  publisherNames,
  labelOf,
  onOpenApp,
  onNotice,
}: {
  paged: PagedDomains;
  /** AdGuard unreachable: actions disabled */
  degraded: boolean;
  /** blocked/allowed counts exist: status and reason columns */
  showStatus: boolean;
  publisherNames: ReadonlyMap<string, string>;
  labelOf: (pkg: string | undefined) => string | undefined;
  onOpenApp: (pkg: string) => void;
  onNotice: (n: { tone: 'ok' | 'bad' | 'warn'; text: string }) => void;
}) {
  // Rules saved during this visit: they show up immediately, before the lists are read again.
  const [local, setLocal] = useState<ReadonlyMap<string, TrackAction>>(new Map());
  const [busy, setBusy] = useState<string | undefined>();
  const [conflict, setConflict] = useState<Pending | undefined>();
  const [forcing, setForcing] = useState(false);
  const [open, setOpen] = useState<string | null>(null);

  const run = async (domain: string, action: TrackAction, force = false) => {
    setBusy(domain);
    try {
      await api.trackingOverride({ domain, action, ...(force ? { force: true } : {}) });
      setLocal((m) => new Map(m).set(domain, action));
      setConflict(undefined);
      onNotice({
        tone: 'ok',
        text:
          action === 'default'
            ? `Manual rule removed for "${domain}": back to the lists' behaviour.`
            : `"${domain}": rule "${action === 'block' ? 'block' : 'allow'}" saved in AdGuard Home. It applies to the next queries; the counts displayed remain those of the past.`,
      });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.code === 'essential_domain' && action === 'block' && !force) {
        setConflict({ domain, action, conflict: parseConflict(e) });
      } else {
        onNotice({ tone: 'bad', text: `The rule was not saved. ${e instanceof ApiError ? trackingErrorMessage(e) : String(e)}` });
        setConflict(undefined);
      }
    } finally {
      setBusy(undefined);
      setForcing(false);
    }
  };

  if (paged.error && paged.domains.length === 0) return <ErrorBox message={paged.error.message} onRetry={paged.reload} />;
  if (paged.loading && paged.domains.length === 0) return <Loading label="Loading domains…" />;
  if (paged.domains.length === 0) return <Empty>No domain matches these filters for this period.</Empty>;

  return (
    <div className={paged.loading ? 'is-refreshing' : undefined}>
      <div className="table-wrap">
        <table className="tbl trk-dom">
          <thead>
            <tr>
              <th scope="col">Domain</th>
              <th scope="col" className="right">
                Queries
              </th>
              {showStatus && <th scope="col">Status</th>}
              {showStatus && <th scope="col">Reason</th>}
              <th scope="col">Applications</th>
              <th scope="col">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {paged.domains.map((d) => (
              <DomainRow
                key={d.domain}
                d={d}
                degraded={degraded}
                showStatus={showStatus}
                override={effectiveOverride(d, local)}
                pendingLocal={local.has(d.domain)}
                busy={busy === d.domain}
                publisherName={d.publisher ? publisherNames.get(d.publisher) : undefined}
                labelOf={labelOf}
                isOpen={open === d.domain}
                onToggle={() => setOpen(open === d.domain ? null : d.domain)}
                onOpenApp={onOpenApp}
                onAction={(a) => void run(d.domain, a)}
              />
            ))}
          </tbody>
        </table>
      </div>
      {paged.error && <ErrorBox message={paged.error.message} onRetry={paged.loadMore} />}
      <div className="pager">
        {paged.hasMore ? (
          <button type="button" className="btn" onClick={paged.loadMore} disabled={paged.loadingMore}>
            {paged.loadingMore ? 'Loading…' : 'Load more'}
          </button>
        ) : null}
        <span>
          {fmtNumber(paged.domains.length)} domain{paged.domains.length > 1 ? 's' : ''}
          {paged.hasMore ? '' : ' — end of the list'}
        </span>
      </div>

      {conflict && (
        <Dialog
          title="This domain is essential to the phone"
          tone="danger"
          busy={forcing}
          onClose={() => setConflict(undefined)}
          footer={
            <>
              <button type="button" className="btn btn-primary" onClick={() => setConflict(undefined)} disabled={forcing}>
                Do not block
              </button>
              <button
                type="button"
                className="btn btn-danger"
                disabled={forcing}
                onClick={() => {
                  setForcing(true);
                  void run(conflict.domain, 'block', true);
                }}
              >
                {forcing ? 'Blocking…' : 'Block anyway'}
              </button>
            </>
          }
        >
          <p>
            Blocking <strong className="mono break">{conflict.domain}</strong> would break essential functions:
          </p>
          <div className="callout callout-bad">
            <p>{cleanText(conflict.conflict?.message, 400)}</p>
            {conflict.conflict && conflict.conflict.impacts.length > 0 && (
              <ul>
                {conflict.conflict.impacts.map((i) => (
                  <li key={i}>{cleanText(i, 400)}</li>
                ))}
              </ul>
            )}
          </div>
          <p className="muted">
            The rule is reversible ("Reset to default"), but as long as it is active the phone may lose these functions with no other visible sign.
          </p>
        </Dialog>
      )}
    </div>
  );
}

function DomainRow({
  d,
  degraded,
  showStatus,
  override,
  pendingLocal,
  busy,
  publisherName,
  labelOf,
  isOpen,
  onToggle,
  onOpenApp,
  onAction,
}: {
  d: TrackingDomain;
  degraded: boolean;
  showStatus: boolean;
  override: 'block' | 'allow' | undefined;
  pendingLocal: boolean;
  busy: boolean;
  publisherName: string | undefined;
  labelOf: (pkg: string | undefined) => string | undefined;
  isOpen: boolean;
  onToggle: () => void;
  onOpenApp: (pkg: string) => void;
  onAction: (a: TrackAction) => void;
}) {
  const st = domainStatus(d.status);
  const reason = reasonLabel(d.reason);
  const { shown, more } = splitApps(d.apps, 2);
  const actions = availableActions(d.status, override);
  const ov = overrideLabel(override);
  return (
    <Fragment>
      <tr>
        <td className="c-dom break">
          <span className="mono">{d.domain}</span> <PublisherChip pkey={d.publisher} name={publisherName} />
        </td>
        <td className="right c-q">{fmtNumber(d.queries)}</td>
        {showStatus && (
          <td className="c-st">
            <Badge tone={st.tone}>{st.label}</Badge>
            {d.blocked !== undefined && d.allowed !== undefined && d.status === 'mixed' && (
              <span className="hint">
                {' '}
                {fmtNumber(d.blocked)} blocked · {fmtNumber(d.allowed)} allowed
              </span>
            )}
            {ov && (
              <div>
                <Badge tone="info" title={pendingLocal ? 'Rule saved just now: it applies to the next queries.' : undefined}>
                  {ov}
                </Badge>
              </div>
            )}
          </td>
        )}
        {showStatus && (
          <td className="c-why break">
            <span className="hint">{reason ?? '—'}</span>
          </td>
        )}
        <td className="c-apps break">
          {shown.length === 0 && <span className="muted">—</span>}
          {shown.map((a) => (
            <div key={a.package}>
              <button type="button" className="linkish" onClick={() => onOpenApp(a.package)} title={`${a.package}: see in the Applications tab`}>
                {labelOf(a.package) ?? a.package}
              </button>{' '}
              <span className="muted">({fmtNumber(a.count)})</span>
            </div>
          ))}
          {more > 0 && (
            <button type="button" className="linkish" onClick={onToggle} aria-expanded={isOpen}>
              + {more} other{more > 1 ? 's' : ''}
            </button>
          )}
        </td>
        <td className="c-act">
          <div className="act-group">
            {actions.map((a) => (
              <button
                key={a}
                type="button"
                className={`btn btn-sm${a === 'block' ? ' btn-block' : ''}`}
                disabled={degraded || busy}
                title={degraded ? 'Unavailable: AdGuard Home is not reachable' : undefined}
                onClick={() => onAction(a)}
                aria-label={`${ACTION_LABELS[a]} ${d.domain}`}
              >
                {ACTION_LABELS[a]}
              </button>
            ))}
          </div>
        </td>
      </tr>
      {isOpen && more > 0 && (
        <tr>
          <td colSpan={6} className="detail-cell">
            Applications requesting <span className="mono">{d.domain}</span>:{' '}
            {[...(d.apps ?? [])]
              .sort((a, b) => b.count - a.count)
              .map((a, i) => (
                <Fragment key={a.package}>
                  {i > 0 && ', '}
                  <button type="button" className="linkish" onClick={() => onOpenApp(a.package)}>
                    {labelOf(a.package) ?? a.package}
                  </button>{' '}
                  ({fmtNumber(a.count)})
                </Fragment>
              ))}
          </td>
        </tr>
      )}
    </Fragment>
  );
}
