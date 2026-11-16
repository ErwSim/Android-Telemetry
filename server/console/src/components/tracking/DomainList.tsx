import { Fragment, useState } from 'react';
import { api } from '../../api/endpoints.ts';
import { ApiError } from '../../api/client.ts';
import type { PagedDomains } from '../../api/usePagedDomains.ts';
import type { TrackingDomain } from '../../api/types.ts';
import { ACTION_LABELS, availableActions, domainStatus, effectiveOverride, overrideLabel, parseConflict, reasonLabel, splitApps, type Conflict, type TrackAction } from '../../lib/tracking.ts';
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
  publisherNames,
  labelOf,
  onOpenApp,
  onNotice,
}: {
  paged: PagedDomains;
  degraded: boolean;
  publisherNames: ReadonlyMap<string, string>;
  labelOf: (pkg: string | undefined) => string | undefined;
  onOpenApp: (pkg: string) => void;
  onNotice: (n: { tone: 'ok' | 'bad' | 'warn'; text: string }) => void;
}) {
  // Règles enregistrées pendant cette visite : elles s'affichent tout de suite, avant que les listes soient relues.
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
            ? `Règle manuelle retirée pour « ${domain} » : retour au comportement des listes.`
            : `« ${domain} » : règle « ${action === 'block' ? 'bloquer' : 'autoriser'} » enregistrée dans AdGuard Home. Elle s'applique aux prochaines requêtes ; les décomptes affichés restent ceux du passé.`,
      });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && action === 'block') {
        setConflict({ domain, action, conflict: parseConflict(e) });
      } else if (e instanceof ApiError && e.status === 503) {
        onNotice({ tone: 'bad', text: `La règle n'a pas été enregistrée. ${e.message}` });
        setConflict(undefined);
      } else {
        onNotice({ tone: 'bad', text: `La règle n'a pas été enregistrée. ${e instanceof ApiError ? e.message : String(e)}` });
        setConflict(undefined);
      }
    } finally {
      setBusy(undefined);
      setForcing(false);
    }
  };

  if (paged.error && paged.domains.length === 0) return <ErrorBox message={paged.error.message} onRetry={paged.reload} />;
  if (paged.loading && paged.domains.length === 0) return <Loading label="Chargement des domaines…" />;
  if (paged.domains.length === 0) return <Empty>Aucun domaine ne correspond à ces filtres sur cette période.</Empty>;

  return (
    <div className={paged.loading ? 'is-refreshing' : undefined}>
      <div className="table-wrap">
        <table className="tbl trk-dom">
          <thead>
            <tr>
              <th scope="col">Domaine</th>
              <th scope="col" className="right">
                Requêtes
              </th>
              {!degraded && <th scope="col">Statut</th>}
              {!degraded && <th scope="col">Motif</th>}
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
            {paged.loadingMore ? 'Chargement…' : 'Charger plus'}
          </button>
        ) : null}
        <span>
          {fmtNumber(paged.domains.length)} domaine{paged.domains.length > 1 ? 's' : ''}
          {paged.hasMore ? '' : ' — fin de la liste'}
        </span>
      </div>

      {conflict && (
        <Dialog
          title="Ce domaine est indispensable au téléphone"
          tone="danger"
          busy={forcing}
          onClose={() => setConflict(undefined)}
          footer={
            <>
              <button type="button" className="btn btn-primary" onClick={() => setConflict(undefined)} disabled={forcing}>
                Ne pas bloquer
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
                {forcing ? 'Blocage…' : 'Bloquer quand même'}
              </button>
            </>
          }
        >
          <p>
            Bloquer <strong className="mono break">{conflict.domain}</strong> casserait des fonctions essentielles :
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
            La règle est réversible (« Remettre par défaut »), mais tant qu'elle est active le téléphone peut perdre ces fonctions sans autre signe visible.
          </p>
        </Dialog>
      )}
    </div>
  );
}

function DomainRow({
  d,
  degraded,
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
        {!degraded && (
          <td className="c-st">
            <Badge tone={st.tone}>{st.label}</Badge>
            {d.blocked !== undefined && d.allowed !== undefined && d.status === 'mixed' && (
              <span className="hint">
                {' '}
                {fmtNumber(d.blocked)} bloquées · {fmtNumber(d.allowed)} autorisées
              </span>
            )}
            {ov && (
              <div>
                <Badge tone="info" title={pendingLocal ? "Règle enregistrée à l'instant : elle s'applique aux prochaines requêtes." : undefined}>
                  {ov}
                </Badge>
              </div>
            )}
          </td>
        )}
        {!degraded && (
          <td className="c-why break">
            <span className="hint">{reason ?? '—'}</span>
          </td>
        )}
        <td className="c-apps break">
          {shown.length === 0 && <span className="muted">—</span>}
          {shown.map((a) => (
            <div key={a.package}>
              <button type="button" className="linkish" onClick={() => onOpenApp(a.package)} title={`${a.package} : voir dans l'onglet Applications`}>
                {labelOf(a.package) ?? a.package}
              </button>{' '}
              <span className="muted">({fmtNumber(a.count)})</span>
            </div>
          ))}
          {more > 0 && (
            <button type="button" className="linkish" onClick={onToggle} aria-expanded={isOpen}>
              + {more} autre{more > 1 ? 's' : ''}
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
                title={degraded ? "Indisponible : AdGuard Home n'est pas joignable" : undefined}
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
            Applications qui demandent <span className="mono">{d.domain}</span> :{' '}
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
