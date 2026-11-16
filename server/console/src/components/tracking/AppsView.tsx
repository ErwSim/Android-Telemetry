import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { TrackingApp } from '../../api/types.ts';
import { blockedPct, domainStatus, filterApps } from '../../lib/tracking.ts';
import { fmtBytes, fmtNumber, fmtPct } from '../../lib/format.ts';
import { AppName } from '../AppName.tsx';
import { Badge, Empty } from '../ui.tsx';
import { SplitBar } from './SplitBar.tsx';

/** Vue par application : ce qu'elle contacte, bloqué ou autorisé, volumes. Une application à la fois est dépliée. */
export function AppsView({
  apps,
  showStatus,
  openPkg,
  onOpen,
  onShowDomain,
}: {
  apps: TrackingApp[];
  showStatus: boolean;
  openPkg: string | undefined;
  onOpen: (pkg: string | undefined) => void;
  onShowDomain: (domain: string) => void;
}) {
  const [q, setQ] = useState('');
  const [shown, setShown] = useState(40);
  const rows = useMemo(() => filterApps(apps, q), [apps, q]);
  // L'application ouverte depuis la liste des domaines passe en tête, même au-delà des 40 premières.
  const visible = useMemo(() => {
    const head = rows.slice(0, shown);
    const open = openPkg ? rows.find((a) => a.package === openPkg) : undefined;
    return open && !head.includes(open) ? [open, ...head] : head;
  }, [rows, shown, openPkg]);

  if (apps.length === 0) return <Empty>Aucune application n'a émis de requête DNS sur cette période.</Empty>;
  return (
    <>
      <div className="toolbar">
        <label className="filter grow">
          Recherche
          <input type="search" value={q} onChange={(e) => { setQ(e.target.value); setShown(40); }} placeholder="nom ou paquet" />
        </label>
      </div>
      <p className="hint">
        Les requêtes DNS par application viennent de l'agent. Les décomptes bloqué / autorisé et les octets par application sont des <strong>estimations</strong>{' '}
        (répartition au prorata des requêtes DNS) : ils indiquent un ordre de grandeur, pas une mesure.
      </p>
      {rows.length === 0 && <Empty>Aucune application ne correspond.</Empty>}
      <ul className="trk-apps">
        {visible.map((a) => {
          const isOpen = openPkg === a.package;
          const pct = blockedPct(a);
          return (
            <li key={a.package} className={isOpen ? 'is-open' : undefined} id={`app-${a.package}`}>
              <button type="button" className="trk-app-head" aria-expanded={isOpen} onClick={() => onOpen(isOpen ? undefined : a.package)}>
                <span className="trk-app-name">
                  <span aria-hidden="true">{isOpen ? '▾' : '▸'}</span> <AppName pkg={a.package} label={a.label} />
                </span>
                <span className="trk-app-num">
                  <strong>{fmtNumber(a.queries)}</strong> <span className="muted">requêtes</span>
                </span>
                {showStatus && (
                  <span className="trk-app-split">
                    <SplitBar blocked={a.blocked} allowed={a.allowed} />
                    <span className="muted"> {pct === undefined ? '' : `${fmtPct(pct)} bloquées`}</span>
                  </span>
                )}
                <span className="trk-app-bytes muted">
                  ↑ {fmtBytes(a.tx_bytes)} · ↓ {fmtBytes(a.rx_bytes)}
                </span>
              </button>
              {isOpen && (
                <div className="trk-app-body">
                  <h3>Domaines les plus demandés</h3>
                  {(a.top_domains ?? []).length === 0 ? (
                    <p className="muted">Aucun domaine détaillé.</p>
                  ) : (
                    <ul className="findings">
                      {(a.top_domains ?? []).map((d) => {
                        const st = domainStatus(d.status);
                        return (
                          <li key={d.domain}>
                            {showStatus && <Badge tone={st.tone}>{st.label}</Badge>}
                            <span className="f-label mono break">{d.domain}</span>
                            <span className="f-val">
                              {fmtNumber(d.count)} requêtes ·{' '}
                              <button type="button" className="linkish" onClick={() => onShowDomain(d.domain)}>
                                agir dans « Domaines »
                              </button>
                            </span>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                  <p className="hint">
                    Octets : volumes de l'application sur la période (↑ envoyés, ↓ reçus), tous sites confondus.{' '}
                    <Link to={`/reseau?app=${encodeURIComponent(a.package)}`}>Détail réseau de cette application</Link>
                  </p>
                </div>
              )}
            </li>
          );
        })}
      </ul>
      {rows.length > shown && (
        <div className="pager">
          <button type="button" className="btn" onClick={() => setShown((n) => n + 40)}>
            Afficher plus
          </button>
          <span>
            {Math.min(shown, rows.length)} sur {rows.length}
          </span>
        </div>
      )}
    </>
  );
}
