import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { TrackingApp } from '../../api/types.ts';
import { blockedPct, domainStatus, filterApps } from '../../lib/tracking.ts';
import { fmtBytes, fmtNumber, fmtPct } from '../../lib/format.ts';
import { AppName } from '../AppName.tsx';
import { Badge, Empty } from '../ui.tsx';
import { SplitBar } from './SplitBar.tsx';

/** Per-application view: what it contacts, blocked or allowed, volumes. One application at a time is expanded. */
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
  // The application opened from the domain list comes first, even beyond the first 40.
  const visible = useMemo(() => {
    const head = rows.slice(0, shown);
    const open = openPkg ? rows.find((a) => a.package === openPkg) : undefined;
    return open && !head.includes(open) ? [open, ...head] : head;
  }, [rows, shown, openPkg]);

  if (apps.length === 0) return <Empty>No application made a DNS query during this period.</Empty>;
  return (
    <>
      <div className="toolbar">
        <label className="filter grow">
          Search
          <input type="search" value={q} onChange={(e) => { setQ(e.target.value); setShown(40); }} placeholder="name or package" />
        </label>
      </div>
      <p className="hint">
        DNS queries per application come from the agent. The blocked / allowed counts and the bytes per application are <strong>estimates</strong>{' '}
        (split in proportion to the DNS queries): they give an order of magnitude, not a measurement.
      </p>
      {rows.length === 0 && <Empty>No matching application.</Empty>}
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
                  <strong>{fmtNumber(a.queries)}</strong> <span className="muted">queries</span>
                </span>
                {showStatus && (
                  <span className="trk-app-split">
                    <SplitBar blocked={a.blocked} allowed={a.allowed} />
                    <span className="muted"> {pct === undefined ? '' : `${fmtPct(pct)} blocked`}</span>
                  </span>
                )}
                <span className="trk-app-bytes muted">
                  ↑ {fmtBytes(a.tx_bytes)} · ↓ {fmtBytes(a.rx_bytes)}
                </span>
              </button>
              {isOpen && (
                <div className="trk-app-body">
                  <h3>Most requested domains</h3>
                  {(a.top_domains ?? []).length === 0 ? (
                    <p className="muted">No detailed domain.</p>
                  ) : (
                    <ul className="findings">
                      {(a.top_domains ?? []).map((d) => {
                        const st = domainStatus(d.status);
                        return (
                          <li key={d.domain}>
                            {showStatus && <Badge tone={st.tone}>{st.label}</Badge>}
                            <span className="f-label mono break">{d.domain}</span>
                            <span className="f-val">
                              {fmtNumber(d.count)} queries ·{' '}
                              <button type="button" className="linkish" onClick={() => onShowDomain(d.domain)}>
                                act in "Domains"
                              </button>
                            </span>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                  <p className="hint">
                    Bytes: the application's volumes over the period (↑ sent, ↓ received), all sites combined.{' '}
                    <Link to={`/network?app=${encodeURIComponent(a.package)}`}>Network detail for this application</Link>
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
            Show more
          </button>
          <span>
            {Math.min(shown, rows.length)} of {rows.length}
          </span>
        </div>
      )}
    </>
  );
}
