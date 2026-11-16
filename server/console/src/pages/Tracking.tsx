import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { usePagedDomains } from '../api/usePagedDomains.ts';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Async, Card, Empty, Stat, Tabs } from '../components/ui.tsx';
import { AppsView } from '../components/tracking/AppsView.tsx';
import { DomainList } from '../components/tracking/DomainList.tsx';
import { LevelCard } from '../components/tracking/LevelCard.tsx';
import { PublisherTable } from '../components/tracking/PublisherTable.tsx';
import { fmtNumber, fmtPct } from '../lib/format.ts';
import { periodRange } from '../lib/period.ts';
import { blockedPct, hasStatusData, totalsOf } from '../lib/tracking.ts';
import { useAppLabels } from '../state/appLabels.ts';
import { useDevice } from '../state/device.tsx';

type Tab = 'domains' | 'apps';
type StatusFilter = 'all' | 'blocked' | 'allowed';

function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => {
    const t = window.setTimeout(() => setD(v), ms);
    return () => window.clearTimeout(t);
  }, [v, ms]);
  return d;
}

interface Notice {
  tone: 'ok' | 'bad' | 'warn';
  text: string;
}

export default function Tracking() {
  const { deviceId } = useDevice();
  const [sp] = useSearchParams();
  const ctl = usePeriod((['24h', '7d', '30d'] as const).find((k) => k === sp.get('period')) ?? '24h');
  const range = periodRange(ctl.period);
  const labelOf = useAppLabels();
  // Links from detections and application detail pages: `?q=<domain>` or `?app=<package>`, `&period=7d`.
  const [tab, setTab] = useState<Tab>(sp.get('app') ? 'apps' : 'domains');
  const [publisher, setPublisher] = useState<string | undefined>();
  const [status, setStatus] = useState<StatusFilter>('all');
  const [qInput, setQInput] = useState(sp.get('q') ?? '');
  const q = useDebounced(qInput, 400);
  const [openApp, setOpenApp] = useState<string | undefined>(sp.get('app') || undefined);
  const [notice, setNotice] = useState<Notice | undefined>();

  const summary = useApi(deviceId ? `trk-sum:${deviceId}:${range.from}:${range.to}` : null, (s) => api.trackingSummary({ device_id: deviceId, ...range }, s));
  const apps = useApi(deviceId && tab === 'apps' ? `trk-apps:${deviceId}:${range.from}:${range.to}:${publisher ?? ''}` : null, (s) =>
    api.trackingApps({ device_id: deviceId, ...range, ...(publisher ? { publisher } : {}) }, s),
  );

  const degraded = summary.data ? !summary.data.adguard : false;
  // Blocked/allowed counts exist (even if AdGuard is momentarily unreachable: the stored aggregates are still served).
  const showStatus = summary.data ? hasStatusData(totalsOf(summary.data.totals, summary.data.publishers)) : true;
  // Without status counts, the blocked / allowed filter is ignored.
  const effStatus = showStatus ? status : 'all';
  const haveSummary = !!summary.data;
  const domParams = useMemo(
    () =>
      deviceId && haveSummary
        ? { device_id: deviceId, ...range, publisher, status: effStatus === 'all' ? undefined : effStatus, q: q.trim() || undefined }
        : null,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [deviceId, haveSummary, range.from, range.to, publisher, effStatus, q],
  );
  const domains = usePagedDomains(domParams, 50);

  const publisherNames = useMemo(() => new Map((summary.data?.publishers ?? []).map((p) => [p.key, p.name])), [summary.data]);

  const showApp = (pkg: string) => {
    setOpenApp(pkg);
    setTab('apps');
  };
  const showDomain = (domain: string) => {
    setQInput(domain);
    setStatus('all');
    setTab('domains');
  };

  useEffect(() => {
    if (tab === 'apps' && openApp) document.getElementById(`app-${openApp}`)?.scrollIntoView?.({ block: 'nearest' });
  }, [tab, openApp, apps.data]);

  return (
    <>
      <div className="page-head">
        <h1>Tracking</h1>
        <span className="muted">What is blocked and what goes through to Google, Samsung and the others</span>
      </div>

      <div className="callout callout-info honest" role="note">
        <p>
          <strong>What this page shows, and what it does not show.</strong> Watchpost sees <em>who</em> the phone talks to (the domain names requested),{' '}
          <em>how many times</em> and <em>from which application</em>. It does <strong>not see the content</strong> of the exchanges: it is encrypted (TLS). "Allowed"
          means that the query was not blocked, not that we know what was sent; "blocked" means that the name was not resolved, so nothing
          went to that domain. An application can also bypass the phone's DNS.
        </p>
      </div>

      {degraded && (
        <div className="state state-warn" role="alert">
          <div>
            <strong>Degraded mode: AdGuard Home is not reachable or not configured on this collector.</strong>{' '}
            {showStatus
              ? 'The blocked / allowed counts displayed are those recorded before the outage; recent queries are not included.'
              : 'The view is built only from the DNS queries recorded by the phone agent (Device Owner): we see who asks for what, but not whether the query was blocked.'}{' '}
            The Block and Allow buttons and the blocking level choice are disabled until AdGuard Home is restored.
          </div>
        </div>
      )}

      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
        <button type="button" className="btn" onClick={() => { ctl.refresh(); summary.reload(); domains.reload(); apps.reload(); }}>
          Refresh
        </button>
        <span className="hint">
          Traffic details (volumes, destinations, timeline) are on the <Link to="/network">Network</Link> page.
        </span>
      </div>

      {summary.error?.status === 404 ? (
        <Empty>This collector does not offer the "tracking" view yet (contract §9). Update it to use it.</Empty>
      ) : (
        <>
          <div className="grid grid-start">
            <Card title="Summary by publisher" className="span-12">
              <Async state={summary} isEmpty={(s) => s.publishers.length === 0} empty="No DNS queries for this period (the agent must be Device Owner, or AdGuard Home must log).">
                {(s) => {
                  const totals = totalsOf(s.totals, s.publishers);
                  const pct = blockedPct(totals);
                  return (
                    <>
                      <div className="stats trk-stats">
                        <Stat label="DNS queries" value={fmtNumber(totals.queries)} />
                        {showStatus && <Stat label="Blocked" value={fmtNumber(totals.blocked)} sub={pct === undefined ? undefined : fmtPct(pct, 1)} tone="ok" />}
                        {showStatus && <Stat label="Allowed" value={fmtNumber(totals.allowed)} sub={pct === undefined ? undefined : fmtPct(100 - pct, 1)} />}
                      </div>
                      <PublisherTable publishers={s.publishers} totals={totals} showStatus={showStatus} selected={publisher} onSelect={setPublisher} />
                      <p className="hint">
                        Click a publisher to filter the list of domains and applications. Bytes per publisher are <strong>estimates</strong>: each application's
                        volume is split between publishers in proportion to its DNS queries.
                      </p>
                    </>
                  );
                }}
              </Async>
            </Card>
            <Card title="Blocking level" className="span-12">
              <Async state={summary}>{(s) => <LevelCard summary={s} onChanged={() => { setNotice({ tone: 'ok', text: 'Blocking level changed: it applies to the next queries.' }); summary.reload(); domains.reload(); }} />}</Async>
            </Card>
          </div>

          {notice && (
            <div className={`state ${notice.tone === 'ok' ? 'state-ok' : notice.tone === 'warn' ? 'state-warn' : 'state-error'}`} role="status" aria-live="polite">
              {notice.text}
            </div>
          )}

          <Tabs
            label="Tracking views"
            value={tab}
            onChange={setTab}
            tabs={[
              { key: 'domains', label: 'Domains' },
              { key: 'apps', label: 'Applications' },
            ]}
          />

          {publisher && (
            <p className="hint">
              Filter: <strong>{publisherNames.get(publisher) ?? publisher}</strong>{' '}
              <button type="button" className="linkish" onClick={() => setPublisher(undefined)}>
                remove the filter
              </button>
            </p>
          )}

          {tab === 'domains' && (
            <Card className="events-card">
              <div className="toolbar trk-filters">
                <label className="filter">
                  Publisher
                  <select value={publisher ?? ''} onChange={(e) => setPublisher(e.target.value || undefined)}>
                    <option value="">All</option>
                    {(summary.data?.publishers ?? []).map((p) => (
                      <option key={p.key} value={p.key}>
                        {p.name}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="filter">
                  <span id="trk-status">Status</span>
                  <div className="seg" role="group" aria-labelledby="trk-status">
                    {(
                      [
                        ['all', 'All'],
                        ['blocked', 'Blocked'],
                        ['allowed', 'Allowed'],
                      ] as [StatusFilter, string][]
                    ).map(([k, label]) => (
                      <button
                        key={k}
                        type="button"
                        className={`seg-btn${effStatus === k ? ' is-active' : ''}`}
                        aria-pressed={effStatus === k}
                        disabled={!showStatus && k !== 'all'}
                        title={!showStatus && k !== 'all' ? 'Unavailable: no blocked / allowed count' : undefined}
                        onClick={() => setStatus(k)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
                <label className="filter grow">
                  Domain search
                  <input type="search" value={qInput} onChange={(e) => setQInput(e.target.value)} placeholder="e.g. doubleclick, samsungdm…" spellCheck={false} />
                </label>
              </div>
              <div className="flush">
                <DomainList paged={domains} degraded={degraded} showStatus={showStatus} publisherNames={publisherNames} labelOf={labelOf} onOpenApp={showApp} onNotice={setNotice} />
              </div>
            </Card>
          )}

          {tab === 'apps' && (
            <Card>
              <Async state={apps} isEmpty={(d) => d.apps.length === 0} empty="No application made a DNS query during this period.">
                {(d) => <AppsView apps={d.apps} showStatus={showStatus} openPkg={openApp} onOpen={setOpenApp} onShowDomain={showDomain} />}
              </Async>
            </Card>
          )}
        </>
      )}
    </>
  );
}
