import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
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
  const ctl = usePeriod('24h');
  const range = periodRange(ctl.period);
  const labelOf = useAppLabels();
  const [tab, setTab] = useState<Tab>('domains');
  const [publisher, setPublisher] = useState<string | undefined>();
  const [status, setStatus] = useState<StatusFilter>('all');
  const [qInput, setQInput] = useState('');
  const q = useDebounced(qInput, 400);
  const [openApp, setOpenApp] = useState<string | undefined>();
  const [notice, setNotice] = useState<Notice | undefined>();

  const summary = useApi(deviceId ? `trk-sum:${deviceId}:${range.from}:${range.to}` : null, (s) => api.trackingSummary({ device_id: deviceId, ...range }, s));
  const apps = useApi(deviceId && tab === 'apps' ? `trk-apps:${deviceId}:${range.from}:${range.to}:${publisher ?? ''}` : null, (s) =>
    api.trackingApps({ device_id: deviceId, ...range, ...(publisher ? { publisher } : {}) }, s),
  );

  const degraded = summary.data ? !summary.data.adguard : false;
  // Des décomptes bloqué/autorisé existent (même si AdGuard est momentanément injoignable : les agrégats stockés restent servis).
  const showStatus = summary.data ? hasStatusData(totalsOf(summary.data.totals, summary.data.publishers)) : true;
  // Sans décompte de statut, le filtre bloqué / autorisé est ignoré.
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
        <h1>Pistage</h1>
        <span className="muted">Ce qui est bloqué et ce qui passe vers Google, Samsung et les autres</span>
      </div>

      <div className="callout callout-info honest" role="note">
        <p>
          <strong>Ce que cette page montre, et ce qu'elle ne montre pas.</strong> Vigie voit <em>à qui</em> le téléphone parle (les noms de domaine demandés),{' '}
          <em>combien de fois</em> et <em>depuis quelle application</em>. Il ne voit <strong>pas le contenu</strong> des échanges : il est chiffré (TLS). « Autorisé »
          veut dire que la requête n'a pas été bloquée, pas qu'on sait ce qui a été envoyé ; « bloqué » veut dire que le nom n'a pas été résolu, donc que rien n'est
          parti vers ce domaine. Une application peut aussi contourner le DNS du téléphone.
        </p>
      </div>

      {degraded && (
        <div className="state state-warn" role="alert">
          <div>
            <strong>Mode dégradé : AdGuard Home n'est pas joignable ou pas configuré sur ce collecteur.</strong>{' '}
            {showStatus
              ? "Les décomptes bloqué / autorisé affichés sont ceux enregistrés avant la panne ; les requêtes récentes n'y figurent pas."
              : "La vue est construite à partir des seules requêtes DNS relevées par l'agent du téléphone (Device Owner) : on voit qui demande quoi, mais pas si la requête a été bloquée."}{' '}
            Les boutons Bloquer, Autoriser et le choix du niveau de blocage sont désactivés tant qu'AdGuard Home n'est pas rétabli.
          </div>
        </div>
      )}

      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
        <button type="button" className="btn" onClick={() => { ctl.refresh(); summary.reload(); domains.reload(); apps.reload(); }}>
          Actualiser
        </button>
        <span className="hint">
          Le détail du trafic (volumes, destinations, chronologie) est sur la page <Link to="/reseau">Réseau</Link>.
        </span>
      </div>

      {summary.error?.status === 404 ? (
        <Empty>Ce collecteur ne propose pas encore la vue « pistage » (contrat §9). Mettez-le à jour pour l'utiliser.</Empty>
      ) : (
        <>
          <div className="grid grid-start">
            <Card title="Synthèse par éditeur" className="span-12">
              <Async state={summary} isEmpty={(s) => s.publishers.length === 0} empty="Aucune requête DNS sur cette période (l'agent doit être Device Owner, ou AdGuard Home doit journaliser).">
                {(s) => {
                  const totals = totalsOf(s.totals, s.publishers);
                  const pct = blockedPct(totals);
                  return (
                    <>
                      <div className="stats trk-stats">
                        <Stat label="Requêtes DNS" value={fmtNumber(totals.queries)} />
                        {showStatus && <Stat label="Bloquées" value={fmtNumber(totals.blocked)} sub={pct === undefined ? undefined : fmtPct(pct, 1)} tone="ok" />}
                        {showStatus && <Stat label="Autorisées" value={fmtNumber(totals.allowed)} sub={pct === undefined ? undefined : fmtPct(100 - pct, 1)} />}
                      </div>
                      <PublisherTable publishers={s.publishers} totals={totals} showStatus={showStatus} selected={publisher} onSelect={setPublisher} />
                      <p className="hint">
                        Cliquez un éditeur pour filtrer la liste des domaines et des applications. Les octets par éditeur sont des <strong>estimations</strong> : le volume de chaque
                        application est réparti entre éditeurs au prorata de ses requêtes DNS.
                      </p>
                    </>
                  );
                }}
              </Async>
            </Card>
            <Card title="Niveau de blocage" className="span-12">
              <Async state={summary}>{(s) => <LevelCard summary={s} onChanged={() => { setNotice({ tone: 'ok', text: 'Niveau de blocage changé : il s\'applique aux prochaines requêtes.' }); summary.reload(); domains.reload(); }} />}</Async>
            </Card>
          </div>

          {notice && (
            <div className={`state ${notice.tone === 'ok' ? 'state-ok' : notice.tone === 'warn' ? 'state-warn' : 'state-error'}`} role="status" aria-live="polite">
              {notice.text}
            </div>
          )}

          <Tabs
            label="Vues du pistage"
            value={tab}
            onChange={setTab}
            tabs={[
              { key: 'domains', label: 'Domaines' },
              { key: 'apps', label: 'Applications' },
            ]}
          />

          {publisher && (
            <p className="hint">
              Filtre : <strong>{publisherNames.get(publisher) ?? publisher}</strong>{' '}
              <button type="button" className="linkish" onClick={() => setPublisher(undefined)}>
                retirer le filtre
              </button>
            </p>
          )}

          {tab === 'domains' && (
            <Card className="events-card">
              <div className="toolbar trk-filters">
                <label className="filter">
                  Éditeur
                  <select value={publisher ?? ''} onChange={(e) => setPublisher(e.target.value || undefined)}>
                    <option value="">Tous</option>
                    {(summary.data?.publishers ?? []).map((p) => (
                      <option key={p.key} value={p.key}>
                        {p.name}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="filter">
                  <span id="trk-status">Statut</span>
                  <div className="seg" role="group" aria-labelledby="trk-status">
                    {(
                      [
                        ['all', 'Tous'],
                        ['blocked', 'Bloqués'],
                        ['allowed', 'Autorisés'],
                      ] as [StatusFilter, string][]
                    ).map(([k, label]) => (
                      <button
                        key={k}
                        type="button"
                        className={`seg-btn${effStatus === k ? ' is-active' : ''}`}
                        aria-pressed={effStatus === k}
                        disabled={!showStatus && k !== 'all'}
                        title={!showStatus && k !== 'all' ? "Indisponible : aucun décompte bloqué / autorisé" : undefined}
                        onClick={() => setStatus(k)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
                <label className="filter grow">
                  Recherche d'un domaine
                  <input type="search" value={qInput} onChange={(e) => setQInput(e.target.value)} placeholder="ex. doubleclick, samsungdm…" spellCheck={false} />
                </label>
              </div>
              <div className="flush">
                <DomainList paged={domains} degraded={degraded} showStatus={showStatus} publisherNames={publisherNames} labelOf={labelOf} onOpenApp={showApp} onNotice={setNotice} />
              </div>
            </Card>
          )}

          {tab === 'apps' && (
            <Card>
              <Async state={apps} isEmpty={(d) => d.apps.length === 0} empty="Aucune application n'a émis de requête DNS sur cette période.">
                {(d) => <AppsView apps={d.apps} showStatus={showStatus} openPkg={openApp} onOpen={setOpenApp} onShowDomain={showDomain} />}
              </Async>
            </Card>
          )}
        </>
      )}
    </>
  );
}
