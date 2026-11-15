import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import type { TopItem, TopKind } from '../api/types.ts';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Ranking } from '../components/Ranking.tsx';
import { Async, Card, Empty, Loading, Stat } from '../components/ui.tsx';
import { countKeys, mergeTop, vendorShare, type VendorShare } from '../lib/agg.ts';
import { str } from '../lib/data.ts';
import { fmtBytes, fmtNumber, fmtPct } from '../lib/format.ts';
import { chooseBucket, periodRange } from '../lib/period.ts';
import { VENDOR_LABELS, type Vendor } from '../lib/vendors.ts';
import { useAppLabels } from '../state/appLabels.ts';
import { useDevice } from '../state/device.tsx';
import { AppName } from '../components/AppName.tsx';

const TimelineChart = lazy(() => import('../components/TimelineChart.tsx'));

const NET_TYPES = ['net.dns', 'net.connect'];
const NET_LABEL = (k: string) => (k === 'net.dns' ? 'Requêtes DNS' : k === 'net.connect' ? 'Connexions' : k);

function useTop(deviceId: string | undefined, kind: TopKind, from: string, to: string, limit: number) {
  return useApi(deviceId ? `top:${deviceId}:${kind}:${from}:${to}:${limit}` : null, (s) =>
    api.top({ device_id: deviceId, kind, from, to, limit }, s),
  );
}

export default function Network() {
  const { deviceId } = useDevice();
  const ctl = usePeriod('24h');
  const range = periodRange(ctl.period);
  const labelOf = useAppLabels();
  const [pkg, setPkg] = useState<string | undefined>();
  const detailRef = useRef<HTMLDivElement>(null);
  const [filter, setFilter] = useState('');

  const dns = useTop(deviceId, 'dns_hostname', range.from, range.to, 100);
  const dest = useTop(deviceId, 'connect_dest', range.from, range.to, 30);
  const dnsPkg = useTop(deviceId, 'dns_package', range.from, range.to, 50);
  const conPkg = useTop(deviceId, 'connect_package', range.from, range.to, 50);
  const usage = useTop(deviceId, 'usage_package', range.from, range.to, 30);
  const bucket = chooseBucket(ctl.period.from, ctl.period.to);
  const timeline = useApi(deviceId ? `net-tl:${deviceId}:${range.from}:${range.to}:${bucket}` : null, (s) =>
    api.timeline({ device_id: deviceId, ...range, bucket, by: 'type' }, s),
  );

  const reqApps = useMemo(() => mergeTop(dnsPkg.data?.items ?? [], conPkg.data?.items ?? []), [dnsPkg.data, conPkg.data]);
  const filteredDns = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const items = dns.data?.items ?? [];
    return f ? items.filter((i) => i.key.toLowerCase().includes(f)) : items;
  }, [dns.data, filter]);
  const netTimeline = useMemo(() => {
    const t = timeline.data;
    if (!t) return undefined;
    return { buckets: t.buckets, series: t.series.filter((s) => NET_TYPES.includes(s.key)) };
  }, [timeline.data]);

  useEffect(() => {
    if (pkg) detailRef.current?.scrollIntoView?.({ behavior: 'smooth', block: 'nearest' });
  }, [pkg]);

  return (
    <>
      <div className="page-head">
        <h1>Réseau</h1>
      </div>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
        <button type="button" className="btn" onClick={() => ctl.refresh()}>
          Actualiser
        </button>
      </div>

      <div className="grid">
        <Card title="Part Google / Samsung" className="span-12">
          <div className="two-col">
            <ShareBlock
              title="Requêtes DNS par domaine"
              note="d'après les 100 noms les plus fréquents"
              loading={dns.loading && !dns.data}
              error={dns.error?.message}
              share={dns.data ? vendorShare(dns.data.items, 'host') : undefined}
            />
            <ShareBlock
              title="Requêtes (DNS + connexions) par application"
              note="classées selon l'éditeur du paquet"
              loading={(dnsPkg.loading && !dnsPkg.data) || (conPkg.loading && !conPkg.data)}
              error={dnsPkg.error?.message ?? conPkg.error?.message}
              share={dnsPkg.data && conPkg.data ? vendorShare(reqApps, 'package') : undefined}
            />
          </div>
        </Card>
      </div>

      <div className="grid">
        <Card
          title="Noms DNS les plus demandés"
          className="span-6"
          actions={
            <input
              type="search"
              aria-label="Filtrer les noms DNS"
              placeholder="Filtrer…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          }
        >
          <Async state={dns} isEmpty={(d) => d.items.length === 0} empty="Aucune requête DNS sur cette période (collecteur Device Owner requis).">
            {() => <Ranking items={filteredDns} kind="host" limit={20} emptyText="Aucun nom ne correspond au filtre." />}
          </Async>
        </Card>
        <Card title="Destinations (connexions)" className="span-6">
          <Async state={dest} isEmpty={(d) => d.items.length === 0} empty="Aucune connexion enregistrée sur cette période.">
            {(d) => <Ranking items={d.items} kind="plain" limit={20} />}
          </Async>
        </Card>
      </div>

      <div className="grid">
        <Card title="Applications les plus actives (requêtes)" className="span-6">
          <Async state={dnsPkg} isEmpty={() => reqApps.length === 0} empty="Aucune requête attribuée à une application.">
            {() => (
              <>
                <Ranking items={reqApps} kind="package" labelOf={labelOf} selected={pkg} onSelect={setPkg} limit={15} />
                <p className="hint">Cliquez une application pour voir les domaines qu'elle contacte.</p>
              </>
            )}
          </Async>
        </Card>
        <Card title="Applications par volume de données" className="span-6">
          <Async state={usage} isEmpty={(d) => d.items.length === 0} empty="Aucun volume d'usage sur cette période.">
            {(d) => <Ranking items={d.items} kind="package" metric="bytes" labelOf={labelOf} selected={pkg} onSelect={setPkg} limit={15} />}
          </Async>
        </Card>
      </div>

      {pkg && deviceId && (
        <div className="grid" ref={detailRef}>
          <Card
            title={<AppName pkg={pkg} label={labelOf(pkg)} />}
            className="span-12"
            actions={
              <button type="button" className="btn btn-sm" onClick={() => setPkg(undefined)}>
                Fermer
              </button>
            }
          >
            <AppDomains deviceId={deviceId} pkg={pkg} from={range.from} to={range.to} usage={usage.data?.items.find((i) => i.key === pkg)} />
          </Card>
        </div>
      )}

      <div className="grid">
        <Card title="Chronologie du trafic" className="span-12">
          <Async
            state={{ ...timeline, data: netTimeline }}
            isEmpty={(t) => t.series.length === 0 || t.buckets.length === 0}
            empty="Aucune activité réseau sur cette période."
          >
            {(t) => (
              <Suspense fallback={<Loading />}>
                <TimelineChart data={t} bucket={bucket} order={NET_TYPES} labelOf={NET_LABEL} ariaLabel="Requêtes DNS et connexions dans le temps" />
              </Suspense>
            )}
          </Async>
        </Card>
      </div>
    </>
  );
}

function ShareBlock({
  title,
  note,
  share,
  loading,
  error,
}: {
  title: string;
  note: string;
  share: VendorShare | undefined;
  loading: boolean;
  error: string | undefined;
}) {
  return (
    <div>
      <h3>{title}</h3>
      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : loading ? (
        <Loading />
      ) : !share || share.total === 0 ? (
        <Empty>Aucune donnée.</Empty>
      ) : (
        <>
          <div className="share" role="img" aria-label={`Google ${fmtPct((share.google / share.total) * 100)}, Samsung ${fmtPct((share.samsung / share.total) * 100)}, autres ${fmtPct((share.other / share.total) * 100)}`}>
            {(['google', 'samsung', 'other'] as Vendor[]).map((v) => (
              <ShareSegment key={v} vendor={v} frac={share[v] / share.total} />
            ))}
          </div>
          <ul className="legend">
            {(['google', 'samsung', 'other'] as Vendor[]).map((v) => (
              <li key={v}>
                <span className={`swatch sh-${v}`} aria-hidden="true" />
                {VENDOR_LABELS[v]} <strong>{fmtPct((share[v] / share.total) * 100, 1)}</strong>
                <span className="muted"> ({fmtNumber(share[v])})</span>
              </li>
            ))}
          </ul>
          <p className="hint">{note}</p>
        </>
      )}
    </div>
  );
}

function ShareSegment({ vendor, frac }: { vendor: Vendor; frac: number }) {
  if (frac <= 0) return null;
  return <span className={`s-${vendor}`} style={{ width: `${frac * 100}%` }} />;
}

/**
 * Domaines contactés par une application. L'API `/stats/top` n'a pas de filtre par paquet : on lit les
 * événements `net.dns` / `net.connect` (recherche textuelle sur le nom du paquet) puis on agrège ici.
 */
async function loadAppEvents(
  deviceId: string,
  type: string,
  pkg: string,
  from: string,
  to: string,
  signal: AbortSignal,
): Promise<{ hosts: string[]; scanned: number; truncated: boolean }> {
  const hosts: string[] = [];
  let cursor: string | undefined;
  let scanned = 0;
  for (let page = 0; page < 4; page++) {
    const r = await api.events({ device_id: deviceId, type, q: pkg, from, to, limit: 500, ...(cursor ? { cursor } : {}) }, signal);
    for (const ev of r.events) {
      scanned++;
      if (str(ev.data, 'package') !== pkg) continue;
      const k = type === 'net.dns' ? str(ev.data, 'hostname') : `${str(ev.data, 'ip') ?? '?'}${ev.data['port'] !== undefined ? `:${String(ev.data['port'])}` : ''}`;
      if (k) hosts.push(k);
    }
    cursor = r.next_cursor || undefined;
    if (!cursor) return { hosts, scanned, truncated: false };
  }
  return { hosts, scanned, truncated: true };
}

function AppDomains({ deviceId, pkg, from, to, usage }: { deviceId: string; pkg: string; from: string; to: string; usage: TopItem | undefined }) {
  const state = useApi(`appdom:${deviceId}:${pkg}:${from}:${to}`, async (signal) => {
    const [dns, con] = await Promise.all([
      loadAppEvents(deviceId, 'net.dns', pkg, from, to, signal),
      loadAppEvents(deviceId, 'net.connect', pkg, from, to, signal),
    ]);
    return { dns, con };
  });
  return (
    <>
      {usage?.bytes !== undefined && (
        <div className="stats app-stats">
          <Stat label="Volume sur la période" value={fmtBytes(usage.bytes)} />
        </div>
      )}
      <Async state={state} loadingLabel="Analyse des événements de l'application…">
        {({ dns, con }) => {
          const dnsTop = countKeys(dns.hosts, 25).map((c) => ({ key: c.key, count: c.count }));
          const conTop = countKeys(con.hosts, 15).map((c) => ({ key: c.key, count: c.count }));
          const truncated = dns.truncated || con.truncated;
          return (
            <>
              {truncated && (
                <p className="state state-warn">
                  Échantillon limité aux {fmtNumber(Math.max(dns.scanned, con.scanned))} événements les plus récents : les décomptes sont partiels.
                </p>
              )}
              <div className="two-col">
                <div>
                  <h3>Domaines demandés ({fmtNumber(dns.hosts.length)} requêtes)</h3>
                  <Ranking items={dnsTop} kind="host" limit={25} emptyText="Aucune requête DNS pour cette application." />
                </div>
                <div>
                  <h3>Destinations contactées ({fmtNumber(con.hosts.length)} connexions)</h3>
                  <Ranking items={conTop} kind="plain" limit={15} emptyText="Aucune connexion pour cette application." />
                </div>
              </div>
            </>
          );
        }}
      </Async>
    </>
  );
}
