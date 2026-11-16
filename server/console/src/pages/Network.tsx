import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import type { TopKind } from '../api/types.ts';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Ranking } from '../components/Ranking.tsx';
import { Async, Card, Empty, Loading } from '../components/ui.tsx';
import { mergeTop, vendorShare, type VendorShare } from '../lib/agg.ts';
import { fmtNumber, fmtPct } from '../lib/format.ts';
import { chooseBucket, periodRange } from '../lib/period.ts';
import { VENDOR_LABELS, type Vendor } from '../lib/vendors.ts';
import { useAppLabels } from '../state/appLabels.ts';
import { useDevice } from '../state/device.tsx';
import { AppName } from '../components/AppName.tsx';
import { AppDomains } from '../components/AppDomains.tsx';

const TimelineChart = lazy(() => import('../components/TimelineChart.tsx'));

const NET_TYPES = ['net.dns', 'net.connect'];
const NET_LABEL = (k: string) => (k === 'net.dns' ? 'DNS queries' : k === 'net.connect' ? 'Connections' : k);

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
  const [sp] = useSearchParams();
  const [pkg, setPkg] = useState<string | undefined>(sp.get('app') || undefined);
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
        <h1>Network</h1>
      </div>
      <p className="hint net-intro">
        This page describes the traffic observed on the phone: names requested, destinations, volumes, timeline. To see what is <strong>blocked or allowed</strong>,
        by publisher, and to act (block a domain, change the level), open <Link to="/tracking">Tracking</Link>.
      </p>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
        <button type="button" className="btn" onClick={() => ctl.refresh()}>
          Refresh
        </button>
      </div>

      <div className="grid">
        <Card title="Google / Samsung share" className="span-12">
          <div className="two-col">
            <ShareBlock
              title="DNS queries per domain"
              note="based on the 100 most frequent names"
              loading={dns.loading && !dns.data}
              error={dns.error?.message}
              share={dns.data ? vendorShare(dns.data.items, 'host') : undefined}
            />
            <ShareBlock
              title="Queries (DNS + connections) per application"
              note="classified by the package's publisher"
              loading={(dnsPkg.loading && !dnsPkg.data) || (conPkg.loading && !conPkg.data)}
              error={dnsPkg.error?.message ?? conPkg.error?.message}
              share={dnsPkg.data && conPkg.data ? vendorShare(reqApps, 'package') : undefined}
            />
          </div>
        </Card>
      </div>

      <div className="grid">
        <Card
          title="Most requested DNS names"
          className="span-6"
          actions={
            <input
              type="search"
              aria-label="Filter the DNS names"
              placeholder="Filter…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          }
        >
          <Async state={dns} isEmpty={(d) => d.items.length === 0} empty="No DNS queries for this period (Device Owner collector required).">
            {() => <Ranking items={filteredDns} kind="host" limit={20} emptyText="No name matches the filter." />}
          </Async>
        </Card>
        <Card title="Destinations (connections)" className="span-6">
          <Async state={dest} isEmpty={(d) => d.items.length === 0} empty="No connection recorded for this period.">
            {(d) => <Ranking items={d.items} kind="plain" limit={20} />}
          </Async>
        </Card>
      </div>

      <div className="grid">
        <Card title="Most active applications (queries)" className="span-6">
          <Async state={dnsPkg} isEmpty={() => reqApps.length === 0} empty="No query attributed to an application.">
            {() => (
              <>
                <Ranking items={reqApps} kind="package" labelOf={labelOf} selected={pkg} onSelect={setPkg} limit={15} />
                <p className="hint">Click an application to see the domains it contacts.</p>
              </>
            )}
          </Async>
        </Card>
        <Card title="Applications by data volume" className="span-6">
          <Async state={usage} isEmpty={(d) => d.items.length === 0} empty="No usage volume for this period.">
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
                Close
              </button>
            }
          >
            <AppDomains deviceId={deviceId} pkg={pkg} from={range.from} to={range.to} usage={usage.data?.items.find((i) => i.key === pkg)} />
          </Card>
        </div>
      )}

      <div className="grid">
        <Card title="Traffic timeline" className="span-12">
          <Async
            state={{ ...timeline, data: netTimeline }}
            isEmpty={(t) => t.series.length === 0 || t.buckets.length === 0}
            empty="No network activity for this period."
          >
            {(t) => (
              <Suspense fallback={<Loading />}>
                <TimelineChart data={t} bucket={bucket} order={NET_TYPES} labelOf={NET_LABEL} ariaLabel="DNS queries and connections over time" />
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
        <Empty>No data.</Empty>
      ) : (
        <>
          <div className="share" role="img" aria-label={`Google ${fmtPct((share.google / share.total) * 100)}, Samsung ${fmtPct((share.samsung / share.total) * 100)}, others ${fmtPct((share.other / share.total) * 100)}`}>
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
