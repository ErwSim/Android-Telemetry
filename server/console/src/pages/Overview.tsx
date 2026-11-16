import { lazy, Suspense, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { usePagedEvents } from '../api/usePagedEvents.ts';
import type { Device } from '../api/types.ts';
import { Async, Badge, Card, Empty, LevelBadge, Loading, Stat, StatusPill } from '../components/ui.tsx';
import { EventList } from '../components/EventList.tsx';
import { DetectionsOverview } from '../components/detections/OverviewCard.tsx';
import { channelState } from '../lib/commands.ts';
import { blockedPct, hasStatusData, totalsOf } from '../lib/tracking.ts';
import { attentionPoints, evaluatePosture, overallStatus } from '../lib/posture.ts';
import { fmtBytes, fmtDateTime, fmtNumber, fmtPct, fmtRelative, fmtDuration } from '../lib/format.ts';
import { useNow } from '../lib/useNow.ts';
import { useDevice } from '../state/device.tsx';

const MapView = lazy(() => import('../components/MapView.tsx'));
const TimelineChart = lazy(() => import('../components/TimelineChart.tsx'));

const STALE_MS = 35 * 60_000; // two missed heartbeats (15 min each) + margin

export default function Overview() {
  const { device } = useDevice();
  const now = useNow();
  const minute = Math.floor(now.getTime() / 60_000);
  const from24 = useMemo(() => new Date(minute * 60_000 - 24 * 3600_000).toISOString(), [minute]);
  const to = useMemo(() => new Date(minute * 60_000).toISOString(), [minute]);
  const id = device?.device_id;

  const timeline = useApi(id ? `tl:${id}:${minute}` : null, (s) =>
    api.timeline({ device_id: id, from: from24, to, bucket: 'hour', by: 'domain' }, s),
  );
  const alerts = useApi(`alerts:${Math.floor(minute / 5)}`, (s) =>
    api.alerts({ from: new Date(minute * 60_000 - 7 * 24 * 3600_000).toISOString(), to, limit: 5 }, s),
  );
  const tracking = useApi(id ? `ov-trk:${id}:${minute}` : null, (s) => api.trackingSummary({ device_id: id, from: from24, to }, s));
  const sevEvents = usePagedEvents(id ? { device_id: id, sev_min: 2, from: new Date(minute * 60_000 - 7 * 24 * 3600_000).toISOString(), to } : null, 8);

  if (!device) return null;
  return (
    <>
      <div className="page-head">
        <h1>Overview</h1>
        <span className="muted">
          {device.name} · <span className="mono">{device.device_id}</span>
        </span>
      </div>

      <DetectionsOverview deviceId={device.device_id} now={now} />

      <div className="grid">
        <Card title="Device state" className="span-7">
          <DeviceState device={device} now={now} />
        </Card>
        <Card
          title="Last location"
          className="span-5"
          actions={
            <Link to="/map" className="btn btn-sm">
              Open the map
            </Link>
          }
        >
          <LastPosition device={device} />
        </Card>
      </div>

      <div className="grid">
        <Card
          title="Security posture"
          className="span-5"
          actions={
            <Link to="/security" className="btn btn-sm">
              Details
            </Link>
          }
        >
          <PostureSummary device={device} />
        </Card>
        <Card title="Activity of the last 24 h" className="span-7">
          <Async state={timeline} isEmpty={(t) => t.series.length === 0 || t.buckets.length === 0} empty="No event received in the last 24 h.">
            {(t) => (
              <Suspense fallback={<Loading />}>
                <TimelineChart data={t} bucket="hour" ariaLabel="Events per hour and per domain" />
              </Suspense>
            )}
          </Async>
        </Card>
      </div>

      <div className="grid">
        <Card
          title="Remote commands"
          className="span-5"
          actions={
            <Link to="/commands" className="btn btn-sm">
              Commands
            </Link>
          }
        >
          <CommandsSummary device={device} now={now} />
        </Card>
        <Card
          title="Tracking, last 24 h"
          className="span-7"
          actions={
            <Link to="/tracking" className="btn btn-sm">
              Details
            </Link>
          }
        >
          {tracking.error ? (
            <Empty>Tracking view unavailable on this collector.</Empty>
          ) : (
            <Async state={tracking} isEmpty={(t) => t.publishers.length === 0} empty="No DNS queries in the last 24 h.">
              {(t) => {
                const totals = totalsOf(t.totals, t.publishers);
                const pct = blockedPct(totals);
                return (
                  <>
                    <div className="stats">
                      <Stat label="DNS queries" value={fmtNumber(totals.queries)} />
                      {hasStatusData(totals) ? (
                        <Stat label="Blocked" value={fmtNumber(totals.blocked)} sub={pct === undefined ? undefined : fmtPct(pct, 1)} tone="ok" />
                      ) : (
                        <Stat label="Blocking" value="Unknown" sub={t.adguard ? 'no count' : 'AdGuard Home unreachable'} tone="warn" />
                      )}
                    </div>
                    <p className="hint">Watchpost sees who the phone talks to, not the content of the exchanges (encrypted).</p>
                  </>
                );
              }}
            </Async>
          )}
        </Card>
      </div>

      <div className="grid">
        <Card
          title="Latest events (severity ≥ 2, 7 days)"
          className="span-7"
          actions={
            <Link to="/events?sev_min=2" className="btn btn-sm">
              See all
            </Link>
          }
        >
          <div className="flush">
            <EventList paged={sevEvents} compact empty="No event of severity 2 or more in 7 days." />
          </div>
        </Card>
        <Card
          title="Latest Wazuh alerts"
          className="span-5"
          actions={
            <Link to="/alerts" className="btn btn-sm">
              All
            </Link>
          }
        >
          <Async state={alerts}>
            {(a) =>
              !a.wazuh ? (
                <Empty>
                  Wazuh is not configured on this collector: no alerts available.
                </Empty>
              ) : a.alerts.length === 0 ? (
                <Empty>No alerts in 7 days.</Empty>
              ) : (
                <ul className="findings">
                  {a.alerts.map((al, i) => (
                    <li key={`${al.ts}-${al.rule_id ?? ''}-${i}`}>
                      <LevelBadge level={al.level} />
                      <span className="f-label">{al.description ?? al.rule_id ?? 'Alert'}</span>
                      <span className="f-val">
                        {fmtDateTime(al.ts)}
                        {al.rule_id ? ` · rule ${al.rule_id}` : ''}
                      </span>
                    </li>
                  ))}
                </ul>
              )
            }
          </Async>
        </Card>
      </div>
    </>
  );
}

function CommandsSummary({ device, now }: { device: Device; now: Date }) {
  const ch = device.command_channel;
  const st = channelState(ch, now);
  return (
    <>
      <div className="stats">
        <Stat label="Channel" value={st.label} tone={st.tone === 'neutral' ? undefined : st.tone} />
        <Stat label="Last contact" value={ch?.last_contact ? fmtRelative(ch.last_contact, now) : '—'} sub={ch?.last_contact ? fmtDateTime(ch.last_contact) : undefined} />
      </div>
      <p className="hint">{st.hint} Ring, vibrate, locate, lock or erase: Commands page.</p>
    </>
  );
}

function DeviceState({ device, now }: { device: Device; now: Date }) {
  const hb = device.last_heartbeat;
  const seen = device.last_seen ? new Date(device.last_seen) : undefined;
  const age = seen ? now.getTime() - seen.getTime() : undefined;
  const stale = age === undefined || age > STALE_MS;
  const collectors = Object.entries(hb?.collectors ?? {});
  const bad = collectors.filter(([, s]) => s !== 'running');
  return (
    <>
      {device.revoked && (
        <div className="state state-error" role="alert">
          This device is revoked: its uploads are refused.
        </div>
      )}
      {!device.revoked && stale && (
        <div className="state state-warn" role="alert">
          {seen ? (
            <>
              No contact for <strong>{fmtDuration(age)}</strong> (last: {fmtDateTime(device.last_seen)}). The phone may be
              off, offline or the agent stopped.
            </>
          ) : (
            <>This device has never sent any data yet.</>
          )}
        </div>
      )}
      <div className="stats">
        <Stat
          label="Last contact"
          value={seen ? fmtRelative(device.last_seen, now) : '—'}
          sub={seen ? fmtDateTime(device.last_seen) : undefined}
          tone={stale ? 'bad' : 'ok'}
        />
        <Stat
          label="Battery"
          value={hb?.battery_pct !== undefined ? fmtPct(hb.battery_pct) : '—'}
          sub={hb?.charging === undefined ? undefined : hb.charging ? 'charging' : 'on battery'}
          tone={hb?.battery_pct !== undefined && hb.battery_pct < 15 && !hb.charging ? 'warn' : undefined}
        />
        <Stat
          label="Pending buffer"
          value={hb?.queue_depth !== undefined ? `${fmtNumber(hb.queue_depth)} evt` : '—'}
          sub={hb?.queue_bytes !== undefined ? fmtBytes(hb.queue_bytes) : undefined}
          tone={hb?.queue_depth !== undefined && hb.queue_depth > 500 ? 'warn' : undefined}
        />
        <Stat
          label="Device Owner"
          value={hb?.device_owner === undefined ? '—' : hb.device_owner ? 'Active' : 'Inactive'}
          sub={hb?.device_owner === false ? 'degraded mode' : undefined}
          tone={hb?.device_owner === undefined ? undefined : hb.device_owner ? 'ok' : 'warn'}
        />
        <Stat label="Agent" value={device.agent_version ? `v${device.agent_version}` : '—'} sub={hb?.uptime_ms !== undefined ? `up for ${fmtDuration(hb.uptime_ms)}` : undefined} />
        <Stat
          label="Lost events"
          value={hb?.dropped_total !== undefined ? fmtNumber(hb.dropped_total) : '—'}
          sub={hb?.last_upload_ts ? `last upload ${fmtRelative(hb?.last_upload_ts, now)}` : undefined}
          tone={hb?.dropped_total ? 'warn' : undefined}
        />
      </div>
      <h3 className="section-title">Collectors</h3>
      {collectors.length === 0 ? (
        <p className="muted">Collector state unknown (no heartbeat received).</p>
      ) : (
        <>
          <p className="muted">
            {collectors.length - bad.length} running out of {collectors.length}
            {bad.length > 0 ? ` — ${bad.length} to watch` : ''}.
          </p>
          <ul className="chip-list" aria-label="Collector state">
            {collectors.map(([id, st]) => (
              <li key={id}>
                <Badge tone={st === 'running' ? 'ok' : st === 'unavailable' ? 'bad' : 'neutral'} title={collectorStateLabel(st)}>
                  {id} · {collectorStateLabel(st)}
                </Badge>
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}

function collectorStateLabel(s: string): string {
  return s === 'running' ? 'running' : s === 'disabled' ? 'disabled' : s === 'unavailable' ? 'unavailable' : s;
}

function LastPosition({ device }: { device: Device }) {
  const loc = device.last_location;
  const points = useMemo(
    () => (loc ? [{ lat: loc.lat, lon: loc.lon, t: new Date(loc.ts).getTime(), ...(loc.acc_m !== undefined ? { acc: loc.acc_m } : {}) }] : []),
    [loc],
  );
  if (!loc) return <Empty>No location received for this device.</Empty>;
  return (
    <>
      <div className="map-sm">
        <Suspense fallback={<Loading label="Loading the map…" />}>
          <MapView points={points} selected={0} interactive={false} ariaLabel="Last known location of the device" />
        </Suspense>
      </div>
      <p className="hint overview-pos">
        {fmtDateTime(loc.ts)} ({fmtRelative(loc.ts)})
        {loc.acc_m !== undefined ? ` · accuracy ±${fmtNumber(loc.acc_m)} m` : ''} · {fmtNumber(loc.lat, 5)}, {fmtNumber(loc.lon, 5)}
      </p>
    </>
  );
}

function PostureSummary({ device }: { device: Device }) {
  const findings = useMemo(() => evaluatePosture(device.last_posture), [device.last_posture]);
  if (findings.length === 0) return <Empty>No posture received for this device.</Empty>;
  const status = overallStatus(findings);
  const points = attentionPoints(findings);
  const ok = findings.filter((f) => f.status === 'ok').length;
  return (
    <>
      <p>
        <StatusPill status={status} />{' '}
        <span className="muted">
          {ok} of {findings.length} check{findings.length > 1 ? 's' : ''} compliant
        </span>
      </p>
      {points.length === 0 ? (
        <p>No point of attention.</p>
      ) : (
        <ul className="findings" aria-label="Points of attention">
          {points.map((f) => (
            <li key={f.id}>
              <StatusPill status={f.status} />
              <span className="f-label">{f.label}</span>
              <span className="f-val">
                {f.value}
                {f.detail ? ` — ${f.detail}` : ''}
              </span>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
