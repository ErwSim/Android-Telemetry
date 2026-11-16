import { useCallback, useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { useEventStream } from '../api/useEventStream.ts';
import { usePagedDetections } from '../api/usePagedDetections.ts';
import { usePagedEvents } from '../api/usePagedEvents.ts';
import type { WatchpostEvent } from '../api/types.ts';
import { AppDomains } from '../components/AppDomains.tsx';
import { AppName } from '../components/AppName.tsx';
import { opsCollectorState } from '../components/apps/OpsView.tsx';
import { installerText } from '../components/apps/RiskView.tsx';
import { DetectionCard } from '../components/detections/DetectionCard.tsx';
import { EventList } from '../components/EventList.tsx';
import { ComboCallout, GrantNote, ReasonList, RiskBadge, ScoreBar } from '../components/risk/Risk.tsx';
import { Async, Badge, Card, Empty, ErrorBox, KV, Loading } from '../components/ui.tsx';
import { isRecord, list } from '../lib/data.ts';
import { applyMutes, detectionFromEvent, isMuteEvent, matchesDetection } from '../lib/detections.ts';
import { useMuting } from '../components/detections/Mute.tsx';
import { describeEvent, installerLabel, isSideloaded, permissionLabel } from '../lib/events.ts';
import { fmtDate, fmtDateTime, fmtNumber } from '../lib/format.ts';
import { groupByApp, opInfo } from '../lib/ops.ts';
import { combosOf } from '../lib/risk.ts';
import { involves, roleChanges, roleLabel, rolesHeldBy, roleWhy } from '../lib/roles.ts';
import { cleanText } from '../lib/text.ts';
import { useNow } from '../lib/useNow.ts';
import { useDevice } from '../state/device.tsx';
import { isUnsupported, useAppOps, useAppRisk, useMutes } from '../state/appData.ts';

const DAY = 86_400_000;
const HISTORY_TYPES = 'app.installed,app.updated,app.removed,app.permission_changed';

/**
 * Detail page of an application: risk profile and reasons, default roles, permissions, sensitive operations,
 * contacted domains and detections. Gathers what the other pages show application by application.
 */
export default function AppSheet() {
  const [sp] = useSearchParams();
  const pkg = sp.get('pkg') ?? '';
  const { deviceId, device } = useDevice();
  const now = useNow(300_000);
  const slot = Math.floor(now.getTime() / 300_000) * 300_000;
  const to = new Date(slot + 300_000).toISOString();
  const from30 = new Date(slot - 30 * DAY).toISOString();
  const from90 = new Date(slot - 90 * DAY).toISOString();
  const from7 = new Date(slot - 7 * DAY).toISOString();

  const inventory = useApi(deviceId ? `apps:${deviceId}` : null, (s) => api.apps(deviceId, s));
  const risk = useAppRisk();
  const app = inventory.data?.apps.find((a) => a.package === pkg);
  const profile = risk.data?.apps.find((a) => a.package === pkg);
  const label = cleanText(app?.label ?? profile?.label, 80) || undefined;

  return (
    <>
      <Link className="back-link" to="/apps">
        ← Applications
      </Link>
      <div className="sheet-head">
        <h1>{label ?? cleanText(pkg, 255)}</h1>
        {profile && <RiskBadge risk={profile} />}
        {app?.system && <Badge>system</Badge>}
        {app && isSideloaded(app) && <Badge tone="warn">outside a store</Badge>}
        {app?.enabled === false && <Badge tone="warn">disabled</Badge>}
      </div>
      <div className="sheet-sub">
        <AppName pkg={cleanText(pkg, 255)} label={label} />
        {device && <span>· {device.name || device.device_id}</span>}
        <Link className="btn btn-sm" to={`/tracking?app=${encodeURIComponent(pkg)}`}>
          Tracking
        </Link>
        <Link className="btn btn-sm" to={`/network?app=${encodeURIComponent(pkg)}`}>
          Network
        </Link>
      </div>

      {!inventory.loading && inventory.data && !app && !profile && (
        <div className="state state-warn" role="status">
          This application appears neither in the latest inventory nor in the risk profiles: it may have been uninstalled, or the package name is misspelled.
        </div>
      )}

      <div className="grid grid-start">
        <Card title="Risk profile" className="span-7">
          <RiskCard state={risk} pkg={pkg} />
        </Card>
        <div className="span-5 stack">
          <Card title="Default roles">
            <RolesCard pkg={pkg} from={from90} to={to} />
          </Card>
          <Card title="Information">
            {app ? (
              <KV
                items={[
                  { k: 'Version', v: `${app.version_name ?? '—'}${app.version_code !== undefined ? ` (code ${app.version_code})` : ''}` },
                  { k: 'Installer', v: profile ? installerText(profile, app) : installerLabel(app.installer) },
                  { k: 'Target SDK', v: app.target_sdk ?? '—' },
                  { k: 'First installed', v: fmtDateTime(app.first_install) },
                  { k: 'Last updated', v: fmtDateTime(app.last_update) },
                  { k: 'Signature SHA-256', v: app.signer_sha256 ? <code className="break">{app.signer_sha256}</code> : '—' },
                ]}
              />
            ) : (
              <Empty>No inventory information.</Empty>
            )}
          </Card>
        </div>
      </div>

      <div className="grid">
        <Card title="Detections concerning this application" className="span-12">
          <SheetDetections pkg={pkg} from={from30} to={to} now={now} />
        </Card>
      </div>

      <div className="grid grid-start">
        <Card title={`Dangerous permissions granted${app ? ` (${app.granted_dangerous?.length ?? 0})` : ''}`} className="span-6">
          {!app ? (
            <Empty>Application absent from the inventory.</Empty>
          ) : (app.granted_dangerous ?? []).length === 0 ? (
            <p className="muted">None.</p>
          ) : (
            <ul className="chip-list">
              {(app.granted_dangerous ?? []).map((p) => (
                <li key={p} className="chip" title={p}>
                  {permissionLabel(p)}
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Sensitive operations (30 days, experimental)" className="span-6">
          <SheetOps pkg={pkg} from={from30} to={to} />
        </Card>
      </div>

      <div className="grid">
        <Card title="Domains contacted (7 days)" className="span-12">
          {deviceId ? <AppDomains deviceId={deviceId} pkg={pkg} from={from7} to={to} usage={undefined} /> : null}
        </Card>
      </div>

      <div className="grid">
        <Card title="History (installations, updates, permissions)" className="span-12">
          <SheetHistory pkg={pkg} from={from90} to={to} />
        </Card>
      </div>
    </>
  );
}

function RiskCard({ state, pkg }: { state: ReturnType<typeof useAppRisk>; pkg: string }) {
  if (isUnsupported(state.error)) return <Empty>This collector does not provide the risk profile yet (contract v1.2).</Empty>;
  return (
    <Async state={state}>
      {(d) => {
        const r = d.apps.find((a) => a.package === pkg);
        if (!r) {
          return (
            <Empty>
              No risk profile received for this application. The v1.2 agent sends one at installation, at update, then every day if the score or reasons change.
            </Empty>
          );
        }
        return (
          <>
            <div className="stats">
              <div className="stat">
                <div className="stat-label">Score</div>
                <div className="stat-value">
                  <ScoreBar risk={r} />
                </div>
                <div className="stat-sub">out of 100 · {r.reasons.length} reason{r.reasons.length > 1 ? 's' : ''}</div>
              </div>
              <div className="stat">
                <div className="stat-label">Level</div>
                <div className="stat-value">
                  <RiskBadge risk={r} />
                </div>
                <div className="stat-sub">{r.ts ? `reading of ${fmtDate(r.ts)}` : ' '}</div>
              </div>
              <div className="stat">
                <div className="stat-label">Installer</div>
                <div className="stat-value">{r.from_store === false ? 'Outside a store' : r.from_store ? 'Store' : 'Unknown'}</div>
                <div className="stat-sub">{installerLabel(r.installer)}</div>
              </div>
            </div>
            <p className="hint">The score measures what the application could do, not what it does: it is a reason to look more closely, not proof.</p>
            <GrantNote hasGranted={r.granted !== undefined} />
            <ComboCallout reasons={r.reasons} />
            <ReasonList reasons={r.reasons.filter((c) => !combosOf(c ? [c] : []).length)} granted={r.granted} />
          </>
        );
      }}
    </Async>
  );
}

/** Roles held today (from `app.special_access`) and `app.role` history where the application gains or loses a role. */
function RolesCard({ pkg, from, to }: { pkg: string; from: string; to: string }) {
  const { deviceId } = useDevice();
  const special = usePagedEvents(deviceId ? { device_id: deviceId, type: 'app.special_access', from, to } : null, 1);
  const roles = usePagedEvents(deviceId ? { device_id: deviceId, type: 'app.role', q: pkg, from, to } : null, 100);
  const defaults = special.events[0]?.data['default_apps'];
  const held = rolesHeldBy(isRecord(defaults) ? defaults : undefined, pkg);
  const accessibility = list<unknown>(special.events[0]?.data, 'accessibility_services').filter((x): x is string => typeof x === 'string' && x.split('/')[0] === pkg);
  const changes = roleChanges(roles.events).filter((c) => involves(c, pkg));
  if ((special.loading && !special.events[0]) || (roles.loading && roles.events.length === 0)) return <Loading />;
  return (
    <>
      <h3 className="section-title">Roles currently held</h3>
      {held.length === 0 ? (
        <p className="muted">No default role (SMS, phone, browser, assistant, home).</p>
      ) : (
        <ul className="role-list">
          {held.map((r) => (
            <li key={r}>
              <strong>{roleLabel(r)}</strong>
              {roleWhy(r) && <p className="hint">{roleWhy(r)}</p>}
            </li>
          ))}
        </ul>
      )}
      {accessibility.length > 0 && (
        <p>
          <Badge tone="warn">Accessibility service active</Badge> <span className="mono break">{accessibility.map((a) => cleanText(a, 200)).join(', ')}</span>
        </p>
      )}
      <h3 className="section-title">Role changes (90 days)</h3>
      {changes.length === 0 ? (
        <p className="muted">This application neither gained nor lost a default role.</p>
      ) : (
        <ul className="role-list">
          {changes.map((c) => (
            <li key={c.id}>
              <div className="role-change">
                <strong>{roleLabel(c.role)}</strong>
                <span className="muted">{fmtDateTime(c.ts)}</span>
                {c.new === pkg ? <Badge tone="warn">gained</Badge> : <Badge>lost</Badge>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function SheetDetections({ pkg, from, to, now }: { pkg: string; from: string; to: string; now: Date }) {
  const { deviceId } = useDevice();
  const params = useMemo(() => (deviceId ? { device_id: deviceId, package: pkg, from, to } : null), [deviceId, pkg, from, to]);
  const paged = usePagedDetections(params, 50);
  const addLive = paged.addLive;
  const reloadList = paged.reload;
  const mutes = useMutes();
  const reloadMutes = mutes.reload;
  const muting = useMuting(deviceId, useCallback(() => {
    reloadList();
    reloadMutes();
  }, [reloadList, reloadMutes]));
  const onEvent = useCallback(
    (ev: WatchpostEvent) => {
      if (isMuteEvent(ev.type)) {
        reloadList();
        reloadMutes();
        return;
      }
      const d = detectionFromEvent(ev);
      if (d && matchesDetection(d, { pkg })) addLive(d);
    },
    [addLive, pkg, reloadList, reloadMutes],
  );
  const shown = useMemo(() => applyMutes(paged.detections, mutes.data ?? []), [paged.detections, mutes.data]);
  const canMute = !isUnsupported(mutes.error);
  useEventStream(true, deviceId, onEvent);
  if (paged.error && paged.detections.length === 0) {
    return isUnsupported(paged.error) ? <Empty>This collector does not provide detections yet (contract v1.2).</Empty> : <ErrorBox message={paged.error.message} onRetry={paged.reload} />;
  }
  if (paged.loading && paged.detections.length === 0) return <Loading label="Loading detections…" />;
  if (paged.detections.length === 0) return <Empty>No detection for this application in 30 days.</Empty>;
  return (
    <div className="det-compact">
      <ul className="det-list" aria-label="Detections of the application">
        {shown.map((d, i) => (
          <DetectionCard
            key={d.id}
            d={d}
            now={now}
            showAppLink={false}
            open={i === 0 && !d.muted}
            onMute={canMute ? muting.askMute : undefined}
            onUnmute={canMute ? (x) => void muting.unmute({ type: x.type, package: x.package ?? '' }) : undefined}
          />
        ))}
      </ul>
      {paged.hasMore && (
        <div className="pager">
          <button type="button" className="btn" onClick={paged.loadMore} disabled={paged.loadingMore}>
            {paged.loadingMore ? 'Loading…' : 'Load more'}
          </button>
        </div>
      )}
      {muting.notice && <p className="hint">{muting.notice}</p>}
      {muting.dialog}
    </div>
  );
}

function SheetOps({ pkg, from, to }: { pkg: string; from: string; to: string }) {
  const { device } = useDevice();
  const ops = useAppOps(from, to);
  if (ops.error && !isUnsupported(ops.error)) return <ErrorBox message={ops.error.message} onRetry={ops.reload} />;
  if (!ops.data && !isUnsupported(ops.error)) return <Loading />;
  const rows = ops.data?.rows ?? [];
  if (rows.length === 0) {
    return (
      <>
        <p className="muted">No sensitive operations usage data for this application.</p>
        <p className="hint">
          Experimental measurement, off by default{opsCollectorState(device) ? '' : ' (collector not reported by the phone)'}. <Link to="/apps?tab=ops">How to enable it</Link>.
        </p>
      </>
    );
  }
  const mine = groupByApp(rows).find((a) => a.package === pkg);
  if (!mine) return <p className="muted">This application used no sensitive operation in 30 days.</p>;
  return (
    <table className="tbl mini-tbl" data-testid="sheet-ops">
      <thead>
        <tr>
          <th scope="col">Operation</th>
          <th scope="col" className="right">Uses</th>
          <th scope="col" className="right">In the background</th>
        </tr>
      </thead>
      <tbody>
        {mine.ops.map((o) => (
          <tr key={o.op}>
            <td>{opInfo(o.op).label}</td>
            <td className="right">{fmtNumber(o.count)}</td>
            <td className="right">{o.background > 0 ? <strong>{fmtNumber(o.background)}</strong> : <span className="muted">0</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SheetHistory({ pkg, from, to }: { pkg: string; from: string; to: string }) {
  const { deviceId } = useDevice();
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: HISTORY_TYPES, q: pkg, from, to } : null, 50);
  const mine = useMemo(() => ({ ...paged, events: paged.events.filter((e) => e.data['package'] === pkg) }), [paged, pkg]);
  const describe = (ev: WatchpostEvent) => describeEvent(ev);
  return (
    <div className="flush">
      <EventList paged={mine} describe={describe} empty="No installation, update or permission change in 90 days." />
    </div>
  );
}
