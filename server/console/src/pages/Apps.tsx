import { Fragment, useMemo, useState } from 'react';
import { appSheetPath } from '../lib/text.ts';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { usePagedEvents } from '../api/usePagedEvents.ts';
import type { AppInfo, WatchpostEvent } from '../api/types.ts';
import { AppName } from '../components/AppName.tsx';
import { EventList } from '../components/EventList.tsx';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Async, Badge, Card, Empty, ErrorBox, KV, Loading, Stat, Tabs } from '../components/ui.tsx';
import { OpsEmpty, OpsView, opsCollectorState } from '../components/apps/OpsView.tsx';
import { RiskView } from '../components/apps/RiskView.tsx';
import { RiskBadge } from '../components/risk/Risk.tsx';
import { Ranking } from '../components/Ranking.tsx';
import { summarizeNotifications } from '../lib/notifications.ts';
import { countByInstaller, groupPermissions } from '../lib/agg.ts';
import { isRecord, list, str } from '../lib/data.ts';
import { describeEvent, installerLabel, isSideloaded, permissionLabel, shortPermission } from '../lib/events.ts';
import { fmtDate, fmtDateTime, fmtNumber, parseTs } from '../lib/format.ts';
import { periodRange } from '../lib/period.ts';
import { useNow } from '../lib/useNow.ts';
import { useDevice } from '../state/device.tsx';
import { isUnsupported, useAppOps, useAppRisk } from '../state/appData.ts';
import type { AppRisk } from '../api/types.ts';
import { levelInfo } from '../lib/risk.ts';

type Tab = 'risk' | 'inventory' | 'ops' | 'permissions' | 'special' | 'notifications' | 'history';
const TABS: Tab[] = ['risk', 'inventory', 'ops', 'permissions', 'special', 'notifications', 'history'];

export default function Apps() {
  const { deviceId } = useDevice();
  const [sp] = useSearchParams();
  const [tab, setTab] = useState<Tab>(() => TABS.find((t) => t === sp.get('tab')) ?? 'risk');
  const apps = useApi(deviceId ? `apps:${deviceId}` : null, (s) => api.apps(deviceId, s));
  const risk = useAppRisk();
  const riskMap = useMemo(() => new Map((risk.data?.apps ?? []).map((r) => [r.package, r])), [risk.data]);
  const labelMap = useMemo(() => {
    const m = new Map<string, string>();
    for (const a of apps.data?.apps ?? []) if (a.label) m.set(a.package, a.label);
    return m;
  }, [apps.data]);

  return (
    <>
      <div className="page-head">
        <h1>Applications</h1>
        {apps.data?.ts && <span className="muted">Inventory of {fmtDateTime(apps.data.ts)}</span>}
      </div>
      <Tabs
        label="Sections"
        value={tab}
        onChange={setTab}
        tabs={[
          { key: 'risk', label: 'Risk' },
          { key: 'inventory', label: 'Inventory' },
          { key: 'ops', label: 'Sensitive operations' },
          { key: 'permissions', label: 'Dangerous permissions' },
          { key: 'special', label: 'Special access' },
          { key: 'notifications', label: 'Notifications' },
          { key: 'history', label: 'History' },
        ]}
      />
      {tab === 'risk' && <RiskTab risk={risk} inventory={apps.data?.apps ?? []} />}
      {tab === 'inventory' && (
        <Async state={apps} isEmpty={(d) => d.apps.length === 0} empty="No application inventory received for this device.">
          {(d) => <Inventory apps={d.apps} riskMap={riskMap} />}
        </Async>
      )}
      {tab === 'ops' && <OpsTab />}
      {tab === 'permissions' && (
        <Async state={apps} isEmpty={(d) => d.apps.length === 0} empty="No application inventory received.">
          {(d) => <Permissions apps={d.apps} />}
        </Async>
      )}
      {tab === 'special' && <SpecialAccess labelOf={(p) => labelMap.get(p)} />}
      {tab === 'notifications' && <Notifications labelOf={(p) => labelMap.get(p)} />}
      {tab === 'history' && <History labelOf={(p) => labelMap.get(p)} />}
    </>
  );
}

type Cat = 'all' | 'user' | 'system' | 'disabled' | 'suspended' | 'hidden' | 'sideload';
const CATS: { key: Cat; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'user', label: 'User' },
  { key: 'system', label: 'System' },
  { key: 'disabled', label: 'Disabled' },
  { key: 'suspended', label: 'Suspended' },
  { key: 'hidden', label: 'Hidden' },
  { key: 'sideload', label: 'Outside a store' },
];

function inCat(a: AppInfo, c: Cat): boolean {
  switch (c) {
    case 'all':
      return true;
    case 'user':
      return !a.system;
    case 'system':
      return a.system === true;
    case 'disabled':
      return a.enabled === false;
    case 'suspended':
      return a.suspended === true;
    case 'hidden':
      return a.hidden === true;
    case 'sideload':
      return isSideloaded(a);
  }
}

type Sort = 'label' | 'update' | 'perms';

function Inventory({ apps, riskMap }: { apps: AppInfo[]; riskMap: Map<string, AppRisk> }) {
  const [q, setQ] = useState('');
  const [cat, setCat] = useState<Cat>('all');
  const [installer, setInstaller] = useState('');
  const [sort, setSort] = useState<Sort>('label');
  const [shown, setShown] = useState(100);
  const [open, setOpen] = useState<string | null>(null);

  const counts = useMemo(() => Object.fromEntries(CATS.map((c) => [c.key, apps.filter((a) => inCat(a, c.key)).length])) as Record<Cat, number>, [apps]);
  const installers = useMemo(() => countByInstaller(apps), [apps]);

  const rows = useMemo(() => {
    const f = q.trim().toLowerCase();
    const out = apps.filter(
      (a) =>
        inCat(a, cat) &&
        (!installer || (a.installer || '(none)') === installer) &&
        (!f || a.package.toLowerCase().includes(f) || (a.label ?? '').toLowerCase().includes(f)),
    );
    const name = (a: AppInfo) => (a.label ?? a.package).toLowerCase();
    out.sort((a, b) =>
      sort === 'update'
        ? (parseTs(b.last_update)?.getTime() ?? 0) - (parseTs(a.last_update)?.getTime() ?? 0)
        : sort === 'perms'
          ? (b.granted_dangerous?.length ?? 0) - (a.granted_dangerous?.length ?? 0) || name(a).localeCompare(name(b), 'en')
          : name(a).localeCompare(name(b), 'en'),
    );
    return out;
  }, [apps, q, cat, installer, sort]);

  return (
    <>
      <div className="stats app-summary">
        <Stat label="Applications" value={fmtNumber(apps.length)} />
        <Stat label="User" value={fmtNumber(counts.user)} />
        <Stat label="System" value={fmtNumber(counts.system)} />
        <Stat label="Disabled" value={fmtNumber(counts.disabled)} />
        <Stat label="Suspended" value={fmtNumber(counts.suspended)} tone={counts.suspended ? 'warn' : undefined} />
        <Stat label="Outside a store" value={fmtNumber(counts.sideload)} sub="installed outside Play / Galaxy Store" tone={counts.sideload ? 'warn' : undefined} />
      </div>
      <Card className="inv-card">
        <div className="toolbar">
          <label className="filter grow">
            Search
            <input type="search" value={q} onChange={(e) => { setQ(e.target.value); setShown(100); }} placeholder="name or package" />
          </label>
          <label className="filter">
            Category
            <select value={cat} onChange={(e) => { setCat(e.target.value as Cat); setShown(100); }}>
              {CATS.map((c) => (
                <option key={c.key} value={c.key}>
                  {c.label} ({counts[c.key]})
                </option>
              ))}
            </select>
          </label>
          <label className="filter">
            Installer
            <select value={installer} onChange={(e) => { setInstaller(e.target.value); setShown(100); }}>
              <option value="">All</option>
              {installers.map((i) => (
                <option key={i.key} value={i.key}>
                  {i.key === '(none)' ? installerLabel(undefined) : installerLabel(i.key)} ({i.count})
                </option>
              ))}
            </select>
          </label>
          <label className="filter">
            Sort
            <select value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
              <option value="label">Name</option>
              <option value="update">Last update</option>
              <option value="perms">Dangerous permissions</option>
            </select>
          </label>
        </div>
        {rows.length === 0 ? (
          <Empty>No matching application.</Empty>
        ) : (
          <div className="flush">
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th scope="col">Application</th>
                    <th scope="col" className="hide-sm">Version</th>
                    <th scope="col">Installer</th>
                    <th scope="col">State</th>
                    <th scope="col" className="right">Danger. perms</th>
                    <th scope="col" className="hide-sm">Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.slice(0, shown).map((a) => {
                    const isOpen = open === a.package;
                    const perms = a.granted_dangerous ?? [];
                    return (
                      <Fragment key={a.package}>
                        <tr>
                          <td>
                            <button type="button" className="expander" aria-expanded={isOpen} aria-label={`Details of ${a.label ?? a.package}`} onClick={() => setOpen(isOpen ? null : a.package)}>
                              {isOpen ? '▾' : '▸'}
                            </button>
                            <AppName pkg={a.package} label={a.label} />
                          </td>
                          <td className="hide-sm">{a.version_name ?? '—'}</td>
                          <td>{a.system && !a.installer ? 'Preinstalled' : installerLabel(a.installer)}</td>
                          <td>
                            <span className="chip-list">
                              {a.system ? <Badge>system</Badge> : <Badge tone="info">user</Badge>}
                              {a.enabled === false && <Badge tone="warn">disabled</Badge>}
                              {a.suspended && <Badge tone="warn">suspended</Badge>}
                              {a.hidden && <Badge>hidden</Badge>}
                              {isSideloaded(a) && <Badge tone="warn">outside a store</Badge>}
                              {riskMap.has(a.package) && levelInfo(riskMap.get(a.package)?.level, riskMap.get(a.package)?.score).key !== 'low' && <RiskBadge risk={riskMap.get(a.package) as AppRisk} />}
                            </span>
                          </td>
                          <td className="right">{perms.length ? perms.length : <span className="muted">0</span>}</td>
                          <td className="hide-sm nowrap">{fmtDate(a.last_update)}</td>
                        </tr>
                        {isOpen && (
                          <tr>
                            <td colSpan={6} className="detail-cell">
                              <AppDetail app={a} risk={riskMap.get(a.package)} />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="pager">
              {rows.length > shown ? (
                <button type="button" className="btn" onClick={() => setShown(shown + 100)}>
                  Show more
                </button>
              ) : null}
              <span>
                {Math.min(shown, rows.length)} of {rows.length}
              </span>
            </div>
          </div>
        )}
      </Card>
    </>
  );
}

function AppDetail({ app, risk }: { app: AppInfo; risk: AppRisk | undefined }) {
  const perms = app.granted_dangerous ?? [];
  return (
    <div className="two-col">
      <KV
        items={[
          { k: 'Package', v: <code>{app.package}</code> },
          { k: 'Version', v: `${app.version_name ?? '—'}${app.version_code !== undefined ? ` (code ${app.version_code})` : ''}` },
          { k: 'Target SDK', v: app.target_sdk ?? '—' },
          { k: 'Installer', v: `${installerLabel(app.installer)}${app.installer ? ` (${app.installer})` : ''}` },
          { k: 'First installed', v: fmtDateTime(app.first_install) },
          { k: 'Last updated', v: fmtDateTime(app.last_update) },
          { k: 'Signature SHA-256', v: app.signer_sha256 ? <code className="break">{app.signer_sha256}</code> : '—' },
          { k: 'Risk', v: risk ? <RiskBadge risk={risk} /> : 'not scored' },
          { k: 'Detail page', v: <Link to={appSheetPath(app.package)}>Open the application's detail page</Link> },
        ]}
      />
      <div>
        <h3>Dangerous permissions granted ({perms.length})</h3>
        {perms.length === 0 ? (
          <p className="muted">None.</p>
        ) : (
          <ul className="chip-list">
            {perms.map((p) => (
              <li key={p} className="chip" title={p}>
                {permissionLabel(p)}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function RiskTab({ risk, inventory }: { risk: ReturnType<typeof useAppRisk>; inventory: AppInfo[] }) {
  if (isUnsupported(risk.error)) {
    return <Empty>This collector does not provide the risk profile yet (contract v1.2, GET /apps/risk).</Empty>;
  }
  return (
    <Async
      state={risk}
      isEmpty={(d) => d.apps.length === 0}
      empty="No risk profile received for this device. The v1.2 agent sends one at each application installation and update, then every day if the score or reasons change."
    >
      {(d) => <RiskView risks={d.apps} inventory={inventory} ts={d.ts} />}
    </Async>
  );
}

function OpsTab() {
  const { device } = useDevice();
  const ctl = usePeriod('7d');
  const range = periodRange(ctl.period);
  const ops = useAppOps(range.from, range.to);
  const unsupported = isUnsupported(ops.error);
  const running = opsCollectorState(device) === 'running';
  return (
    <>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
      </div>
      {ops.error && !unsupported ? (
        <ErrorBox message={ops.error.message} onRetry={ops.reload} />
      ) : !ops.data && !unsupported ? (
        <Loading label="Loading…" />
      ) : unsupported || !ops.data ? (
        <OpsEmpty device={device} reason="absent" />
      ) : ops.data.rows.length === 0 ? (
        <OpsEmpty device={device} reason={running ? 'empty' : 'absent'} />
      ) : (
        <OpsView rows={ops.data.rows} from={ops.data.from ?? range.from} to={ops.data.to ?? range.to} device={device} />
      )}
    </>
  );
}

const SENSITIVE = new Set(['ACCESS_BACKGROUND_LOCATION', 'RECORD_AUDIO', 'CAMERA', 'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_CALL_LOG', 'READ_CONTACTS', 'ACCESS_FINE_LOCATION']);

function Permissions({ apps }: { apps: AppInfo[] }) {
  const [userOnly, setUserOnly] = useState(true);
  const groups = useMemo(() => groupPermissions(userOnly ? apps.filter((a) => !a.system) : apps), [apps, userOnly]);
  return (
    <>
      <div className="toolbar">
        <label className="check">
          <input type="checkbox" checked={userOnly} onChange={(e) => setUserOnly(e.target.checked)} />
          User applications only
        </label>
      </div>
      {groups.length === 0 ? (
        <Empty>No dangerous permission granted.</Empty>
      ) : (
        <div className="grid">
          {groups.map((g) => (
            <Card
              key={g.permission}
              className="span-6"
              title={
                <>
                  {permissionLabel(g.permission)}{' '}
                  {SENSITIVE.has(shortPermission(g.permission)) && <Badge tone="warn">sensitive</Badge>}
                </>
              }
              actions={<span className="muted">{g.apps.length} app{g.apps.length > 1 ? 's' : ''}</span>}
            >
              <p className="hint mono">{g.permission}</p>
              <ul className="chip-list">
                {g.apps.map((a) => (
                  <li key={a.package} className="chip" title={a.package}>
                    {a.label ?? a.package}
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}

const SPECIAL: { key: string; label: string; hint: string; risky: boolean }[] = [
  { key: 'accessibility_services', label: 'Accessibility services', hint: 'Can read the screen and act in your place.', risky: true },
  { key: 'notification_listeners', label: 'Notification listeners', hint: 'Read all the notifications received.', risky: true },
  { key: 'device_admins', label: 'Device administrators', hint: 'Can enforce rules or lock/erase.', risky: true },
  { key: 'overlay_apps', label: 'Screen overlay', hint: 'Can draw over other apps.', risky: true },
  { key: 'unknown_sources_apps', label: 'Installation from unknown sources', hint: 'Can install APKs.', risky: true },
  { key: 'usage_access_apps', label: 'Usage data access', hint: 'See which apps are used.', risky: false },
  { key: 'vpn_apps', label: 'VPN applications', hint: 'Can route traffic through them.', risky: true },
];

function SpecialAccess({ labelOf }: { labelOf: (pkg: string) => string | undefined }) {
  const { deviceId } = useDevice();
  const now = useNow(300_000);
  const from = new Date(now.getTime() - 30 * 24 * 3600_000).toISOString();
  const to = now.toISOString();
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: 'app.special_access', from, to } : null, 1);
  const ev = paged.events[0];
  if (paged.loading && !ev) return <Empty>Loading…</Empty>;
  if (paged.error) return <Empty>{paged.error.message}</Empty>;
  if (!ev) return <Empty>No special access reading in the last 30 days.</Empty>;
  const defaults = isRecord(ev.data['default_apps']) ? (ev.data['default_apps'] as Record<string, unknown>) : undefined;
  return (
    <>
      <p className="muted">Reading of {fmtDateTime(ev.ts)}.</p>
      <div className="grid">
        {SPECIAL.map((s) => {
          const items = list<unknown>(ev.data, s.key).map((x) => (typeof x === 'string' ? x : JSON.stringify(x)));
          return (
            <Card
              key={s.key}
              className="span-6"
              title={s.label}
              actions={<Badge tone={items.length === 0 ? 'ok' : s.risky ? 'warn' : 'neutral'}>{items.length}</Badge>}
            >
              <p className="hint">{s.hint}</p>
              {items.length === 0 ? (
                <p className="muted">No application.</p>
              ) : (
                <ul className="findings">
                  {items.map((it) => {
                    const pkg = it.split('/')[0] ?? it;
                    return (
                      <li key={it}>
                        <span className="f-label">{labelOf(pkg) ?? pkg}</span>
                        <span className="f-val mono break">{it}</span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Card>
          );
        })}
        {defaults && (
          <Card className="span-6" title="Default applications">
            <KV items={Object.entries(defaults).map(([k, v]) => ({ k, v: typeof v === 'string' ? labelOf(v) ? `${labelOf(v)} (${v})` : v : JSON.stringify(v) }))} />
          </Card>
        )}
      </div>
    </>
  );
}

const HISTORY_TYPES = 'app.installed,app.updated,app.removed,app.permission_changed';

const NOTIF_COLLECTOR: Record<string, string> = {
  running: 'running',
  disabled: 'disabled in the app',
  unavailable: 'unavailable: the "notifier" companion APK is not installed or not authorised',
};

/** Which applications notify, and (if the option is enabled on the phone) what their notifications say. */
function Notifications({ labelOf }: { labelOf: (pkg: string) => string | undefined }) {
  const { deviceId, device } = useDevice();
  const ctl = usePeriod('7d');
  const range = periodRange(ctl.period);
  const [pkg, setPkg] = useState<string | undefined>();
  const top = useApi(deviceId ? `notif-top:${deviceId}:${range.from}:${range.to}` : null, (s) =>
    api.top({ device_id: deviceId, kind: 'notification_package', ...range, limit: 50 }, s),
  );
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: 'app.notification', q: pkg, ...range } : null, 50);
  const sum = useMemo(() => summarizeNotifications(paged.events), [paged.events]);
  const collector = device?.last_heartbeat?.collectors?.['notifications'];
  const total = (top.data?.items ?? []).reduce((a, i) => a + i.count, 0);
  const describe = (ev: WatchpostEvent) => {
    const p = str(ev.data, 'package');
    const label = p ? labelOf(p) : undefined;
    const base = describeEvent(ev);
    return label && p ? base.replace(p, `${label} (${p})`) : base;
  };
  return (
    <>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
      </div>
      <p className="hint">
        Notification collector: {collector ? (NOTIF_COLLECTOR[collector] ?? collector) : 'state unknown (no heartbeat received)'}. It is provided by the companion
        APK, separate from the agent. By default only <em>which application</em> notifies is visible; the title and text are only reported if the "Notification
        content" option is enabled in the app (numeric codes of 4 to 8 digits are then masked). They come from the applications: they are
        displayed as plain text.
      </p>
      <div className="grid grid-start">
        <Card title={`Applications that notify the most${total ? ` · ${fmtNumber(total)} notifications` : ''}`} className="span-5">
          <Async state={top} isEmpty={(d) => d.items.length === 0} empty="No notification recorded for this period (collector disabled or unavailable?).">
            {(d) => (
              <>
                <Ranking items={d.items} kind="package" labelOf={labelOf} selected={pkg} onSelect={(k) => setPkg(pkg === k ? undefined : k)} limit={20} />
                <p className="hint">Notifications posted (not removals). Click an application to filter the list.</p>
              </>
            )}
          </Async>
        </Card>
        <Card
          title={pkg ? `Notifications of ${labelOf(pkg) ?? pkg}` : 'Latest notifications'}
          className="span-7"
          actions={
            pkg ? (
              <button type="button" className="btn btn-sm" onClick={() => setPkg(undefined)}>
                All applications
              </button>
            ) : undefined
          }
        >
          {paged.events.length > 0 && (
            <p className="hint notif-sum">
              Among the latest {fmtNumber(paged.events.length)}: {fmtNumber(sum.posted)} posted, {fmtNumber(sum.removed)} removed, {fmtNumber(sum.withContent)} with
              content{sum.redacted ? `, ${fmtNumber(sum.redacted)} with hidden content` : ''}.
            </p>
          )}
          <div className="flush">
            <EventList paged={paged} describe={describe} empty="No notification for this period." />
          </div>
        </Card>
      </div>
    </>
  );
}

function History({ labelOf }: { labelOf: (pkg: string) => string | undefined }) {
  const { deviceId } = useDevice();
  const ctl = usePeriod('30d');
  const [kind, setKind] = useState('');
  const range = periodRange(ctl.period);
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: kind || HISTORY_TYPES, ...range } : null, 100);
  const describe = (ev: WatchpostEvent) => {
    const pkg = str(ev.data, 'package');
    const label = pkg ? labelOf(pkg) : undefined;
    const base = describeEvent(ev);
    return label && pkg ? base.replace(pkg, `${label} (${pkg})`) : base;
  };
  const kinds = [
    { v: '', l: 'All' },
    { v: 'app.installed', l: 'Installations' },
    { v: 'app.updated', l: 'Updates' },
    { v: 'app.removed', l: 'Removals' },
    { v: 'app.permission_changed', l: 'Permissions' },
  ];
  return (
    <>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
        <div className="seg" role="group" aria-label="Type of change">
          {kinds.map((k) => (
            <button key={k.v} type="button" className={`seg-btn${kind === k.v ? ' is-active' : ''}`} aria-pressed={kind === k.v} onClick={() => setKind(k.v)}>
              {k.l}
            </button>
          ))}
        </div>
      </div>
      <Card>
        <div className="flush">
          <EventList paged={paged} describe={describe} empty="No installation, update, removal or permission change for this period." />
        </div>
      </Card>
    </>
  );
}

