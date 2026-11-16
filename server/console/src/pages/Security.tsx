import { useMemo, useState, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { usePagedEvents } from '../api/usePagedEvents.ts';
import type { Posture } from '../api/types.ts';
import { EventList } from '../components/EventList.tsx';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Async, Badge, Card, Empty, StatusPill, Tabs } from '../components/ui.tsx';
import { countKeys } from '../lib/agg.ts';
import { bool, isRecord, str } from '../lib/data.ts';
import { roleChanges, roleLabel, roleWhy } from '../lib/roles.ts';
import { appSheetPath, cleanText } from '../lib/text.ts';
import { fmtDateTime, fmtValue } from '../lib/format.ts';
import { evaluatePosture, overallStatus, POSTURE_LABELS } from '../lib/posture.ts';
import { periodRange, type PeriodKey } from '../lib/period.ts';
import { useAppLabels } from '../state/appLabels.ts';
import { useDevice } from '../state/device.tsx';

type Tab = 'posture' | 'roles' | 'log' | 'sensors' | 'keyguard' | 'certs' | 'radio' | 'policy';
const TABS: Tab[] = ['posture', 'roles', 'log', 'sensors', 'keyguard', 'certs', 'radio', 'policy'];

export default function Security() {
  const [sp] = useSearchParams();
  const [tab, setTab] = useState<Tab>(() => TABS.find((t) => t === sp.get('tab')) ?? 'posture');
  return (
    <>
      <div className="page-head">
        <h1>Security</h1>
      </div>
      <Tabs
        label="Sections"
        value={tab}
        onChange={setTab}
        tabs={[
          { key: 'posture', label: 'Posture' },
          { key: 'roles', label: 'Default roles' },
          { key: 'log', label: 'System log' },
          { key: 'sensors', label: 'Camera and microphone' },
          { key: 'keyguard', label: 'Unlocks' },
          { key: 'certs', label: 'CA certificates' },
          { key: 'radio', label: 'Cellular and BLE' },
          { key: 'policy', label: 'Policy applied' },
        ]}
      />
      {tab === 'posture' && <PostureTab />}
      {tab === 'roles' && <RolesTab />}
      {tab === 'log' && (
        <EventSection title="System security log (security.log)" types="security.log" searchable hint="Native Android log (Device Owner): authentication, APK installation, key injection, etc." />
      )}
      {tab === 'sensors' && <SensorsTab />}
      {tab === 'keyguard' && (
        <EventSection title="Unlocks" types="security.keyguard" q="unlock_failed" qLabel="failures only" hint="Only failed unlock attempts are listed." defaultPeriod="7d" />
      )}
      {tab === 'certs' && <CertsTab />}
      {tab === 'radio' && (
        <EventSection
          title="Cellular network and Bluetooth trackers"
          types="net.cell_security,net.ble_tracker"
          hint="2G downgrade, null encryption, identifier disclosure, AirTag / SmartTag / Tile beacons detected over time."
          defaultPeriod="7d"
        />
      )}
      {tab === 'policy' && (
        <EventSection title="Policy actions applied (security.policy)" types="security.policy" hint="Each action performed locally by the agent (private DNS, disabled packages, denied permissions...)." defaultPeriod="30d" />
      )}
    </>
  );
}

/**
 * Default roles (SMS, phone, browser, assistant, home, call screening): who holds them and
 * the change history (`app.role`). Malware often tries to become the SMS app
 * or the call screening app: a change that you did not make deserves a look.
 */
function RolesTab() {
  const labelOf = useAppLabels();
  const { deviceId } = useDevice();
  const ctl = usePeriod('30d');
  const range = periodRange(ctl.period);
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: 'app.role', ...range } : null, 200);
  const special = usePagedEvents(deviceId ? { device_id: deviceId, type: 'app.special_access', ...range } : null, 1);
  const changes = useMemo(() => roleChanges(paged.events), [paged.events]);
  const defaults = special.events[0]?.data['default_apps'];
  const current = isRecord(defaults) ? Object.entries(defaults).filter(([, v]) => typeof v === 'string' && v !== '') : [];
  const pkgName = (p: string | undefined) => {
    if (!p) return <span className="muted">none</span>;
    const l = labelOf(p);
    return (
      <Link className="role-pkg" to={appSheetPath(p)}>
        {l ? `${cleanText(l, 80)} (${cleanText(p, 160)})` : cleanText(p, 160)}
      </Link>
    );
  };
  return (
    <>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
      </div>
      <div className="grid grid-start">
        <Card title="Current roles" className="span-5">
          {special.loading && !special.events[0] ? (
            <Empty>Loading…</Empty>
          ) : current.length === 0 ? (
            <Empty>No reading of the default applications for this period.</Empty>
          ) : (
            <ul className="role-list">
              {current.map(([role, p]) => (
                <li key={role}>
                  <strong>{roleLabel(role)}</strong>: {pkgName(p as string)}
                  {roleWhy(role) && <p className="hint">{roleWhy(role)}</p>}
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Change history" className="span-7">
          {changes.length === 0 && !paged.loading ? (
            <Empty>No default role change for this period.</Empty>
          ) : (
            <div className="flush">
              <div className="table-wrap">
                <table className="tbl" data-testid="roles-table">
                  <thead>
                    <tr>
                      <th scope="col">Date</th>
                      <th scope="col">Role</th>
                      <th scope="col">Change</th>
                    </tr>
                  </thead>
                  <tbody>
                    {changes.map((c) => (
                      <tr key={c.id} className={c.role === 'sms' || c.role === 'call_screening' ? 'sev-2' : ''}>
                        <td className="nowrap">{fmtDateTime(c.ts)}</td>
                        <td>{roleLabel(c.role)}</td>
                        <td className="break">
                          {pkgName(c.old)} <span className="role-arrow">→</span> <strong>{pkgName(c.new)}</strong>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          <p className="hint">
            A change that you did not make yourself (especially the SMS app or call screening) should be checked on the new application's detail page.
          </p>
        </Card>
      </div>
    </>
  );
}

function PostureTab() {
  const { deviceId } = useDevice();
  const state = useApi(deviceId ? `posture:${deviceId}` : null, (s) => api.posture(deviceId, s));
  return (
    <Async state={state} isEmpty={(d) => Object.keys(d.current ?? {}).length === 0} empty="No security posture received for this device.">
      {(d) => <PostureView current={d.current} ts={d.ts} changes={d.changes ?? []} />}
    </Async>
  );
}

function PostureView({ current, ts, changes }: { current: Posture; ts: string | undefined; changes: { ts: string; field: string; old?: unknown; new?: unknown }[] }) {
  const findings = useMemo(() => evaluatePosture(current), [current]);
  const status = overallStatus(findings);
  const certs = current.user_ca_certs ?? [];
  return (
    <div className="grid">
      <Card title="Current posture" className="span-7" actions={<>{ts && <span className="hint">as of {fmtDateTime(ts)}</span>}<StatusPill status={status} /></>}>
        <ul className="findings">
          {findings.map((f) => (
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
        {certs.length > 0 && (
          <>
            <h3 className="section-title">Fingerprints of the user CAs</h3>
            <ul className="findings">
              {certs.map((c) => (
                <li key={c}>
                  <span className="f-label mono break">{c}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </Card>
      <Card title="Change history" className="span-5">
        {changes.length === 0 ? (
          <Empty>No posture change recorded.</Empty>
        ) : (
          <div className="flush">
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th scope="col">Date</th>
                    <th scope="col">Setting</th>
                    <th scope="col">Change</th>
                  </tr>
                </thead>
                <tbody>
                  {changes.map((c, i) => (
                    <tr key={`${c.ts}-${c.field}-${i}`}>
                      <td className="nowrap">{fmtDateTime(c.ts)}</td>
                      <td>{POSTURE_LABELS[c.field] ?? c.field}</td>
                      <td className="break">
                        {fmtChangeValue(c.old)} → <strong>{fmtChangeValue(c.new)}</strong>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

/** Value of a posture change; fingerprint lists are abbreviated. */
function fmtChangeValue(v: unknown): string {
  if (Array.isArray(v)) {
    if (v.length === 0) return 'none';
    return v.map((x) => (typeof x === 'string' && x.length > 20 ? `${x.slice(0, 12)}…` : fmtValue(x))).join(', ');
  }
  return fmtValue(v);
}

function SensorsTab() {
  const labelOf = useAppLabels();
  const { deviceId } = useDevice();
  const ctl = usePeriod('7d');
  const range = periodRange(ctl.period);
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: 'sensor.', ...range } : null, 200);
  const usage = useMemo(() => {
    const cam = paged.events.filter((e) => e.type === 'sensor.camera' && bool(e.data, 'in_use')).map((e) => str(e.data, 'package') ?? 'unknown');
    const mic = paged.events.filter((e) => e.type === 'sensor.microphone' && bool(e.data, 'recording')).map((e) => str(e.data, 'package') ?? 'unknown');
    return { cam: countKeys(cam, 6), mic: countKeys(mic, 6) };
  }, [paged.events]);
  return (
    <>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
      </div>
      <div className="grid">
        <Card title="Camera uses" className="span-6">
          <Usage items={usage.cam} labelOf={labelOf} />
        </Card>
        <Card title="Microphone uses" className="span-6">
          <Usage items={usage.mic} labelOf={labelOf} />
        </Card>
      </div>
      <Card title="Detail (sensor.*)">
        <div className="flush">
          <EventList paged={paged} empty="No camera or microphone use for this period." />
        </div>
      </Card>
    </>
  );
}

function Usage({ items, labelOf }: { items: { key: string; count: number }[]; labelOf: (p: string | undefined) => string | undefined }) {
  if (items.length === 0) return <p className="muted">No access among the loaded events.</p>;
  return (
    <ul className="findings">
      {items.map((i) => (
        <li key={i.key}>
          <Badge>{i.count}×</Badge>
          <span className="f-label">{labelOf(i.key) ?? i.key}</span>
          {labelOf(i.key) && <span className="f-val mono">{i.key}</span>}
        </li>
      ))}
    </ul>
  );
}

function CertsTab() {
  const { device } = useDevice();
  const certs = device?.last_posture?.user_ca_certs ?? [];
  return (
    <>
      <Card title="CA certificates installed by the user (current posture)" className="certs-now">
        {device?.last_posture === undefined ? (
          <Empty>Posture unknown.</Empty>
        ) : certs.length === 0 ? (
          <p>No user CA certificate: good state.</p>
        ) : (
          <ul className="findings">
            {certs.map((c) => (
              <li key={c}>
                <Badge tone="bad">User CA</Badge>
                <span className="f-label mono break">{c}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <div className="spacer" />
      <EventSection title="Additions and removals (security.ca_cert)" types="security.ca_cert" hint="An added CA can allow encrypted traffic to be intercepted." defaultPeriod="30d" />
    </>
  );
}

function EventSection({
  title,
  types,
  q,
  qLabel,
  hint,
  searchable = false,
  defaultPeriod = '7d',
}: {
  title: string;
  types: string;
  q?: string;
  qLabel?: string;
  hint?: ReactNode;
  searchable?: boolean;
  defaultPeriod?: PeriodKey;
}) {
  const { deviceId } = useDevice();
  const ctl = usePeriod(defaultPeriod);
  const [search, setSearch] = useState('');
  const range = periodRange(ctl.period);
  const text = (q ?? search).trim();
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: types, q: text || undefined, ...range } : null, 100);
  return (
    <>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
        {searchable && (
          <label className="filter grow">
            Search
            <input type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="tag, field, value…" />
          </label>
        )}
        {qLabel && <Badge>{qLabel}</Badge>}
      </div>
      <Card title={title}>
        {hint && <p className="hint">{hint}</p>}
        <div className="flush">
          <EventList paged={paged} empty="Nothing to report for this period." />
        </div>
      </Card>
    </>
  );
}
