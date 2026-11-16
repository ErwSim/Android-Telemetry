import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { AppOpsRow, Device } from '../../api/types.ts';
import { HEADLINE_OPS, backgroundShare, groupByApp, groupByOp, opInfo } from '../../lib/ops.ts';
import { fmtDateTime, fmtNumber } from '../../lib/format.ts';
import { appSheetPath, cleanText } from '../../lib/text.ts';
import { AppName } from '../AppName.tsx';
import { Badge, Card, Empty } from '../ui.tsx';

/** State of the sensitive operations collector in the last heartbeat (exact name not fixed by the contract: we look for "ops"). */
export function opsCollectorState(device: Device | undefined): string | undefined {
  const c = device?.last_heartbeat?.collectors;
  if (!c) return undefined;
  const key = Object.keys(c).find((k) => /ops/i.test(k));
  return key ? c[key] : undefined;
}

const STATE_TEXT: Record<string, string> = {
  running: 'running',
  disabled: 'disabled in the app',
  unavailable: 'unavailable (DUMP permission not granted?)',
};

/**
 * Empty state of the sensitive operations usage. These data are experimental and off by default: the page
 * says how to enable them, without ever presenting an absence of data as an absence of use.
 */
export function OpsEmpty({ device, reason }: { device: Device | undefined; reason: 'absent' | 'empty' }) {
  const st = opsCollectorState(device);
  return (
    <div className="state-ops" data-testid="ops-empty">
      <div className="callout callout-info">
        <p>
          <strong>{reason === 'absent' ? 'No sensitive operations usage data for this device.' : 'No sensitive operation used during this period.'}</strong>{' '}
          {reason === 'empty' && 'If the collector is active, this is rather a good sign: the reading is hourly and only mentions operations actually used.'}
        </p>
        {st && <p>Collector state on the phone: <strong>{STATE_TEXT[st] ?? st}</strong>.</p>}
      </div>
      <p>
        This measurement is <strong>experimental</strong> and <strong>off by default</strong>: it reads Android's operation counters (who sent an SMS, placed a call, read the
        contacts, used the microphone or the camera, and how many times, including in the background) thanks to the <code>DUMP</code> permission, which Android only grants from the command line. To enable it:
      </p>
      <ol className="ops-steps">
        <li>
          Connect the phone to the computer (USB debugging) and run <code>./scripts/grant-adb-permissions.sh</code> (or the <code>.ps1</code> version on Windows): it grants{' '}
          <code>DUMP</code> to Watchpost (equivalent: <code>adb shell pm grant io.github.erwsim.watchpost android.permission.DUMP</code>).
        </li>
        <li>
          In the Watchpost app, <em>Collectors</em> tab: enable the experimental "Sensitive operations usage" collector.
        </li>
        <li>Wait for the next hour: the first reading arrives within the hour, then every hour.</li>
      </ol>
      <p className="hint">
        As long as these data are missing, the "abnormal SMS" and "microphone or camera in the background" detections cannot trigger; the other detections (network, new applications) and the
        risk profile work without them. The absence of these data is <strong>not</strong> proof that no application sends SMS: also check the risk profile and the
        permissions of each application.
      </p>
    </div>
  );
}

/** Who sends SMS, places calls, reads contacts, uses the microphone or the camera, and how many times, including in the background. */
export function OpsView({ rows, from, to, device }: { rows: AppOpsRow[]; from?: string | undefined; to?: string | undefined; device: Device | undefined }) {
  const [opFilter, setOpFilter] = useState('');
  const byOp = useMemo(() => groupByOp(rows), [rows]);
  const byApp = useMemo(() => groupByApp(rows), [rows]);
  const flat = useMemo(() => {
    const out: { package: string; label?: string; op: string; count: number; background: number; rejected: number; lastTs?: string }[] = [];
    for (const a of byApp) for (const o of a.ops) if (!opFilter || o.op === opFilter) out.push({ package: a.package, ...(a.label ? { label: a.label } : {}), ...o });
    return out.sort((x, y) => y.count - x.count || x.package.localeCompare(y.package));
  }, [byApp, opFilter]);
  const hasRejected = flat.some((r) => r.rejected > 0);
  const present = new Map(byOp.map((o) => [o.op, o]));
  const headline = HEADLINE_OPS.map((op) => present.get(op) ?? { op, count: 0, background: 0, apps: [] });

  if (rows.length === 0) return <OpsEmpty device={device} reason="empty" />;
  return (
    <>
      {byApp.some((a) => a.rejected > 0) && (
        <div className="callout callout-info" role="note">
          <p>
            <strong>"Refused"</strong>: uses that the system prevented (for example by the SMS guard of the Watchpost app). The application tried: the attempt remains a signal, even without effect.
          </p>
        </div>
      )}
      <p className="hint">
        <strong>Experimental</strong> data{from && to ? ` from ${fmtDateTime(from)} to ${fmtDateTime(to)}` : ''}: Android operation counters read every hour. A "background" use
        is made while the application is not on screen.
      </p>
      <div className="ops-cards" data-testid="ops-cards">
        {headline.map((o) => {
          const info = opInfo(o.op);
          const bg = o.background > 0;
          return (
            <div key={o.op} className={`op-card${bg ? ' is-bg' : ''}`}>
              <h3>{info.label}</h3>
              <div className="op-n">{fmtNumber(o.count)}</div>
              <div className="op-bg">{o.count === 0 ? 'no use' : bg ? `of which ${fmtNumber(o.background)} in the background` : 'none in the background'}</div>
              {o.apps.length > 0 && (
                <ol>
                  {o.apps.slice(0, 3).map((a) => (
                    <li key={a.package} className="break">
                      {cleanText(a.label, 60) || cleanText(a.package, 120)}: {fmtNumber(a.count)}
                    </li>
                  ))}
                </ol>
              )}
            </div>
          );
        })}
      </div>
      <Card title="Detail per application and per operation">
        <div className="toolbar">
          <ul className="chip-list" aria-label="Filter by operation">
            <li>
              <button type="button" className="chip-btn" aria-pressed={opFilter === ''} onClick={() => setOpFilter('')}>
                All
              </button>
            </li>
            {byOp.map((o) => (
              <li key={o.op}>
                <button type="button" className="chip-btn" aria-pressed={opFilter === o.op} onClick={() => setOpFilter(opFilter === o.op ? '' : o.op)}>
                  {opInfo(o.op).label}
                </button>
              </li>
            ))}
          </ul>
        </div>
        {flat.length === 0 ? (
          <Empty>No use for this operation.</Empty>
        ) : (
          <div className="flush">
            <div className="table-wrap">
              <table className="tbl" data-testid="ops-table">
                <thead>
                  <tr>
                    <th scope="col">Application</th>
                    <th scope="col">Operation</th>
                    <th scope="col" className="right">Uses</th>
                    <th scope="col" className="right">In the background</th>
                    {hasRejected && <th scope="col" className="right">Refused</th>}
                    <th scope="col" className="hide-sm">Last use</th>
                  </tr>
                </thead>
                <tbody>
                  {flat.map((r) => {
                    const share = backgroundShare(r.count, r.background);
                    return (
                      <tr key={`${r.package}|${r.op}`} className={share >= 0.5 && r.background > 0 ? 'sev-2' : ''}>
                        <td>
                          <Link className="app-link" to={appSheetPath(r.package)}>
                            <AppName pkg={cleanText(r.package, 255)} label={cleanText(r.label, 80) || undefined} />
                          </Link>
                        </td>
                        <td>{opInfo(r.op).label}</td>
                        <td className="right">{fmtNumber(r.count)}</td>
                        <td className="right">
                          {r.background > 0 ? (
                            <>
                              {fmtNumber(r.background)} {share >= 0.5 && <Badge tone="warn">mostly in the background</Badge>}
                            </>
                          ) : (
                            <span className="muted">0</span>
                          )}
                        </td>
                        {hasRejected && <td className="right">{r.rejected > 0 ? <strong>{fmtNumber(r.rejected)}</strong> : <span className="muted">0</span>}</td>}
                        <td className="hide-sm nowrap">{r.lastTs ? fmtDateTime(r.lastTs) : '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Card>
    </>
  );
}
