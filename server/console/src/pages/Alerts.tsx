import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Async, Card, Empty, LevelBadge, Stat } from '../components/ui.tsx';
import { fmtDateTime, fmtNumber } from '../lib/format.ts';
import { periodRange } from '../lib/period.ts';
import { detectionLabel, isDetectionType } from '../lib/detections.ts';
import { useDevice } from '../state/device.tsx';

const LEVELS = [
  { v: 0, l: 'All levels' },
  { v: 5, l: 'Level 5 and above' },
  { v: 7, l: 'Level 7 and above' },
  { v: 10, l: 'Level 10 and above' },
  { v: 12, l: 'Level 12 and above (critical)' },
];

export default function Alerts() {
  const { devices } = useDevice();
  const ctl = usePeriod('7d');
  const [level, setLevel] = useState(0);
  const range = periodRange(ctl.period);
  const state = useApi(`alerts:${range.from}:${range.to}:${level}`, (s) =>
    api.alerts({ ...range, ...(level > 0 ? { level_min: level } : {}), limit: 500 }, s),
  );
  const nameOf = (id: string | undefined) => (id ? (devices.find((d) => d.device_id === id)?.name ?? id) : '—');
  return (
    <>
      <div className="page-head">
        <h1>Wazuh alerts</h1>
      </div>
      <p className="hint net-intro">
        This page shows the alerts that <strong>Wazuh</strong> raised (Wazuh rules and levels, all topics combined). The abnormal application behaviours computed
        by Watchpost (mass SMS, threat domains, background microphone...) are <strong>explained and ranked on the <Link to="/detections">Detections</Link> page</strong>: Wazuh also
        receives them, hence their presence here when it is configured.
      </p>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
        <label className="filter">
          Level
          <select value={level} onChange={(e) => setLevel(Number(e.target.value))}>
            {LEVELS.map((l) => (
              <option key={l.v} value={l.v}>
                {l.l}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="btn" onClick={() => { ctl.refresh(); state.reload(); }}>
          Refresh
        </button>
      </div>
      <Async state={state} loadingLabel="Querying Wazuh…">
        {(d) =>
          !d.wazuh ? (
            <Card title="Wazuh not configured">
              <p>
                The collector is not connected to the Wazuh indexer: there are therefore no alerts to display. Events are
                still collected and can be viewed in the event log.
              </p>
              <p className="hint">
                To enable this page, set <code>WATCHPOST_WAZUH_INDEXER_URL</code> (and credentials) on the collector side.
              </p>
            </Card>
          ) : d.alerts.length === 0 ? (
            <Empty>No alerts for this period.</Empty>
          ) : (
            <>
              <div className="stats alert-stats">
                <Stat label="Alerts" value={fmtNumber(d.alerts.length)} />
                <Stat label="Level ≥ 10" value={fmtNumber(d.alerts.filter((a) => a.level >= 10).length)} tone={d.alerts.some((a) => a.level >= 10) ? 'bad' : undefined} />
                <Stat label="Level 7-9" value={fmtNumber(d.alerts.filter((a) => a.level >= 7 && a.level < 10).length)} />
              </div>
              <Card>
                <div className="flush">
                  <div className="table-wrap">
                    <table className="tbl">
                      <thead>
                        <tr>
                          <th scope="col">Date</th>
                          <th scope="col">Level</th>
                          <th scope="col">Rule</th>
                          <th scope="col">Description</th>
                          <th scope="col" className="hide-sm">Type</th>
                          <th scope="col" className="hide-sm">Device</th>
                        </tr>
                      </thead>
                      <tbody>
                        {d.alerts.map((a, i) => (
                          <tr key={`${a.ts}-${a.rule_id ?? ''}-${i}`} className={a.level >= 12 ? 'sev-3' : a.level >= 8 ? 'sev-2' : ''}>
                            <td className="nowrap">{fmtDateTime(a.ts)}</td>
                            <td>
                              <LevelBadge level={a.level} />
                            </td>
                            <td className="mono">{a.rule_id ?? '—'}</td>
                            <td className="break">
                              {a.description ?? '—'}
                              {a.type && isDetectionType(a.type) && (
                                <>
                                  {' '}
                                  <Link to={`/detections?type=${encodeURIComponent(a.type)}`}>See the "{detectionLabel(a.type)}" detection</Link>
                                </>
                              )}
                            </td>
                            <td className="hide-sm mono">{a.type ?? '—'}</td>
                            <td className="hide-sm">{nameOf(a.device_id)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </Card>
            </>
          )
        }
      </Async>
    </>
  );
}
