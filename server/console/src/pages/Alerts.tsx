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
  { v: 0, l: 'Tous les niveaux' },
  { v: 5, l: 'Niveau 5 et plus' },
  { v: 7, l: 'Niveau 7 et plus' },
  { v: 10, l: 'Niveau 10 et plus' },
  { v: 12, l: 'Niveau 12 et plus (critique)' },
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
        <h1>Alertes Wazuh</h1>
      </div>
      <p className="hint net-intro">
        Cette page montre ce que <strong>Wazuh</strong> a levé comme alertes (règles et niveaux de Wazuh, tous sujets confondus). Les comportements anormaux des applications calculés
        par Vigie (SMS en masse, domaines de menaces, micro en arrière-plan…) sont <strong>expliqués et classés sur la page <Link to="/detections">Détections</Link></strong> : Wazuh les
        reçoit aussi, d'où leur présence ici quand il est configuré.
      </p>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
        <label className="filter">
          Niveau
          <select value={level} onChange={(e) => setLevel(Number(e.target.value))}>
            {LEVELS.map((l) => (
              <option key={l.v} value={l.v}>
                {l.l}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="btn" onClick={() => { ctl.refresh(); state.reload(); }}>
          Actualiser
        </button>
      </div>
      <Async state={state} loadingLabel="Interrogation de Wazuh…">
        {(d) =>
          !d.wazuh ? (
            <Card title="Wazuh non configuré">
              <p>
                Le collecteur n'est pas relié à l'indexeur Wazuh : il n'y a donc pas d'alertes à afficher. Les événements sont
                néanmoins collectés et consultables dans le journal.
              </p>
              <p className="hint">
                Pour activer cette page, renseignez <code>VIGIE_WAZUH_INDEXER_URL</code> (et identifiants) côté collecteur.
              </p>
            </Card>
          ) : d.alerts.length === 0 ? (
            <Empty>Aucune alerte sur cette période.</Empty>
          ) : (
            <>
              <div className="stats alert-stats">
                <Stat label="Alertes" value={fmtNumber(d.alerts.length)} />
                <Stat label="Niveau ≥ 10" value={fmtNumber(d.alerts.filter((a) => a.level >= 10).length)} tone={d.alerts.some((a) => a.level >= 10) ? 'bad' : undefined} />
                <Stat label="Niveau 7-9" value={fmtNumber(d.alerts.filter((a) => a.level >= 7 && a.level < 10).length)} />
              </div>
              <Card>
                <div className="flush">
                  <div className="table-wrap">
                    <table className="tbl">
                      <thead>
                        <tr>
                          <th scope="col">Date</th>
                          <th scope="col">Niveau</th>
                          <th scope="col">Règle</th>
                          <th scope="col">Description</th>
                          <th scope="col" className="hide-sm">Type</th>
                          <th scope="col" className="hide-sm">Appareil</th>
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
                                  <Link to={`/detections?type=${encodeURIComponent(a.type)}`}>Voir la détection « {detectionLabel(a.type)} »</Link>
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
