import { Fragment, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { AppInfo, AppRisk } from '../../api/types.ts';
import { combosOf, filterRisk, levelInfo, riskCounts, sortByScore } from '../../lib/risk.ts';
import { installerLabel } from '../../lib/events.ts';
import { fmtDateTime, fmtNumber } from '../../lib/format.ts';
import { appSheetPath, cleanText } from '../../lib/text.ts';
import { AppName } from '../AppName.tsx';
import { Badge, Card, Empty, Stat } from '../ui.tsx';
import { ComboCallout, GrantNote, ReasonChips, ReasonList, RiskBadge, ScoreBar } from '../risk/Risk.tsx';
import type { RiskLevel } from '../../api/types.ts';

type Sort = 'score' | 'name';

/** Installer text: "Play Store", "Outside a store (ADB)"... from `installer` and `from_store`. */
export function installerText(r: Pick<AppRisk, 'installer' | 'from_store'>, inv?: AppInfo): string {
  const inst = r.installer ?? inv?.installer;
  const name = installerLabel(inst);
  if (r.from_store === false) return inst ? `Outside a store (${name})` : 'Outside a store';
  if (r.from_store === true) return name;
  return name;
}

/**
 * Risk profile (`app.risk`): ranking by score, level, reasons in plain words, highlighted combinations,
 * installer. The score summarises capabilities, not behaviour: a high-risk application is not
 * necessarily malicious.
 */
export function RiskView({ risks, inventory, ts }: { risks: AppRisk[]; inventory: AppInfo[]; ts: string | undefined }) {
  const [q, setQ] = useState('');
  const [level, setLevel] = useState<RiskLevel | 'all'>('all');
  const [comboOnly, setComboOnly] = useState(false);
  const [sort, setSort] = useState<Sort>('score');
  const [open, setOpen] = useState<string | null>(null);
  const [shown, setShown] = useState(100);

  const inv = useMemo(() => new Map(inventory.map((a) => [a.package, a])), [inventory]);
  const counts = useMemo(() => riskCounts(risks), [risks]);
  const rows = useMemo(() => {
    const f = filterRisk(risks, { level, comboOnly, q });
    if (sort === 'name') {
      const n = (a: AppRisk) => (a.label ?? inv.get(a.package)?.label ?? a.package).toLowerCase();
      return [...f].sort((a, b) => n(a).localeCompare(n(b), 'en'));
    }
    return sortByScore(f);
  }, [risks, level, comboOnly, q, sort, inv]);

  return (
    <>
      <div className="stats app-summary">
        <Stat label="High risk" value={fmtNumber(counts.high)} tone={counts.high ? 'bad' : 'ok'} />
        <Stat label="Medium risk" value={fmtNumber(counts.medium)} tone={counts.medium ? 'warn' : undefined} />
        <Stat label="Low risk" value={fmtNumber(counts.low)} />
        <Stat label="Risky combinations" value={fmtNumber(counts.withCombo)} sub="malware profiles" tone={counts.withCombo ? 'bad' : 'ok'} />
      </div>
      <p className="hint">
        Each application is scored from 0 to 100 at installation, at update, then every day if its capabilities change{ts ? ` (last reading on ${fmtDateTime(ts)})` : ''}. The score
        measures what the application <em>could</em> do, not what it does: a high score is not proof of malice, it is a reason to look more closely. System
        applications and the Watchpost agent are scored but capped at "low".
      </p>
      <GrantNote hasGranted={risks.some((r) => r.granted !== undefined)} />
      <Card className="inv-card">
        <div className="toolbar">
          <label className="filter grow">
            Search
            <input type="search" value={q} onChange={(e) => { setQ(e.target.value); setShown(100); }} placeholder="name or package" />
          </label>
          <label className="filter">
            Level
            <select value={level} onChange={(e) => { setLevel(e.target.value as RiskLevel | 'all'); setShown(100); }}>
              <option value="all">All</option>
              <option value="high">High</option>
              <option value="medium">Medium and above</option>
              <option value="low">Low and above</option>
            </select>
          </label>
          <label className="filter">
            Sort
            <select value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
              <option value="score">Score, descending</option>
              <option value="name">Name</option>
            </select>
          </label>
          <label className="check">
            <input type="checkbox" checked={comboOnly} onChange={(e) => { setComboOnly(e.target.checked); setShown(100); }} />
            Combinations only
          </label>
        </div>
        {rows.length === 0 ? (
          <Empty>No matching application.</Empty>
        ) : (
          <div className="flush">
            <div className="table-wrap">
              <table className="tbl risk-tbl" data-testid="risk-table">
                <thead>
                  <tr>
                    <th scope="col">Application</th>
                    <th scope="col">Score</th>
                    <th scope="col">Level</th>
                    <th scope="col">Reasons</th>
                    <th scope="col" className="hide-sm">Installer</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.slice(0, shown).map((r) => {
                    const isOpen = open === r.package;
                    const lv = levelInfo(r.level, r.score);
                    const app = inv.get(r.package);
                    const label = cleanText(r.label ?? app?.label, 80) || undefined;
                    const sideloaded = r.from_store === false;
                    return (
                      <Fragment key={r.package}>
                        <tr className={`risk-${lv.key}`} data-risk={lv.key}>
                          <td className="c-app">
                            <button type="button" className="expander" aria-expanded={isOpen} aria-label={`Reasons for the score of ${label ?? r.package}`} onClick={() => setOpen(isOpen ? null : r.package)}>
                              {isOpen ? '▾' : '▸'}
                            </button>
                            <AppName pkg={cleanText(r.package, 255)} label={label} />
                          </td>
                          <td className="c-score">
                            <ScoreBar risk={r} />
                          </td>
                          <td className="c-level">
                            <RiskBadge risk={r} />
                          </td>
                          <td className="c-reasons">
                            <ReasonChips reasons={r.reasons} granted={r.granted} />
                          </td>
                          <td className="hide-sm">
                            {installerText(r, app)} {sideloaded && <Badge tone="warn">outside a store</Badge>}
                          </td>
                        </tr>
                        {isOpen && (
                          <tr>
                            <td colSpan={5} className="detail-cell">
                              <ComboCallout reasons={r.reasons} />
                              <ReasonList reasons={r.reasons.filter((c) => combosOf([c]).length === 0)} granted={r.granted} />
                              <p className="det-actions">
                                <Link className="btn btn-sm btn-primary" to={appSheetPath(r.package)}>
                                  Application detail page
                                </Link>
                              </p>
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
