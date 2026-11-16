import { Fragment, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { AppInfo, AppRisk } from '../../api/types.ts';
import { combosOf, filterRisk, levelInfo, riskCounts, sortByScore } from '../../lib/risk.ts';
import { installerLabel } from '../../lib/events.ts';
import { fmtDateTime, fmtNumber } from '../../lib/format.ts';
import { appSheetPath, cleanText } from '../../lib/text.ts';
import { AppName } from '../AppName.tsx';
import { Badge, Card, Empty, Stat } from '../ui.tsx';
import { ComboCallout, ReasonChips, ReasonList, RiskBadge, ScoreBar } from '../risk/Risk.tsx';
import type { RiskLevel } from '../../api/types.ts';

type Sort = 'score' | 'name';

/** Texte d'installateur : « Play Store », « Hors boutique (ADB) »… d'après `installer` et `from_store`. */
export function installerText(r: Pick<AppRisk, 'installer' | 'from_store'>, inv?: AppInfo): string {
  const inst = r.installer ?? inv?.installer;
  const name = installerLabel(inst);
  if (r.from_store === false) return inst ? `Hors boutique (${name})` : 'Hors boutique';
  if (r.from_store === true) return name;
  return name;
}

/**
 * Profil de risque (`app.risk`) : classement par score, niveau, raisons en clair, combinaisons mises en évidence,
 * installateur. Le score résume des capacités, pas un comportement : une application à risque élevé n'est pas
 * forcément malveillante.
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
      return [...f].sort((a, b) => n(a).localeCompare(n(b), 'fr'));
    }
    return sortByScore(f);
  }, [risks, level, comboOnly, q, sort, inv]);

  return (
    <>
      <div className="stats app-summary">
        <Stat label="Risque élevé" value={fmtNumber(counts.high)} tone={counts.high ? 'bad' : 'ok'} />
        <Stat label="Risque moyen" value={fmtNumber(counts.medium)} tone={counts.medium ? 'warn' : undefined} />
        <Stat label="Risque faible" value={fmtNumber(counts.low)} />
        <Stat label="Combinaisons à risque" value={fmtNumber(counts.withCombo)} sub="profils de logiciel malveillant" tone={counts.withCombo ? 'bad' : 'ok'} />
      </div>
      <p className="hint">
        Chaque application est notée de 0 à 100 à l'installation, à la mise à jour, puis chaque jour si ses capacités changent{ts ? ` (dernier relevé le ${fmtDateTime(ts)})` : ''}. Le score
        mesure ce que l'application <em>pourrait</em> faire, pas ce qu'elle fait : un score élevé n'est pas une preuve de malveillance, c'est un motif de regarder de plus près. Les
        applications du système et l'agent Vigie sont notés mais plafonnés à « faible ».
      </p>
      <Card className="inv-card">
        <div className="toolbar">
          <label className="filter grow">
            Recherche
            <input type="search" value={q} onChange={(e) => { setQ(e.target.value); setShown(100); }} placeholder="nom ou paquet" />
          </label>
          <label className="filter">
            Niveau
            <select value={level} onChange={(e) => { setLevel(e.target.value as RiskLevel | 'all'); setShown(100); }}>
              <option value="all">Tous</option>
              <option value="high">Élevé</option>
              <option value="medium">Moyen et plus</option>
              <option value="low">Faible et plus</option>
            </select>
          </label>
          <label className="filter">
            Tri
            <select value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
              <option value="score">Score décroissant</option>
              <option value="name">Nom</option>
            </select>
          </label>
          <label className="check">
            <input type="checkbox" checked={comboOnly} onChange={(e) => { setComboOnly(e.target.checked); setShown(100); }} />
            Combinaisons seulement
          </label>
        </div>
        {rows.length === 0 ? (
          <Empty>Aucune application ne correspond.</Empty>
        ) : (
          <div className="flush">
            <div className="table-wrap">
              <table className="tbl risk-tbl" data-testid="risk-table">
                <thead>
                  <tr>
                    <th scope="col">Application</th>
                    <th scope="col">Score</th>
                    <th scope="col">Niveau</th>
                    <th scope="col">Raisons</th>
                    <th scope="col" className="hide-sm">Installateur</th>
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
                            <button type="button" className="expander" aria-expanded={isOpen} aria-label={`Raisons du score de ${label ?? r.package}`} onClick={() => setOpen(isOpen ? null : r.package)}>
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
                            <ReasonChips reasons={r.reasons} />
                          </td>
                          <td className="hide-sm">
                            {installerText(r, app)} {sideloaded && <Badge tone="warn">hors boutique</Badge>}
                          </td>
                        </tr>
                        {isOpen && (
                          <tr>
                            <td colSpan={5} className="detail-cell">
                              <ComboCallout reasons={r.reasons} />
                              <ReasonList reasons={r.reasons.filter((c) => combosOf([c]).length === 0)} />
                              <p className="det-actions">
                                <Link className="btn btn-sm btn-primary" to={appSheetPath(r.package)}>
                                  Fiche de l'application
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
                  Afficher plus
                </button>
              ) : null}
              <span>
                {Math.min(shown, rows.length)} sur {rows.length}
              </span>
            </div>
          </div>
        )}
      </Card>
    </>
  );
}
