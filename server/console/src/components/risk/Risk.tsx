import type { AppRisk } from '../../api/types.ts';
import { combosOf, levelInfo, orderReasons, reasonInfo } from '../../lib/risk.ts';
import { cleanText } from '../../lib/text.ts';
import { Badge } from '../ui.tsx';

/** Niveau de risque en mots (jamais par la couleur seule). */
export function RiskBadge({ risk }: { risk: Pick<AppRisk, 'level' | 'score'> }) {
  const lv = levelInfo(risk.level, risk.score);
  return (
    <Badge tone={lv.tone} title={`Niveau de risque ${lv.label.toLowerCase()}, score ${risk.score} sur 100`}>
      Risque {lv.label.toLowerCase()}
    </Badge>
  );
}

export function ScoreBar({ risk }: { risk: Pick<AppRisk, 'level' | 'score'> }) {
  const lv = levelInfo(risk.level, risk.score);
  return (
    <span className="risk-score" title={`Score ${risk.score} sur 100`}>
      <strong>{risk.score}</strong>
      <span className="score-bar" aria-hidden="true">
        <span className={`score-fill score-fill-${lv.key}`} style={{ width: `${Math.max(3, risk.score)}%` }} />
      </span>
      <span className="sr-only">sur 100</span>
    </span>
  );
}

/** Puces compactes : les combinaisons d'abord (en rouge), puis les premières raisons. */
export function ReasonChips({ reasons, max = 3 }: { reasons: readonly string[]; max?: number }) {
  const ordered = orderReasons(reasons);
  const shown = ordered.slice(0, max);
  const rest = ordered.length - shown.length;
  if (ordered.length === 0) return <span className="muted">aucune</span>;
  return (
    <span className="reason-chips">
      {shown.map((r) => (
        <Badge key={r.code} tone={r.combo ? 'bad' : r.tone === 'warn' ? 'warn' : 'neutral'} title={r.explain}>
          {cleanText(r.label, 80)}
        </Badge>
      ))}
      {rest > 0 && <Badge title={ordered.slice(max).map((r) => r.label).join(', ')}>+{rest}</Badge>}
    </span>
  );
}

/** Mise en évidence des combinaisons `combo_*` : ce qu'elles signifient. */
export function ComboCallout({ reasons }: { reasons: readonly string[] }) {
  const combos = combosOf(reasons);
  if (combos.length === 0) return null;
  return (
    <div className="callout callout-bad combo-callout" role="note">
      {combos.map((c) => {
        const r = reasonInfo(c);
        return (
          <p key={c}>
            <strong>{r.label}.</strong> {r.explain}
          </p>
        );
      })}
    </div>
  );
}

/** Toutes les raisons avec leur explication, et pourquoi elles peuvent être normales. */
export function ReasonList({ reasons, innocent = true }: { reasons: readonly string[]; innocent?: boolean }) {
  const list = orderReasons(reasons);
  if (list.length === 0) return <p className="muted">Aucune raison de suspicion relevée.</p>;
  return (
    <ul className="reasons">
      {list.map((r) => (
        <li key={r.code} className={`reason-${r.combo ? 'bad' : r.tone}`}>
          <span className="reason-label">
            {cleanText(r.label, 100)}
            {r.combo && <Badge tone="bad">combinaison</Badge>}
            {!r.known && <Badge>code inconnu</Badge>}
            {r.known && <span className="reason-code">{r.code}</span>}
          </span>
          <p>{r.explain}</p>
          {innocent && r.innocent && <p className="reason-innocent">Souvent légitime : {r.innocent}</p>}
        </li>
      ))}
    </ul>
  );
}
