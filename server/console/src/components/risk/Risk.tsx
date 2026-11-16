import type { AppRisk } from '../../api/types.ts';
import { combosOf, grantState, levelInfo, orderReasons, reasonInfo } from '../../lib/risk.ts';
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
export function ReasonChips({ reasons, granted, max = 3 }: { reasons: readonly string[]; granted?: readonly string[] | undefined; max?: number }) {
  const ordered = orderReasons(reasons);
  const shown = ordered.slice(0, max);
  const rest = ordered.length - shown.length;
  if (ordered.length === 0) return <span className="muted">aucune</span>;
  return (
    <span className="reason-chips">
      {shown.map((r) => {
        const g = grantState({ granted: granted as string[] | undefined }, r.code);
        return (
          <span key={r.code} className={g === 'declared' ? 'badge-declared' : undefined}>
            <Badge tone={r.combo ? 'bad' : r.tone === 'warn' ? 'warn' : 'neutral'} title={`${r.explain}${g === 'declared' ? ' (demandée, pas accordée)' : g === 'granted' ? ' (accordée)' : ''}`}>
              {cleanText(r.label, 80)}
              {g === 'declared' ? ' · demandée' : ''}
            </Badge>
          </span>
        );
      })}
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
export function ReasonList({ reasons, granted, innocent = true }: { reasons: readonly string[]; granted?: readonly string[] | undefined; innocent?: boolean }) {
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
            {grantState({ granted: granted as string[] | undefined }, r.code) === 'granted' && <Badge tone="warn" title="Le système a accordé cette capacité à l'application">Accordée</Badge>}
            {grantState({ granted: granted as string[] | undefined }, r.code) === 'declared' && <Badge title="L'application la demande (déclarée dans son paquet) mais ne l'a pas obtenue : par exemple refusée par une garde ou la quarantaine de l'application Vigie">Demandée, pas accordée</Badge>}
            {r.known && <span className="reason-code">{r.code}</span>}
          </span>
          <p>{r.explain}</p>
          {innocent && r.innocent && <p className="reason-innocent">Souvent légitime : {r.innocent}</p>}
        </li>
      ))}
    </ul>
  );
}

/** Explication de la différence entre capacité déclarée et accordée (contrat §11.4), à placer sous un profil de risque. */
export function GrantNote({ hasGranted }: { hasGranted: boolean }) {
  return (
    <p className="hint" data-testid="grant-note">
      Le score porte sur ce que l'application <strong>demande</strong> (capacités déclarées dans son paquet), pas seulement sur ce qu'elle a obtenu : il reste élevé quand une garde de
      l'application Vigie ou la quarantaine empêche l'octroi.{' '}
      {hasGranted ? (
        <>
          Chaque capacité est marquée <strong>accordée</strong> (le système l'a donnée) ou <strong>demandée, pas accordée</strong> (trait pointillé dans les listes).
        </>
      ) : (
        <>Ce téléphone ne dit pas quelles capacités ont été accordées : seule l'intention est connue.</>
      )}
    </p>
  );
}
