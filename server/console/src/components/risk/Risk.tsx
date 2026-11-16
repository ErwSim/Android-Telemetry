import type { AppRisk } from '../../api/types.ts';
import { combosOf, grantState, levelInfo, orderReasons, reasonInfo } from '../../lib/risk.ts';
import { cleanText } from '../../lib/text.ts';
import { Badge } from '../ui.tsx';

/** Risk level in words (never by colour alone). */
export function RiskBadge({ risk }: { risk: Pick<AppRisk, 'level' | 'score'> }) {
  const lv = levelInfo(risk.level, risk.score);
  return (
    <Badge tone={lv.tone} title={`${lv.label} risk level, score ${risk.score} out of 100`}>
      {lv.label} risk
    </Badge>
  );
}

export function ScoreBar({ risk }: { risk: Pick<AppRisk, 'level' | 'score'> }) {
  const lv = levelInfo(risk.level, risk.score);
  return (
    <span className="risk-score" title={`Score ${risk.score} out of 100`}>
      <strong>{risk.score}</strong>
      <span className="score-bar" aria-hidden="true">
        <span className={`score-fill score-fill-${lv.key}`} style={{ width: `${Math.max(3, risk.score)}%` }} />
      </span>
      <span className="sr-only">out of 100</span>
    </span>
  );
}

/** Compact chips: combinations first (in red), then the first reasons. */
export function ReasonChips({ reasons, granted, max = 3 }: { reasons: readonly string[]; granted?: readonly string[] | undefined; max?: number }) {
  const ordered = orderReasons(reasons);
  const shown = ordered.slice(0, max);
  const rest = ordered.length - shown.length;
  if (ordered.length === 0) return <span className="muted">none</span>;
  return (
    <span className="reason-chips">
      {shown.map((r) => {
        const g = grantState({ granted: granted as string[] | undefined }, r.code);
        return (
          <span key={r.code} className={g === 'declared' ? 'badge-declared' : undefined}>
            <Badge tone={r.combo ? 'bad' : r.tone === 'warn' ? 'warn' : 'neutral'} title={`${r.explain}${g === 'declared' ? ' (requested, not granted)' : g === 'granted' ? ' (granted)' : ''}`}>
              {cleanText(r.label, 80)}
              {g === 'declared' ? ' · requested' : ''}
            </Badge>
          </span>
        );
      })}
      {rest > 0 && <Badge title={ordered.slice(max).map((r) => r.label).join(', ')}>+{rest}</Badge>}
    </span>
  );
}

/** Highlighting of `combo_*` combinations: what they mean. */
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

/** All the reasons with their explanation, and why they may be normal. */
export function ReasonList({ reasons, granted, innocent = true }: { reasons: readonly string[]; granted?: readonly string[] | undefined; innocent?: boolean }) {
  const list = orderReasons(reasons);
  if (list.length === 0) return <p className="muted">No reason for suspicion found.</p>;
  return (
    <ul className="reasons">
      {list.map((r) => (
        <li key={r.code} className={`reason-${r.combo ? 'bad' : r.tone}`}>
          <span className="reason-label">
            {cleanText(r.label, 100)}
            {r.combo && <Badge tone="bad">combination</Badge>}
            {!r.known && <Badge>unknown code</Badge>}
            {grantState({ granted: granted as string[] | undefined }, r.code) === 'granted' && <Badge tone="warn" title="The system granted this capability to the application">Granted</Badge>}
            {grantState({ granted: granted as string[] | undefined }, r.code) === 'declared' && <Badge title="The application requests it (declared in its package) but did not obtain it: for example refused by a guard or by the quarantine of the Watchpost app">Requested, not granted</Badge>}
            {r.known && <span className="reason-code">{r.code}</span>}
          </span>
          <p>{r.explain}</p>
          {innocent && r.innocent && <p className="reason-innocent">Often legitimate: {r.innocent}</p>}
        </li>
      ))}
    </ul>
  );
}

/** Explanation of the difference between a declared and a granted capability (contract §11.4), to place under a risk profile. */
export function GrantNote({ hasGranted }: { hasGranted: boolean }) {
  return (
    <p className="hint" data-testid="grant-note">
      The score reflects what the application <strong>requests</strong> (capabilities declared in its package), not only what it obtained: it stays high when a guard of
      the Watchpost app or the quarantine prevents granting.{' '}
      {hasGranted ? (
        <>
          Each capability is marked <strong>granted</strong> (the system gave it) or <strong>requested, not granted</strong> (dashed outline in the lists).
        </>
      ) : (
        <>This phone does not say which capabilities were granted: only the intent is known.</>
      )}
    </p>
  );
}
