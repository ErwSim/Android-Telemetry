import { Link } from 'react-router-dom';
import type { Detection } from '../../api/types.ts';
import { countBySeverity, groupByPackage, headline } from '../../lib/detections.ts';
import { fmtNumber } from '../../lib/format.ts';
import { cleanText } from '../../lib/text.ts';

const OK_ICON = 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm-1.500 14.500-4-4 1.400-1.400 2.600 2.600 5.600-5.600 1.400 1.400z';
const ALERT_ICON = 'M12 2 1 21h22zm1 15h-2v-2h2zm0-4h-2V9h2z';

/**
 * Bandeau de situation : « Rien à signaler » ou le nombre de détections par gravité et l'application la plus
 * préoccupante. Sert sur la vue d'ensemble et en tête de la page Détections.
 */
export function Verdict({
  detections,
  truncated = false,
  periodLabel,
  linkToDetections = false,
  blindSpot = null,
}: {
  detections: readonly Detection[];
  truncated?: boolean;
  /** « les 7 derniers jours » */
  periodLabel: string;
  linkToDetections?: boolean;
  /** Ce qui n'est pas surveillé sur ce téléphone (voir `opsBlindSpot`) : toujours affiché, verdict vert compris. */
  blindSpot?: string | null;
}) {
  const c = countBySeverity(detections);
  const h = headline(c, truncated);
  const top = groupByPackage(detections)[0];
  const tone = h.tone;
  return (
    <section className={`verdict verdict-${tone}`} aria-label="Situation" data-testid="verdict" data-tone={tone}>
      <svg className="verdict-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path d={tone === 'ok' && c.total === 0 ? OK_ICON : ALERT_ICON} fill="currentColor" />
      </svg>
      <div className="verdict-main">
        <p className="verdict-title">{c.total === 0 ? 'Rien à signaler' : `${fmtNumber(c.total)}${truncated ? ' ou plus' : ''} détection${c.total > 1 ? 's' : ''} à examiner`}</p>
        <p className="verdict-sub">
          {c.total === 0 ? (
            <>
              Aucune détection sur {periodLabel}. <span className="hint">Ce n'est pas une garantie : Vigie voit à qui le téléphone parle et ce que les applications font, pas le contenu des échanges.</span>
            </>
          ) : (
            <>
              {top ? (
                <>
                  Application la plus préoccupante : <strong>{cleanText(top.label, 80) || cleanText(top.package, 120)}</strong> ({top.count} détection{top.count > 1 ? 's' : ''}).{' '}
                </>
              ) : null}
              <span className="hint">Sur {periodLabel}.</span>
            </>
          )}
        </p>
        {blindSpot && (
          <p className="verdict-blind" data-testid="verdict-blind">
            {blindSpot}
          </p>
        )}
      </div>
      {c.total > 0 && (
        <div className="sev-counts" aria-label="Détections par gravité">
          {c.critical > 0 && (
            <span className="sev-count sev-count-3">
              <strong>{fmtNumber(c.critical)}</strong> critique{c.critical > 1 ? 's' : ''}
            </span>
          )}
          {c.warning > 0 && (
            <span className="sev-count sev-count-2">
              <strong>{fmtNumber(c.warning)}</strong> avertissement{c.warning > 1 ? 's' : ''}
            </span>
          )}
          {c.notable > 0 && (
            <span className="sev-count">
              <strong>{fmtNumber(c.notable)}</strong> à noter
            </span>
          )}
          {c.info > 0 && (
            <span className="sev-count sev-count-0">
              <strong>{fmtNumber(c.info)}</strong> info
            </span>
          )}
        </div>
      )}
      {linkToDetections && (
        <Link className="btn btn-sm" to="/detections">
          {c.total === 0 ? 'Voir les détections' : 'Examiner'}
        </Link>
      )}
    </section>
  );
}
