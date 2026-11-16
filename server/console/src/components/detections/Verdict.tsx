import { Link } from 'react-router-dom';
import type { Detection } from '../../api/types.ts';
import { countBySeverity, groupByPackage, headline, type MonitoringScope } from '../../lib/detections.ts';
import { fmtNumber } from '../../lib/format.ts';
import { cleanText } from '../../lib/text.ts';

const OK_ICON = 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm-1.500 14.500-4-4 1.400-1.400 2.600 2.600 5.600-5.600 1.400 1.400z';
const ALERT_ICON = 'M12 2 1 21h22zm1 15h-2v-2h2zm0-4h-2V9h2z';

/**
 * Status banner: "Nothing to report" or the number of detections by severity and the most
 * worrying application. Used on the Overview and at the top of the Detections page.
 */
export function Verdict({
  detections,
  truncated = false,
  periodLabel,
  linkToDetections = false,
  scope,
  mutedCount = 0,
}: {
  detections: readonly Detection[];
  truncated?: boolean;
  /** "the last 7 days" */
  periodLabel: string;
  linkToDetections?: boolean;
  /** What is and is not monitored on this phone (see `monitoringScope`): always displayed, green verdict included. */
  scope?: MonitoringScope;
  /** muted detections, not counted */
  mutedCount?: number;
}) {
  const c = countBySeverity(detections);
  const h = headline(c, truncated);
  const top = groupByPackage(detections)[0];
  const tone = h.tone;
  return (
    <section className={`verdict verdict-${tone}`} aria-label="Status" data-testid="verdict" data-tone={tone}>
      <svg className="verdict-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path d={tone === 'ok' && c.total === 0 ? OK_ICON : ALERT_ICON} fill="currentColor" />
      </svg>
      <div className="verdict-main">
        <p className="verdict-title">{c.total === 0 ? 'Nothing to report' : `${fmtNumber(c.total)}${truncated ? ' or more' : ''} detection${c.total > 1 ? 's' : ''} to examine`}</p>
        <p className="verdict-sub">
          {c.total === 0 ? (
            <>
              No detection over {periodLabel}. <span className="hint">This is not a guarantee: Watchpost sees who the phone talks to and what applications do, not the content of the exchanges.</span>
            </>
          ) : (
            <>
              {top ? (
                <>
                  Most worrying application: <strong>{cleanText(top.label, 80) || cleanText(top.package, 120)}</strong> ({top.count} detection{top.count > 1 ? 's' : ''}).{' '}
                </>
              ) : null}
              <span className="hint">Over {periodLabel}.</span>
            </>
          )}
        </p>
        {mutedCount > 0 && (
          <p className="hint" data-testid="verdict-muted">
            {mutedCount} muted detection{mutedCount > 1 ? 's' : ''} not counted (still computed, neither alerted nor notified).
          </p>
        )}
        {scope?.blind && (
          <p className="verdict-blind" data-testid="verdict-blind">
            {scope.blind}
          </p>
        )}
        {scope && (
          <p className="verdict-scope hint" data-testid="verdict-scope">
            {scope.watched} {scope.ops} <strong>{scope.guard}</strong>
          </p>
        )}
      </div>
      {c.total > 0 && (
        <div className="sev-counts" aria-label="Detections by severity">
          {c.critical > 0 && (
            <span className="sev-count sev-count-3">
              <strong>{fmtNumber(c.critical)}</strong> critical
            </span>
          )}
          {c.warning > 0 && (
            <span className="sev-count sev-count-2">
              <strong>{fmtNumber(c.warning)}</strong> warning{c.warning > 1 ? 's' : ''}
            </span>
          )}
          {c.notable > 0 && (
            <span className="sev-count">
              <strong>{fmtNumber(c.notable)}</strong> notable
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
          {c.total === 0 ? 'See the detections' : 'Examine'}
        </Link>
      )}
    </section>
  );
}
