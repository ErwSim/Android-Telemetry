import { Link } from 'react-router-dom';
import type { Detection } from '../../api/types.ts';
import { detectionDomains, detectionLabel, evidenceItems, fmtWindow, isMutable, observation, typeInfo } from '../../lib/detections.ts';
import { fmtDateTime, fmtRelative } from '../../lib/format.ts';
import { guardInfo } from '../../lib/guards.ts';
import { appSheetPath, cleanText } from '../../lib/text.ts';
import { AppName } from '../AppName.tsx';
import { Badge, SevBadge } from '../ui.tsx';

/**
 * A detection, readable by the user: what was observed (one sentence), the application, the period,
 * the evidence, why it is suspicious, what may explain it without malice, and what to do. All text
 * coming from the phone or the network (names of applications, packages, domains) is displayed as text.
 */
export function DetectionCard({
  d,
  open = false,
  isNew = false,
  now,
  showAppLink = true,
  onMute,
  onUnmute,
}: {
  d: Detection;
  open?: boolean;
  isNew?: boolean;
  now?: Date;
  /** false on the application's own detail page */
  showAppLink?: boolean;
  /** muting (§11.4): offered only for a mutable type */
  onMute?: ((d: Detection) => void) | undefined;
  onUnmute?: ((d: Detection) => void) | undefined;
}) {
  const info = typeInfo(d.type);
  const sev = Math.max(0, Math.min(3, Math.trunc(d.severity)));
  const evidence = evidenceItems(d);
  const domains = info.domains ? detectionDomains(d) : [];
  const window = fmtWindow(d.window_from, d.window_to);
  const pkg = d.package;
  const label = cleanText(d.label, 80);
  const guard = info.guard ? guardInfo(info.guard) : undefined;
  const enc = pkg ? encodeURIComponent(pkg) : '';
  return (
    <li className={`det det-sev-${sev}${isNew ? ' is-new' : ''}${d.muted ? ' is-muted' : ''}`} data-testid="detection" data-id={d.id} data-type={d.type} data-muted={d.muted ? 'true' : undefined}>
      <div className="det-head">
        <SevBadge sev={sev} />
        <Badge tone="info">{detectionLabel(d.type)}</Badge>
        {info.review && <Badge tone="warn" title="A review: this application holds a sensitive right; does it have a reason to?">To check</Badge>}
        {d.recurring && <Badge title="Already reported within 30 days: the severity is capped at 1 (Notable)">Already reported, recurring</Badge>}
        {d.muted && <Badge tone="neutral" title="Computed and recorded, but neither alerted nor notified">Muted</Badge>}
        <time className="det-time" dateTime={d.ts} title={fmtDateTime(d.ts)}>
          {fmtRelative(d.ts, now)}
        </time>
      </div>
      <h3 className="det-what">{observation(d)}</h3>
      {info.review && (
        <p className="hint det-review" data-testid="det-review">
          This is a <strong>review</strong>, not proof of abuse: this application can send SMS without going through your messaging app. Is this intended?
        </p>
      )}
      <div className="det-meta">
        {pkg ? (
          <span>
            Application: <AppName pkg={cleanText(pkg, 255)} label={label || undefined} />
          </span>
        ) : (
          <span>Application: unknown</span>
        )}
        <span>
          Period: <strong>{window ?? `detected on ${fmtDateTime(d.ts)}`}</strong>
        </span>
        {d.updated_at && d.updated_at !== d.ts && <span>Updated: {fmtRelative(d.updated_at, now)}</span>}
      </div>
      {evidence.length > 0 && (
        <ul className="chip-list det-chips" aria-label="Evidence items (preview)">
          {evidence.slice(0, 4).map((e) => (
            <li key={e.label} className="chip" title={`${e.label}: ${e.value}`}>
              <span className="muted">{e.label}:</span> <span className="break">{e.value.length > 60 ? `${e.value.slice(0, 57)}…` : e.value}</span>
            </li>
          ))}
        </ul>
      )}
      <details className="det-more" open={open}>
        <summary>Evidence, explanations and what to do</summary>
        <div className="det-body">
          {evidence.length > 0 && (
            <section>
              <h4>Evidence items</h4>
              <dl className="kv">
                {evidence.map((e) => (
                  <div key={e.label} className="kv-row">
                    <dt>{e.label}</dt>
                    <dd>{e.value}</dd>
                  </div>
                ))}
              </dl>
            </section>
          )}
          {domains.length > 0 && (
            <section>
              <h4>Domains concerned (open in Tracking to block them)</h4>
              <div className="det-domains">
                {domains.map((dom) => (
                  <Link key={dom} className="chip-link" to={`/tracking?q=${encodeURIComponent(dom)}&period=30d`}>
                    {dom}
                  </Link>
                ))}
              </div>
            </section>
          )}
          {d.summary && d.summary !== observation(d) && (
            <section>
              <h4>Collector description</h4>
              <p className="break">{cleanText(d.summary, 400)}</p>
            </section>
          )}
          <section>
            <h4>Why it is suspicious</h4>
            <p>{info.why}</p>
            {d.type === 'detect.default_app_changed' && d.evidence['role'] === 'sms' && (
              <p className="callout callout-bad" data-testid="det-sms-role">
                <strong>SMS role: the classic route of SMS trojans.</strong> An application that gets itself designated as the default SMS app obtains sending, reading and interception of SMS
                (your bank's codes included) and escapes permission refusals. Unless you chose it yourself, put the previous application back and uninstall the new one.
              </p>
            )}
          </section>
          {info.innocent.length > 0 && (
            <section>
              <h4>What innocent things it could be</h4>
              <ul>
                {info.innocent.map((t) => (
                  <li key={t}>{t}</li>
                ))}
              </ul>
            </section>
          )}
          <section>
            <h4>What to do</h4>
            <ul>
              {info.actions.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
            <div className="det-actions">
              {pkg && showAppLink && (
                <Link className="btn btn-sm btn-primary" to={appSheetPath(pkg)}>
                  Application detail page
                </Link>
              )}
              {pkg && (
                <Link className="btn btn-sm" to={`/tracking?app=${enc}&period=7d`}>
                  Its domains in Tracking
                </Link>
              )}
              {pkg && (
                <Link className="btn btn-sm" to={`/network?app=${enc}`}>
                  Its traffic in Network
                </Link>
              )}
              {d.muted && onUnmute && (
                <button type="button" className="btn btn-sm" onClick={() => onUnmute(d)}>
                  Resume reporting
                </button>
              )}
              {!d.muted && onMute && isMutable(d) && (
                <button type="button" className="btn btn-sm" onClick={() => onMute(d)} data-testid="mute-btn">
                  Stop reporting for this application
                </button>
              )}
              {(d.type === 'detect.sensor_background' || d.type === 'detect.sms_abuse') && (
                <Link className="btn btn-sm" to="/security?tab=sensors">
                  Camera and microphone (Security)
                </Link>
              )}
            </div>
          </section>
          {guard && (
            <section className="det-guard">
              <h4>Watchpost app guard that answers this risk</h4>
              <p>
                <strong>"{guard.label}" guard</strong>: {guard.effect} It is set on the phone (Policy screen): the console cannot enable it, the
                server never commands the phone.
              </p>
            </section>
          )}
        </div>
      </details>
    </li>
  );
}
