import { useState } from 'react';
import { api } from '../../api/endpoints.ts';
import { ApiError } from '../../api/client.ts';
import type { TrackingSummary } from '../../api/types.ts';
import { levelTexts, trackingErrorMessage } from '../../lib/tracking.ts';
import { Dialog } from '../Dialog.tsx';
import { Badge } from '../ui.tsx';

/** Blocking level: three described levels, confirmation before changing AdGuard Home's lists. */
export function LevelCard({ summary, onChanged }: { summary: TrackingSummary; onChanged: (level: string) => void }) {
  const levels = levelTexts(summary.levels);
  const current = summary.level;
  const [choice, setChoice] = useState<string | undefined>();
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const off = !summary.adguard;
  const selected = choice ?? current;
  const target = levels.find((l) => l.key === selected);
  const from = levels.find((l) => l.key === current);
  const changed = !!selected && selected !== current;

  const apply = async () => {
    if (!selected) return;
    setBusy(true);
    setError(undefined);
    try {
      await api.setTrackingLevel(selected);
      setConfirm(false);
      setChoice(undefined);
      onChanged(selected);
    } catch (e) {
      setError(e instanceof ApiError ? `The level was not changed. ${trackingErrorMessage(e)}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <fieldset className="levels" disabled={off}>
        <legend className="sr-only">Blocking level</legend>
        {levels.map((l) => (
          <label key={l.key} className={`level${selected === l.key ? ' is-sel' : ''}`}>
            <input type="radio" name="level" value={l.key} checked={selected === l.key} onChange={() => setChoice(l.key)} />
            <span>
              <strong>{l.name}</strong> {current === l.key && <Badge tone="ok">Current</Badge>}
              <br />
              <span className="muted">{l.description}</span>
            </span>
          </label>
        ))}
      </fieldset>
      {!off && !current && (
        <p className="hint">No level matches the current state of AdGuard Home's lists (set by hand?). Choosing a level brings them back in line.</p>
      )}
      {off ? (
        <p className="hint">The level can be neither read nor changed: AdGuard Home is not reachable from the collector.</p>
      ) : (
        <div className="level-actions">
          <button type="button" className="btn btn-primary" disabled={!changed} onClick={() => setConfirm(true)}>
            Apply the {target ? `"${target.name}" ` : ''}level…
          </button>
          {changed && (
            <button type="button" className="btn" onClick={() => setChoice(undefined)}>
              Cancel
            </button>
          )}
        </div>
      )}
      {confirm && target && (
        <Dialog
          title={`Switch to the "${target.name}" level?`}
          busy={busy}
          onClose={() => setConfirm(false)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setConfirm(false)} disabled={busy}>
                Cancel
              </button>
              <button type="button" className="btn btn-primary" onClick={() => void apply()} disabled={busy}>
                {busy ? 'Applying…' : 'Change the level'}
              </button>
            </>
          }
        >
          <p>
            {from ? (
              <>
                From the <strong>{from.name}</strong> level to the <strong>{target.name}</strong> level.
              </>
            ) : (
              <>
                <strong>{target.name}</strong> level.
              </>
            )}
          </p>
          <p className="muted">{target.description}</p>
          <div className="callout callout-info">
            <ul>
              <li>The collector enables or disables blocklists in AdGuard Home; your manual rules (Block / Allow) are kept.</li>
              <li>The change applies to everything that uses this DNS, and takes effect on the next queries (past counts do not change).</li>
              <li>It is reversible: just choose the previous level again.</li>
              {target.key === 'strict' && <li>The strict level may prevent some applications from working fully: try it for a few days.</li>}
            </ul>
          </div>
          {error && (
            <div className="state state-error" role="alert">
              {error}
            </div>
          )}
        </Dialog>
      )}
      {!confirm && error && (
        <div className="state state-error" role="alert">
          {error}
        </div>
      )}
    </>
  );
}
