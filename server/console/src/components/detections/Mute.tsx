import { useCallback, useState, type ReactNode } from 'react';
import { api } from '../../api/endpoints.ts';
import { ApiError } from '../../api/client.ts';
import type { Detection, DetectionMute } from '../../api/types.ts';
import { appNameOf, detectionLabel, muteErrorMessage } from '../../lib/detections.ts';
import { fmtDateTime } from '../../lib/format.ts';
import { cleanText } from '../../lib/text.ts';
import { Dialog } from '../Dialog.tsx';
import { Card, Empty } from '../ui.tsx';

export const MUTE_REASON_MAX = 200;

export interface MuteTarget {
  type: string;
  package: string;
  /** readable name for the dialog text */
  name: string;
}

/**
 * Muting a (detection type, application) pair: a confirmation that says what it does and does not
 * do, then the API call. `onChanged` reloads the list and the mutes.
 */
export function useMuting(deviceId: string | undefined, onChanged: () => void): {
  askMute: (d: Detection) => void;
  unmute: (t: { type: string; package: string }) => Promise<void>;
  dialog: ReactNode;
  notice: string | undefined;
} {
  const [target, setTarget] = useState<MuteTarget | undefined>();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [notice, setNotice] = useState<string | undefined>();

  const askMute = useCallback((d: Detection) => {
    if (!d.package) return;
    setReason('');
    setError(undefined);
    setTarget({ type: d.type, package: d.package, name: appNameOf(d) });
  }, []);

  const confirm = async () => {
    if (!target || !deviceId || busy) return;
    setBusy(true);
    setError(undefined);
    try {
      const body: { device_id: string; type: string; package: string; reason?: string } = { device_id: deviceId, type: target.type, package: target.package };
      const r = reason.trim();
      if (r) body.reason = r;
      await api.muteDetection(body);
      setNotice(`"${detectionLabel(target.type)}" will no longer be reported for ${target.name}. It is still computed and visible, collapsed, on this page.`);
      setTarget(undefined);
      onChanged();
    } catch (e) {
      setError(e instanceof ApiError ? muteErrorMessage(e) : 'Muting failed.');
    } finally {
      setBusy(false);
    }
  };

  const unmute = useCallback(
    async (t: { type: string; package: string }) => {
      if (!deviceId) return;
      try {
        await api.unmuteDetection({ device_id: deviceId, type: t.type, package: t.package });
        setNotice(`Mute lifted: "${detectionLabel(t.type)}" will be reported again for this application.`);
      } catch (e) {
        setNotice(e instanceof ApiError ? muteErrorMessage(e) : 'Lifting the mute failed.');
      } finally {
        onChanged();
      }
    },
    [deviceId, onChanged],
  );

  const dialog = target ? (
    <Dialog
      title="Stop reporting for this application"
      busy={busy}
      onClose={() => setTarget(undefined)}
      footer={
        <>
          <button type="button" className="btn" onClick={() => setTarget(undefined)} disabled={busy}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" onClick={() => void confirm()} disabled={busy}>
            {busy ? 'Saving…' : 'Mute'}
          </button>
        </>
      }
    >
      <p>
        You are about to mute <strong>"{detectionLabel(target.type)}"</strong> for <strong className="break">{target.name}</strong> (<span className="mono break">{cleanText(target.package, 255)}</span>).
      </p>
      <div className="callout callout-info" data-testid="mute-explain">
        <p>
          <strong>What this changes.</strong> The detection is still <strong>computed and recorded</strong>: you will find it here, collapsed, with a filter to see it again. It will
          <strong> no longer be sent to Wazuh or notified</strong>: you will no longer get an alert for this type of detection on this application.
        </p>
        <p>
          <strong>What this does not change.</strong> Other detection types, other applications and the risk profile are not affected. Some detections cannot be muted (abnormal SMS
          sending, default application change). You can lift the mute at any time, in "Current mutes".
        </p>
      </div>
      <label className="field">
        <span>
          <strong>Reason</strong> <span className="muted">(optional, to remind yourself)</span>
        </span>
        <textarea rows={2} maxLength={MUTE_REASON_MAX} value={reason} onChange={(e) => setReason(e.target.value)} disabled={busy} placeholder="E.g. browser with secure DNS, intended" />
        <span className="counter">
          {reason.length} / {MUTE_REASON_MAX}
        </span>
      </label>
      {error && (
        <div className="state state-error" role="alert">
          {error}
        </div>
      )}
    </Dialog>
  ) : null;

  return { askMute, unmute, dialog, notice };
}

/** Current mutes, with their lifting. */
export function MutesCard({ mutes, onUnmute, labelOf }: { mutes: readonly DetectionMute[]; onUnmute: (m: DetectionMute) => void; labelOf?: (pkg: string) => string | undefined }) {
  return (
    <Card title={`Current mutes (${mutes.length})`} className="mutes-card" id="mutes">
      {mutes.length === 0 ? (
        <Empty>No mutes: all detections are reported.</Empty>
      ) : (
        <div className="flush">
          <div className="table-wrap">
            <table className="tbl" data-testid="mutes-table">
              <thead>
                <tr>
                  <th scope="col">Detection</th>
                  <th scope="col">Application</th>
                  <th scope="col" className="hide-sm">Reason</th>
                  <th scope="col" className="hide-sm">Since</th>
                  <th scope="col">
                    <span className="sr-only">Lift</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {mutes.map((m) => {
                  const name = cleanText(m.label, 80) || cleanText(labelOf?.(m.package), 80);
                  return (
                    <tr key={`${m.type}|${m.package}`}>
                      <td>{detectionLabel(m.type)}</td>
                      <td className="break">
                        {name && <strong>{name}</strong>} {name && <br />}
                        <span className="mono">{cleanText(m.package, 255)}</span>
                      </td>
                      <td className="hide-sm break">{m.reason ? cleanText(m.reason, MUTE_REASON_MAX) : <span className="muted">—</span>}</td>
                      <td className="hide-sm nowrap">
                        {m.created_at ? fmtDateTime(m.created_at) : '—'}
                        {m.created_by ? <span className="muted"> · {cleanText(m.created_by, 60)}</span> : null}
                      </td>
                      <td>
                        <button type="button" className="btn btn-sm" onClick={() => onUnmute(m)}>
                          Lift the mute
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Card>
  );
}
