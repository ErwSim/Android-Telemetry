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
  /** nom lisible pour le texte du dialogue */
  name: string;
}

/**
 * Mise en sourdine d'un couple (type de détection, application) : demande de confirmation qui dit ce que cela fait et ne
 * fait pas, puis appel de l'API. `onChanged` recharge la liste et les sourdines.
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
      setNotice(`« ${detectionLabel(target.type)} » ne sera plus signalé pour ${target.name}. Elle reste calculée et visible, repliée, dans cette page.`);
      setTarget(undefined);
      onChanged();
    } catch (e) {
      setError(e instanceof ApiError ? muteErrorMessage(e) : 'Mise en sourdine impossible.');
    } finally {
      setBusy(false);
    }
  };

  const unmute = useCallback(
    async (t: { type: string; package: string }) => {
      if (!deviceId) return;
      try {
        await api.unmuteDetection({ device_id: deviceId, type: t.type, package: t.package });
        setNotice(`Sourdine levée : « ${detectionLabel(t.type)} » sera de nouveau signalé pour cette application.`);
      } catch (e) {
        setNotice(e instanceof ApiError ? muteErrorMessage(e) : 'Levée de la sourdine impossible.');
      } finally {
        onChanged();
      }
    },
    [deviceId, onChanged],
  );

  const dialog = target ? (
    <Dialog
      title="Ne plus signaler pour cette application"
      busy={busy}
      onClose={() => setTarget(undefined)}
      footer={
        <>
          <button type="button" className="btn" onClick={() => setTarget(undefined)} disabled={busy}>
            Annuler
          </button>
          <button type="button" className="btn btn-primary" onClick={() => void confirm()} disabled={busy}>
            {busy ? 'Enregistrement…' : 'Mettre en sourdine'}
          </button>
        </>
      }
    >
      <p>
        Vous allez mettre en sourdine <strong>« {detectionLabel(target.type)} »</strong> pour <strong className="break">{target.name}</strong> (<span className="mono break">{cleanText(target.package, 255)}</span>).
      </p>
      <div className="callout callout-info" data-testid="mute-explain">
        <p>
          <strong>Ce que cela change.</strong> La détection reste <strong>calculée et enregistrée</strong> : vous la retrouvez ici, repliée, avec un filtre pour la revoir. Elle ne sera
          <strong> plus envoyée vers Wazuh ni notifiée</strong> : vous n'aurez plus d'alerte pour ce type de détection sur cette application.
        </p>
        <p>
          <strong>Ce que cela ne change pas.</strong> Les autres types de détection, les autres applications et le profil de risque ne sont pas touchés. Certaines détections ne peuvent pas être mises en sourdine (envoi de SMS
          anormal, changement d'application par défaut). Vous pouvez lever la sourdine à tout moment, dans « Sourdines en cours ».
        </p>
      </div>
      <label className="field">
        <span>
          <strong>Motif</strong> <span className="muted">(facultatif, pour vous en souvenir)</span>
        </span>
        <textarea rows={2} maxLength={MUTE_REASON_MAX} value={reason} onChange={(e) => setReason(e.target.value)} disabled={busy} placeholder="Ex. : navigateur avec DNS sécurisé, voulu" />
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

/** Sourdines en cours, avec leur levée. */
export function MutesCard({ mutes, onUnmute, labelOf }: { mutes: readonly DetectionMute[]; onUnmute: (m: DetectionMute) => void; labelOf?: (pkg: string) => string | undefined }) {
  return (
    <Card title={`Sourdines en cours (${mutes.length})`} className="mutes-card" id="sourdines">
      {mutes.length === 0 ? (
        <Empty>Aucune sourdine : toutes les détections sont signalées.</Empty>
      ) : (
        <div className="flush">
          <div className="table-wrap">
            <table className="tbl" data-testid="mutes-table">
              <thead>
                <tr>
                  <th scope="col">Détection</th>
                  <th scope="col">Application</th>
                  <th scope="col" className="hide-sm">Motif</th>
                  <th scope="col" className="hide-sm">Depuis</th>
                  <th scope="col">
                    <span className="sr-only">Lever</span>
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
                          Lever la sourdine
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
