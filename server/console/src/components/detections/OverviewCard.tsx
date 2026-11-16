import { Link } from 'react-router-dom';
import { api } from '../../api/endpoints.ts';
import { useApi } from '../../api/useApi.ts';
import { useEventStream } from '../../api/useEventStream.ts';
import type { Detection } from '../../api/types.ts';
import { Verdict } from './Verdict.tsx';
import { Badge, Card, ErrorBox, Loading, SevBadge } from '../ui.tsx';
import { active, applyMutes, detectionLabel, isDetectionType, observation, monitoringScope } from '../../lib/detections.ts';
import { opsCollectorState } from '../apps/OpsView.tsx';
import { useDevice } from '../../state/device.tsx';
import { fmtRelative } from '../../lib/format.ts';
import { cleanText } from '../../lib/text.ts';
import { isUnsupported, useMutes } from '../../state/appData.ts';

const MAX = 200;

/**
 * Vue d'ensemble : « Rien à signaler » ou le nombre de détections récentes par gravité, avec les plus récentes.
 * Se met à jour quand le flux SSE apporte une détection.
 */
export function DetectionsOverview({ deviceId, now }: { deviceId: string; now: Date }) {
  const { device } = useDevice();
  // Fenêtre arrondie à 5 minutes : la clé ne change pas à chaque minute (pas de clignotement de chargement).
  const slot = Math.floor(now.getTime() / 300_000) * 300_000;
  const from = new Date(slot - 7 * 24 * 3600_000).toISOString();
  const to = new Date(slot + 300_000).toISOString();
  const state = useApi(`ov-det:${deviceId}:${slot}`, (s) => api.detections({ device_id: deviceId, from, to, limit: MAX }, s));
  const reload = state.reload;
  const mutes = useMutes();
  useEventStream(true, deviceId, (ev) => {
    if (isDetectionType(ev.type)) reload();
  });

  if (state.error && isUnsupported(state.error)) {
    return (
      <Card title="Détections" className="ov-det">
        <p className="muted">Ce collecteur ne fournit pas encore les détections (contrat v1.2).</p>
      </Card>
    );
  }
  if (state.error) {
    return (
      <Card title="Détections" className="ov-det">
        <ErrorBox message={state.error.message} onRetry={reload} />
      </Card>
    );
  }
  if (!state.data) {
    return (
      <Card title="Détections" className="ov-det">
        <Loading label="Chargement des détections…" />
      </Card>
    );
  }
  const list: Detection[] = applyMutes(state.data.detections, mutes.data ?? []);
  const recent = [...active(list)].sort((a, b) => b.severity - a.severity || (a.ts < b.ts ? 1 : -1)).slice(0, 3);
  return (
    <div className="ov-det" data-testid="overview-detections">
      <Verdict detections={list} truncated={!!state.data.next_cursor} periodLabel="les 7 derniers jours" linkToDetections scope={monitoringScope(opsCollectorState(device))} mutedCount={list.filter((d) => d.muted).length} />
      {recent.length > 0 && (
        <ul className="findings ov-det-list" aria-label="Détections les plus graves">
          {recent.map((d) => (
            <li key={d.id}>
              <SevBadge sev={d.severity} short />
              <span className="f-label break">{observation(d)}</span>
              <span className="f-val">
                <Badge tone="info">{detectionLabel(d.type)}</Badge> {cleanText(d.label, 80) || cleanText(d.package, 120)} · {fmtRelative(d.ts, now)}
              </span>
            </li>
          ))}
          <li>
            <Link to="/detections">Voir toutes les détections</Link>
          </li>
        </ul>
      )}
    </div>
  );
}
