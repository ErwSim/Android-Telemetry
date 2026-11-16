import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useEventStream } from '../api/useEventStream.ts';
import { usePagedDetections } from '../api/usePagedDetections.ts';
import type { VigieEvent } from '../api/types.ts';
import { DetectionCard } from '../components/detections/DetectionCard.tsx';
import { Verdict } from '../components/detections/Verdict.tsx';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Card, Empty, ErrorBox, Loading } from '../components/ui.tsx';
import { DETECTION_TYPES, applyMutes, detectionFromEvent, detectionLabel, isMuteEvent, matchesDetection, monitoringScope } from '../lib/detections.ts';
import { MutesCard, useMuting } from '../components/detections/Mute.tsx';
import { opsCollectorState } from '../components/apps/OpsView.tsx';
import { GUARDS } from '../lib/guards.ts';
import { PERIOD_LABELS, periodRange } from '../lib/period.ts';
import { useNow } from '../lib/useNow.ts';
import { useDevice } from '../state/device.tsx';
import { isUnsupported, useMutes } from '../state/appData.ts';
import { useAppLabels } from '../state/appLabels.ts';

const PERIOD_TEXT: Record<string, string> = { today: "aujourd'hui", '24h': 'les dernières 24 h', '7d': 'les 7 derniers jours', '30d': 'les 30 derniers jours', custom: 'la période choisie' };
const SEV_OPTIONS = [
  { v: 0, l: 'Toutes les gravités' },
  { v: 2, l: 'Avertissement et plus' },
  { v: 3, l: 'Critiques seulement' },
];

export default function Detections() {
  const { deviceId, device } = useDevice();
  const [sp] = useSearchParams();
  const ctl = usePeriod('7d');
  const initialType = sp.get('type') ?? '';
  const [type, setType] = useState(initialType.startsWith('detect.') ? initialType : '');
  const [sevMin, setSevMin] = useState(0);
  const range = periodRange(ctl.period);
  const now = useNow(60_000);
  const [newIds, setNewIds] = useState<ReadonlySet<string>>(new Set());

  const params = useMemo(
    () => (deviceId ? { device_id: deviceId, type: type || undefined, ...range } : null),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [deviceId, type, range.from, range.to],
  );
  const paged = usePagedDetections(params, 50);
  const addLive = paged.addLive;
  const reloadList = paged.reload;
  const mutes = useMutes();
  const reloadMutes = mutes.reload;
  const [showMuted, setShowMuted] = useState(false);
  const labelOf = useAppLabels();
  const muting = useMuting(deviceId, useCallback(() => {
    reloadList();
    reloadMutes();
  }, [reloadList, reloadMutes]));

  // Arrivée en direct : événements serveur `detect.*` du flux SSE existant. Le filtre de type est respecté ;
  // la période ne l'est que pour les périodes qui se terminent « maintenant ».
  const typeRef = useRef(type);
  useEffect(() => {
    typeRef.current = type;
  });
  const periodKey = ctl.key;
  const onEvent = useCallback(
    (ev: VigieEvent) => {
      // Sourdine posée ou levée (depuis un autre onglet, ou par le collecteur) : on relit la liste et les sourdines.
      if (isMuteEvent(ev.type)) {
        reloadList();
        reloadMutes();
        return;
      }
      const d = detectionFromEvent(ev);
      if (!d || !matchesDetection(d, { type: typeRef.current })) return;
      if (periodKey === 'custom') return;
      addLive(d);
      setNewIds((prev) => new Set(prev).add(d.id));
    },
    [addLive, periodKey, reloadList, reloadMutes],
  );
  const stream = useEventStream(true, deviceId, onEvent);

  // Les sourdines en cours s'appliquent même aux détections créées avant elles ; une détection en sourdine est repliée par défaut.
  const covered = useMemo(() => applyMutes(paged.detections, mutes.data ?? []), [paged.detections, mutes.data]);
  const mutedCount = covered.filter((d) => d.muted).length;
  const visible = useMemo(() => covered.filter((d) => matchesDetection(d, { sevMin }) && (showMuted || !d.muted)), [covered, sevMin, showMuted]);
  const mutesUnsupported = isUnsupported(mutes.error);
  const canMute = !mutesUnsupported && !!deviceId;
  const unsupported = isUnsupported(paged.error);

  return (
    <>
      <div className="page-head">
        <h1>Détections</h1>
        <span className="hint" role="status">
          <span className={`live-dot${stream === 'open' ? '' : ' is-off'}`} aria-hidden="true" />
          {stream === 'open' ? 'En direct' : stream === 'error' ? 'Connexion perdue, nouvelle tentative…' : 'Connexion…'}
        </span>
      </div>

      <div className="callout callout-info honest" role="note">
        <p>
          <strong>Ce que montre cette page.</strong> Le collecteur surveille ce que font les applications (réseau, installations, droits sensibles, applications par défaut ; envois de SMS, micro et
          caméra seulement si le collecteur expérimental d'opérations est actif) et signale les comportements anormaux, <em>quel que soit le moyen par lequel un logiciel malveillant s'est installé</em>. Ce sont des <strong>indices, pas des preuves</strong> :
          chaque détection dit ce qui a été vu, pourquoi c'est suspect, ce que cela peut être d'innocent et que faire. Les <Link to="/alertes">Alertes</Link> montrent ce
          que Wazuh en fait (règles, niveaux) : les détections y sont aussi envoyées, mais c'est ici qu'elles sont expliquées.
        </p>
      </div>

      {unsupported ? (
        <Card title="Détections indisponibles">
          <Empty>
            Ce collecteur ne fournit pas encore les détections (contrat v1.2, <code>GET /detections</code>). Mettez-le à jour pour les voir ici.
          </Empty>
        </Card>
      ) : (
        <>
          <div className="toolbar">
            <PeriodPicker ctl={ctl} />
            <label className="filter type-filter">
              Type
              <select value={type} onChange={(e) => setType(e.target.value)} aria-label="Type de détection">
                <option value="">Tous les types</option>
                {DETECTION_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {detectionLabel(t)}
                  </option>
                ))}
              </select>
            </label>
            <label className="filter">
              Gravité
              <select value={sevMin} onChange={(e) => setSevMin(Number(e.target.value))} aria-label="Gravité minimale">
                {SEV_OPTIONS.map((o) => (
                  <option key={o.v} value={o.v}>
                    {o.l}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="btn"
              onClick={() => {
                ctl.refresh();
                paged.reload();
                setNewIds(new Set());
              }}
            >
              Actualiser
            </button>
          </div>

          {paged.error && paged.detections.length === 0 ? (
            <ErrorBox message={paged.error.message} onRetry={paged.reload} />
          ) : paged.loading && paged.detections.length === 0 ? (
            <Loading label="Chargement des détections…" />
          ) : (
            <>
              <div className="stack">
                <Verdict
                  detections={covered}
                  truncated={paged.hasMore}
                  periodLabel={PERIOD_TEXT[ctl.key] ?? PERIOD_LABELS[ctl.key]}
                  scope={monitoringScope(opsCollectorState(device))}
                  mutedCount={mutedCount}
                />
                {muting.notice && (
                  <div className="state state-ok" role="status" data-testid="mute-notice">
                    {muting.notice}
                  </div>
                )}
                {mutedCount > 0 && (
                  <label className="check">
                    <input type="checkbox" checked={showMuted} onChange={(e) => setShowMuted(e.target.checked)} />
                    Afficher les détections en sourdine ({mutedCount})
                  </label>
                )}
                {type !== '' && (
                  <p className="hint">
                    Le bandeau et les compteurs ne portent que sur le type « {detectionLabel(type)} ». Choisissez « Tous les types » pour la situation d'ensemble.
                  </p>
                )}
                {visible.length === 0 ? (
                  paged.detections.length > 0 ? (
                    <Empty>Aucune détection ne correspond au filtre de gravité.</Empty>
                  ) : null
                ) : (
                  <ul className={`det-list${paged.loading ? ' is-refreshing' : ''}`} aria-label="Détections">
                    {visible.map((d, i) => (
                      <DetectionCard
                        key={d.id}
                        d={d}
                        open={i === 0 && d.severity >= 2 && !d.muted}
                        isNew={newIds.has(d.id)}
                        now={now}
                        onMute={canMute ? muting.askMute : undefined}
                        onUnmute={canMute ? (x) => void muting.unmute({ type: x.type, package: x.package ?? '' }) : undefined}
                      />
                    ))}
                  </ul>
                )}
                {paged.error && <ErrorBox message={paged.error.message} onRetry={paged.loadMore} />}
                {paged.hasMore && (
                  <div className="pager">
                    <button type="button" className="btn" onClick={paged.loadMore} disabled={paged.loadingMore}>
                      {paged.loadingMore ? 'Chargement…' : 'Charger plus'}
                    </button>
                    <span>{paged.detections.length} affichées</span>
                  </div>
                )}
                {!paged.hasMore && visible.length > 0 && <div className="pager">{visible.length} détection{visible.length > 1 ? 's' : ''} — fin de la liste</div>}
              </div>
            </>
          )}
        </>
      )}

      {!unsupported && !mutesUnsupported && mutes.data && (
        <MutesCard mutes={mutes.data} onUnmute={(m) => void muting.unmute(m)} labelOf={labelOf} />
      )}
      {muting.dialog}

      <Card title="Les gardes de l'application Vigie" className="guards-card">
        <details>
          <summary>Rappel : verrouiller à l'avance ce qu'un logiciel malveillant utiliserait</summary>
          <p className="hint">
            Les gardes se règlent <strong>sur le téléphone</strong>, dans l'écran Politique de l'application Vigie (Device Owner requis). Elles sont éteintes par défaut, réversibles
            (« Tout rétablir »), et la console ne peut ni les activer ni les désactiver : le serveur ne commande jamais le téléphone.
          </p>
          <ul className="guards">
            {GUARDS.map((g) => (
              <li key={g.key}>
                <strong>{g.label}</strong> : {g.effect}
              </li>
            ))}
          </ul>
        </details>
      </Card>
    </>
  );
}
