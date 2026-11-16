import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useEventStream } from '../api/useEventStream.ts';
import { usePagedDetections } from '../api/usePagedDetections.ts';
import type { VigieEvent } from '../api/types.ts';
import { DetectionCard } from '../components/detections/DetectionCard.tsx';
import { Verdict } from '../components/detections/Verdict.tsx';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Card, Empty, ErrorBox, Loading } from '../components/ui.tsx';
import { DETECTION_TYPES, detectionFromEvent, detectionLabel, matchesDetection } from '../lib/detections.ts';
import { GUARDS } from '../lib/guards.ts';
import { PERIOD_LABELS, periodRange } from '../lib/period.ts';
import { useNow } from '../lib/useNow.ts';
import { useDevice } from '../state/device.tsx';
import { isUnsupported } from '../state/appData.ts';

const PERIOD_TEXT: Record<string, string> = { today: "aujourd'hui", '24h': 'les dernières 24 h', '7d': 'les 7 derniers jours', '30d': 'les 30 derniers jours', custom: 'la période choisie' };
const SEV_OPTIONS = [
  { v: 0, l: 'Toutes les gravités' },
  { v: 2, l: 'Avertissement et plus' },
  { v: 3, l: 'Critiques seulement' },
];

export default function Detections() {
  const { deviceId } = useDevice();
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

  // Arrivée en direct : événements serveur `detect.*` du flux SSE existant. Le filtre de type est respecté ;
  // la période ne l'est que pour les périodes qui se terminent « maintenant ».
  const typeRef = useRef(type);
  useEffect(() => {
    typeRef.current = type;
  });
  const periodKey = ctl.key;
  const onEvent = useCallback(
    (ev: VigieEvent) => {
      const d = detectionFromEvent(ev);
      if (!d || !matchesDetection(d, { type: typeRef.current })) return;
      if (periodKey === 'custom') return;
      addLive(d);
      setNewIds((prev) => new Set(prev).add(d.id));
    },
    [addLive, periodKey],
  );
  const stream = useEventStream(true, deviceId, onEvent);

  const visible = useMemo(() => paged.detections.filter((d) => matchesDetection(d, { sevMin })), [paged.detections, sevMin]);
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
          <strong>Ce que montre cette page.</strong> Le collecteur surveille ce que font les applications (réseau, SMS, micro, caméra, installations) et signale les
          comportements anormaux, <em>quel que soit le moyen par lequel un logiciel malveillant s'est installé</em>. Ce sont des <strong>indices, pas des preuves</strong> :
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
                <Verdict detections={paged.detections} truncated={paged.hasMore} periodLabel={PERIOD_TEXT[ctl.key] ?? PERIOD_LABELS[ctl.key]} />
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
                      <DetectionCard key={d.id} d={d} open={i === 0 && d.severity >= 2} isNew={newIds.has(d.id)} now={now} />
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
