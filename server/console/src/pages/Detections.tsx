import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useEventStream } from '../api/useEventStream.ts';
import { usePagedDetections } from '../api/usePagedDetections.ts';
import type { WatchpostEvent } from '../api/types.ts';
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

const PERIOD_TEXT: Record<string, string> = { today: 'today', '24h': 'the last 24 h', '7d': 'the last 7 days', '30d': 'the last 30 days', custom: 'the selected period' };
const SEV_OPTIONS = [
  { v: 0, l: 'All severities' },
  { v: 2, l: 'Warning and above' },
  { v: 3, l: 'Critical only' },
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

  // Live arrival: server `detect.*` events of the existing SSE stream. The type filter is respected;
  // the period only for periods that end "now".
  const typeRef = useRef(type);
  useEffect(() => {
    typeRef.current = type;
  });
  const periodKey = ctl.key;
  const onEvent = useCallback(
    (ev: WatchpostEvent) => {
      // Mute set or lifted (from another tab, or by the collector): we read the list and the mutes again.
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

  // Current mutes also apply to detections created before them; a muted detection is collapsed by default.
  const covered = useMemo(() => applyMutes(paged.detections, mutes.data ?? []), [paged.detections, mutes.data]);
  const mutedCount = covered.filter((d) => d.muted).length;
  const visible = useMemo(() => covered.filter((d) => matchesDetection(d, { sevMin }) && (showMuted || !d.muted)), [covered, sevMin, showMuted]);
  const mutesUnsupported = isUnsupported(mutes.error);
  const canMute = !mutesUnsupported && !!deviceId;
  const unsupported = isUnsupported(paged.error);

  return (
    <>
      <div className="page-head">
        <h1>Detections</h1>
        <span className="hint" role="status">
          <span className={`live-dot${stream === 'open' ? '' : ' is-off'}`} aria-hidden="true" />
          {stream === 'open' ? 'Live' : stream === 'error' ? 'Connection lost, retrying…' : 'Connecting…'}
        </span>
      </div>

      <div className="callout callout-info honest" role="note">
        <p>
          <strong>What this page shows.</strong> The collector monitors what applications do (network, installations, sensitive rights, default applications; SMS sending, microphone and
          camera only if the experimental operations collector is active) and flags abnormal behaviours, <em>whatever the way malware got installed</em>. These are <strong>clues, not proof</strong>:
          each detection says what was seen, why it is suspicious, what innocent thing it could be and what to do. The <Link to="/alerts">Alerts</Link> show what
          Wazuh does with them (rules, levels): detections are also sent there, but this is where they are explained.
        </p>
      </div>

      {unsupported ? (
        <Card title="Detections unavailable">
          <Empty>
            This collector does not provide detections yet (contract v1.2, <code>GET /detections</code>). Update it to see them here.
          </Empty>
        </Card>
      ) : (
        <>
          <div className="toolbar">
            <PeriodPicker ctl={ctl} />
            <label className="filter type-filter">
              Type
              <select value={type} onChange={(e) => setType(e.target.value)} aria-label="Detection type">
                <option value="">All types</option>
                {DETECTION_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {detectionLabel(t)}
                  </option>
                ))}
              </select>
            </label>
            <label className="filter">
              Severity
              <select value={sevMin} onChange={(e) => setSevMin(Number(e.target.value))} aria-label="Minimum severity">
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
              Refresh
            </button>
          </div>

          {paged.error && paged.detections.length === 0 ? (
            <ErrorBox message={paged.error.message} onRetry={paged.reload} />
          ) : paged.loading && paged.detections.length === 0 ? (
            <Loading label="Loading detections…" />
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
                    Show muted detections ({mutedCount})
                  </label>
                )}
                {type !== '' && (
                  <p className="hint">
                    The banner and the counters only cover the "{detectionLabel(type)}" type. Choose "All types" for the overall situation.
                  </p>
                )}
                {visible.length === 0 ? (
                  paged.detections.length > 0 ? (
                    <Empty>No detection matches the severity filter.</Empty>
                  ) : null
                ) : (
                  <ul className={`det-list${paged.loading ? ' is-refreshing' : ''}`} aria-label="Detections">
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
                      {paged.loadingMore ? 'Loading…' : 'Load more'}
                    </button>
                    <span>{paged.detections.length} shown</span>
                  </div>
                )}
                {!paged.hasMore && visible.length > 0 && <div className="pager">{visible.length} detection{visible.length > 1 ? 's' : ''} — end of the list</div>}
              </div>
            </>
          )}
        </>
      )}

      {!unsupported && !mutesUnsupported && mutes.data && (
        <MutesCard mutes={mutes.data} onUnmute={(m) => void muting.unmute(m)} labelOf={labelOf} />
      )}
      {muting.dialog}

      <Card title="The guards of the Watchpost app" className="guards-card">
        <details>
          <summary>Reminder: lock down in advance what malware would use</summary>
          <p className="hint">
            Guards are set <strong>on the phone</strong>, in the Policy screen of the Watchpost app (Device Owner required). They are off by default, reversible
            ("Restore everything"), and the console can neither enable nor disable them: the server never commands the phone.
          </p>
          <ul className="guards">
            {GUARDS.map((g) => (
              <li key={g.key}>
                <strong>{g.label}</strong>: {g.effect}
              </li>
            ))}
          </ul>
        </details>
      </Card>
    </>
  );
}
