import { lazy, Suspense, useEffect, useMemo, useState } from 'react';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import type { LocationPoint } from '../api/types.ts';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Async, Badge, Card, Empty, KV, Loading } from '../components/ui.tsx';
import type { MapPoint } from '../components/MapView.tsx';
import { timelineTotals } from '../lib/agg.ts';
import {
  classifyGap,
  detectGaps,
  effectiveThreshold,
  GAP_LABELS,
  splitSegments,
  type Activity,
} from '../lib/gaps.ts';
import { fmtDateTime, fmtDateTimeShort, fmtDistance, fmtDuration, fmtNumber, fmtSpeedKmh } from '../lib/format.ts';
import { isValidLatLon, pathLength } from '../lib/geo.ts';
import { periodRange } from '../lib/period.ts';
import { useDevice } from '../state/device.tsx';

const MapView = lazy(() => import('../components/MapView.tsx'));

const THRESHOLDS = [
  { v: 15, label: '15 min' },
  { v: 30, label: '30 min' },
  { v: 60, label: '1 h' },
  { v: 120, label: '2 h' },
];

function activityBucket(spanMs: number): 'minute' | 'hour' | 'day' {
  if (spanMs <= 36 * 3600_000) return 'minute';
  if (spanMs <= 16 * 24 * 3600_000) return 'hour';
  return 'day';
}

interface Track {
  pts: (LocationPoint & { t: number })[];
}

export default function MapPage() {
  const { deviceId } = useDevice();
  const ctl = usePeriod('24h');
  const [thr, setThr] = useState(30);
  const range = periodRange(ctl.period);
  const spanMs = ctl.period.to.getTime() - ctl.period.from.getTime();
  const bucket = activityBucket(spanMs);

  const loc = useApi(deviceId ? `loc:${deviceId}:${range.from}:${range.to}` : null, (s) =>
    api.locations({ device_id: deviceId, ...range, max_points: 2000 }, s),
  );
  const act = useApi(deviceId ? `act:${deviceId}:${range.from}:${range.to}:${bucket}` : null, (s) =>
    api.timeline({ device_id: deviceId, ...range, bucket, by: 'domain' }, s),
  );

  const activity: Activity | undefined = useMemo(() => {
    if (!act.data) return undefined;
    const { starts, totals } = timelineTotals(act.data);
    return { starts, totals, bucketMs: bucket === 'minute' ? 60_000 : bucket === 'hour' ? 3600_000 : 86400_000 };
  }, [act.data, bucket]);

  return (
    <>
      <div className="page-head">
        <h1>Carte</h1>
      </div>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} keys={['today', '24h', '7d', 'custom']} />
        <label className="filter">
          Trou si aucune position pendant
          <select value={thr} onChange={(e) => setThr(Number(e.target.value))}>
            {THRESHOLDS.map((t) => (
              <option key={t.v} value={t.v}>
                {t.label}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="btn" onClick={() => { ctl.refresh(); loc.reload(); act.reload(); }}>
          Actualiser
        </button>
      </div>
      <Async
        state={loc}
        isEmpty={(d) => d.points.filter((p) => isValidLatLon(p.lat, p.lon)).length === 0}
        empty="Aucune position enregistrée sur cette période."
        loadingLabel="Chargement de la trace…"
      >
        {(d) => <TrackView track={prepare(d.points)} thresholdMin={thr} activity={activity} truncated={d.points.length >= 2000} />}
      </Async>
    </>
  );
}

function prepare(points: LocationPoint[]): Track {
  const pts = points
    .filter((p) => isValidLatLon(p.lat, p.lon))
    .map((p) => ({ ...p, t: new Date(p.ts).getTime() }))
    .filter((p) => Number.isFinite(p.t))
    .sort((a, b) => a.t - b.t);
  return { pts };
}

function TrackView({
  track,
  thresholdMin,
  activity,
  truncated,
}: {
  track: Track;
  thresholdMin: number;
  activity: Activity | undefined;
  truncated: boolean;
}) {
  const n = track.pts.length;
  const dataKey = `${n}:${track.pts[0]?.t ?? 0}:${track.pts[n - 1]?.t ?? 0}`;
  const [selection, setSelection] = useState<{ key: string; idx: number }>({ key: dataKey, idx: n - 1 });
  const selected = Math.min(n - 1, Math.max(0, selection.key === dataKey ? selection.idx : n - 1));
  const select = (i: number) => setSelection({ key: dataKey, idx: i });
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(2);

  const mapPoints: MapPoint[] = useMemo(
    () => track.pts.map((p) => ({ lat: p.lat, lon: p.lon, t: p.t, ...(p.acc_m !== undefined ? { acc: p.acc_m } : {}) })),
    [track],
  );
  const threshold = useMemo(() => effectiveThreshold(track.pts, thresholdMin * 60_000), [track, thresholdMin]);
  const gaps = useMemo(() => detectGaps(track.pts, threshold), [track, threshold]);
  const segments = useMemo(() => splitSegments(n, gaps), [n, gaps]);
  const gapInfo = useMemo(() => gaps.map((g) => ({ ...g, kind: classifyGap(g, activity) })), [gaps, activity]);
  const distance = useMemo(() => {
    const gapEnds = new Set(gaps.map((g) => g.toIdx));
    return pathLength(track.pts, (i) => gapEnds.has(i));
  }, [track, gaps]);

  // Lecture du trajet (la lecture s'arrête d'elle-même sur le dernier point).
  const isPlaying = playing && selected < n - 1;
  useEffect(() => {
    if (!isPlaying) return;
    const t = window.setInterval(() => {
      setSelection((s) => {
        const c = s.key === dataKey ? s.idx : n - 1;
        return { key: dataKey, idx: Math.min(n - 1, c + speed) };
      });
    }, 120);
    return () => window.clearInterval(t);
  }, [isPlaying, speed, n, dataKey]);

  const cur = track.pts[selected];
  const first = track.pts[0];
  const last = track.pts[n - 1];
  const silent = gapInfo.filter((g) => g.kind === 'silent').reduce((a, g) => a + g.durationMs, 0);
  const speeds = track.pts.map((p) => p.speed_mps ?? 0);
  const vmax = speeds.length ? Math.max(...speeds) : 0;

  return (
    <div className="grid grid-start">
      <Card
        title={`Trace · ${fmtNumber(n)} position${n > 1 ? 's' : ''}`}
        className="span-8"
        actions={
          <span className="hint">
            {first && last ? `${fmtDateTimeShort(first.ts)} → ${fmtDateTimeShort(last.ts)}` : ''}
          </span>
        }
      >
        <div className="map-lg">
          <Suspense fallback={<Loading label="Chargement de la carte…" />}>
            <MapView
              points={mapPoints}
              segments={segments}
              gaps={gaps}
              selected={selected}
              onSelect={(i) => {
                setPlaying(false);
                select(i);
              }}
              ariaLabel="Carte de la trace des positions"
            />
          </Suspense>
        </div>
        <p className="hint map-legend">
          <span className="legend-line" aria-hidden="true" /> trajet · <span className="legend-dash" aria-hidden="true" /> trou de données (aucune position)
          · points orange : précision supérieure à 100 m. Cliquez un point pour le sélectionner.
          {truncated ? ' Trace sous-échantillonnée par le serveur (2 000 points maximum).' : ''}
        </p>
        <div className="replay">
          <div className="replay-btns">
            <button type="button" className="btn btn-icon" aria-label="Point précédent" onClick={() => { setPlaying(false); select(Math.max(0, selected - 1)); }}>
              ‹
            </button>
            <button
              type="button"
              className="btn btn-primary"
              aria-pressed={isPlaying}
              onClick={() => {
                if (isPlaying) {
                  setPlaying(false);
                  return;
                }
                if (selected >= n - 1) select(0);
                setPlaying(true);
              }}
              disabled={n < 2}
            >
              {isPlaying ? 'Pause' : 'Rejouer'}
            </button>
            <button type="button" className="btn btn-icon" aria-label="Point suivant" onClick={() => { setPlaying(false); select(Math.min(n - 1, selected + 1)); }}>
              ›
            </button>
            <label className="sr-only" htmlFor="replay-speed">
              Vitesse de lecture
            </label>
            <select id="replay-speed" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
              <option value={1}>×1</option>
              <option value={2}>×2</option>
              <option value={5}>×5</option>
              <option value={15}>×15</option>
            </select>
          </div>
          <input
            type="range"
            min={0}
            max={Math.max(0, n - 1)}
            value={selected}
            onChange={(e) => {
              setPlaying(false);
              select(Number(e.target.value));
            }}
            aria-label="Curseur temporel"
            aria-valuetext={cur ? fmtDateTime(cur.ts) : undefined}
            disabled={n < 2}
          />
          {cur && (
            <div className="replay-info">
              <strong>{fmtDateTime(cur.ts)}</strong>
              <span>
                point {selected + 1}/{n}
              </span>
            </div>
          )}
        </div>
      </Card>

      <div className="span-4 stack">
        <Card title="Point sélectionné">
          {cur ? (
            <KV
              items={[
                { k: 'Heure', v: fmtDateTime(cur.ts) },
                { k: 'Coordonnées', v: `${fmtNumber(cur.lat, 5)}, ${fmtNumber(cur.lon, 5)}` },
                {
                  k: 'Précision',
                  v: cur.acc_m !== undefined ? (
                    <>
                      ±{fmtNumber(cur.acc_m)} m {cur.acc_m > 100 && <Badge tone="warn">faible</Badge>}
                    </>
                  ) : (
                    'inconnue'
                  ),
                },
                { k: 'Vitesse', v: fmtSpeedKmh(cur.speed_mps) },
                { k: 'Fournisseur', v: cur.provider ?? '—' },
              ]}
            />
          ) : (
            <Empty>Aucun point.</Empty>
          )}
        </Card>
        <Card title="Résumé">
          <KV
            items={[
              { k: 'Distance parcourue', v: fmtDistance(distance) },
              { k: 'Durée couverte', v: first && last ? fmtDuration(last.t - first.t) : '—' },
              { k: 'Vitesse maximale', v: fmtSpeedKmh(vmax) },
              { k: 'Trous de données', v: `${gaps.length}${silent ? ` (dont ${fmtDuration(silent)} sans aucun événement)` : ''}` },
            ]}
          />
        </Card>
        <Card title={`Trous de données (> ${fmtDuration(threshold)})`}>
          {gapInfo.length === 0 ? (
            <p className="muted">Aucun trou : la trace est continue sur la période.</p>
          ) : (
            <ul className="gap-list">
              {gapInfo.map((g) => (
                <li key={`${g.start}`} className={g.kind === 'silent' ? 'is-silent' : ''}>
                  <button type="button" className="linkish" onClick={() => { setPlaying(false); select(g.toIdx); }}>
                    {fmtDateTimeShort(g.start)} → {fmtDateTimeShort(g.end)} ({fmtDuration(g.durationMs)})
                  </button>
                  <span className="hint">{GAP_LABELS[g.kind]}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
