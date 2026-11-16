import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { useEventStream } from '../api/useEventStream.ts';
import type { LocationPoint, WatchpostEvent } from '../api/types.ts';
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
import { fmtDateTime, fmtDateTimeShort, fmtDistance, fmtDuration, fmtNumber, fmtSpeedKmh, fmtTime } from '../lib/format.ts';
import { num, str } from '../lib/data.ts';
import { countProviders, providerInfo } from '../lib/provider.ts';
import { ProviderDot, ProviderLegend } from '../components/Provider.tsx';
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

  // Suivi en direct : les `location.fix` reçus par le flux s'ajoutent à la trace (par exemple après « Localiser
  // maintenant »). Désactivé pour une période personnalisée, qui ne se termine pas « maintenant ».
  const [follow, setFollow] = useState(true);
  const liveKey = `${deviceId ?? ''}|${range.from}|${range.to}`;
  const [extra, setExtra] = useState<{ key: string; pts: LocationPoint[] }>({ key: liveKey, pts: [] });
  const onEvent = useCallback(
    (ev: WatchpostEvent) => {
      if (ev.type !== 'location.fix') return;
      const lat = num(ev.data, 'lat');
      const lon = num(ev.data, 'lon');
      if (lat === undefined || lon === undefined) return;
      const acc = num(ev.data, 'acc_m');
      const spd = num(ev.data, 'speed_mps');
      const provider = str(ev.data, 'provider');
      const p: LocationPoint = { ts: ev.ts, lat, lon, ...(acc !== undefined ? { acc_m: acc } : {}), ...(spd !== undefined ? { speed_mps: spd } : {}), ...(provider ? { provider } : {}) };
      setExtra((prev) => {
        const base = prev.key === liveKey ? prev.pts : [];
        return base.some((x) => x.ts === p.ts) ? prev : { key: liveKey, pts: [...base, p] };
      });
    },
    [liveKey],
  );
  const streamOn = follow && ctl.key !== 'custom' && !!deviceId;
  const stream = useEventStream(streamOn, deviceId, onEvent);
  const livePts = useMemo(() => (extra.key === liveKey ? extra.pts : []), [extra, liveKey]);
  const merged = useMemo(() => {
    if (!loc.data) return undefined;
    const seen = new Set(loc.data.points.map((p) => p.ts));
    return { points: [...loc.data.points, ...livePts.filter((p) => !seen.has(p.ts))] };
  }, [loc.data, livePts]);
  const lastLive = livePts[livePts.length - 1];

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
        <label className="check">
          <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} disabled={ctl.key === 'custom'} />
          <span className={`live-dot${streamOn && stream === 'open' ? '' : ' is-off'}`} aria-hidden="true" />
          Suivi en direct
          <span className="hint" role="status" data-testid="live-status">
            {streamOn ? (stream === 'open' ? (lastLive ? ` · dernière position reçue à ${fmtTime(lastLive.ts)}` : ' · connecté') : stream === 'error' ? ' · connexion perdue, nouvelle tentative…' : ' · connexion…') : ''}
          </span>
        </label>
      </div>
      <Async
        state={{ ...loc, data: merged }}
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
    () => track.pts.map((p) => ({ lat: p.lat, lon: p.lon, t: p.t, ...(p.acc_m !== undefined ? { acc: p.acc_m } : {}), ...(p.provider ? { provider: p.provider } : {}) })),
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
  const providerCounts = useMemo(() => countProviders(track.pts), [track]);

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
          · contour orange : précision supérieure à 100 m. Cliquez un point pour le sélectionner.
          {truncated ? ' Trace sous-échantillonnée par le serveur (2 000 points maximum).' : ''}
        </p>
        <ProviderLegend />
        <p className="hint">
          Le fournisseur de chaque position est celui qui l'a calculée : <em>GPS</em> (satellites seuls), <em>Réseau</em> et <em>Fusionné</em> passent par les Services
          Google Play.
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
                {
                  k: 'Fournisseur',
                  v: cur.provider ? (
                    <>
                      <ProviderDot provider={cur.provider} />
                      {providerInfo(cur.provider).label}
                      {providerInfo(cur.provider).google && (
                        <>
                          {' '}
                          <Badge tone="warn" title={providerInfo(cur.provider).note}>
                            via Google
                          </Badge>
                        </>
                      )}
                    </>
                  ) : (
                    '—'
                  ),
                },
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
              {
                k: 'Fournisseurs',
                v: providerCounts.map((c) => `${c.label} ${fmtNumber(c.count)}`).join(' · ') || '—',
              },
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
