import { useEffect, useRef, useState } from 'react';
import * as maplibregl from 'maplibre-gl';
import workerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?url';
import 'maplibre-gl/dist/maplibre-gl.css';
import { loadConfig, DEFAULT_CONFIG, type AppConfig } from '../lib/config.ts';
import { circleRing } from '../lib/geo.ts';
import { cssVar, useTheme } from '../state/theme.tsx';

// Worker servi par le même hôte : pas besoin de `worker-src blob:`.
maplibregl.setWorkerUrl(workerUrl);

export interface MapPoint {
  lat: number;
  lon: number;
  /** epoch ms */
  t: number;
  acc?: number;
}

export interface MapViewProps {
  points: MapPoint[];
  /** Segments continus [début, fin] (index inclus) ; par défaut un seul segment. */
  segments?: [number, number][];
  /** Trous : tirets entre le dernier point avant et le premier après. */
  gaps?: { fromIdx: number; toIdx: number }[];
  selected?: number | undefined;
  onSelect?: (i: number) => void;
  interactive?: boolean;
  /** Zoom initial pour une position unique. */
  singleZoom?: number;
  ariaLabel: string;
}

type FC = GeoJSON.FeatureCollection;
const empty: FC = { type: 'FeatureCollection', features: [] };

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);
}

function styleFor(cfg: AppConfig, dark: boolean): maplibregl.StyleSpecification {
  const attribution = `<a href="${escapeHtml(cfg.tileAttributionUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(cfg.tileAttribution)}</a>`;
  return {
    version: 8,
    sources: { base: { type: 'raster', tiles: [cfg.tileUrl], tileSize: 256, maxzoom: 19, attribution } },
    layers: [
      { id: 'bg', type: 'background', paint: { 'background-color': dark ? '#1b222c' : '#e8ecf0' } },
      {
        id: 'base',
        type: 'raster',
        source: 'base',
        paint: dark
          ? { 'raster-brightness-max': 0.55, 'raster-saturation': -0.4, 'raster-contrast': 0.1 }
          : {},
      },
    ],
  };
}

function lineFeatures(points: MapPoint[], segs: [number, number][], upTo?: number): FC {
  const features: GeoJSON.Feature[] = [];
  for (const [a, b] of segs) {
    const end = upTo === undefined ? b : Math.min(b, upTo);
    if (end <= a) continue;
    const coords = points.slice(a, end + 1).map((p) => [p.lon, p.lat]);
    features.push({ type: 'Feature', properties: {}, geometry: { type: 'LineString', coordinates: coords } });
  }
  return { type: 'FeatureCollection', features };
}

function applyColors(map: maplibregl.Map) {
  const accent = cssVar('--accent', '#1d4ed8');
  const warn = cssVar('--warn', '#b45309');
  const muted = cssVar('--text-muted', '#667');
  const surface = cssVar('--surface', '#fff');
  const set = (l: string, p: string, v: unknown) => {
    if (map.getLayer(l)) map.setPaintProperty(l, p as 'line-color', v as string);
  };
  set('route', 'line-color', accent);
  set('trail', 'line-color', accent);
  set('gaps', 'line-color', warn);
  set('points', 'circle-stroke-color', surface);
  set('points', 'circle-color', ['case', ['>', ['get', 'acc'], 100], warn, accent]);
  set('accuracy-fill', 'fill-color', accent);
  set('accuracy-line', 'line-color', accent);
  set('selected', 'circle-color', accent);
  set('selected', 'circle-stroke-color', surface);
  set('selected-halo', 'circle-color', accent);
  void muted;
}

export default function MapView({
  points,
  segments,
  gaps,
  selected,
  onSelect,
  interactive = true,
  singleZoom = 15,
  ariaLabel,
}: MapViewProps) {
  const host = useRef<HTMLDivElement>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const [ready, setReady] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const [tileProblem, setTileProblem] = useState(false);
  const { effective } = useTheme();
  const onSelectRef = useRef(onSelect);
  useEffect(() => {
    onSelectRef.current = onSelect;
  });
  const fitted = useRef<string>('');

  // Création de la carte (une fois par thème : le fond de carte change de style).
  useEffect(() => {
    let disposed = false;
    let map: maplibregl.Map | null = null;
    void loadConfig().then((cfg) => {
      if (disposed || !host.current) return;
      try {
        map = new maplibregl.Map({
          container: host.current,
          style: styleFor(cfg ?? DEFAULT_CONFIG, effective === 'dark'),
          center: [2.3522, 48.8566],
          zoom: 10,
          interactive,
          attributionControl: { compact: true },
          fadeDuration: 0,
          canvasContextAttributes: { preserveDrawingBuffer: false },
        });
      } catch (e) {
        setFailure(e instanceof Error ? e.message : 'WebGL indisponible');
        return;
      }
      mapRef.current = map;
      if (interactive) map.addControl(new maplibregl.NavigationControl({ showCompass: false }), 'top-right');
      map.addControl(new maplibregl.ScaleControl({ unit: 'metric' }), 'bottom-left');
      let tileErrors = 0;
      let tileOk = 0;
      map.on('error', (ev) => {
        const src = (ev as { sourceId?: string }).sourceId;
        if (src === 'base') {
          tileErrors++;
          if (tileOk === 0 && tileErrors >= 3) setTileProblem(true);
        }
      });
      map.on('data', (ev) => {
        if ((ev as { sourceId?: string; tile?: unknown }).sourceId === 'base' && (ev as { tile?: unknown }).tile) {
          tileOk++;
          setTileProblem(false);
        }
      });
      map.on('load', () => {
        if (!map || disposed) return;
        map.addSource('route', { type: 'geojson', data: empty });
        map.addSource('trail', { type: 'geojson', data: empty });
        map.addSource('gaps', { type: 'geojson', data: empty });
        map.addSource('points', { type: 'geojson', data: empty });
        map.addSource('accuracy', { type: 'geojson', data: empty });
        map.addSource('sel', { type: 'geojson', data: empty });
        map.addLayer({
          id: 'gaps',
          type: 'line',
          source: 'gaps',
          paint: { 'line-width': 2, 'line-dasharray': [2, 2], 'line-opacity': 0.9 },
          layout: { 'line-cap': 'butt' },
        });
        map.addLayer({
          id: 'route',
          type: 'line',
          source: 'route',
          paint: { 'line-width': 3, 'line-opacity': 0.5 },
          layout: { 'line-join': 'round', 'line-cap': 'round' },
        });
        map.addLayer({
          id: 'trail',
          type: 'line',
          source: 'trail',
          paint: { 'line-width': 4, 'line-opacity': 0.95 },
          layout: { 'line-join': 'round', 'line-cap': 'round' },
        });
        map.addLayer({ id: 'accuracy-fill', type: 'fill', source: 'accuracy', paint: { 'fill-opacity': 0.12 } });
        map.addLayer({ id: 'accuracy-line', type: 'line', source: 'accuracy', paint: { 'line-width': 1, 'line-opacity': 0.6 } });
        map.addLayer({
          id: 'points',
          type: 'circle',
          source: 'points',
          paint: {
            'circle-radius': ['interpolate', ['linear'], ['zoom'], 8, 2.5, 16, 5],
            'circle-stroke-width': 1,
            'circle-opacity': 0.9,
          },
        });
        map.addLayer({ id: 'selected-halo', type: 'circle', source: 'sel', paint: { 'circle-radius': 14, 'circle-opacity': 0.2 } });
        map.addLayer({ id: 'selected', type: 'circle', source: 'sel', paint: { 'circle-radius': 7, 'circle-stroke-width': 2.5 } });
        applyColors(map);
        if (interactive) {
          map.on('click', 'points', (e) => {
            const f = e.features?.[0];
            const i = f?.properties?.['i'];
            if (typeof i === 'number') onSelectRef.current?.(i);
          });
          map.on('mouseenter', 'points', () => {
            map?.getCanvas().style.setProperty('cursor', 'pointer');
          });
          map.on('mouseleave', 'points', () => {
            map?.getCanvas().style.removeProperty('cursor');
          });
        }
        setReady(true);
      });
    });
    return () => {
      disposed = true;
      setReady(false);
      map?.remove();
      mapRef.current = null;
      fitted.current = '';
    };
  }, [effective, interactive]);

  // Données de la trace.
  useEffect(() => {
    const map = mapRef.current;
    if (!ready || !map) return;
    const segs = segments ?? (points.length ? [[0, points.length - 1] as [number, number]] : []);
    const set = (id: string, d: FC) => (map.getSource(id) as maplibregl.GeoJSONSource | undefined)?.setData(d);
    set('route', lineFeatures(points, segs));
    set(
      'gaps',
      {
        type: 'FeatureCollection',
        features: (gaps ?? []).flatMap((g) => {
          const a = points[g.fromIdx];
          const b = points[g.toIdx];
          return a && b
            ? [
                {
                  type: 'Feature' as const,
                  properties: {},
                  geometry: {
                    type: 'LineString' as const,
                    coordinates: [
                      [a.lon, a.lat],
                      [b.lon, b.lat],
                    ],
                  },
                },
              ]
            : [];
        }),
      },
    );
    set('points', {
      type: 'FeatureCollection',
      features: points.map((p, i) => ({
        type: 'Feature' as const,
        properties: { i, acc: p.acc ?? 0 },
        geometry: { type: 'Point' as const, coordinates: [p.lon, p.lat] },
      })),
    });
    // Cadrage une fois par jeu de points (évite de recadrer pendant la lecture du trajet).
    const sig = `${points.length}:${points[0]?.t ?? 0}:${points[points.length - 1]?.t ?? 0}`;
    if (fitted.current !== sig && points.length > 0) {
      fitted.current = sig;
      if (points.length === 1) {
        const p = points[0];
        if (p) map.jumpTo({ center: [p.lon, p.lat], zoom: singleZoom });
      } else {
        const b = new maplibregl.LngLatBounds();
        points.forEach((p) => b.extend([p.lon, p.lat]));
        map.fitBounds(b, { padding: 48, maxZoom: 16, duration: 0 });
      }
    }
  }, [ready, points, segments, gaps, singleZoom]);

  // Point sélectionné, cercle de précision et trajet parcouru.
  useEffect(() => {
    const map = mapRef.current;
    if (!ready || !map) return;
    const set = (id: string, d: FC) => (map.getSource(id) as maplibregl.GeoJSONSource | undefined)?.setData(d);
    const p = selected === undefined ? undefined : points[selected];
    if (!p) {
      set('sel', empty);
      set('accuracy', empty);
      set('trail', empty);
      return;
    }
    set('sel', { type: 'FeatureCollection', features: [{ type: 'Feature', properties: {}, geometry: { type: 'Point', coordinates: [p.lon, p.lat] } }] });
    set(
      'accuracy',
      p.acc
        ? {
            type: 'FeatureCollection',
            features: [{ type: 'Feature', properties: {}, geometry: { type: 'Polygon', coordinates: [circleRing(p, p.acc)] } }],
          }
        : empty,
    );
    const segs = segments ?? [[0, points.length - 1] as [number, number]];
    set('trail', lineFeatures(points, segs, selected));
    const bounds = map.getBounds();
    if (!bounds.contains([p.lon, p.lat])) map.easeTo({ center: [p.lon, p.lat], duration: 250 });
  }, [ready, points, segments, selected]);

  // Couleurs des couches selon le thème (les variables CSS changent avec data-theme).
  useEffect(() => {
    const map = mapRef.current;
    if (ready && map) applyColors(map);
  }, [ready, effective]);

  if (failure)
    return (
      <div className="map map-fallback" role="img" aria-label={ariaLabel}>
        <p>
          <strong>Carte indisponible</strong> (WebGL requis). {failure}
        </p>
      </div>
    );

  return (
    <div className="map-wrap">
      <div ref={host} className="map" role="region" aria-label={ariaLabel} />
      {tileProblem && (
        <div className="map-notice" role="status">
          Fond de carte indisponible (tuiles non chargées). La trace reste affichée.
        </div>
      )}
    </div>
  );
}
