export interface LatLon {
  lat: number;
  lon: number;
}

const R = 6_371_000;
const rad = (d: number) => (d * Math.PI) / 180;

export function haversine(a: LatLon, b: LatLon): number {
  const dLat = rad(b.lat - a.lat);
  const dLon = rad(b.lon - a.lon);
  const s = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(s)));
}

/** Longueur cumulée d'un trajet, en mètres. Ignore les sauts supérieurs à `maxJumpM` (trous de données). */
export function pathLength(points: LatLon[], skip?: (i: number) => boolean): number {
  let total = 0;
  for (let i = 1; i < points.length; i++) {
    if (skip?.(i)) continue;
    const a = points[i - 1];
    const b = points[i];
    if (a && b) total += haversine(a, b);
  }
  return total;
}

/** Polygone approximant un cercle de rayon `radiusM` (anneau GeoJSON fermé, [lon, lat]). */
export function circleRing(center: LatLon, radiusM: number, steps = 48): [number, number][] {
  const ring: [number, number][] = [];
  const dLat = (radiusM / R) * (180 / Math.PI);
  const dLon = dLat / Math.max(0.01, Math.cos(rad(center.lat)));
  for (let i = 0; i <= steps; i++) {
    const t = (i / steps) * 2 * Math.PI;
    ring.push([center.lon + dLon * Math.cos(t), center.lat + dLat * Math.sin(t)]);
  }
  return ring;
}

export function isValidLatLon(lat: unknown, lon: unknown): boolean {
  return (
    typeof lat === 'number' &&
    typeof lon === 'number' &&
    Number.isFinite(lat) &&
    Number.isFinite(lon) &&
    Math.abs(lat) <= 90 &&
    Math.abs(lon) <= 180
  );
}
