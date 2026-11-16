// Runtime configuration: `/config.json` (static file, optional), then build variables.

export interface AppConfig {
  tileUrl: string;
  tileAttribution: string;
  tileAttributionUrl: string;
}

export const DEFAULT_CONFIG: AppConfig = {
  tileUrl: (import.meta.env.VITE_TILE_URL as string | undefined) ?? 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
  tileAttribution: (import.meta.env.VITE_TILE_ATTRIBUTION as string | undefined) ?? '© OpenStreetMap contributors',
  tileAttributionUrl:
    (import.meta.env.VITE_TILE_ATTRIBUTION_URL as string | undefined) ?? 'https://www.openstreetmap.org/copyright',
};

/** A valid tile URL uses https (or same origin) and contains {z}, {x} and {y}. */
export function isValidTileUrl(u: unknown): u is string {
  if (typeof u !== 'string') return false;
  if (!u.includes('{z}') || !u.includes('{x}') || !u.includes('{y}')) return false;
  return /^https:\/\//.test(u) || u.startsWith('/') || /^http:\/\/(localhost|127\.0\.0\.1)(:|\/)/.test(u);
}

export function mergeConfig(raw: unknown): AppConfig {
  const out = { ...DEFAULT_CONFIG };
  if (raw && typeof raw === 'object') {
    const r = raw as Record<string, unknown>;
    if (isValidTileUrl(r['tileUrl'])) out.tileUrl = r['tileUrl'];
    if (typeof r['tileAttribution'] === 'string' && r['tileAttribution']) out.tileAttribution = r['tileAttribution'];
    if (typeof r['tileAttributionUrl'] === 'string' && /^https?:\/\//.test(r['tileAttributionUrl']))
      out.tileAttributionUrl = r['tileAttributionUrl'];
  }
  return out;
}

let cached: Promise<AppConfig> | undefined;

export function loadConfig(): Promise<AppConfig> {
  cached ??= fetch('/config.json', { headers: { Accept: 'application/json' }, credentials: 'omit' })
    .then(async (r) => {
      if (!r.ok) return DEFAULT_CONFIG;
      const ct = r.headers.get('content-type') ?? '';
      if (!ct.includes('json')) return DEFAULT_CONFIG; // SPA fallback to index.html
      return mergeConfig(await r.json());
    })
    .catch(() => DEFAULT_CONFIG);
  return cached;
}
