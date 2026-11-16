import type { WatchpostEvent } from '../api/types.ts';

export function parsePrefixes(type: string): string[] {
  return type
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function togglePrefix(type: string, prefix: string): string {
  const list = parsePrefixes(type);
  const next = list.includes(prefix) ? list.filter((p) => p !== prefix) : [...list, prefix];
  return next.join(',');
}

/** Client-side filter for events received live (same semantics as the API). */
export function matchesFilters(
  ev: WatchpostEvent,
  f: { type: string; sevMin: number; q: string; deviceId?: string | undefined },
): boolean {
  if (f.deviceId && ev.device_id && ev.device_id !== f.deviceId) return false;
  const prefixes = parsePrefixes(f.type);
  if (prefixes.length > 0 && !prefixes.some((p) => ev.type.startsWith(p))) return false;
  if (ev.sev < f.sevMin) return false;
  const q = f.q.trim().toLowerCase();
  if (q) {
    let hay: string;
    try {
      hay = JSON.stringify(ev.data).toLowerCase();
    } catch {
      return false;
    }
    if (!hay.includes(q)) return false;
  }
  return true;
}
