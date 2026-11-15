// Formatage (français, heure locale du navigateur).

const LOCALE = 'fr-FR';

/** Convertit un horodatage RFC 3339 ou un epoch (ms ou s) en Date ; undefined si invalide. */
export function parseTs(v: unknown): Date | undefined {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? undefined : v;
  if (typeof v === 'number' && Number.isFinite(v)) {
    const ms = v < 1e11 ? v * 1000 : v;
    return new Date(ms);
  }
  if (typeof v === 'string' && v !== '') {
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? undefined : d;
  }
  return undefined;
}

function fmt(opts: Intl.DateTimeFormatOptions, v: unknown, tz?: string): string {
  const d = parseTs(v);
  if (!d) return '—';
  return new Intl.DateTimeFormat(LOCALE, tz ? { ...opts, timeZone: tz } : opts).format(d);
}

export function fmtDateTime(v: unknown, tz?: string): string {
  return fmt(
    { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' },
    v,
    tz,
  );
}
export function fmtDateTimeShort(v: unknown, tz?: string): string {
  return fmt({ day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }, v, tz);
}
export function fmtDate(v: unknown, tz?: string): string {
  return fmt({ day: '2-digit', month: '2-digit', year: 'numeric' }, v, tz);
}
export function fmtTime(v: unknown, tz?: string): string {
  return fmt({ hour: '2-digit', minute: '2-digit', second: '2-digit' }, v, tz);
}
export function fmtHourMinute(v: unknown, tz?: string): string {
  return fmt({ hour: '2-digit', minute: '2-digit' }, v, tz);
}

/** « il y a 3 min », « dans 2 h »… */
export function fmtRelative(v: unknown, now: Date = new Date()): string {
  const d = parseTs(v);
  if (!d) return '—';
  const diffS = Math.round((d.getTime() - now.getTime()) / 1000);
  const abs = Math.abs(diffS);
  const rtf = new Intl.RelativeTimeFormat(LOCALE, { numeric: 'auto' });
  if (abs < 45) return diffS <= 0 ? "à l'instant" : 'dans un instant';
  if (abs < 3600) return rtf.format(Math.round(diffS / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(diffS / 3600), 'hour');
  if (abs < 86400 * 60) return rtf.format(Math.round(diffS / 86400), 'day');
  return rtf.format(Math.round(diffS / (86400 * 30)), 'month');
}

const NBSP = ' ';

export function fmtNumber(n: number | undefined | null, digits = 0): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '—';
  return new Intl.NumberFormat(LOCALE, { maximumFractionDigits: digits, minimumFractionDigits: 0 }).format(n);
}

/** Tailles binaires (Kio, Mio, Gio), base 1024, comme dans le contrat. */
export function fmtBytes(n: number | undefined | null): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '—';
  const units = ['o', 'Kio', 'Mio', 'Gio', 'Tio'];
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  const digits = i === 0 || v >= 100 ? 0 : v >= 10 ? 1 : 2;
  const sign = n < 0 ? '-' : '';
  return `${sign}${fmtNumber(v, digits)}${NBSP}${units[i]}`;
}

/** Durée lisible : « 45 s », « 12 min », « 2 h 05 », « 3 j 4 h ». */
export function fmtDuration(ms: number | undefined | null): string {
  if (ms === undefined || ms === null || !Number.isFinite(ms) || ms < 0) return '—';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}${NBSP}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}${NBSP}min`;
  const h = Math.floor(m / 60);
  if (h < 24) {
    const rm = m % 60;
    return rm ? `${h}${NBSP}h${NBSP}${String(rm).padStart(2, '0')}` : `${h}${NBSP}h`;
  }
  const d = Math.floor(h / 24);
  const rh = h % 24;
  return rh ? `${d}${NBSP}j${NBSP}${rh}${NBSP}h` : `${d}${NBSP}j`;
}

export function fmtDistance(m: number | undefined | null): string {
  if (m === undefined || m === null || !Number.isFinite(m)) return '—';
  if (m < 1000) return `${fmtNumber(Math.round(m))}${NBSP}m`;
  return `${fmtNumber(m / 1000, m < 10000 ? 2 : 1)}${NBSP}km`;
}

export function fmtSpeedKmh(mps: number | undefined | null): string {
  if (mps === undefined || mps === null || !Number.isFinite(mps)) return '—';
  return `${fmtNumber(mps * 3.6, 0)}${NBSP}km/h`;
}

export function fmtPct(n: number | undefined | null, digits = 0): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '—';
  return `${fmtNumber(n, digits)}${NBSP}%`;
}

export function fmtCoord(lat: number, lon: number): string {
  return `${fmtNumber(lat, 5)}, ${fmtNumber(lon, 5)}`;
}

/** Texte lisible pour une valeur arbitraire de `data` (affichage dans un tableau). */
export function fmtValue(v: unknown): string {
  if (v === undefined || v === null) return '—';
  if (typeof v === 'boolean') return v ? 'oui' : 'non';
  if (typeof v === 'number') return fmtNumber(v, 2);
  if (typeof v === 'string') return v === '' ? '—' : v;
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

/** Début de la journée locale. */
export function startOfDay(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate());
}

/** Valeur pour <input type="datetime-local"> en heure locale. */
export function toLocalInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
