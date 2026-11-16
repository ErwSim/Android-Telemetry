// Text coming from the phone (hence from any application: notification title and text...).
// It is never interpreted: React inserts it as a text node. Control characters and bidirectional
// reordering characters, which could be used to disguise the display, are also removed.

const esc = (code: number): string => '\\u' + code.toString(16).padStart(4, '0');
const range = (a: number, b: number): string => `${esc(a)}-${esc(b)}`;

// C0 controls (except tab) and C1; bidirectional marks and isolates; line separators.
const CONTROL = new RegExp(`[${range(0, 8)}${esc(0x0b)}${esc(0x0c)}${range(0x0e, 0x1f)}${range(0x7f, 0x9f)}]`, 'g');
const BIDI = new RegExp(`[${esc(0x061c)}${esc(0x200e)}${esc(0x200f)}${range(0x202a, 0x202e)}${range(0x2066, 0x2069)}]`, 'g');
const LINE_BREAKS = new RegExp(`[${esc(0x0a)}${esc(0x0d)}${esc(0x2028)}${esc(0x2029)}]+`, 'g');

export function cleanText(v: unknown, max = 512): string {
  if (typeof v !== 'string') return '';
  const s = v.replace(LINE_BREAKS, ' \u23CE ').replace(CONTROL, '').replace(BIDI, '').trim();
  const chars = Array.from(s);
  return chars.length > max ? `${chars.slice(0, max).join('')}…` : s;
}

/**
 * Path of an application's detail page. The package name is a query parameter and not part of the path: it
 * contains dots, and the server answers 404 (not `index.html`) to a path whose end looks like a file
 * extension (contract §6, static files), which would break direct opening and page reload.
 */
export function appSheetPath(pkg: string): string {
  return `/apps/detail?pkg=${encodeURIComponent(pkg)}`;
}
