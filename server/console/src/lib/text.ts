// Texte venant du téléphone (donc de n'importe quelle application : titre et texte de notification…).
// Il n'est jamais interprété : React l'insère comme nœud texte. On retire en plus les caractères de contrôle
// et de réordonnancement bidirectionnel, qui permettraient de maquiller l'affichage.

const esc = (code: number): string => '\\u' + code.toString(16).padStart(4, '0');
const range = (a: number, b: number): string => `${esc(a)}-${esc(b)}`;

// Contrôles C0 (sauf tabulation) et C1 ; marques et isolats bidirectionnels ; séparateurs de ligne.
const CONTROL = new RegExp(`[${range(0, 8)}${esc(0x0b)}${esc(0x0c)}${range(0x0e, 0x1f)}${range(0x7f, 0x9f)}]`, 'g');
const BIDI = new RegExp(`[${esc(0x061c)}${esc(0x200e)}${esc(0x200f)}${range(0x202a, 0x202e)}${range(0x2066, 0x2069)}]`, 'g');
const LINE_BREAKS = new RegExp(`[${esc(0x0a)}${esc(0x0d)}${esc(0x2028)}${esc(0x2029)}]+`, 'g');

export function cleanText(v: unknown, max = 512): string {
  if (typeof v !== 'string') return '';
  const s = v.replace(LINE_BREAKS, ' \u23CE ').replace(CONTROL, '').replace(BIDI, '').trim();
  const chars = Array.from(s);
  return chars.length > max ? `${chars.slice(0, max).join('')}…` : s;
}
