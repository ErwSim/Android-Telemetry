import { useMemo, useState } from 'react';

type Tok = { t: 'key' | 'str' | 'num' | 'lit' | 'punct'; s: string };

/** Découpe un JSON indenté en jetons pour la coloration (sans innerHTML). */
export function tokenizeJson(text: string): Tok[] {
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b|([{}[\],:])|(\s+)/g;
  const out: Tok[] = [];
  let last = 0;
  for (const m of text.matchAll(re)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push({ t: 'punct', s: text.slice(last, idx) });
    if (m[1] !== undefined) {
      if (m[2]) {
        out.push({ t: 'key', s: m[1] });
        out.push({ t: 'punct', s: m[2] });
      } else out.push({ t: 'str', s: m[1] });
    } else if (m[3] !== undefined) out.push({ t: 'num', s: m[3] });
    else if (m[4] !== undefined) out.push({ t: 'lit', s: m[4] });
    else out.push({ t: 'punct', s: m[0] });
    last = idx + m[0].length;
  }
  if (last < text.length) out.push({ t: 'punct', s: text.slice(last) });
  return out;
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2) ?? 'null';
  } catch {
    return String(v);
  }
}

export function JsonView({ value, maxChars = 20000 }: { value: unknown; maxChars?: number }) {
  const [full, setFull] = useState(false);
  const [copied, setCopied] = useState(false);
  const text = useMemo(() => safeStringify(value), [value]);
  const truncated = !full && text.length > maxChars;
  const shown = truncated ? `${text.slice(0, maxChars)}\n…` : text;
  const toks = useMemo(() => tokenizeJson(shown), [shown]);

  const copy = () => {
    void navigator.clipboard
      ?.writeText(text)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      })
      .catch(() => undefined);
  };

  return (
    <div className="json">
      <div className="json-tools">
        <button type="button" className="btn btn-sm" onClick={copy}>
          {copied ? 'Copié' : 'Copier le JSON'}
        </button>
        {truncated && (
          <button type="button" className="btn btn-sm" onClick={() => setFull(true)}>
            Tout afficher ({Math.round(text.length / 1024)} Kio)
          </button>
        )}
      </div>
      <pre className="json-pre" tabIndex={0} aria-label="Contenu JSON">
        {toks.map((k, i) => (
          <span key={i} className={`j-${k.t}`}>
            {k.s}
          </span>
        ))}
      </pre>
    </div>
  );
}
