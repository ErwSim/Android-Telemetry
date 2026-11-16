import { useState } from 'react';
import { api } from '../../api/endpoints.ts';
import { ApiError } from '../../api/client.ts';
import type { TrackingSummary } from '../../api/types.ts';
import { levelTexts } from '../../lib/tracking.ts';
import { Dialog } from '../Dialog.tsx';
import { Badge } from '../ui.tsx';

/** Niveau de blocage : trois niveaux décrits, confirmation avant de changer les listes d'AdGuard Home. */
export function LevelCard({ summary, onChanged }: { summary: TrackingSummary; onChanged: (level: string) => void }) {
  const levels = levelTexts(summary.levels);
  const current = summary.level;
  const [choice, setChoice] = useState<string | undefined>();
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const off = !summary.adguard;
  const selected = choice ?? current;
  const target = levels.find((l) => l.key === selected);
  const from = levels.find((l) => l.key === current);
  const changed = !!selected && selected !== current;

  const apply = async () => {
    if (!selected) return;
    setBusy(true);
    setError(undefined);
    try {
      await api.setTrackingLevel(selected);
      setConfirm(false);
      setChoice(undefined);
      onChanged(selected);
    } catch (e) {
      setError(e instanceof ApiError ? `Le niveau n'a pas été changé. ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <fieldset className="levels" disabled={off}>
        <legend className="sr-only">Niveau de blocage</legend>
        {levels.map((l) => (
          <label key={l.key} className={`level${selected === l.key ? ' is-sel' : ''}`}>
            <input type="radio" name="level" value={l.key} checked={selected === l.key} onChange={() => setChoice(l.key)} />
            <span>
              <strong>{l.name}</strong> {current === l.key && <Badge tone="ok">Actuel</Badge>}
              <br />
              <span className="muted">{l.description}</span>
            </span>
          </label>
        ))}
      </fieldset>
      {off ? (
        <p className="hint">Le niveau ne peut pas être lu ni changé : AdGuard Home n'est pas joignable depuis le collecteur.</p>
      ) : (
        <div className="level-actions">
          <button type="button" className="btn btn-primary" disabled={!changed} onClick={() => setConfirm(true)}>
            Appliquer le niveau {target ? `« ${target.name} »` : ''}…
          </button>
          {changed && (
            <button type="button" className="btn" onClick={() => setChoice(undefined)}>
              Annuler
            </button>
          )}
        </div>
      )}
      {confirm && target && (
        <Dialog
          title={`Passer au niveau « ${target.name} » ?`}
          busy={busy}
          onClose={() => setConfirm(false)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setConfirm(false)} disabled={busy}>
                Annuler
              </button>
              <button type="button" className="btn btn-primary" onClick={() => void apply()} disabled={busy}>
                {busy ? 'Application…' : 'Changer le niveau'}
              </button>
            </>
          }
        >
          <p>
            {from ? (
              <>
                Du niveau <strong>{from.name}</strong> au niveau <strong>{target.name}</strong>.
              </>
            ) : (
              <>
                Niveau <strong>{target.name}</strong>.
              </>
            )}
          </p>
          <p className="muted">{target.description}</p>
          <div className="callout callout-info">
            <ul>
              <li>Le collecteur active ou désactive des listes de blocage dans AdGuard Home ; vos règles manuelles (Bloquer / Autoriser) sont conservées.</li>
              <li>Le changement vaut pour tout ce qui utilise ce DNS, et s'applique aux prochaines requêtes (les décomptes passés ne changent pas).</li>
              <li>Il est réversible : il suffit de rechoisir l'ancien niveau.</li>
              {target.key === 'strict' && <li>Le niveau strict peut empêcher certaines applications de fonctionner pleinement : essayez-le quelques jours.</li>}
            </ul>
          </div>
          {error && (
            <div className="state state-error" role="alert">
              {error}
            </div>
          )}
        </Dialog>
      )}
      {!confirm && error && (
        <div className="state state-error" role="alert">
          {error}
        </div>
      )}
    </>
  );
}
