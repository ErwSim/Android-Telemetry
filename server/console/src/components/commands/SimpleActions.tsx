import { useState } from 'react';
import { LIMITS, validateParams, type CommandParams, type CommandType } from '../../lib/commands.ts';

type Simple = Extract<CommandType, 'ring' | 'vibrate' | 'stop_ring' | 'locate'>;

function parseDuration(v: string): number | undefined {
  const n = Number(v);
  return v.trim() !== '' && Number.isFinite(n) ? n : undefined;
}

/** Commandes simples (sans signature) : sonner, vibrer, arrêter la sonnerie, localiser. */
export function SimpleActions({ disabled, onSend }: { disabled: boolean; onSend: (type: Simple, params: CommandParams) => void }) {
  const [ringS, setRingS] = useState(String(LIMITS.ringDefault));
  const [ringVibrate, setRingVibrate] = useState(true);
  const [vibS, setVibS] = useState(String(LIMITS.vibrateDefault));

  const ringN = parseDuration(ringS);
  const vibN = parseDuration(vibS);
  const ringErr = ringN === undefined ? 'Indiquez une durée.' : validateParams('ring', { duration_s: ringN });
  const vibErr = vibN === undefined ? 'Indiquez une durée.' : validateParams('vibrate', { duration_s: vibN });

  return (
    <div className="cmd-list">
      <div className="cmd-row">
        <div className="cmd-info">
          <strong>Sonner</strong>
          <span className="hint">Sonnerie à plein volume, même si le téléphone est en silencieux.</span>
        </div>
        <div className="cmd-ctl">
          <label className="filter">
            Durée (s)
            <input
              type="number"
              inputMode="numeric"
              min={1}
              max={LIMITS.ringMax}
              value={ringS}
              onChange={(e) => setRingS(e.target.value)}
              aria-invalid={!!ringErr}
              aria-describedby={ringErr ? 'ring-err' : undefined}
            />
          </label>
          <label className="check">
            <input type="checkbox" checked={ringVibrate} onChange={(e) => setRingVibrate(e.target.checked)} /> Vibrer aussi
          </label>
          <button
            type="button"
            className="btn btn-primary"
            disabled={disabled || !!ringErr}
            onClick={() => onSend('ring', { duration_s: ringN as number, vibrate: ringVibrate })}
          >
            Sonner
          </button>
        </div>
        {ringErr && (
          <p id="ring-err" className="form-error cmd-err" role="alert">
            {ringErr} (1 à {LIMITS.ringMax} s)
          </p>
        )}
      </div>

      <div className="cmd-row">
        <div className="cmd-info">
          <strong>Vibrer</strong>
          <span className="hint">Fait vibrer le téléphone, sans son.</span>
        </div>
        <div className="cmd-ctl">
          <label className="filter">
            Durée (s)
            <input
              type="number"
              inputMode="numeric"
              min={1}
              max={LIMITS.vibrateMax}
              value={vibS}
              onChange={(e) => setVibS(e.target.value)}
              aria-invalid={!!vibErr}
              aria-describedby={vibErr ? 'vib-err' : undefined}
            />
          </label>
          <button type="button" className="btn btn-primary" disabled={disabled || !!vibErr} onClick={() => onSend('vibrate', { duration_s: vibN as number })}>
            Vibrer
          </button>
        </div>
        {vibErr && (
          <p id="vib-err" className="form-error cmd-err" role="alert">
            {vibErr} (1 à {LIMITS.vibrateMax} s)
          </p>
        )}
      </div>

      <div className="cmd-row">
        <div className="cmd-info">
          <strong>Arrêter la sonnerie</strong>
          <span className="hint">Coupe une sonnerie en cours.</span>
        </div>
        <div className="cmd-ctl">
          <button type="button" className="btn" disabled={disabled} onClick={() => onSend('stop_ring', {})}>
            Arrêter la sonnerie
          </button>
        </div>
      </div>

      <div className="cmd-row">
        <div className="cmd-info">
          <strong>Localiser maintenant</strong>
          <span className="hint">Position précise immédiate (jusqu'à 60 s d'acquisition), puis envoi immédiat des données en attente. La carte se met à jour à l'arrivée de la position.</span>
        </div>
        <div className="cmd-ctl">
          <button type="button" className="btn btn-primary" disabled={disabled} onClick={() => onSend('locate', {})}>
            Localiser maintenant
          </button>
        </div>
      </div>
    </div>
  );
}
