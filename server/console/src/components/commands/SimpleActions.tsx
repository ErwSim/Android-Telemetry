import { useState } from 'react';
import { LIMITS, validateParams, type CommandParams, type CommandType } from '../../lib/commands.ts';

type Simple = Extract<CommandType, 'ring' | 'vibrate' | 'stop_ring' | 'locate'>;

function parseDuration(v: string): number | undefined {
  const n = Number(v);
  return v.trim() !== '' && Number.isFinite(n) ? n : undefined;
}

/** Simple commands (no signature): ring, vibrate, stop ringing, locate. */
export function SimpleActions({ disabled, onSend }: { disabled: boolean; onSend: (type: Simple, params: CommandParams) => void }) {
  const [ringS, setRingS] = useState(String(LIMITS.ringDefault));
  const [ringVibrate, setRingVibrate] = useState(true);
  const [vibS, setVibS] = useState(String(LIMITS.vibrateDefault));

  const ringN = parseDuration(ringS);
  const vibN = parseDuration(vibS);
  const ringErr = ringN === undefined ? 'Enter a duration.' : validateParams('ring', { duration_s: ringN });
  const vibErr = vibN === undefined ? 'Enter a duration.' : validateParams('vibrate', { duration_s: vibN });

  return (
    <div className="cmd-list">
      <div className="cmd-row">
        <div className="cmd-info">
          <strong>Ring</strong>
          <span className="hint">Ring at full volume, even if the phone is on silent.</span>
        </div>
        <div className="cmd-ctl">
          <label className="filter">
            Duration (s)
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
            <input type="checkbox" checked={ringVibrate} onChange={(e) => setRingVibrate(e.target.checked)} /> Vibrate too
          </label>
          <button
            type="button"
            className="btn btn-primary"
            disabled={disabled || !!ringErr}
            onClick={() => onSend('ring', { duration_s: ringN as number, vibrate: ringVibrate })}
          >
            Ring
          </button>
        </div>
        {ringErr && (
          <p id="ring-err" className="form-error cmd-err" role="alert">
            {ringErr} (1 to {LIMITS.ringMax} s)
          </p>
        )}
      </div>

      <div className="cmd-row">
        <div className="cmd-info">
          <strong>Vibrate</strong>
          <span className="hint">Makes the phone vibrate, without sound.</span>
        </div>
        <div className="cmd-ctl">
          <label className="filter">
            Duration (s)
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
            Vibrate
          </button>
        </div>
        {vibErr && (
          <p id="vib-err" className="form-error cmd-err" role="alert">
            {vibErr} (1 to {LIMITS.vibrateMax} s)
          </p>
        )}
      </div>

      <div className="cmd-row">
        <div className="cmd-info">
          <strong>Stop ringing</strong>
          <span className="hint">Stops a ring in progress.</span>
        </div>
        <div className="cmd-ctl">
          <button type="button" className="btn" disabled={disabled} onClick={() => onSend('stop_ring', {})}>
            Stop ringing
          </button>
        </div>
      </div>

      <div className="cmd-row">
        <div className="cmd-info">
          <strong>Locate now</strong>
          <span className="hint">Immediate precise location (up to 60 s of acquisition), then immediate upload of the pending data. The map updates when the location arrives.</span>
        </div>
        <div className="cmd-ctl">
          <button type="button" className="btn btn-primary" disabled={disabled} onClick={() => onSend('locate', {})}>
            Locate now
          </button>
        </div>
      </div>
    </div>
  );
}
