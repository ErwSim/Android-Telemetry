import { useRef, useState } from 'react';
import { api } from '../../api/endpoints.ts';
import { ApiError, clockSkewMs } from '../../api/client.ts';
import type { Device } from '../../api/types.ts';
import {
  canSign,
  codeProblem,
  commandErrorMessage,
  defaultValidityMs,
  issueTime,
  validateParams,
  DAY_MS,
  HOUR_MS,
  LIMITS,
  prepareCommand,
  signPayload,
  type CommandType,
} from '../../lib/commands.ts';
import { fmtDateTime } from '../../lib/format.ts';
import { Dialog } from '../Dialog.tsx';
import { ServerLimits } from './ServerLimits.tsx';

export type SensitiveKind = Extract<CommandType, 'lock' | 'clear_lock_message' | 'wipe'>;

const MIN_MS = 60_000;

/** Validity choices: an erase is 15 min by default and 24 h at most; lock 7 days by default, 30 at most (contract §8). */
const VALIDITIES: Record<SensitiveKind, { ms: number; label: string }[]> = {
  wipe: [
    { ms: 5 * MIN_MS, label: '5 minutes' },
    { ms: 15 * MIN_MS, label: '15 minutes (default)' },
    { ms: HOUR_MS, label: '1 hour' },
    { ms: 6 * HOUR_MS, label: '6 hours' },
    { ms: DAY_MS, label: '24 hours (maximum)' },
  ],
  lock: [
    { ms: HOUR_MS, label: '1 hour' },
    { ms: DAY_MS, label: '24 hours' },
    { ms: 7 * DAY_MS, label: '7 days (default)' },
    { ms: 30 * DAY_MS, label: '30 days (maximum)' },
  ],
  clear_lock_message: [
    { ms: HOUR_MS, label: '1 hour' },
    { ms: DAY_MS, label: '24 hours' },
    { ms: 7 * DAY_MS, label: '7 days (default)' },
    { ms: 30 * DAY_MS, label: '30 days (maximum)' },
  ],
};


type Phase = 'idle' | 'signing' | 'sending';

/**
 * Sensitive command: the passphrase is entered each time in an uncontrolled field (it only exists in that
 * field's DOM, never in React state), is used to derive the key then the signature with WebCrypto, and the field is
 * cleared immediately. Neither the passphrase nor the key is stored or sent: only `{ device_id, payload, sig }` leaves.
 */
export function SensitiveDialog({
  kind,
  device,
  recentBadSignatures,
  onClose,
  onSent,
}: {
  kind: SensitiveKind;
  device: Device;
  recentBadSignatures: number;
  onClose: () => void;
  onSent: (id: string) => void;
}) {
  const isWipe = kind === 'wipe';
  const deviceName = device.name || device.device_id;
  const [step, setStep] = useState<1 | 2 | 3>(isWipe ? 1 : 3);
  const [message, setMessage] = useState('');
  const [validityMs, setValidityMs] = useState<number>(defaultValidityMs(kind));
  const [confirmed, setConfirmed] = useState(false);
  const [typedName, setTypedName] = useState('');
  const [codeLen, setCodeLen] = useState(0);
  const [showCode, setShowCode] = useState(false);
  const [openedAt] = useState(() => Date.now());
  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | undefined>();
  const codeRef = useRef<HTMLInputElement>(null);
  const busy = phase !== 'idle';
  const cryptoOk = canSign();

  const nameOk = typedName.trim() === deviceName;
  const messageProblem = kind === 'lock' ? validateParams('lock', { message }) : undefined;
  const lastStep: 1 | 2 | 3 = 3;
  const stepCount = isWipe ? 3 : 1;
  const stepNo = isWipe ? step : 1;

  const submit = async () => {
    const el = codeRef.current;
    if (!el || busy) return;
    const code = el.value;
    const problem = codeProblem(code);
    if (code === '' || problem) {
      setError(problem ?? 'Enter your command passphrase.');
      return;
    }
    setError(undefined);
    let prepared;
    try {
      prepared = prepareCommand(device.device_id, kind, kind === 'lock' ? { message } : {}, validityMs, issueTime(Date.now(), clockSkewMs()));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    setPhase('signing');
    let sig: string;
    try {
      sig = await signPayload(code, device.device_id, prepared.payload);
    } catch (e) {
      setPhase('idle');
      setError(e instanceof Error ? e.message : 'Signing failed.');
      return;
    } finally {
      // The passphrase stays nowhere: the field is cleared as soon as the signature is computed.
      el.value = '';
      setCodeLen(0);
    }
    setPhase('sending');
    try {
      const r = await api.createCommand({ device_id: device.device_id, payload: prepared.payload, sig });
      onSent(r.id);
    } catch (e) {
      setPhase('idle');
      setError(e instanceof ApiError ? sendError(e) : 'Sending failed.');
    }
  };

  const title =
    kind === 'wipe' ? 'Erase the phone (factory reset)' : kind === 'lock' ? 'Lock the phone with a message' : 'Clear the lock message';

  const codeField = (
    <div className="field">
      <label htmlFor="cmd-code">
        <strong>Command passphrase</strong> <span className="muted">(at least 12 characters, to be entered again each time; ideally five randomly chosen words, reserved for this use)</span>
      </label>
      <div className="code-row">
        <input
          id="cmd-code"
          ref={codeRef}
          type={showCode ? 'text' : 'password'}
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          data-1p-ignore
          data-lpignore="true"
          disabled={busy || !cryptoOk}
          onInput={(e) => setCodeLen(Array.from(e.currentTarget.value).length)}
          aria-describedby="cmd-code-help"
        />
        <button type="button" className="btn btn-sm" onClick={() => setShowCode((v) => !v)} aria-pressed={showCode} disabled={busy}>
          {showCode ? 'Hide' : 'Show'}
        </button>
      </div>
      <p id="cmd-code-help" className="hint">
        {codeLen > 0 && codeLen < LIMITS.codeMin
          ? `${codeLen} character${codeLen > 1 ? 's' : ''} out of at least ${LIMITS.codeMin}. `
          : ''}
        The passphrase is used here, in this browser, to compute the signature, then erased. It is neither sent to the server nor stored.
        Spaces count. <strong>This page is served by your server</strong>: a compromised server could read the passphrase as you type it. If you
        suspect it, <strong>do not enter the passphrase here any more</strong> and change it in the phone app.
      </p>
    </div>
  );

  const validityField = (
    <label className="field">
      <span>
        <strong>Command validity</strong>
      </span>
      <select value={validityMs} onChange={(e) => setValidityMs(Number(e.target.value))} disabled={busy}>
        {VALIDITIES[kind].map((v) => (
          <option key={v.ms} value={v.ms}>
            {v.label}
          </option>
        ))}
      </select>
      <span className="hint">
        If the phone is off or offline, the command waits for it until {fmtDateTime(new Date(openedAt + validityMs))}.
        {isWipe ? ' An erase is only valid for 15 minutes by default and 24 hours at most: the shorter the duration, the less exposed it stays. ' : ' '}
        You can cancel it while it is "Pending", but <strong>"cancelled" and "expired" only commit the server</strong>: the phone itself
        executes any correctly signed command until that date if it holds a copy. <strong>Only changing the command passphrase in
        the phone app makes an already signed command void.</strong>
      </span>
    </label>
  );

  const footer = (
    <>
      <button type="button" className="btn" onClick={onClose} disabled={busy}>
        Cancel
      </button>
      {isWipe && step > 1 && (
        <button type="button" className="btn" onClick={() => setStep((s) => (s === 3 ? 2 : 1))} disabled={busy}>
          Back
        </button>
      )}
      {isWipe && step === 1 && (
        <button type="button" className="btn btn-primary" onClick={() => setStep(2)} disabled={!confirmed}>
          Continue
        </button>
      )}
      {isWipe && step === 2 && (
        <button type="button" className="btn btn-primary" onClick={() => setStep(lastStep)} disabled={!nameOk}>
          Continue
        </button>
      )}
      {step === 3 && (
        <button
          type="button"
          className={`btn ${isWipe ? 'btn-danger' : 'btn-primary'}`}
          onClick={() => void submit()}
          disabled={busy || !cryptoOk || codeLen < LIMITS.codeMin || (kind === 'lock' && (!confirmed || !!messageProblem))}
        >
          {phase === 'signing' ? 'Computing the signature…' : phase === 'sending' ? 'Sending…' : isWipe ? 'Sign and erase permanently' : 'Sign and send'}
        </button>
      )}
    </>
  );

  return (
    <Dialog title={title} onClose={onClose} busy={busy} footer={footer} tone={isWipe ? 'danger' : undefined}>
      {isWipe && <p className="dlg-steps">Step {stepNo} of {stepCount}</p>}

      {isWipe && step === 1 && (
        <>
          <div className="callout callout-bad">
            <p>
              <strong>This action is irreversible.</strong> The phone is reset to factory settings: applications, photos, messages, accounts and
              settings are deleted, with no recycle bin and no way back. The Watchpost agent disappears too: the device will have to be enrolled again.
            </p>
          </div>
          <div className="callout callout-warn">
            <p>
              <strong>The erase must have been allowed in the phone app</strong> (the "Allow remote erase" setting, off by
              default). Otherwise the phone will refuse the command ("channel disabled") and nothing will be erased.
            </p>
          </div>
          <p className="muted">
            To be reserved for a lost or stolen phone that you will not see again. To find it, use <em>Ring</em> and <em>Locate now</em> instead;
            to protect it without losing anything, use <em>Lock with message</em>.
          </p>
          <label className="check">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
            I understand that the erase is irreversible.
          </label>
        </>
      )}

      {isWipe && step === 2 && (
        <>
          <p>
            To confirm, type the device name: <strong className="mono">{deviceName}</strong>
          </p>
          <p className="hint">
            Identifier that will be signed: <span className="mono">{device.device_id}</span> (the one shown by the phone app, on the
            "Enrollment" screen).
          </p>
          <label className="field">
            <span className="sr-only">Device name</span>
            <input
              type="text"
              value={typedName}
              onChange={(e) => setTypedName(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              aria-invalid={typedName !== '' && !nameOk}
              placeholder={deviceName}
            />
          </label>
          {typedName !== '' && !nameOk && <p className="form-error">That is not the exact name of the device.</p>}
        </>
      )}

      {kind === 'lock' && (
        <>
          <p>
            The phone locks its screen right away and shows the message below on the lock screen (with Device Owner active). It then
            unlocks normally with its PIN or fingerprint.
          </p>
          <label className="field">
            <span>
              <strong>Message shown</strong> <span className="muted">(optional)</span>
            </span>
            <textarea
              rows={3}
              maxLength={LIMITS.messageMax}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              disabled={busy}
              placeholder="Lost phone — please call +1 555 0100"
            />
            {messageProblem && (
              <span className="form-error" role="alert">
                {messageProblem}
              </span>
            )}
            <span className="counter" aria-live="polite">
              {message.length} / {LIMITS.messageMax}
            </span>
          </label>
          {message.trim() !== '' && (
            <p className="callout">
              Preview: <q>{message}</q>
            </p>
          )}
          <label className="check">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} disabled={busy} />
            I confirm that I want to lock this phone now.
          </label>
        </>
      )}

      {kind === 'clear_lock_message' && (
        <p>The message shown on the phone's lock screen is cleared. This command neither locks nor unlocks the phone.</p>
      )}

      {step === 3 && (
        <>
          {isWipe && (
            <div className="callout callout-bad">
              <p>
                Last step: <strong>{deviceName}</strong> will be erased as soon as it receives this command.
              </p>
            </div>
          )}
          {validityField}
          <ServerLimits compact />
          {recentBadSignatures > 0 && (
            <div className="callout callout-warn" role="alert">
              <strong>
                {recentBadSignatures} invalid signature{recentBadSignatures > 1 ? 's' : ''} in the last hour.
              </strong>{' '}
              At the fifth, the phone refuses every sensitive command for an hour. Check your passphrase before trying again.
            </div>
          )}
          {!cryptoOk && (
            <div className="state state-error" role="alert">
              WebCrypto is unavailable: open the console over HTTPS (or on localhost) to sign a command.
            </div>
          )}
          {codeField}
          {phase === 'signing' && (
            <p className="muted" role="status">
              Deriving the key (600,000 iterations) then signing: a few seconds.
            </p>
          )}
        </>
      )}

      {error && (
        <div className="state state-error" role="alert">
          {error}
        </div>
      )}
    </Dialog>
  );
}

function sendError(e: ApiError): string {
  if (e.status === 0) return e.message;
  return `The server refused the command. ${commandErrorMessage(e)}`;
}

