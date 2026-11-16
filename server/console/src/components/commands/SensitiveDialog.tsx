import { useRef, useState } from 'react';
import { api } from '../../api/endpoints.ts';
import { ApiError } from '../../api/client.ts';
import type { Device } from '../../api/types.ts';
import {
  canSign,
  codeProblem,
  commandErrorMessage,
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

const VALIDITIES = [
  { ms: HOUR_MS, label: '1 heure' },
  { ms: DAY_MS, label: '24 heures' },
  { ms: 7 * DAY_MS, label: '7 jours (par défaut)' },
  { ms: 30 * DAY_MS, label: '30 jours (maximum)' },
];

type Phase = 'idle' | 'signing' | 'sending';

/**
 * Commande sensible : le code est saisi à chaque fois dans un champ non contrôlé (il n'existe que dans le DOM de
 * ce champ, jamais dans l'état React), sert à dériver la clé puis la signature par WebCrypto, et le champ est
 * vidé aussitôt. Ni le code ni la clé ne sont stockés ni envoyés : seul `{ device_id, payload, sig }` part.
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
  const [validityMs, setValidityMs] = useState<number>(LIMITS.validitySensitiveMs);
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
      setError(problem ?? 'Saisissez votre code de commande.');
      return;
    }
    setError(undefined);
    let prepared;
    try {
      prepared = prepareCommand(device.device_id, kind, kind === 'lock' ? { message } : {}, validityMs);
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
      setError(e instanceof Error ? e.message : 'La signature a échoué.');
      return;
    } finally {
      // Le code ne reste nulle part : le champ est vidé dès que la signature est calculée.
      el.value = '';
      setCodeLen(0);
    }
    setPhase('sending');
    try {
      const r = await api.createCommand({ device_id: device.device_id, payload: prepared.payload, sig });
      onSent(r.id);
    } catch (e) {
      setPhase('idle');
      setError(e instanceof ApiError ? sendError(e) : 'Envoi impossible.');
    }
  };

  const title =
    kind === 'wipe' ? "Effacer le téléphone (réinitialisation d'usine)" : kind === 'lock' ? 'Verrouiller le téléphone avec un message' : 'Effacer le message de verrouillage';

  const codeField = (
    <div className="field">
      <label htmlFor="cmd-code">
        <strong>Code de commande</strong> <span className="muted">(12 caractères au moins, à ressaisir à chaque fois)</span>
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
          {showCode ? 'Masquer' : 'Afficher'}
        </button>
      </div>
      <p id="cmd-code-help" className="hint">
        {codeLen > 0 && codeLen < LIMITS.codeMin
          ? `${codeLen} caractère${codeLen > 1 ? 's' : ''} sur ${LIMITS.codeMin} au moins. `
          : ''}
        Le code est utilisé ici, dans ce navigateur, pour calculer la signature, puis effacé. Il n'est ni envoyé au serveur ni enregistré.
        Les espaces comptent.
      </p>
    </div>
  );

  const validityField = (
    <label className="field">
      <span>
        <strong>Validité de la commande</strong>
      </span>
      <select value={validityMs} onChange={(e) => setValidityMs(Number(e.target.value))} disabled={busy}>
        {VALIDITIES.map((v) => (
          <option key={v.ms} value={v.ms}>
            {v.label}
          </option>
        ))}
      </select>
      <span className="hint">
        Si le téléphone est éteint ou hors ligne, la commande l'attend jusqu'au {fmtDateTime(new Date(openedAt + validityMs))} ; passé ce délai elle
        expire sans jamais s'exécuter. Vous pouvez l'annuler tant qu'elle est « En attente ».
      </span>
    </label>
  );

  const footer = (
    <>
      <button type="button" className="btn" onClick={onClose} disabled={busy}>
        Annuler
      </button>
      {isWipe && step > 1 && (
        <button type="button" className="btn" onClick={() => setStep((s) => (s === 3 ? 2 : 1))} disabled={busy}>
          Retour
        </button>
      )}
      {isWipe && step === 1 && (
        <button type="button" className="btn btn-primary" onClick={() => setStep(2)} disabled={!confirmed}>
          Continuer
        </button>
      )}
      {isWipe && step === 2 && (
        <button type="button" className="btn btn-primary" onClick={() => setStep(lastStep)} disabled={!nameOk}>
          Continuer
        </button>
      )}
      {step === 3 && (
        <button
          type="button"
          className={`btn ${isWipe ? 'btn-danger' : 'btn-primary'}`}
          onClick={() => void submit()}
          disabled={busy || !cryptoOk || codeLen < LIMITS.codeMin || (kind === 'lock' && (!confirmed || !!messageProblem))}
        >
          {phase === 'signing' ? 'Calcul de la signature…' : phase === 'sending' ? 'Envoi…' : isWipe ? 'Signer et effacer définitivement' : 'Signer et envoyer'}
        </button>
      )}
    </>
  );

  return (
    <Dialog title={title} onClose={onClose} busy={busy} footer={footer} tone={isWipe ? 'danger' : undefined}>
      {isWipe && <p className="dlg-steps">Étape {stepNo} sur {stepCount}</p>}

      {isWipe && step === 1 && (
        <>
          <div className="callout callout-bad">
            <p>
              <strong>Cette action est irréversible.</strong> Le téléphone est réinitialisé aux paramètres d'usine : applications, photos, messages, comptes et
              réglages sont supprimés, sans corbeille ni retour en arrière. L'agent Vigie disparaît aussi : il faudra réenrôler l'appareil.
            </p>
          </div>
          <div className="callout callout-warn">
            <p>
              <strong>L'effacement doit avoir été autorisé dans l'application du téléphone</strong> (réglage « Autoriser l'effacement à distance », éteint par
              défaut). Sinon le téléphone refusera la commande (« canal désactivé ») et rien ne sera effacé.
            </p>
          </div>
          <p className="muted">
            À réserver à un téléphone perdu ou volé que vous ne reverrez pas. Pour le retrouver, utilisez plutôt <em>Sonner</em> et <em>Localiser maintenant</em> ;
            pour le protéger sans rien perdre, <em>Verrouiller avec message</em>.
          </p>
          <label className="check">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
            Je comprends que l'effacement est irréversible.
          </label>
        </>
      )}

      {isWipe && step === 2 && (
        <>
          <p>
            Pour confirmer, tapez le nom de l'appareil : <strong className="mono">{deviceName}</strong>
          </p>
          <label className="field">
            <span className="sr-only">Nom de l'appareil</span>
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
          {typedName !== '' && !nameOk && <p className="form-error">Ce n'est pas le nom exact de l'appareil.</p>}
        </>
      )}

      {kind === 'lock' && (
        <>
          <p>
            Le téléphone verrouille son écran tout de suite et affiche le message ci-dessous sur l'écran de verrouillage (avec Device Owner actif). Il se
            déverrouille ensuite normalement avec son code ou son empreinte.
          </p>
          <label className="field">
            <span>
              <strong>Message affiché</strong> <span className="muted">(facultatif)</span>
            </span>
            <textarea
              rows={3}
              maxLength={LIMITS.messageMax}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              disabled={busy}
              placeholder="Téléphone perdu, appelez le 01 23 45 67 89"
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
              Aperçu : <q>{message}</q>
            </p>
          )}
          <label className="check">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} disabled={busy} />
            Je confirme vouloir verrouiller ce téléphone maintenant.
          </label>
        </>
      )}

      {kind === 'clear_lock_message' && (
        <p>Le message affiché sur l'écran de verrouillage du téléphone est effacé. Le téléphone n'est ni verrouillé ni déverrouillé par cette commande.</p>
      )}

      {step === 3 && (
        <>
          {isWipe && (
            <div className="callout callout-bad">
              <p>
                Dernière étape : <strong>{deviceName}</strong> sera effacé dès qu'il recevra cette commande.
              </p>
            </div>
          )}
          {validityField}
          <ServerLimits compact />
          {recentBadSignatures > 0 && (
            <div className="callout callout-warn" role="alert">
              <strong>
                {recentBadSignatures} signature{recentBadSignatures > 1 ? 's' : ''} invalide{recentBadSignatures > 1 ? 's' : ''} dans la dernière heure.
              </strong>{' '}
              À la cinquième, le téléphone refuse toute commande sensible pendant une heure. Vérifiez votre code avant de réessayer.
            </div>
          )}
          {!cryptoOk && (
            <div className="state state-error" role="alert">
              WebCrypto est indisponible : ouvrez la console en HTTPS (ou sur localhost) pour signer une commande.
            </div>
          )}
          {codeField}
          {phase === 'signing' && (
            <p className="muted" role="status">
              Dérivation de la clé (600 000 itérations) puis signature : quelques secondes.
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
  return `Le serveur a refusé la commande. ${commandErrorMessage(e)}`;
}

