import { lazy, Suspense, useCallback, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { ApiError, clockSkewMs } from '../api/client.ts';
import { useCommandList } from '../api/useCommands.ts';
import { useEventStream } from '../api/useEventStream.ts';
import type { Device, LastLocation, VigieEvent } from '../api/types.ts';
import { Badge, Card, Empty, ErrorBox, Loading, Stat } from '../components/ui.tsx';
import { CommandHistory } from '../components/commands/CommandHistory.tsx';
import { SimpleActions } from '../components/commands/SimpleActions.tsx';
import { SensitiveDialog, type SensitiveKind } from '../components/commands/SensitiveDialog.tsx';
import { ServerLimits } from '../components/commands/ServerLimits.tsx';
import {
  badSignatureCount,
  canSign,
  channelState,
  clockProblem,
  commandErrorMessage,
  commandLabel,
  defaultValidityMs,
  isSensitive,
  issueTime,
  prepareCommand,
  SIGNED_CAVEAT,
  type CommandParams,
  type CommandType,
} from '../lib/commands.ts';
import { num, str } from '../lib/data.ts';
import { fmtDateTime, fmtNumber, fmtRelative, fmtTime } from '../lib/format.ts';
import { providerInfo } from '../lib/provider.ts';
import { useNow } from '../lib/useNow.ts';
import { useDevice } from '../state/device.tsx';

const MapView = lazy(() => import('../components/MapView.tsx'));

interface Notice {
  tone: 'ok' | 'bad' | 'warn';
  text: string;
}

export default function Commands() {
  const { device, reload: reloadDevices } = useDevice();
  const now = useNow();
  const deviceId = device?.device_id;
  const list = useCommandList(deviceId);
  const [notice, setNotice] = useState<Notice | undefined>();
  const [sending, setSending] = useState(false);
  const [dialog, setDialog] = useState<SensitiveKind | undefined>();
  const [cancelling, setCancelling] = useState<string | undefined>();
  // « Localiser maintenant » : instant de la demande, puis position reçue depuis.
  const [locateSince, setLocateSince] = useState<number | undefined>();
  const [fixArrived, setFixArrived] = useState(false);
  // Arrivée détectée sur le flux SSE après la demande (pas de comparaison d'horloges téléphone / navigateur).
  const waitingFix = useRef(false);
  const [liveLoc, setLiveLoc] = useState<(LastLocation & { provider?: string }) | undefined>();

  const reloadList = list.reload;
  const onEvent = useCallback(
    (ev: VigieEvent) => {
      if (ev.type === 'command.result') reloadList();
      if (ev.type === 'location.fix') {
        const lat = num(ev.data, 'lat');
        const lon = num(ev.data, 'lon');
        if (lat === undefined || lon === undefined) return;
        const acc = num(ev.data, 'acc_m');
        const provider = str(ev.data, 'provider');
        if (waitingFix.current) {
          waitingFix.current = false;
          setFixArrived(true);
        }
        setLiveLoc({ ts: ev.ts, lat, lon, ...(acc !== undefined ? { acc_m: acc } : {}), ...(provider ? { provider } : {}) });
        reloadDevices();
      }
    },
    [reloadList, reloadDevices],
  );
  const stream = useEventStream(!!deviceId, deviceId, onEvent);

  // La position affichée : la plus récente entre celle de l'appareil et celle reçue en direct.
  const loc = useMemo(() => {
    const base = device?.last_location;
    if (liveLoc && (!base || Date.parse(liveLoc.ts) >= Date.parse(base.ts))) return liveLoc;
    return base;
  }, [device?.last_location, liveLoc]);

  if (!device || !deviceId) return null;
  const channel = channelState(device.command_channel, now);
  const disabled = sending || !!device.revoked;
  const cmds = list.commands ?? [];
  const badSigs = badSignatureCount(cmds, now);

  const fail = (e: unknown) => {
    const msg = e instanceof ApiError ? commandErrorMessage(e) : String(e);
    setNotice({ tone: 'bad', text: `La commande n'a pas été envoyée. ${msg}` });
  };

  const sendSimple = async (type: Extract<CommandType, 'ring' | 'vibrate' | 'stop_ring' | 'locate'>, params: CommandParams) => {
    setSending(true);
    setNotice(undefined);
    try {
      const c = prepareCommand(deviceId, type, params, defaultValidityMs(type), issueTime(Date.now(), clockSkewMs()));
      await api.createCommand({ device_id: deviceId, payload: c.payload });
      if (type === 'locate') {
        waitingFix.current = true;
        setFixArrived(false);
        setLocateSince(Date.now());
      }
      setNotice({
        tone: 'ok',
        text: `« ${commandLabel(type)} » envoyée au serveur. ${channel.key === 'connected' ? 'Le téléphone la reçoit dans un instant.' : "Elle attend que le téléphone se connecte (voir l'état du canal)."}`,
      });
      list.reload();
    } catch (e) {
      fail(e);
    } finally {
      setSending(false);
    }
  };

  const cancel = async (id: string) => {
    setCancelling(id);
    try {
      await api.cancelCommand(id);
      const cancelled = cmds.find((c) => c.id === id);
      const signed = cancelled ? (cancelled.signed ?? isSensitive(cancelled.type)) : false;
      setNotice({
        tone: signed ? 'warn' : 'ok',
        text: signed
          ? `Commande annulée côté serveur : il ne la remettra plus. ${SIGNED_CAVEAT}`
          : 'Commande annulée : elle ne sera jamais exécutée.',
      });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setNotice({ tone: 'warn', text: "Trop tard : la commande n'est plus « En attente » (le téléphone l'a déjà reçue)." });
      else fail(e);
    } finally {
      setCancelling(undefined);
      list.reload();
    }
  };

  return (
    <>
      <div className="page-head">
        <h1>Commandes à distance</h1>
        <span className="muted">
          {device.name} · <span className="mono">{device.device_id}</span>
        </span>
      </div>

      {clockProblem(clockSkewMs()) && (
        <div className="state state-warn" role="alert">
          {clockProblem(clockSkewMs())}
        </div>
      )}

      {device.revoked && (
        <div className="state state-error" role="alert">
          Cet appareil est révoqué : aucune commande ne peut lui être envoyée.
        </div>
      )}

      {notice && (
        <div className={`state ${notice.tone === 'ok' ? 'state-ok' : notice.tone === 'warn' ? 'state-warn' : 'state-error'}`} role="status" aria-live="polite">
          {notice.text}
        </div>
      )}

      <div className="grid grid-start">
        <div className="span-7 stack">
          <Card title="Canal de commandes">
            <ChannelPanel device={device} now={now} streamOpen={stream === 'open'} />
          </Card>
          <Card title="Actions simples">
            <p className="hint">Sans code : le serveur peut les relayer seul. Valables 1 heure.</p>
            <SimpleActions disabled={disabled} onSend={(t, p) => void sendSimple(t, p)} />
          </Card>
        </div>
        <div className="span-5 stack">
          <Card
            title="Dernière position"
            actions={
              <Link to="/carte" className="btn btn-sm">
                Ouvrir la carte
              </Link>
            }
          >
            <PositionPanel loc={loc} locateSince={locateSince} fixArrived={fixArrived} />
          </Card>
          <Card title="Actions sensibles (signées)">
            {!canSign() && (
              <div className="state state-error" role="alert">
                WebCrypto est indisponible dans ce contexte : ouvrez la console en HTTPS (ou sur localhost) pour signer.
              </div>
            )}
            <div className="cmd-list">
              <div className="cmd-row">
                <div className="cmd-info">
                  <strong>Verrouiller avec message</strong>
                  <span className="hint">Verrouille l'écran et affiche un message de votre choix.</span>
                </div>
                <div className="cmd-ctl">
                  <button type="button" className="btn btn-primary" disabled={disabled} onClick={() => setDialog('lock')}>
                    Verrouiller…
                  </button>
                </div>
              </div>
              <div className="cmd-row">
                <div className="cmd-info">
                  <strong>Effacer le message</strong>
                  <span className="hint">Retire le message de l'écran de verrouillage.</span>
                </div>
                <div className="cmd-ctl">
                  <button type="button" className="btn" disabled={disabled} onClick={() => setDialog('clear_lock_message')}>
                    Effacer le message…
                  </button>
                </div>
              </div>
            </div>
            <ServerLimits />
          </Card>
        </div>
      </div>

      <div className="grid">
        <Card title="Zone dangereuse" className="span-12 card-danger">
          <div className="cmd-row">
            <div className="cmd-info">
              <strong>Effacer le téléphone</strong>
              <span className="hint">
                Réinitialisation d'usine, irréversible. Exige que l'effacement soit autorisé dans l'application du téléphone ; confirmation en trois
                étapes (explication, nom de l'appareil, code). La commande n'est valable que 15 minutes par défaut (24 heures au plus).
              </span>
            </div>
            <div className="cmd-ctl">
              <button type="button" className="btn btn-danger" disabled={disabled} onClick={() => setDialog('wipe')}>
                Effacer le téléphone…
              </button>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid">
        <Card title="Historique des commandes" className="span-12" actions={<span className="hint">Mis à jour en direct</span>}>
          {badSigs > 0 && (
            <div className="callout callout-warn history-warn" role="alert">
              <strong>
                {badSigs} commande{badSigs > 1 ? 's' : ''} refusée{badSigs > 1 ? 's' : ''} pour signature invalide dans la dernière heure.
              </strong>{' '}
              Le code saisi n'est probablement pas celui défini dans l'application du téléphone. À la cinquième, le téléphone bloque toute commande
              sensible pendant une heure.
            </div>
          )}
          <div className="flush">
            {list.error && !list.commands ? (
              <ErrorBox message={list.error.message} onRetry={list.reload} />
            ) : list.loading ? (
              <Loading label="Chargement de l'historique…" />
            ) : cmds.length === 0 ? (
              <Empty>Aucune commande envoyée à cet appareil.</Empty>
            ) : (
              <CommandHistory commands={cmds} onCancel={(id) => void cancel(id)} cancelling={cancelling} />
            )}
          </div>
          {list.error && list.commands && <p className="form-error">Actualisation impossible : {list.error.message}</p>}
        </Card>
      </div>

      {dialog && (
        <SensitiveDialog
          key={dialog}
          kind={dialog}
          device={device}
          recentBadSignatures={badSigs}
          onClose={() => setDialog(undefined)}
          onSent={() => {
            setDialog(undefined);
            setNotice({
              tone: 'ok',
              text: `« ${commandLabel(dialog)} » signée et envoyée. Suivez son état dans l'historique : seul le téléphone peut confirmer que la signature est valide.`,
            });
            list.reload();
          }}
        />
      )}
    </>
  );
}

function ChannelPanel({ device, now, streamOpen }: { device: Device; now: Date; streamOpen: boolean }) {
  const ch = device.command_channel;
  const st = channelState(ch, now);
  const mode = ch?.mode === 'stream' ? 'connexion permanente' : ch?.mode === 'poll' ? 'interrogation périodique' : 'mode inconnu';
  return (
    <>
      <div className="stats">
        <Stat label="État" value={st.label} tone={st.tone === 'neutral' ? undefined : st.tone} sub={st.key === 'unknown' ? undefined : st.key === 'polling' ? 'toutes les 1 à 15 min' : mode} />
        <Stat
          label="Dernier contact"
          value={ch?.last_contact ? fmtRelative(ch.last_contact, now) : '—'}
          sub={ch?.last_contact ? fmtDateTime(ch.last_contact) : 'aucun contact connu'}
        />
        <Stat label="Console" value={streamOpen ? 'En direct' : 'Hors flux'} sub="flux des événements" tone={streamOpen ? 'ok' : 'warn'} />
      </div>
      <p className="hint cmd-hint">{st.hint}</p>
    </>
  );
}

function PositionPanel({ loc, locateSince, fixArrived }: { loc: (LastLocation & { provider?: string }) | undefined; locateSince: number | undefined; fixArrived: boolean }) {
  const points = useMemo(
    () => (loc ? [{ lat: loc.lat, lon: loc.lon, t: new Date(loc.ts).getTime(), ...(loc.acc_m !== undefined ? { acc: loc.acc_m } : {}), ...(loc.provider ? { provider: loc.provider } : {}) }] : []),
    [loc],
  );
  return (
    <>
      {locateSince !== undefined && !fixArrived && (
        <p className="state state-warn" role="status">
          Localisation demandée à {fmtTime(locateSince)} : en attente de la nouvelle position…
        </p>
      )}
      {locateSince !== undefined && fixArrived && (
        <p className="state state-ok" role="status">
          Nouvelle position reçue : la carte est à jour.
        </p>
      )}
      {!loc ? (
        <Empty>Aucune position reçue pour cet appareil.</Empty>
      ) : (
        <>
          <div className="map-sm">
            <Suspense fallback={<Loading label="Chargement de la carte…" />}>
              <MapView points={points} selected={0} interactive={false} ariaLabel="Dernière position connue de l'appareil" />
            </Suspense>
          </div>
          <p className="hint overview-pos" data-testid="pos-info">
            {fmtDateTime(loc.ts)} ({fmtRelative(loc.ts)})
            {loc.acc_m !== undefined ? ` · précision ±${fmtNumber(loc.acc_m)} m` : ''} · {fmtNumber(loc.lat, 5)}, {fmtNumber(loc.lon, 5)}
            {loc.provider ? (
              <>
                {' '}
                · <Badge tone={providerInfo(loc.provider).google ? 'warn' : 'neutral'}>{providerInfo(loc.provider).label}</Badge>
              </>
            ) : null}
          </p>
        </>
      )}
    </>
  );
}

