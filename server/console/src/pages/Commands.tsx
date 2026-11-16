import { lazy, Suspense, useCallback, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { ApiError, clockSkewMs } from '../api/client.ts';
import { useCommandList } from '../api/useCommands.ts';
import { useEventStream } from '../api/useEventStream.ts';
import type { Device, LastLocation, WatchpostEvent } from '../api/types.ts';
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
  // "Locate now": instant of the request, then location received since.
  const [locateSince, setLocateSince] = useState<number | undefined>();
  const [fixArrived, setFixArrived] = useState(false);
  // Arrival detected on the SSE stream after the request (no comparison of phone / browser clocks).
  const waitingFix = useRef(false);
  const [liveLoc, setLiveLoc] = useState<(LastLocation & { provider?: string }) | undefined>();

  const reloadList = list.reload;
  const onEvent = useCallback(
    (ev: WatchpostEvent) => {
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

  // The location displayed: the most recent between the device's and the one received live.
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
    setNotice({ tone: 'bad', text: `The command was not sent. ${msg}` });
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
        text: `"${commandLabel(type)}" sent to the server. ${channel.key === 'connected' ? 'The phone receives it in a moment.' : 'It waits for the phone to connect (see the channel state).'}`,
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
          ? `Command cancelled on the server side: it will no longer deliver it. ${SIGNED_CAVEAT}`
          : 'Command cancelled: it will never be executed.',
      });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setNotice({ tone: 'warn', text: 'Too late: the command is no longer "Pending" (the phone already received it).' });
      else fail(e);
    } finally {
      setCancelling(undefined);
      list.reload();
    }
  };

  return (
    <>
      <div className="page-head">
        <h1>Remote commands</h1>
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
          This device is revoked: no command can be sent to it.
        </div>
      )}

      {notice && (
        <div className={`state ${notice.tone === 'ok' ? 'state-ok' : notice.tone === 'warn' ? 'state-warn' : 'state-error'}`} role="status" aria-live="polite">
          {notice.text}
        </div>
      )}

      <div className="grid grid-start">
        <div className="span-7 stack">
          <Card title="Command channel">
            <ChannelPanel device={device} now={now} streamOpen={stream === 'open'} />
          </Card>
          <Card title="Simple actions">
            <p className="hint">No passphrase: the server can relay them on its own. Valid for 1 hour.</p>
            <SimpleActions disabled={disabled} onSend={(t, p) => void sendSimple(t, p)} />
          </Card>
        </div>
        <div className="span-5 stack">
          <Card
            title="Last location"
            actions={
              <Link to="/map" className="btn btn-sm">
                Open the map
              </Link>
            }
          >
            <PositionPanel loc={loc} locateSince={locateSince} fixArrived={fixArrived} />
          </Card>
          <Card title="Sensitive actions (signed)">
            {!canSign() && (
              <div className="state state-error" role="alert">
                WebCrypto is unavailable in this context: open the console over HTTPS (or on localhost) to sign.
              </div>
            )}
            <div className="cmd-list">
              <div className="cmd-row">
                <div className="cmd-info">
                  <strong>Lock with message</strong>
                  <span className="hint">Locks the screen and shows a message of your choice.</span>
                </div>
                <div className="cmd-ctl">
                  <button type="button" className="btn btn-primary" disabled={disabled} onClick={() => setDialog('lock')}>
                    Lock…
                  </button>
                </div>
              </div>
              <div className="cmd-row">
                <div className="cmd-info">
                  <strong>Clear the message</strong>
                  <span className="hint">Removes the message from the lock screen.</span>
                </div>
                <div className="cmd-ctl">
                  <button type="button" className="btn" disabled={disabled} onClick={() => setDialog('clear_lock_message')}>
                    Clear the message…
                  </button>
                </div>
              </div>
            </div>
            <ServerLimits />
          </Card>
        </div>
      </div>

      <div className="grid">
        <Card title="Danger zone" className="span-12 card-danger">
          <div className="cmd-row">
            <div className="cmd-info">
              <strong>Erase the phone</strong>
              <span className="hint">
                Factory reset, irreversible. Requires the erase to be allowed in the phone app; confirmation in three
                steps (explanation, device name, passphrase). The command is only valid for 15 minutes by default (24 hours at most).
              </span>
            </div>
            <div className="cmd-ctl">
              <button type="button" className="btn btn-danger" disabled={disabled} onClick={() => setDialog('wipe')}>
                Erase the phone…
              </button>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid">
        <Card title="Command history" className="span-12" actions={<span className="hint">Updated live</span>}>
          {badSigs > 0 && (
            <div className="callout callout-warn history-warn" role="alert">
              <strong>
                {badSigs} command{badSigs > 1 ? 's' : ''} refused for an invalid signature in the last hour.
              </strong>{' '}
              The passphrase entered is probably not the one set in the phone app. At the fifth, the phone blocks every sensitive
              command for an hour.
            </div>
          )}
          <div className="flush">
            {list.error && !list.commands ? (
              <ErrorBox message={list.error.message} onRetry={list.reload} />
            ) : list.loading ? (
              <Loading label="Loading the history…" />
            ) : cmds.length === 0 ? (
              <Empty>No command sent to this device.</Empty>
            ) : (
              <CommandHistory commands={cmds} onCancel={(id) => void cancel(id)} cancelling={cancelling} />
            )}
          </div>
          {list.error && list.commands && <p className="form-error">Refresh failed: {list.error.message}</p>}
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
              text: `"${commandLabel(dialog)}" signed and sent. Follow its state in the history: only the phone can confirm that the signature is valid.`,
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
  const mode = ch?.mode === 'stream' ? 'permanent connection' : ch?.mode === 'poll' ? 'periodic polling' : 'unknown mode';
  return (
    <>
      <div className="stats">
        <Stat label="State" value={st.label} tone={st.tone === 'neutral' ? undefined : st.tone} sub={st.key === 'unknown' ? undefined : st.key === 'polling' ? 'every 1 to 15 min' : mode} />
        <Stat
          label="Last contact"
          value={ch?.last_contact ? fmtRelative(ch.last_contact, now) : '—'}
          sub={ch?.last_contact ? fmtDateTime(ch.last_contact) : 'no known contact'}
        />
        <Stat label="Console" value={streamOpen ? 'Live' : 'No stream'} sub="event stream" tone={streamOpen ? 'ok' : 'warn'} />
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
          Location requested at {fmtTime(locateSince)}: waiting for the new location…
        </p>
      )}
      {locateSince !== undefined && fixArrived && (
        <p className="state state-ok" role="status">
          New location received: the map is up to date.
        </p>
      )}
      {!loc ? (
        <Empty>No location received for this device.</Empty>
      ) : (
        <>
          <div className="map-sm">
            <Suspense fallback={<Loading label="Loading the map…" />}>
              <MapView points={points} selected={0} interactive={false} ariaLabel="Last known location of the device" />
            </Suspense>
          </div>
          <p className="hint overview-pos" data-testid="pos-info">
            {fmtDateTime(loc.ts)} ({fmtRelative(loc.ts)})
            {loc.acc_m !== undefined ? ` · accuracy ±${fmtNumber(loc.acc_m)} m` : ''} · {fmtNumber(loc.lat, 5)}, {fmtNumber(loc.lon, 5)}
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

