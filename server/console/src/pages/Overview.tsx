import { lazy, Suspense, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { usePagedEvents } from '../api/usePagedEvents.ts';
import type { Device } from '../api/types.ts';
import { Async, Badge, Card, Empty, LevelBadge, Loading, Stat, StatusPill } from '../components/ui.tsx';
import { EventList } from '../components/EventList.tsx';
import { DetectionsOverview } from '../components/detections/OverviewCard.tsx';
import { channelState } from '../lib/commands.ts';
import { blockedPct, hasStatusData, totalsOf } from '../lib/tracking.ts';
import { attentionPoints, evaluatePosture, overallStatus } from '../lib/posture.ts';
import { fmtBytes, fmtDateTime, fmtNumber, fmtPct, fmtRelative, fmtDuration } from '../lib/format.ts';
import { useNow } from '../lib/useNow.ts';
import { useDevice } from '../state/device.tsx';

const MapView = lazy(() => import('../components/MapView.tsx'));
const TimelineChart = lazy(() => import('../components/TimelineChart.tsx'));

const STALE_MS = 35 * 60_000; // deux pulsations manquées (15 min chacune) + marge

export default function Overview() {
  const { device } = useDevice();
  const now = useNow();
  const minute = Math.floor(now.getTime() / 60_000);
  const from24 = useMemo(() => new Date(minute * 60_000 - 24 * 3600_000).toISOString(), [minute]);
  const to = useMemo(() => new Date(minute * 60_000).toISOString(), [minute]);
  const id = device?.device_id;

  const timeline = useApi(id ? `tl:${id}:${minute}` : null, (s) =>
    api.timeline({ device_id: id, from: from24, to, bucket: 'hour', by: 'domain' }, s),
  );
  const alerts = useApi(`alerts:${Math.floor(minute / 5)}`, (s) =>
    api.alerts({ from: new Date(minute * 60_000 - 7 * 24 * 3600_000).toISOString(), to, limit: 5 }, s),
  );
  const tracking = useApi(id ? `ov-trk:${id}:${minute}` : null, (s) => api.trackingSummary({ device_id: id, from: from24, to }, s));
  const sevEvents = usePagedEvents(id ? { device_id: id, sev_min: 2, from: new Date(minute * 60_000 - 7 * 24 * 3600_000).toISOString(), to } : null, 8);

  if (!device) return null;
  return (
    <>
      <div className="page-head">
        <h1>Vue d'ensemble</h1>
        <span className="muted">
          {device.name} · <span className="mono">{device.device_id}</span>
        </span>
      </div>

      <DetectionsOverview deviceId={device.device_id} now={now} />

      <div className="grid">
        <Card title="État de l'appareil" className="span-7">
          <DeviceState device={device} now={now} />
        </Card>
        <Card
          title="Dernière position"
          className="span-5"
          actions={
            <Link to="/carte" className="btn btn-sm">
              Ouvrir la carte
            </Link>
          }
        >
          <LastPosition device={device} />
        </Card>
      </div>

      <div className="grid">
        <Card
          title="Posture de sécurité"
          className="span-5"
          actions={
            <Link to="/securite" className="btn btn-sm">
              Détails
            </Link>
          }
        >
          <PostureSummary device={device} />
        </Card>
        <Card title="Activité des dernières 24 h" className="span-7">
          <Async state={timeline} isEmpty={(t) => t.series.length === 0 || t.buckets.length === 0} empty="Aucun événement reçu sur les dernières 24 h.">
            {(t) => (
              <Suspense fallback={<Loading />}>
                <TimelineChart data={t} bucket="hour" ariaLabel="Événements par heure et par domaine" />
              </Suspense>
            )}
          </Async>
        </Card>
      </div>

      <div className="grid">
        <Card
          title="Commandes à distance"
          className="span-5"
          actions={
            <Link to="/commandes" className="btn btn-sm">
              Commandes
            </Link>
          }
        >
          <CommandsSummary device={device} now={now} />
        </Card>
        <Card
          title="Pistage des dernières 24 h"
          className="span-7"
          actions={
            <Link to="/pistage" className="btn btn-sm">
              Détails
            </Link>
          }
        >
          {tracking.error ? (
            <Empty>Vue pistage indisponible sur ce collecteur.</Empty>
          ) : (
            <Async state={tracking} isEmpty={(t) => t.publishers.length === 0} empty="Aucune requête DNS sur les dernières 24 h.">
              {(t) => {
                const totals = totalsOf(t.totals, t.publishers);
                const pct = blockedPct(totals);
                return (
                  <>
                    <div className="stats">
                      <Stat label="Requêtes DNS" value={fmtNumber(totals.queries)} />
                      {hasStatusData(totals) ? (
                        <Stat label="Bloquées" value={fmtNumber(totals.blocked)} sub={pct === undefined ? undefined : fmtPct(pct, 1)} tone="ok" />
                      ) : (
                        <Stat label="Blocage" value="Inconnu" sub={t.adguard ? 'aucun décompte' : 'AdGuard Home injoignable'} tone="warn" />
                      )}
                    </div>
                    <p className="hint">Vigie voit à qui le téléphone parle, pas le contenu des échanges (chiffré).</p>
                  </>
                );
              }}
            </Async>
          )}
        </Card>
      </div>

      <div className="grid">
        <Card
          title="Derniers événements (sévérité ≥ 2, 7 jours)"
          className="span-7"
          actions={
            <Link to="/evenements?sev_min=2" className="btn btn-sm">
              Tout voir
            </Link>
          }
        >
          <div className="flush">
            <EventList paged={sevEvents} compact empty="Aucun événement de sévérité 2 ou plus sur 7 jours." />
          </div>
        </Card>
        <Card
          title="Dernières alertes Wazuh"
          className="span-5"
          actions={
            <Link to="/alertes" className="btn btn-sm">
              Toutes
            </Link>
          }
        >
          <Async state={alerts}>
            {(a) =>
              !a.wazuh ? (
                <Empty>
                  Wazuh n'est pas configuré sur ce collecteur : aucune alerte disponible.
                </Empty>
              ) : a.alerts.length === 0 ? (
                <Empty>Aucune alerte sur 7 jours.</Empty>
              ) : (
                <ul className="findings">
                  {a.alerts.map((al, i) => (
                    <li key={`${al.ts}-${al.rule_id ?? ''}-${i}`}>
                      <LevelBadge level={al.level} />
                      <span className="f-label">{al.description ?? al.rule_id ?? 'Alerte'}</span>
                      <span className="f-val">
                        {fmtDateTime(al.ts)}
                        {al.rule_id ? ` · règle ${al.rule_id}` : ''}
                      </span>
                    </li>
                  ))}
                </ul>
              )
            }
          </Async>
        </Card>
      </div>
    </>
  );
}

function CommandsSummary({ device, now }: { device: Device; now: Date }) {
  const ch = device.command_channel;
  const st = channelState(ch, now);
  return (
    <>
      <div className="stats">
        <Stat label="Canal" value={st.label} tone={st.tone === 'neutral' ? undefined : st.tone} />
        <Stat label="Dernier contact" value={ch?.last_contact ? fmtRelative(ch.last_contact, now) : '—'} sub={ch?.last_contact ? fmtDateTime(ch.last_contact) : undefined} />
      </div>
      <p className="hint">{st.hint} Sonner, faire vibrer, localiser, verrouiller ou effacer : page Commandes.</p>
    </>
  );
}

function DeviceState({ device, now }: { device: Device; now: Date }) {
  const hb = device.last_heartbeat;
  const seen = device.last_seen ? new Date(device.last_seen) : undefined;
  const age = seen ? now.getTime() - seen.getTime() : undefined;
  const stale = age === undefined || age > STALE_MS;
  const collectors = Object.entries(hb?.collectors ?? {});
  const bad = collectors.filter(([, s]) => s !== 'running');
  return (
    <>
      {device.revoked && (
        <div className="state state-error" role="alert">
          Cet appareil est révoqué : ses envois sont refusés.
        </div>
      )}
      {!device.revoked && stale && (
        <div className="state state-warn" role="alert">
          {seen ? (
            <>
              Aucun contact depuis <strong>{fmtDuration(age)}</strong> (dernier : {fmtDateTime(device.last_seen)}). Le téléphone est
              peut-être éteint, hors ligne ou l'agent est arrêté.
            </>
          ) : (
            <>Cet appareil n'a encore jamais envoyé de données.</>
          )}
        </div>
      )}
      <div className="stats">
        <Stat
          label="Dernier contact"
          value={seen ? fmtRelative(device.last_seen, now) : '—'}
          sub={seen ? fmtDateTime(device.last_seen) : undefined}
          tone={stale ? 'bad' : 'ok'}
        />
        <Stat
          label="Batterie"
          value={hb?.battery_pct !== undefined ? fmtPct(hb.battery_pct) : '—'}
          sub={hb?.charging === undefined ? undefined : hb.charging ? 'en charge' : 'sur batterie'}
          tone={hb?.battery_pct !== undefined && hb.battery_pct < 15 && !hb.charging ? 'warn' : undefined}
        />
        <Stat
          label="Tampon en attente"
          value={hb?.queue_depth !== undefined ? `${fmtNumber(hb.queue_depth)} évt` : '—'}
          sub={hb?.queue_bytes !== undefined ? fmtBytes(hb.queue_bytes) : undefined}
          tone={hb?.queue_depth !== undefined && hb.queue_depth > 500 ? 'warn' : undefined}
        />
        <Stat
          label="Device Owner"
          value={hb?.device_owner === undefined ? '—' : hb.device_owner ? 'Actif' : 'Inactif'}
          sub={hb?.device_owner === false ? 'mode dégradé' : undefined}
          tone={hb?.device_owner === undefined ? undefined : hb.device_owner ? 'ok' : 'warn'}
        />
        <Stat label="Agent" value={device.agent_version ? `v${device.agent_version}` : '—'} sub={hb?.uptime_ms !== undefined ? `actif depuis ${fmtDuration(hb.uptime_ms)}` : undefined} />
        <Stat
          label="Événements perdus"
          value={hb?.dropped_total !== undefined ? fmtNumber(hb.dropped_total) : '—'}
          sub={hb?.last_upload_ts ? `dernier envoi ${fmtRelative(hb?.last_upload_ts, now)}` : undefined}
          tone={hb?.dropped_total ? 'warn' : undefined}
        />
      </div>
      <h3 className="section-title">Collecteurs</h3>
      {collectors.length === 0 ? (
        <p className="muted">État des collecteurs inconnu (aucune pulsation reçue).</p>
      ) : (
        <>
          <p className="muted">
            {collectors.length - bad.length} en marche sur {collectors.length}
            {bad.length > 0 ? ` — ${bad.length} à surveiller` : ''}.
          </p>
          <ul className="chip-list" aria-label="État des collecteurs">
            {collectors.map(([id, st]) => (
              <li key={id}>
                <Badge tone={st === 'running' ? 'ok' : st === 'unavailable' ? 'bad' : 'neutral'} title={collectorStateLabel(st)}>
                  {id} · {collectorStateLabel(st)}
                </Badge>
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}

function collectorStateLabel(s: string): string {
  return s === 'running' ? 'en marche' : s === 'disabled' ? 'désactivé' : s === 'unavailable' ? 'indisponible' : s;
}

function LastPosition({ device }: { device: Device }) {
  const loc = device.last_location;
  const points = useMemo(
    () => (loc ? [{ lat: loc.lat, lon: loc.lon, t: new Date(loc.ts).getTime(), ...(loc.acc_m !== undefined ? { acc: loc.acc_m } : {}) }] : []),
    [loc],
  );
  if (!loc) return <Empty>Aucune position reçue pour cet appareil.</Empty>;
  return (
    <>
      <div className="map-sm">
        <Suspense fallback={<Loading label="Chargement de la carte…" />}>
          <MapView points={points} selected={0} interactive={false} ariaLabel="Dernière position connue de l'appareil" />
        </Suspense>
      </div>
      <p className="hint overview-pos">
        {fmtDateTime(loc.ts)} ({fmtRelative(loc.ts)})
        {loc.acc_m !== undefined ? ` · précision ±${fmtNumber(loc.acc_m)} m` : ''} · {fmtNumber(loc.lat, 5)}, {fmtNumber(loc.lon, 5)}
      </p>
    </>
  );
}

function PostureSummary({ device }: { device: Device }) {
  const findings = useMemo(() => evaluatePosture(device.last_posture), [device.last_posture]);
  if (findings.length === 0) return <Empty>Aucune posture reçue pour cet appareil.</Empty>;
  const status = overallStatus(findings);
  const points = attentionPoints(findings);
  const ok = findings.filter((f) => f.status === 'ok').length;
  return (
    <>
      <p>
        <StatusPill status={status} />{' '}
        <span className="muted">
          {ok} contrôle{ok > 1 ? 's' : ''} conforme{ok > 1 ? 's' : ''} sur {findings.length}
        </span>
      </p>
      {points.length === 0 ? (
        <p>Aucun point d'attention.</p>
      ) : (
        <ul className="findings" aria-label="Points d'attention">
          {points.map((f) => (
            <li key={f.id}>
              <StatusPill status={f.status} />
              <span className="f-label">{f.label}</span>
              <span className="f-val">
                {f.value}
                {f.detail ? ` — ${f.detail}` : ''}
              </span>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
