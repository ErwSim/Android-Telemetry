import { useCallback, useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { useEventStream } from '../api/useEventStream.ts';
import { usePagedDetections } from '../api/usePagedDetections.ts';
import { usePagedEvents } from '../api/usePagedEvents.ts';
import type { VigieEvent } from '../api/types.ts';
import { AppDomains } from '../components/AppDomains.tsx';
import { AppName } from '../components/AppName.tsx';
import { opsCollectorState } from '../components/apps/OpsView.tsx';
import { installerText } from '../components/apps/RiskView.tsx';
import { DetectionCard } from '../components/detections/DetectionCard.tsx';
import { EventList } from '../components/EventList.tsx';
import { ComboCallout, GrantNote, ReasonList, RiskBadge, ScoreBar } from '../components/risk/Risk.tsx';
import { Async, Badge, Card, Empty, ErrorBox, KV, Loading } from '../components/ui.tsx';
import { isRecord, list } from '../lib/data.ts';
import { applyMutes, detectionFromEvent, isMuteEvent, matchesDetection } from '../lib/detections.ts';
import { useMuting } from '../components/detections/Mute.tsx';
import { describeEvent, installerLabel, isSideloaded, permissionLabel } from '../lib/events.ts';
import { fmtDate, fmtDateTime, fmtNumber } from '../lib/format.ts';
import { groupByApp, opInfo } from '../lib/ops.ts';
import { combosOf } from '../lib/risk.ts';
import { involves, roleChanges, roleLabel, rolesHeldBy, roleWhy } from '../lib/roles.ts';
import { cleanText } from '../lib/text.ts';
import { useNow } from '../lib/useNow.ts';
import { useDevice } from '../state/device.tsx';
import { isUnsupported, useAppOps, useAppRisk, useMutes } from '../state/appData.ts';

const DAY = 86_400_000;
const HISTORY_TYPES = 'app.installed,app.updated,app.removed,app.permission_changed';

/**
 * Fiche d'une application : profil de risque et raisons, rôles par défaut, permissions, opérations sensibles,
 * domaines contactés et détections. Réunit ce que les autres pages montrent application par application.
 */
export default function AppSheet() {
  const [sp] = useSearchParams();
  const pkg = sp.get('pkg') ?? '';
  const { deviceId, device } = useDevice();
  const now = useNow(300_000);
  const slot = Math.floor(now.getTime() / 300_000) * 300_000;
  const to = new Date(slot + 300_000).toISOString();
  const from30 = new Date(slot - 30 * DAY).toISOString();
  const from90 = new Date(slot - 90 * DAY).toISOString();
  const from7 = new Date(slot - 7 * DAY).toISOString();

  const inventory = useApi(deviceId ? `apps:${deviceId}` : null, (s) => api.apps(deviceId, s));
  const risk = useAppRisk();
  const app = inventory.data?.apps.find((a) => a.package === pkg);
  const profile = risk.data?.apps.find((a) => a.package === pkg);
  const label = cleanText(app?.label ?? profile?.label, 80) || undefined;

  return (
    <>
      <Link className="back-link" to="/applications">
        ← Applications
      </Link>
      <div className="sheet-head">
        <h1>{label ?? cleanText(pkg, 255)}</h1>
        {profile && <RiskBadge risk={profile} />}
        {app?.system && <Badge>système</Badge>}
        {app && isSideloaded(app) && <Badge tone="warn">hors boutique</Badge>}
        {app?.enabled === false && <Badge tone="warn">désactivée</Badge>}
      </div>
      <div className="sheet-sub">
        <AppName pkg={cleanText(pkg, 255)} label={label} />
        {device && <span>· {device.name || device.device_id}</span>}
        <Link className="btn btn-sm" to={`/pistage?app=${encodeURIComponent(pkg)}`}>
          Pistage
        </Link>
        <Link className="btn btn-sm" to={`/reseau?app=${encodeURIComponent(pkg)}`}>
          Réseau
        </Link>
      </div>

      {!inventory.loading && inventory.data && !app && !profile && (
        <div className="state state-warn" role="status">
          Cette application ne figure ni dans le dernier inventaire ni dans les profils de risque : elle a peut-être été désinstallée, ou le paquet est mal orthographié.
        </div>
      )}

      <div className="grid grid-start">
        <Card title="Profil de risque" className="span-7">
          <RiskCard state={risk} pkg={pkg} />
        </Card>
        <div className="span-5 stack">
          <Card title="Rôles par défaut">
            <RolesCard pkg={pkg} from={from90} to={to} />
          </Card>
          <Card title="Informations">
            {app ? (
              <KV
                items={[
                  { k: 'Version', v: `${app.version_name ?? '—'}${app.version_code !== undefined ? ` (code ${app.version_code})` : ''}` },
                  { k: 'Installateur', v: profile ? installerText(profile, app) : installerLabel(app.installer) },
                  { k: 'SDK cible', v: app.target_sdk ?? '—' },
                  { k: 'Première installation', v: fmtDateTime(app.first_install) },
                  { k: 'Dernière mise à jour', v: fmtDateTime(app.last_update) },
                  { k: 'Signature SHA-256', v: app.signer_sha256 ? <code className="break">{app.signer_sha256}</code> : '—' },
                ]}
              />
            ) : (
              <Empty>Aucune information d'inventaire.</Empty>
            )}
          </Card>
        </div>
      </div>

      <div className="grid">
        <Card title="Détections concernant cette application" className="span-12">
          <SheetDetections pkg={pkg} from={from30} to={to} now={now} />
        </Card>
      </div>

      <div className="grid grid-start">
        <Card title={`Permissions dangereuses accordées${app ? ` (${app.granted_dangerous?.length ?? 0})` : ''}`} className="span-6">
          {!app ? (
            <Empty>Application absente de l'inventaire.</Empty>
          ) : (app.granted_dangerous ?? []).length === 0 ? (
            <p className="muted">Aucune.</p>
          ) : (
            <ul className="chip-list">
              {(app.granted_dangerous ?? []).map((p) => (
                <li key={p} className="chip" title={p}>
                  {permissionLabel(p)}
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Opérations sensibles (30 jours, expérimental)" className="span-6">
          <SheetOps pkg={pkg} from={from30} to={to} />
        </Card>
      </div>

      <div className="grid">
        <Card title="Domaines contactés (7 jours)" className="span-12">
          {deviceId ? <AppDomains deviceId={deviceId} pkg={pkg} from={from7} to={to} usage={undefined} /> : null}
        </Card>
      </div>

      <div className="grid">
        <Card title="Historique (installations, mises à jour, permissions)" className="span-12">
          <SheetHistory pkg={pkg} from={from90} to={to} />
        </Card>
      </div>
    </>
  );
}

function RiskCard({ state, pkg }: { state: ReturnType<typeof useAppRisk>; pkg: string }) {
  if (isUnsupported(state.error)) return <Empty>Ce collecteur ne fournit pas encore le profil de risque (contrat v1.2).</Empty>;
  return (
    <Async state={state}>
      {(d) => {
        const r = d.apps.find((a) => a.package === pkg);
        if (!r) {
          return (
            <Empty>
              Aucun profil de risque reçu pour cette application. L'agent v1.2 en envoie un à l'installation, à la mise à jour, puis chaque jour si le score ou les raisons changent.
            </Empty>
          );
        }
        return (
          <>
            <div className="stats">
              <div className="stat">
                <div className="stat-label">Score</div>
                <div className="stat-value">
                  <ScoreBar risk={r} />
                </div>
                <div className="stat-sub">sur 100 · {r.reasons.length} raison{r.reasons.length > 1 ? 's' : ''}</div>
              </div>
              <div className="stat">
                <div className="stat-label">Niveau</div>
                <div className="stat-value">
                  <RiskBadge risk={r} />
                </div>
                <div className="stat-sub">{r.ts ? `relevé le ${fmtDate(r.ts)}` : ' '}</div>
              </div>
              <div className="stat">
                <div className="stat-label">Installateur</div>
                <div className="stat-value">{r.from_store === false ? 'Hors boutique' : r.from_store ? 'Boutique' : 'Inconnu'}</div>
                <div className="stat-sub">{installerLabel(r.installer)}</div>
              </div>
            </div>
            <p className="hint">Le score mesure ce que l'application pourrait faire, pas ce qu'elle fait : c'est un motif de regarder de plus près, pas une preuve.</p>
            <GrantNote hasGranted={r.granted !== undefined} />
            <ComboCallout reasons={r.reasons} />
            <ReasonList reasons={r.reasons.filter((c) => !combosOf(c ? [c] : []).length)} granted={r.granted} />
          </>
        );
      }}
    </Async>
  );
}

/** Rôles tenus aujourd'hui (d'après `app.special_access`) et historique `app.role` où l'application gagne ou perd un rôle. */
function RolesCard({ pkg, from, to }: { pkg: string; from: string; to: string }) {
  const { deviceId } = useDevice();
  const special = usePagedEvents(deviceId ? { device_id: deviceId, type: 'app.special_access', from, to } : null, 1);
  const roles = usePagedEvents(deviceId ? { device_id: deviceId, type: 'app.role', q: pkg, from, to } : null, 100);
  const defaults = special.events[0]?.data['default_apps'];
  const held = rolesHeldBy(isRecord(defaults) ? defaults : undefined, pkg);
  const accessibility = list<unknown>(special.events[0]?.data, 'accessibility_services').filter((x): x is string => typeof x === 'string' && x.split('/')[0] === pkg);
  const changes = roleChanges(roles.events).filter((c) => involves(c, pkg));
  if ((special.loading && !special.events[0]) || (roles.loading && roles.events.length === 0)) return <Loading />;
  return (
    <>
      <h3 className="section-title">Rôles actuellement tenus</h3>
      {held.length === 0 ? (
        <p className="muted">Aucun rôle par défaut (SMS, téléphone, navigateur, assistant, accueil).</p>
      ) : (
        <ul className="role-list">
          {held.map((r) => (
            <li key={r}>
              <strong>{roleLabel(r)}</strong>
              {roleWhy(r) && <p className="hint">{roleWhy(r)}</p>}
            </li>
          ))}
        </ul>
      )}
      {accessibility.length > 0 && (
        <p>
          <Badge tone="warn">Service d'accessibilité actif</Badge> <span className="mono break">{accessibility.map((a) => cleanText(a, 200)).join(', ')}</span>
        </p>
      )}
      <h3 className="section-title">Changements de rôle (90 jours)</h3>
      {changes.length === 0 ? (
        <p className="muted">Cette application n'a ni gagné ni perdu de rôle par défaut.</p>
      ) : (
        <ul className="role-list">
          {changes.map((c) => (
            <li key={c.id}>
              <div className="role-change">
                <strong>{roleLabel(c.role)}</strong>
                <span className="muted">{fmtDateTime(c.ts)}</span>
                {c.new === pkg ? <Badge tone="warn">obtenu</Badge> : <Badge>perdu</Badge>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function SheetDetections({ pkg, from, to, now }: { pkg: string; from: string; to: string; now: Date }) {
  const { deviceId } = useDevice();
  const params = useMemo(() => (deviceId ? { device_id: deviceId, package: pkg, from, to } : null), [deviceId, pkg, from, to]);
  const paged = usePagedDetections(params, 50);
  const addLive = paged.addLive;
  const reloadList = paged.reload;
  const mutes = useMutes();
  const reloadMutes = mutes.reload;
  const muting = useMuting(deviceId, useCallback(() => {
    reloadList();
    reloadMutes();
  }, [reloadList, reloadMutes]));
  const onEvent = useCallback(
    (ev: VigieEvent) => {
      if (isMuteEvent(ev.type)) {
        reloadList();
        reloadMutes();
        return;
      }
      const d = detectionFromEvent(ev);
      if (d && matchesDetection(d, { pkg })) addLive(d);
    },
    [addLive, pkg, reloadList, reloadMutes],
  );
  const shown = useMemo(() => applyMutes(paged.detections, mutes.data ?? []), [paged.detections, mutes.data]);
  const canMute = !isUnsupported(mutes.error);
  useEventStream(true, deviceId, onEvent);
  if (paged.error && paged.detections.length === 0) {
    return isUnsupported(paged.error) ? <Empty>Ce collecteur ne fournit pas encore les détections (contrat v1.2).</Empty> : <ErrorBox message={paged.error.message} onRetry={paged.reload} />;
  }
  if (paged.loading && paged.detections.length === 0) return <Loading label="Chargement des détections…" />;
  if (paged.detections.length === 0) return <Empty>Aucune détection pour cette application sur 30 jours.</Empty>;
  return (
    <div className="det-compact">
      <ul className="det-list" aria-label="Détections de l'application">
        {shown.map((d, i) => (
          <DetectionCard
            key={d.id}
            d={d}
            now={now}
            showAppLink={false}
            open={i === 0 && !d.muted}
            onMute={canMute ? muting.askMute : undefined}
            onUnmute={canMute ? (x) => void muting.unmute({ type: x.type, package: x.package ?? '' }) : undefined}
          />
        ))}
      </ul>
      {paged.hasMore && (
        <div className="pager">
          <button type="button" className="btn" onClick={paged.loadMore} disabled={paged.loadingMore}>
            {paged.loadingMore ? 'Chargement…' : 'Charger plus'}
          </button>
        </div>
      )}
      {muting.notice && <p className="hint">{muting.notice}</p>}
      {muting.dialog}
    </div>
  );
}

function SheetOps({ pkg, from, to }: { pkg: string; from: string; to: string }) {
  const { device } = useDevice();
  const ops = useAppOps(from, to);
  if (ops.error && !isUnsupported(ops.error)) return <ErrorBox message={ops.error.message} onRetry={ops.reload} />;
  if (!ops.data && !isUnsupported(ops.error)) return <Loading />;
  const rows = ops.data?.rows ?? [];
  if (rows.length === 0) {
    return (
      <>
        <p className="muted">Aucune donnée d'usage des opérations sensibles pour cette application.</p>
        <p className="hint">
          Mesure expérimentale, éteinte par défaut{opsCollectorState(device) ? '' : ' (collecteur non signalé par le téléphone)'}. <Link to="/applications?tab=ops">Comment l'activer</Link>.
        </p>
      </>
    );
  }
  const mine = groupByApp(rows).find((a) => a.package === pkg);
  if (!mine) return <p className="muted">Cette application n'a utilisé aucune opération sensible sur 30 jours.</p>;
  return (
    <table className="tbl mini-tbl" data-testid="sheet-ops">
      <thead>
        <tr>
          <th scope="col">Opération</th>
          <th scope="col" className="right">Usages</th>
          <th scope="col" className="right">En arrière-plan</th>
        </tr>
      </thead>
      <tbody>
        {mine.ops.map((o) => (
          <tr key={o.op}>
            <td>{opInfo(o.op).label}</td>
            <td className="right">{fmtNumber(o.count)}</td>
            <td className="right">{o.background > 0 ? <strong>{fmtNumber(o.background)}</strong> : <span className="muted">0</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SheetHistory({ pkg, from, to }: { pkg: string; from: string; to: string }) {
  const { deviceId } = useDevice();
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: HISTORY_TYPES, q: pkg, from, to } : null, 50);
  const mine = useMemo(() => ({ ...paged, events: paged.events.filter((e) => e.data['package'] === pkg) }), [paged, pkg]);
  const describe = (ev: VigieEvent) => describeEvent(ev);
  return (
    <div className="flush">
      <EventList paged={mine} describe={describe} empty="Aucune installation, mise à jour ni changement de permission sur 90 jours." />
    </div>
  );
}
