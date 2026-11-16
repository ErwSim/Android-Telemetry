import { useMemo, useState, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { usePagedEvents } from '../api/usePagedEvents.ts';
import type { Posture } from '../api/types.ts';
import { EventList } from '../components/EventList.tsx';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Async, Badge, Card, Empty, StatusPill, Tabs } from '../components/ui.tsx';
import { countKeys } from '../lib/agg.ts';
import { bool, isRecord, str } from '../lib/data.ts';
import { roleChanges, roleLabel, roleWhy } from '../lib/roles.ts';
import { appSheetPath, cleanText } from '../lib/text.ts';
import { fmtDateTime, fmtValue } from '../lib/format.ts';
import { evaluatePosture, overallStatus, POSTURE_LABELS } from '../lib/posture.ts';
import { periodRange, type PeriodKey } from '../lib/period.ts';
import { useAppLabels } from '../state/appLabels.ts';
import { useDevice } from '../state/device.tsx';

type Tab = 'posture' | 'roles' | 'log' | 'sensors' | 'keyguard' | 'certs' | 'radio' | 'policy';
const TABS: Tab[] = ['posture', 'roles', 'log', 'sensors', 'keyguard', 'certs', 'radio', 'policy'];

export default function Security() {
  const [sp] = useSearchParams();
  const [tab, setTab] = useState<Tab>(() => TABS.find((t) => t === sp.get('tab')) ?? 'posture');
  return (
    <>
      <div className="page-head">
        <h1>Sécurité</h1>
      </div>
      <Tabs
        label="Sections"
        value={tab}
        onChange={setTab}
        tabs={[
          { key: 'posture', label: 'Posture' },
          { key: 'roles', label: 'Rôles par défaut' },
          { key: 'log', label: 'Journal système' },
          { key: 'sensors', label: 'Caméra et micro' },
          { key: 'keyguard', label: 'Déverrouillages' },
          { key: 'certs', label: "Certificats d'AC" },
          { key: 'radio', label: 'Cellulaire et BLE' },
          { key: 'policy', label: 'Politique appliquée' },
        ]}
      />
      {tab === 'posture' && <PostureTab />}
      {tab === 'roles' && <RolesTab />}
      {tab === 'log' && (
        <EventSection title="Journal de sécurité système (security.log)" types="security.log" searchable hint="Journal natif Android (Device Owner) : authentification, installation d'APK, injection de clés, etc." />
      )}
      {tab === 'sensors' && <SensorsTab />}
      {tab === 'keyguard' && (
        <EventSection title="Déverrouillages" types="security.keyguard" q="unlock_failed" qLabel="échecs seulement" hint="Seules les tentatives de déverrouillage échouées sont listées." defaultPeriod="7d" />
      )}
      {tab === 'certs' && <CertsTab />}
      {tab === 'radio' && (
        <EventSection
          title="Réseau cellulaire et traceurs Bluetooth"
          types="net.cell_security,net.ble_tracker"
          hint="Rétrogradation 2G, chiffrement nul, divulgation d'identifiant, balises AirTag / SmartTag / Tile détectées dans la durée."
          defaultPeriod="7d"
        />
      )}
      {tab === 'policy' && (
        <EventSection title="Actions de politique appliquées (security.policy)" types="security.policy" hint="Chaque action effectuée localement par l'agent (DNS privé, paquets désactivés, permissions refusées…)." defaultPeriod="30d" />
      )}
    </>
  );
}

/**
 * Rôles par défaut (SMS, téléphone, navigateur, assistant, accueil, filtrage d'appels) : qui les tient et
 * l'historique des changements (`app.role`). Un logiciel malveillant cherche souvent à devenir l'application SMS
 * ou le filtre d'appels : un changement que vous n'avez pas fait mérite d'être regardé.
 */
function RolesTab() {
  const labelOf = useAppLabels();
  const { deviceId } = useDevice();
  const ctl = usePeriod('30d');
  const range = periodRange(ctl.period);
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: 'app.role', ...range } : null, 200);
  const special = usePagedEvents(deviceId ? { device_id: deviceId, type: 'app.special_access', ...range } : null, 1);
  const changes = useMemo(() => roleChanges(paged.events), [paged.events]);
  const defaults = special.events[0]?.data['default_apps'];
  const current = isRecord(defaults) ? Object.entries(defaults).filter(([, v]) => typeof v === 'string' && v !== '') : [];
  const pkgName = (p: string | undefined) => {
    if (!p) return <span className="muted">aucune</span>;
    const l = labelOf(p);
    return (
      <Link className="role-pkg" to={appSheetPath(p)}>
        {l ? `${cleanText(l, 80)} (${cleanText(p, 160)})` : cleanText(p, 160)}
      </Link>
    );
  };
  return (
    <>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
      </div>
      <div className="grid grid-start">
        <Card title="Rôles actuels" className="span-5">
          {special.loading && !special.events[0] ? (
            <Empty>Chargement…</Empty>
          ) : current.length === 0 ? (
            <Empty>Aucun relevé des applications par défaut sur cette période.</Empty>
          ) : (
            <ul className="role-list">
              {current.map(([role, p]) => (
                <li key={role}>
                  <strong>{roleLabel(role)}</strong> : {pkgName(p as string)}
                  {roleWhy(role) && <p className="hint">{roleWhy(role)}</p>}
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Historique des changements" className="span-7">
          {changes.length === 0 && !paged.loading ? (
            <Empty>Aucun changement de rôle par défaut sur cette période.</Empty>
          ) : (
            <div className="flush">
              <div className="table-wrap">
                <table className="tbl" data-testid="roles-table">
                  <thead>
                    <tr>
                      <th scope="col">Date</th>
                      <th scope="col">Rôle</th>
                      <th scope="col">Changement</th>
                    </tr>
                  </thead>
                  <tbody>
                    {changes.map((c) => (
                      <tr key={c.id} className={c.role === 'sms' || c.role === 'call_screening' ? 'sev-2' : ''}>
                        <td className="nowrap">{fmtDateTime(c.ts)}</td>
                        <td>{roleLabel(c.role)}</td>
                        <td className="break">
                          {pkgName(c.old)} <span className="role-arrow">→</span> <strong>{pkgName(c.new)}</strong>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          <p className="hint">
            Un changement que vous n'avez pas fait vous-même (surtout l'application SMS ou le filtrage d'appels) est à vérifier dans la fiche de la nouvelle application.
          </p>
        </Card>
      </div>
    </>
  );
}

function PostureTab() {
  const { deviceId } = useDevice();
  const state = useApi(deviceId ? `posture:${deviceId}` : null, (s) => api.posture(deviceId, s));
  return (
    <Async state={state} isEmpty={(d) => Object.keys(d.current ?? {}).length === 0} empty="Aucune posture de sécurité reçue pour cet appareil.">
      {(d) => <PostureView current={d.current} ts={d.ts} changes={d.changes ?? []} />}
    </Async>
  );
}

function PostureView({ current, ts, changes }: { current: Posture; ts: string | undefined; changes: { ts: string; field: string; old?: unknown; new?: unknown }[] }) {
  const findings = useMemo(() => evaluatePosture(current), [current]);
  const status = overallStatus(findings);
  const certs = current.user_ca_certs ?? [];
  return (
    <div className="grid">
      <Card title="Posture courante" className="span-7" actions={<>{ts && <span className="hint">au {fmtDateTime(ts)}</span>}<StatusPill status={status} /></>}>
        <ul className="findings">
          {findings.map((f) => (
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
        {certs.length > 0 && (
          <>
            <h3 className="section-title">Empreintes des AC utilisateur</h3>
            <ul className="findings">
              {certs.map((c) => (
                <li key={c}>
                  <span className="f-label mono break">{c}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </Card>
      <Card title="Historique des changements" className="span-5">
        {changes.length === 0 ? (
          <Empty>Aucun changement de posture enregistré.</Empty>
        ) : (
          <div className="flush">
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th scope="col">Date</th>
                    <th scope="col">Réglage</th>
                    <th scope="col">Changement</th>
                  </tr>
                </thead>
                <tbody>
                  {changes.map((c, i) => (
                    <tr key={`${c.ts}-${c.field}-${i}`}>
                      <td className="nowrap">{fmtDateTime(c.ts)}</td>
                      <td>{POSTURE_LABELS[c.field] ?? c.field}</td>
                      <td className="break">
                        {fmtChangeValue(c.old)} → <strong>{fmtChangeValue(c.new)}</strong>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

/** Valeur d'un changement de posture ; les listes d'empreintes sont abrégées. */
function fmtChangeValue(v: unknown): string {
  if (Array.isArray(v)) {
    if (v.length === 0) return 'aucun';
    return v.map((x) => (typeof x === 'string' && x.length > 20 ? `${x.slice(0, 12)}…` : fmtValue(x))).join(', ');
  }
  return fmtValue(v);
}

function SensorsTab() {
  const labelOf = useAppLabels();
  const { deviceId } = useDevice();
  const ctl = usePeriod('7d');
  const range = periodRange(ctl.period);
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: 'sensor.', ...range } : null, 200);
  const usage = useMemo(() => {
    const cam = paged.events.filter((e) => e.type === 'sensor.camera' && bool(e.data, 'in_use')).map((e) => str(e.data, 'package') ?? 'inconnu');
    const mic = paged.events.filter((e) => e.type === 'sensor.microphone' && bool(e.data, 'recording')).map((e) => str(e.data, 'package') ?? 'inconnu');
    return { cam: countKeys(cam, 6), mic: countKeys(mic, 6) };
  }, [paged.events]);
  return (
    <>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
      </div>
      <div className="grid">
        <Card title="Utilisations de la caméra" className="span-6">
          <Usage items={usage.cam} labelOf={labelOf} />
        </Card>
        <Card title="Utilisations du microphone" className="span-6">
          <Usage items={usage.mic} labelOf={labelOf} />
        </Card>
      </div>
      <Card title="Détail (sensor.*)">
        <div className="flush">
          <EventList paged={paged} empty="Aucune utilisation de la caméra ou du microphone sur cette période." />
        </div>
      </Card>
    </>
  );
}

function Usage({ items, labelOf }: { items: { key: string; count: number }[]; labelOf: (p: string | undefined) => string | undefined }) {
  if (items.length === 0) return <p className="muted">Aucun accès parmi les événements chargés.</p>;
  return (
    <ul className="findings">
      {items.map((i) => (
        <li key={i.key}>
          <Badge>{i.count}×</Badge>
          <span className="f-label">{labelOf(i.key) ?? i.key}</span>
          {labelOf(i.key) && <span className="f-val mono">{i.key}</span>}
        </li>
      ))}
    </ul>
  );
}

function CertsTab() {
  const { device } = useDevice();
  const certs = device?.last_posture?.user_ca_certs ?? [];
  return (
    <>
      <Card title="Certificats d'AC installés par l'utilisateur (posture courante)" className="certs-now">
        {device?.last_posture === undefined ? (
          <Empty>Posture inconnue.</Empty>
        ) : certs.length === 0 ? (
          <p>Aucun certificat d'AC utilisateur : bon état.</p>
        ) : (
          <ul className="findings">
            {certs.map((c) => (
              <li key={c}>
                <Badge tone="bad">AC utilisateur</Badge>
                <span className="f-label mono break">{c}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <div className="spacer" />
      <EventSection title="Ajouts et retraits (security.ca_cert)" types="security.ca_cert" hint="Une AC ajoutée peut permettre d'intercepter le trafic chiffré." defaultPeriod="30d" />
    </>
  );
}

function EventSection({
  title,
  types,
  q,
  qLabel,
  hint,
  searchable = false,
  defaultPeriod = '7d',
}: {
  title: string;
  types: string;
  q?: string;
  qLabel?: string;
  hint?: ReactNode;
  searchable?: boolean;
  defaultPeriod?: PeriodKey;
}) {
  const { deviceId } = useDevice();
  const ctl = usePeriod(defaultPeriod);
  const [search, setSearch] = useState('');
  const range = periodRange(ctl.period);
  const text = (q ?? search).trim();
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: types, q: text || undefined, ...range } : null, 100);
  return (
    <>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
        {searchable && (
          <label className="filter grow">
            Recherche
            <input type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="tag, champ, valeur…" />
          </label>
        )}
        {qLabel && <Badge>{qLabel}</Badge>}
      </div>
      <Card title={title}>
        {hint && <p className="hint">{hint}</p>}
        <div className="flush">
          <EventList paged={paged} empty="Rien à signaler sur cette période." />
        </div>
      </Card>
    </>
  );
}
