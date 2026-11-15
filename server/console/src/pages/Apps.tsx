import { Fragment, useMemo, useState } from 'react';
import { api } from '../api/endpoints.ts';
import { useApi } from '../api/useApi.ts';
import { usePagedEvents } from '../api/usePagedEvents.ts';
import type { AppInfo, VigieEvent } from '../api/types.ts';
import { AppName } from '../components/AppName.tsx';
import { EventList } from '../components/EventList.tsx';
import { PeriodPicker, usePeriod } from '../components/PeriodPicker.tsx';
import { Async, Badge, Card, Empty, KV, Stat, Tabs } from '../components/ui.tsx';
import { countByInstaller, groupPermissions } from '../lib/agg.ts';
import { isRecord, list, str } from '../lib/data.ts';
import { describeEvent, installerLabel, isSideloaded, permissionLabel, shortPermission } from '../lib/events.ts';
import { fmtDate, fmtDateTime, fmtNumber, parseTs } from '../lib/format.ts';
import { periodRange } from '../lib/period.ts';
import { useNow } from '../lib/useNow.ts';
import { useDevice } from '../state/device.tsx';

type Tab = 'inventory' | 'permissions' | 'special' | 'history';

export default function Apps() {
  const { deviceId } = useDevice();
  const [tab, setTab] = useState<Tab>('inventory');
  const apps = useApi(deviceId ? `apps:${deviceId}` : null, (s) => api.apps(deviceId, s));
  const labelMap = useMemo(() => {
    const m = new Map<string, string>();
    for (const a of apps.data?.apps ?? []) if (a.label) m.set(a.package, a.label);
    return m;
  }, [apps.data]);

  return (
    <>
      <div className="page-head">
        <h1>Applications</h1>
        {apps.data?.ts && <span className="muted">Inventaire du {fmtDateTime(apps.data.ts)}</span>}
      </div>
      <Tabs
        label="Sections"
        value={tab}
        onChange={setTab}
        tabs={[
          { key: 'inventory', label: 'Inventaire' },
          { key: 'permissions', label: 'Permissions dangereuses' },
          { key: 'special', label: 'Accès spéciaux' },
          { key: 'history', label: 'Historique' },
        ]}
      />
      {tab === 'inventory' && (
        <Async state={apps} isEmpty={(d) => d.apps.length === 0} empty="Aucun inventaire d'applications reçu pour cet appareil.">
          {(d) => <Inventory apps={d.apps} />}
        </Async>
      )}
      {tab === 'permissions' && (
        <Async state={apps} isEmpty={(d) => d.apps.length === 0} empty="Aucun inventaire d'applications reçu.">
          {(d) => <Permissions apps={d.apps} />}
        </Async>
      )}
      {tab === 'special' && <SpecialAccess labelOf={(p) => labelMap.get(p)} />}
      {tab === 'history' && <History labelOf={(p) => labelMap.get(p)} />}
    </>
  );
}

type Cat = 'all' | 'user' | 'system' | 'disabled' | 'suspended' | 'hidden' | 'sideload';
const CATS: { key: Cat; label: string }[] = [
  { key: 'all', label: 'Toutes' },
  { key: 'user', label: 'Utilisateur' },
  { key: 'system', label: 'Système' },
  { key: 'disabled', label: 'Désactivées' },
  { key: 'suspended', label: 'Suspendues' },
  { key: 'hidden', label: 'Masquées' },
  { key: 'sideload', label: 'Hors store' },
];

function inCat(a: AppInfo, c: Cat): boolean {
  switch (c) {
    case 'all':
      return true;
    case 'user':
      return !a.system;
    case 'system':
      return a.system === true;
    case 'disabled':
      return a.enabled === false;
    case 'suspended':
      return a.suspended === true;
    case 'hidden':
      return a.hidden === true;
    case 'sideload':
      return isSideloaded(a);
  }
}

type Sort = 'label' | 'update' | 'perms';

function Inventory({ apps }: { apps: AppInfo[] }) {
  const [q, setQ] = useState('');
  const [cat, setCat] = useState<Cat>('all');
  const [installer, setInstaller] = useState('');
  const [sort, setSort] = useState<Sort>('label');
  const [shown, setShown] = useState(100);
  const [open, setOpen] = useState<string | null>(null);

  const counts = useMemo(() => Object.fromEntries(CATS.map((c) => [c.key, apps.filter((a) => inCat(a, c.key)).length])) as Record<Cat, number>, [apps]);
  const installers = useMemo(() => countByInstaller(apps), [apps]);

  const rows = useMemo(() => {
    const f = q.trim().toLowerCase();
    const out = apps.filter(
      (a) =>
        inCat(a, cat) &&
        (!installer || (a.installer || '(aucun)') === installer) &&
        (!f || a.package.toLowerCase().includes(f) || (a.label ?? '').toLowerCase().includes(f)),
    );
    const name = (a: AppInfo) => (a.label ?? a.package).toLowerCase();
    out.sort((a, b) =>
      sort === 'update'
        ? (parseTs(b.last_update)?.getTime() ?? 0) - (parseTs(a.last_update)?.getTime() ?? 0)
        : sort === 'perms'
          ? (b.granted_dangerous?.length ?? 0) - (a.granted_dangerous?.length ?? 0) || name(a).localeCompare(name(b), 'fr')
          : name(a).localeCompare(name(b), 'fr'),
    );
    return out;
  }, [apps, q, cat, installer, sort]);

  return (
    <>
      <div className="stats app-summary">
        <Stat label="Applications" value={fmtNumber(apps.length)} />
        <Stat label="Utilisateur" value={fmtNumber(counts.user)} />
        <Stat label="Système" value={fmtNumber(counts.system)} />
        <Stat label="Désactivées" value={fmtNumber(counts.disabled)} />
        <Stat label="Suspendues" value={fmtNumber(counts.suspended)} tone={counts.suspended ? 'warn' : undefined} />
        <Stat label="Hors store" value={fmtNumber(counts.sideload)} sub="installées hors Play / Galaxy Store" tone={counts.sideload ? 'warn' : undefined} />
      </div>
      <Card className="inv-card">
        <div className="toolbar">
          <label className="filter grow">
            Recherche
            <input type="search" value={q} onChange={(e) => { setQ(e.target.value); setShown(100); }} placeholder="nom ou paquet" />
          </label>
          <label className="filter">
            Catégorie
            <select value={cat} onChange={(e) => { setCat(e.target.value as Cat); setShown(100); }}>
              {CATS.map((c) => (
                <option key={c.key} value={c.key}>
                  {c.label} ({counts[c.key]})
                </option>
              ))}
            </select>
          </label>
          <label className="filter">
            Installateur
            <select value={installer} onChange={(e) => { setInstaller(e.target.value); setShown(100); }}>
              <option value="">Tous</option>
              {installers.map((i) => (
                <option key={i.key} value={i.key}>
                  {i.key === '(aucun)' ? installerLabel(undefined) : installerLabel(i.key)} ({i.count})
                </option>
              ))}
            </select>
          </label>
          <label className="filter">
            Tri
            <select value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
              <option value="label">Nom</option>
              <option value="update">Dernière mise à jour</option>
              <option value="perms">Permissions dangereuses</option>
            </select>
          </label>
        </div>
        {rows.length === 0 ? (
          <Empty>Aucune application ne correspond.</Empty>
        ) : (
          <div className="flush">
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th scope="col">Application</th>
                    <th scope="col" className="hide-sm">Version</th>
                    <th scope="col">Installateur</th>
                    <th scope="col">État</th>
                    <th scope="col" className="right">Perm. dang.</th>
                    <th scope="col" className="hide-sm">Mise à jour</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.slice(0, shown).map((a) => {
                    const isOpen = open === a.package;
                    const perms = a.granted_dangerous ?? [];
                    return (
                      <Fragment key={a.package}>
                        <tr>
                          <td>
                            <button type="button" className="expander" aria-expanded={isOpen} aria-label={`Détails de ${a.label ?? a.package}`} onClick={() => setOpen(isOpen ? null : a.package)}>
                              {isOpen ? '▾' : '▸'}
                            </button>
                            <AppName pkg={a.package} label={a.label} />
                          </td>
                          <td className="hide-sm">{a.version_name ?? '—'}</td>
                          <td>{installerLabel(a.installer)}</td>
                          <td>
                            <span className="chip-list">
                              {a.system ? <Badge>système</Badge> : <Badge tone="info">utilisateur</Badge>}
                              {a.enabled === false && <Badge tone="warn">désactivée</Badge>}
                              {a.suspended && <Badge tone="warn">suspendue</Badge>}
                              {a.hidden && <Badge>masquée</Badge>}
                              {isSideloaded(a) && <Badge tone="warn">hors store</Badge>}
                            </span>
                          </td>
                          <td className="right">{perms.length ? perms.length : <span className="muted">0</span>}</td>
                          <td className="hide-sm nowrap">{fmtDate(a.last_update)}</td>
                        </tr>
                        {isOpen && (
                          <tr>
                            <td colSpan={6} className="detail-cell">
                              <AppDetail app={a} />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="pager">
              {rows.length > shown ? (
                <button type="button" className="btn" onClick={() => setShown(shown + 100)}>
                  Afficher plus
                </button>
              ) : null}
              <span>
                {Math.min(shown, rows.length)} sur {rows.length}
              </span>
            </div>
          </div>
        )}
      </Card>
    </>
  );
}

function AppDetail({ app }: { app: AppInfo }) {
  const perms = app.granted_dangerous ?? [];
  return (
    <div className="two-col">
      <KV
        items={[
          { k: 'Paquet', v: <code>{app.package}</code> },
          { k: 'Version', v: `${app.version_name ?? '—'}${app.version_code !== undefined ? ` (code ${app.version_code})` : ''}` },
          { k: 'SDK cible', v: app.target_sdk ?? '—' },
          { k: 'Installateur', v: `${installerLabel(app.installer)}${app.installer ? ` (${app.installer})` : ''}` },
          { k: 'Première installation', v: fmtDateTime(app.first_install) },
          { k: 'Dernière mise à jour', v: fmtDateTime(app.last_update) },
          { k: 'Signature SHA-256', v: app.signer_sha256 ? <code className="break">{app.signer_sha256}</code> : '—' },
        ]}
      />
      <div>
        <h3>Permissions dangereuses accordées ({perms.length})</h3>
        {perms.length === 0 ? (
          <p className="muted">Aucune.</p>
        ) : (
          <ul className="chip-list">
            {perms.map((p) => (
              <li key={p} className="chip" title={p}>
                {permissionLabel(p)}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

const SENSITIVE = new Set(['ACCESS_BACKGROUND_LOCATION', 'RECORD_AUDIO', 'CAMERA', 'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_CALL_LOG', 'READ_CONTACTS', 'ACCESS_FINE_LOCATION']);

function Permissions({ apps }: { apps: AppInfo[] }) {
  const [userOnly, setUserOnly] = useState(true);
  const groups = useMemo(() => groupPermissions(userOnly ? apps.filter((a) => !a.system) : apps), [apps, userOnly]);
  return (
    <>
      <div className="toolbar">
        <label className="check">
          <input type="checkbox" checked={userOnly} onChange={(e) => setUserOnly(e.target.checked)} />
          Applications utilisateur seulement
        </label>
      </div>
      {groups.length === 0 ? (
        <Empty>Aucune permission dangereuse accordée.</Empty>
      ) : (
        <div className="grid">
          {groups.map((g) => (
            <Card
              key={g.permission}
              className="span-6"
              title={
                <>
                  {permissionLabel(g.permission)}{' '}
                  {SENSITIVE.has(shortPermission(g.permission)) && <Badge tone="warn">sensible</Badge>}
                </>
              }
              actions={<span className="muted">{g.apps.length} app{g.apps.length > 1 ? 's' : ''}</span>}
            >
              <p className="hint mono">{g.permission}</p>
              <ul className="chip-list">
                {g.apps.map((a) => (
                  <li key={a.package} className="chip" title={a.package}>
                    {a.label ?? a.package}
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}

const SPECIAL: { key: string; label: string; hint: string; risky: boolean }[] = [
  { key: 'accessibility_services', label: "Services d'accessibilité", hint: "Peuvent lire l'écran et agir à votre place.", risky: true },
  { key: 'notification_listeners', label: 'Écoute des notifications', hint: 'Lisent toutes les notifications reçues.', risky: true },
  { key: 'device_admins', label: "Administrateurs de l'appareil", hint: 'Peuvent imposer des règles ou verrouiller/effacer.', risky: true },
  { key: 'overlay_apps', label: "Superposition à l'écran", hint: "Peuvent s'afficher par-dessus d'autres apps.", risky: true },
  { key: 'unknown_sources_apps', label: 'Installation de sources inconnues', hint: 'Peuvent installer des APK.', risky: true },
  { key: 'usage_access_apps', label: "Accès aux données d'utilisation", hint: 'Voient quelles apps sont utilisées.', risky: false },
  { key: 'vpn_apps', label: 'Applications VPN', hint: 'Peuvent faire transiter le trafic.', risky: true },
];

function SpecialAccess({ labelOf }: { labelOf: (pkg: string) => string | undefined }) {
  const { deviceId } = useDevice();
  const now = useNow(300_000);
  const from = new Date(now.getTime() - 30 * 24 * 3600_000).toISOString();
  const to = now.toISOString();
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: 'app.special_access', from, to } : null, 1);
  const ev = paged.events[0];
  if (paged.loading && !ev) return <Empty>Chargement…</Empty>;
  if (paged.error) return <Empty>{paged.error.message}</Empty>;
  if (!ev) return <Empty>Aucun relevé d'accès spéciaux sur les 30 derniers jours.</Empty>;
  const defaults = isRecord(ev.data['default_apps']) ? (ev.data['default_apps'] as Record<string, unknown>) : undefined;
  return (
    <>
      <p className="muted">Relevé du {fmtDateTime(ev.ts)}.</p>
      <div className="grid">
        {SPECIAL.map((s) => {
          const items = list<unknown>(ev.data, s.key).map((x) => (typeof x === 'string' ? x : JSON.stringify(x)));
          return (
            <Card
              key={s.key}
              className="span-6"
              title={s.label}
              actions={<Badge tone={items.length === 0 ? 'ok' : s.risky ? 'warn' : 'neutral'}>{items.length}</Badge>}
            >
              <p className="hint">{s.hint}</p>
              {items.length === 0 ? (
                <p className="muted">Aucune application.</p>
              ) : (
                <ul className="findings">
                  {items.map((it) => {
                    const pkg = it.split('/')[0] ?? it;
                    return (
                      <li key={it}>
                        <span className="f-label">{labelOf(pkg) ?? pkg}</span>
                        <span className="f-val mono break">{it}</span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Card>
          );
        })}
        {defaults && (
          <Card className="span-6" title="Applications par défaut">
            <KV items={Object.entries(defaults).map(([k, v]) => ({ k, v: typeof v === 'string' ? labelOf(v) ? `${labelOf(v)} (${v})` : v : JSON.stringify(v) }))} />
          </Card>
        )}
      </div>
    </>
  );
}

const HISTORY_TYPES = 'app.installed,app.updated,app.removed,app.permission_changed';

function History({ labelOf }: { labelOf: (pkg: string) => string | undefined }) {
  const { deviceId } = useDevice();
  const ctl = usePeriod('30d');
  const [kind, setKind] = useState('');
  const range = periodRange(ctl.period);
  const paged = usePagedEvents(deviceId ? { device_id: deviceId, type: kind || HISTORY_TYPES, ...range } : null, 100);
  const describe = (ev: VigieEvent) => {
    const pkg = str(ev.data, 'package');
    const label = pkg ? labelOf(pkg) : undefined;
    const base = describeEvent(ev);
    return label && pkg ? base.replace(pkg, `${label} (${pkg})`) : base;
  };
  const kinds = [
    { v: '', l: 'Tout' },
    { v: 'app.installed', l: 'Installations' },
    { v: 'app.updated', l: 'Mises à jour' },
    { v: 'app.removed', l: 'Suppressions' },
    { v: 'app.permission_changed', l: 'Permissions' },
  ];
  return (
    <>
      <div className="toolbar">
        <PeriodPicker ctl={ctl} />
        <div className="seg" role="group" aria-label="Type de changement">
          {kinds.map((k) => (
            <button key={k.v} type="button" className={`seg-btn${kind === k.v ? ' is-active' : ''}`} aria-pressed={kind === k.v} onClick={() => setKind(k.v)}>
              {k.l}
            </button>
          ))}
        </div>
      </div>
      <Card>
        <div className="flush">
          <EventList paged={paged} describe={describe} empty="Aucune installation, mise à jour, suppression ou changement de permission sur cette période." />
        </div>
      </Card>
    </>
  );
}

