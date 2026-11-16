import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { AppOpsRow, Device } from '../../api/types.ts';
import { HEADLINE_OPS, backgroundShare, groupByApp, groupByOp, opInfo } from '../../lib/ops.ts';
import { fmtDateTime, fmtNumber } from '../../lib/format.ts';
import { appSheetPath, cleanText } from '../../lib/text.ts';
import { AppName } from '../AppName.tsx';
import { Badge, Card, Empty } from '../ui.tsx';

/** État du collecteur d'opérations sensibles dans la dernière pulsation (nom exact non fixé par le contrat : on cherche « ops »). */
export function opsCollectorState(device: Device | undefined): string | undefined {
  const c = device?.last_heartbeat?.collectors;
  if (!c) return undefined;
  const key = Object.keys(c).find((k) => /ops/i.test(k));
  return key ? c[key] : undefined;
}

const STATE_TEXT: Record<string, string> = {
  running: 'en marche',
  disabled: 'désactivé dans l’application',
  unavailable: 'indisponible (permission DUMP non accordée ?)',
};

/**
 * État vide de l'usage des opérations sensibles. Ces données sont expérimentales et éteintes par défaut : la page
 * dit comment les activer, sans jamais présenter une absence de données comme une absence d'usage.
 */
export function OpsEmpty({ device, reason }: { device: Device | undefined; reason: 'absent' | 'empty' }) {
  const st = opsCollectorState(device);
  return (
    <div className="state-ops" data-testid="ops-empty">
      <div className="callout callout-info">
        <p>
          <strong>{reason === 'absent' ? "Aucune donnée d'usage des opérations sensibles pour cet appareil." : 'Aucune opération sensible utilisée sur cette période.'}</strong>{' '}
          {reason === 'empty' && 'Si le collecteur est actif, c’est plutôt bon signe : le relevé est horaire et ne mentionne que les opérations réellement utilisées.'}
        </p>
        {st && <p>État du collecteur sur le téléphone : <strong>{STATE_TEXT[st] ?? st}</strong>.</p>}
      </div>
      <p>
        Cette mesure est <strong>expérimentale</strong> et <strong>éteinte par défaut</strong> : elle lit les compteurs d'opérations d'Android (qui a envoyé un SMS, passé un appel, lu les
        contacts, utilisé le micro ou la caméra, et combien de fois dont en arrière-plan) grâce à la permission <code>DUMP</code>, qu'Android n'accorde qu'en ligne de commande. Pour l'activer :
      </p>
      <ol className="ops-steps">
        <li>
          Brancher le téléphone à l'ordinateur (débogage USB) et lancer <code>./scripts/grant-adb-permissions.sh</code> (ou la version <code>.ps1</code> sous Windows) : il accorde{' '}
          <code>DUMP</code> à Vigie (équivalent : <code>adb shell pm grant io.github.erwsim.watchpost android.permission.DUMP</code>).
        </li>
        <li>
          Dans l'application Vigie, onglet <em>Collecteurs</em> : activer le collecteur expérimental « Usage des opérations sensibles ».
        </li>
        <li>Attendre l'heure suivante : le premier relevé arrive dans l'heure, puis chaque heure.</li>
      </ol>
      <p className="hint">
        Tant que ces données manquent, les détections « SMS anormaux » et « micro ou caméra en arrière-plan » ne peuvent pas se déclencher ; les autres détections (réseau, nouvelles applications) et le
        profil de risque fonctionnent sans elles. L'absence de ces données n'est <strong>pas</strong> une preuve qu'aucune application n'envoie de SMS : voyez aussi le profil de risque et les
        permissions de chaque application.
      </p>
    </div>
  );
}

/** Qui envoie des SMS, passe des appels, lit les contacts, utilise le micro ou la caméra, et combien de fois dont en arrière-plan. */
export function OpsView({ rows, from, to, device }: { rows: AppOpsRow[]; from?: string | undefined; to?: string | undefined; device: Device | undefined }) {
  const [opFilter, setOpFilter] = useState('');
  const byOp = useMemo(() => groupByOp(rows), [rows]);
  const byApp = useMemo(() => groupByApp(rows), [rows]);
  const flat = useMemo(() => {
    const out: { package: string; label?: string; op: string; count: number; background: number; rejected: number; lastTs?: string }[] = [];
    for (const a of byApp) for (const o of a.ops) if (!opFilter || o.op === opFilter) out.push({ package: a.package, ...(a.label ? { label: a.label } : {}), ...o });
    return out.sort((x, y) => y.count - x.count || x.package.localeCompare(y.package));
  }, [byApp, opFilter]);
  const hasRejected = flat.some((r) => r.rejected > 0);
  const present = new Map(byOp.map((o) => [o.op, o]));
  const headline = HEADLINE_OPS.map((op) => present.get(op) ?? { op, count: 0, background: 0, apps: [] });

  if (rows.length === 0) return <OpsEmpty device={device} reason="empty" />;
  return (
    <>
      {byApp.some((a) => a.rejected > 0) && (
        <div className="callout callout-info" role="note">
          <p>
            <strong>« Refusés »</strong> : usages que le système a empêchés (par exemple par la garde SMS de l'application Vigie). L'application a essayé : la tentative reste un signal, même sans effet.
          </p>
        </div>
      )}
      <p className="hint">
        Données <strong>expérimentales</strong>{from && to ? ` du ${fmtDateTime(from)} au ${fmtDateTime(to)}` : ''} : compteurs d'opérations d'Android relevés toutes les heures. Un usage « en arrière-plan »
        est fait alors que l'application n'est pas à l'écran.
      </p>
      <div className="ops-cards" data-testid="ops-cards">
        {headline.map((o) => {
          const info = opInfo(o.op);
          const bg = o.background > 0;
          return (
            <div key={o.op} className={`op-card${bg ? ' is-bg' : ''}`}>
              <h3>{info.label}</h3>
              <div className="op-n">{fmtNumber(o.count)}</div>
              <div className="op-bg">{o.count === 0 ? 'aucun usage' : bg ? `dont ${fmtNumber(o.background)} en arrière-plan` : 'aucun en arrière-plan'}</div>
              {o.apps.length > 0 && (
                <ol>
                  {o.apps.slice(0, 3).map((a) => (
                    <li key={a.package} className="break">
                      {cleanText(a.label, 60) || cleanText(a.package, 120)} : {fmtNumber(a.count)}
                    </li>
                  ))}
                </ol>
              )}
            </div>
          );
        })}
      </div>
      <Card title="Détail par application et par opération">
        <div className="toolbar">
          <ul className="chip-list" aria-label="Filtrer par opération">
            <li>
              <button type="button" className="chip-btn" aria-pressed={opFilter === ''} onClick={() => setOpFilter('')}>
                Toutes
              </button>
            </li>
            {byOp.map((o) => (
              <li key={o.op}>
                <button type="button" className="chip-btn" aria-pressed={opFilter === o.op} onClick={() => setOpFilter(opFilter === o.op ? '' : o.op)}>
                  {opInfo(o.op).label}
                </button>
              </li>
            ))}
          </ul>
        </div>
        {flat.length === 0 ? (
          <Empty>Aucun usage pour cette opération.</Empty>
        ) : (
          <div className="flush">
            <div className="table-wrap">
              <table className="tbl" data-testid="ops-table">
                <thead>
                  <tr>
                    <th scope="col">Application</th>
                    <th scope="col">Opération</th>
                    <th scope="col" className="right">Usages</th>
                    <th scope="col" className="right">En arrière-plan</th>
                    {hasRejected && <th scope="col" className="right">Refusés</th>}
                    <th scope="col" className="hide-sm">Dernier usage</th>
                  </tr>
                </thead>
                <tbody>
                  {flat.map((r) => {
                    const share = backgroundShare(r.count, r.background);
                    return (
                      <tr key={`${r.package}|${r.op}`} className={share >= 0.5 && r.background > 0 ? 'sev-2' : ''}>
                        <td>
                          <Link className="app-link" to={appSheetPath(r.package)}>
                            <AppName pkg={cleanText(r.package, 255)} label={cleanText(r.label, 80) || undefined} />
                          </Link>
                        </td>
                        <td>{opInfo(r.op).label}</td>
                        <td className="right">{fmtNumber(r.count)}</td>
                        <td className="right">
                          {r.background > 0 ? (
                            <>
                              {fmtNumber(r.background)} {share >= 0.5 && <Badge tone="warn">surtout en arrière-plan</Badge>}
                            </>
                          ) : (
                            <span className="muted">0</span>
                          )}
                        </td>
                        {hasRejected && <td className="right">{r.rejected > 0 ? <strong>{fmtNumber(r.rejected)}</strong> : <span className="muted">0</span>}</td>}
                        <td className="hide-sm nowrap">{r.lastTs ? fmtDateTime(r.lastTs) : '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Card>
    </>
  );
}
