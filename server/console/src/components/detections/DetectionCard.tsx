import { Link } from 'react-router-dom';
import type { Detection } from '../../api/types.ts';
import { detectionDomains, detectionLabel, evidenceItems, fmtWindow, isMutable, observation, typeInfo } from '../../lib/detections.ts';
import { fmtDateTime, fmtRelative } from '../../lib/format.ts';
import { guardInfo } from '../../lib/guards.ts';
import { appSheetPath, cleanText } from '../../lib/text.ts';
import { AppName } from '../AppName.tsx';
import { Badge, SevBadge } from '../ui.tsx';

/**
 * Une détection, lisible par le propriétaire : ce qui a été observé (une phrase), l'application, la période,
 * les preuves, pourquoi c'est suspect, ce qui peut l'expliquer sans malveillance, et que faire. Tout le texte
 * venu du téléphone ou du réseau (noms d'applications, de paquets, de domaines) est affiché comme du texte.
 */
export function DetectionCard({
  d,
  open = false,
  isNew = false,
  now,
  showAppLink = true,
  onMute,
  onUnmute,
}: {
  d: Detection;
  open?: boolean;
  isNew?: boolean;
  now?: Date;
  /** faux sur la fiche de l'application elle-même */
  showAppLink?: boolean;
  /** mise en sourdine (§11.4) : proposée seulement pour un type masquable */
  onMute?: ((d: Detection) => void) | undefined;
  onUnmute?: ((d: Detection) => void) | undefined;
}) {
  const info = typeInfo(d.type);
  const sev = Math.max(0, Math.min(3, Math.trunc(d.severity)));
  const evidence = evidenceItems(d);
  const domains = info.domains ? detectionDomains(d) : [];
  const window = fmtWindow(d.window_from, d.window_to);
  const pkg = d.package;
  const label = cleanText(d.label, 80);
  const guard = info.guard ? guardInfo(info.guard) : undefined;
  const enc = pkg ? encodeURIComponent(pkg) : '';
  return (
    <li className={`det det-sev-${sev}${isNew ? ' is-new' : ''}${d.muted ? ' is-muted' : ''}`} data-testid="detection" data-type={d.type} data-muted={d.muted ? 'true' : undefined}>
      <div className="det-head">
        <SevBadge sev={sev} />
        <Badge tone="info">{detectionLabel(d.type)}</Badge>
        {info.review && <Badge tone="warn" title="Une revue : cette application détient un droit sensible, a-t-elle une raison de l'avoir ?">À vérifier</Badge>}
        {d.recurring && <Badge title="Déjà signalé dans les 30 jours : la gravité est plafonnée à 1 (Notable)">Déjà signalé, récurrent</Badge>}
        {d.muted && <Badge tone="neutral" title="Calculée et enregistrée, mais ni alertée ni notifiée">En sourdine</Badge>}
        <time className="det-time" dateTime={d.ts} title={fmtDateTime(d.ts)}>
          {fmtRelative(d.ts, now)}
        </time>
      </div>
      <h3 className="det-what">{observation(d)}</h3>
      {info.review && (
        <p className="hint det-review" data-testid="det-review">
          Ceci est une <strong>revue</strong>, pas la preuve d'un abus : cette application peut envoyer des SMS sans passer par votre messagerie. Est-ce voulu ?
        </p>
      )}
      <div className="det-meta">
        {pkg ? (
          <span>
            Application : <AppName pkg={cleanText(pkg, 255)} label={label || undefined} />
          </span>
        ) : (
          <span>Application : inconnue</span>
        )}
        <span>
          Période : <strong>{window ?? `détectée le ${fmtDateTime(d.ts)}`}</strong>
        </span>
        {d.updated_at && d.updated_at !== d.ts && <span>Mise à jour : {fmtRelative(d.updated_at, now)}</span>}
      </div>
      {evidence.length > 0 && (
        <ul className="chip-list det-chips" aria-label="Éléments de preuve (aperçu)">
          {evidence.slice(0, 4).map((e) => (
            <li key={e.label} className="chip" title={`${e.label} : ${e.value}`}>
              <span className="muted">{e.label} :</span> <span className="break">{e.value.length > 60 ? `${e.value.slice(0, 57)}…` : e.value}</span>
            </li>
          ))}
        </ul>
      )}
      <details className="det-more" open={open}>
        <summary>Preuves, explications et que faire</summary>
        <div className="det-body">
          {evidence.length > 0 && (
            <section>
              <h4>Éléments de preuve</h4>
              <dl className="kv">
                {evidence.map((e) => (
                  <div key={e.label} className="kv-row">
                    <dt>{e.label}</dt>
                    <dd>{e.value}</dd>
                  </div>
                ))}
              </dl>
            </section>
          )}
          {domains.length > 0 && (
            <section>
              <h4>Domaines concernés (ouvrir dans Pistage pour les bloquer)</h4>
              <div className="det-domains">
                {domains.map((dom) => (
                  <Link key={dom} className="chip-link" to={`/pistage?q=${encodeURIComponent(dom)}&period=30d`}>
                    {dom}
                  </Link>
                ))}
              </div>
            </section>
          )}
          {d.summary && d.summary !== observation(d) && (
            <section>
              <h4>Description du collecteur</h4>
              <p className="break">{cleanText(d.summary, 400)}</p>
            </section>
          )}
          <section>
            <h4>Pourquoi c'est suspect</h4>
            <p>{info.why}</p>
            {d.type === 'detect.default_app_changed' && d.evidence['role'] === 'sms' && (
              <p className="callout callout-bad" data-testid="det-sms-role">
                <strong>Rôle SMS : la voie classique des chevaux de Troie SMS.</strong> Une application qui se fait désigner application SMS par défaut obtient l'envoi, la lecture et l'interception des SMS
                (codes de votre banque compris) et échappe aux refus de permission. À moins que vous ne l'ayez choisie vous-même, remettez l'ancienne application et désinstallez la nouvelle.
              </p>
            )}
          </section>
          {info.innocent.length > 0 && (
            <section>
              <h4>Ce que cela peut être d'innocent</h4>
              <ul>
                {info.innocent.map((t) => (
                  <li key={t}>{t}</li>
                ))}
              </ul>
            </section>
          )}
          <section>
            <h4>Que faire</h4>
            <ul>
              {info.actions.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
            <div className="det-actions">
              {pkg && showAppLink && (
                <Link className="btn btn-sm btn-primary" to={appSheetPath(pkg)}>
                  Fiche de l'application
                </Link>
              )}
              {pkg && (
                <Link className="btn btn-sm" to={`/pistage?app=${enc}&period=7d`}>
                  Ses domaines dans Pistage
                </Link>
              )}
              {pkg && (
                <Link className="btn btn-sm" to={`/reseau?app=${enc}`}>
                  Son trafic dans Réseau
                </Link>
              )}
              {d.muted && onUnmute && (
                <button type="button" className="btn btn-sm" onClick={() => onUnmute(d)}>
                  Réactiver le signalement
                </button>
              )}
              {!d.muted && onMute && isMutable(d) && (
                <button type="button" className="btn btn-sm" onClick={() => onMute(d)} data-testid="mute-btn">
                  Ne plus signaler pour cette application
                </button>
              )}
              {(d.type === 'detect.sensor_background' || d.type === 'detect.sms_abuse') && (
                <Link className="btn btn-sm" to="/securite?tab=sensors">
                  Caméra et micro (Sécurité)
                </Link>
              )}
            </div>
          </section>
          {guard && (
            <section className="det-guard">
              <h4>Garde de l'application Vigie qui répond à ce risque</h4>
              <p>
                <strong>Garde « {guard.label} »</strong> : {guard.effect} Elle se règle sur le téléphone (écran Politique) : la console ne peut pas l'activer, le
                serveur ne commande jamais le téléphone.
              </p>
            </section>
          )}
        </div>
      </details>
    </li>
  );
}
