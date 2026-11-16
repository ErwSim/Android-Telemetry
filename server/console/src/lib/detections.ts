// Détections (contrat §11.3) : traduction des types, phrase « ce qui a été observé », éléments de preuve,
// explications et conduite à tenir, agrégations. Fonctions pures.
//
// Le contrat ne fixe pas les clés de `evidence` : chaque lecture essaie quelques noms plausibles et la phrase
// retombe sur le `summary` du collecteur quand la preuve ne suffit pas. Tout ce qui vient du téléphone ou du
// réseau (noms d'applications, de paquets, de domaines) est du texte : jamais interprété.
import type { DataObject, Detection, DetectionMute, VigieEvent } from '../api/types.ts';
import { isRecord } from './data.ts';
import { fmtBytes, fmtDate, fmtNumber, fmtTime, parseTs } from './format.ts';
import { cleanText } from './text.ts';
import { opInfo } from './ops.ts';
import { reasonInfo } from './risk.ts';
import { roleLabel } from './roles.ts';

export const DETECTION_TYPES = [
  'detect.threat_domain',
  'detect.upload_spike',
  'detect.fanout',
  'detect.mail_ports',
  'detect.dns_bypass',
  'detect.sms_abuse',
  'detect.sensor_background',
  'detect.new_app_risky',
  // §11.4 : détections qui ne dépendent pas de `app.ops`
  'detect.sms_permission',
  'detect.default_app_changed',
  'detect.flood',
] as const;

export type DetectionType = (typeof DETECTION_TYPES)[number];

export function isDetectionType(t: string): boolean {
  return t.startsWith('detect.');
}

export interface TypeInfo {
  label: string;
  /** pourquoi c'est suspect */
  why: string;
  /** explications innocentes possibles */
  innocent: string[];
  /** que faire (sans les liens, ajoutés par l'écran) */
  actions: string[];
  /** garde de l'agent qui répond à ce risque (contrat §11.1) */
  guard?: string;
  /** la détection porte des domaines : proposer le blocage dans Pistage */
  domains?: boolean;
  /** c'est une revue (« est-ce voulu ? ») et non l'observation d'un comportement */
  review?: boolean;
  /** peut être mise en sourdine (§11.4) ; faux pour `sms_abuse`, `default_app_changed` et `flood` (sans application) */
  mutable?: boolean;
}

const TYPES: Record<DetectionType, TypeInfo> = {
  'detect.threat_domain': {
    label: 'Domaine de la liste de menaces',
    why: "AdGuard Home bloque des listes de menaces connues (hameçonnage, logiciels malveillants, serveurs de contrôle). Qu'une application essaie de joindre ces domaines est un signe classique d'infection : elle cherche son serveur de commande ou un site de fraude. Le blocage a fonctionné, la requête n'a pas abouti, mais l'application a essayé.",
    innocent: [
      "Un domaine légitime ajouté à tort à une liste, ou récemment racheté.",
      "Une bibliothèque publicitaire douteuse embarquée dans une application par ailleurs honnête.",
      "Un lien suspect que vous avez vous-même ouvert dans un navigateur ou une messagerie.",
    ],
    actions: [
      "Regarder le profil de risque de l'application dans sa fiche.",
      "Dans Pistage, vérifier que le domaine est bien bloqué, et le bloquer à la main s'il ne l'est pas.",
      "Désinstaller l'application si vous ne l'avez pas choisie ou si vous ne vous en servez pas.",
    ],
    domains: true,
  },
  'detect.upload_spike': {
    label: "Envoi de données inhabituel",
    why: "Un volume envoyé très supérieur à l'habitude peut être une fuite (photos, contacts, messages) ou l'application utilisée comme relais. Vigie compare avec la médiane horaire de l'application sur 14 jours.",
    innocent: [
      "Vous avez envoyé une vidéo, des photos ou lancé une sauvegarde dans le nuage.",
      "Première utilisation après installation ou mise à jour : synchronisation initiale.",
    ],
    actions: [
      "Vous souvenir de ce que vous faisiez à ce moment (sauvegarde, partage de vidéo).",
      "Regarder dans Réseau les destinations contactées par l'application.",
      "Si rien ne l'explique, retirer l'accès aux données de l'application ou la désinstaller.",
    ],
  },
  'detect.fanout': {
    label: "Connexions vers de très nombreuses adresses",
    why: "Parler à des centaines d'adresses différentes en une heure est inhabituel pour une application ordinaire : balayage de réseau, participation à un réseau de machines compromises, pair-à-pair non voulu, ou relais pour un envoi de masse.",
    innocent: [
      "Un navigateur, un lecteur vidéo ou un jeu qui récupère du contenu sur beaucoup de serveurs.",
      "Un client pair-à-pair (BitTorrent) que vous utilisez volontairement.",
    ],
    actions: [
      "Ouvrir la fiche de l'application : profil de risque et domaines contactés.",
      "Si vous ne la reconnaissez pas, la désinstaller.",
    ],
  },
  'detect.mail_ports': {
    label: "Connexion à un serveur de courrier",
    why: "Les ports 25, 465 et 587 servent à envoyer du courrier. Une application qui n'est pas un client de messagerie connu et qui s'y connecte peut envoyer du courrier indésirable ou du hameçonnage depuis votre connexion.",
    innocent: [
      "Une application de messagerie, de factures ou de sauvegarde peu connue que vous avez configurée vous-même.",
      "Un outil d'administration ou de développement.",
    ],
    actions: [
      "Vérifier que vous avez configuré un compte de courrier dans cette application.",
      "Sinon, la désinstaller et regarder ses domaines dans Pistage.",
    ],
  },
  'detect.dns_bypass': {
    label: 'Contournement du DNS du téléphone',
    why: "En contactant directement un résolveur DNS public (DNS-over-HTTPS ou DNS-over-TLS) ou des adresses jamais demandées au DNS du téléphone, l'application évite les filtres d'AdGuard Home et la visibilité de Vigie sur les domaines. Les logiciels malveillants le font pour ne pas être bloqués.",
    innocent: [
      "Un navigateur avec « DNS sécurisé » activé ou une application de confidentialité.",
      "Une application qui contient des adresses IP écrites en dur (jeu, caméra connectée, application d'entreprise).",
    ],
    actions: [
      "Regarder dans la fiche si l'application a un profil de risque élevé.",
      "Désinstaller l'application si elle n'a aucune raison légitime de contourner le DNS.",
    ],
  },
  'detect.sms_abuse': {
    label: "Envoi de SMS anormal",
    why: "Un logiciel malveillant peut envoyer des milliers de SMS (hameçonnage, numéros surtaxés) sans rien afficher. L'envoi de SMS par une application autre que votre application de messagerie est anormal, et un volume élevé coûte de l'argent, expose votre numéro et peut le faire bloquer par l'opérateur.",
    innocent: [
      "Une application à laquelle vous avez donné ce droit : code de vérification, alarme, covoiturage, livraison.",
      "Une application SMS alternative qui n'est pas celle réglée par défaut.",
    ],
    actions: [
      "Désinstaller l'application tout de suite si vous ne l'avez pas autorisée à envoyer des SMS.",
      "Retirer sa permission SMS dans Paramètres, Applications.",
      "Vérifier votre facture et vos SMS envoyés auprès de votre opérateur.",
    ],
    guard: 'sms',
    mutable: false,
  },
  'detect.sensor_background': {
    label: "Micro ou caméra en arrière-plan",
    why: "Le micro ou la caméra utilisés quand l'application n'est pas à l'écran : écoute ou prise de vue à votre insu, comme le fait un logiciel espion.",
    innocent: [
      "Un appel ou une visioconférence en cours, réduits en fenêtre flottante.",
      "Un enregistreur vocal, un assistant vocal ou une reconnaissance de musique que vous avez lancés.",
    ],
    actions: [
      "Vous souvenir de ce que vous faisiez à ce moment.",
      "Retirer la permission micro ou caméra de l'application, ou la désinstaller si vous ne la connaissez pas.",
      "Consulter la page Sécurité, onglet Caméra et micro.",
    ],
  },
  'detect.new_app_risky': {
    label: "Application récente à risque",
    why: "Une application à haut risque dès son installation (par exemple SMS, démarrage automatique, installation hors boutique), ou une application toute récente qui obtient une capacité sensible, c'est la signature d'un logiciel malveillant qui vient de s'installer.",
    innocent: [
      "Une application hors boutique que vous avez installée volontairement (F-Droid, application d'entreprise, outil technique).",
      "Une application légitime mais très demandeuse en permissions.",
    ],
    actions: [
      "Lire les raisons du profil de risque dans la fiche de l'application.",
      "La désinstaller si vous ne la reconnaissez pas.",
    ],
    guard: 'quarantine',
  },
  'detect.sms_permission': {
    label: "Permission d'envoi de SMS à vérifier",
    why: "Cette application détient le droit d'envoyer des SMS sans passer par votre application de messagerie, alors qu'elle n'est ni l'application SMS par défaut ni une application du système. C'est une revue, pas la preuve d'un abus : un logiciel de fraude au SMS a besoin de ce droit, et Vigie ne voit pas les envois eux-mêmes sans le collecteur expérimental « Usage des opérations sensibles ». Une seule revue par application, à la première observation.",
    innocent: [
      "Une application que vous avez choisie pour cela : code de vérification, alarme, covoiturage, livraison, banque.",
      "Une messagerie alternative installée à côté de l'application par défaut.",
      "Un droit déjà présent quand Vigie a été installé (inventaire initial), sans que l'application ait fait quoi que ce soit.",
    ],
    actions: [
      "Vous demander si c'est voulu : cette application a-t-elle une raison d'envoyer des SMS ?",
      "Si non : retirer sa permission SMS (Paramètres, Applications) ou la désinstaller.",
      "Si oui : rien à faire, ou mettre cette revue en sourdine pour cette application.",
      "Dans tous les cas, la vraie protection est la garde SMS de l'application Vigie : elle refuse l'envoi de SMS à toutes les applications sauf votre liste.",
    ],
    guard: 'sms',
    review: true,
  },
  'detect.default_app_changed': {
    label: "Application par défaut changée",
    why: "L'application par défaut d'un rôle sensible (SMS, téléphone, clavier, assistant) a changé. Pour le rôle SMS, c'est la voie classique des chevaux de Troie SMS : se faire désigner application SMS par défaut leur donne l'envoi, la lecture et l'interception des SMS, et contourne les refus de permission. Pour le composeur, le clavier ou l'assistant, la nouvelle application voit les appels, la saisie ou l'écran.",
    innocent: [
      "Vous venez d'installer une autre messagerie, un autre composeur ou un autre clavier et vous l'avez choisi vous-même.",
      "Une mise à jour ou une réinitialisation d'Android qui a rétabli le choix par défaut.",
    ],
    actions: [
      "Vous souvenir si vous avez fait ce choix. Sinon : Paramètres, Applications, Applications par défaut : remettre l'ancienne application.",
      "Ouvrir la fiche de la nouvelle application : profil de risque et raisons.",
      "La désinstaller si vous ne la reconnaissez pas.",
    ],
    guard: 'sms',
    mutable: false,
  },
  'detect.flood': {
    label: "Trop de détections en une journée",
    why: "Au-delà de 200 détections par appareil et par jour, le collecteur n'en garde plus qu'une seule, celle-ci. Un volume pareil n'est pas normal : l'appareil envoie des données incohérentes (agent défectueux, horloge fausse) ou il est compromis et quelqu'un fabrique des événements pour noyer les vraies alertes.",
    innocent: [
      "Un défaut de l'agent ou une horloge du téléphone très décalée.",
      "Le rattrapage d'un très long historique envoyé d'un coup après une coupure.",
    ],
    actions: [
      "Regarder l'état de l'appareil sur la vue d'ensemble (événements perdus, collecteurs en erreur) et le journal des événements du jour.",
      "Si rien ne l'explique, considérer le téléphone comme compromis : changer le code de commande dans l'application, et au besoin révoquer l'appareil puis le ré-enrôler (ligne de commande du collecteur).",
    ],
    mutable: false,
  },
};

/** Informations de repli pour un type inconnu de cette version de la console. */
const UNKNOWN: TypeInfo = {
  label: '',
  why: "Ce type de détection n'est pas connu de cette version de la console : la description et les preuves du collecteur sont affichées telles quelles.",
  innocent: [],
  actions: ["Regarder la fiche de l'application concernée, si elle est connue."],
};

export function typeInfo(type: string): TypeInfo {
  const e = Object.prototype.hasOwnProperty.call(TYPES, type) ? TYPES[type as DetectionType] : undefined;
  return e ?? { ...UNKNOWN, label: type };
}

/** Types qui ne se mettent jamais en sourdine (§11.4) : `sms_abuse`, `default_app_changed` ; `flood` n'a pas d'application. */
export function isMutable(d: Pick<Detection, 'type' | 'package'>): boolean {
  return !!d.package && typeInfo(d.type).mutable !== false && d.type !== 'detect.muted' && d.type !== 'detect.unmuted';
}

/** Événements serveur de la sourdine : ce ne sont pas des détections (§11.4). */
export function isMuteEvent(type: string): boolean {
  return type === 'detect.muted' || type === 'detect.unmuted';
}

export function detectionLabel(type: string): string {
  return typeInfo(type).label;
}

// ------------------------------------------------------------------------------------------- gravité

/** Gravité sur l'échelle 0 à 3 des événements ; accepte aussi un mot (`low`, `medium`, `high`, `critical`). */
export function normSeverity(v: unknown): number {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.max(0, Math.min(3, Math.trunc(v)));
  if (typeof v === 'string') {
    switch (v.toLowerCase()) {
      case 'info':
        return 0;
      case 'low':
        return 1;
      case 'medium':
        return 2;
      case 'high':
      case 'critical':
        return 3;
      default: {
        const n = Number(v);
        return Number.isFinite(n) ? Math.max(0, Math.min(3, Math.trunc(n))) : 0;
      }
    }
  }
  return 0;
}

export interface SeverityCounts {
  critical: number;
  warning: number;
  notable: number;
  info: number;
  total: number;
}

/** Nombre de détections par gravité : 3 critique, 2 avertissement, 1 notable, 0 info. */
export function countBySeverity(all: readonly { severity: number; muted?: boolean | undefined }[]): SeverityCounts {
  const list = all.filter((d) => !d.muted);
  const c: SeverityCounts = { critical: 0, warning: 0, notable: 0, info: 0, total: list.length };
  for (const d of list) {
    const s = normSeverity(d.severity);
    if (s >= 3) c.critical++;
    else if (s === 2) c.warning++;
    else if (s === 1) c.notable++;
    else c.info++;
  }
  return c;
}

// ------------------------------------------------------------------------------------- lecture API

function isoOrUndef(v: unknown): string | undefined {
  return typeof v === 'string' && parseTs(v) ? v : undefined;
}

/** Normalise un élément de `GET /detections` ; undefined s'il manque l'identifiant, l'heure ou le type. */
export function normalizeDetection(raw: unknown): Detection | undefined {
  if (!isRecord(raw)) return undefined;
  const id = raw['id'];
  const ts = raw['ts'];
  const type = raw['type'];
  if (typeof id !== 'string' || id === '' || typeof type !== 'string' || type === '' || typeof ts !== 'string') return undefined;
  const ev = isRecord(raw['evidence']) ? raw['evidence'] : {};
  const d: Detection = { id, ts, type, severity: normSeverity(raw['severity'] ?? raw['sev']), evidence: ev };
  if (typeof raw['package'] === 'string' && raw['package'] !== '') d.package = raw['package'];
  if (typeof raw['label'] === 'string' && raw['label'] !== '') d.label = raw['label'];
  if (typeof raw['summary'] === 'string' && raw['summary'] !== '') d.summary = raw['summary'];
  const wf = isoOrUndef(raw['window_from']) ?? isoOrUndef(ev['window_from']);
  const wt = isoOrUndef(raw['window_to']) ?? isoOrUndef(ev['window_to']);
  if (wf) d.window_from = wf;
  if (wt) d.window_to = wt;
  if (typeof raw['device_id'] === 'string') d.device_id = raw['device_id'];
  if (typeof raw['updated_at'] === 'string' && parseTs(raw['updated_at'])) d.updated_at = raw['updated_at'];
  if (raw['recurring'] === true || ev['recurring'] === true) d.recurring = true;
  if (raw['muted'] === true) d.muted = true;
  return d;
}

export function parseDetectionsResponse(raw: unknown): { detections: Detection[]; next_cursor?: string } {
  const arr = isRecord(raw) ? raw['detections'] : Array.isArray(raw) ? raw : [];
  const detections = (Array.isArray(arr) ? arr : []).map(normalizeDetection).filter((d): d is Detection => !!d);
  const next = isRecord(raw) && typeof raw['next_cursor'] === 'string' && raw['next_cursor'] !== '' ? raw['next_cursor'] : undefined;
  return next ? { detections, next_cursor: next } : { detections };
}

/** Détection reçue en direct : événement serveur `detect.*` du flux SSE (la détection y est dans `data`). */
export function detectionFromEvent(ev: VigieEvent): Detection | undefined {
  if (!isDetectionType(ev.type) || isMuteEvent(ev.type)) return undefined;
  const d = ev.data;
  // Une mise à jour (`update: true`, `detection_id`) est une nouvelle version d'une détection existante : même identifiant.
  const updated = d['update'] === true && typeof d['detection_id'] === 'string' && d['detection_id'] !== '';
  return normalizeDetection({
    id: updated ? d['detection_id'] : ev.id,
    ...(updated ? { updated_at: ev.ts } : {}),
    ...(d['recurring'] === true ? { recurring: true } : {}),
    ...(d['muted'] === true ? { muted: true } : {}),
    ts: ev.ts,
    type: ev.type,
    package: d['package'],
    label: d['label'],
    severity: ev.sev,
    summary: d['summary'],
    evidence: d['evidence'],
    window_from: d['window_from'],
    window_to: d['window_to'],
    device_id: ev.device_id,
  });
}

/**
 * Ajoute des détections en tête (les plus récentes d'abord), sans doublon, ordre par `ts` décroissant. L'identifiant
 * d'une détection est celui de son événement serveur : il est le même dans la liste de l'API et dans le flux SSE.
 * (Une même fenêtre peut porter plusieurs détections d'une même application, par exemple un domaine de menace
 * par détection : on ne déduplique donc pas sur la fenêtre.)
 */
export function mergeDetections(existing: readonly Detection[], incoming: readonly Detection[], opts: { replace?: boolean } = {}): Detection[] {
  const seen = new Set(existing.map((d) => d.id));
  const fresh: Detection[] = [];
  const replaced = new Map<string, Detection>();
  for (const d of incoming) {
    if (seen.has(d.id)) {
      // Mise à jour reçue en direct : la version du flux est plus récente que celle de la liste.
      if (opts.replace) replaced.set(d.id, d);
      continue;
    }
    seen.add(d.id);
    fresh.push(d);
  }
  if (fresh.length === 0 && replaced.size === 0) return existing as Detection[];
  const base = replaced.size ? existing.map((e) => (replaced.has(e.id) ? { ...e, ...(replaced.get(e.id) as Detection), ts: e.ts } : e)) : existing;
  return [...fresh, ...base].sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
}

/** Détections qui comptent pour le verdict : celles en sourdine sont calculées mais ne sont ni alertées ni comptées. */
export function active<T extends { muted?: boolean | undefined }>(list: readonly T[]): T[] {
  return list.filter((d) => !d.muted);
}

export interface DetectionFilter {
  type?: string | undefined;
  pkg?: string | undefined;
  sevMin?: number | undefined;
  from?: string | undefined;
  to?: string | undefined;
}

export function matchesDetection(d: Detection, f: DetectionFilter): boolean {
  if (f.type && d.type !== f.type) return false;
  if (f.pkg && d.package !== f.pkg) return false;
  if (f.sevMin && d.severity < f.sevMin) return false;
  const t = parseTs(d.ts)?.getTime();
  if (t !== undefined) {
    if (f.from && t < Date.parse(f.from)) return false;
    if (f.to && t > Date.parse(f.to)) return false;
  }
  return true;
}

// ------------------------------------------------------------------------------------------- preuves

function pick(ev: DataObject, keys: readonly string[]): unknown {
  for (const k of keys) if (ev[k] !== undefined && ev[k] !== null) return ev[k];
  return undefined;
}
function pickNum(ev: DataObject, keys: readonly string[]): number | undefined {
  const v = pick(ev, keys);
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}
function pickStrList(ev: DataObject, keys: readonly string[]): string[] {
  const v = pick(ev, keys);
  if (Array.isArray(v)) return v.filter((x): x is string | number => typeof x === 'string' || typeof x === 'number').map((x) => cleanText(String(x), 255)).filter(Boolean);
  if (typeof v === 'string' && v !== '') return [cleanText(v, 255)];
  return [];
}
function pickBool(ev: DataObject, keys: readonly string[]): boolean | undefined {
  const v = pick(ev, keys);
  return typeof v === 'boolean' ? v : undefined;
}

const plural = (n: number, one: string, many: string) => (n > 1 ? many : one);

/** Domaines cités par une détection (`domains`), nettoyés ; vide si la preuve n'en porte pas. */
export function detectionDomains(d: Detection): string[] {
  return pickStrList(d.evidence, ['domains', 'domain', 'hostnames', 'blocked_domains', 'examples']).slice(0, 50);
}

/** Nom lisible de l'application : libellé nettoyé, sinon paquet, sinon formulation neutre. */
export function appNameOf(d: Pick<Detection, 'label' | 'package'>): string {
  return cleanText(d.label, 80) || cleanText(d.package, 120) || 'Une application';
}

/**
 * Ce qui a été observé, en une phrase. S'appuie sur la preuve quand elle est lisible ; sinon sur le `summary`
 * du collecteur, sinon sur le libellé du type.
 */
export function observation(d: Detection): string {
  const who = appNameOf(d);
  const ev = d.evidence;
  const fallback = () => cleanText(d.summary, 300) || `${detectionLabel(d.type)} : ${who}`;
  switch (d.type) {
    case 'detect.threat_domain': {
      const list = detectionDomains(d);
      const n = pickNum(ev, ['domain_count', 'domains_count', 'count', 'n']) ?? (list.length || undefined);
      if (n === undefined) return fallback();
      // Le collecteur émet une détection par domaine (`domain`, `requests`) ; une preuve groupée (`domains`) est aussi lue.
      const req = pickNum(ev, ['requests']);
      if (n === 1 && list.length === 1) {
        return `${who} a tenté de joindre le domaine ${list[0]} de la liste de menaces${req !== undefined ? ` (${fmtNumber(req)} ${plural(req, 'requête', 'requêtes')})` : ''}`;
      }
      return `${who} a tenté de joindre ${fmtNumber(n)} ${plural(n, 'domaine', 'domaines')} de la liste de menaces${req !== undefined ? ` (${fmtNumber(req)} ${plural(req, 'requête', 'requêtes')})` : ''}`;
    }
    case 'detect.upload_spike': {
      const sent = pickNum(ev, ['tx_bytes', 'bytes', 'sent_bytes', 'upload_bytes']);
      if (sent === undefined) return fallback();
      const base = pickNum(ev, ['median_bytes', 'baseline_bytes', 'median_tx_bytes']);
      const ratio = pickNum(ev, ['ratio', 'factor', 'multiple']) ?? (base && base > 0 ? sent / base : undefined);
      const limit = pickNum(ev, ['threshold_bytes']);
      const learning = pickBool(ev, ['learning']) === true;
      return `${who} a envoyé ${fmtBytes(sent)} en une heure${ratio !== undefined && ratio >= 1.5 ? `, soit ${fmtNumber(ratio, ratio < 10 ? 1 : 0)} fois plus que d'habitude` : ''}${base !== undefined ? ` (médiane : ${fmtBytes(base)})` : learning && limit !== undefined ? ` (au-delà du seuil de ${fmtBytes(limit)} ; pas encore assez d'historique pour une médiane)` : ''}`;
    }
    case 'detect.fanout': {
      const n = pickNum(ev, ['addresses', 'distinct_ips', 'distinct', 'destinations', 'count']);
      if (n === undefined) return fallback();
      return `${who} s'est connectée à ${fmtNumber(n)} adresses différentes en une heure`;
    }
    case 'detect.mail_ports': {
      const ports = pickStrList(ev, ['ports']);
      const n = pickNum(ev, ['connections', 'count']);
      const p = ports.length ? ` (port${ports.length > 1 ? 's' : ''} ${ports.join(', ')})` : '';
      if (n === undefined && ports.length === 0) return fallback();
      return `${who} ${n !== undefined ? `a ouvert ${fmtNumber(n)} ${plural(n, 'connexion', 'connexions')}` : 'se connecte'} vers des serveurs de courrier${p}, sans être un client de messagerie connu`;
    }
    case 'detect.dns_bypass': {
      const prov = pickStrList(ev, ['providers']);
      const res = prov.length > 0 ? prov : pickStrList(ev, ['resolvers', 'resolver']);
      const unresolved = pickNum(ev, ['unresolved_ips', 'unresolved', 'unresolved_count']);
      if (res.length > 0) return `${who} a contacté ${res.length > 1 ? 'des résolveurs DNS publics' : 'un résolveur DNS public'} (${res.slice(0, 3).join(', ')}) : ses requêtes DNS échappent au filtrage du téléphone`;
      if (unresolved !== undefined) return `${who} s'est connectée à ${fmtNumber(unresolved)} ${plural(unresolved, 'adresse', 'adresses')} que le téléphone n'avait jamais demandées à son DNS`;
      return fallback();
    }
    case 'detect.sms_abuse': {
      const n = pickNum(ev, ['sent', 'count', 'sms_count', 'send_sms']);
      if (n === undefined) return fallback();
      const bg = pickNum(ev, ['background', 'background_count']);
      const notDefault = ev['reason'] === 'not_default_sms_app' || pickBool(ev, ['default_sms_app', 'is_default_sms', 'is_default']) === false;
      const volume = ev['reason'] === 'volume';
      const rej = pickNum(ev, ['rejected']);
      return `${who} a envoyé ${fmtNumber(n)} ${plural(n, 'SMS', 'SMS')}${bg !== undefined && bg > 0 ? `, dont ${fmtNumber(bg)} en arrière-plan` : ''}${rej ? `, et a tenté d'en envoyer ${fmtNumber(rej)} de plus, refusés par le système` : ''}${notDefault ? " alors que ce n'est pas l'application SMS par défaut" : volume ? ' : un volume anormal' : ''}`;
    }
    case 'detect.sensor_background': {
      // Format du collecteur : une détection par application et par jour, avec `microphone_background` et `camera_background` ;
      // ancien format : `op` et `background_count`.
      const mic = pickNum(ev, ['microphone_background']);
      const cam = pickNum(ev, ['camera_background']);
      if (mic !== undefined || cam !== undefined) {
        const parts: string[] = [];
        if (mic) parts.push(`le micro ${fmtNumber(mic)} ${plural(mic, 'fois', 'fois')}`);
        if (cam) parts.push(`la caméra ${fmtNumber(cam)} ${plural(cam, 'fois', 'fois')}`);
        if (parts.length > 0) return `${who} a utilisé ${parts.join(' et ')} en arrière-plan`;
      }
      const op = typeof ev['op'] === 'string' ? ev['op'] : undefined;
      const n = pickNum(ev, ['background_count', 'count']);
      if (n === undefined) return fallback();
      const what = op === 'camera' ? 'la caméra' : op === 'record_audio' ? 'le micro' : op ? opInfo(op).label.toLowerCase() : 'le micro ou la caméra';
      return `${who} a utilisé ${what} ${fmtNumber(n)} ${plural(n, 'fois', 'fois')} en arrière-plan`;
    }
    case 'detect.new_app_risky': {
      // Format du collecteur : `high_risk` (bool) et `capabilities` (codes) ; ancien format : `trigger` et `capability`.
      const caps = pickStrList(ev, ['capabilities']).map(capabilityLabel);
      const one = typeof ev['capability'] === 'string' ? capabilityLabel(ev['capability']) : undefined;
      if (one) caps.push(one);
      const level = typeof ev['level'] === 'string' ? ev['level'] : undefined;
      const high = ev['high_risk'] === true || ev['trigger'] === 'high_risk' || (ev['high_risk'] === undefined && ev['trigger'] === undefined && level === 'high');
      if (high && caps.length > 0) return `${who} vient d'être installée avec un profil de risque élevé et a déjà obtenu : ${caps.join(', ')}`;
      if (high) return `${who} vient d'être installée avec un profil de risque élevé`;
      if (caps.length > 0) return `${who}, installée depuis moins de 24 h, a obtenu une capacité sensible : ${caps.join(', ')}`;
      return fallback();
    }
    case 'detect.sms_permission':
      return `${who} peut envoyer des SMS sans passer par votre messagerie ; est-ce voulu ?`;
    case 'detect.default_app_changed': {
      const role = typeof ev['role'] === 'string' ? ev['role'] : undefined;
      const old = typeof ev['old'] === 'string' && ev['old'] !== '' ? cleanText(ev['old'], 120) : undefined;
      if (!role) return fallback();
      return `${who} est devenue ${role === 'sms' ? "l'application SMS par défaut" : `le rôle « ${roleLabel(role)} » par défaut`}${old ? ` (à la place de ${old})` : ''}`;
    }
    case 'detect.flood': {
      const n = pickNum(ev, ['count', 'total', 'suppressed', 'dropped']);
      const cap = pickNum(ev, ['limit', 'cap', 'max']) ?? 200;
      return `Plus de ${fmtNumber(cap)} détections en une journée sur cet appareil${n !== undefined ? ` (${fmtNumber(n)} produites)` : ''} : seule celle-ci est gardée`;
    }
    default:
      return fallback();
  }
}

/** Capacités suivies par `detect.new_app_risky` (clés du collecteur) ; une clé inconnue est affichée telle quelle. */
const CAPABILITY_LABELS: Record<string, string> = {
  accessibility: "service d'accessibilité",
  notification_listener: 'lecture des notifications',
  device_admin: "administrateur de l'appareil",
  unknown_sources: "installation d'autres applications",
  overlay: 'superposition aux autres applications',
  vpn: 'VPN',
  'role:sms': 'application SMS par défaut',
  'role:dialer': 'application Téléphone par défaut',
  'role:assistant': 'assistant par défaut',
  'role:call_screening': "filtrage d'appels",
  'permission:SEND_SMS': 'envoi de SMS',
  'permission:READ_SMS': 'lecture des SMS',
  'permission:RECEIVE_SMS': 'réception des SMS',
  'permission:RECEIVE_MMS': 'réception des MMS',
  'permission:READ_CALL_LOG': "journal d'appels",
  'permission:PROCESS_OUTGOING_CALLS': 'appels sortants',
  'permission:CALL_PHONE': 'appels téléphoniques',
};

export function capabilityLabel(code: string): string {
  return Object.prototype.hasOwnProperty.call(CAPABILITY_LABELS, code) ? (CAPABILITY_LABELS[code] as string) : cleanText(code, 80);
}

const REASON_VALUES: Record<string, string> = {
  not_default_sms_app: "pas l'application SMS par défaut",
  volume: 'volume quotidien dépassé',
  high_risk: 'profil à risque élevé',
  capability: 'capacité sensible obtenue',
  doh_resolver: 'résolveur DNS public',
  unresolved_ips: 'adresses jamais résolues',
};

export interface EvidenceItem {
  label: string;
  value: string;
}

const EVIDENCE_LABELS: Record<string, string> = {
  microphone_background: 'Micro en arrière-plan',
  microphone_count: 'Micro (total)',
  camera_background: 'Caméra en arrière-plan',
  camera_count: 'Caméra (total)',
  ops: 'Opérations',
  high_risk: 'Profil à risque élevé',
  capabilities: 'Capacités obtenues',
  minutes_to_first_capability: "Minutes avant la première capacité",
  hours: 'Heures concernées',
  first_hour: 'Première heure',
  peak_hour: 'Heure de pointe',
  role: 'Rôle',
  old: 'Ancienne application',
  new: 'Nouvelle application',
  limit: 'Plafond',
  domain: 'Domaine',
  requests: 'Requêtes',
  blocked: 'Bloqué par AdGuard',
  reason: 'Motif',
  addresses: 'Adresses distinctes',
  providers: 'Fournisseurs',
  sent: 'SMS envoyés',
  rejected: 'Refusés par le système',
  background: 'Dont en arrière-plan',
  read_contacts: 'Lectures de contacts',
  history_hours: "Heures d'historique",
  learning: "Historique insuffisant",
  screen_on_minutes: 'Minutes écran allumé',
  minutes_after_install: "Minutes après l'installation",
  installer: 'Installateur',
  from_store: 'Depuis une boutique',
  domains: 'Domaines',
  domain_count: 'Nombre de domaines',
  list: 'Liste de menaces',
  lists: 'Listes de menaces',
  tx_bytes: 'Octets envoyés sur l’heure',
  median_bytes: 'Médiane horaire sur 14 jours',
  ratio: 'Facteur par rapport à la médiane',
  threshold_bytes: 'Seuil',
  distinct_ips: 'Adresses distinctes',
  threshold: 'Seuil',
  sample: 'Exemples',
  ports: 'Ports',
  connections: 'Connexions',
  destinations: 'Destinations',
  resolvers: 'Résolveurs',
  unresolved_ips: 'Adresses jamais résolues',
  count: 'Nombre',
  background_count: 'Dont en arrière-plan',
  default_sms_app: 'Application SMS par défaut',
  op: 'Opération',
  level: 'Niveau de risque',
  score: 'Score',
  reasons: 'Raisons',
  capability: 'Capacité obtenue',
  installed_at: 'Installée le',
  trigger: 'Déclencheur',
};

const DATE_KEYS = new Set(['installed_at', 'first_hour', 'peak_hour']);
const BYTES_KEYS = new Set(['tx_bytes', 'median_bytes', 'threshold_bytes', 'rx_bytes', 'bytes']);

function scalar(v: unknown): string | undefined {
  if (typeof v === 'string') return v === '' ? undefined : cleanText(v, 255);
  if (typeof v === 'number' && Number.isFinite(v)) return fmtNumber(v, Number.isInteger(v) ? 0 : 2);
  if (typeof v === 'boolean') return v ? 'oui' : 'non';
  return undefined;
}

/** Éléments de preuve lisibles : clés connues traduites, autres clés affichées telles quelles (texte). */
export function evidenceItems(d: Detection): EvidenceItem[] {
  const out: EvidenceItem[] = [];
  for (const [k, v] of Object.entries(d.evidence)) {
    if (k === 'window_from' || k === 'window_to') continue;
    const label = Object.prototype.hasOwnProperty.call(EVIDENCE_LABELS, k) ? (EVIDENCE_LABELS[k] as string) : k;
    let value: string | undefined;
    if (typeof v === 'number' && BYTES_KEYS.has(k)) value = fmtBytes(v);
    else if (k === 'op' && typeof v === 'string') value = opInfo(v).label;
    else if ((k === 'reason' || k === 'trigger') && typeof v === 'string') value = REASON_VALUES[v] ?? scalar(v);
    else if (k === 'capability' && typeof v === 'string') value = capabilityLabel(v);
    else if (k === 'reasons' && Array.isArray(v)) value = v.filter((x): x is string => typeof x === 'string').map((x) => reasonInfo(x).label).join(', ') || undefined;
    else if (DATE_KEYS.has(k) && typeof v === 'string') value = parseTs(v) ? `${fmtDate(v)} ${fmtTime(v)}` : scalar(v);
    else if (k === 'role' && typeof v === 'string') value = roleLabel(v);
    else if (k === 'blocked' && typeof v === 'number') {
      out.push({ label: 'Blocages comptés par AdGuard', value: fmtNumber(v) });
      continue;
    } else if (k === 'capabilities' && Array.isArray(v)) value = v.filter((x): x is string => typeof x === 'string').map(capabilityLabel).join(', ') || undefined;
    else if (k === 'risk' && isRecord(v)) {
      // profil de risque de la nouvelle application (default_app_changed) : aplati
      for (const [rk, rv] of Object.entries(v)) {
        if (rk === 'reasons' && Array.isArray(rv)) out.push({ label: 'Risque : raisons', value: rv.filter((x): x is string => typeof x === 'string').map((x) => reasonInfo(x).label).join(', ') });
        else if (scalar(rv) !== undefined) out.push({ label: `Risque : ${rk === 'score' ? 'score' : rk === 'level' ? 'niveau' : rk}`, value: scalar(rv) as string });
      }
      continue;
    }
    else if (Array.isArray(v)) {
      const items = v.map((x) => scalar(x) ?? (isRecord(x) ? safeJson(x) : '')).filter(Boolean);
      value = items.length ? items.join(', ') : undefined;
    } else if (isRecord(v)) value = safeJson(v);
    else value = scalar(v);
    if (value !== undefined) out.push({ label, value });
  }
  return out;
}

function safeJson(v: unknown): string {
  try {
    return cleanText(JSON.stringify(v), 255);
  } catch {
    return '';
  }
}

// ------------------------------------------------------------------------------------------- période

/** « 15/11/2026 de 14:00 à 15:00 » ou, si la fenêtre enjambe un jour, « du … au … » ; undefined sans fenêtre. */
export function fmtWindow(from: string | undefined, to: string | undefined): string | undefined {
  const a = parseTs(from);
  const b = parseTs(to);
  if (!a || !b) return undefined;
  const hm = (d: Date) => new Intl.DateTimeFormat('fr-FR', { hour: '2-digit', minute: '2-digit' }).format(d);
  if (fmtDate(a) === fmtDate(b)) return `${fmtDate(a)} de ${hm(a)} à ${hm(b)}`;
  return `du ${fmtDate(a)} ${hm(a)} au ${fmtDate(b)} ${hm(b)}`;
}

/** Une détection est « fraîche » si elle date de moins de 24 h. */
export function isRecent(d: Detection, now: Date, hours = 24): boolean {
  const t = parseTs(d.ts)?.getTime();
  return t !== undefined && now.getTime() - t < hours * 3600_000;
}

export interface Headline {
  tone: 'ok' | 'warn' | 'bad';
  text: string;
}

/** Résumé en une ligne : « Rien à signaler » ou « 2 critiques, 1 avertissement ». */
export function headline(c: SeverityCounts, truncated = false): Headline {
  if (c.total === 0) return { tone: 'ok', text: 'Rien à signaler' };
  const parts: string[] = [];
  if (c.critical) parts.push(`${fmtNumber(c.critical)} ${plural(c.critical, 'critique', 'critiques')}`);
  if (c.warning) parts.push(`${fmtNumber(c.warning)} ${plural(c.warning, 'avertissement', 'avertissements')}`);
  if (c.notable) parts.push(`${fmtNumber(c.notable)} ${plural(c.notable, 'à noter', 'à noter')}`);
  if (c.info) parts.push(`${fmtNumber(c.info)} ${plural(c.info, 'information', 'informations')}`);
  const tone = c.critical > 0 ? 'bad' : c.warning > 0 || c.notable > 0 ? 'warn' : 'ok';
  return { tone, text: `${parts.join(', ')}${truncated ? ' ou plus' : ''}` };
}

export interface AppDetections {
  package: string;
  label?: string;
  count: number;
  maxSeverity: number;
  types: string[];
}

/** Applications concernées, la plus préoccupante d'abord (gravité maximale, puis nombre de détections). */
export function groupByPackage(list: readonly Detection[]): AppDetections[] {
  const m = new Map<string, AppDetections>();
  for (const d of list) {
    if (!d.package || d.muted) continue;
    let g = m.get(d.package);
    if (!g) {
      g = { package: d.package, count: 0, maxSeverity: 0, types: [] };
      m.set(d.package, g);
    }
    if (d.label && !g.label) g.label = d.label;
    g.count++;
    g.maxSeverity = Math.max(g.maxSeverity, normSeverity(d.severity));
    if (!g.types.includes(d.type)) g.types.push(d.type);
  }
  return [...m.values()].sort((a, b) => b.maxSeverity - a.maxSeverity || b.count - a.count || a.package.localeCompare(b.package));
}

/**
 * Ce que les détections ne surveillent pas sur ce téléphone, à dire sous le verdict : `detect.sms_abuse` et
 * `detect.sensor_background` ne reposent que sur `app.ops`, collecteur expérimental et éteint par défaut. Sans
 * lui, un envoi massif de SMS par une application discrète ne produit AUCUNE détection (les SMS ne passent
 * pas par le réseau IP) : « Rien à signaler » ne doit pas le laisser croire. `state` est l'état du collecteur
 * dans le dernier battement de cœur (`running`, `disabled`, `unavailable`, absent si inconnu).
 */
export function opsBlindSpot(state: string | undefined): string | null {
  return monitoringScope(state).blind;
}

export interface MonitoringScope {
  /** ce qui est surveillé dans tous les cas */
  watched: string;
  /** ce qui ne l'est pas ; null quand le collecteur `app_ops` tourne */
  blind: string | null;
  /** précision sur `app_ops` quand il tourne : en marche ne prouve pas que des données arrivent */
  ops: string | null;
  /** la vraie protection */
  guard: string;
}

/**
 * Ce que les détections surveillent et ne surveillent pas sur ce téléphone (contrat §11.4), à dire sous le verdict, vert compris.
 * Sans le collecteur expérimental `app_ops`, les envois de SMS eux-mêmes ne sont pas vus (ils ne passent pas par le réseau IP) ;
 * restent surveillés la détention de la permission d'envoi et le changement d'application SMS par défaut. La garde SMS de
 * l'application Vigie est la vraie protection : une détection signale, la garde empêche.
 */
export function monitoringScope(state: string | undefined): MonitoringScope {
  const why =
    state === 'disabled'
      ? 'est désactivé dans l’application Vigie'
      : state === 'unavailable'
        ? 'est indisponible sur ce téléphone (permission DUMP non accordée, ou lecture impossible)'
        : 'n’est pas signalé par ce téléphone';
  const watched =
    "Surveillé dans tous les cas : les applications qui détiennent la permission d'envoyer des SMS sans être votre messagerie, le changement d'application SMS (ou téléphone, clavier, assistant) par défaut, les domaines de menaces, les gros envois de données, les connexions inhabituelles et les nouvelles applications à risque.";
  const guard =
    "La vraie protection est la garde SMS de l'application Vigie, à régler sur le téléphone : une détection signale, la garde empêche.";
  if (state === 'running') {
    return {
      watched,
      blind: null,
      ops: "Les envois de SMS et l'usage du micro ou de la caméra en arrière-plan sont surveillés par le collecteur expérimental « Usage des opérations sensibles » (« en marche » ne prouve pas que des données arrivent : voir Applications, Opérations sensibles).",
      guard,
    };
  }
  return {
    watched,
    blind: `Non surveillé ici : les envois de SMS eux-mêmes et l’usage du micro ou de la caméra en arrière-plan. Le collecteur expérimental « Usage des opérations sensibles » ${why} ; sans lui, une application qui enverrait des milliers de SMS ne produirait aucune détection d’envoi.`,
    ops: null,
    guard,
  };
}

// ------------------------------------------------------------------------------------------- sourdines (§11.4)

/** Lit `GET /detections/mutes` : `{ mutes: [...] }`, ou tableau nu ; les éléments sans type ni paquet sont ignorés. */
export function parseMutes(raw: unknown): DetectionMute[] {
  const arr = Array.isArray(raw) ? raw : isRecord(raw) ? (raw['mutes'] ?? raw['items'] ?? []) : [];
  const out: DetectionMute[] = [];
  for (const it of Array.isArray(arr) ? arr : []) {
    if (!isRecord(it) || typeof it['type'] !== 'string' || typeof it['package'] !== 'string' || it['type'] === '' || it['package'] === '') continue;
    const m: DetectionMute = { type: it['type'], package: it['package'] };
    for (const k of ['label', 'reason', 'device_id', 'created_by'] as const) if (typeof it[k] === 'string' && it[k] !== '') m[k] = it[k] as string;
    const when = it['created_at'] ?? it['since'] ?? it['ts'];
    if (typeof when === 'string' && parseTs(when)) m.created_at = when;
    out.push(m);
  }
  return out;
}

export function isCovered(d: Pick<Detection, 'type' | 'package'>, mutes: readonly DetectionMute[]): boolean {
  return !!d.package && mutes.some((m) => m.type === d.type && m.package === d.package);
}

/** Marque en sourdine les détections couvertes par une sourdine en cours (même celles créées avant elle). */
export function applyMutes(list: readonly Detection[], mutes: readonly DetectionMute[]): Detection[] {
  if (mutes.length === 0) return list as Detection[];
  return list.map((d) => (d.muted || !isCovered(d, mutes) ? d : { ...d, muted: true }));
}

/** Message utile pour l'échec d'une mise en sourdine ou de sa levée. */
export function muteErrorMessage(e: { status: number; code: string; message: string }): string {
  if (e.status === 0) return e.message;
  if (e.code === 'not_mutable' || e.status === 400 || e.status === 422) return `Cette détection ne peut pas être mise en sourdine : ${e.message}`;
  if (e.status === 404) return "Ce collecteur ne gère pas encore la mise en sourdine des détections (contrat §11.4).";
  return e.message;
}
