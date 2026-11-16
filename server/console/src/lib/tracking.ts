// Vue « pistage » (contrat §9) : niveaux, statuts, motifs, agrégations. Fonctions pures.
import type { ApiError } from '../api/client.ts';
import type { Publisher, TrackingApp, TrackingDomain, TrackingTotals } from '../api/types.ts';

export type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'info';

// ------------------------------------------------------------------------------------------- niveaux

export interface LevelText {
  key: string;
  name: string;
  description: string;
}

/** Textes de repli si le collecteur n'en fournit pas (`levels[].name` / `description`). */
export const LEVEL_FALLBACK: Record<string, { name: string; description: string }> = {
  permissif: {
    name: 'Permissif',
    description: 'Bloque la publicité et les traqueurs les plus connus. Aucune télémétrie de Google ou de Samsung n’est coupée : le risque de casser une application est minimal.',
  },
  equilibre: {
    name: 'Équilibré',
    description: 'Ajoute le blocage de la télémétrie et de la mesure d’audience (Google, Samsung, éditeurs tiers) en laissant passer ce dont le téléphone a besoin : notifications push, mises à jour, services Google Play.',
  },
  strict: {
    name: 'Strict',
    description: 'Bloque aussi les services d’arrière-plan facultatifs des éditeurs. Certaines applications peuvent perdre des fonctions (synchronisation, recommandations, connexion avec un compte).',
  },
};

export const LEVEL_ORDER = ['permissif', 'equilibre', 'strict'];

/** Fusionne les niveaux du collecteur avec les textes de repli ; l'ordre est permissif, équilibré, strict. */
export function levelTexts(levels: { key: string; name?: string; description?: string }[] | undefined): LevelText[] {
  const src: { key: string; name?: string; description?: string }[] =
    levels && levels.length > 0 ? levels : LEVEL_ORDER.map((key) => ({ key }));
  const out = src.map((l) => {
    const fb = LEVEL_FALLBACK[l.key];
    return { key: l.key, name: l.name || fb?.name || l.key, description: l.description || fb?.description || '' };
  });
  const rank = (k: string) => {
    const i = LEVEL_ORDER.indexOf(k);
    return i < 0 ? LEVEL_ORDER.length : i;
  };
  return out.sort((a, b) => rank(a.key) - rank(b.key));
}

// ------------------------------------------------------------------------------------ statuts et motifs

export interface StatusText {
  label: string;
  tone: Tone;
}

export function domainStatus(status: string | undefined): StatusText {
  switch (status) {
    case 'blocked':
      return { label: 'Bloqué', tone: 'ok' };
    case 'allowed':
      return { label: 'Autorisé', tone: 'neutral' };
    case 'mixed':
      return { label: 'Mixte', tone: 'warn' };
    default:
      return { label: 'Non évalué', tone: 'neutral' };
  }
}

export function overrideLabel(o: 'block' | 'allow' | undefined): string | undefined {
  return o === 'block' ? 'Règle manuelle : bloquer' : o === 'allow' ? 'Règle manuelle : autoriser' : undefined;
}

const REASON_TOKENS: Record<string, string> = {
  FilteredBlackList: 'Liste de blocage',
  FilteredBlockedService: 'Service bloqué',
  FilteredSafeBrowsing: 'Navigation sécurisée',
  FilteredParental: 'Contrôle parental',
  FilteredSafeSearch: 'Recherche sécurisée',
  FilteredInvalid: 'Requête invalide',
  NotFilteredWhiteList: 'Autorisé par une règle',
  NotFilteredNotFound: 'Aucune liste ne le bloque',
  NotFilteredError: 'Non filtré (erreur du filtre)',
  Rewrite: 'Réécrit par une règle',
  RewriteEtcHosts: 'Réécrit (fichier hosts)',
  RewriteAutoHosts: 'Réécrit (hôte automatique)',
};

/**
 * Traduit un motif. Le contrat ne fixe pas son format : on reconnaît les jetons d'AdGuard Home, éventuellement
 * suivis de « : nom de liste ou règle », et on affiche tout autre texte tel quel.
 */
export function reasonLabel(reason: string | undefined): string | undefined {
  if (!reason) return undefined;
  const m = /^([A-Za-z]+)\s*(?::\s*(.*))?$/.exec(reason.trim());
  const token = m?.[1];
  const known = token ? REASON_TOKENS[token] : undefined;
  if (known) return m?.[2] ? `${known} : ${m[2]}` : known;
  return reason.trim();
}

// ----------------------------------------------------------------------------------------- agrégations

/** Part bloquée en pour cent (0-100), ou undefined sans décompte bloqué/autorisé (mode dégradé). */
export function blockedPct(x: { queries: number; blocked?: number; allowed?: number }): number | undefined {
  if (x.blocked === undefined && x.allowed === undefined) return undefined;
  const total = (x.blocked ?? 0) + (x.allowed ?? 0) || x.queries;
  if (total <= 0) return 0;
  return ((x.blocked ?? 0) / total) * 100;
}

/** Totaux fournis par le collecteur, sinon somme des éditeurs. */
export function totalsOf(totals: TrackingTotals | undefined, publishers: Publisher[]): TrackingTotals {
  if (totals) return totals;
  const out: TrackingTotals = { queries: 0 };
  for (const p of publishers) {
    out.queries += p.queries;
    if (p.blocked !== undefined) out.blocked = (out.blocked ?? 0) + p.blocked;
    if (p.allowed !== undefined) out.allowed = (out.allowed ?? 0) + p.allowed;
  }
  return out;
}

/** Éditeurs triés par requêtes décroissantes ; les éditeurs sans requête sont écartés. */
export function sortPublishers(publishers: Publisher[]): Publisher[] {
  return publishers.filter((p) => p.queries > 0).sort((a, b) => b.queries - a.queries || a.name.localeCompare(b.name, 'fr'));
}

/** Ajoute la page suivante de domaines en écartant les doublons (le curseur peut chevaucher). */
export function mergeDomains(prev: TrackingDomain[], next: TrackingDomain[]): TrackingDomain[] {
  const seen = new Set(prev.map((d) => d.domain));
  return [...prev, ...next.filter((d) => !seen.has(d.domain))];
}

/** Règle effective d'un domaine : la modification locale en attente l'emporte sur celle du collecteur. */
export function effectiveOverride(d: TrackingDomain, local: ReadonlyMap<string, 'block' | 'allow' | 'default'>): 'block' | 'allow' | undefined {
  const l = local.get(d.domain);
  if (l === 'default') return undefined;
  return l ?? d.override;
}

/** Applications d'un domaine : les `max` premières, et le nombre des autres. */
export function splitApps(apps: { package: string; count: number }[] | undefined, max = 3): { shown: { package: string; count: number }[]; more: number } {
  const sorted = [...(apps ?? [])].sort((a, b) => b.count - a.count);
  return { shown: sorted.slice(0, max), more: Math.max(0, sorted.length - max) };
}

/** Applications triées par requêtes décroissantes, avec une recherche sur le nom ou le paquet. */
export function filterApps(apps: TrackingApp[], q: string): TrackingApp[] {
  const f = q.trim().toLowerCase();
  return apps
    .filter((a) => !f || a.package.toLowerCase().includes(f) || (a.label ?? '').toLowerCase().includes(f))
    .sort((a, b) => b.queries - a.queries || a.package.localeCompare(b.package));
}

// ------------------------------------------------------------------------------------------- erreur 409

export interface Conflict {
  message: string;
  /** ce que le blocage casserait, si le collecteur le détaille */
  impacts: string[];
}

const IMPACT_KEYS = ['impacts', 'impact', 'breaks', 'would_break', 'consequences', 'affects', 'details'];

/**
 * Lit la réponse `409` de `PUT /tracking/override` (domaine indispensable). Le contrat n'en fixe que l'esprit
 * (« expliquant ce que le blocage casserait ») : on affiche `message`, plus toute liste ou chaîne trouvée sous
 * une clé usuelle.
 */
export function parseConflict(e: Pick<ApiError, 'message' | 'body'>): Conflict {
  const impacts: string[] = [];
  const body = e.body ?? {};
  for (const k of IMPACT_KEYS) {
    const v = body[k];
    if (typeof v === 'string' && v.trim()) impacts.push(v.trim());
    else if (Array.isArray(v)) {
      for (const x of v) if (typeof x === 'string' && x.trim()) impacts.push(x.trim());
    }
  }
  return { message: e.message, impacts };
}

// ------------------------------------------------------------------------------------------- actions

export type TrackAction = 'block' | 'allow' | 'default';

/**
 * Actions proposées pour un domaine, d'après son statut sur la période et la règle manuelle en vigueur.
 * « Bloquer » n'a pas de sens pour un domaine déjà bloqué sans règle contraire, « Autoriser » pour un domaine
 * déjà autorisé ; « Remettre par défaut » n'existe que s'il y a une règle manuelle à retirer.
 */
export function availableActions(status: string | undefined, override: 'block' | 'allow' | undefined): TrackAction[] {
  const out: TrackAction[] = [];
  if (override !== 'block' && status !== 'blocked') out.push('block');
  if (override !== 'allow' && status !== 'allowed') out.push('allow');
  if (override) out.push('default');
  // Statut inconnu et aucune règle : on propose quand même les deux choix.
  if (out.length === 0) out.push('block', 'allow');
  return out;
}

export const ACTION_LABELS: Record<TrackAction, string> = { block: 'Bloquer', allow: 'Autoriser', default: 'Remettre par défaut' };
