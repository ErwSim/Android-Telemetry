// Profil de risque des applications (contrat §11.2, `app.risk`) : traduction des codes de raison, niveaux,
// combinaisons, lecture tolérante de la réponse de `GET /apps/risk`. Fonctions pures.
import type { AppRisk, AppRiskResponse, RiskLevel } from '../api/types.ts';
import { isRecord } from './data.ts';

export type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'info';

export interface ReasonInfo {
  code: string;
  label: string;
  /** ce que cela veut dire, en clair */
  explain: string;
  /** pourquoi cela peut être normal */
  innocent?: string;
  tone: Tone;
  /** `combo_*` : combinaison de capacités typique d'un type de logiciel malveillant */
  combo: boolean;
  /** vrai si le code appartient à la liste fermée du contrat §11.2 */
  known: boolean;
}

type Entry = Omit<ReasonInfo, 'code' | 'known' | 'combo'> & { combo?: boolean };

/** Liste fermée du contrat §11.2, dans l'ordre du contrat. */
const REASONS: Record<string, Entry> = {
  sideloaded: {
    label: 'Installée hors boutique',
    explain: "L'application n'a pas été installée depuis le Play Store ni le Galaxy Store : fichier APK ouvert à la main, depuis un navigateur ou par ADB. Les boutiques font des contrôles que cette voie contourne.",
    innocent: "Normal pour F-Droid, un outil technique ou une application d'entreprise que vous avez installés vous-même.",
    tone: 'warn',
  },
  unknown_installer: {
    label: 'Installateur inconnu',
    explain: "Le programme qui a installé l'application n'est pas connu de Vigie : impossible de savoir d'où elle vient.",
    innocent: 'Une application préinstallée ou restaurée depuis une sauvegarde peut n\'avoir aucun installateur.',
    tone: 'warn',
  },
  no_launcher_icon: {
    label: 'Aucune icône dans la liste des applications',
    explain: "L'application n'apparaît pas dans le lanceur : on ne la voit pas, et elle est plus difficile à désinstaller. Un logiciel espion ou malveillant se cache souvent ainsi.",
    innocent: 'Normal pour un service système, un composant ou une extension (clavier, thème, module).',
    tone: 'warn',
  },
  sms_send: {
    label: 'Peut envoyer des SMS',
    explain: "Permission d'envoi de SMS : l'application peut envoyer des messages à votre insu, vers des numéros surtaxés ou pour du hameçonnage depuis votre numéro, sans rien afficher.",
    innocent: "Normal pour votre application de messagerie, ou pour une application qui envoie un code de vérification que vous avez demandé.",
    tone: 'warn',
  },
  sms_read: {
    label: 'Peut lire les SMS',
    explain: "Permission de lecture ou de réception des SMS : l'application peut lire vos messages, y compris les codes à usage unique envoyés par votre banque.",
    innocent: 'Normal pour une application de messagerie ou pour une application qui lit elle-même le code de vérification (authentification).',
    tone: 'warn',
  },
  calls: {
    label: 'Peut passer ou gérer des appels',
    explain: "Permissions d'appel : l'application peut composer des numéros (surtaxés par exemple), répondre aux appels ou lire le journal des appels.",
    innocent: "Normal pour un composeur, une messagerie qui propose les appels ou un filtre d'appels que vous avez choisi.",
    tone: 'info',
  },
  accessibility_service: {
    label: "Service d'accessibilité",
    explain: "L'application peut lire tout ce qui s'affiche à l'écran et agir à votre place (toucher, saisir du texte). C'est le moyen favori des chevaux de Troie bancaires.",
    innocent: "Normal pour un lecteur d'écran, un gestionnaire de mots de passe ou un outil d'aide que vous avez activé.",
    tone: 'warn',
  },
  notification_listener: {
    label: 'Lit toutes les notifications',
    explain: 'Accès aux notifications : l\'application voit vos messages, vos codes à usage unique et peut en supprimer avant que vous les voyiez.',
    innocent: 'Normal pour une montre connectée, un assistant de messagerie ou une application de transfert de notifications que vous avez installée.',
    tone: 'warn',
  },
  device_admin: {
    label: "Administrateur de l'appareil",
    explain: "L'application a des droits d'administration : verrouiller l'écran, imposer des règles, parfois s'opposer à sa propre désinstallation.",
    innocent: 'Normal pour une application de gestion professionnelle ou de localisation du téléphone.',
    tone: 'warn',
  },
  overlay: {
    label: "Affichage par-dessus les autres applications",
    explain: "L'application peut dessiner par-dessus d'autres applications : par exemple une fausse page de connexion devant celle de votre banque.",
    innocent: "Normal pour une bulle de discussion, un enregistreur d'écran ou un filtre de lumière bleue.",
    tone: 'warn',
  },
  install_packages: {
    label: "Peut installer d'autres applications",
    explain: "L'application peut télécharger puis installer d'autres APK : c'est la porte d'entrée d'autres logiciels malveillants.",
    innocent: 'Normal pour un magasin d\'applications alternatif (F-Droid), un navigateur ou un gestionnaire de fichiers.',
    tone: 'warn',
  },
  vpn_service: {
    label: 'Service VPN',
    explain: 'Le trafic réseau du téléphone peut passer par cette application, qui voit ou redirige tout ce qui sort.',
    innocent: 'Normal pour un VPN ou un bloqueur de publicité que vous avez installé et activé.',
    tone: 'info',
  },
  boot_receiver: {
    label: 'Démarre avec le téléphone',
    explain: "L'application se lance toute seule à l'allumage, sans que vous l'ouvriez : nécessaire à un service permanent, mais aussi à un logiciel espion ou à un envoi en arrière-plan.",
    innocent: 'Très courant : messageries, synchronisation, applications de sécurité.',
    tone: 'info',
  },
  background_location: {
    label: "Position en arrière-plan",
    explain: "L'application peut connaître votre position même quand elle n'est pas à l'écran : suivi permanent de vos déplacements.",
    innocent: 'Normal pour la navigation, le partage de position choisi avec des proches ou une application de course.',
    tone: 'info',
  },
  mic_camera_background: {
    label: 'Micro ou caméra en arrière-plan',
    explain: "L'application peut utiliser le micro ou la caméra quand elle n'est pas à l'écran : écoute ou prise de vue à votre insu.",
    innocent: "Normal pour un appel en cours, un enregistreur vocal ou un assistant vocal.",
    tone: 'warn',
  },
  old_target_sdk: {
    label: 'Conçue pour une ancienne version d\'Android',
    explain: "L'application vise une version d'Android ancienne : elle échappe à des protections introduites depuis (permissions accordées plus facilement, accès aux fichiers plus large).",
    innocent: 'Courant pour de vieilles applications simplement non mises à jour.',
    tone: 'info',
  },
  debuggable: {
    label: 'Application en mode débogage',
    explain: "L'application est marquée « débogable » : ce n'est pas une version publiée normale, et d'autres programmes peuvent lire ou modifier son exécution.",
    innocent: 'Normal pour une application de développement que vous construisez vous-même.',
    tone: 'warn',
  },
  combo_banking_trojan: {
    label: 'Profil de cheval de Troie bancaire',
    explain: "Accessibilité, superposition à l'écran et lecture des SMS ou des notifications réunies : c'est la combinaison classique des chevaux de Troie bancaires (fausses pages devant votre banque, lecture des codes, validation à votre place).",
    tone: 'bad',
    combo: true,
  },
  combo_sms_fraud: {
    label: 'Profil de fraude au SMS',
    explain: "Peut envoyer des SMS, démarre avec le téléphone et n'est pas votre application de messagerie : le profil des logiciels qui envoient des milliers de SMS de hameçonnage ou surtaxés, en arrière-plan, sans rien afficher.",
    tone: 'bad',
    combo: true,
  },
  combo_stalkerware: {
    label: 'Profil de logiciel espion',
    explain: "Aucune icône visible, accès à la position ou au micro, et démarrage avec le téléphone : le profil d'un logiciel espion installé pour vous surveiller.",
    tone: 'bad',
    combo: true,
  },
};

export const REASON_CODES: readonly string[] = Object.keys(REASONS);
const GRANTED_SUFFIX = ':granted';

/** Raisons qui sont des capacités pouvant être demandées sans être accordées ; les autres décrivent un état (installateur, icône…). */
export const CAPABILITY_CODES: ReadonlySet<string> = new Set([
  'sms_send',
  'sms_read',
  'calls',
  'accessibility_service',
  'notification_listener',
  'device_admin',
  'overlay',
  'install_packages',
  'vpn_service',
  'background_location',
  'mic_camera_background',
]);

/**
 * État d'une raison d'après `granted` : `granted` (accordée), `declared` (demandée, pas accordée : refusée par une garde, ou
 * pas encore accordée), ou `unknown` (l'agent ne distingue pas : profil sans liste `granted`).
 */
export function grantState(r: Pick<AppRisk, 'granted'>, code: string): 'granted' | 'declared' | 'unknown' {
  if (!r.granted || !CAPABILITY_CODES.has(code)) return 'unknown';
  return r.granted.includes(code) ? 'granted' : 'declared';
}

export const COMBO_CODES: readonly string[] = REASON_CODES.filter((c) => REASONS[c]?.combo);

/** Traduit un code de raison. Un code inconnu est affiché tel quel, sans explication inventée. */
export function reasonInfo(code: string): ReasonInfo {
  const e = Object.prototype.hasOwnProperty.call(REASONS, code) ? REASONS[code] : undefined;
  if (!e) {
    return {
      code,
      label: code,
      explain: "Ce code n'est pas connu de cette version de la console : il est affiché tel que le téléphone l'a envoyé.",
      tone: 'neutral',
      combo: false,
      known: false,
    };
  }
  return { code, label: e.label, explain: e.explain, ...(e.innocent ? { innocent: e.innocent } : {}), tone: e.tone, combo: e.combo === true, known: true };
}

/** Combinaisons (`combo_*`) présentes dans une liste de raisons, dans l'ordre du contrat. */
export function combosOf(reasons: readonly string[]): string[] {
  return COMBO_CODES.filter((c) => reasons.includes(c));
}

/** Raisons ordonnées : combinaisons d'abord, puis gravité décroissante, puis ordre du contrat ; inconnues en dernier. */
export function orderReasons(reasons: readonly string[]): ReasonInfo[] {
  const rank = (r: ReasonInfo): number => (r.combo ? 0 : r.tone === 'warn' ? 1 : r.tone === 'info' ? 2 : 3);
  const uniq = [...new Set(reasons)];
  return uniq
    .map((c, i) => ({ r: reasonInfo(c), i }))
    .sort((a, b) => rank(a.r) - rank(b.r) || a.i - b.i)
    .map((x) => x.r);
}

// ------------------------------------------------------------------------------------------- niveaux

export interface LevelInfo {
  key: RiskLevel;
  label: string;
  tone: Tone;
}

const LEVELS: Record<RiskLevel, LevelInfo> = {
  low: { key: 'low', label: 'Faible', tone: 'ok' },
  medium: { key: 'medium', label: 'Moyen', tone: 'warn' },
  high: { key: 'high', label: 'Élevé', tone: 'bad' },
};

/** Niveau annoncé ; si la valeur est inconnue ou absente, repli sur le score (< 30 faible, < 70 moyen : contrat §11.2). */
export function levelInfo(level: string | undefined, score?: number): LevelInfo {
  if (level === 'low' || level === 'medium' || level === 'high') return LEVELS[level];
  const s = score ?? 0;
  return s >= 70 ? LEVELS.high : s >= 30 ? LEVELS.medium : LEVELS.low;
}

export const LEVEL_RANK: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2 };

// ------------------------------------------------------------------------------------- lecture API

function clampScore(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) ? Math.max(0, Math.min(100, Math.round(v))) : 0;
}

/** Normalise un élément de `/apps/risk` (champs à plat ou sous `data`) ; undefined si le paquet manque. */
export function normalizeRisk(raw: unknown): AppRisk | undefined {
  if (!isRecord(raw)) return undefined;
  const d = isRecord(raw['data']) ? { ...raw['data'], ...(typeof raw['ts'] === 'string' ? { ts: raw['ts'] } : {}) } : raw;
  const pkg = d['package'];
  if (typeof pkg !== 'string' || pkg === '') return undefined;
  const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '') : []);
  // §11.4 : `reasons` = capacités déclarées ; `granted` = celles effectivement accordées. Un suffixe « :granted » (sur une
  // raison ou dans la liste parallèle) est retiré : il ne sert qu'à distinguer l'intention de l'état.
  const base = (c: string): string => (c.endsWith(GRANTED_SUFFIX) ? c.slice(0, -GRANTED_SUFFIX.length) : c);
  const rawReasons = strs(d['reasons']);
  const reasons = [...new Set(rawReasons.map(base))];
  const hasGranted = Array.isArray(d['granted']) || rawReasons.some((c) => c.endsWith(GRANTED_SUFFIX));
  const granted = [...new Set([...strs(d['granted']).map(base), ...rawReasons.filter((c) => c.endsWith(GRANTED_SUFFIX)).map(base)])];
  const out: AppRisk = {
    package: pkg,
    score: clampScore(d['score']),
    level: typeof d['level'] === 'string' ? d['level'] : '',
    reasons,
  };
  if (hasGranted) out.granted = granted;
  if (typeof d['label'] === 'string' && d['label'] !== '') out.label = d['label'];
  if (typeof d['version_code'] === 'number') out.version_code = d['version_code'];
  if (typeof d['installer'] === 'string') out.installer = d['installer'];
  if (typeof d['from_store'] === 'boolean') out.from_store = d['from_store'];
  if (typeof d['ts'] === 'string') out.ts = d['ts'];
  return out;
}

/** Lit la réponse de `GET /apps/risk` (`{ apps: [...] }`, ou tableau nu), triée par score décroissant. */
export function parseRiskResponse(raw: unknown): AppRiskResponse {
  const arr = Array.isArray(raw) ? raw : isRecord(raw) ? (raw['apps'] ?? raw['risks'] ?? raw['items'] ?? []) : [];
  const apps = (Array.isArray(arr) ? arr : []).map(normalizeRisk).filter((x): x is AppRisk => !!x);
  const out: AppRiskResponse = { apps: sortByScore(apps) };
  if (isRecord(raw) && typeof raw['ts'] === 'string') out.ts = raw['ts'];
  return out;
}

/** Score décroissant ; à score égal, plus de raisons d'abord, puis nom. */
export function sortByScore(list: readonly AppRisk[]): AppRisk[] {
  const name = (a: AppRisk) => (a.label ?? a.package).toLowerCase();
  return [...list].sort((a, b) => b.score - a.score || b.reasons.length - a.reasons.length || name(a).localeCompare(name(b), 'fr'));
}

export interface RiskCounts {
  high: number;
  medium: number;
  low: number;
  total: number;
  withCombo: number;
}

export function riskCounts(list: readonly AppRisk[]): RiskCounts {
  const c: RiskCounts = { high: 0, medium: 0, low: 0, total: list.length, withCombo: 0 };
  for (const a of list) {
    c[levelInfo(a.level, a.score).key]++;
    if (combosOf(a.reasons).length > 0) c.withCombo++;
  }
  return c;
}

/** Filtre : niveau minimal, combinaisons seulement, texte (nom ou paquet). */
export function filterRisk(
  list: readonly AppRisk[],
  f: { level: RiskLevel | 'all'; comboOnly: boolean; q: string },
): AppRisk[] {
  const q = f.q.trim().toLowerCase();
  const min = f.level === 'all' ? 0 : LEVEL_RANK[f.level];
  return list.filter(
    (a) =>
      LEVEL_RANK[levelInfo(a.level, a.score).key] >= min &&
      (!f.comboOnly || combosOf(a.reasons).length > 0) &&
      (!q || a.package.toLowerCase().includes(q) || (a.label ?? '').toLowerCase().includes(q)),
  );
}
