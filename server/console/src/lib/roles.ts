// Rôles par défaut d'Android (contrat §11.2, `app.role`) : SMS, composeur, navigateur, assistant, écran d'accueil,
// filtrage d'appels… Un changement de rôle est un signal fort : un logiciel malveillant cherche souvent à devenir
// l'application SMS ou le filtre d'appels.
import type { VigieEvent } from '../api/types.ts';
import { str } from './data.ts';

const ROLE_LABELS: Record<string, string> = {
  sms: 'Application SMS',
  dialer: 'Application Téléphone',
  browser: 'Navigateur',
  assistant: 'Assistant',
  home: "Écran d'accueil",
  call_screening: "Filtrage d'appels",
  launcher: "Écran d'accueil",
};

const ROLE_WHY: Record<string, string> = {
  sms: "L'application SMS par défaut reçoit et envoie tous vos SMS : c'est le rôle que visent les logiciels de fraude au SMS.",
  dialer: "L'application Téléphone par défaut gère les appels entrants et sortants.",
  browser: 'Le navigateur par défaut ouvre tous les liens : un faux navigateur peut vous envoyer sur des sites piégés.',
  assistant: "L'assistant par défaut peut lire l'écran et écouter le micro sur commande.",
  home: "L'écran d'accueil voit toutes les applications que vous lancez.",
  call_screening: "L'application de filtrage d'appels voit tous les numéros qui vous appellent.",
};

export function roleLabel(role: string): string {
  return Object.prototype.hasOwnProperty.call(ROLE_LABELS, role) ? (ROLE_LABELS[role] as string) : role;
}

export function roleWhy(role: string): string | undefined {
  return Object.prototype.hasOwnProperty.call(ROLE_WHY, role) ? ROLE_WHY[role] : undefined;
}

export interface RoleChange {
  id: string;
  ts: string;
  role: string;
  old?: string;
  new?: string;
}

/** Changements de rôle (`app.role`) lus dans des événements, du plus récent au plus ancien ; les autres types sont ignorés. */
export function roleChanges(events: readonly VigieEvent[]): RoleChange[] {
  const out: RoleChange[] = [];
  for (const e of events) {
    if (e.type !== 'app.role') continue;
    const role = str(e.data, 'role');
    if (!role) continue;
    const c: RoleChange = { id: e.id, ts: e.ts, role };
    const o = str(e.data, 'old');
    const n = str(e.data, 'new');
    if (o) c.old = o;
    if (n) c.new = n;
    out.push(c);
  }
  return out.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
}

/** Premier changement de rôle d'une application ? Vrai si elle l'a gagné (`new`) ou perdu (`old`). */
export function involves(c: RoleChange, pkg: string): boolean {
  return c.new === pkg || c.old === pkg;
}

/** Rôles actuellement tenus par un paquet d'après `app.special_access.default_apps` (clé de rôle → paquet). */
export function rolesHeldBy(defaults: Record<string, unknown> | undefined, pkg: string): string[] {
  if (!defaults) return [];
  return Object.entries(defaults)
    .filter(([, v]) => v === pkg)
    .map(([k]) => (k === 'launcher' ? 'home' : k));
}
