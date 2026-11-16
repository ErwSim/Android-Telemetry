// Android default roles (contract §11.2, `app.role`): SMS, dialer, browser, assistant, home screen,
// call screening... A role change is a strong signal: malware often tries to become
// the SMS app or the call screening app.
import type { WatchpostEvent } from '../api/types.ts';
import { str } from './data.ts';

const ROLE_LABELS: Record<string, string> = {
  sms: 'SMS app',
  dialer: 'Phone app',
  browser: 'Browser',
  assistant: 'Assistant',
  home: 'Home screen',
  call_screening: 'Call screening',
  launcher: 'Home screen',
  keyboard: 'Keyboard',
};

const ROLE_WHY: Record<string, string> = {
  sms: 'The default SMS app receives and sends all your SMS messages: this is the role SMS fraud software aims for.',
  dialer: 'The default Phone app handles incoming and outgoing calls.',
  browser: 'The default browser opens all links: a fake browser can send you to booby-trapped sites.',
  assistant: 'The default assistant can read the screen and listen to the microphone on command.',
  home: 'The home screen sees all the applications you launch.',
  call_screening: 'The call screening app sees every number that calls you.',
  keyboard: 'The keyboard sees everything you type, passwords included.',
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

/** Role changes (`app.role`) read from events, newest first; other types are ignored. */
export function roleChanges(events: readonly WatchpostEvent[]): RoleChange[] {
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

/** Does a role change involve an application? True if it gained (`new`) or lost (`old`) the role. */
export function involves(c: RoleChange, pkg: string): boolean {
  return c.new === pkg || c.old === pkg;
}

/** Roles currently held by a package according to `app.special_access.default_apps` (role key → package). */
export function rolesHeldBy(defaults: Record<string, unknown> | undefined, pkg: string): string[] {
  if (!defaults) return [];
  return Object.entries(defaults)
    .filter(([, v]) => v === pkg)
    .map(([k]) => (k === 'launcher' ? 'home' : k));
}
