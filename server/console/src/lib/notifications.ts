// Agrégation des événements `app.notification` (contrat §10), pour la section Notifications des applications.
import type { VigieEvent } from '../api/types.ts';
import { bool, str } from './data.ts';

export interface NotificationSummary {
  total: number;
  posted: number;
  removed: number;
  /** événements portant un titre ou un texte (option « Contenu des notifications » active sur le téléphone) */
  withContent: number;
  redacted: number;
  ongoing: number;
  byCategory: { key: string; count: number }[];
}

export function summarizeNotifications(events: VigieEvent[]): NotificationSummary {
  const s: NotificationSummary = { total: 0, posted: 0, removed: 0, withContent: 0, redacted: 0, ongoing: 0, byCategory: [] };
  const cats = new Map<string, number>();
  for (const e of events) {
    if (e.type !== 'app.notification') continue;
    s.total++;
    const ev = str(e.data, 'event');
    if (ev === 'posted') s.posted++;
    else if (ev === 'removed') s.removed++;
    if (str(e.data, 'title') || str(e.data, 'text')) s.withContent++;
    if (bool(e.data, 'redacted')) s.redacted++;
    if (bool(e.data, 'ongoing')) s.ongoing++;
    const c = str(e.data, 'category');
    if (c) cats.set(c, (cats.get(c) ?? 0) + 1);
  }
  s.byCategory = [...cats.entries()].map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
  return s;
}
