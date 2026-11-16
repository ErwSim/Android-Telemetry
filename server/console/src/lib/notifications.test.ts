import { describe, expect, it } from 'vitest';
import type { VigieEvent } from '../api/types.ts';
import { describeEvent } from './events.ts';
import { summarizeNotifications } from './notifications.ts';

const ev = (data: Record<string, unknown>, type = 'app.notification'): VigieEvent => ({ id: 'x', ts: '2026-11-16T10:00:00.000Z', type, sev: 0, data });

describe('app.notification dans le journal', () => {
  it('sans contenu : application, événement, catégorie', () => {
    expect(describeEvent(ev({ package: 'com.whatsapp', event: 'posted', category: 'msg' }))).toBe('com.whatsapp publiée · msg');
    expect(describeEvent(ev({ package: 'com.whatsapp', event: 'removed' }))).toBe('com.whatsapp retirée');
  });
  it('avec titre et texte', () => {
    expect(describeEvent(ev({ package: 'com.whatsapp', event: 'posted', title: 'Alice', text: 'On se voit à 18 h ?' }))).toBe(
      'com.whatsapp publiée · « Alice — On se voit à 18 h ? »',
    );
    expect(describeEvent(ev({ package: 'p', event: 'posted', title: 'Seul titre' }))).toBe('p publiée · « Seul titre »');
  });
  it('mentionne le contenu masqué', () => {
    const s = describeEvent(ev({ package: 'com.bank', event: 'posted', title: 'Code', text: 'Votre code est ●●●●●●', redacted: true }));
    expect(s).toContain('contenu masqué');
    const s2 = describeEvent(ev({ package: 'com.bank', event: 'posted', redacted: true }));
    expect(s2).toContain('contenu masqué');
  });
  it('n’interprète jamais le texte et retire les caractères trompeurs', () => {
    const s = describeEvent(ev({ package: 'p', event: 'posted', title: '<b onmouseover=x>Gagnant‮</b>', text: 'a\nb' }));
    expect(s).toBe('p publiée · « <b onmouseover=x>Gagnant</b> — a ⏎ b »');
  });
  it('titre démesuré : tronqué à 512 caractères', () => {
    const s = describeEvent(ev({ package: 'p', event: 'posted', title: 'x'.repeat(2000) }));
    expect(s.length).toBeLessThan(560);
  });
});

describe('command.result dans le journal', () => {
  it('traduit statut et motif', () => {
    expect(describeEvent(ev({ command_id: 'c', type: 'lock', status: 'refused', detail: 'bad_signature', signed: true }, 'command.result'))).toBe(
      'Verrouiller avec message · refusée (Signature invalide (code incorrect ?)) · signée',
    );
    expect(describeEvent(ev({ command_id: 'c', type: 'ring', status: 'executed', signed: false }, 'command.result'))).toBe('Sonner · exécutée');
  });
});

describe('résumé des notifications', () => {
  it('compte posées, retirées, avec contenu, masquées et par catégorie', () => {
    const s = summarizeNotifications([
      ev({ package: 'a', event: 'posted', category: 'msg', title: 't' }),
      ev({ package: 'a', event: 'posted', category: 'msg', redacted: true, text: 'x' }),
      ev({ package: 'b', event: 'removed', category: 'email' }),
      ev({ package: 'b', event: 'posted', ongoing: true }),
      ev({}, 'net.dns'),
    ]);
    expect(s).toMatchObject({ total: 4, posted: 3, removed: 1, withContent: 2, redacted: 1, ongoing: 1 });
    expect(s.byCategory).toEqual([
      { key: 'msg', count: 2 },
      { key: 'email', count: 1 },
    ]);
  });
});
