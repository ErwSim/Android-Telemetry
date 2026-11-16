import { describe, expect, it } from 'vitest';
import type { WatchpostEvent } from '../api/types.ts';
import { describeEvent } from './events.ts';
import { summarizeNotifications } from './notifications.ts';

const ev = (data: Record<string, unknown>, type = 'app.notification'): WatchpostEvent => ({ id: 'x', ts: '2026-11-16T10:00:00.000Z', type, sev: 0, data });

describe('app.notification in the event log', () => {
  it('without content: application, event, category', () => {
    expect(describeEvent(ev({ package: 'com.whatsapp', event: 'posted', category: 'msg' }))).toBe('com.whatsapp posted · msg');
    expect(describeEvent(ev({ package: 'com.whatsapp', event: 'removed' }))).toBe('com.whatsapp removed');
  });
  it('with title and text', () => {
    expect(describeEvent(ev({ package: 'com.whatsapp', event: 'posted', title: 'Alice', text: 'See you at 6 pm?' }))).toBe(
      'com.whatsapp posted · "Alice — See you at 6 pm?"',
    );
    expect(describeEvent(ev({ package: 'p', event: 'posted', title: 'Title only' }))).toBe('p posted · "Title only"');
  });
  it('mentions hidden content', () => {
    const s = describeEvent(ev({ package: 'com.bank', event: 'posted', title: 'Code', text: 'Your code is ●●●●●●', redacted: true }));
    expect(s).toContain('content hidden');
    const s2 = describeEvent(ev({ package: 'com.bank', event: 'posted', redacted: true }));
    expect(s2).toContain('content hidden');
  });
  it('never interprets the text and removes misleading characters', () => {
    const s = describeEvent(ev({ package: 'p', event: 'posted', title: '<b onmouseover=x>Winner‮</b>', text: 'a\nb' }));
    expect(s).toBe('p posted · "<b onmouseover=x>Winner</b> — a ⏎ b"');
  });
  it('oversized title: truncated to 512 characters', () => {
    const s = describeEvent(ev({ package: 'p', event: 'posted', title: 'x'.repeat(2000) }));
    expect(s.length).toBeLessThan(560);
  });
});

describe('command.result in the event log', () => {
  it('translates status and reason', () => {
    expect(describeEvent(ev({ command_id: 'c', type: 'lock', status: 'refused', detail: 'bad_signature', signed: true }, 'command.result'))).toBe(
      'Lock with message · refused (Invalid signature (wrong passphrase?)) · signed',
    );
    expect(describeEvent(ev({ command_id: 'c', type: 'ring', status: 'executed', signed: false }, 'command.result'))).toBe('Ring · executed');
  });
});

describe('notifications summary', () => {
  it('counts posted, removed, with content, hidden and per category', () => {
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
