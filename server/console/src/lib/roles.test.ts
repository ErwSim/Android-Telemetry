import { describe, expect, it } from 'vitest';
import type { WatchpostEvent } from '../api/types.ts';
import { involves, roleChanges, roleLabel, rolesHeldBy, roleWhy } from './roles.ts';

const ev = (id: string, ts: string, data: Record<string, unknown>, type = 'app.role'): WatchpostEvent => ({ id, ts, type, sev: 1, data });

describe('default roles', () => {
  it('translates known roles and lets others through', () => {
    expect(roleLabel('sms')).toBe('SMS app');
    expect(roleLabel('call_screening')).toBe('Call screening');
    expect(roleLabel('wallet')).toBe('wallet');
    expect(roleLabel('constructor')).toBe('constructor');
    expect(roleWhy('sms')).toContain('SMS');
    expect(roleWhy('wallet')).toBeUndefined();
  });

  it('extracts the changes, newest first, ignoring the rest', () => {
    const l = roleChanges([
      ev('1', '2026-11-10T10:00:00Z', { role: 'browser', old: 'a', new: 'b' }),
      ev('2', '2026-11-14T10:00:00Z', { role: 'sms', new: 'c' }),
      ev('3', '2026-11-12T10:00:00Z', { old: 'x' }),
      ev('4', '2026-11-13T10:00:00Z', { role: 'home' }, 'app.risk'),
    ]);
    expect(l.map((c) => c.id)).toEqual(['2', '1']);
    expect(l[0]).toEqual({ id: '2', ts: '2026-11-14T10:00:00Z', role: 'sms', new: 'c' });
    expect(involves(l[1] as never, 'a')).toBe(true);
    expect(involves(l[1] as never, 'z')).toBe(false);
  });

  it('finds the roles held by a package', () => {
    expect(rolesHeldBy({ sms: 'p', launcher: 'p', browser: 'q', assistant: 3 }, 'p')).toEqual(['sms', 'home']);
    expect(rolesHeldBy(undefined, 'p')).toEqual([]);
  });
});
