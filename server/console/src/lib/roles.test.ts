import { describe, expect, it } from 'vitest';
import type { VigieEvent } from '../api/types.ts';
import { involves, roleChanges, roleLabel, rolesHeldBy, roleWhy } from './roles.ts';

const ev = (id: string, ts: string, data: Record<string, unknown>, type = 'app.role'): VigieEvent => ({ id, ts, type, sev: 1, data });

describe('rôles par défaut', () => {
  it('traduit les rôles connus et laisse passer les autres', () => {
    expect(roleLabel('sms')).toBe('Application SMS');
    expect(roleLabel('call_screening')).toBe("Filtrage d'appels");
    expect(roleLabel('wallet')).toBe('wallet');
    expect(roleLabel('constructor')).toBe('constructor');
    expect(roleWhy('sms')).toContain('SMS');
    expect(roleWhy('wallet')).toBeUndefined();
  });

  it('extrait les changements, du plus récent au plus ancien, en ignorant le reste', () => {
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

  it('retrouve les rôles tenus par un paquet', () => {
    expect(rolesHeldBy({ sms: 'p', launcher: 'p', browser: 'q', assistant: 3 }, 'p')).toEqual(['sms', 'home']);
    expect(rolesHeldBy(undefined, 'p')).toEqual([]);
  });
});
