import { describe, expect, it } from 'vitest';
import { HEADLINE_OPS, backgroundShare, groupByApp, groupByOp, opInfo, parseOpsResponse } from './ops.ts';

describe('opérations sensibles', () => {
  it('traduit les dix opérations du contrat et laisse passer une inconnue', () => {
    expect(opInfo('send_sms').label).toBe('Envoi de SMS');
    expect(opInfo('record_audio').label).toBe('Micro');
    expect(opInfo('camera').label).toBe('Caméra');
    expect(opInfo('teleport').label).toBe('teleport');
    expect(opInfo('toString').group).toBe('other');
    expect(HEADLINE_OPS).toEqual(['send_sms', 'call_phone', 'read_contacts', 'record_audio', 'camera']);
  });

  it('lit les deux formes de réponse (lignes à plat, ou opérations imbriquées par application)', () => {
    const flat = parseOpsResponse({ ops: [{ package: 'a', op: 'send_sms', count: 5, background_count: 4, last_ts: '2026-11-16T10:00:00Z' }, { package: 'a', op: 'camera', count: 1 }] });
    const nested = parseOpsResponse({ apps: [{ package: 'a', label: 'A', ops: [{ op: 'send_sms', count: 5, background_count: 4 }, { op: 'camera', count: 1 }] }] });
    expect(flat.rows).toHaveLength(2);
    expect(nested.rows.map((r) => [r.package, r.op, r.count])).toEqual([['a', 'send_sms', 5], ['a', 'camera', 1]]);
    expect(nested.rows[0]?.label).toBe('A');
  });

  it('une réponse absente, vide ou mal formée donne zéro ligne, sans exception', () => {
    expect(parseOpsResponse(undefined).rows).toEqual([]);
    expect(parseOpsResponse(null).rows).toEqual([]);
    expect(parseOpsResponse({}).rows).toEqual([]);
    expect(parseOpsResponse({ ops: 'oops' }).rows).toEqual([]);
    expect(parseOpsResponse({ ops: [null, 3, { package: 'a' }, { op: 'camera', count: 1 }, { package: 'a', op: 'camera', count: -4 }] }).rows).toEqual([{ package: 'a', op: 'camera', count: 0 }]);
  });

  it('agrège par application (totaux, arrière-plan plafonné au total) et par opération', () => {
    const rows = parseOpsResponse({
      ops: [
        { package: 'a', op: 'send_sms', count: 100, background_count: 90 },
        { package: 'a', op: 'send_sms', count: 20, background_count: 50 },
        { package: 'b', op: 'send_sms', count: 3 },
        { package: 'b', op: 'record_audio', count: 7, background_count: 1 },
      ],
    }).rows;
    const apps = groupByApp(rows);
    expect(apps[0]).toMatchObject({ package: 'a', total: 120, background: 110 });
    expect(apps[0]?.ops).toHaveLength(1);
    expect(apps[1]?.ops.map((o) => o.op)).toEqual(['send_sms', 'record_audio']);
    const ops = groupByOp(rows);
    expect(ops.map((o) => o.op)).toEqual(['send_sms', 'record_audio']);
    expect(ops[0]).toMatchObject({ count: 123, background: 110 });
    expect(ops[0]?.apps.map((a) => a.package)).toEqual(['a', 'b']);
  });

  it('lit et additionne les usages refusés par le système (rejected_count du collecteur)', () => {
    const r = parseOpsResponse({ apps: [{ package: 'a', ops: [{ op: 'send_sms', count: 10, background_count: 10, rejected_count: 4 }, { op: 'read_contacts', count: 2, rejected_count: 0 }] }] });
    expect(r.rows[0]?.rejected_count).toBe(4);
    expect(r.rows[1]?.rejected_count).toBeUndefined();
    const a = groupByApp(r.rows)[0];
    expect(a?.rejected).toBe(4);
    expect(a?.ops.map((o) => o.rejected)).toEqual([4, 0]);
  });

  it('part en arrière-plan', () => {
    expect(backgroundShare(10, 5)).toBe(0.5);
    expect(backgroundShare(0, 5)).toBe(0);
    expect(backgroundShare(2, 9)).toBe(1);
  });
});
