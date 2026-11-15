import { describe, expect, it } from 'vitest';
import { attentionPoints, evaluatePosture, overallStatus } from './posture.ts';

describe('evaluatePosture', () => {
  it('ne plante pas sur une posture vide ou partielle', () => {
    expect(evaluatePosture(undefined)).toEqual([]);
    expect(evaluatePosture({})).toEqual([]);
    expect(evaluatePosture({ encrypted: true })).toHaveLength(1);
  });
  it("relève les points d'attention", () => {
    const f = evaluatePosture({
      patch_age_days: 130,
      encrypted: true,
      adb_wifi_enabled: true,
      dev_options: true,
      private_dns_mode: 'hostname',
      private_dns_host: 'dns.exemple.fr',
      user_ca_certs: ['abc'],
      device_owner: false,
    });
    const ids = attentionPoints(f).map((x) => `${x.id}:${x.status}`);
    expect(ids).toEqual(['patch:bad', 'adbwifi:bad', 'ca:bad', 'do:warn', 'dev:warn']);
    expect(overallStatus(f)).toBe('bad');
  });
  it('une posture saine est OK', () => {
    const f = evaluatePosture({ patch_age_days: 10, encrypted: true, lock_secure: true, verified_boot_state: 'green', adb_enabled: false, user_ca_certs: [], device_owner: true });
    expect(overallStatus(f)).toBe('ok');
    expect(attentionPoints(f)).toEqual([]);
  });
});
