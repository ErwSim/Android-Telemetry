import { describe, expect, it } from 'vitest';
import type { VigieEvent } from '../api/types.ts';
import { describeEvent, domainOf, installerLabel, isSideloaded, permissionLabel, sevLabel } from './events.ts';
import { matchesFilters, parsePrefixes, togglePrefix } from './eventFilter.ts';
import { classifyHost, classifyPackage } from './vendors.ts';
import { tokenizeJson } from '../components/JsonView.tsx';
import { circleRing, haversine, pathLength } from './geo.ts';
import { mergeConfig, isValidTileUrl } from './config.ts';
import { chooseBucket, resolvePeriod } from './period.ts';

const ev = (type: string, data: Record<string, unknown>, sev = 0): VigieEvent => ({ id: 'x', ts: '2026-11-15T10:00:00Z', type, sev, data });

describe('describeEvent', () => {
  it('résume les types du catalogue', () => {
    expect(describeEvent(ev('net.dns', { package: 'com.a', hostname: 'h.fr' }))).toBe('com.a → h.fr');
    expect(describeEvent(ev('app.permission_changed', { package: 'p', permission: 'android.permission.CAMERA', granted: true }))).toBe('p · CAMERA accordée');
  });
  it('ne plante jamais sur data partiel, vide ou inattendu', () => {
    const types = ['net.dns', 'location.fix', 'security.log', 'app.inventory', 'net.usage', 'device.battery', 'security.policy', 'agent.heartbeat', 'sensor.camera'];
    for (const t of types) {
      expect(() => describeEvent(ev(t, {}))).not.toThrow();
      expect(() => describeEvent(ev(t, { apps: 'oops', fields: 3, lat: 'x', transports: {} }))).not.toThrow();
    }
    expect(() => describeEvent({ id: 'x', ts: '', type: 'a.b', sev: 0 } as unknown as VigieEvent)).not.toThrow();
  });
  it('replie un type inconnu sur ses champs scalaires', () => {
    expect(describeEvent(ev('futur.chose', { a: 1, b: 'x', c: { d: 1 } }))).toBe('a=1 · b=x');
  });
});

describe('divers', () => {
  it('libellés', () => {
    expect(domainOf('net.dns')).toBe('net');
    expect(sevLabel(3)).toBe('Critique');
    expect(sevLabel(9)).toBe('Critique');
    expect(permissionLabel('android.permission.RECORD_AUDIO')).toBe('Microphone');
    expect(installerLabel('com.android.vending')).toBe('Play Store');
    expect(installerLabel(undefined)).toBe('Inconnu / préinstallée');
  });
  it('installation hors store', () => {
    expect(isSideloaded({ system: false, installer: 'com.android.shell' })).toBe(true);
    expect(isSideloaded({ system: false, installer: 'com.android.vending' })).toBe(false);
    expect(isSideloaded({ system: true })).toBe(false);
  });
  it('Google / Samsung', () => {
    expect(classifyHost('www.googleapis.com')).toBe('google');
    expect(classifyHost('eu-api.samsungcloud.com.')).toBe('samsung');
    expect(classifyHost('notsamsung.com')).toBe('other');
    expect(classifyPackage('com.google.android.gms')).toBe('google');
    expect(classifyPackage('com.android.vending')).toBe('google');
    expect(classifyPackage('com.sec.android.app.camera')).toBe('samsung');
    expect(classifyPackage('com.whatsapp')).toBe('other');
  });
});

describe('filtres', () => {
  it('préfixes de type', () => {
    expect(parsePrefixes(' net. , security.log,')).toEqual(['net.', 'security.log']);
    expect(togglePrefix('net.', 'app.')).toBe('net.,app.');
    expect(togglePrefix('net.,app.', 'net.')).toBe('app.');
  });
  it('filtre côté client des événements en direct', () => {
    const e = ev('net.dns', { hostname: 'Exemple.FR' }, 1);
    expect(matchesFilters(e, { type: 'net.', sevMin: 0, q: '' })).toBe(true);
    expect(matchesFilters(e, { type: 'app.', sevMin: 0, q: '' })).toBe(false);
    expect(matchesFilters(e, { type: '', sevMin: 2, q: '' })).toBe(false);
    expect(matchesFilters(e, { type: '', sevMin: 0, q: 'exemple' })).toBe(true);
    expect(matchesFilters(e, { type: '', sevMin: 0, q: 'autre' })).toBe(false);
  });
});

describe('JSON', () => {
  it('découpe en jetons sans perdre de texte', () => {
    const text = JSON.stringify({ a: [1, 'x', null, true], b: { c: -2.5e3 } }, null, 2);
    const toks = tokenizeJson(text);
    expect(toks.map((t) => t.s).join('')).toBe(text);
    expect(toks.find((t) => t.t === 'key')?.s).toBe('"a"');
  });
});

describe('géographie', () => {
  it('distance de Paris à Versailles', () => {
    const d = haversine({ lat: 48.8566, lon: 2.3522 }, { lat: 48.8049, lon: 2.1204 });
    expect(d).toBeGreaterThan(17_000);
    expect(d).toBeLessThan(19_000);
  });
  it('longueur de trajet avec saut ignoré', () => {
    const p = [{ lat: 0, lon: 0 }, { lat: 0, lon: 0.001 }, { lat: 10, lon: 10 }, { lat: 10, lon: 10.001 }];
    const l = pathLength(p, (i) => i === 2);
    expect(l).toBeGreaterThan(200);
    expect(l).toBeLessThan(230);
  });
  it('cercle fermé de rayon voulu', () => {
    const r = circleRing({ lat: 48.86, lon: 2.35 }, 100, 16);
    expect(r).toHaveLength(17);
    expect(r[0]).toEqual(r[16]);
    expect(haversine({ lat: 48.86, lon: 2.35 }, { lat: (r[4] as [number, number])[1], lon: (r[4] as [number, number])[0] })).toBeCloseTo(100, 0);
  });
});

describe('configuration et périodes', () => {
  it("valide l'URL de tuiles et retombe sur la valeur par défaut", () => {
    expect(isValidTileUrl('https://t.example/{z}/{x}/{y}.png')).toBe(true);
    expect(isValidTileUrl('http://t.example/{z}/{x}/{y}.png')).toBe(false);
    expect(isValidTileUrl('https://t.example/tile.png')).toBe(false);
    expect(mergeConfig({ tileUrl: 'javascript:alert(1)' }).tileUrl).toContain('openstreetmap');
    expect(mergeConfig({ tileUrl: 'https://tiles.exemple.fr/{z}/{x}/{y}.png' }).tileUrl).toBe('https://tiles.exemple.fr/{z}/{x}/{y}.png');
    expect(mergeConfig('n importe quoi').tileUrl).toContain('openstreetmap');
  });
  it('périodes relatives et personnalisée invalide', () => {
    const now = new Date(2026, 10, 15, 14, 30);
    expect(resolvePeriod('24h', now).from.getTime()).toBe(now.getTime() - 86_400_000);
    expect(resolvePeriod('today', now).from).toEqual(new Date(2026, 10, 15));
    const bad = resolvePeriod('custom', now, { from: now, to: new Date(now.getTime() - 1) });
    expect(bad.key).toBe('24h');
    expect(chooseBucket(new Date(0), new Date(3 * 3_600_000))).toBe('minute');
    expect(chooseBucket(new Date(0), new Date(3 * 86_400_000))).toBe('hour');
    expect(chooseBucket(new Date(0), new Date(60 * 86_400_000))).toBe('day');
  });
});

describe('événements de la v1.2 et du pistage lisibles dans le journal', () => {
  it('tracking.level_changed : ancien et nouveau niveau, qui, combien de listes', () => {
    expect(describeEvent(ev('tracking.level_changed', { old: 'equilibre', new: 'strict', changes: ['a', 'b'], user: 'admin' }, 1))).toBe(
      'Niveau de blocage : Équilibré → Strict · 2 listes modifiées · par admin',
    );
    expect(describeEvent(ev('tracking.level_changed', { new: 'permissif', user: 'admin' }, 2))).toBe('Niveau de blocage : inconnu → Permissif · par admin');
    expect(describeEvent(ev('tracking.level_changed', { old: 'x', new: 'y', changes: 1 }))).toBe('Niveau de blocage : x → y · 1 liste modifiée');
  });
  it('tracking.override : action, domaine, forcé, règle précédente', () => {
    expect(describeEvent(ev('tracking.override', { domain: 'ads.exemple.top', action: 'block', forced: false, user: 'admin' }))).toBe("Blocage de « ads.exemple.top » · par admin");
    expect(describeEvent(ev('tracking.override', { domain: 'mtalk.google.com', action: 'block', forced: true, previous: 'allow', user: 'admin' }, 2))).toBe(
      'Blocage de « mtalk.google.com » · forcé (domaine indispensable) · règle précédente : autorisation · par admin',
    );
    expect(describeEvent(ev('tracking.override', { domain: 'x.fr', action: 'default' }))).toBe('Retour au réglage par défaut de « x.fr »');
  });
  it('app.risk, app.role, app.ops', () => {
    expect(describeEvent(ev('app.risk', { package: 'p', label: 'Appli', level: 'high', score: 91, reasons: ['sms_send', 'combo_sms_fraud'] }))).toBe('Appli · p · risque élevé (91/100) · 2 raisons');
    expect(describeEvent(ev('app.role', { role: 'sms', old: 'a', new: 'b' }))).toBe('Application SMS : a → b');
    expect(describeEvent(ev('app.role', { role: 'home', new: 'b' }))).toBe("Écran d'accueil : aucune → b");
    expect(describeEvent(ev('app.ops', { apps: [{ package: 'a', op: 'send_sms', count: 3 }, { package: 'b', op: 'camera', count: 1 }] }))).toContain('2 usages');
  });
  it('ne plante pas sur data partiel ou hostile', () => {
    for (const t of ['tracking.level_changed', 'tracking.override', 'app.risk', 'app.role', 'app.ops', 'detect.fanout', 'detect.inconnue']) {
      expect(() => describeEvent(ev(t, {}))).not.toThrow();
      expect(() => describeEvent(ev(t, { apps: 7, reasons: 'x', evidence: 3, changes: {}, domain: 4, user: ['a'] }))).not.toThrow();
    }
    expect(describeEvent(ev('tracking.override', { domain: '<img src=x onerror=alert(1)>‮', action: 'block' }))).not.toContain('‮');
  });
});

describe('journal : sourdines et nouveaux types de détection', () => {
  it('detect.muted / detect.unmuted et les types du §11.4 sont lisibles', () => {
    expect(describeEvent(ev('detect.muted', { type: 'detect.dns_bypass', package: 'com.android.chrome', reason: 'voulu', user: 'admin' }))).toBe('Sourdine : Contournement du DNS du téléphone pour com.android.chrome · motif : voulu · par admin');
    expect(describeEvent(ev('detect.unmuted', { type: 'detect.dns_bypass', package: 'p' }))).toBe('Fin de sourdine : Contournement du DNS du téléphone pour p');
    expect(describeEvent(ev('detect.muted', {}))).toBe('Sourdine : détection pour ?');
    expect(describeEvent(ev('detect.sms_permission', { package: 'com.x', evidence: {} }))).toContain('peut envoyer des SMS');
    expect(describeEvent(ev('detect.default_app_changed', { package: 'com.x', evidence: { role: 'sms' } }))).toContain("application SMS par défaut");
  });
});
