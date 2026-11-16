import { describe, expect, it } from 'vitest';
import type { WatchpostEvent } from '../api/types.ts';
import { describeEvent, domainOf, installerLabel, isSideloaded, permissionLabel, sevLabel } from './events.ts';
import { matchesFilters, parsePrefixes, togglePrefix } from './eventFilter.ts';
import { classifyHost, classifyPackage } from './vendors.ts';
import { tokenizeJson } from '../components/JsonView.tsx';
import { circleRing, haversine, pathLength } from './geo.ts';
import { mergeConfig, isValidTileUrl } from './config.ts';
import { chooseBucket, resolvePeriod } from './period.ts';

const ev = (type: string, data: Record<string, unknown>, sev = 0): WatchpostEvent => ({ id: 'x', ts: '2026-11-15T10:00:00Z', type, sev, data });

describe('describeEvent', () => {
  it('summarises the catalogue types', () => {
    expect(describeEvent(ev('net.dns', { package: 'com.a', hostname: 'h.example' }))).toBe('com.a → h.example');
    expect(describeEvent(ev('app.permission_changed', { package: 'p', permission: 'android.permission.CAMERA', granted: true }))).toBe('p · CAMERA granted');
  });
  it('never crashes on partial, empty or unexpected data', () => {
    const types = ['net.dns', 'location.fix', 'security.log', 'app.inventory', 'net.usage', 'device.battery', 'security.policy', 'agent.heartbeat', 'sensor.camera'];
    for (const t of types) {
      expect(() => describeEvent(ev(t, {}))).not.toThrow();
      expect(() => describeEvent(ev(t, { apps: 'oops', fields: 3, lat: 'x', transports: {} }))).not.toThrow();
    }
    expect(() => describeEvent({ id: 'x', ts: '', type: 'a.b', sev: 0 } as unknown as WatchpostEvent)).not.toThrow();
  });
  it('falls back to scalar fields for an unknown type', () => {
    expect(describeEvent(ev('future.thing', { a: 1, b: 'x', c: { d: 1 } }))).toBe('a=1 · b=x');
  });
});

describe('misc', () => {
  it('labels', () => {
    expect(domainOf('net.dns')).toBe('net');
    expect(sevLabel(3)).toBe('Critical');
    expect(sevLabel(9)).toBe('Critical');
    expect(permissionLabel('android.permission.RECORD_AUDIO')).toBe('Microphone');
    expect(installerLabel('com.android.vending')).toBe('Play Store');
    expect(installerLabel(undefined)).toBe('Unknown / preinstalled');
  });
  it('installation outside a store', () => {
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

describe('filters', () => {
  it('type prefixes', () => {
    expect(parsePrefixes(' net. , security.log,')).toEqual(['net.', 'security.log']);
    expect(togglePrefix('net.', 'app.')).toBe('net.,app.');
    expect(togglePrefix('net.,app.', 'net.')).toBe('app.');
  });
  it('client-side filter of live events', () => {
    const e = ev('net.dns', { hostname: 'Example.ORG' }, 1);
    expect(matchesFilters(e, { type: 'net.', sevMin: 0, q: '' })).toBe(true);
    expect(matchesFilters(e, { type: 'app.', sevMin: 0, q: '' })).toBe(false);
    expect(matchesFilters(e, { type: '', sevMin: 2, q: '' })).toBe(false);
    expect(matchesFilters(e, { type: '', sevMin: 0, q: 'example' })).toBe(true);
    expect(matchesFilters(e, { type: '', sevMin: 0, q: 'other' })).toBe(false);
  });
});

describe('JSON', () => {
  it('splits into tokens without losing text', () => {
    const text = JSON.stringify({ a: [1, 'x', null, true], b: { c: -2.5e3 } }, null, 2);
    const toks = tokenizeJson(text);
    expect(toks.map((t) => t.s).join('')).toBe(text);
    expect(toks.find((t) => t.t === 'key')?.s).toBe('"a"');
  });
});

describe('geography', () => {
  it('distance between two points about 18 km apart', () => {
    const d = haversine({ lat: 48.8566, lon: 2.3522 }, { lat: 48.8049, lon: 2.1204 });
    expect(d).toBeGreaterThan(17_000);
    expect(d).toBeLessThan(19_000);
  });
  it('track length with a skipped jump', () => {
    const p = [{ lat: 0, lon: 0 }, { lat: 0, lon: 0.001 }, { lat: 10, lon: 10 }, { lat: 10, lon: 10.001 }];
    const l = pathLength(p, (i) => i === 2);
    expect(l).toBeGreaterThan(200);
    expect(l).toBeLessThan(230);
  });
  it('closed circle of the wanted radius', () => {
    const r = circleRing({ lat: 48.86, lon: 2.35 }, 100, 16);
    expect(r).toHaveLength(17);
    expect(r[0]).toEqual(r[16]);
    expect(haversine({ lat: 48.86, lon: 2.35 }, { lat: (r[4] as [number, number])[1], lon: (r[4] as [number, number])[0] })).toBeCloseTo(100, 0);
  });
});

describe('configuration and periods', () => {
  it('validates the tile URL and falls back to the default value', () => {
    expect(isValidTileUrl('https://t.example/{z}/{x}/{y}.png')).toBe(true);
    expect(isValidTileUrl('http://t.example/{z}/{x}/{y}.png')).toBe(false);
    expect(isValidTileUrl('https://t.example/tile.png')).toBe(false);
    expect(mergeConfig({ tileUrl: 'javascript:alert(1)' }).tileUrl).toContain('openstreetmap');
    expect(mergeConfig({ tileUrl: 'https://tiles.example.org/{z}/{x}/{y}.png' }).tileUrl).toBe('https://tiles.example.org/{z}/{x}/{y}.png');
    expect(mergeConfig('anything').tileUrl).toContain('openstreetmap');
  });
  it('relative periods and invalid custom period', () => {
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

describe('v1.2 and tracking events readable in the event log', () => {
  it('tracking.level_changed: old and new level, who, how many lists', () => {
    expect(describeEvent(ev('tracking.level_changed', { old: 'balanced', new: 'strict', changes: ['a', 'b'], user: 'admin' }, 1))).toBe(
      'Blocking level: Balanced → Strict · 2 lists changed · by admin',
    );
    expect(describeEvent(ev('tracking.level_changed', { new: 'permissive', user: 'admin' }, 2))).toBe('Blocking level: unknown → Permissive · by admin');
    expect(describeEvent(ev('tracking.level_changed', { old: 'x', new: 'y', changes: 1 }))).toBe('Blocking level: x → y · 1 list changed');
  });
  it('tracking.override: action, domain, forced, previous rule', () => {
    expect(describeEvent(ev('tracking.override', { domain: 'ads.example.top', action: 'block', forced: false, user: 'admin' }))).toBe('Rule for "ads.example.top": block · by admin');
    expect(describeEvent(ev('tracking.override', { domain: 'mtalk.google.com', action: 'block', forced: true, previous: 'allow', user: 'admin' }, 2))).toBe(
      'Rule for "mtalk.google.com": block · forced (essential domain) · previous rule: allow · by admin',
    );
    expect(describeEvent(ev('tracking.override', { domain: 'x.example', action: 'default' }))).toBe('Rule for "x.example": reset to default');
  });
  it('app.risk, app.role, app.ops', () => {
    expect(describeEvent(ev('app.risk', { package: 'p', label: 'App', level: 'high', score: 91, reasons: ['sms_send', 'combo_sms_fraud'] }))).toBe('App · p · high risk (91/100) · 2 reasons');
    expect(describeEvent(ev('app.role', { role: 'sms', old: 'a', new: 'b' }))).toBe('SMS app: a → b');
    expect(describeEvent(ev('app.role', { role: 'home', new: 'b' }))).toBe('Home screen: none → b');
    expect(describeEvent(ev('app.ops', { apps: [{ package: 'a', op: 'send_sms', count: 3 }, { package: 'b', op: 'camera', count: 1 }] }))).toContain('2 sensitive operation uses');
  });
  it('does not crash on partial or hostile data', () => {
    for (const t of ['tracking.level_changed', 'tracking.override', 'app.risk', 'app.role', 'app.ops', 'detect.fanout', 'detect.unknown']) {
      expect(() => describeEvent(ev(t, {}))).not.toThrow();
      expect(() => describeEvent(ev(t, { apps: 7, reasons: 'x', evidence: 3, changes: {}, domain: 4, user: ['a'] }))).not.toThrow();
    }
    expect(describeEvent(ev('tracking.override', { domain: '<img src=x onerror=alert(1)>‮', action: 'block' }))).not.toContain('‮');
  });
});

describe('event log: mutes and new detection types', () => {
  it('detect.muted / detect.unmuted and the §11.4 types are readable', () => {
    expect(describeEvent(ev('detect.muted', { type: 'detect.dns_bypass', package: 'com.android.chrome', reason: 'intended', user: 'admin' }))).toBe('Muted: Bypass of the phone\'s DNS for com.android.chrome · reason: intended · by admin');
    expect(describeEvent(ev('detect.unmuted', { type: 'detect.dns_bypass', package: 'p' }))).toBe('Mute lifted: Bypass of the phone\'s DNS for p');
    expect(describeEvent(ev('detect.muted', {}))).toBe('Muted: detection for ?');
    expect(describeEvent(ev('detect.sms_permission', { package: 'com.x', evidence: {} }))).toContain('can send SMS');
    expect(describeEvent(ev('detect.default_app_changed', { package: 'com.x', evidence: { role: 'sms' } }))).toContain('default SMS app');
  });
});
