import { describe, expect, it } from 'vitest';
import type { Detection, WatchpostEvent } from '../api/types.ts';
import {
  DETECTION_TYPES,
  appNameOf,
  countBySeverity,
  detectionDomains,
  detectionFromEvent,
  evidenceItems,
  fmtWindow,
  groupByPackage,
  headline,
  isRecent,
  isMutable,
  isMuteEvent,
  applyMutes,
  parseMutes,
  monitoringScope,
  active,
  muteErrorMessage,
  matchesDetection,
  mergeDetections,
  normSeverity,
  normalizeDetection,
  observation,
  parseDetectionsResponse,
  typeInfo,
} from './detections.ts';
import { describeEvent } from './events.ts';

const det = (type: string, evidence: Record<string, unknown>, extra: Partial<Detection> = {}): Detection => ({
  id: `id-${type}`,
  ts: '2026-11-16T10:00:00.000Z',
  type,
  severity: 2,
  package: 'com.example.app',
  label: 'App',
  evidence,
  ...extra,
});

describe('detection types', () => {
  it('the twelve types of contracts §11.3 and §11.4 have a label, a reason, innocent explanations and what to do', () => {
    expect(DETECTION_TYPES).toHaveLength(12);
    for (const t of DETECTION_TYPES) {
      const i = typeInfo(t);
      expect(i.label).not.toBe(t);
      expect(i.why.length).toBeGreaterThan(60);
      expect(i.innocent.length).toBeGreaterThan(0);
      expect(i.actions.length).toBeGreaterThan(0);
    }
    expect(typeInfo('detect.sms_abuse').guard).toBe('sms');
    expect(typeInfo('detect.threat_domain').domains).toBe(true);
  });

  it('an unknown type keeps its code and says it is not known', () => {
    const i = typeInfo('detect.future');
    expect(i.label).toBe('detect.future');
    expect(i.why).toContain('is not known');
    expect(typeInfo('constructor').label).toBe('constructor');
  });
});

describe('"what was observed" sentence', () => {
  it('threat_domain: the number of domains comes from the list or the counter', () => {
    expect(observation(det('detect.threat_domain', { domains: ['a.top', 'b.top', 'c.top'] }))).toBe('App tried to reach 3 domains from the threat list');
    expect(observation(det('detect.threat_domain', { domain_count: 1 }))).toBe('App tried to reach 1 domain from the threat list');
  });

  it('upload_spike, fanout, mail_ports, dns_bypass', () => {
    expect(observation(det('detect.upload_spike', { tx_bytes: 52_428_800, median_bytes: 1_048_576 }))).toMatch(/App sent 50\sMiB in one hour, 50 times more than usual \(median: 1\sMiB\)/);
    expect(observation(det('detect.fanout', { distinct_ips: 214 }))).toBe('App connected to 214 different addresses in one hour');
    expect(observation(det('detect.mail_ports', { ports: [25, 587], connections: 40 }))).toBe('App opened 40 connections to mail servers (ports 25, 587), without being a known mail client');
    expect(observation(det('detect.dns_bypass', { resolvers: ['1.1.1.1'] }))).toContain('a public DNS resolver (1.1.1.1)');
    expect(observation(det('detect.dns_bypass', { unresolved_ips: 80 }))).toContain('80 addresses that the phone');
  });

  it('sms_abuse, sensor_background, new_app_risky', () => {
    expect(observation(det('detect.sms_abuse', { count: 1984, background_count: 1790, default_sms_app: false }))).toMatch(/sent 1,984 SMS, of which 1,790 in the background although it is not the default SMS app/);
    expect(observation(det('detect.sensor_background', { op: 'record_audio', background_count: 3 }))).toBe('App used the microphone 3 times in the background');
    expect(observation(det('detect.sensor_background', { op: 'camera', background_count: 1 }))).toBe('App used the camera 1 time in the background');
    expect(observation(det('detect.new_app_risky', { level: 'high', score: 90 }))).toBe('App was just installed with a high risk profile');
    expect(observation(det('detect.new_app_risky', { capability: 'READ_SMS' }))).toContain('installed less than 24 h ago');
  });

  it('falls back on the collector summary when the evidence is empty or unreadable, then on the type label', () => {
    expect(observation(det('detect.fanout', {}, { summary: 'Many destinations' }))).toBe('Many destinations');
    expect(observation(det('detect.fanout', { distinct_ips: 'many' }))).toBe('Connections to a very large number of addresses: App');
    expect(observation(det('detect.unknown', { x: 1 }, { summary: 'Server summary' }))).toBe('Server summary');
  });

  it('the application name comes from the phone: cleaned, never interpreted; without a name, package then neutral wording', () => {
    const hostile = '<img src=x onerror=alert(1)>\u202E';
    const n = appNameOf({ label: hostile, package: 'p' });
    expect(n).toContain('<img src=x onerror=alert(1)>');
    expect(n).not.toContain('\u202E');
    expect(appNameOf({ package: 'com.x' })).toBe('com.x');
    expect(appNameOf({})).toBe('An application');
  });
});

describe('evidence', () => {
  it('translates known keys, formats bytes and keeps unknown keys as they are', () => {
    const items = evidenceItems(det('detect.upload_spike', { tx_bytes: 2048, ratio: 12.5, window_from: 'x', zzz_unknown: 'v', list_of: ['a', 'b'], object: { k: 1 }, empty: '', nul: null }));
    expect(items).toContainEqual({ label: 'Bytes sent over the hour', value: '2\u00a0KiB' });
    expect(items).toContainEqual({ label: 'Factor relative to the median', value: '12.5' });
    expect(items).toContainEqual({ label: 'zzz_unknown', value: 'v' });
    expect(items).toContainEqual({ label: 'list_of', value: 'a, b' });
    expect(items.find((i) => i.label === 'object')?.value).toBe('{"k":1}');
    expect(items.some((i) => i.label === 'window_from' || i.label === 'empty' || i.label === 'nul')).toBe(false);
  });

  it('extracts the domains, cleaned', () => {
    expect(detectionDomains(det('detect.threat_domain', { domains: ['a.top', 'b\u0007.top', 3] }))).toEqual(['a.top', 'b.top', '3']);
    expect(detectionDomains(det('detect.threat_domain', {}))).toEqual([]);
  });
});

describe('API reading', () => {
  it('normalises a detection, rejects incomplete items', () => {
    const d = normalizeDetection({ id: 'x', ts: '2026-11-16T10:00:00Z', type: 'detect.fanout', severity: 3, package: 'p', label: 'L', summary: 's', evidence: { a: 1, window_from: '2026-11-16T09:00:00Z', window_to: '2026-11-16T10:00:00Z' } });
    expect(d).toMatchObject({ id: 'x', severity: 3, window_from: '2026-11-16T09:00:00Z', window_to: '2026-11-16T10:00:00Z' });
    expect(normalizeDetection({ id: 'x', type: 'detect.a' })).toBeUndefined();
    expect(normalizeDetection({ ts: 't', type: 'detect.a' })).toBeUndefined();
    expect(normalizeDetection(null)).toBeUndefined();
    expect(normalizeDetection({ id: 'x', ts: 't', type: 'detect.a' })?.evidence).toEqual({});
  });

  it('accepts a severity as words, clamps numbers', () => {
    expect(normSeverity('critical')).toBe(3);
    expect(normSeverity('medium')).toBe(2);
    expect(normSeverity('low')).toBe(1);
    expect(normSeverity(9)).toBe(3);
    expect(normSeverity(-2)).toBe(0);
    expect(normSeverity('2')).toBe(2);
    expect(normSeverity(undefined)).toBe(0);
  });

  it('reads a response with a cursor, empty, or invalid', () => {
    const r = parseDetectionsResponse({ detections: [{ id: 'a', ts: 't', type: 'detect.x', severity: 1 }, 7], next_cursor: 'c1' });
    expect(r.detections).toHaveLength(1);
    expect(r.next_cursor).toBe('c1');
    expect(parseDetectionsResponse({ detections: [] })).toEqual({ detections: [] });
    expect(parseDetectionsResponse('oops')).toEqual({ detections: [] });
  });

  it('turns a `detect.*` event of the SSE stream into a detection, ignores the others', () => {
    const ev: WatchpostEvent = { id: 'E1', ts: '2026-11-16T10:00:00Z', type: 'detect.sms_abuse', sev: 3, device_id: 'dev', data: { package: 'p', label: 'L', evidence: { count: 5 }, window_from: '2026-11-16T09:00:00Z', window_to: '2026-11-16T10:00:00Z', summary: 's' } };
    expect(detectionFromEvent(ev)).toMatchObject({ id: 'E1', type: 'detect.sms_abuse', severity: 3, package: 'p', evidence: { count: 5 }, window_from: '2026-11-16T09:00:00Z' });
    expect(detectionFromEvent({ ...ev, type: 'net.dns' })).toBeUndefined();
    expect(detectionFromEvent({ ...ev, data: {} })?.evidence).toEqual({});
  });

  it('the event log describes a detection in plain words', () => {
    const ev: WatchpostEvent = { id: 'E1', ts: '2026-11-16T10:00:00Z', type: 'detect.fanout', sev: 2, data: { package: 'com.x', evidence: { distinct_ips: 300 } } };
    expect(describeEvent(ev)).toBe('com.x connected to 300 different addresses in one hour');
  });
});

describe('aggregations', () => {
  it('counts by severity and builds the headline', () => {
    const c = countBySeverity([{ severity: 3 }, { severity: 3 }, { severity: 2 }, { severity: 1 }, { severity: 0 }]);
    expect(c).toEqual({ critical: 2, warning: 1, notable: 1, info: 1, total: 5 });
    expect(headline(c)).toEqual({ tone: 'bad', text: '2 critical, 1 warning, 1 notable, 1 info' });
    expect(headline(countBySeverity([{ severity: 2 }]))).toEqual({ tone: 'warn', text: '1 warning' });
    expect(headline(countBySeverity([{ severity: 3 }]), true).text).toBe('1 critical or more');
  });

  it('"nothing to report" without a detection', () => {
    expect(headline(countBySeverity([]))).toEqual({ tone: 'ok', text: 'Nothing to report' });
    expect(countBySeverity([]).total).toBe(0);
  });

  it('merges without duplicates (same identifier) and sorts newest first', () => {
    const a = det('detect.fanout', {}, { id: 'a', ts: '2026-11-16T10:00:00Z', window_from: 'w1', window_to: 'w2' });
    const b = det('detect.fanout', {}, { id: 'b', ts: '2026-11-16T12:00:00Z', package: 'other' });
    const merged = mergeDetections([a], [b, a]);
    expect(merged.map((d) => d.id)).toEqual(['b', 'a']);
    const same = [a];
    expect(mergeDetections(same, [a])).toBe(same);
  });

  it('two detections of the same application over the same window (one domain each) are both kept', () => {
    const w = { window_from: '2026-11-16T00:00:00Z', window_to: '2026-11-17T00:00:00Z' };
    const d1 = det('detect.threat_domain', { domain: 'a.top' }, { id: '1', ...w });
    const d2 = det('detect.threat_domain', { domain: 'b.top' }, { id: '2', ts: '2026-11-16T10:00:01.000Z', ...w });
    expect(mergeDetections([d1], [d2]).map((d) => d.id)).toEqual(['2', '1']);
  });

  it('filters by type, application, severity and period', () => {
    const d = det('detect.fanout', {}, { severity: 2 });
    expect(matchesDetection(d, {})).toBe(true);
    expect(matchesDetection(d, { type: 'detect.fanout' })).toBe(true);
    expect(matchesDetection(d, { type: 'detect.mail_ports' })).toBe(false);
    expect(matchesDetection(d, { pkg: 'other' })).toBe(false);
    expect(matchesDetection(d, { sevMin: 3 })).toBe(false);
    expect(matchesDetection(d, { from: '2026-11-16T11:00:00Z' })).toBe(false);
    expect(matchesDetection(d, { to: '2026-11-16T11:00:00Z', from: '2026-11-16T09:00:00Z' })).toBe(true);
  });

  it('recency and window', () => {
    const d = det('detect.fanout', {});
    expect(isRecent(d, new Date('2026-11-16T20:00:00Z'))).toBe(true);
    expect(isRecent(d, new Date('2026-11-18T20:00:00Z'))).toBe(false);
    expect(fmtWindow('2026-11-16T13:00:00Z', '2026-11-16T14:00:00Z')).toMatch(/^16\/11\/2026 from \d\d:\d\d to \d\d:\d\d$/);
    expect(fmtWindow('2026-11-15T13:00:00Z', '2026-11-16T14:00:00Z')).toMatch(/^from /);
    expect(fmtWindow(undefined, '2026-11-16T14:00:00Z')).toBeUndefined();
  });
});

describe('applications concerned', () => {
  it('ranks by maximum severity then by number, ignores detections without an application', () => {
    const l = [
      det('detect.fanout', {}, { id: '1', package: 'a', severity: 2 }),
      det('detect.fanout', {}, { id: '2', package: 'a', severity: 2 }),
      det('detect.sms_abuse', {}, { id: '3', package: 'b', severity: 3, label: 'B' }),
      det('detect.fanout', {}, { id: '4', package: 'c', severity: 1 }),
      det('detect.fanout', {}, { id: '5', severity: 3 }),
    ].map((d) => (d.id === '5' ? { ...d, package: undefined } : d)) as Detection[];
    const g = groupByPackage(l);
    expect(g.map((x) => x.package)).toEqual(['b', 'a', 'c']);
    expect(g[0]).toMatchObject({ label: 'B', count: 1, maxSeverity: 3, types: ['detect.sms_abuse'] });
    expect(g[1]).toMatchObject({ count: 2 });
    expect(groupByPackage([])).toEqual([]);
  });
});

describe('evidence in the collector format (internal/detect)', () => {
  it('threat_domain: one domain per detection', () => {
    const d = det('detect.threat_domain', { domain: 'sms-relay.cheap-gw.top', requests: 14, blocked: true, reason: 'List: Watchpost threats' });
    expect(observation(d)).toBe('App tried to reach the domain sms-relay.cheap-gw.top from the threat list (14 requests)');
    expect(detectionDomains(d)).toEqual(['sms-relay.cheap-gw.top']);
    expect(evidenceItems(d)).toContainEqual({ label: 'Blocked by AdGuard', value: 'yes' });
  });
  it('upload_spike without a median (learning), fanout, dns_bypass, mail_ports', () => {
    expect(observation(det('detect.upload_spike', { tx_bytes: 52_428_800, threshold_bytes: 10_485_760, learning: true }))).toMatch(/50\sMiB in one hour \(above the threshold of 10\sMiB; not enough history yet for a median\)/);
    expect(observation(det('detect.fanout', { addresses: 150, connections: 400, threshold: 100 }))).toBe('App connected to 150 different addresses in one hour');
    expect(observation(det('detect.dns_bypass', { connections: 9, resolvers: ['1.1.1.1:853'], providers: ['Cloudflare'] }))).toContain('(Cloudflare)');
    expect(observation(det('detect.mail_ports', { connections: 30, addresses: 4, ports: [25] }))).toContain('(port 25)');
  });
  it('sms_abuse: reasons "not the default SMS app" and "volume"', () => {
    expect(observation(det('detect.sms_abuse', { reason: 'not_default_sms_app', sent: 40, background: 40, default_sms_app: ['com.samsung.android.messaging'] }))).toBe(
      'App sent 40 SMS, of which 40 in the background although it is not the default SMS app',
    );
    expect(observation(det('detect.sms_abuse', { reason: 'volume', sent: 900, background: 0 }))).toBe('App sent 900 SMS: an abnormal volume');
    expect(observation(det('detect.sms_abuse', { reason: 'not_default_sms_app', sent: 1136, background: 1136, rejected: 354 }))).toMatch(/, and tried to send 354 more, refused by the system although/);
    expect(evidenceItems(det('detect.sms_abuse', { reason: 'volume', sent: 9 }))).toContainEqual({ label: 'Reason', value: 'daily volume exceeded' });
  });
  it('new_app_risky: risk profile or capability (collector key translated)', () => {
    expect(observation(det('detect.new_app_risky', { trigger: 'capability', capability: 'permission:SEND_SMS' }))).toBe('App, installed less than 24 h ago, obtained a sensitive capability: sending SMS');
    expect(observation(det('detect.new_app_risky', { trigger: 'capability', capability: 'role:wallet' }))).toContain('role:wallet');
    const items = evidenceItems(det('detect.new_app_risky', { trigger: 'high_risk', level: 'high', score: 90, reasons: ['combo_sms_fraud', 'zzz'] }));
    expect(items).toContainEqual({ label: 'Trigger', value: 'high risk profile' });
    expect(items.find((i) => i.label === 'Reasons')?.value).toBe('SMS fraud profile, zzz');
  });
});

describe('opsBlindSpot', () => {
  it('is silent only when the app.ops collector is running', async () => {
    const { opsBlindSpot } = await import('./detections.ts');
    expect(opsBlindSpot('running')).toBeNull();
    for (const state of ['disabled', 'unavailable', undefined, 'other']) {
      const text = opsBlindSpot(state);
      expect(text).toContain('SMS');
      expect(text).toContain('no sending detection');
    }
    expect(opsBlindSpot('unavailable')).toContain('DUMP');
  });
});

describe('§11.4 detections (without app.ops)', () => {
  it('sms_permission: a review, pointing to the SMS guard', () => {
    const d = det('detect.sms_permission', { permission: 'SEND_SMS' });
    expect(observation(d)).toBe('App can send SMS without going through your messaging app; is this intended?');
    const i = typeInfo('detect.sms_permission');
    expect(i.review).toBe(true);
    expect(i.guard).toBe('sms');
    expect(i.why).toContain('review');
    expect(i.mutable).not.toBe(false);
  });
  it('default_app_changed: sentence per role, previous application, flattened evidence', () => {
    const sms = det('detect.default_app_changed', { role: 'sms', old: 'com.samsung.android.messaging', new: 'com.example.app', risk: { score: 88, level: 'high', reasons: ['combo_sms_fraud'] } }, { severity: 3 });
    expect(observation(sms)).toBe('App became the default SMS app (in place of com.samsung.android.messaging)');
    expect(observation(det('detect.default_app_changed', { role: 'keyboard' }))).toBe('App became the default "Keyboard" role');
    expect(observation(det('detect.default_app_changed', {}, { summary: 'Role changed' }))).toBe('Role changed');
    const items = evidenceItems(sms);
    expect(items).toContainEqual({ label: 'Role', value: 'SMS app' });
    expect(items).toContainEqual({ label: 'Risk: score', value: '88' });
    expect(items).toContainEqual({ label: 'Risk: reasons', value: 'SMS fraud profile' });
    expect(typeInfo('detect.default_app_changed').why).toContain('SMS trojans');
  });
  it('flood: without an application, cap read', () => {
    expect(observation(det('detect.flood', { count: 412, limit: 200 }, { package: undefined, label: undefined } as never))).toBe('More than 200 detections in one day on this device (412 produced)');
    expect(observation(det('detect.flood', { suppressed: 37, limit: 200 }, { package: undefined, label: undefined } as never))).toBe('More than 200 detections in one day on this device: 37 more not recorded');
    expect(observation(det('detect.inventory_mismatch', {}))).toContain('declared a system application');
    expect(isMutable({ type: 'detect.inventory_mismatch', package: 'p' })).toBe(false);
    expect(observation(det('detect.flood', {}))).toContain('More than 200');
  });
  it('non-mutable types: sms_abuse, default_app_changed, flood; without an application: nothing to mute', () => {
    expect(isMutable({ type: 'detect.dns_bypass', package: 'p' })).toBe(true);
    expect(isMutable({ type: 'detect.sms_permission', package: 'p' })).toBe(true);
    expect(isMutable({ type: 'detect.sms_abuse', package: 'p' })).toBe(false);
    expect(isMutable({ type: 'detect.default_app_changed', package: 'p' })).toBe(false);
    expect(isMutable({ type: 'detect.flood', package: 'p' })).toBe(false);
    expect(isMutable({ type: 'detect.fanout' })).toBe(false);
    expect(isMutable({ type: 'detect.unknown', package: 'p' })).toBe(true);
  });
  it('recurrence, mute and update read from the detection', () => {
    const d = normalizeDetection({ id: 'a', ts: '2026-11-16T10:00:00Z', type: 'detect.dns_bypass', severity: 1, recurring: true, muted: true, updated_at: '2026-11-16T11:00:00Z' });
    expect(d).toMatchObject({ recurring: true, muted: true, updated_at: '2026-11-16T11:00:00Z' });
    expect(normalizeDetection({ id: 'a', ts: 't', type: 'detect.x', evidence: { recurring: true } })?.recurring).toBe(true);
    expect(normalizeDetection({ id: 'a', ts: 't', type: 'detect.x' })?.muted).toBeUndefined();
  });
  it('count excluding muted: a muted detection changes neither the verdict nor the most worrying application', () => {
    const l = [{ ...det('detect.sms_permission', {}), muted: true, id: '1' }, det('detect.fanout', {}, { id: '2', severity: 1 })];
    expect(countBySeverity(l)).toEqual({ critical: 0, warning: 0, notable: 1, info: 0, total: 1 });
    expect(countBySeverity([{ ...det('detect.fanout', {}), muted: true }])).toMatchObject({ total: 0 });
    expect(active(l)).toHaveLength(1);
    expect(groupByPackage([{ ...det('detect.fanout', {}), muted: true }])).toEqual([]);
    expect(headline(countBySeverity([{ ...det('detect.fanout', {}), muted: true }]))).toEqual({ tone: 'ok', text: 'Nothing to report' });
  });
  it('mutes: tolerant reading, applied to already created detections, stream events', () => {
    const m = parseMutes({ mutes: [{ type: 'detect.dns_bypass', package: 'com.android.chrome', reason: 'intended', created_at: '2026-11-16T10:00:00Z', created_by: 'admin' }, { type: 'x' }, 4, null] });
    expect(m).toEqual([{ type: 'detect.dns_bypass', package: 'com.android.chrome', reason: 'intended', created_at: '2026-11-16T10:00:00Z', created_by: 'admin' }]);
    expect(parseMutes([{ type: 'a', package: 'b' }])).toHaveLength(1);
    expect(parseMutes('oops')).toEqual([]);
    expect(parseMutes(undefined)).toEqual([]);
    const l = [det('detect.dns_bypass', {}, { id: '1', package: 'com.android.chrome' }), det('detect.dns_bypass', {}, { id: '2', package: 'other' }), det('detect.fanout', {}, { id: '3', package: 'com.android.chrome' })];
    expect(applyMutes(l, m).map((d) => !!d.muted)).toEqual([true, false, false]);
    expect(applyMutes(l, [])).toBe(l);
    expect(isMuteEvent('detect.muted')).toBe(true);
    expect(isMuteEvent('detect.fanout')).toBe(false);
    const ev: WatchpostEvent = { id: 'E', ts: '2026-11-16T10:00:00Z', type: 'detect.muted', sev: 0, data: { package: 'p' } };
    expect(detectionFromEvent(ev)).toBeUndefined();
  });
  it('a stream update (update + detection_id) replaces the existing detection instead of creating another', () => {
    const base = det('detect.threat_domain', { domains: ['a.top'], domain_count: 1 }, { id: 'D1', ts: '2026-11-16T08:00:00Z' });
    const ev: WatchpostEvent = { id: 'E9', ts: '2026-11-16T12:00:00Z', type: 'detect.threat_domain', sev: 3, device_id: 'dev', data: { update: true, detection_id: 'D1', package: 'com.example.app', evidence: { domains: ['a.top', 'b.top'], domain_count: 2 }, window_from: '2026-11-16T00:00:00Z', window_to: '2026-11-17T00:00:00Z' } };
    const d = detectionFromEvent(ev) as Detection;
    expect(d.id).toBe('D1');
    expect(d.updated_at).toBe('2026-11-16T12:00:00Z');
    const merged = mergeDetections([base], [d], { replace: true });
    expect(merged).toHaveLength(1);
    expect(merged[0]?.evidence).toEqual({ domains: ['a.top', 'b.top'], domain_count: 2 });
    expect(merged[0]?.ts).toBe('2026-11-16T08:00:00Z');
    expect(mergeDetections([base], [d])).toHaveLength(1);
    expect(mergeDetections([base], [d])[0]?.evidence).toEqual(base.evidence);
  });
  it('mute error messages', () => {
    expect(muteErrorMessage({ status: 400, code: 'not_mutable', message: 'type not mutable' })).toContain('cannot be muted');
    expect(muteErrorMessage({ status: 404, code: 'not_found', message: 'x' })).toContain('§11.4');
    expect(muteErrorMessage({ status: 0, code: 'network', message: 'Server unreachable' })).toBe('Server unreachable');
  });
});

describe('what is monitored and what is not (§11.4)', () => {
  it('without app_ops: says that sending is not seen, what is monitored anyway, and that the SMS guard is the real protection', () => {
    for (const state of ['disabled', 'unavailable', undefined, 'other']) {
      const sc = monitoringScope(state);
      expect(sc.blind).toContain('SMS sending itself');
      expect(sc.blind).toContain('no sending detection');
      expect(sc.watched).toContain('permission to send SMS');
      expect(sc.watched).toContain('change of default SMS app');
      expect(sc.guard).toContain('SMS guard');
      expect(sc.ops).toBeNull();
    }
    expect(monitoringScope('unavailable').blind).toContain('DUMP');
  });
  it('with app_ops running: no blind spot announced, but "running" does not prove that data is arriving', () => {
    const sc = monitoringScope('running');
    expect(sc.blind).toBeNull();
    expect(sc.ops).toContain('does not prove that data is arriving');
    expect(sc.guard).toContain('SMS guard');
    expect(sc.watched).toContain('Monitored in all cases');
  });
});

describe('§11.4 evidence in the collector format', () => {
  it('sms_permission and default_app_changed: flattened risk profile, dates, origin, granted capabilities', () => {
    const items = evidenceItems(det('detect.sms_permission', { permission: 'SEND_SMS', level: 'high', score: 91, reasons: ['combo_sms_fraud', 'sms_send'], source: 'permission_changed', since: '2026-11-15T13:53:20.157Z', default_sms_app: ['com.samsung.android.messaging'] }));
    expect(items).toContainEqual({ label: 'Risk level', value: 'High' });
    expect(items).toContainEqual({ label: 'Origin', value: 'permission granted' });
    expect(items.find((i) => i.label === 'Since')?.value).toMatch(/^15\/11\/2026 /);
    expect(items.find((i) => i.label === 'Reasons')?.value).toBe('SMS fraud profile, Can send SMS');
    const g = evidenceItems(det('detect.default_app_changed', { role: 'sms', granted: ['accessibility_service', 'overlay'] }));
    expect(g.find((i) => i.label === 'Capabilities granted')?.value).toBe('Accessibility service, Drawing over other applications');
  });
});
