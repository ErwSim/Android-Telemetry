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
  package: 'com.exemple.app',
  label: 'Appli',
  evidence,
  ...extra,
});

describe('types de détection', () => {
  it('les douze types des contrats §11.3 et §11.4 ont libellé, raison, explications innocentes et conduite à tenir', () => {
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

  it('un type inconnu garde son code et dit ne pas le connaître', () => {
    const i = typeInfo('detect.futur');
    expect(i.label).toBe('detect.futur');
    expect(i.why).toContain("n'est pas connu");
    expect(typeInfo('constructor').label).toBe('constructor');
  });
});

describe('phrase « ce qui a été observé »', () => {
  it('threat_domain : le nombre de domaines vient de la liste ou du compteur', () => {
    expect(observation(det('detect.threat_domain', { domains: ['a.top', 'b.top', 'c.top'] }))).toBe("Appli a tenté de joindre 3 domaines de la liste de menaces");
    expect(observation(det('detect.threat_domain', { domain_count: 1 }))).toBe('Appli a tenté de joindre 1 domaine de la liste de menaces');
  });

  it('upload_spike, fanout, mail_ports, dns_bypass', () => {
    expect(observation(det('detect.upload_spike', { tx_bytes: 52_428_800, median_bytes: 1_048_576 }))).toMatch(/Appli a envoyé 50\sMio en une heure, soit 50 fois plus que d'habitude \(médiane : 1\sMio\)/);
    expect(observation(det('detect.fanout', { distinct_ips: 214 }))).toBe("Appli s'est connectée à 214 adresses différentes en une heure");
    expect(observation(det('detect.mail_ports', { ports: [25, 587], connections: 40 }))).toBe('Appli a ouvert 40 connexions vers des serveurs de courrier (ports 25, 587), sans être un client de messagerie connu');
    expect(observation(det('detect.dns_bypass', { resolvers: ['1.1.1.1'] }))).toContain('un résolveur DNS public (1.1.1.1)');
    expect(observation(det('detect.dns_bypass', { unresolved_ips: 80 }))).toContain('80 adresses que le téléphone');
  });

  it('sms_abuse, sensor_background, new_app_risky', () => {
    expect(observation(det('detect.sms_abuse', { count: 1984, background_count: 1790, default_sms_app: false }))).toMatch(/a envoyé 1\s984 SMS, dont 1\s790 en arrière-plan alors que ce n'est pas l'application SMS par défaut/);
    expect(observation(det('detect.sensor_background', { op: 'record_audio', background_count: 3 }))).toBe('Appli a utilisé le micro 3 fois en arrière-plan');
    expect(observation(det('detect.sensor_background', { op: 'camera', background_count: 1 }))).toBe('Appli a utilisé la caméra 1 fois en arrière-plan');
    expect(observation(det('detect.new_app_risky', { level: 'high', score: 90 }))).toBe("Appli vient d'être installée avec un profil de risque élevé");
    expect(observation(det('detect.new_app_risky', { capability: 'READ_SMS' }))).toContain('installée depuis moins de 24 h');
  });

  it('retombe sur le résumé du collecteur quand la preuve est vide ou illisible, puis sur le libellé du type', () => {
    expect(observation(det('detect.fanout', {}, { summary: 'Beaucoup de destinations' }))).toBe('Beaucoup de destinations');
    expect(observation(det('detect.fanout', { distinct_ips: 'beaucoup' }))).toBe('Connexions vers de très nombreuses adresses : Appli');
    expect(observation(det('detect.inconnue', { x: 1 }, { summary: 'Résumé serveur' }))).toBe('Résumé serveur');
  });

  it('le nom de l’application vient du téléphone : nettoyé, jamais interprété ; sans nom, paquet puis formulation neutre', () => {
    const hostile = '<img src=x onerror=alert(1)>\u202E';
    const n = appNameOf({ label: hostile, package: 'p' });
    expect(n).toContain('<img src=x onerror=alert(1)>');
    expect(n).not.toContain('\u202E');
    expect(appNameOf({ package: 'com.x' })).toBe('com.x');
    expect(appNameOf({})).toBe('Une application');
  });
});

describe('preuves', () => {
  it('traduit les clés connues, formate les octets et garde les clés inconnues telles quelles', () => {
    const items = evidenceItems(det('detect.upload_spike', { tx_bytes: 2048, ratio: 12.5, window_from: 'x', zzz_inconnu: 'v', liste: ['a', 'b'], objet: { k: 1 }, vide: '', nul: null }));
    expect(items).toContainEqual({ label: 'Octets envoyés sur l’heure', value: '2\u00a0Kio' });
    expect(items).toContainEqual({ label: 'Facteur par rapport à la médiane', value: '12,5' });
    expect(items).toContainEqual({ label: 'zzz_inconnu', value: 'v' });
    expect(items).toContainEqual({ label: 'liste', value: 'a, b' });
    expect(items.find((i) => i.label === 'objet')?.value).toBe('{"k":1}');
    expect(items.some((i) => i.label === 'window_from' || i.label === 'vide' || i.label === 'nul')).toBe(false);
  });

  it('extrait les domaines, nettoyés', () => {
    expect(detectionDomains(det('detect.threat_domain', { domains: ['a.top', 'b\u0007.top', 3] }))).toEqual(['a.top', 'b.top', '3']);
    expect(detectionDomains(det('detect.threat_domain', {}))).toEqual([]);
  });
});

describe('lecture de l’API', () => {
  it('normalise une détection, rejette les éléments incomplets', () => {
    const d = normalizeDetection({ id: 'x', ts: '2026-11-16T10:00:00Z', type: 'detect.fanout', severity: 3, package: 'p', label: 'L', summary: 's', evidence: { a: 1, window_from: '2026-11-16T09:00:00Z', window_to: '2026-11-16T10:00:00Z' } });
    expect(d).toMatchObject({ id: 'x', severity: 3, window_from: '2026-11-16T09:00:00Z', window_to: '2026-11-16T10:00:00Z' });
    expect(normalizeDetection({ id: 'x', type: 'detect.a' })).toBeUndefined();
    expect(normalizeDetection({ ts: 't', type: 'detect.a' })).toBeUndefined();
    expect(normalizeDetection(null)).toBeUndefined();
    expect(normalizeDetection({ id: 'x', ts: 't', type: 'detect.a' })?.evidence).toEqual({});
  });

  it('accepte une gravité en mots, borne les nombres', () => {
    expect(normSeverity('critical')).toBe(3);
    expect(normSeverity('medium')).toBe(2);
    expect(normSeverity('low')).toBe(1);
    expect(normSeverity(9)).toBe(3);
    expect(normSeverity(-2)).toBe(0);
    expect(normSeverity('2')).toBe(2);
    expect(normSeverity(undefined)).toBe(0);
  });

  it('lit une réponse avec curseur, vide, ou invalide', () => {
    const r = parseDetectionsResponse({ detections: [{ id: 'a', ts: 't', type: 'detect.x', severity: 1 }, 7], next_cursor: 'c1' });
    expect(r.detections).toHaveLength(1);
    expect(r.next_cursor).toBe('c1');
    expect(parseDetectionsResponse({ detections: [] })).toEqual({ detections: [] });
    expect(parseDetectionsResponse('oops')).toEqual({ detections: [] });
  });

  it('transforme un événement `detect.*` du flux SSE en détection, ignore les autres', () => {
    const ev: WatchpostEvent = { id: 'E1', ts: '2026-11-16T10:00:00Z', type: 'detect.sms_abuse', sev: 3, device_id: 'dev', data: { package: 'p', label: 'L', evidence: { count: 5 }, window_from: '2026-11-16T09:00:00Z', window_to: '2026-11-16T10:00:00Z', summary: 's' } };
    expect(detectionFromEvent(ev)).toMatchObject({ id: 'E1', type: 'detect.sms_abuse', severity: 3, package: 'p', evidence: { count: 5 }, window_from: '2026-11-16T09:00:00Z' });
    expect(detectionFromEvent({ ...ev, type: 'net.dns' })).toBeUndefined();
    expect(detectionFromEvent({ ...ev, data: {} })?.evidence).toEqual({});
  });

  it('le journal décrit une détection en clair', () => {
    const ev: WatchpostEvent = { id: 'E1', ts: '2026-11-16T10:00:00Z', type: 'detect.fanout', sev: 2, data: { package: 'com.x', evidence: { distinct_ips: 300 } } };
    expect(describeEvent(ev)).toBe("com.x s'est connectée à 300 adresses différentes en une heure");
  });
});

describe('agrégations', () => {
  it('compte par gravité et fait le titre', () => {
    const c = countBySeverity([{ severity: 3 }, { severity: 3 }, { severity: 2 }, { severity: 1 }, { severity: 0 }]);
    expect(c).toEqual({ critical: 2, warning: 1, notable: 1, info: 1, total: 5 });
    expect(headline(c)).toEqual({ tone: 'bad', text: '2 critiques, 1 avertissement, 1 à noter, 1 information' });
    expect(headline(countBySeverity([{ severity: 2 }]))).toEqual({ tone: 'warn', text: '1 avertissement' });
    expect(headline(countBySeverity([{ severity: 3 }]), true).text).toBe('1 critique ou plus');
  });

  it('« rien à signaler » sans détection', () => {
    expect(headline(countBySeverity([]))).toEqual({ tone: 'ok', text: 'Rien à signaler' });
    expect(countBySeverity([]).total).toBe(0);
  });

  it('fusionne sans doublon (même identifiant) et trie du plus récent au plus ancien', () => {
    const a = det('detect.fanout', {}, { id: 'a', ts: '2026-11-16T10:00:00Z', window_from: 'w1', window_to: 'w2' });
    const b = det('detect.fanout', {}, { id: 'b', ts: '2026-11-16T12:00:00Z', package: 'autre' });
    const merged = mergeDetections([a], [b, a]);
    expect(merged.map((d) => d.id)).toEqual(['b', 'a']);
    const same = [a];
    expect(mergeDetections(same, [a])).toBe(same);
  });

  it("deux détections d'une même application sur la même fenêtre (un domaine chacune) sont toutes deux gardées", () => {
    const w = { window_from: '2026-11-16T00:00:00Z', window_to: '2026-11-17T00:00:00Z' };
    const d1 = det('detect.threat_domain', { domain: 'a.top' }, { id: '1', ...w });
    const d2 = det('detect.threat_domain', { domain: 'b.top' }, { id: '2', ts: '2026-11-16T10:00:01.000Z', ...w });
    expect(mergeDetections([d1], [d2]).map((d) => d.id)).toEqual(['2', '1']);
  });

  it('filtre par type, application, gravité et période', () => {
    const d = det('detect.fanout', {}, { severity: 2 });
    expect(matchesDetection(d, {})).toBe(true);
    expect(matchesDetection(d, { type: 'detect.fanout' })).toBe(true);
    expect(matchesDetection(d, { type: 'detect.mail_ports' })).toBe(false);
    expect(matchesDetection(d, { pkg: 'autre' })).toBe(false);
    expect(matchesDetection(d, { sevMin: 3 })).toBe(false);
    expect(matchesDetection(d, { from: '2026-11-16T11:00:00Z' })).toBe(false);
    expect(matchesDetection(d, { to: '2026-11-16T11:00:00Z', from: '2026-11-16T09:00:00Z' })).toBe(true);
  });

  it('récence et fenêtre', () => {
    const d = det('detect.fanout', {});
    expect(isRecent(d, new Date('2026-11-16T20:00:00Z'))).toBe(true);
    expect(isRecent(d, new Date('2026-11-18T20:00:00Z'))).toBe(false);
    expect(fmtWindow('2026-11-16T13:00:00Z', '2026-11-16T14:00:00Z')).toMatch(/^16\/11\/2026 de \d\d:\d\d à \d\d:\d\d$/);
    expect(fmtWindow('2026-11-15T13:00:00Z', '2026-11-16T14:00:00Z')).toMatch(/^du /);
    expect(fmtWindow(undefined, '2026-11-16T14:00:00Z')).toBeUndefined();
  });
});

describe('applications concernées', () => {
  it('classe par gravité maximale puis par nombre, ignore les détections sans application', () => {
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

describe('preuves au format du collecteur (internal/detect)', () => {
  it('threat_domain : un domaine par détection', () => {
    const d = det('detect.threat_domain', { domain: 'sms-relay.cheap-gw.top', requests: 14, blocked: true, reason: 'Liste : Vigie menaces' });
    expect(observation(d)).toBe('Appli a tenté de joindre le domaine sms-relay.cheap-gw.top de la liste de menaces (14 requêtes)');
    expect(detectionDomains(d)).toEqual(['sms-relay.cheap-gw.top']);
    expect(evidenceItems(d)).toContainEqual({ label: 'Bloqué par AdGuard', value: 'oui' });
  });
  it('upload_spike sans médiane (apprentissage), fanout, dns_bypass, mail_ports', () => {
    expect(observation(det('detect.upload_spike', { tx_bytes: 52_428_800, threshold_bytes: 10_485_760, learning: true }))).toMatch(/50\sMio en une heure \(au-delà du seuil de 10\sMio ; pas encore assez d'historique pour une médiane\)/);
    expect(observation(det('detect.fanout', { addresses: 150, connections: 400, threshold: 100 }))).toBe("Appli s'est connectée à 150 adresses différentes en une heure");
    expect(observation(det('detect.dns_bypass', { connections: 9, resolvers: ['1.1.1.1:853'], providers: ['Cloudflare'] }))).toContain('(Cloudflare)');
    expect(observation(det('detect.mail_ports', { connections: 30, addresses: 4, ports: [25] }))).toContain('(port 25)');
  });
  it('sms_abuse : motifs « pas l’application SMS par défaut » et « volume »', () => {
    expect(observation(det('detect.sms_abuse', { reason: 'not_default_sms_app', sent: 40, background: 40, default_sms_app: ['com.samsung.android.messaging'] }))).toBe(
      "Appli a envoyé 40 SMS, dont 40 en arrière-plan alors que ce n'est pas l'application SMS par défaut",
    );
    expect(observation(det('detect.sms_abuse', { reason: 'volume', sent: 900, background: 0 }))).toBe('Appli a envoyé 900 SMS : un volume anormal');
    expect(observation(det('detect.sms_abuse', { reason: 'not_default_sms_app', sent: 1136, background: 1136, rejected: 354 }))).toMatch(/, et a tenté d'en envoyer 354 de plus, refusés par le système alors que/);
    expect(evidenceItems(det('detect.sms_abuse', { reason: 'volume', sent: 9 }))).toContainEqual({ label: 'Motif', value: 'volume quotidien dépassé' });
  });
  it('new_app_risky : profil à risque ou capacité (clé du collecteur traduite)', () => {
    expect(observation(det('detect.new_app_risky', { trigger: 'capability', capability: 'permission:SEND_SMS' }))).toBe('Appli, installée depuis moins de 24 h, a obtenu une capacité sensible : envoi de SMS');
    expect(observation(det('detect.new_app_risky', { trigger: 'capability', capability: 'role:wallet' }))).toContain('role:wallet');
    const items = evidenceItems(det('detect.new_app_risky', { trigger: 'high_risk', level: 'high', score: 90, reasons: ['combo_sms_fraud', 'zzz'] }));
    expect(items).toContainEqual({ label: 'Déclencheur', value: 'profil à risque élevé' });
    expect(items.find((i) => i.label === 'Raisons')?.value).toBe('Profil de fraude au SMS, zzz');
  });
});

describe('opsBlindSpot', () => {
  it('se tait seulement quand le collecteur app.ops tourne', async () => {
    const { opsBlindSpot } = await import('./detections.ts');
    expect(opsBlindSpot('running')).toBeNull();
    for (const state of ['disabled', 'unavailable', undefined, 'autre']) {
      const text = opsBlindSpot(state);
      expect(text).toContain('SMS');
      expect(text).toContain('aucune détection');
    }
    expect(opsBlindSpot('unavailable')).toContain('DUMP');
  });
});

describe('détections du §11.4 (sans app.ops)', () => {
  it('sms_permission : une revue, avec renvoi vers la garde SMS', () => {
    const d = det('detect.sms_permission', { permission: 'SEND_SMS' });
    expect(observation(d)).toBe('Appli peut envoyer des SMS sans passer par votre messagerie ; est-ce voulu ?');
    const i = typeInfo('detect.sms_permission');
    expect(i.review).toBe(true);
    expect(i.guard).toBe('sms');
    expect(i.why).toContain('revue');
    expect(i.mutable).not.toBe(false);
  });
  it('default_app_changed : phrase par rôle, ancienne application, preuve aplatie', () => {
    const sms = det('detect.default_app_changed', { role: 'sms', old: 'com.samsung.android.messaging', new: 'com.exemple.app', risk: { score: 88, level: 'high', reasons: ['combo_sms_fraud'] } }, { severity: 3 });
    expect(observation(sms)).toBe("Appli est devenue l'application SMS par défaut (à la place de com.samsung.android.messaging)");
    expect(observation(det('detect.default_app_changed', { role: 'keyboard' }))).toBe('Appli est devenue le rôle « Clavier » par défaut');
    expect(observation(det('detect.default_app_changed', {}, { summary: 'Rôle changé' }))).toBe('Rôle changé');
    const items = evidenceItems(sms);
    expect(items).toContainEqual({ label: 'Rôle', value: 'Application SMS' });
    expect(items).toContainEqual({ label: 'Risque : score', value: '88' });
    expect(items).toContainEqual({ label: 'Risque : raisons', value: 'Profil de fraude au SMS' });
    expect(typeInfo('detect.default_app_changed').why).toContain('chevaux de Troie SMS');
  });
  it('flood : sans application, plafond lu', () => {
    expect(observation(det('detect.flood', { count: 412, limit: 200 }, { package: undefined, label: undefined } as never))).toBe('Plus de 200 détections en une journée sur cet appareil (412 produites)');
    expect(observation(det('detect.flood', { suppressed: 37, limit: 200 }, { package: undefined, label: undefined } as never))).toBe('Plus de 200 détections en une journée sur cet appareil : 37 de plus non enregistrées');
    expect(observation(det('detect.inventory_mismatch', {}))).toContain('déclarée application du système');
    expect(isMutable({ type: 'detect.inventory_mismatch', package: 'p' })).toBe(false);
    expect(observation(det('detect.flood', {}))).toContain('Plus de 200');
  });
  it('types non masquables : sms_abuse, default_app_changed, flood ; sans application : rien à masquer', () => {
    expect(isMutable({ type: 'detect.dns_bypass', package: 'p' })).toBe(true);
    expect(isMutable({ type: 'detect.sms_permission', package: 'p' })).toBe(true);
    expect(isMutable({ type: 'detect.sms_abuse', package: 'p' })).toBe(false);
    expect(isMutable({ type: 'detect.default_app_changed', package: 'p' })).toBe(false);
    expect(isMutable({ type: 'detect.flood', package: 'p' })).toBe(false);
    expect(isMutable({ type: 'detect.fanout' })).toBe(false);
    expect(isMutable({ type: 'detect.inconnu', package: 'p' })).toBe(true);
  });
  it('récurrence, sourdine et mise à jour lues sur la détection', () => {
    const d = normalizeDetection({ id: 'a', ts: '2026-11-16T10:00:00Z', type: 'detect.dns_bypass', severity: 1, recurring: true, muted: true, updated_at: '2026-11-16T11:00:00Z' });
    expect(d).toMatchObject({ recurring: true, muted: true, updated_at: '2026-11-16T11:00:00Z' });
    expect(normalizeDetection({ id: 'a', ts: 't', type: 'detect.x', evidence: { recurring: true } })?.recurring).toBe(true);
    expect(normalizeDetection({ id: 'a', ts: 't', type: 'detect.x' })?.muted).toBeUndefined();
  });
  it('compte hors sourdine : une détection en sourdine ne change ni le verdict ni l’application la plus préoccupante', () => {
    const l = [{ ...det('detect.sms_permission', {}), muted: true, id: '1' }, det('detect.fanout', {}, { id: '2', severity: 1 })];
    expect(countBySeverity(l)).toEqual({ critical: 0, warning: 0, notable: 1, info: 0, total: 1 });
    expect(countBySeverity([{ ...det('detect.fanout', {}), muted: true }])).toMatchObject({ total: 0 });
    expect(active(l)).toHaveLength(1);
    expect(groupByPackage([{ ...det('detect.fanout', {}), muted: true }])).toEqual([]);
    expect(headline(countBySeverity([{ ...det('detect.fanout', {}), muted: true }]))).toEqual({ tone: 'ok', text: 'Rien à signaler' });
  });
  it('sourdines : lecture tolérante, application aux détections déjà créées, événements du flux', () => {
    const m = parseMutes({ mutes: [{ type: 'detect.dns_bypass', package: 'com.android.chrome', reason: 'voulu', created_at: '2026-11-16T10:00:00Z', created_by: 'admin' }, { type: 'x' }, 4, null] });
    expect(m).toEqual([{ type: 'detect.dns_bypass', package: 'com.android.chrome', reason: 'voulu', created_at: '2026-11-16T10:00:00Z', created_by: 'admin' }]);
    expect(parseMutes([{ type: 'a', package: 'b' }])).toHaveLength(1);
    expect(parseMutes('oops')).toEqual([]);
    expect(parseMutes(undefined)).toEqual([]);
    const l = [det('detect.dns_bypass', {}, { id: '1', package: 'com.android.chrome' }), det('detect.dns_bypass', {}, { id: '2', package: 'autre' }), det('detect.fanout', {}, { id: '3', package: 'com.android.chrome' })];
    expect(applyMutes(l, m).map((d) => !!d.muted)).toEqual([true, false, false]);
    expect(applyMutes(l, [])).toBe(l);
    expect(isMuteEvent('detect.muted')).toBe(true);
    expect(isMuteEvent('detect.fanout')).toBe(false);
    const ev: WatchpostEvent = { id: 'E', ts: '2026-11-16T10:00:00Z', type: 'detect.muted', sev: 0, data: { package: 'p' } };
    expect(detectionFromEvent(ev)).toBeUndefined();
  });
  it('une mise à jour du flux (update + detection_id) remplace la détection existante au lieu d’en créer une autre', () => {
    const base = det('detect.threat_domain', { domains: ['a.top'], domain_count: 1 }, { id: 'D1', ts: '2026-11-16T08:00:00Z' });
    const ev: WatchpostEvent = { id: 'E9', ts: '2026-11-16T12:00:00Z', type: 'detect.threat_domain', sev: 3, device_id: 'dev', data: { update: true, detection_id: 'D1', package: 'com.exemple.app', evidence: { domains: ['a.top', 'b.top'], domain_count: 2 }, window_from: '2026-11-16T00:00:00Z', window_to: '2026-11-17T00:00:00Z' } };
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
  it('messages d’erreur de la sourdine', () => {
    expect(muteErrorMessage({ status: 400, code: 'not_mutable', message: 'type non masquable' })).toContain('ne peut pas être mise en sourdine');
    expect(muteErrorMessage({ status: 404, code: 'not_found', message: 'x' })).toContain('§11.4');
    expect(muteErrorMessage({ status: 0, code: 'network', message: 'Serveur injoignable' })).toBe('Serveur injoignable');
  });
});

describe('ce qui est surveillé et ce qui ne l’est pas (§11.4)', () => {
  it('sans app_ops : dit que les envois ne sont pas vus, ce qui est surveillé quand même, et que la garde SMS est la vraie protection', () => {
    for (const state of ['disabled', 'unavailable', undefined, 'autre']) {
      const sc = monitoringScope(state);
      expect(sc.blind).toContain('envois de SMS eux-mêmes');
      expect(sc.blind).toContain("aucune détection d’envoi");
      expect(sc.watched).toContain("permission d'envoyer des SMS");
      expect(sc.watched).toContain("changement d'application SMS");
      expect(sc.guard).toContain('garde SMS');
      expect(sc.ops).toBeNull();
    }
    expect(monitoringScope('unavailable').blind).toContain('DUMP');
  });
  it('avec app_ops en marche : plus d’angle mort annoncé, mais « en marche » ne prouve pas que des données arrivent', () => {
    const sc = monitoringScope('running');
    expect(sc.blind).toBeNull();
    expect(sc.ops).toContain('ne prouve pas que des données arrivent');
    expect(sc.guard).toContain('garde SMS');
    expect(sc.watched).toContain('Surveillé dans tous les cas');
  });
});

describe('preuves §11.4 au format du collecteur', () => {
  it('sms_permission et default_app_changed : profil de risque à plat, dates, origine, capacités accordées', () => {
    const items = evidenceItems(det('detect.sms_permission', { permission: 'SEND_SMS', level: 'high', score: 91, reasons: ['combo_sms_fraud', 'sms_send'], source: 'permission_changed', since: '2026-11-15T13:53:20.157Z', default_sms_app: ['com.samsung.android.messaging'] }));
    expect(items).toContainEqual({ label: 'Niveau de risque', value: 'Élevé' });
    expect(items).toContainEqual({ label: 'Origine', value: 'permission accordée' });
    expect(items.find((i) => i.label === 'Depuis')?.value).toMatch(/^15\/11\/2026 /);
    expect(items.find((i) => i.label === 'Raisons')?.value).toBe('Profil de fraude au SMS, Peut envoyer des SMS');
    const g = evidenceItems(det('detect.default_app_changed', { role: 'sms', granted: ['accessibility_service', 'overlay'] }));
    expect(g.find((i) => i.label === 'Capacités accordées')?.value).toBe("Service d'accessibilité, Affichage par-dessus les autres applications");
  });
});
