import { describe, expect, it } from 'vitest';
import type { Publisher, TrackingApp, TrackingDomain } from '../api/types.ts';
import {
  availableActions,
  blockedPct,
  domainStatus,
  effectiveOverride,
  filterApps,
  levelTexts,
  mergeDomains,
  parseConflict,
  reasonLabel,
  sortPublishers,
  splitApps,
  totalsOf,
} from './tracking.ts';

describe('niveaux de blocage', () => {
  it('complète les textes manquants et ordonne permissif, équilibré, strict', () => {
    const t = levelTexts([{ key: 'strict' }, { key: 'permissif', description: 'Mon texte' }, { key: 'equilibre', name: 'Équilibré' }]);
    expect(t.map((l) => l.key)).toEqual(['permissif', 'equilibre', 'strict']);
    expect(t[0]?.description).toBe('Mon texte');
    expect(t[0]?.name).toBe('Permissif');
    expect(t[2]?.description).toContain('Certaines applications');
  });
  it('sans liste du collecteur, propose les trois niveaux', () => {
    expect(levelTexts(undefined).map((l) => l.key)).toEqual(['permissif', 'equilibre', 'strict']);
  });
  it('garde un niveau inconnu à la fin, sans le perdre', () => {
    const t = levelTexts([{ key: 'paranoiaque' }, { key: 'strict' }]);
    expect(t.map((l) => l.key)).toEqual(['strict', 'paranoiaque']);
    expect(t[1]?.name).toBe('paranoiaque');
  });
});

describe('motifs et statuts', () => {
  it('traduit les jetons d’AdGuard Home et garde le nom de la liste', () => {
    expect(reasonLabel('FilteredBlackList: AdGuard DNS filter')).toBe('Liste de blocage : AdGuard DNS filter');
    expect(reasonLabel('FilteredBlackList')).toBe('Liste de blocage');
    expect(reasonLabel('NotFilteredWhiteList: @@||x.com^')).toBe('Autorisé par une règle : @@||x.com^');
    expect(reasonLabel('NotFilteredNotFound')).toBe('Aucune liste ne le bloque');
  });
  it('affiche tel quel un motif libre', () => {
    expect(reasonLabel('Liste Vigie : télémétrie Samsung')).toBe('Liste Vigie : télémétrie Samsung');
    expect(reasonLabel(undefined)).toBeUndefined();
    expect(reasonLabel('')).toBeUndefined();
  });
  it('statuts', () => {
    expect(domainStatus('blocked').label).toBe('Bloqué');
    expect(domainStatus('allowed').label).toBe('Autorisé');
    expect(domainStatus('mixed').label).toBe('Mixte');
    expect(domainStatus(undefined).label).toBe('Non évalué');
  });
});

describe('agrégations', () => {
  const pubs: Publisher[] = [
    { key: 'a', name: 'Autres', queries: 10, blocked: 2, allowed: 8, domains: 3, apps: 2 },
    { key: 'g', name: 'Google', queries: 100, blocked: 40, allowed: 60, domains: 20, apps: 5, tx_bytes: 10 },
    { key: 'v', name: 'Vide', queries: 0 },
  ];
  it('part bloquée', () => {
    expect(blockedPct({ queries: 100, blocked: 40, allowed: 60 })).toBe(40);
    expect(blockedPct({ queries: 0, blocked: 0, allowed: 0 })).toBe(0);
    expect(blockedPct({ queries: 50 })).toBeUndefined();
    expect(blockedPct({ queries: 10, blocked: 10 })).toBe(100);
  });
  it('totaux : ceux du collecteur, sinon la somme des éditeurs', () => {
    expect(totalsOf({ queries: 5, blocked: 1, allowed: 4 }, pubs)).toEqual({ queries: 5, blocked: 1, allowed: 4 });
    expect(totalsOf(undefined, pubs)).toEqual({ queries: 110, blocked: 42, allowed: 68 });
    expect(totalsOf(undefined, [{ key: 'x', name: 'X', queries: 3 }])).toEqual({ queries: 3 });
  });
  it('trie les éditeurs et écarte les vides', () => {
    expect(sortPublishers(pubs).map((p) => p.key)).toEqual(['g', 'a']);
  });
  it('fusionne les pages de domaines sans doublon', () => {
    const d = (domain: string): TrackingDomain => ({ domain, queries: 1 });
    expect(mergeDomains([d('a'), d('b')], [d('b'), d('c')]).map((x) => x.domain)).toEqual(['a', 'b', 'c']);
  });
  it('règle effective : la modification locale l’emporte', () => {
    const d: TrackingDomain = { domain: 'x.com', queries: 1, override: 'block' };
    expect(effectiveOverride(d, new Map())).toBe('block');
    expect(effectiveOverride(d, new Map([['x.com', 'allow' as const]]))).toBe('allow');
    expect(effectiveOverride(d, new Map([['x.com', 'default' as const]]))).toBeUndefined();
    expect(effectiveOverride({ domain: 'y.com', queries: 1 }, new Map())).toBeUndefined();
  });
  it('applications d’un domaine : les plus demandeuses puis le reste', () => {
    const s = splitApps([{ package: 'a', count: 1 }, { package: 'b', count: 9 }, { package: 'c', count: 5 }, { package: 'd', count: 2 }], 2);
    expect(s.shown.map((x) => x.package)).toEqual(['b', 'c']);
    expect(s.more).toBe(2);
    expect(splitApps(undefined)).toEqual({ shown: [], more: 0 });
  });
  it('filtre les applications par nom ou paquet', () => {
    const apps: TrackingApp[] = [
      { package: 'com.a', label: 'Alpha', queries: 1 },
      { package: 'com.b', label: 'Beta', queries: 5 },
    ];
    expect(filterApps(apps, '').map((a) => a.package)).toEqual(['com.b', 'com.a']);
    expect(filterApps(apps, 'alp').map((a) => a.package)).toEqual(['com.a']);
    expect(filterApps(apps, 'COM.B').map((a) => a.package)).toEqual(['com.b']);
  });
});

describe('409 domaine indispensable', () => {
  it('reprend le message et les conséquences détaillées', () => {
    const c = parseConflict({ message: 'Domaine indispensable', body: { error: 'essential', impacts: ['Notifications push', 'Mises à jour'] } });
    expect(c.message).toBe('Domaine indispensable');
    expect(c.impacts).toEqual(['Notifications push', 'Mises à jour']);
  });
  it('lit le format du collecteur : breaks = [{ domain, breaks }]', () => {
    const c = parseConflict({
      message: 'bloquer x casserait…',
      body: { error: 'essential_domain', breaks: [{ domain: 'mtalk.google.com', breaks: 'notifications push' }, { domain: 'a.fr' }] },
    });
    expect(c.impacts).toEqual(['mtalk.google.com : notifications push']);
  });
  it('accepte une chaîne et ignore ce qui n’est pas du texte', () => {
    expect(parseConflict({ message: 'm', body: { breaks: 'Les notifications' } }).impacts).toEqual(['Les notifications']);
    expect(parseConflict({ message: 'm', body: { impacts: [1, { a: 1 }] } }).impacts).toEqual([]);
    expect(parseConflict({ message: 'm', body: undefined }).impacts).toEqual([]);
  });
});

describe('actions proposées pour un domaine', () => {
  it('domaine autorisé : bloquer ; avec règle : remettre par défaut', () => {
    expect(availableActions('allowed', undefined)).toEqual(['block']);
    expect(availableActions('allowed', 'block')).toEqual(['default']);
    expect(availableActions('allowed', 'allow')).toEqual(['default']);
  });
  it('domaine bloqué : autoriser', () => {
    expect(availableActions('blocked', undefined)).toEqual(['allow']);
    expect(availableActions('blocked', 'block')).toEqual(['default']);
    expect(availableActions('blocked', 'allow')).toEqual(['default']);
  });
  it('domaine mixte ou sans statut : les deux choix', () => {
    expect(availableActions('mixed', undefined)).toEqual(['block', 'allow']);
    expect(availableActions(undefined, undefined)).toEqual(['block', 'allow']);
    expect(availableActions('mixed', 'block')).toEqual(['allow', 'default']);
  });
});
