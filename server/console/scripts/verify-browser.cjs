/* Vérification réelle dans Chromium (Playwright préinstallé globalement) contre le serveur factice.
 *
 *   npm run build && npm run verify
 *
 * Variables : OUT (dossier des captures), PORT (défaut 8799), TILES=real pour ne pas simuler les tuiles OSM,
 * CSP (remplace la CSP du serveur factice, voir mock/server.ts).
 * Contrôle : absence d'erreur console / d'exception, de violation CSP, de requête hors hôte local et hors tuiles ;
 * parcours de chaque page en clair et en sombre, bureau et téléphone. Sort avec un code non nul en cas d'échec.
 */
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { chromium } = require('playwright');

const ROOT = path.resolve(__dirname, '..');
const OUT = process.env.OUT || path.join(ROOT, 'verify-out');
const PORT = Number(process.env.PORT || 8799);
const BASE = `http://127.0.0.1:${PORT}`;
const TILE_HOST = 'tile.openstreetmap.org';
const REAL_TILES = process.env.TILES === 'real';
fs.mkdirSync(OUT, { recursive: true });

const failures = [];
const notes = [];
const fail = (m) => {
  failures.push(m);
  console.log('  ✗ ' + m);
};
const ok = (m) => console.log('  ✓ ' + m);

function crc32(buf) {
  let c;
  const table = crc32.t || (crc32.t = Array.from({ length: 256 }, (_, n) => { c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; }));
  let crc = 0xffffffff;
  for (const b of buf) crc = table[(crc ^ b) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
/** Tuile 256x256 synthétique (quadrillage clair) : simule OSM sans réseau. */
function tilePng() {
  const w = 256, h = 256;
  const raw = Buffer.alloc((w * 3 + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (w * 3 + 1)] = 0;
    for (let x = 0; x < w; x++) {
      const line = x % 64 === 0 || y % 64 === 0;
      const o = y * (w * 3 + 1) + 1 + x * 3;
      const v = line ? [196, 204, 196] : [236, 240, 232];
      raw[o] = v[0]; raw[o + 1] = v[1]; raw[o + 2] = v[2];
    }
  }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

async function waitHealth() {
  for (let i = 0; i < 50; i++) {
    try { const r = await fetch(`${BASE}/healthz`); if (r.ok) return; } catch { /* attente */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('serveur factice injoignable');
}

async function control(body) {
  await fetch(`${BASE}/__mock/control`, { method: 'POST', body: JSON.stringify(body) });
}

async function main() {
  if (!fs.existsSync(path.join(ROOT, 'dist/index.html'))) throw new Error("dist/ absent : lancez d'abord npm run build");
  const mock = spawn(process.execPath, ['mock/server.ts', '--port', String(PORT), '--static', 'dist'], { cwd: ROOT, stdio: ['ignore', 'pipe', 'inherit'] });
  mock.stdout.on('data', () => undefined);
  try {
    await waitHealth();
    const browser = await chromium.launch({ args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
    const scenarios = [
      { name: 'clair-bureau', scheme: 'light', viewport: { width: 1280, height: 800 } },
      { name: 'sombre-bureau', scheme: 'dark', viewport: { width: 1280, height: 800 } },
      { name: 'clair-telephone', scheme: 'light', viewport: { width: 390, height: 844 }, mobile: true },
      { name: 'sombre-telephone', scheme: 'dark', viewport: { width: 390, height: 844 }, mobile: true },
    ];
    // ONLY=features : seulement les parcours commandes / pistage / notifications (itération rapide).
    if (process.env.ONLY !== 'features') {
      for (const sc of scenarios) await runScenario(browser, sc);
      await runBehaviours(browser);
    }
    await runFeatures(browser);
    await browser.close();
  } finally {
    mock.kill();
  }
  console.log(`\nRésultat : ${failures.length === 0 ? 'OK' : failures.length + ' échec(s)'}`);
  for (const n of notes) console.log('  note : ' + n);
  process.exit(failures.length ? 1 : 0);
}

function instrument(page, label, state) {
  state.requests = state.requests || [];
  state.logs = state.logs || [];
  page.on('console', (m) => state.logs.push(m.text()));
  page.on('request', (r) => state.requests.push({ url: r.url(), body: r.postData() || '', headers: JSON.stringify(r.headers()) }));
  page.on('console', (m) => {
    if (m.type() === 'error' || m.type() === 'warning') {
      const t = m.text();
      // Les tuiles réelles peuvent échouer derrière le proxy de l'environnement : ce n'est pas un défaut du code.
      if (REAL_TILES && /tile\.openstreetmap|Failed to load resource|ERR_/.test(t)) return;
      // Les statuts HTTP >= 400 sont vérifiés via les réponses (voir ci-dessous) : le navigateur les journalise toujours.
      if (/Failed to load resource: the server responded with a status of/.test(t)) return;
      state.errors.push(`[${label}] console.${m.type()}: ${t}`);
    }
  });
  page.on('pageerror', (e) => state.errors.push(`[${label}] exception: ${e.message}`));
  page.on('response', (r) => {
    const u = new URL(r.url());
    if (r.status() >= 400 && u.host === `127.0.0.1:${PORT}`) {
      const expected = state.expected ? state.expected(u.pathname, r.status()) : u.pathname === '/api/console/me' && r.status() === 401;
      if (!expected) state.errors.push(`[${label}] HTTP ${r.status()} ${u.pathname}`);
    }
  });
  page.on('request', (r) => {
    const u = new URL(r.url());
    if (u.protocol === 'data:' || u.protocol === 'blob:') return;
    if (u.host !== `127.0.0.1:${PORT}`) state.hosts.add(u.host);
  });
}

async function newContext(browser, sc, state) {
  const ctx = await browser.newContext({
    viewport: sc.viewport,
    colorScheme: sc.scheme,
    locale: 'fr-FR',
    timezoneId: 'Europe/Paris',
    isMobile: !!sc.mobile,
    hasTouch: !!sc.mobile,
    deviceScaleFactor: sc.mobile ? 2 : 1,
  });
  await ctx.addInitScript(() => {
    window.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`));
  });
  if (!REAL_TILES) {
    const png = tilePng();
    await ctx.route(`https://${TILE_HOST}/**`, (r) => r.fulfill({ status: 200, contentType: 'image/png', body: png, headers: { 'access-control-allow-origin': '*' } }));
  }
  state.ctx = ctx;
  return ctx;
}

async function login(page) {
  await page.goto(`${BASE}/`, { waitUntil: 'load' });
  await page.waitForURL(/\/connexion/, { timeout: 10000 }).catch(() => { throw new Error('pas de redirection vers /connexion'); });
  await page.fill('input[name=username]', 'admin');
  await page.fill('input[name=password]', 'vigie');
  await Promise.all([page.waitForURL(`${BASE}/`), page.click('button[type=submit]')]);
}

async function settle(page, sel) {
  await page.waitForLoadState('load');
  if (sel) await page.waitForSelector(sel, { timeout: 15000 });
  await page.waitForTimeout(700);
}

async function shot(page, sc, name, fullPage = true) {
  const file = path.join(OUT, `${sc.name}-${name}.png`);
  await page.screenshot({ path: file, fullPage });
}

async function runScenario(browser, sc) {
  console.log(`\n== ${sc.name}`);
  const state = { errors: [], hosts: new Set() };
  const ctx = await newContext(browser, sc, state);
  const page = await ctx.newPage();
  instrument(page, sc.name, state);

  await page.goto(`${BASE}/connexion`, { waitUntil: 'load' });
  await page.waitForSelector('input[name=username]');
  await shot(page, sc, '00-connexion');
  await login(page);

  const pages = [
    ['01-vue-ensemble', '/', '.stats'],
    ['02-carte', '/carte', '.replay'],
    ['03-evenements', '/evenements', '.tbl'],
    ['04-reseau', '/reseau', '.rank'],
    ['05-applications', '/applications', '.tbl'],
    ['06-securite', '/securite', '.findings'],
    ['07-alertes', '/alertes', '.tbl'],
    ['08-commandes', '/commandes', '.cmd-list'],
    ['09-pistage', '/pistage', '.trk-dom tbody tr'],
  ];
  for (const [name, url, sel] of pages) {
    await page.goto(`${BASE}${url}`, { waitUntil: 'load' });
    await settle(page, sel);
    await shot(page, sc, name);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    if (overflow > 1) fail(`${sc.name} ${url} : défilement horizontal de la page (${overflow}px)`);
  }

  // Détails interactifs une fois par scénario clair/sombre bureau + téléphone.
  await page.goto(`${BASE}/evenements`, { waitUntil: 'load' });
  await page.click('.tbl tbody .expander');
  await page.waitForSelector('.json-pre');
  await shot(page, sc, '03b-evenement-detail');

  await page.goto(`${BASE}/securite`, { waitUntil: 'load' });
  for (const [tab, name] of [['Journal système', 'log'], ['Caméra et micro', 'capteurs'], ['Certificats d\'AC', 'certs'], ['Cellulaire et BLE', 'radio'], ['Politique appliquée', 'politique'], ['Déverrouillages', 'keyguard']]) {
    await page.click(`role=tab[name="${tab}"]`);
    await settle(page, '.tbl, .findings');
    await shot(page, sc, `06-securite-${name}`);
  }

  await page.goto(`${BASE}/applications`, { waitUntil: 'load' });
  await settle(page, '.tbl');
  for (const [tab, name] of [['Permissions dangereuses', 'permissions'], ['Accès spéciaux', 'acces'], ['Historique', 'historique']]) {
    await page.click(`role=tab[name="${tab}"]`);
    await settle(page);
    await shot(page, sc, `05-applications-${name}`);
  }

  await page.goto(`${BASE}/reseau`, { waitUntil: 'load' });
  await settle(page, '.rank');
  await page.click('.rank .linkish[aria-pressed]');
  await page.waitForSelector('.two-col .rank', { timeout: 20000 });
  await settle(page);
  await shot(page, sc, '04b-reseau-app');

  // Pistage : onglet Applications, application dépliée.
  await page.goto(`${BASE}/pistage`, { waitUntil: 'load' });
  await settle(page, '.trk-dom tbody tr');
  await page.click('role=tab[name="Applications"]');
  await page.waitForSelector('.trk-apps > li');
  await page.click('.trk-app-head >> nth=0');
  await page.waitForSelector('.trk-app-body');
  await shot(page, sc, '09-pistage-applications');

  // Applications : notifications (contenu, contenu masqué, texte hostile non interprété).
  await page.goto(`${BASE}/applications`, { waitUntil: 'load' });
  await settle(page, '.tbl');
  await page.click('role=tab[name="Notifications"]');
  await page.waitForSelector('.rank li');
  await page.waitForSelector('.tbl tbody tr');
  await settle(page);
  await shot(page, sc, '05-applications-notifications');

  // Carte : fournisseurs de position.
  await page.goto(`${BASE}/carte`, { waitUntil: 'load' });
  await settle(page, '.replay');
  await shot(page, sc, '02-carte-fournisseurs');

  const csp = await page.evaluate(() => window.__csp);
  if (csp.length) fail(`${sc.name} : violations CSP : ${[...new Set(csp)].join(' | ')}`);
  else ok('aucune violation CSP');
  const extra = [...state.hosts].filter((h) => h !== TILE_HOST);
  if (extra.length) fail(`${sc.name} : requêtes vers des hôtes tiers : ${extra.join(', ')}`);
  else ok(`hôtes contactés : 127.0.0.1${state.hosts.size ? ' + ' + [...state.hosts].join(', ') : ''}`);
  if (state.errors.length) for (const e of state.errors) fail(e);
  else ok('aucune erreur console ni exception');
  await ctx.close();
}

async function runBehaviours(browser) {
  console.log('\n== comportements (clair, bureau)');
  const sc = { name: 'comportement', scheme: 'light', viewport: { width: 1280, height: 800 } };
  const state = {
    errors: [],
    hosts: new Set(),
    // Statuts d'erreur provoqués volontairement par ce test (session expirée, panne simulée, mauvais mot de passe).
    expected: (p, st) => (st === 401 && /^\/api\/console\/(me|login|devices|events|stats|apps|posture|alerts|locations)/.test(p)) || (st === 500 && p.startsWith('/api/console/stats/top')),
  };
  const ctx = await newContext(browser, sc, state);
  const page = await ctx.newPage();
  instrument(page, 'comportement', state);
  await login(page);

  // Bascule de thème : cycle auto -> clair -> sombre -> auto.
  const attr = () => page.evaluate(() => document.documentElement.getAttribute('data-theme'));
  await page.click('button[aria-label^="Thème"]');
  if ((await attr()) !== 'light') fail('bascule de thème : attendu light');
  await page.click('button[aria-label^="Thème"]');
  if ((await attr()) !== 'dark') fail('bascule de thème : attendu dark');
  else ok('bascule de thème');
  await page.reload({ waitUntil: 'load' });
  if ((await attr()) !== 'dark') fail('thème non mémorisé après rechargement');
  else ok('thème mémorisé');
  await page.click('button[aria-label^="Thème"]');

  // Carte : curseur temporel et lecture.
  await page.goto(`${BASE}/carte`, { waitUntil: 'load' });
  await settle(page, '.replay');
  const count0 = await page.textContent('.replay-info');
  await page.fill('input[type=range]', '10').catch(async () => {
    await page.$eval('input[type=range]', (el) => { el.value = '10'; el.dispatchEvent(new Event('input', { bubbles: true })); });
  });
  await page.waitForTimeout(300);
  const count1 = await page.textContent('.replay-info');
  if (count0 === count1) fail('curseur temporel : aucun changement'); else ok('curseur temporel');
  await page.click('button:has-text("Rejouer")');
  await page.waitForTimeout(900);
  await page.click('button:has-text("Pause")');
  ok('lecture du trajet');
  const gapItems = await page.locator('.gap-list li').count();
  notes.push(`carte 24 h : ${gapItems} trou(s) de données listé(s)`);
  await page.click('button.seg-btn:has-text("7 jours")');
  await settle(page, '.gap-list li');
  await page.screenshot({ path: path.join(OUT, 'carte-7j-trous.png'), fullPage: true });
  const silent = await page.locator('.gap-list li.is-silent').count();
  if (silent < 1) fail('carte 7 j : aucun trou « sans événement » détecté'); else ok(`carte 7 j : ${silent} trou(s) sans événement`);

  // Événements : filtre, sévérité, direct.
  await page.goto(`${BASE}/evenements`, { waitUntil: 'load' });
  await settle(page, '.tbl');
  await page.click('.chip-btn:has-text("Sécurité")');
  await page.selectOption('select >> nth=0', { index: 0 }).catch(() => undefined);
  await settle(page, '.tbl');
  const rows = await page.locator('.tbl tbody tr').count();
  if (rows < 1) fail('filtre par domaine : aucune ligne'); else ok(`filtre par domaine : ${rows} lignes`);
  await page.click('.chip-btn:has-text("Effacer le filtre")');
  await page.check('label.check input[type=checkbox]');
  await page.waitForSelector('.live-dot:not(.is-off)', { timeout: 10000 });
  await page.waitForSelector('.new-row', { timeout: 15000 });
  ok('mode direct : événements reçus par SSE');
  await page.screenshot({ path: path.join(OUT, 'evenements-direct.png') });
  await page.uncheck('label.check input[type=checkbox]');

  // Type inconnu / data partielle : repli JSON, pas de plantage.
  await page.click('button.seg-btn:has-text("7 jours")');
  await page.fill('input[list=event-types]', 'experimental.');
  await page.waitForSelector('.tbl tbody tr:has-text("experimental.future_probe")', { timeout: 15000 });
  await page.click('.tbl tbody .expander');
  const j = await page.textContent('.json-pre');
  if (!j || !j.includes('future_probe')) fail('type inconnu : JSON brut non affiché'); else ok('type inconnu : JSON brut affiché');
  await page.fill('input[list=event-types]', 'location.fix');
  await page.fill('input[type=search]', '48.86');
  await settle(page, '.tbl');
  ok('data partielle (location.fix sans lon) : pas de plantage');

  // Alertes : wazuh false.
  await control({ wazuh: false });
  await page.goto(`${BASE}/alertes`, { waitUntil: 'load' });
  await page.waitForSelector('text=Wazuh non configuré');
  await page.screenshot({ path: path.join(OUT, 'alertes-sans-wazuh.png') });
  ok('alertes : wazuh=false géré');
  await control({ wazuh: true });

  // Erreur serveur : état d'erreur + Réessayer.
  await control({ fail: ['/stats/top'] });
  await page.goto(`${BASE}/reseau`, { waitUntil: 'load' });
  await page.waitForSelector('.state-error button:has-text("Réessayer")');
  await page.screenshot({ path: path.join(OUT, 'reseau-erreur.png') });
  ok('état d\'erreur avec réessai');
  await control({ fail: [] });

  // Appareil sans données : états vides.
  await page.goto(`${BASE}/`, { waitUntil: 'load' });
  await page.selectOption('select[aria-label=Appareil]', { label: 'ancien-s23 (révoqué)' });
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(OUT, 'appareil-vide.png'), fullPage: true });
  for (const u of ['/carte', '/evenements', '/reseau', '/applications', '/securite']) {
    await page.goto(`${BASE}${u}`, { waitUntil: 'load' });
    await page.waitForTimeout(500);
    const empty = await page.locator('.state-empty, .state-error').count();
    if (!empty) fail(`appareil sans données : ${u} sans état vide`);
  }
  ok('appareil sans données : états vides');
  await page.selectOption('select[aria-label=Appareil]', { label: 's25' });

  // Session expirée : retour à la connexion.
  await page.goto(`${BASE}/`, { waitUntil: 'load' });
  await page.waitForSelector('.sidenav');
  await page.waitForSelector('.stats');
  await control({ expire: true });
  await page.click('.sidenav a:has-text("Événements")');
  await page.waitForURL(/\/connexion/);
  const notice = await page.textContent('.login-card');
  if (!notice.includes('expiré')) fail('session expirée : message absent'); else ok('session expirée -> connexion avec message');
  await page.fill('input[name=username]', 'admin');
  await page.fill('input[name=password]', 'mauvais');
  await page.click('button[type=submit]');
  await page.waitForSelector('.state-error');
  ok('mauvais mot de passe : erreur affichée');

  // Navigation clavier : le lien d'évitement est le premier élément focalisable.
  await page.goto(`${BASE}/connexion`, { waitUntil: 'load' });
  const active = await page.evaluate(() => document.activeElement && document.activeElement.getAttribute('name'));
  if (active !== 'username') fail('focus initial de la connexion'); else ok('focus initial sur l\'identifiant');

  const csp = await page.evaluate(() => window.__csp);
  if (csp.length) fail(`comportements : violations CSP : ${[...new Set(csp)].join(' | ')}`);
  for (const e of state.errors) fail(e);
  const extra = [...state.hosts].filter((h) => h !== TILE_HOST);
  if (extra.length) fail(`comportements : hôtes tiers : ${extra.join(', ')}`);
  await ctx.close();
}

// ---------------------------------------------------------------------------------------------------
// Commandes à distance, pistage, notifications : comportements de bout en bout contre le serveur factice.
const RIGHT_CODE = 'correct horse battery staple';
const WRONG_CODE = 'mauvais code 987654';

async function runFeatures(browser) {
  console.log('\n== commandes, pistage, notifications (clair, bureau)');
  const sc = { name: 'fonctions', scheme: 'light', viewport: { width: 1280, height: 900 } };
  const state = {
    errors: [],
    hosts: new Set(),
    expected: (p, st) =>
      (st === 401 && p === '/api/console/me') ||
      (st === 409 && (p.startsWith('/api/console/tracking/override') || p.includes('/cancel'))) ||
      (st === 503 && p.startsWith('/api/console/tracking/')) ||
      (st === 400 && p.startsWith('/api/console/commands')) ||
      (st === 429 && p.startsWith('/api/console/commands')),
  };
  const ctx = await newContext(browser, sc, state);
  const page = await ctx.newPage();
  instrument(page, 'fonctions', state);
  await login(page);
  await control({ quiet: true, channel: 'stream', adguard: true, agent: { disabled: false, wipe_allowed: false, code_configured: true, device_owner: true, locate_fail: false, deliver_ms: 300, exec_ms: 500 } });

  const rowOf = (label) => page.locator('.cmd-tbl tbody tr', { hasText: label }).first();
  const waitStatus = (label, text, timeout = 15000) =>
    page.waitForFunction(([l, t]) => [...document.querySelectorAll('.cmd-tbl tbody tr')].some((r) => r.textContent.includes(l) && r.textContent.includes(t)), [label, text], { timeout });

  // ---- Canal et commande simple
  await page.goto(`${BASE}/commandes`, { waitUntil: 'load' });
  await settle(page, '.cmd-list');
  if (!(await page.textContent('.main')).includes('Connecté')) fail('commandes : état du canal « Connecté » absent'); else ok('canal connecté affiché');
  await page.click('button:has-text("Vibrer"):not(:has-text("aussi"))');
  await page.waitForSelector('.cmd-tbl tbody tr:first-child:has-text("Vibrer")');
  await waitStatus('Vibrer', 'Exécutée');
  ok('vibrer : en attente -> remise -> exécutée (suivi en direct)');
  // valeur hors bornes : bouton désactivé
  await page.fill('.cmd-row:has-text("Sonner") input[type=number]', '999');
  if (!(await page.locator('.cmd-row:has-text("Sonner") button.btn-primary').isDisabled())) fail('sonner : durée 999 acceptée'); else ok('sonner : durée hors bornes refusée par l\'interface');
  await page.fill('.cmd-row:has-text("Sonner") input[type=number]', '20');
  await page.click('.cmd-row:has-text("Sonner") button.btn-primary');
  await waitStatus('Sonner', 'Exécutée');

  // ---- Localiser : la carte se met à jour à l'arrivée de la position
  const before = await page.textContent('[data-testid=pos-info]');
  await page.click('button:has-text("Localiser maintenant")');
  await page.waitForSelector('text=en attente de la nouvelle position');
  await page.waitForSelector('text=Nouvelle position reçue : la carte est à jour', { timeout: 20000 });
  const after = await page.textContent('[data-testid=pos-info]');
  if (before === after) fail('localiser : la position affichée n\'a pas changé'); else ok('localiser : position mise à jour par le flux SSE (' + after.trim().slice(0, 60) + '…)');
  await page.waitForSelector('[data-testid=pos-info] .badge:has-text("GPS")');
  await shot(page, sc, '08-commandes-localisation', false);

  // ---- Annulation tant que « En attente »
  await control({ channel: 'offline' });
  await page.reload({ waitUntil: 'load' });
  await settle(page, '.cmd-list');
  if (!(await page.textContent('.main')).includes('Hors ligne')) fail('canal hors ligne non affiché'); else ok('canal hors ligne affiché');
  await page.click('button:has-text("Arrêter la sonnerie")');
  await page.waitForSelector('.cmd-tbl tbody tr:first-child:has-text("En attente")');
  await page.screenshot({ path: path.join(OUT, 'commandes-hors-ligne-attente.png'), fullPage: true });
  await page.click('.cmd-tbl tbody tr:first-child button:has-text("Annuler")');
  await waitStatus('Arrêter la sonnerie', 'Annulée');
  ok('commande en attente annulée');
  await control({ channel: 'poll' });
  await page.reload({ waitUntil: 'load' });
  await settle(page, '.cmd-list');
  if (!(await page.textContent('.main')).includes('Interrogation')) fail('mode interrogation non affiché'); else ok('mode interrogation affiché');
  await control({ channel: 'stream' });

  // ---- Horloge du navigateur décalée : avertissement, puis refus clair du serveur (issued_at à plus de 10 min)
  await control({ clock_skew_ms: 2 * 3600_000 });
  await page.reload({ waitUntil: 'load' });
  await settle(page, '.cmd-list');
  await page.waitForSelector('.state-warn:has-text("horloge de cet ordinateur")');
  await page.click('button:has-text("Vibrer"):not(:has-text("aussi"))');
  await page.waitForSelector('.state-error:has-text("Horloge de cet ordinateur décalée")');
  ok('horloge décalée : avertissement préalable et refus du serveur traduit en message clair');
  await control({ clock_skew_ms: 0 });
  await page.reload({ waitUntil: 'load' });
  await settle(page, '.cmd-list');

  // ---- Verrouillage : mauvais code (bad_signature), puis bon code
  const sensitiveSteps = async (code, message) => {
    await page.click('button:has-text("Verrouiller…")');
    await page.waitForSelector('dialog[open]');
    await page.fill('dialog textarea', message);
    const btn = page.locator('dialog button:has-text("Signer et envoyer")');
    if (!(await btn.isDisabled())) fail('verrouillage : bouton actif sans confirmation ni code');
    await page.check('dialog input[type=checkbox]');
    await page.fill('#cmd-code', 'court');
    if (!(await btn.isDisabled())) fail('verrouillage : code de moins de 12 caractères accepté');
    await page.fill('#cmd-code', code);
    await btn.click();
    await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 20000 });
  };
  await page.goto(`${BASE}/commandes`, { waitUntil: 'load' });
  await settle(page, '.cmd-list');
  await page.click('button:has-text("Verrouiller…")');
  await page.waitForSelector('dialog[open]');
  await page.screenshot({ path: path.join(OUT, 'commandes-dialogue-verrouiller.png') });
  await page.keyboard.press('Escape');
  await page.waitForSelector('dialog[open]', { state: 'detached' });
  ok('dialogue de verrouillage : Échap ferme');
  await sensitiveSteps(WRONG_CODE, 'Téléphone perdu, appelez le 01 23 45 67 89');
  await waitStatus('Verrouiller avec message', 'Refusée');
  await page.waitForSelector('.cmd-tbl tbody tr:first-child:has-text("Signature invalide")');
  await page.waitForSelector('.history-warn');
  ok('mauvais code : refus « signature invalide » par le téléphone, avertissement affiché');
  await page.screenshot({ path: path.join(OUT, 'commandes-bad-signature.png'), fullPage: true });
  await sensitiveSteps(RIGHT_CODE, 'Téléphone perdu, appelez le 01 23 45 67 89');
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Exécutée'), null, { timeout: 15000 });
  ok('bon code : verrouillage exécuté (la signature du navigateur est reconnue par l\'agent factice)');
  // effacer le message
  await page.click('button:has-text("Effacer le message…")');
  await page.waitForSelector('dialog[open]');
  await page.fill('#cmd-code', RIGHT_CODE);
  await page.click('dialog button:has-text("Signer et envoyer")');
  await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 20000 });
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Exécutée'), null, { timeout: 15000 });
  ok('effacer le message : exécuté');

  // ---- Effacer le téléphone : parcours en trois étapes, refus « disabled » puis exécution
  const wipeFlow = async (expectDone) => {
    await page.click('button:has-text("Effacer le téléphone…")');
    await page.waitForSelector('dialog[open]');
    const next = page.locator('dialog button:has-text("Continuer")');
    if (!(await next.isDisabled())) fail('effacement : étape 1 franchissable sans confirmation');
    if (expectDone) await page.screenshot({ path: path.join(OUT, 'commandes-effacement-etape1.png') });
    await page.check('dialog input[type=checkbox]');
    await next.click();
    await page.fill('dialog input[type=text]', 'mauvais nom');
    if (!(await next.isDisabled())) fail('effacement : étape 2 franchie avec un mauvais nom');
    await page.fill('dialog input[type=text]', 's25');
    await next.click();
    if (expectDone) await page.screenshot({ path: path.join(OUT, 'commandes-effacement-etape3.png') });
    await page.fill('#cmd-code', RIGHT_CODE);
    await page.click('dialog button:has-text("Signer et effacer")');
    await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 20000 });
  };
  await wipeFlow(true);
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Refusée'), null, { timeout: 15000 });
  if (!(await rowOf('Effacer le téléphone').textContent()).includes('Canal désactivé')) fail('effacement non autorisé : motif « disabled » non traduit'); else ok('effacement non autorisé dans l\'app : refus « Canal désactivé » traduit');
  await control({ agent: { wipe_allowed: true } });
  await wipeFlow(false);
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Exécutée'), null, { timeout: 15000 });
  ok('effacement autorisé : exécuté après le parcours en trois étapes');
  await page.screenshot({ path: path.join(OUT, 'commandes-historique.png'), fullPage: true });

  // ---- Le code ne quitte jamais la page
  const secrets = [RIGHT_CODE, WRONG_CODE];
  const variants = (c) => [c, encodeURIComponent(c), Buffer.from(c).toString('base64'), Buffer.from(c).toString('hex'), c.replace(/ /g, '+')];
  const leaks = [];
  for (const r of state.requests) for (const c of secrets) for (const v of variants(c)) {
    if (r.url.includes(v) || r.body.includes(v) || r.headers.includes(v)) leaks.push(`requête ${r.url} contient « ${v} »`);
  }
  for (const l of state.logs) for (const c of secrets) if (l.includes(c)) leaks.push('journal console : ' + l.slice(0, 80));
  const posts = state.requests.filter((r) => r.url.endsWith('/api/console/commands') && r.body);
  const mockLog = await (await fetch(`${BASE}/__mock/requests`)).json();
  for (const r of mockLog) for (const c of secrets) for (const v of variants(c)) if (r.body.includes(v)) leaks.push('serveur : corps contenant le code');
  const storage = await page.evaluate(async () => {
    const dump = { local: JSON.stringify({ ...localStorage }), session: JSON.stringify({ ...sessionStorage }), cookie: document.cookie, idb: [] };
    try { dump.idb = ((await indexedDB.databases?.()) || []).map((d) => d.name); } catch { /* ignoré */ }
    dump.inputs = [...document.querySelectorAll('input')].map((i) => i.value).join('|');
    return dump;
  });
  for (const c of secrets) for (const part of [storage.local, storage.session, storage.cookie, storage.inputs]) if (part.includes(c)) leaks.push('stockage ou champ contenant le code');
  if (storage.idb.length) leaks.push('IndexedDB créée : ' + storage.idb.join(','));
  if (leaks.length) for (const l of leaks) fail('FUITE DU CODE : ' + l);
  else ok(`le code ne quitte pas la page : ${state.requests.length} requêtes, ${state.logs.length} messages console, ${mockLog.length} corps reçus par le serveur, stockages, cookies et champs inspectés`);
  if (posts.length < 4) fail('commandes sensibles : corps POST attendus non observés');
  else {
    const bodies = posts.map((r) => JSON.parse(r.body));
    const signed = bodies.filter((b) => b.sig);
    const keysOk = signed.length >= 4 && signed.every((b) => Object.keys(b).sort().join() === 'device_id,payload,sig' && typeof b.payload === 'string' && JSON.parse(b.payload).id);
    if (!keysOk) fail('corps d\'une commande signée inattendu'); else ok('corps envoyé : uniquement { device_id, payload (chaîne), sig }');
    if (bodies.filter((b) => !b.sig).some((b) => 'sig' in b)) fail('commande simple avec sig');
  }
  // Journal du serveur : un seul `payload` signé chaque fois (même chaîne que celle de l'historique).

  // ---- Pistage : filtres, actions, 409, niveau, dégradé
  await page.goto(`${BASE}/pistage`, { waitUntil: 'load' });
  await settle(page, '.trk-dom tbody tr');
  await page.click('.trk-pub .linkish >> nth=0');
  await settle(page, '.trk-dom tbody tr');
  const pub1 = await page.locator('.trk-dom tbody tr').count();
  await page.click('.seg-btn:has-text("Bloqués")');
  await settle(page, '.trk-dom tbody tr');
  const blockedRows = await page.locator('.trk-dom tbody tr').allTextContents();
  if (!blockedRows.length || !blockedRows.every((t) => t.includes('Bloqué') || t.includes('Mixte'))) fail('filtre Bloqués : lignes non bloquées'); else ok(`filtres éditeur + bloqués : ${blockedRows.length} domaines (sur ${pub1} de l'éditeur)`);
  await page.click('.seg-btn:has-text("Tous")');
  await page.click('button:has-text("retirer le filtre")');
  await page.fill('input[placeholder^="ex. doubleclick"]', 'pagead2');
  await page.waitForSelector('.trk-dom tbody tr:has-text("pagead2.googlesyndication.com")');
  ok('recherche de domaine');
  await page.fill('input[placeholder^="ex. doubleclick"]', 'www.leboncoin.fr');
  await page.waitForSelector('.trk-dom tbody tr:has-text("www.leboncoin.fr")');
  const row = page.locator('.trk-dom tbody tr', { hasText: 'www.leboncoin.fr' }).first();
  await row.locator('button:has-text("Bloquer")').click();
  await row.locator('button:has-text("Remettre par défaut")').waitFor();
  if (!(await row.textContent()).includes('Règle manuelle : bloquer')) fail('override : badge de règle absent'); else ok('Bloquer : règle enregistrée et affichée');
  await row.locator('button:has-text("Remettre par défaut")').click();
  await row.locator('button:has-text("Bloquer")').waitFor();
  ok('Remettre par défaut : règle retirée');
  await row.locator('button:has-text("Bloquer")').click();
  await row.locator('button:has-text("Remettre par défaut")').waitFor();
  // 409 : domaine indispensable
  await page.fill('input[placeholder^="ex. doubleclick"]', 'mtalk.google.com');
  await page.waitForSelector('.trk-dom tbody tr:has-text("mtalk.google.com")');
  await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().locator('button:has-text("Bloquer")').click();
  await page.waitForSelector('dialog[open]:has-text("indispensable")');
  await page.waitForSelector('dialog[open] li:has-text("notifications push")');
  await page.screenshot({ path: path.join(OUT, 'pistage-409.png') });
  await page.click('dialog button:has-text("Ne pas bloquer")');
  await page.waitForSelector('dialog[open]', { state: 'detached' });
  if ((await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().textContent()).includes('Règle manuelle')) fail('409 : règle créée sans confirmation');
  await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().locator('button:has-text("Bloquer")').click();
  await page.waitForSelector('dialog[open]:has-text("indispensable")');
  await page.click('dialog button:has-text("Bloquer quand même")');
  await page.waitForSelector('dialog[open]', { state: 'detached' });
  await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().locator('button:has-text("Remettre par défaut")').waitFor();
  ok('409 domaine indispensable : détail affiché, refus sans force, blocage avec confirmation');
  await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().locator('button:has-text("Remettre par défaut")').click();
  await page.waitForTimeout(400);
  // Niveau
  await page.fill('input[placeholder^="ex. doubleclick"]', '');
  await page.click('.level:has-text("Strict")');
  await page.click('button:has-text("Appliquer le niveau")');
  await page.waitForSelector('dialog[open]:has-text("Passer au niveau")');
  await page.screenshot({ path: path.join(OUT, 'pistage-niveau-confirmation.png') });
  await page.click('dialog button:has-text("Changer le niveau")');
  await page.waitForSelector('dialog[open]', { state: 'detached' });
  await page.waitForSelector('.level.is-sel:has-text("Strict") .badge:has-text("Actuel")');
  ok('niveau de blocage : confirmation puis changement (strict)');
  await page.click('.level:has-text("Équilibré")');
  await page.click('button:has-text("Appliquer le niveau")');
  await page.click('dialog button:has-text("Changer le niveau")');
  await page.waitForSelector('.level.is-sel:has-text("Équilibré") .badge:has-text("Actuel")');
  // AdGuard indisponible
  await control({ adguard: false });
  await page.reload({ waitUntil: 'load' });
  await page.waitForSelector('.state-warn:has-text("Mode dégradé")');
  await page.waitForSelector('.trk-dom tbody tr');
  const dis = await page.locator('.trk-dom tbody tr button.btn-sm').evaluateAll((els) => els.length === 0 || els.every((e) => e.disabled));
  const lvlDis = await page.locator('fieldset.levels').evaluate((e) => e.disabled);
  const txt = await page.textContent('.main');
  if (!dis || !lvlDis) fail('mode dégradé : actions ou niveau non désactivés'); else ok('adguard=false : vue DNS seule, actions et niveau désactivés avec explication');
  if (txt.includes('Bloquées') && (await page.locator('.trk-pub').textContent()).includes('Bloquées / autorisées')) fail('mode dégradé : colonnes bloqué/autorisé affichées');
  await shot(page, sc, '09-pistage-degrade');
  // AdGuard injoignable mais agrégats déjà stockés : décomptes affichés, actions désactivées
  await control({ adguard: false, stored: true });
  await page.reload({ waitUntil: 'load' });
  await page.waitForSelector('.state-warn:has-text("enregistrés avant la panne")');
  await page.waitForSelector('.trk-dom tbody tr');
  const stDis = await page.locator('.trk-dom tbody tr button.btn-sm').evaluateAll((els) => els.length > 0 && els.every((e) => e.disabled));
  const stCols = await page.locator('.trk-pub').textContent();
  if (!stDis || !stCols.includes('Bloquées / autorisées')) fail('agrégats stockés : décomptes absents ou actions actives'); else ok('adguard=false avec agrégats stockés : décomptes servis, actions désactivées, avertissement');
  await control({ adguard: true, stored: false });

  // ---- Notifications : contenu, masquage, texte hostile affiché comme texte
  await page.goto(`${BASE}/evenements`, { waitUntil: 'load' });
  await settle(page, '.tbl');
  await page.click('button.seg-btn:has-text("7 jours")');
  await page.fill('input[list=event-types]', 'app.notification');
  await page.waitForSelector('.tbl tbody tr:has-text("contenu masqué")', { timeout: 15000 });
  await page.fill('input[type=search]', 'iPhone');
  await page.waitForSelector('.tbl tbody tr:has-text("Gagnez un iPhone")', { timeout: 15000 });
  const hostile = await page.locator('.tbl tbody tr', { hasText: 'Gagnez un iPhone' }).first().textContent();
  const imgs = await page.locator('.main img, .main b').count();
  if (!hostile.includes('<img src=x onerror=alert(1)>') || imgs) fail('notification hostile : balisage interprété'); else ok('notification : titre et texte hostiles affichés comme texte, jamais interprétés');
  if (hostile.includes('‮')) fail('notification : caractère bidirectionnel conservé');
  await page.screenshot({ path: path.join(OUT, 'evenements-notifications.png') });
  await page.goto(`${BASE}/carte`, { waitUntil: 'load' });
  await settle(page, '.replay');
  await page.click('button.seg-btn:has-text("7 jours")');
  await settle(page, '.replay');
  const prov = await page.textContent('.main');
  if (!/Fournisseur/.test(prov) || !prov.includes('Fournisseurs')) fail('carte : fournisseur non indiqué'); else ok('carte : fournisseur de la position indiqué (détail du point, légende, résumé)');
  // Suivi en direct de la carte : une nouvelle position reçue pendant qu'on regarde la trace
  await page.click('button.seg-btn:has-text("24 h")');
  await settle(page, '.replay');
  await page.waitForSelector('[data-testid=live-status]:has-text("connecté")');
  const nBefore = await page.textContent('.replay-info');
  const other = await ctx.newPage();
  instrument(other, 'fonctions-2', state);
  await other.goto(`${BASE}/commandes`, { waitUntil: 'load' });
  await other.waitForSelector('.cmd-list');
  await other.click('button:has-text("Localiser maintenant")');
  await page.waitForSelector('[data-testid=live-status]:has-text("dernière position reçue")', { timeout: 20000 });
  const nAfter = await page.textContent('.replay-info');
  if (nBefore === nAfter) fail('carte : la trace n\'a pas reçu la nouvelle position'); else ok('carte : position reçue en direct ajoutée à la trace après « Localiser maintenant »');
  await page.screenshot({ path: path.join(OUT, 'carte-direct-apres-localisation.png') });
  await other.close();

  const csp = await page.evaluate(() => window.__csp);
  if (csp.length) fail(`fonctions : violations CSP : ${[...new Set(csp)].join(' | ')}`); else ok('aucune violation CSP (WebCrypto, dialogues natifs)');
  for (const e of state.errors) fail(e);
  const extra = [...state.hosts].filter((h) => h !== TILE_HOST);
  if (extra.length) fail(`fonctions : hôtes tiers : ${extra.join(', ')}`); else ok('aucune requête vers un tiers');
  await ctx.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
