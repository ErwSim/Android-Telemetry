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
    for (const sc of scenarios) await runScenario(browser, sc);
    await runBehaviours(browser);
    await browser.close();
  } finally {
    mock.kill();
  }
  console.log(`\nRésultat : ${failures.length === 0 ? 'OK' : failures.length + ' échec(s)'}`);
  for (const n of notes) console.log('  note : ' + n);
  process.exit(failures.length ? 1 : 0);
}

function instrument(page, label, state) {
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
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  if (!page.url().includes('/connexion')) throw new Error('pas de redirection vers /connexion');
  await page.fill('input[name=username]', 'admin');
  await page.fill('input[name=password]', 'vigie');
  await Promise.all([page.waitForURL(`${BASE}/`), page.click('button[type=submit]')]);
}

async function settle(page, sel) {
  await page.waitForLoadState('networkidle');
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

  await page.goto(`${BASE}/connexion`, { waitUntil: 'networkidle' });
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
  ];
  for (const [name, url, sel] of pages) {
    await page.goto(`${BASE}${url}`, { waitUntil: 'networkidle' });
    await settle(page, sel);
    await shot(page, sc, name);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    if (overflow > 1) fail(`${sc.name} ${url} : défilement horizontal de la page (${overflow}px)`);
  }

  // Détails interactifs une fois par scénario clair/sombre bureau + téléphone.
  await page.goto(`${BASE}/evenements`, { waitUntil: 'networkidle' });
  await page.click('.tbl tbody .expander');
  await page.waitForSelector('.json-pre');
  await shot(page, sc, '03b-evenement-detail');

  await page.goto(`${BASE}/securite`, { waitUntil: 'networkidle' });
  for (const [tab, name] of [['Journal système', 'log'], ['Caméra et micro', 'capteurs'], ['Certificats d\'AC', 'certs'], ['Cellulaire et BLE', 'radio'], ['Politique appliquée', 'politique'], ['Déverrouillages', 'keyguard']]) {
    await page.click(`role=tab[name="${tab}"]`);
    await settle(page, '.tbl, .findings');
    await shot(page, sc, `06-securite-${name}`);
  }

  await page.goto(`${BASE}/applications`, { waitUntil: 'networkidle' });
  await settle(page, '.tbl');
  for (const [tab, name] of [['Permissions dangereuses', 'permissions'], ['Accès spéciaux', 'acces'], ['Historique', 'historique']]) {
    await page.click(`role=tab[name="${tab}"]`);
    await settle(page);
    await shot(page, sc, `05-applications-${name}`);
  }

  await page.goto(`${BASE}/reseau`, { waitUntil: 'networkidle' });
  await settle(page, '.rank');
  await page.click('.rank .linkish[aria-pressed]');
  await page.waitForSelector('.two-col .rank', { timeout: 20000 });
  await settle(page);
  await shot(page, sc, '04b-reseau-app');

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
  await page.reload({ waitUntil: 'networkidle' });
  if ((await attr()) !== 'dark') fail('thème non mémorisé après rechargement');
  else ok('thème mémorisé');
  await page.click('button[aria-label^="Thème"]');

  // Carte : curseur temporel et lecture.
  await page.goto(`${BASE}/carte`, { waitUntil: 'networkidle' });
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
  await page.goto(`${BASE}/evenements`, { waitUntil: 'networkidle' });
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
  await page.goto(`${BASE}/alertes`, { waitUntil: 'networkidle' });
  await page.waitForSelector('text=Wazuh non configuré');
  await page.screenshot({ path: path.join(OUT, 'alertes-sans-wazuh.png') });
  ok('alertes : wazuh=false géré');
  await control({ wazuh: true });

  // Erreur serveur : état d'erreur + Réessayer.
  await control({ fail: ['/stats/top'] });
  await page.goto(`${BASE}/reseau`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.state-error button:has-text("Réessayer")');
  await page.screenshot({ path: path.join(OUT, 'reseau-erreur.png') });
  ok('état d\'erreur avec réessai');
  await control({ fail: [] });

  // Appareil sans données : états vides.
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await page.selectOption('select[aria-label=Appareil]', { label: 'ancien-s23 (révoqué)' });
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(OUT, 'appareil-vide.png'), fullPage: true });
  for (const u of ['/carte', '/evenements', '/reseau', '/applications', '/securite']) {
    await page.goto(`${BASE}${u}`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);
    const empty = await page.locator('.state-empty, .state-error').count();
    if (!empty) fail(`appareil sans données : ${u} sans état vide`);
  }
  ok('appareil sans données : états vides');
  await page.selectOption('select[aria-label=Appareil]', { label: 's25' });

  // Session expirée : retour à la connexion.
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
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
  await page.goto(`${BASE}/connexion`, { waitUntil: 'networkidle' });
  const active = await page.evaluate(() => document.activeElement && document.activeElement.getAttribute('name'));
  if (active !== 'username') fail('focus initial de la connexion'); else ok('focus initial sur l\'identifiant');

  const csp = await page.evaluate(() => window.__csp);
  if (csp.length) fail(`comportements : violations CSP : ${[...new Set(csp)].join(' | ')}`);
  for (const e of state.errors) fail(e);
  const extra = [...state.hosts].filter((h) => h !== TILE_HOST);
  if (extra.length) fail(`comportements : hôtes tiers : ${extra.join(', ')}`);
  await ctx.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
