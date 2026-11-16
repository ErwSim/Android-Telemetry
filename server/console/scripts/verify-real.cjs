/* Rejoue dans Chromium les parcours commandes / pistage / notifications contre un VRAI collecteur.
 *
 *   REAL_URL=http://127.0.0.1:8090 REAL_PASSWORD=… [REAL_USER=admin] [OUT=dossier] node scripts/verify-real.cjs
 *
 * Prérequis (voir server/collector/README.md) : collecteur lancé avec VIGIE_CONSOLE_DIR=<ce dossier>/dist, un appareil
 * enrôlé et alimenté (`sim --backfill 48h --follow`), et un agent qui interroge /api/v1/commands (le simulateur du
 * collecteur, ou `AGENT_CODE=… node <agent simulé> fichier.vigie`) dont le code de commande est `REAL_CODE`
 * (défaut : « correct horse battery staple »). AdGuard Home n'est pas requis : sans lui on contrôle le mode dégradé.
 * Échoue sur toute erreur console, violation CSP, statut HTTP inattendu ou requête vers un tiers.
 */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const BASE = process.env.REAL_URL || 'http://127.0.0.1:8090';
const USER = process.env.REAL_USER || 'admin';
const PASSWORD = process.env.REAL_PASSWORD || '';
const RIGHT = process.env.REAL_CODE || 'correct horse battery staple';
const WRONG = 'mauvais code 987654';
const OUT = process.env.OUT || path.resolve(__dirname, '../verify-out-real');
fs.mkdirSync(OUT, { recursive: true });
const failures = [];
const fail = (m) => { failures.push(m); console.log('  ✗ ' + m); };
const ok = (m) => console.log('  ✓ ' + m);
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');

async function main() {
  const browser = await chromium.launch({ args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'fr-FR', timezoneId: 'Europe/Paris' });
  await ctx.addInitScript(() => { window.__csp = []; document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`)); });
  await ctx.route('https://tile.openstreetmap.org/**', (r) => r.fulfill({ status: 200, contentType: 'image/png', body: PNG, headers: { 'access-control-allow-origin': '*' } }));
  const page = await ctx.newPage();
  const errors = [], hosts = new Set(), requests = [], logs = [];
  const host = new URL(BASE).host;
  page.on('console', (m) => { logs.push(m.text()); if (['error', 'warning'].includes(m.type()) && !/status of (401|409|503)/.test(m.text())) errors.push('console: ' + m.text()); });
  page.on('pageerror', (e) => errors.push('exception: ' + e.message));
  page.on('request', (r) => { const u = new URL(r.url()); if (u.protocol.startsWith('http') && u.host !== host) hosts.add(u.host); requests.push({ url: r.url(), body: r.postData() || '', headers: JSON.stringify(r.headers()) }); });
  page.on('response', (r) => { const u = new URL(r.url()); if (r.status() >= 400 && u.host === host && !(r.status() === 401 && u.pathname.endsWith('/me')) && !(r.status() === 409 && u.pathname.endsWith('/tracking/override'))) errors.push(`HTTP ${r.status()} ${u.pathname}`); });

  console.log('\n== connexion');
  await page.goto(`${BASE}/connexion`, { waitUntil: 'load' });
  await page.fill('input[name=username]', USER);
  await page.fill('input[name=password]', PASSWORD);
  await Promise.all([page.waitForURL(`${BASE}/`), page.click('button[type=submit]')]);
  await page.waitForSelector('.stats');
  ok('connexion et vue d\'ensemble');
  await page.screenshot({ path: path.join(OUT, 'reel-01-vue-ensemble.png'), fullPage: true });

  console.log('\n== commandes');
  await page.goto(`${BASE}/commandes`, { waitUntil: 'load' });
  await page.waitForSelector('.cmd-list');
  await page.waitForTimeout(2500);
  const main = await page.textContent('.main');
  ok('canal : ' + (['Connecté', 'Interrogation périodique', 'Hors ligne', 'État inconnu'].find((s) => main.includes(s)) || '?'));
  const waitStatus = (label, text, timeout = 30000) => page.waitForFunction(([l, t]) => [...document.querySelectorAll('.cmd-tbl tbody tr')].some((r) => r.textContent.includes(l) && r.textContent.includes(t)), [label, text], { timeout });
  const firstRow = (text, timeout = 30000) => page.waitForFunction((t) => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes(t), text, { timeout });
  await page.click('button:has-text("Vibrer"):not(:has-text("aussi"))');
  await firstRow('Vibrer');
  await waitStatus('Vibrer', 'Exécutée');
  ok('vibrer : exécutée (agent simulé, vrai collecteur)');
  const before = await page.textContent('[data-testid=pos-info]').catch(() => '');
  await page.click('button:has-text("Localiser maintenant")');
  await page.waitForSelector('text=Nouvelle position reçue : la carte est à jour', { timeout: 40000 });
  await page.waitForTimeout(500);
  const after = await page.textContent('[data-testid=pos-info]');
  if (before === after) fail('localiser : position inchangée'); else ok('localiser : position reçue par le vrai flux SSE (' + after.trim().slice(0, 70) + ')');
  await page.screenshot({ path: path.join(OUT, 'reel-02-localisation.png'), fullPage: true });

  const lock = async (code) => {
    await page.click('button:has-text("Verrouiller…")');
    await page.waitForSelector('dialog[open]');
    await page.fill('dialog textarea', 'Téléphone perdu, appelez le 01 23 45 67 89');
    await page.check('dialog input[type=checkbox]');
    await page.fill('#cmd-code', code);
    await page.click('dialog button:has-text("Signer et envoyer")');
    await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 20000 });
  };
  await lock(WRONG);
  await firstRow('Verrouiller');
  await waitStatus('Verrouiller', 'Refusée');
  await page.waitForSelector('.cmd-tbl tbody tr:first-child:has-text("Signature invalide")');
  ok('mauvais code : refus bad_signature constaté par l\'agent, traduit en français');
  await lock(RIGHT);
  await firstRow('Verrouiller');
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Exécutée'), null, { timeout: 30000 });
  ok('bon code : la signature calculée par le navigateur est acceptée par l\'agent (HMAC identique)');
  await page.screenshot({ path: path.join(OUT, 'reel-03-historique.png'), fullPage: true });

  // Annulation : l'agent est arrêté par le script appelant si REAL_PAUSE_AGENT est fourni (sinon on tente à la volée).
  await page.click('button:has-text("Arrêter la sonnerie")');
  await firstRow('Arrêter la sonnerie');
  const cancel = page.locator('.cmd-tbl tbody tr:first-child button:has-text("Annuler")');
  if (await cancel.count()) {
    await cancel.click().catch(() => undefined);
    await page.waitForFunction(() => /Annulée|Exécutée|Remise/.test(document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent || ''), null, { timeout: 15000 });
    ok('annulation : ' + (await page.locator('.cmd-tbl tbody tr:first-child .badge').first().textContent()));
  } else ok('annulation : la commande avait déjà été remise (course avec l\'agent)');

  // Effacement : parcours en trois étapes, refusé par l'agent (effacement non autorisé dans l'app)
  await page.click('button:has-text("Effacer le téléphone…")');
  await page.waitForSelector('dialog[open]');
  await page.check('dialog input[type=checkbox]');
  await page.click('dialog button:has-text("Continuer")');
  const devName = (await page.locator('dialog strong.mono').textContent()).trim();
  await page.fill('dialog input[type=text]', devName);
  await page.click('dialog button:has-text("Continuer")');
  await page.fill('#cmd-code', RIGHT);
  await page.click('dialog button:has-text("Signer et effacer")');
  await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 20000 });
  await firstRow('Effacer le téléphone');
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Refusée'), null, { timeout: 30000 });
  if (!(await page.locator('.cmd-tbl tbody tr:first-child').textContent()).includes('Canal désactivé')) fail('effacement : motif disabled non traduit'); else ok('effacement : parcours en trois étapes, refus « disabled » de l\'agent traduit');

  const secrets = [RIGHT, WRONG];
  const leaks = [];
  for (const r of requests) for (const c of secrets) for (const v of [c, encodeURIComponent(c), Buffer.from(c).toString('base64'), Buffer.from(c).toString('hex')]) if (r.url.includes(v) || r.body.includes(v) || r.headers.includes(v)) leaks.push(r.url);
  for (const l of logs) for (const c of secrets) if (l.includes(c)) leaks.push('console');
  const st = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + document.cookie);
  for (const c of secrets) if (st.includes(c)) leaks.push('stockage');
  if (leaks.length) fail('FUITE DU CODE : ' + leaks.join(', ')); else ok(`le code ne quitte pas la page (${requests.length} requêtes inspectées, stockages et cookies compris)`);

  console.log('\n== pistage');
  await page.goto(`${BASE}/pistage`, { waitUntil: 'load' });
  await page.waitForSelector('.trk-pub, .state-warn, .state-empty', { timeout: 20000 });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUT, 'reel-04-pistage.png'), fullPage: true });
  const ptxt = await page.textContent('.main');
  if (ptxt.includes('Mode dégradé')) ok('AdGuard non configuré : mode dégradé affiché, actions désactivées');
  else ok('AdGuard joignable : vue complète');
  const rows = await page.locator('.trk-dom tbody tr').count();
  ok(`${rows} domaines listés (première page)`);
  if (!ptxt.includes('Mode dégradé')) {
    // AdGuard Home (réel ou faux) joignable : filtres, règle manuelle, 409, niveau.
    await page.click('.seg-btn:has-text("Bloqués")');
    await page.waitForTimeout(1200);
    const bl = await page.locator('.trk-dom tbody tr').allTextContents();
    if (bl.length && bl.every((t) => /Bloqué|Mixte/.test(t))) ok(`filtre Bloqués : ${bl.length} domaines`); else fail('filtre Bloqués incohérent');
    await page.click('.seg-btn:has-text("Tous")');
    await page.fill('input[placeholder^="ex. doubleclick"]', 'mtalk.google.com');
    await page.waitForSelector('.trk-dom tbody tr:has-text("mtalk.google.com")', { timeout: 15000 });
    await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().locator('button:has-text("Bloquer")').click();
    await page.waitForSelector('dialog[open]:has-text("indispensable")');
    await page.screenshot({ path: path.join(OUT, 'reel-04b-pistage-409.png') });
    ok('409 domaine indispensable : ' + (await page.locator('dialog[open] .callout li').allTextContents()).join(' | ').slice(0, 120));
    await page.click('dialog button:has-text("Ne pas bloquer")');
    await page.fill('input[placeholder^="ex. doubleclick"]', 'tracker');
    await page.waitForTimeout(1500);
    let target = page.locator('.trk-dom tbody tr:has(button:has-text("Bloquer"))').first();
    if (!(await target.count())) { await page.fill('input[placeholder^="ex. doubleclick"]', ''); await page.waitForTimeout(1500); target = page.locator('.trk-dom tbody tr:has(button:has-text("Bloquer")):not(:has-text("mtalk"))').first(); }
    const dom = (await target.locator('.c-dom .mono').textContent()).trim();
    await target.locator('button:has-text("Bloquer")').first().click();
    await page.waitForSelector('dialog[open]', { timeout: 3000 }).then(async () => { await page.click('dialog button:has-text("Ne pas bloquer")'); fail('domaine ' + dom + ' signalé indispensable'); }).catch(() => undefined);
    const row = page.locator('.trk-dom tbody tr', { hasText: dom }).first();
    await row.locator('button:has-text("Remettre par défaut")').waitFor({ timeout: 15000 });
    ok('Bloquer ' + dom + ' : règle enregistrée dans AdGuard Home (badge « règle manuelle »)');
    await row.locator('button:has-text("Remettre par défaut")').click();
    await row.locator('button:has-text("Remettre par défaut")').waitFor({ state: 'detached', timeout: 15000 });
    ok('Remettre par défaut : règle retirée');
    // Niveau : on change puis on remet l'ancien
    const cur = (await page.locator('.level.is-sel strong').first().textContent()).trim();
    const other = cur === 'Équilibré' ? 'Strict' : 'Équilibré';
    await page.click(`.level:has-text("${other}")`);
    await page.click('button:has-text("Appliquer le niveau")');
    await page.click('dialog button:has-text("Changer le niveau")');
    await page.waitForSelector(`.level.is-sel:has-text("${other}") .badge:has-text("Actuel")`, { timeout: 120000 });
    ok(`niveau ${cur} -> ${other} appliqué dans AdGuard Home`);
    await page.click(`.level:has-text("${cur}")`);
    await page.click('button:has-text("Appliquer le niveau")');
    await page.click('dialog button:has-text("Changer le niveau")');
    await page.waitForSelector(`.level.is-sel:has-text("${cur}") .badge:has-text("Actuel")`, { timeout: 120000 });
    await page.screenshot({ path: path.join(OUT, 'reel-04c-pistage-niveau.png'), fullPage: true });
    ok(`niveau remis sur ${cur}`);
    await page.fill('input[placeholder^="ex. doubleclick"]', '');
  }
  if (rows > 0) {
    await page.click('role=tab[name="Applications"]');
    await page.waitForSelector('.trk-apps > li', { timeout: 15000 });
    await page.click('.trk-app-head >> nth=0');
    await page.waitForSelector('.trk-app-body');
    ok('vue par application dépliée');
  }

  console.log('\n== notifications et carte');
  await page.goto(`${BASE}/applications`, { waitUntil: 'load' });
  await page.waitForSelector('role=tab[name="Notifications"]');
  await page.click('role=tab[name="Notifications"]');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(OUT, 'reel-05-notifications.png'), fullPage: true });
  ok('onglet Notifications : ' + ((await page.locator('.rank li').count()) + ' application(s) classée(s)'));
  await page.goto(`${BASE}/carte`, { waitUntil: 'load' });
  await page.waitForSelector('.replay');
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUT, 'reel-06-carte.png'), fullPage: true });
  ok('carte chargée, fournisseurs : ' + ((await page.textContent('.main')).match(/Fournisseurs\s+([^\n]*?)(Trous|$)/) || [, '?'])[1].slice(0, 60));

  const csp = await page.evaluate(() => window.__csp);
  if (csp.length) fail('violations CSP : ' + [...new Set(csp)].join(' | ')); else ok('aucune violation CSP');
  const extra = [...hosts].filter((h) => h !== 'tile.openstreetmap.org');
  if (extra.length) fail('hôtes tiers : ' + extra.join(', ')); else ok('aucune requête vers un tiers');
  for (const e of errors) fail(e);
  if (!errors.length) ok('aucune erreur console ni statut HTTP inattendu');
  await browser.close();
  console.log(`\nRésultat : ${failures.length === 0 ? 'OK' : failures.length + ' échec(s)'}`);
  process.exit(failures.length ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(2); });
