/* Parcours de la version 1.2 (détections, profil de risque, opérations sensibles, rôles) contre un VRAI collecteur
 * alimenté par le simulateur avec des scénarios d'attaque (`sim --scenario tout`, voir server/collector/README.md).
 *
 *   REAL_URL=http://127.0.0.1:8097 REAL_PASSWORD=… [REAL_USER=admin] [SCENARIO=tout|sain] [OUT=dossier] node scripts/verify-real-v12.cjs
 *
 * SCENARIO=sain : attend « Rien à signaler » ; SCENARIO=tout (défaut) : attend les huit types de détection. Échoue sur toute erreur
 * console, violation CSP, statut HTTP inattendu ou requête vers un tiers.
 */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const BASE = process.env.REAL_URL || 'http://127.0.0.1:8097';
const USER = process.env.REAL_USER || 'admin';
const PASSWORD = process.env.REAL_PASSWORD || '';
const SCENARIO = process.env.SCENARIO || 'tout';
const OUT = process.env.OUT || path.resolve(__dirname, '../verify-out-real-v12');
fs.mkdirSync(OUT, { recursive: true });
const failures = [];
const fail = (m) => { failures.push(m); console.log('  ✗ ' + m); };
const ok = (m) => console.log('  ✓ ' + m);
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');
const EXTRA = ['sms_permission', 'default_app_changed', 'flood', 'inventory_mismatch'].map((t) => `detect.${t}`);
const TYPES = ['threat_domain', 'upload_spike', 'fanout', 'mail_ports', 'dns_bypass', 'sms_abuse', 'sensor_background', 'new_app_risky'].map((t) => `detect.${t}`);

async function main() {
  const browser = await chromium.launch({ args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
  for (const scheme of ['light', 'dark']) {
    for (const mobile of [false, true]) {
      const tag = `${scheme === 'light' ? 'clair' : 'sombre'}-${mobile ? 'telephone' : 'bureau'}`;
      const ctx = await browser.newContext({
        viewport: mobile ? { width: 390, height: 844 } : { width: 1280, height: 900 }, colorScheme: scheme, locale: 'en-GB', timezoneId: 'Europe/Paris',
        isMobile: mobile, hasTouch: mobile, deviceScaleFactor: mobile ? 2 : 1,
      });
      await ctx.addInitScript(() => { window.__csp = []; document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`)); });
      await ctx.route('https://tile.openstreetmap.org/**', (r) => r.fulfill({ status: 200, contentType: 'image/png', body: PNG, headers: { 'access-control-allow-origin': '*' } }));
      const page = await ctx.newPage();
      const errors = [], hosts = new Set();
      const host = new URL(BASE).host;
      page.on('console', (m) => { if (['error', 'warning'].includes(m.type()) && !/status of (401)/.test(m.text())) errors.push('console: ' + m.text()); });
      page.on('pageerror', (e) => errors.push('exception: ' + e.message));
      page.on('request', (r) => { const u = new URL(r.url()); if (u.protocol.startsWith('http') && u.host !== host) hosts.add(u.host); });
      page.on('response', (r) => { const u = new URL(r.url()); if (r.status() >= 400 && u.host === host && !(r.status() === 401 && u.pathname.endsWith('/me'))) errors.push(`HTTP ${r.status()} ${u.pathname}`); });
      const shot = (name) => page.screenshot({ path: path.join(OUT, `reel-${tag}-${name}.png`), fullPage: true });
      const first = scheme === 'light' && !mobile;
      console.log(`\n== ${tag}`);

      await page.goto(`${BASE}/connexion`, { waitUntil: 'load' });
      await page.fill('input[name=username]', USER);
      await page.fill('input[name=password]', PASSWORD);
      await Promise.all([page.waitForURL(`${BASE}/`), page.click('button[type=submit]')]);
      await page.waitForSelector('[data-testid=verdict]', { timeout: 30000 });
      await page.waitForTimeout(800);
      const ov = await page.textContent('[data-testid=overview-detections]');
      if (first) {
        if (SCENARIO === 'sain') (/Rien à signaler/.test(ov) ? ok : fail)('vue d\'ensemble : « Rien à signaler » (parc sain)');
        else (/à examiner/.test(ov) ? ok : fail)(`vue d'ensemble : ${(ov.match(/\d+ détections? à examiner/) || ['résumé absent'])[0]}`);
      }
      await shot('01-vue-ensemble');

      await page.goto(`${BASE}/detections`, { waitUntil: 'load' });
      await page.waitForSelector('[data-testid=verdict]');
      await page.waitForTimeout(1200);
      const types = new Set(await page.locator('[data-testid=detection]').evaluateAll((els) => els.map((e) => e.getAttribute('data-type'))));
      if (first) {
        if (SCENARIO === 'sain') (types.size === 0 ? ok : fail)(`détections (sain) : ${types.size} type(s) (0 attendu)`);
        else {
          const missing = TYPES.filter((t) => !types.has(t));
          console.log(`  types reçus du vrai collecteur : ${[...types].join(', ')}`);
          if (missing.length) fail(`détections : types absents : ${missing.join(', ')}`); else ok('détections : les huit types du contrat §11.3, produits par le vrai collecteur, affichés');
          const unknown = [...types].filter((t) => !TYPES.includes(t) && !EXTRA.includes(t));
          console.log(`  types du §11.4 reçus : ${[...types].filter((t) => EXTRA.includes(t)).join(', ') || 'aucun'}`);
          if (unknown.length) fail(`détections : types inattendus : ${unknown.join(', ')}`);
          // La phrase construite à partir de la preuve réelle (pas de repli sur le résumé) pour chaque type.
          const sentences = await page.locator('[data-testid=detection]').evaluateAll((els) => els.map((e) => [e.getAttribute('data-type'), e.querySelector('.det-what')?.textContent || '']));
          console.log('  phrases : ' + sentences.slice(0, 14).map(([t, s]) => `${t.slice(7)} → ${s.slice(0, 90)}`).join('\n            '));
        }
      }
      await shot('10-detections');
      if (first && SCENARIO !== 'sain') {
        // Mise en sourdine contre le vrai collecteur : un type masquable, puis levée.
        const target = page.locator('[data-testid=detection]:has([data-testid=mute-btn])').first();
        if (await target.count()) {
          const id = await target.getAttribute('data-id');
          const type = await target.getAttribute('data-type');
          await target.evaluate((el) => { el.querySelector('details').open = true; });
          await target.locator('[data-testid=mute-btn]').click();
          await page.waitForSelector('dialog[open]');
          await page.fill('dialog textarea', 'essai console (vrai collecteur)');
          await page.click('dialog button:has-text("Mettre en sourdine")');
          await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 15000 });
          await page.waitForSelector('[data-testid=mutes-table] tbody tr:has-text("essai console")', { timeout: 15000 });
          await page.waitForFunction((i) => !document.querySelector(`[data-testid=detection][data-id="${i}"]:not([data-muted=true])`), id, { timeout: 10000 });
          ok(`sourdine contre le vrai collecteur (${type}) : posée, détection repliée, listée avec son motif`);
          await page.click('[data-testid=mutes-table] tr:has-text("essai console") button:has-text("Lever la sourdine")');
          await page.waitForSelector(`[data-testid=detection][data-id="${id}"]:not([data-muted=true])`, { timeout: 15000 });
          ok('levée de la sourdine contre le vrai collecteur : détection de nouveau signalée');
        } else fail('aucune détection masquable à essayer contre le vrai collecteur');
        await page.selectOption('select[aria-label="Type de détection"]', 'detect.sms_abuse');
        await page.waitForFunction(() => { const c = [...document.querySelectorAll('[data-testid=detection]')]; return c.length > 0 && c.every((e) => e.getAttribute('data-type') === 'detect.sms_abuse'); }, null, { timeout: 15000 });
        ok('filtre par type contre le vrai collecteur : sms_abuse');
        const sms = await page.textContent('[data-testid=detection]');
        if (!/SMS/.test(sms)) fail('détection sms_abuse sans « SMS »');
        // Fiche de l'application concernée, depuis la détection
        await page.evaluate(() => document.querySelectorAll('[data-testid=detection] details').forEach((d) => { d.open = true; }));
        await page.click('[data-testid=detection] a:has-text("Fiche de l\'application")');
        await page.waitForSelector('.sheet-head h1');
        await page.waitForTimeout(1500);
        const sheet = await page.textContent('.main');
        for (const n of ['Profil de risque', 'Détections concernant cette application', 'Opérations sensibles']) if (!sheet.includes(n)) fail(`fiche : « ${n} » absent`);
        if (!(await page.locator('.det').count())) fail('fiche : aucune détection de l\'application'); else ok('fiche d\'application depuis une détection : profil, détections, opérations');
        await shot('11-fiche');
        await page.reload({ waitUntil: 'load' });
        await page.waitForSelector('.sheet-head h1');
        ok('fiche d\'application rechargée (le vrai serveur répond avec l\'application, pas 404)');
      }

      await page.goto(`${BASE}/applications`, { waitUntil: 'load' });
      await page.waitForSelector('[data-testid=risk-table]', { timeout: 20000 });
      if (first) {
        const nums = (await page.locator('[data-testid=risk-table] tbody .risk-score strong').allTextContents()).map(Number);
        if (nums.length < 5 || nums.some((n, i) => i > 0 && n > nums[i - 1])) fail('risque : tri par score non respecté'); else ok(`risque : ${nums.length} applications triées par score (${nums[0]} … ${nums[nums.length - 1]})`);
        const high = await page.locator('[data-testid=risk-table] tr.risk-high').count();
        const txt = await page.textContent('[data-testid=risk-table]');
        const combos = ['Profil de cheval de Troie bancaire', 'Profil de fraude au SMS', 'Profil de logiciel espion'].filter((c) => txt.includes(c));
        console.log(`  niveaux élevés : ${high} ; combinaisons présentes : ${combos.join(' | ') || 'aucune'}`);
        if (SCENARIO === 'sain' && high) fail('risque : application à risque élevé dans le parc sain');
        const unknown = (await page.locator('[data-testid=risk-table] .reason-chips .badge').allTextContents()).filter((t) => /^[a-z]+(_[a-z]+)+$/.test(t));
        if (unknown.length) fail(`risque : codes de raison non traduits : ${[...new Set(unknown)].join(', ')}`); else ok('risque : toutes les raisons du vrai collecteur sont traduites');
      }
      await shot('05-applications-risque');

      await page.goto(`${BASE}/applications?tab=ops`, { waitUntil: 'load' });
      await page.waitForSelector('[data-testid=ops-cards], [data-testid=ops-empty]', { timeout: 20000 });
      if (first) {
        const present = (await page.locator('[data-testid=ops-cards]').count()) > 0;
        ok(present ? 'opérations sensibles : données du vrai collecteur affichées (' + (await page.locator('[data-testid=ops-table] tbody tr').count()) + ' lignes)' : 'opérations sensibles : état vide explicatif');
      }
      await shot('05-applications-operations');

      await page.goto(`${BASE}/securite?tab=roles`, { waitUntil: 'load' });
      await page.waitForSelector('.card-title:has-text("Rôles actuels")', { timeout: 20000 });
      await page.waitForTimeout(800);
      if (first) {
        const t = await page.textContent('.main');
        ok('rôles par défaut : ' + (/Application SMS/.test(t) ? 'rôles actuels affichés' : 'aucun relevé') + (await page.locator('[data-testid=roles-table]').count() ? ', historique présent' : ', aucun changement'));
      }
      await shot('06-securite-roles');
      await page.goto(`${BASE}/alertes`, { waitUntil: 'load' });
      await page.waitForSelector('.net-intro');
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      if (overflow > 1) fail(`${tag} : défilement horizontal (${overflow}px)`);
      const csp = await page.evaluate(() => window.__csp);
      if (csp.length) fail(`${tag} : violations CSP : ${[...new Set(csp)].join(' | ')}`);
      const extra = [...hosts].filter((h) => h !== 'tile.openstreetmap.org');
      if (extra.length) fail(`${tag} : hôtes tiers : ${extra.join(', ')}`);
      for (const e of errors) fail(`${tag} : ${e}`);
      await ctx.close();
    }
  }
  ok('quatre configurations (clair/sombre, bureau/téléphone) : erreurs console, CSP et tiers contrôlés');
  await browser.close();
  console.log(`\nRésultat : ${failures.length === 0 ? 'OK' : failures.length + ' échec(s)'}`);
  process.exit(failures.length ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(2); });
