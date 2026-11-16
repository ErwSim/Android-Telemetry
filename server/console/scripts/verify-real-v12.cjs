/* Version 1.2 walkthrough (detections, risk profile, sensitive operations, roles) against a REAL collector
 * fed by the simulator with attack scenarios (`sim --scenario all`, see server/collector/README.md).
 *
 *   REAL_URL=http://127.0.0.1:8097 REAL_PASSWORD=... [REAL_USER=admin] [SCENARIO=all|healthy] [OUT=folder] node scripts/verify-real-v12.cjs
 *
 * SCENARIO=healthy: expects "Nothing to report"; SCENARIO=all (default): expects the eight detection types. Fails on any
 * console error, CSP violation, unexpected HTTP status or request to a third party.
 */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const BASE = process.env.REAL_URL || 'http://127.0.0.1:8097';
const USER = process.env.REAL_USER || 'admin';
const PASSWORD = process.env.REAL_PASSWORD || '';
const SCENARIO = process.env.SCENARIO || 'all';
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
      const tag = `${scheme}-${mobile ? 'phone' : 'desktop'}`;
      const ctx = await browser.newContext({
        viewport: mobile ? { width: 390, height: 844 } : { width: 1280, height: 900 }, colorScheme: scheme, locale: 'en-GB', timezoneId: 'UTC',
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
      const shot = (name) => page.screenshot({ path: path.join(OUT, `real-${tag}-${name}.png`), fullPage: true });
      const first = scheme === 'light' && !mobile;
      console.log(`\n== ${tag}`);

      await page.goto(`${BASE}/login`, { waitUntil: 'load' });
      await page.fill('input[name=username]', USER);
      await page.fill('input[name=password]', PASSWORD);
      await Promise.all([page.waitForURL(`${BASE}/`), page.click('button[type=submit]')]);
      await page.waitForSelector('[data-testid=verdict]', { timeout: 30000 });
      await page.waitForTimeout(800);
      const ov = await page.textContent('[data-testid=overview-detections]');
      if (first) {
        if (SCENARIO === 'healthy') (/Nothing to report/.test(ov) ? ok : fail)('overview: "Nothing to report" (healthy phone)');
        else (/to examine/.test(ov) ? ok : fail)(`overview: ${(ov.match(/\d+ detections? to examine/) || ['summary missing'])[0]}`);
      }
      await shot('01-overview');

      await page.goto(`${BASE}/detections`, { waitUntil: 'load' });
      await page.waitForSelector('[data-testid=verdict]');
      await page.waitForTimeout(1200);
      const types = new Set(await page.locator('[data-testid=detection]').evaluateAll((els) => els.map((e) => e.getAttribute('data-type'))));
      if (first) {
        if (SCENARIO === 'healthy') (types.size === 0 ? ok : fail)(`detections (healthy): ${types.size} type(s) (0 expected)`);
        else {
          const missing = TYPES.filter((t) => !types.has(t));
          console.log(`  types received from the real collector: ${[...types].join(', ')}`);
          if (missing.length) fail(`detections: missing types: ${missing.join(', ')}`); else ok('detections: the eight types of contract §11.3, produced by the real collector, displayed');
          const unknown = [...types].filter((t) => !TYPES.includes(t) && !EXTRA.includes(t));
          console.log(`  §11.4 types received: ${[...types].filter((t) => EXTRA.includes(t)).join(', ') || 'none'}`);
          if (unknown.length) fail(`detections: unexpected types: ${unknown.join(', ')}`);
          // The sentence built from the real evidence (no fallback on the summary) for each type.
          const sentences = await page.locator('[data-testid=detection]').evaluateAll((els) => els.map((e) => [e.getAttribute('data-type'), e.querySelector('.det-what')?.textContent || '']));
          console.log('  sentences: ' + sentences.slice(0, 14).map(([t, s]) => `${t.slice(7)} → ${s.slice(0, 90)}`).join('\n            '));
        }
      }
      await shot('10-detections');
      if (first && SCENARIO !== 'healthy') {
        // Muting against the real collector: a mutable type, then lifting.
        const target = page.locator('[data-testid=detection]:has([data-testid=mute-btn])').first();
        if (await target.count()) {
          const id = await target.getAttribute('data-id');
          const type = await target.getAttribute('data-type');
          await target.evaluate((el) => { el.querySelector('details').open = true; });
          await target.locator('[data-testid=mute-btn]').click();
          await page.waitForSelector('dialog[open]');
          await page.fill('dialog textarea', 'console test (real collector)');
          await page.click('dialog button:has-text("Mute")');
          await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 15000 });
          await page.waitForSelector('[data-testid=mutes-table] tbody tr:has-text("console test")', { timeout: 15000 });
          await page.waitForFunction((i) => !document.querySelector(`[data-testid=detection][data-id="${i}"]:not([data-muted=true])`), id, { timeout: 10000 });
          ok(`mute against the real collector (${type}): set, detection collapsed, listed with its reason`);
          await page.click('[data-testid=mutes-table] tr:has-text("console test") button:has-text("Lift the mute")');
          await page.waitForSelector(`[data-testid=detection][data-id="${id}"]:not([data-muted=true])`, { timeout: 15000 });
          ok('lifting the mute against the real collector: detection reported again');
        } else fail('no mutable detection to try against the real collector');
        await page.selectOption('select[aria-label="Detection type"]', 'detect.sms_abuse');
        await page.waitForFunction(() => { const c = [...document.querySelectorAll('[data-testid=detection]')]; return c.length > 0 && c.every((e) => e.getAttribute('data-type') === 'detect.sms_abuse'); }, null, { timeout: 15000 });
        ok('filter by type against the real collector: sms_abuse');
        const sms = await page.textContent('[data-testid=detection]');
        if (!/SMS/.test(sms)) fail('sms_abuse detection without "SMS"');
        // Detail page of the application concerned, from the detection
        await page.evaluate(() => document.querySelectorAll('[data-testid=detection] details').forEach((d) => { d.open = true; }));
        await page.click('[data-testid=detection] a:has-text("Application detail page")');
        await page.waitForSelector('.sheet-head h1');
        await page.waitForTimeout(1500);
        const sheet = await page.textContent('.main');
        for (const n of ['Risk profile', 'Detections concerning this application', 'Sensitive operations']) if (!sheet.includes(n)) fail(`detail page: "${n}" missing`);
        if (!(await page.locator('.det').count())) fail('detail page: no detection of the application'); else ok('application detail page from a detection: profile, detections, operations');
        await shot('11-detail');
        await page.reload({ waitUntil: 'load' });
        await page.waitForSelector('.sheet-head h1');
        ok('application detail page reloaded (the real server answers with the application, not 404)');
      }

      await page.goto(`${BASE}/apps`, { waitUntil: 'load' });
      await page.waitForSelector('[data-testid=risk-table]', { timeout: 20000 });
      if (first) {
        const nums = (await page.locator('[data-testid=risk-table] tbody .risk-score strong').allTextContents()).map(Number);
        if (nums.length < 5 || nums.some((n, i) => i > 0 && n > nums[i - 1])) fail('risk: score order not respected'); else ok(`risk: ${nums.length} applications sorted by score (${nums[0]} … ${nums[nums.length - 1]})`);
        const high = await page.locator('[data-testid=risk-table] tr.risk-high').count();
        const txt = await page.textContent('[data-testid=risk-table]');
        const combos = ['Banking trojan profile', 'SMS fraud profile', 'Stalkerware profile'].filter((c) => txt.includes(c));
        console.log(`  high levels: ${high}; combinations present: ${combos.join(' | ') || 'none'}`);
        if (SCENARIO === 'healthy' && high) fail('risk: high-risk application in the healthy fleet');
        const unknown = (await page.locator('[data-testid=risk-table] .reason-chips .badge').allTextContents()).filter((t) => /^[a-z]+(_[a-z]+)+$/.test(t));
        if (unknown.length) fail(`risk: untranslated reason codes: ${[...new Set(unknown)].join(', ')}`); else ok('risk: all the reasons of the real collector are translated');
      }
      await shot('05-apps-risk');

      await page.goto(`${BASE}/apps?tab=ops`, { waitUntil: 'load' });
      await page.waitForSelector('[data-testid=ops-cards], [data-testid=ops-empty]', { timeout: 20000 });
      if (first) {
        const present = (await page.locator('[data-testid=ops-cards]').count()) > 0;
        ok(present ? 'sensitive operations: data of the real collector displayed (' + (await page.locator('[data-testid=ops-table] tbody tr').count()) + ' rows)' : 'sensitive operations: explanatory empty state');
      }
      await shot('05-apps-operations');

      await page.goto(`${BASE}/security?tab=roles`, { waitUntil: 'load' });
      await page.waitForSelector('.card-title:has-text("Current roles")', { timeout: 20000 });
      await page.waitForTimeout(800);
      if (first) {
        const t = await page.textContent('.main');
        ok('default roles: ' + (/SMS app/.test(t) ? 'current roles displayed' : 'no reading') + (await page.locator('[data-testid=roles-table]').count() ? ', history present' : ', no change'));
      }
      await shot('06-security-roles');
      await page.goto(`${BASE}/alerts`, { waitUntil: 'load' });
      await page.waitForSelector('.net-intro');
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      if (overflow > 1) fail(`${tag}: horizontal scroll (${overflow}px)`);
      const csp = await page.evaluate(() => window.__csp);
      if (csp.length) fail(`${tag}: CSP violations: ${[...new Set(csp)].join(' | ')}`);
      const extra = [...hosts].filter((h) => h !== 'tile.openstreetmap.org');
      if (extra.length) fail(`${tag}: third-party hosts: ${extra.join(', ')}`);
      for (const e of errors) fail(`${tag}: ${e}`);
      await ctx.close();
    }
  }
  ok('four configurations (light/dark, desktop/phone): console errors, CSP and third parties checked');
  await browser.close();
  console.log(`\nResult: ${failures.length === 0 ? 'OK' : failures.length + ' failure(s)'}`);
  process.exit(failures.length ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(2); });
