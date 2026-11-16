/* Replays in Chromium the commands / tracking / notifications walkthroughs against a REAL collector.
 *
 *   REAL_URL=http://127.0.0.1:8090 REAL_PASSWORD=... [REAL_USER=admin] [OUT=folder] node scripts/verify-real.cjs
 *
 * Prerequisites (see server/collector/README.md): collector started with WATCHPOST_CONSOLE_DIR=<this folder>/dist, an enrolled
 * device that is fed (`sim --backfill 48h --follow`), and an agent that polls /api/v1/commands (the collector's simulator,
 * or `AGENT_CODE=... node <simulated agent> file.watchpost`) whose command passphrase is `REAL_CODE`
 * (default: "correct horse battery staple"). AdGuard Home is not required: without it the degraded mode is checked.
 * Fails on any console error, CSP violation, unexpected HTTP status or request to a third party.
 */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const BASE = process.env.REAL_URL || 'http://127.0.0.1:8090';
const USER = process.env.REAL_USER || 'admin';
const PASSWORD = process.env.REAL_PASSWORD || '';
const RIGHT = process.env.REAL_CODE || 'correct horse battery staple';
const WRONG = 'wrong passphrase 987654';
const OUT = process.env.OUT || path.resolve(__dirname, '../verify-out-real');
fs.mkdirSync(OUT, { recursive: true });
const failures = [];
const fail = (m) => { failures.push(m); console.log('  ✗ ' + m); };
const ok = (m) => console.log('  ✓ ' + m);
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');

async function main() {
  const browser = await chromium.launch({ args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'en-GB', timezoneId: 'UTC' });
  await ctx.addInitScript(() => { window.__csp = []; document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`)); });
  await ctx.route('https://tile.openstreetmap.org/**', (r) => r.fulfill({ status: 200, contentType: 'image/png', body: PNG, headers: { 'access-control-allow-origin': '*' } }));
  const page = await ctx.newPage();
  const errors = [], hosts = new Set(), requests = [], logs = [];
  const host = new URL(BASE).host;
  page.on('console', (m) => { logs.push(m.text()); if (['error', 'warning'].includes(m.type()) && !/status of (401|409|503)/.test(m.text())) errors.push('console: ' + m.text()); });
  page.on('pageerror', (e) => errors.push('exception: ' + e.message));
  page.on('request', (r) => { const u = new URL(r.url()); if (u.protocol.startsWith('http') && u.host !== host) hosts.add(u.host); requests.push({ url: r.url(), body: r.postData() || '', headers: JSON.stringify(r.headers()) }); });
  page.on('response', (r) => { const u = new URL(r.url()); if (r.status() >= 400 && u.host === host && !(r.status() === 401 && u.pathname.endsWith('/me')) && !(r.status() === 409 && u.pathname.endsWith('/tracking/override'))) errors.push(`HTTP ${r.status()} ${u.pathname}`); });

  console.log('\n== sign-in');
  await page.goto(`${BASE}/login`, { waitUntil: 'load' });
  await page.fill('input[name=username]', USER);
  await page.fill('input[name=password]', PASSWORD);
  await Promise.all([page.waitForURL(`${BASE}/`), page.click('button[type=submit]')]);
  await page.waitForSelector('.stats');
  ok('sign-in and overview');
  await page.screenshot({ path: path.join(OUT, 'real-01-overview.png'), fullPage: true });

  console.log('\n== commands');
  await page.goto(`${BASE}/commands`, { waitUntil: 'load' });
  await page.waitForSelector('.cmd-list');
  await page.waitForTimeout(2500);
  const main = await page.textContent('.main');
  ok('channel: ' + (['Connected', 'Periodic polling', 'Offline', 'Unknown state'].find((s) => main.includes(s)) || '?'));
  const waitStatus = (label, text, timeout = 30000) => page.waitForFunction(([l, t]) => [...document.querySelectorAll('.cmd-tbl tbody tr')].some((r) => r.textContent.includes(l) && r.textContent.includes(t)), [label, text], { timeout });
  const firstRow = (text, timeout = 30000) => page.waitForFunction((t) => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes(t), text, { timeout });
  await page.click('button:has-text("Vibrate"):not(:has-text("too"))');
  await firstRow('Vibrate');
  await waitStatus('Vibrate', 'Executed');
  ok('vibrate: executed (simulated agent, real collector)');
  const before = await page.textContent('[data-testid=pos-info]').catch(() => '');
  await page.click('button:has-text("Locate now")');
  await page.waitForSelector('text=New location received: the map is up to date', { timeout: 40000 });
  await page.waitForTimeout(500);
  const after = await page.textContent('[data-testid=pos-info]');
  if (before === after) fail('locate: location unchanged'); else ok('locate: location received through the real SSE stream (' + after.trim().slice(0, 70) + ')');
  await page.screenshot({ path: path.join(OUT, 'real-02-location.png'), fullPage: true });

  const lock = async (code) => {
    await page.click('button:has-text("Lock…")');
    await page.waitForSelector('dialog[open]');
    await page.fill('dialog textarea', 'Lost phone — please call +1 555 0100');
    await page.check('dialog input[type=checkbox]');
    await page.fill('#cmd-code', code);
    await page.click('dialog button:has-text("Sign and send")');
    await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 20000 });
  };
  await lock(WRONG);
  await firstRow('Lock');
  await waitStatus('Lock', 'Refused');
  await page.waitForSelector('.cmd-tbl tbody tr:first-child:has-text("Invalid signature")');
  ok('wrong passphrase: bad_signature refusal found by the agent, translated into English');
  await lock(RIGHT);
  await firstRow('Lock');
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Executed'), null, { timeout: 30000 });
  ok('right passphrase: the signature computed by the browser is accepted by the agent (identical HMAC)');
  await page.screenshot({ path: path.join(OUT, 'real-03-history.png'), fullPage: true });

  // Cancellation: the agent is stopped by the calling script if REAL_PAUSE_AGENT is provided (otherwise we try on the fly).
  await page.click('button:has-text("Stop ringing")');
  await firstRow('Stop ringing');
  const cancel = page.locator('.cmd-tbl tbody tr:first-child button:has-text("Cancel")');
  if (await cancel.count()) {
    await cancel.click().catch(() => undefined);
    await page.waitForFunction(() => /Cancelled|Executed|Delivered/.test(document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent || ''), null, { timeout: 15000 });
    ok('cancellation: ' + (await page.locator('.cmd-tbl tbody tr:first-child .badge').first().textContent()));
  } else ok('cancellation: the command had already been delivered (race with the agent)');

  // Erase: three-step flow, refused by the agent (erase not allowed in the app)
  await page.click('button:has-text("Erase the phone…")');
  await page.waitForSelector('dialog[open]');
  await page.check('dialog input[type=checkbox]');
  await page.click('dialog button:has-text("Continue")');
  const devName = (await page.locator('dialog strong.mono').textContent()).trim();
  await page.fill('dialog input[type=text]', devName);
  await page.click('dialog button:has-text("Continue")');
  await page.fill('#cmd-code', RIGHT);
  await page.click('dialog button:has-text("Sign and erase")');
  await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 20000 });
  await firstRow('Erase the phone');
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Refused'), null, { timeout: 30000 });
  if (!(await page.locator('.cmd-tbl tbody tr:first-child').textContent()).includes('Channel disabled')) fail('erase: disabled reason not translated'); else ok('erase: three-step flow, agent "disabled" refusal translated');

  const secrets = [RIGHT, WRONG];
  const leaks = [];
  for (const r of requests) for (const c of secrets) for (const v of [c, encodeURIComponent(c), Buffer.from(c).toString('base64'), Buffer.from(c).toString('hex')]) if (r.url.includes(v) || r.body.includes(v) || r.headers.includes(v)) leaks.push(r.url);
  for (const l of logs) for (const c of secrets) if (l.includes(c)) leaks.push('console');
  const st = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + document.cookie);
  for (const c of secrets) if (st.includes(c)) leaks.push('storage');
  if (leaks.length) fail('PASSPHRASE LEAK: ' + leaks.join(', ')); else ok(`the passphrase does not leave the page (${requests.length} requests inspected, storages and cookies included)`);

  console.log('\n== tracking');
  await page.goto(`${BASE}/tracking`, { waitUntil: 'load' });
  await page.waitForSelector('.trk-pub, .state-warn, .state-empty', { timeout: 20000 });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUT, 'real-04-tracking.png'), fullPage: true });
  const ptxt = await page.textContent('.main');
  if (ptxt.includes('Degraded mode')) ok('AdGuard not configured: degraded mode displayed, actions disabled');
  else ok('AdGuard reachable: full view');
  const rows = await page.locator('.trk-dom tbody tr').count();
  ok(`${rows} domains listed (first page)`);
  if (!ptxt.includes('Degraded mode')) {
    // AdGuard Home (real or fake) reachable: filters, manual rule, 409, level.
    await page.click('.seg-btn:has-text("Blocked")');
    await page.waitForTimeout(1200);
    const bl = await page.locator('.trk-dom tbody tr').allTextContents();
    if (bl.length && bl.every((t) => /Blocked|Mixed/.test(t))) ok(`Blocked filter: ${bl.length} domains`); else fail('Blocked filter inconsistent');
    await page.click('.seg-btn:has-text("All")');
    await page.fill('input[placeholder^="e.g. doubleclick"]', 'mtalk.google.com');
    await page.waitForSelector('.trk-dom tbody tr:has-text("mtalk.google.com")', { timeout: 15000 });
    await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().locator('button:has-text("Block")').click();
    await page.waitForSelector('dialog[open]:has-text("essential")');
    await page.screenshot({ path: path.join(OUT, 'real-04b-tracking-409.png') });
    ok('409 essential domain: ' + (await page.locator('dialog[open] .callout li').allTextContents()).join(' | ').slice(0, 120));
    await page.click('dialog button:has-text("Do not block")');
    await page.fill('input[placeholder^="e.g. doubleclick"]', 'tracker');
    await page.waitForTimeout(1500);
    let target = page.locator('.trk-dom tbody tr:has(button:has-text("Block"))').first();
    if (!(await target.count())) { await page.fill('input[placeholder^="e.g. doubleclick"]', ''); await page.waitForTimeout(1500); target = page.locator('.trk-dom tbody tr:has(button:has-text("Block")):not(:has-text("mtalk"))').first(); }
    const dom = (await target.locator('.c-dom .mono').textContent()).trim();
    await target.locator('button:has-text("Block")').first().click();
    await page.waitForSelector('dialog[open]', { timeout: 3000 }).then(async () => { await page.click('dialog button:has-text("Do not block")'); fail('domain ' + dom + ' flagged essential'); }).catch(() => undefined);
    const row = page.locator('.trk-dom tbody tr', { hasText: dom }).first();
    await row.locator('button:has-text("Reset to default")').waitFor({ timeout: 15000 });
    ok('Block ' + dom + ': rule saved in AdGuard Home ("manual rule" badge)');
    await row.locator('button:has-text("Reset to default")').click();
    await row.locator('button:has-text("Reset to default")').waitFor({ state: 'detached', timeout: 15000 });
    ok('Reset to default: rule removed');
    // Level: we change then put the previous one back
    const cur = (await page.locator('.level.is-sel strong').first().textContent()).trim();
    const other = cur === 'Balanced' ? 'Strict' : 'Balanced';
    await page.click(`.level:has-text("${other}")`);
    await page.click('button:has-text("Apply the")');
    await page.click('dialog button:has-text("Change the level")');
    await page.waitForSelector(`.level.is-sel:has-text("${other}") .badge:has-text("Current")`, { timeout: 120000 });
    ok(`level ${cur} -> ${other} applied in AdGuard Home`);
    await page.click(`.level:has-text("${cur}")`);
    await page.click('button:has-text("Apply the")');
    await page.click('dialog button:has-text("Change the level")');
    await page.waitForSelector(`.level.is-sel:has-text("${cur}") .badge:has-text("Current")`, { timeout: 120000 });
    await page.screenshot({ path: path.join(OUT, 'real-04c-tracking-level.png'), fullPage: true });
    ok(`level put back to ${cur}`);
    await page.fill('input[placeholder^="e.g. doubleclick"]', '');
  }
  if (rows > 0) {
    await page.click('role=tab[name="Applications"]');
    await page.waitForSelector('.trk-apps > li', { timeout: 15000 });
    await page.click('.trk-app-head >> nth=0');
    await page.waitForSelector('.trk-app-body');
    ok('per-application view expanded');
  }

  console.log('\n== notifications and map');
  await page.goto(`${BASE}/apps`, { waitUntil: 'load' });
  await page.waitForSelector('role=tab[name="Notifications"]');
  await page.click('role=tab[name="Notifications"]');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(OUT, 'real-05-notifications.png'), fullPage: true });
  ok('Notifications tab: ' + ((await page.locator('.rank li').count()) + ' application(s) ranked'));
  await page.goto(`${BASE}/map`, { waitUntil: 'load' });
  await page.waitForSelector('.replay');
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUT, 'real-06-map.png'), fullPage: true });
  ok('map loaded, providers: ' + ((await page.textContent('.main')).match(/Providers\s+([^\n]*?)(Data gaps|$)/) || [, '?'])[1].slice(0, 60));

  const csp = await page.evaluate(() => window.__csp);
  if (csp.length) fail('CSP violations: ' + [...new Set(csp)].join(' | ')); else ok('no CSP violation');
  const extra = [...hosts].filter((h) => h !== 'tile.openstreetmap.org');
  if (extra.length) fail('third-party hosts: ' + extra.join(', ')); else ok('no request to a third party');
  for (const e of errors) fail(e);
  if (!errors.length) ok('no console error or unexpected HTTP status');
  await browser.close();
  console.log(`\nResult: ${failures.length === 0 ? 'OK' : failures.length + ' failure(s)'}`);
  process.exit(failures.length ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(2); });
