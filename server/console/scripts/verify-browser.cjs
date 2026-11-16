/* Real verification in Chromium (Playwright preinstalled globally) against the mock server.
 *
 *   npm run build && npm run verify
 *
 * Variables: OUT (screenshots folder), PORT (default 8799), TILES=real to not simulate the OSM tiles,
 * CSP (replaces the mock server's CSP, see mock/server.ts).
 * Checks: no console error / exception, no CSP violation, no request outside the local host and the tiles;
 * walk through each page in light and dark, desktop and phone. Exits with a non-zero code on failure.
 */
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { chromium } = require('playwright');

const ROOT = path.resolve(__dirname, '..');
const OUT = process.env.OUT || path.join(ROOT, 'verify-out');
const PORT0 = Number(process.env.PORT || 8799);
let PORT = PORT0;
let BASE = `http://127.0.0.1:${PORT}`;
/** The walkthroughs of the "healthy" and "sms-fraud" scenarios run against other instances of the mock server. */
function setServer(port) {
  PORT = port;
  BASE = `http://127.0.0.1:${port}`;
}
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
/** Synthetic 256x256 tile (light grid): simulates OSM without a network. */
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
    try { const r = await fetch(`${BASE}/healthz`); if (r.ok) return; } catch { /* waiting */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('mock server unreachable');
}

async function control(body) {
  await fetch(`${BASE}/__mock/control`, { method: 'POST', body: JSON.stringify(body) });
}

function startMock(port, scenario) {
  const child = spawn(process.execPath, ['mock/server.ts', '--port', String(port), '--static', 'dist', '--scenario', scenario], { cwd: ROOT, stdio: ['ignore', 'pipe', 'inherit'] });
  child.stdout.on('data', () => undefined);
  return child;
}

async function main() {
  if (!fs.existsSync(path.join(ROOT, 'dist/index.html'))) throw new Error('dist/ missing: run npm run build first');
  const mock = startMock(PORT0, 'mixed');
  const others = [];
  try {
    await waitHealth();
    const browser = await chromium.launch({ args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
    const scenarios = [
      { name: 'light-desktop', scheme: 'light', viewport: { width: 1280, height: 800 } },
      { name: 'dark-desktop', scheme: 'dark', viewport: { width: 1280, height: 800 } },
      { name: 'light-phone', scheme: 'light', viewport: { width: 390, height: 844 }, mobile: true },
      { name: 'dark-phone', scheme: 'dark', viewport: { width: 390, height: 844 }, mobile: true },
    ];
    // ONLY=features: only the commands / tracking / notifications walkthroughs; ONLY=v12: only version 1.2
    // (quick iteration).
    const only = process.env.ONLY;
    if (!only) {
      for (const sc of scenarios) await runScenario(browser, sc);
      await runBehaviours(browser);
    }
    if (!only || only === 'features') await runFeatures(browser);
    if (!only || only === 'v12') {
      await runV12(browser);
      for (const [i, scenario] of ['healthy', 'sms-fraud'].entries()) {
        const port = PORT0 + 1 + i;
        const child = startMock(port, scenario);
        others.push(child);
        setServer(port);
        await waitHealth();
        await runV12Scenario(browser, scenario, scenarios);
        setServer(PORT0);
      }
    }
    await browser.close();
  } finally {
    mock.kill();
    for (const c of others) c.kill();
  }
  console.log(`\nResult: ${failures.length === 0 ? 'OK' : failures.length + ' failure(s)'}`);
  for (const n of notes) console.log('  note: ' + n);
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
      // Real tiles may fail behind the environment's proxy: this is not a code defect.
      if (REAL_TILES && /tile\.openstreetmap|Failed to load resource|ERR_/.test(t)) return;
      // HTTP statuses >= 400 are checked through the responses (see below): the browser always logs them.
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
    locale: 'en-GB',
    timezoneId: 'UTC',
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
  await page.waitForURL(/\/login/, { timeout: 10000 }).catch(() => { throw new Error('no redirect to /login'); });
  await page.fill('input[name=username]', 'admin');
  await page.fill('input[name=password]', 'watchpost');
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

  await page.goto(`${BASE}/login`, { waitUntil: 'load' });
  await page.waitForSelector('input[name=username]');
  await shot(page, sc, '00-login');
  await login(page);

  const pages = [
    ['01-overview', '/', '.stats'],
    ['02-map', '/map', '.replay'],
    ['03-events', '/events', '.tbl'],
    ['04-network', '/network', '.rank'],
    ['05-apps', '/apps', '.tbl'],
    ['06-security', '/security', '.findings'],
    ['07-alerts', '/alerts', '.tbl'],
    ['08-commands', '/commands', '.cmd-list'],
    ['09-tracking', '/tracking', '.trk-dom tbody tr'],
    ['10-detections', '/detections', '[data-testid=detection]'],
    ['11-app-detail', '/apps/detail?pkg=com.wallpapers.superhd', '.reasons'],
  ];
  for (const [name, url, sel] of pages) {
    await page.goto(`${BASE}${url}`, { waitUntil: 'load' });
    await settle(page, sel);
    await shot(page, sc, name);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    if (overflow > 1) fail(`${sc.name} ${url}: horizontal page scroll (${overflow}px)`);
  }

  // Interactive details once per light/dark desktop + phone scenario.
  await page.goto(`${BASE}/events`, { waitUntil: 'load' });
  await page.click('.tbl tbody .expander');
  await page.waitForSelector('.json-pre');
  await shot(page, sc, '03b-event-detail');

  await page.goto(`${BASE}/security`, { waitUntil: 'load' });
  for (const [tab, name] of [['Default roles', 'roles'], ['System log', 'log'], ['Camera and microphone', 'sensors'], ['CA certificates', 'certs'], ['Cellular and BLE', 'radio'], ['Policy applied', 'policy'], ['Unlocks', 'keyguard']]) {
    await page.click(`role=tab[name="${tab}"]`);
    await settle(page, '.tbl, .findings');
    await shot(page, sc, `06-security-${name}`);
  }

  await page.goto(`${BASE}/apps`, { waitUntil: 'load' });
  await settle(page, '.tbl');
  for (const [tab, name] of [['Inventory', 'inventory'], ['Sensitive operations', 'operations'], ['Dangerous permissions', 'permissions'], ['Special access', 'special-access'], ['History', 'history']]) {
    await page.click(`role=tab[name="${tab}"]`);
    await settle(page);
    await shot(page, sc, `05-apps-${name}`);
  }

  await page.goto(`${BASE}/network`, { waitUntil: 'load' });
  await settle(page, '.rank');
  await page.click('.rank .linkish[aria-pressed]');
  await page.waitForSelector('.two-col .rank', { timeout: 20000 });
  await settle(page);
  await shot(page, sc, '04b-network-app');

  // Tracking: Applications tab, expanded application.
  await page.goto(`${BASE}/tracking`, { waitUntil: 'load' });
  await settle(page, '.trk-dom tbody tr');
  await page.click('role=tab[name="Applications"]');
  await page.waitForSelector('.trk-apps > li');
  await page.click('.trk-app-head >> nth=0');
  await page.waitForSelector('.trk-app-body');
  await shot(page, sc, '09-tracking-apps');

  // Applications: notifications (content, hidden content, hostile text not interpreted).
  await page.goto(`${BASE}/apps`, { waitUntil: 'load' });
  await settle(page, '.tbl');
  await page.click('role=tab[name="Notifications"]');
  await page.waitForSelector('.rank li');
  await page.waitForSelector('.tbl tbody tr');
  await settle(page);
  await shot(page, sc, '05-apps-notifications');

  // Map: location providers.
  await page.goto(`${BASE}/map`, { waitUntil: 'load' });
  await settle(page, '.replay');
  await shot(page, sc, '02-map-providers');

  const csp = await page.evaluate(() => window.__csp);
  if (csp.length) fail(`${sc.name}: CSP violations: ${[...new Set(csp)].join(' | ')}`);
  else ok('no CSP violation');
  const extra = [...state.hosts].filter((h) => h !== TILE_HOST);
  if (extra.length) fail(`${sc.name}: requests to third-party hosts: ${extra.join(', ')}`);
  else ok(`hosts contacted: 127.0.0.1${state.hosts.size ? ' + ' + [...state.hosts].join(', ') : ''}`);
  if (state.errors.length) for (const e of state.errors) fail(e);
  else ok('no console error or exception');
  await ctx.close();
}

async function runBehaviours(browser) {
  console.log('\n== behaviours (light, desktop)');
  const sc = { name: 'behaviour', scheme: 'light', viewport: { width: 1280, height: 800 } };
  const state = {
    errors: [],
    hosts: new Set(),
    // Error statuses deliberately provoked by this test (expired session, simulated outage, wrong password).
    expected: (p, st) => (st === 401 && /^\/api\/console\/(me|login|devices|events|stats|apps|posture|alerts|locations)/.test(p)) || (st === 500 && p.startsWith('/api/console/stats/top')),
  };
  const ctx = await newContext(browser, sc, state);
  const page = await ctx.newPage();
  instrument(page, 'behaviour', state);
  await login(page);

  // Theme switch: cycle auto -> light -> dark -> auto.
  const attr = () => page.evaluate(() => document.documentElement.getAttribute('data-theme'));
  await page.click('button[aria-label^="Theme"]');
  if ((await attr()) !== 'light') fail('theme switch: expected light');
  await page.click('button[aria-label^="Theme"]');
  if ((await attr()) !== 'dark') fail('theme switch: expected dark');
  else ok('theme switch');
  await page.reload({ waitUntil: 'load' });
  if ((await attr()) !== 'dark') fail('theme not remembered after reload');
  else ok('theme remembered');
  await page.click('button[aria-label^="Theme"]');

  // Map: time slider and playback.
  await page.goto(`${BASE}/map`, { waitUntil: 'load' });
  await settle(page, '.replay');
  const count0 = await page.textContent('.replay-info');
  await page.fill('input[type=range]', '10').catch(async () => {
    await page.$eval('input[type=range]', (el) => { el.value = '10'; el.dispatchEvent(new Event('input', { bubbles: true })); });
  });
  await page.waitForTimeout(300);
  const count1 = await page.textContent('.replay-info');
  if (count0 === count1) fail('time slider: no change'); else ok('time slider');
  await page.click('button:has-text("Replay")');
  await page.waitForTimeout(900);
  await page.click('button:has-text("Pause")');
  ok('track playback');
  const gapItems = await page.locator('.gap-list li').count();
  notes.push(`map 24 h: ${gapItems} data gap(s) listed`);
  await page.click('button.seg-btn:has-text("7 days")');
  await settle(page, '.gap-list li');
  await page.screenshot({ path: path.join(OUT, 'map-7d-gaps.png'), fullPage: true });
  const silent = await page.locator('.gap-list li.is-silent').count();
  if (silent < 1) fail('map 7 d: no "without events" gap detected'); else ok(`map 7 d: ${silent} gap(s) without events`);

  // Events: filter, severity, live.
  await page.goto(`${BASE}/events`, { waitUntil: 'load' });
  await settle(page, '.tbl');
  await page.click('.chip-btn:has-text("Security")');
  await page.selectOption('select >> nth=0', { index: 0 }).catch(() => undefined);
  await settle(page, '.tbl');
  const rows = await page.locator('.tbl tbody tr').count();
  if (rows < 1) fail('domain filter: no row'); else ok(`domain filter: ${rows} rows`);
  await page.click('.chip-btn:has-text("Clear the filter")');
  await page.check('label.check input[type=checkbox]');
  await page.waitForSelector('.live-dot:not(.is-off)', { timeout: 10000 });
  await page.waitForSelector('.new-row', { timeout: 15000 });
  ok('live mode: events received through SSE');
  await page.screenshot({ path: path.join(OUT, 'events-live.png') });
  await page.uncheck('label.check input[type=checkbox]');

  // Unknown type / partial data: JSON fallback, no crash.
  await page.click('button.seg-btn:has-text("7 days")');
  await page.fill('input[list=event-types]', 'experimental.');
  await page.waitForSelector('.tbl tbody tr:has-text("experimental.future_probe")', { timeout: 15000 });
  await page.click('.tbl tbody .expander');
  const j = await page.textContent('.json-pre');
  if (!j || !j.includes('future_probe')) fail('unknown type: raw JSON not displayed'); else ok('unknown type: raw JSON displayed');
  await page.fill('input[list=event-types]', 'location.fix');
  await page.fill('input[type=search]', '48.86');
  await settle(page, '.tbl');
  ok('partial data (location.fix without lon): no crash');

  // Alerts: wazuh false.
  await control({ wazuh: false });
  await page.goto(`${BASE}/alerts`, { waitUntil: 'load' });
  await page.waitForSelector('text=Wazuh not configured');
  await page.screenshot({ path: path.join(OUT, 'alerts-without-wazuh.png') });
  ok('alerts: wazuh=false handled');
  await control({ wazuh: true });

  // Server error: error state + Retry.
  await control({ fail: ['/stats/top'] });
  await page.goto(`${BASE}/network`, { waitUntil: 'load' });
  await page.waitForSelector('.state-error button:has-text("Retry")');
  await page.screenshot({ path: path.join(OUT, 'network-error.png') });
  ok('error state with retry');
  await control({ fail: [] });

  // Device without data: empty states.
  await page.goto(`${BASE}/`, { waitUntil: 'load' });
  await page.selectOption('select[aria-label=Device]', { label: 'old-phone (revoked)' });
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(OUT, 'device-empty.png'), fullPage: true });
  for (const u of ['/map', '/events', '/network', '/apps', '/security']) {
    await page.goto(`${BASE}${u}`, { waitUntil: 'load' });
    await page.waitForTimeout(500);
    const empty = await page.locator('.state-empty, .state-error').count();
    if (!empty) fail(`device without data: ${u} without an empty state`);
  }
  ok('device without data: empty states');
  await page.selectOption('select[aria-label=Device]', { label: 'phone' });

  // Expired session: back to the login page.
  await page.goto(`${BASE}/`, { waitUntil: 'load' });
  await page.waitForSelector('.sidenav');
  await page.waitForSelector('.stats');
  await control({ expire: true });
  await page.click('.sidenav a:has-text("Events")');
  await page.waitForURL(/\/login/);
  const notice = await page.textContent('.login-card');
  if (!notice.includes('expired')) fail('expired session: message missing'); else ok('expired session -> login page with message');
  await page.fill('input[name=username]', 'admin');
  await page.fill('input[name=password]', 'wrong');
  await page.click('button[type=submit]');
  await page.waitForSelector('.state-error');
  ok('wrong password: error displayed');

  // Keyboard navigation: the skip link is the first focusable element.
  await page.goto(`${BASE}/login`, { waitUntil: 'load' });
  const active = await page.evaluate(() => document.activeElement && document.activeElement.getAttribute('name'));
  if (active !== 'username') fail('initial focus of the login page'); else ok('initial focus on the username');

  const csp = await page.evaluate(() => window.__csp);
  if (csp.length) fail(`behaviours: CSP violations: ${[...new Set(csp)].join(' | ')}`);
  for (const e of state.errors) fail(e);
  const extra = [...state.hosts].filter((h) => h !== TILE_HOST);
  if (extra.length) fail(`behaviours: third-party hosts: ${extra.join(', ')}`);
  await ctx.close();
}

// ---------------------------------------------------------------------------------------------------
// Remote commands, tracking, notifications: end-to-end behaviours against the mock server.
const RIGHT_CODE = 'correct horse battery staple';
const WRONG_CODE = 'wrong passphrase 987654';

async function runFeatures(browser) {
  console.log('\n== commands, tracking, notifications (light, desktop)');
  const sc = { name: 'features', scheme: 'light', viewport: { width: 1280, height: 900 } };
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
  instrument(page, 'features', state);
  await login(page);
  await control({ quiet: true, channel: 'stream', adguard: true, agent: { disabled: false, wipe_allowed: false, code_configured: true, device_owner: true, locate_fail: false, deliver_ms: 300, exec_ms: 500 } });

  const rowOf = (label) => page.locator('.cmd-tbl tbody tr', { hasText: label }).first();
  const waitStatus = (label, text, timeout = 15000) =>
    page.waitForFunction(([l, t]) => [...document.querySelectorAll('.cmd-tbl tbody tr')].some((r) => r.textContent.includes(l) && r.textContent.includes(t)), [label, text], { timeout });

  // ---- Channel and simple command
  await page.goto(`${BASE}/commands`, { waitUntil: 'load' });
  await settle(page, '.cmd-list');
  if (!(await page.textContent('.main')).includes('Connected')) fail('commands: "Connected" channel state missing'); else ok('connected channel displayed');
  await page.click('button:has-text("Vibrate"):not(:has-text("too"))');
  await page.waitForSelector('.cmd-tbl tbody tr:first-child:has-text("Vibrate")');
  await waitStatus('Vibrate', 'Executed');
  ok('vibrate: pending -> delivered -> executed (live tracking)');
  // out-of-bounds value: button disabled
  await page.fill('.cmd-row:has-text("Ring") input[type=number]', '999');
  if (!(await page.locator('.cmd-row:has-text("Ring") button.btn-primary').isDisabled())) fail('ring: duration 999 accepted'); else ok('ring: out-of-bounds duration refused by the interface');
  await page.fill('.cmd-row:has-text("Ring") input[type=number]', '20');
  await page.click('.cmd-row:has-text("Ring") button.btn-primary');
  await waitStatus('Ring', 'Executed');

  // ---- Locate: the map updates when the location arrives
  const before = await page.textContent('[data-testid=pos-info]');
  await page.click('button:has-text("Locate now")');
  await page.waitForSelector('text=waiting for the new location');
  await page.waitForSelector('text=New location received: the map is up to date', { timeout: 20000 });
  const after = await page.textContent('[data-testid=pos-info]');
  if (before === after) fail('locate: the displayed location did not change'); else ok('locate: location updated by the SSE stream (' + after.trim().slice(0, 60) + '…)');
  await page.waitForSelector('[data-testid=pos-info] .badge:has-text("GPS")');
  await shot(page, sc, '08-commands-location', false);

  // ---- Cancellation while "Pending"
  await control({ channel: 'offline' });
  await page.reload({ waitUntil: 'load' });
  await settle(page, '.cmd-list');
  if (!(await page.textContent('.main')).includes('Offline')) fail('offline channel not displayed'); else ok('offline channel displayed');
  await page.click('button:has-text("Stop ringing")');
  await page.waitForSelector('.cmd-tbl tbody tr:first-child:has-text("Pending")');
  await page.screenshot({ path: path.join(OUT, 'commands-offline-pending.png'), fullPage: true });
  await page.click('.cmd-tbl tbody tr:first-child button:has-text("Cancel")');
  await waitStatus('Stop ringing', 'Cancelled');
  ok('pending command cancelled');
  await control({ channel: 'poll' });
  await page.reload({ waitUntil: 'load' });
  await settle(page, '.cmd-list');
  if (!(await page.textContent('.main')).includes('polling')) fail('polling mode not displayed'); else ok('polling mode displayed');
  await control({ channel: 'stream' });

  // ---- Browser clock skewed: warning, then clear refusal from the server (issued_at more than 10 min off)
  await control({ clock_skew_ms: 2 * 3600_000 });
  await page.reload({ waitUntil: 'load' });
  await settle(page, '.cmd-list');
  await page.waitForSelector('.state-warn:has-text("computer\'s clock")');
  await page.click('button:has-text("Vibrate"):not(:has-text("too"))');
  await page.waitForSelector('.state-error:has-text("clock is off")');
  ok('skewed clock: prior warning and server refusal translated into a clear message');
  await control({ clock_skew_ms: 0 });
  await page.reload({ waitUntil: 'load' });
  await settle(page, '.cmd-list');

  // ---- Lock: wrong passphrase (bad_signature), then right passphrase
  const sensitiveSteps = async (code, message) => {
    await page.click('button:has-text("Lock…")');
    await page.waitForSelector('dialog[open]');
    await page.fill('dialog textarea', message);
    const btn = page.locator('dialog button:has-text("Sign and send")');
    if (!(await btn.isDisabled())) fail('lock: button active without confirmation or passphrase');
    await page.check('dialog input[type=checkbox]');
    await page.fill('#cmd-code', 'short');
    if (!(await btn.isDisabled())) fail('lock: passphrase of less than 12 characters accepted');
    await page.fill('#cmd-code', code);
    await btn.click();
    await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 20000 });
  };
  await page.goto(`${BASE}/commands`, { waitUntil: 'load' });
  await settle(page, '.cmd-list');
  await page.click('button:has-text("Lock…")');
  await page.waitForSelector('dialog[open]');
  await page.screenshot({ path: path.join(OUT, 'commands-lock-dialog.png') });
  await page.keyboard.press('Escape');
  await page.waitForSelector('dialog[open]', { state: 'detached' });
  ok('lock dialog: Escape closes');
  await sensitiveSteps(WRONG_CODE, 'Lost phone — please call +1 555 0100');
  await waitStatus('Lock with message', 'Refused');
  await page.waitForSelector('.cmd-tbl tbody tr:first-child:has-text("Invalid signature")');
  await page.waitForSelector('.history-warn');
  ok('wrong passphrase: "invalid signature" refusal by the phone, warning displayed');
  await page.screenshot({ path: path.join(OUT, 'commands-bad-signature.png'), fullPage: true });
  await sensitiveSteps(RIGHT_CODE, 'Lost phone — please call +1 555 0100');
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Executed'), null, { timeout: 15000 });
  ok('right passphrase: lock executed (the browser signature is recognised by the mock agent)');
  // clear the message
  await page.click('button:has-text("Clear the message…")');
  await page.waitForSelector('dialog[open]');
  await page.fill('#cmd-code', RIGHT_CODE);
  await page.click('dialog button:has-text("Sign and send")');
  await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 20000 });
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Executed'), null, { timeout: 15000 });
  ok('clear the message: executed');

  // ---- Erase the phone: three-step flow, "disabled" refusal then execution
  const wipeFlow = async (expectDone) => {
    await page.click('button:has-text("Erase the phone…")');
    await page.waitForSelector('dialog[open]');
    const next = page.locator('dialog button:has-text("Continue")');
    if (!(await next.isDisabled())) fail('erase: step 1 passable without confirmation');
    if (expectDone) await page.screenshot({ path: path.join(OUT, 'commands-erase-step1.png') });
    await page.check('dialog input[type=checkbox]');
    await next.click();
    await page.fill('dialog input[type=text]', 'wrong name');
    if (!(await next.isDisabled())) fail('erase: step 2 passed with a wrong name');
    await page.fill('dialog input[type=text]', 'phone');
    await next.click();
    if (expectDone) await page.screenshot({ path: path.join(OUT, 'commands-erase-step3.png') });
    await page.fill('#cmd-code', RIGHT_CODE);
    await page.click('dialog button:has-text("Sign and erase")');
    await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 20000 });
  };
  await wipeFlow(true);
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Refused'), null, { timeout: 15000 });
  if (!(await rowOf('Erase the phone').textContent()).includes('Channel disabled')) fail('erase not allowed: "disabled" reason not translated'); else ok('erase not allowed in the app: "Channel disabled" refusal translated');
  await control({ agent: { wipe_allowed: true } });
  await wipeFlow(false);
  await page.waitForFunction(() => document.querySelector('.cmd-tbl tbody tr:first-child')?.textContent.includes('Executed'), null, { timeout: 15000 });
  ok('erase allowed: executed after the three-step flow');
  await page.screenshot({ path: path.join(OUT, 'commands-history.png'), fullPage: true });

  // ---- The passphrase never leaves the page
  const secrets = [RIGHT_CODE, WRONG_CODE];
  const variants = (c) => [c, encodeURIComponent(c), Buffer.from(c).toString('base64'), Buffer.from(c).toString('hex'), c.replace(/ /g, '+')];
  const leaks = [];
  for (const r of state.requests) for (const c of secrets) for (const v of variants(c)) {
    if (r.url.includes(v) || r.body.includes(v) || r.headers.includes(v)) leaks.push(`request ${r.url} contains "${v}"`);
  }
  for (const l of state.logs) for (const c of secrets) if (l.includes(c)) leaks.push('console log: ' + l.slice(0, 80));
  const posts = state.requests.filter((r) => r.url.endsWith('/api/console/commands') && r.body);
  const mockLog = await (await fetch(`${BASE}/__mock/requests`)).json();
  for (const r of mockLog) for (const c of secrets) for (const v of variants(c)) if (r.body.includes(v)) leaks.push('server: body containing the passphrase');
  const storage = await page.evaluate(async () => {
    const dump = { local: JSON.stringify({ ...localStorage }), session: JSON.stringify({ ...sessionStorage }), cookie: document.cookie, idb: [] };
    try { dump.idb = ((await indexedDB.databases?.()) || []).map((d) => d.name); } catch { /* ignored */ }
    dump.inputs = [...document.querySelectorAll('input')].map((i) => i.value).join('|');
    return dump;
  });
  for (const c of secrets) for (const part of [storage.local, storage.session, storage.cookie, storage.inputs]) if (part.includes(c)) leaks.push('storage or field containing the passphrase');
  if (storage.idb.length) leaks.push('IndexedDB created: ' + storage.idb.join(','));
  if (leaks.length) for (const l of leaks) fail('PASSPHRASE LEAK: ' + l);
  else ok(`the passphrase does not leave the page: ${state.requests.length} requests, ${state.logs.length} console messages, ${mockLog.length} bodies received by the server, storages, cookies and fields inspected`);
  if (posts.length < 4) fail('sensitive commands: expected POST bodies not observed');
  else {
    const bodies = posts.map((r) => JSON.parse(r.body));
    const signed = bodies.filter((b) => b.sig);
    const keysOk = signed.length >= 4 && signed.every((b) => Object.keys(b).sort().join() === 'device_id,payload,sig' && typeof b.payload === 'string' && JSON.parse(b.payload).id);
    if (!keysOk) fail('unexpected body of a signed command'); else ok('body sent: only { device_id, payload (string), sig }');
    if (bodies.filter((b) => !b.sig).some((b) => 'sig' in b)) fail('simple command with sig');
  }
  // Server log: a single signed `payload` each time (same string as the history's).

  // ---- Tracking: filters, actions, 409, level, degraded
  await page.goto(`${BASE}/tracking`, { waitUntil: 'load' });
  await settle(page, '.trk-dom tbody tr');
  await page.click('.trk-pub .linkish >> nth=0');
  await settle(page, '.trk-dom tbody tr');
  const pub1 = await page.locator('.trk-dom tbody tr').count();
  await page.click('.seg-btn:has-text("Blocked")');
  await settle(page, '.trk-dom tbody tr');
  const blockedRows = await page.locator('.trk-dom tbody tr').allTextContents();
  if (!blockedRows.length || !blockedRows.every((t) => t.includes('Blocked') || t.includes('Mixed'))) fail('Blocked filter: rows not blocked'); else ok(`publisher + blocked filters: ${blockedRows.length} domains (out of ${pub1} of the publisher)`);
  await page.click('.seg-btn:has-text("All")');
  await page.click('button:has-text("remove the filter")');
  await page.fill('input[placeholder^="e.g. doubleclick"]', 'pagead2');
  await page.waitForSelector('.trk-dom tbody tr:has-text("pagead2.googlesyndication.com")');
  ok('domain search');
  await page.fill('input[placeholder^="e.g. doubleclick"]', 'classifieds.example.org');
  await page.waitForSelector('.trk-dom tbody tr:has-text("classifieds.example.org")');
  const row = page.locator('.trk-dom tbody tr', { hasText: 'classifieds.example.org' }).first();
  await row.locator('button:has-text("Block")').click();
  await row.locator('button:has-text("Reset to default")').waitFor();
  if (!(await row.textContent()).includes('Manual rule: block')) fail('override: rule badge missing'); else ok('Block: rule saved and displayed');
  await row.locator('button:has-text("Reset to default")').click();
  await row.locator('button:has-text("Block")').waitFor();
  ok('Reset to default: rule removed');
  await row.locator('button:has-text("Block")').click();
  await row.locator('button:has-text("Reset to default")').waitFor();
  // 409: essential domain
  await page.fill('input[placeholder^="e.g. doubleclick"]', 'mtalk.google.com');
  await page.waitForSelector('.trk-dom tbody tr:has-text("mtalk.google.com")');
  await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().locator('button:has-text("Block")').click();
  await page.waitForSelector('dialog[open]:has-text("essential")');
  await page.waitForSelector('dialog[open] li:has-text("Push notifications")');
  await page.screenshot({ path: path.join(OUT, 'tracking-409.png') });
  await page.click('dialog button:has-text("Do not block")');
  await page.waitForSelector('dialog[open]', { state: 'detached' });
  if ((await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().textContent()).includes('Manual rule')) fail('409: rule created without confirmation');
  await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().locator('button:has-text("Block")').click();
  await page.waitForSelector('dialog[open]:has-text("essential")');
  await page.click('dialog button:has-text("Block anyway")');
  await page.waitForSelector('dialog[open]', { state: 'detached' });
  await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().locator('button:has-text("Reset to default")').waitFor();
  ok('409 essential domain: detail displayed, refusal without force, blocking with confirmation');
  await page.locator('.trk-dom tbody tr', { hasText: 'mtalk.google.com' }).first().locator('button:has-text("Reset to default")').click();
  await page.waitForTimeout(400);
  // Level
  await page.fill('input[placeholder^="e.g. doubleclick"]', '');
  await page.click('.level:has-text("Strict")');
  await page.click('button:has-text("Apply the")');
  await page.waitForSelector('dialog[open]:has-text("Switch to the")');
  await page.screenshot({ path: path.join(OUT, 'tracking-level-confirmation.png') });
  await page.click('dialog button:has-text("Change the level")');
  await page.waitForSelector('dialog[open]', { state: 'detached' });
  await page.waitForSelector('.level.is-sel:has-text("Strict") .badge:has-text("Current")');
  ok('blocking level: confirmation then change (strict)');
  await page.click('.level:has-text("Balanced")');
  await page.click('button:has-text("Apply the")');
  await page.click('dialog button:has-text("Change the level")');
  await page.waitForSelector('.level.is-sel:has-text("Balanced") .badge:has-text("Current")');
  // AdGuard unavailable
  await control({ adguard: false });
  await page.reload({ waitUntil: 'load' });
  await page.waitForSelector('.state-warn:has-text("Degraded mode")');
  await page.waitForSelector('.trk-dom tbody tr');
  const dis = await page.locator('.trk-dom tbody tr button.btn-sm').evaluateAll((els) => els.length === 0 || els.every((e) => e.disabled));
  const lvlDis = await page.locator('fieldset.levels').evaluate((e) => e.disabled);
  const txt = await page.textContent('.main');
  if (!dis || !lvlDis) fail('degraded mode: actions or level not disabled'); else ok('adguard=false: DNS-only view, actions and level disabled with explanation');
  if (txt.includes('Blocked') && (await page.locator('.trk-pub').textContent()).includes('Blocked / allowed')) fail('degraded mode: blocked/allowed columns displayed');
  await shot(page, sc, '09-tracking-degraded');
  // AdGuard unreachable but aggregates already stored: counts displayed, actions disabled
  await control({ adguard: false, stored: true });
  await page.reload({ waitUntil: 'load' });
  await page.waitForSelector('.state-warn:has-text("recorded before the outage")');
  await page.waitForSelector('.trk-dom tbody tr');
  const stDis = await page.locator('.trk-dom tbody tr button.btn-sm').evaluateAll((els) => els.length > 0 && els.every((e) => e.disabled));
  const stCols = await page.locator('.trk-pub').textContent();
  if (!stDis || !stCols.includes('Blocked / allowed')) fail('stored aggregates: counts missing or actions active'); else ok('adguard=false with stored aggregates: counts served, actions disabled, warning');
  await control({ adguard: true, stored: false });

  // ---- Notifications: content, hiding, hostile text displayed as text
  await page.goto(`${BASE}/events`, { waitUntil: 'load' });
  await settle(page, '.tbl');
  await page.click('button.seg-btn:has-text("7 days")');
  await page.fill('input[list=event-types]', 'app.notification');
  await page.waitForSelector('.tbl tbody tr:has-text("content hidden")', { timeout: 15000 });
  await page.fill('input[type=search]', 'Win a phone');
  await page.waitForSelector('.tbl tbody tr:has-text("Win a phone")', { timeout: 15000 });
  const hostile = await page.locator('.tbl tbody tr', { hasText: 'Win a phone' }).first().textContent();
  const imgs = await page.locator('.main img, .main b').count();
  if (!hostile.includes('<img src=x onerror=alert(1)>') || imgs) fail('hostile notification: markup interpreted'); else ok('notification: hostile title and text displayed as text, never interpreted');
  if (hostile.includes('‮')) fail('notification: bidirectional character kept');
  await page.screenshot({ path: path.join(OUT, 'events-notifications.png') });
  await page.goto(`${BASE}/map`, { waitUntil: 'load' });
  await settle(page, '.replay');
  await page.click('button.seg-btn:has-text("7 days")');
  await settle(page, '.replay');
  const prov = await page.textContent('.main');
  if (!/Provider/.test(prov) || !prov.includes('Providers')) fail('map: provider not indicated'); else ok('map: location provider indicated (point detail, legend, summary)');
  // Live follow on the map: a new location received while looking at the track
  await page.click('button.seg-btn:has-text("24 h")');
  await settle(page, '.replay');
  await page.waitForSelector('[data-testid=live-status]:has-text("connected")');
  const nBefore = await page.textContent('.replay-info');
  const other = await ctx.newPage();
  instrument(other, 'features-2', state);
  await other.goto(`${BASE}/commands`, { waitUntil: 'load' });
  await other.waitForSelector('.cmd-list');
  await other.click('button:has-text("Locate now")');
  await page.waitForSelector('[data-testid=live-status]:has-text("last location received")', { timeout: 20000 });
  const nAfter = await page.textContent('.replay-info');
  if (nBefore === nAfter) fail('map: the track did not receive the new location'); else ok('map: location received live added to the track after "Locate now"');
  await page.screenshot({ path: path.join(OUT, 'map-live-after-locate.png') });
  await other.close();

  const csp = await page.evaluate(() => window.__csp);
  if (csp.length) fail(`features: CSP violations: ${[...new Set(csp)].join(' | ')}`); else ok('no CSP violation (WebCrypto, native dialogs)');
  for (const e of state.errors) fail(e);
  const extra = [...state.hosts].filter((h) => h !== TILE_HOST);
  if (extra.length) fail(`features: third-party hosts: ${extra.join(', ')}`); else ok('no request to a third party');
  await ctx.close();
}

/** Version 1.2 walkthrough against the mock server in the "mixed" scenario (detections, risk, operations, roles, commands). */
async function runV12(browser) {
  console.log('\n== version 1.2: detections, risk profile, sensitive operations, roles, commands (mixed scenario)');
  const sc = { name: 'v12', scheme: 'light', viewport: { width: 1280, height: 900 } };
  const state = {
    errors: [],
    hosts: new Set(),
    // /apps/ops route absent (404): deliberately provoked to check the empty state; cancellation of a signed command.
    expected: (p, st) => (st === 400 && p.startsWith('/api/console/detections/mute')) || (st === 404 && p.startsWith('/api/console/apps/ops')) || (st === 401 && p === '/api/console/me') || (st === 409 && p.includes('/cancel')),
  };
  const ctx = await newContext(browser, sc, state);
  const page = await ctx.newPage();
  instrument(page, 'v12', state);
  await login(page);
  await control({ quiet: true, channel: 'stream', adguard: true, ops_mode: 'normal', agent: { disabled: false, wipe_allowed: true, code_configured: true, device_owner: true, locate_fail: false, deliver_ms: 300, exec_ms: 500 } });

  // ---- Detections: the twelve types, an unknown type, hostile text, filters
  await page.goto(`${BASE}/detections`, { waitUntil: 'load' });
  await settle(page, '[data-testid=detection]');
  const types = new Set(await page.locator('[data-testid=detection]').evaluateAll((els) => els.map((e) => e.getAttribute('data-type'))));
  const want = ['threat_domain', 'upload_spike', 'fanout', 'mail_ports', 'dns_bypass', 'sms_abuse', 'sensor_background', 'new_app_risky', 'sms_permission', 'default_app_changed', 'flood', 'inventory_mismatch'].map((t) => `detect.${t}`);
  const missing = want.filter((t) => !types.has(t));
  if (missing.length) fail(`detections: missing types: ${missing.join(', ')}`); else ok(`detections: the 12 types of contracts §11.3 and §11.4 displayed (${types.size} types including one outside the catalogue)`);
  if (!types.has('detect.quantum_leak')) fail('detections: unknown type not displayed'); else ok('detection of unknown type: displayed with its code and description');
  const main = await page.textContent('.main');
  if (!main.includes('tried to reach the domain')) fail('detections: "what was observed" sentence missing'); else ok('detections: what was observed is written in plain words');
  for (const needle of ['Why it is suspicious', 'What innocent things it could be', 'What to do', 'Evidence items']) {
    const n = await page.locator(`.det h4:has-text("${needle}")`).count();
    if (n < 1) fail(`detections: section "${needle}" missing`);
  }
  await page.waitForSelector(`.det .btn:has-text("Application detail page")`);
  if (!(await page.locator('.det-guard').count())) fail('detections: reminder of the app guard missing'); else ok('detections: evidence, why, innocent explanations, what to do, links and guard reminder');
  if (await page.evaluate(() => window.__pwn !== undefined || !!document.querySelector('.main img, .main script'))) fail('detections: hostile text interpreted'); else ok('hostile application names, domains and reasons: displayed as text');
  if (!main.includes('<img src=x onerror=window.__pwn=1>') || !main.includes('<script>window.__pwn=2</script>.top')) fail('detections: hostile text not displayed as is');
  if (main.includes('‮')) fail('detections: bidirectional character kept');
  await page.screenshot({ path: path.join(OUT, 'v12-detections-mixed.png'), fullPage: true });
  // Filter by type, then by severity
  await page.selectOption('select[aria-label="Detection type"]', 'detect.sms_abuse');
  await page.waitForFunction(() => { const c = [...document.querySelectorAll('[data-testid=detection]')]; return c.length > 0 && c.every((e) => e.getAttribute('data-type') === 'detect.sms_abuse'); }, null, { timeout: 15000 });
  ok('filter by type: only "Abnormal SMS sending"');
  await page.selectOption('select[aria-label="Detection type"]', '');
  await page.selectOption('select[aria-label="Minimum severity"]', '3');
  await page.waitForFunction(() => { const c = [...document.querySelectorAll('[data-testid=detection]')]; return c.length > 0 && c.every((e) => e.classList.contains('det-sev-3')); }, null, { timeout: 15000 });
  ok('severity filter: critical only');
  await page.selectOption('select[aria-label="Minimum severity"]', '0');
  // Period: 24 h then 30 days
  await page.click('button.seg-btn:has-text("24 h")');
  await page.waitForTimeout(800);
  const n24 = await page.locator('[data-testid=detection]').count();
  await page.click('button.seg-btn:has-text("30 days")');
  await page.waitForTimeout(800);
  const n30 = await page.locator('[data-testid=detection]').count();
  if (!(n24 > 0 && n30 > n24)) fail(`period: ${n24} detections over 24 h, ${n30} over 30 days`); else ok(`period filter: ${n24} detections over 24 h, ${n30} over 30 days`);
  await page.click('button.seg-btn:has-text("7 days")');
  await page.waitForTimeout(500);

  // ---- §11.4: detections without app.ops, review, SMS role, cap, recurrence
  const smsPerm = page.locator('[data-testid=detection][data-type="detect.sms_permission"]').first();
  await smsPerm.waitFor();
  const smsPermTxt = await smsPerm.textContent();
  if (!/To check/.test(smsPermTxt) || !/is this intended/i.test(smsPermTxt) || !/review/.test(smsPermTxt) || !/SMS guard/.test(smsPermTxt)) fail('sms_permission: review "is this intended?" and pointer to the SMS guard missing'); else ok('sms_permission: presented as a review ("is this intended?"), pointing to the SMS guard of the app');
  const defApp = page.locator('[data-testid=detection][data-type="detect.default_app_changed"]', { hasText: 'default SMS app' }).first();
  await defApp.waitFor();
  await defApp.locator('summary').click();
  const roleTxt = await defApp.locator('[data-testid=det-sms-role]').textContent();
  if (!/classic route of SMS trojans/.test(roleTxt)) fail('default_app_changed (sms): classic route of SMS trojans not stated'); else ok('default_app_changed on the SMS role: "the classic route of SMS trojans" stated plainly');
  if (await defApp.locator('[data-testid=mute-btn]').count()) fail('default_app_changed: muting offered although the type is not mutable');
  const flood = page.locator('[data-testid=detection][data-type="detect.flood"]').first();
  await flood.waitFor();
  await flood.locator('summary').click();
  const floodTxt = await flood.textContent();
  if (!/More than 200 detections/.test(floodTxt) || !/212 more/.test(floodTxt) || !/compromised/.test(floodTxt) || (await flood.locator('[data-testid=mute-btn]').count())) fail('flood: sentence, explanation or absence of mute incorrect'); else ok('flood: cap of 200 detections explained (faulty agent or compromised device), not mutable');
  const smsAbuse = page.locator('[data-testid=detection][data-type="detect.sms_abuse"]').first();
  await smsAbuse.locator('summary').click();
  if (await smsAbuse.locator('[data-testid=mute-btn]').count()) fail('sms_abuse: muting offered'); else ok('sms_abuse: no muting (non-mutable type)');
  const recurring = await page.locator('[data-testid=detection] .badge:has-text("Already reported, recurring")').count();
  if (recurring < 1) fail('recurrence: "already reported, recurring" badge missing'); else ok(`recurrence: ${recurring} detection(s) "already reported, recurring" (severity capped at 1)`);

  // ---- Verdict: what is monitored and what is not (app_ops collector running in this scenario)
  const scopeTxt = await page.textContent('[data-testid=verdict-scope]');
  if (await page.locator('[data-testid=verdict-blind]').count() || !/does not prove that data is arriving/.test(scopeTxt) || !/SMS guard/.test(scopeTxt) || !/permission to send SMS/.test(scopeTxt)) fail('verdict (app_ops running): scope text incorrect'); else ok('verdict with app_ops running: scope stated (SMS permission, default app), "running" does not prove that data is arriving, SMS guard = real protection');

  // ---- Mutes (§11.4)
  const folded = await page.locator('[data-testid=detection][data-muted=true]').count();
  if (folded) fail('mute: muted detection not collapsed by default');
  const showMuted = page.locator('label.check:has-text("Show muted detections")');
  await showMuted.waitFor();
  const mutedLabel = await showMuted.textContent();
  await page.waitForSelector('[data-testid=mutes-table] tbody tr:has-text("Chrome")');
  const mt = await page.textContent('[data-testid=mutes-table]');
  if (!/Chrome uses secure DNS/.test(mt) || !/Lift the mute/.test(mt)) fail('current mutes: reason or lifting missing'); else ok(`current mutes listed with reason and lifting; muted detection collapsed (${mutedLabel.trim()})`);
  await showMuted.locator('input').check();
  await page.waitForSelector('[data-testid=detection][data-muted=true] .badge:has-text("Muted")');
  ok('"Show muted detections" filter: the collapsed detection reappears, marked');
  await showMuted.locator('input').uncheck();
  // Muting: Sync Helper / DNS bypass
  const syncDns = page.locator('[data-testid=detection][data-type="detect.dns_bypass"]', { hasText: 'Sync Helper' }).first();
  await syncDns.waitFor();
  const syncId = await syncDns.getAttribute('data-id');
  await syncDns.locator('summary').click();
  await syncDns.locator('[data-testid=mute-btn]').click();
  await page.waitForSelector('dialog[open]');
  const mdlg = await page.textContent('dialog[open]');
  if (!/computed and recorded/.test(mdlg) || !/no longer be sent to Wazuh or notified/.test(mdlg) || !/lift the mute/.test(mdlg)) fail('mute dialog: incomplete explanation'); else ok('mute dialog: the detection is still computed, but will no longer be sent to Wazuh or notified; lifting possible');
  await page.screenshot({ path: path.join(OUT, 'v12-mute-dialog.png') });
  await page.fill('dialog textarea', 'Intended resolver (test)');
  await page.click('dialog button:has-text("Mute")');
  await page.waitForSelector('dialog[open]', { state: 'detached' });
  await page.waitForSelector('[data-testid=mute-notice]');
  await page.waitForFunction((id) => !document.querySelector(`[data-testid=detection][data-id="${id}"]:not([data-muted=true])`), syncId, { timeout: 10000 });
  await page.waitForSelector('[data-testid=mutes-table] tbody tr:has-text("Intended resolver (test)")');
  ok('muting: detection collapsed, mute listed with its reason, verdict lightened');
  const mutesApi = await page.evaluate(async () => (await (await fetch('/api/console/detections/mutes')).json()).mutes);
  if (!mutesApi.some((m) => m.package === 'com.sync.helper.svc' && m.type === 'detect.dns_bypass' && m.reason === 'Intended resolver (test)')) fail('mute: not recorded on the server side');
  await page.waitForFunction(() => document.querySelector('[data-testid=verdict-muted]'), null, { timeout: 5000 });
  // Event log: the detect.muted server event is readable (seen below); lifting from the mutes list
  await page.click('[data-testid=mutes-table] tr:has-text("Intended resolver") button:has-text("Lift the mute")');
  await page.waitForFunction(() => !document.querySelector('[data-testid=mutes-table] tr')?.parentElement?.textContent.includes('Intended resolver (test)'), null, { timeout: 10000 });
  await page.waitForSelector(`[data-testid=detection][data-id="${syncId}"]:not([data-muted=true])`);
  ok('mute lifted: the detection is reported again');
  // An update received live replaces the existing detection (no duplicate)
  const nBefore = await page.locator('[data-testid=detection]').count();
  await control({ emit_detection: { type: 'detect.dns_bypass', package: 'com.sync.helper.svc', label: 'Sync Helper', severity: 2, update: true, detection_id: syncId, evidence: { connections: 999, resolvers: ['1.1.1.1:443'], providers: ['Cloudflare DNS'] }, summary: 'update' } });
  await page.waitForFunction(([id]) => document.querySelector(`[data-testid=detection][data-id="${id}"]`)?.textContent.includes('999'), [syncId], { timeout: 15000 });
  const nAfter = await page.locator('[data-testid=detection]').count();
  if (nAfter !== nBefore) fail(`live update: ${nBefore} → ${nAfter} cards (duplicate)`); else ok('live update (update + detection_id): the card is replaced, without duplicate');
  // Mute refused by the server for a non-mutable type: clear message, nothing muted
  const refused = await page.evaluate(async () => {
    const r = await fetch('/api/console/detections/mute', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'watchpost' }, body: JSON.stringify({ device_id: 'dev_8f3a1c2e9b7d', type: 'detect.sms_abuse', package: 'com.wallpapers.superhd' }) });
    return r.status;
  });
  if (refused !== 400) fail(`mute of a non-mutable type: status ${refused} instead of 400`);

  // Cursor pagination: 70 more detections
  await control({ more_detections: 70 });
  await page.click('button:has-text("Refresh")');
  await page.waitForSelector('button:has-text("Load more")', { timeout: 15000 });
  const p1 = await page.locator('[data-testid=detection]').count();
  for (let i = 0; i < 6 && (await page.locator('button:has-text("Load more")').count()); i++) {
    const before = await page.locator('[data-testid=detection]').count();
    await page.click('button:has-text("Load more")');
    await page.waitForFunction((n) => document.querySelectorAll('[data-testid=detection]').length > n, before, { timeout: 15000 });
  }
  const total = await page.locator('[data-testid=detection]').count();
  const uniq = new Set(await page.locator('[data-testid=detection] .det-time').evaluateAll((els) => els.map((e) => e.getAttribute('datetime') + e.closest('li').textContent.slice(0, 80)))).size;
  if (!(await page.textContent('.main')).includes('end of the list') || total <= p1) fail('pagination: end of list not reached'); else ok(`cursor pagination: ${p1} then ${total} detections (${uniq} distinct), end of list reached`);

  // Live arrival (SSE)
  await page.evaluate(() => window.scrollTo(0, 0));
  await control({ emit_detection: { type: 'detect.sms_abuse', package: 'com.wallpapers.superhd', label: 'Super Wallpapers HD', severity: 3, evidence: { reason: 'not_default_sms_app', sent: 777, background: 770 }, summary: 'live' } });
  await page.waitForSelector('.det.is-new:has-text("777 SMS")', { timeout: 15000 });
  ok('detection received live through the SSE stream: "new" card displayed without reloading');
  await page.screenshot({ path: path.join(OUT, 'v12-detections-live.png') });

  // ---- Overview: summary by severity
  await page.goto(`${BASE}/`, { waitUntil: 'load' });
  await settle(page, '[data-testid=verdict]');
  const ov = await page.textContent('[data-testid=overview-detections]');
  if (!/Monitored in all cases/.test(ov) || !/SMS guard/.test(ov)) fail('overview: monitoring scope and SMS guard not stated'); else ok('overview: the verdict states what is monitored and that the SMS guard is the real protection');
  const critBefore = Number((/(\d+)\s*critical/.exec(ov) || [])[1] || 0);
  if (!/to examine/.test(ov) || !critBefore) fail('overview: summary of detections by severity missing'); else ok(`overview: ${critBefore} critical over 7 days, summary by severity`);
  await control({ emit_detection: { type: 'detect.sensor_background', package: 'com.sync.helper.svc', label: 'Sync Helper', severity: 3, evidence: { op: 'camera', background_count: 9, count: 9 }, summary: 'live' } });
  await page.waitForFunction((n) => { const m = /(\d+)\s*critical/.exec(document.querySelector('[data-testid=overview-detections]')?.textContent || ''); return m && Number(m[1]) > n; }, critBefore, { timeout: 15000 });
  ok('overview: the summary updates when a detection arrives');
  await page.screenshot({ path: path.join(OUT, 'v12-overview-mixed.png'), fullPage: true });

  // ---- Alerts: link with detections
  await page.goto(`${BASE}/alerts`, { waitUntil: 'load' });
  await page.waitForSelector('.net-intro a[href="/detections"]');
  ok('alerts: pointer to the Detections page');

  // ---- Applications: risk profile
  await page.goto(`${BASE}/apps`, { waitUntil: 'load' });
  await settle(page, '[data-testid=risk-table]');
  const scores = await page.locator('[data-testid=risk-table] tbody .risk-score strong').allTextContents();
  const nums = scores.map(Number);
  if (nums.length < 10 || nums.some((n, i) => i > 0 && n > nums[i - 1])) fail('risk profile: decreasing score order not respected'); else ok(`risk profile: ${nums.length} applications sorted by score (${nums[0]} … ${nums[nums.length - 1]})`);
  const high = await page.locator('[data-testid=risk-table] tr.risk-high').count();
  const tbl = await page.textContent('[data-testid=risk-table]');
  const combos = ['Banking trojan profile', 'SMS fraud profile', 'Stalkerware profile'].filter((c) => tbl.includes(c));
  if (combos.length !== 3 || high < 3) fail(`risk profile: combinations ${combos.length}/3, high levels ${high}`); else ok('risk profile: the three combinations (bank, SMS, spy) highlighted, high levels spotted');
  await page.check('label.check:has-text("Combinations only") input');
  await page.waitForFunction(() => document.querySelectorAll('[data-testid=risk-table] tbody tr').length === 3, null, { timeout: 5000 });
  await page.uncheck('label.check:has-text("Combinations only") input');
  await page.fill('input[placeholder="name or package"]', 'waze');
  await page.click('[data-testid=risk-table] .expander');
  await page.waitForSelector('.reasons li:has-text("quantum_overlay")');
  const unknown = await page.textContent('.reasons');
  if (!unknown.includes('unknown code') || !unknown.includes('Background location')) fail('risk profile: unknown code / explanations missing'); else ok('risk profile: reasons explained in plain words; an unknown code is displayed as is');
  await page.screenshot({ path: path.join(OUT, 'v12-risk-reasons.png') });
  // Declared / granted (§11.4): Fast Cleaner requests the background microphone and camera without having obtained them
  await page.fill('input[placeholder="name or package"]', 'fast cleaner');
  await page.click('[data-testid=risk-table] .expander');
  await page.waitForSelector('.reasons li:has-text("Microphone or camera in the background")');
  const gr = await page.textContent('.reasons');
  const decl = await page.locator('.reasons li:has-text("Microphone or camera in the background") .badge:has-text("Requested, not granted")').count();
  const accd = await page.locator('.reasons li:has-text("Accessibility service") .badge:has-text("Granted")').count();
  const noteTxt = await page.textContent('[data-testid=grant-note]');
  if (!decl || !accd || !/requests/.test(noteTxt) || !/guard/.test(noteTxt) || /Requested, not granted/.test(await page.locator('.reasons li:has-text("Installed outside a store")').textContent())) fail('risk: requested / granted distinction missing or misplaced'); else ok('risk: distinguishes what the application requests from what it obtained (microphone/camera requested, not granted; accessibility granted); the "outside a store" state is not marked');
  void gr;

  // ---- Application detail page (direct opening: the package contains dots)
  await page.goto(`${BASE}/apps/detail?pkg=com.wallpapers.superhd`, { waitUntil: 'load' });
  await page.waitForSelector('.sheet-head h1:has-text("Super Wallpapers HD")');
  await page.waitForSelector('.det');
  const sheet = await page.textContent('.main');
  for (const needle of ['Risk profile', 'Default roles', 'Detections concerning this application', 'Dangerous permissions granted', 'Sensitive operations', 'Domains contacted', 'SMS fraud profile']) {
    if (!sheet.includes(needle)) fail(`application detail page: "${needle}" missing`);
  }
  const sheetPkgs = await page.locator('.det .det-meta .mono').allTextContents();
  if (!sheetPkgs.length || sheetPkgs.some((t) => !t.includes('com.wallpapers.superhd'))) fail('detail page: detections of other applications displayed'); else ok(`application detail page (direct opening): profile, roles, permissions, operations, domains, ${sheetPkgs.length} detections of this application`);
  await page.waitForSelector('[data-testid=sheet-ops]');
  await page.reload({ waitUntil: 'load' });
  await page.waitForSelector('.sheet-head h1:has-text("Super Wallpapers HD")');
  ok('application detail page: page reload (no 404)');
  await page.goto(`${BASE}/apps/detail?pkg=${encodeURIComponent('com.fastcleaner.pro')}`, { waitUntil: 'load' });
  await page.waitForSelector(`.role-list:has-text("Call screening")`);
  ok('application detail page: "Call screening" role held by a suspicious application');
  await page.goto(`${BASE}/apps/detail?pkg=${encodeURIComponent('com.hostile.app')}`, { waitUntil: 'load' });
  await page.waitForSelector('.det');
  if (await page.evaluate(() => window.__pwn !== undefined)) fail('detail page: hostile text interpreted');
  await page.screenshot({ path: path.join(OUT, 'v12-detail-hostile.png'), fullPage: true });

  // ---- Sensitive operations: present, empty, route absent
  await page.goto(`${BASE}/apps?tab=ops`, { waitUntil: 'load' });
  await settle(page, '[data-testid=ops-cards]');
  const ops = await page.textContent('[data-testid=ops-cards]');
  if (!/SMS sending/.test(ops) || !/1,984/.test(ops) || !/1,790 in the background/.test(ops)) fail('sensitive operations: SMS sending (1,984, of which 1,790 in the background) missing'); else ok('sensitive operations: who sends SMS, how many, including in the background');
  for (const needle of ['Calls placed', 'Contact reading', 'Microphone', 'Camera']) if (!ops.includes(needle)) fail(`sensitive operations: "${needle}" missing`);
  await page.screenshot({ path: path.join(OUT, 'v12-operations-present.png'), fullPage: true });
  for (const mode of ['empty', '404']) {
    await control({ ops_mode: mode });
    await page.reload({ waitUntil: 'load' });
    await settle(page, '[data-testid=ops-empty]');
    const e = await page.textContent('[data-testid=ops-empty]');
    const broken = await page.locator('.state-error').count();
    if (broken || !/grant-adb-permissions/.test(e) || !/DUMP/.test(e) || !/Collectors/.test(e)) fail(`sensitive operations (${mode}): incomplete empty state or broken screen`);
    else ok(`sensitive operations absent (${mode}): empty state explaining the activation (DUMP through ADB, experimental collector), no error`);
  }
  await page.screenshot({ path: path.join(OUT, 'v12-operations-absent.png'), fullPage: true });
  await control({ ops_mode: 'normal' });

  // ---- Security: default roles
  await page.goto(`${BASE}/security?tab=roles`, { waitUntil: 'load' });
  await settle(page, '[data-testid=roles-table]');
  const roles = await page.textContent('[data-testid=roles-table]');
  if (!roles.includes('Browser') || !roles.includes('Assistant') || !roles.includes('Call screening') || !roles.includes('com.fastcleaner.pro')) fail('default roles: incomplete history'); else ok('security: default role change history (including a worrying call screening one)');

  // ---- Event log: readable tracking events (changes made from the console, as the Tracking page would)
  await page.evaluate(async () => {
    const put = (path, body) => fetch(`/api/console/tracking/${path}`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'watchpost' }, body: JSON.stringify(body) });
    await put('level', { level: 'strict' });
    await put('override', { domain: 'classifieds.example.org', action: 'block' });
    await put('override', { domain: 'classifieds.example.org', action: 'default' });
    await put('level', { level: 'balanced' });
  });
  await page.goto(`${BASE}/events`, { waitUntil: 'load' });
  await settle(page, '.tbl');
  await page.click('button.seg-btn:has-text("7 days")');
  await page.fill('input[list=event-types]', 'tracking.');
  await page.waitForSelector('.tbl tbody tr:has-text("Blocking level")', { timeout: 15000 });
  const jt = await page.textContent('.tbl');
  if (!/Blocking level: .+ → .+ · by admin/.test(jt) || !/Rule for "classifieds\.example\.org": block/.test(jt)) fail('event log: tracking.level_changed / tracking.override unreadable'); else ok('event log: tracking.level_changed and tracking.override described in plain words (who, what, before → after)');
  await page.fill('input[list=event-types]', 'detect.');
  await page.waitForSelector('.tbl tbody tr:has-text("tried to reach")', { timeout: 15000 });
  ok('event log: detections described in plain words');
  await page.waitForSelector('.tbl tbody tr:has-text("Muted: Bypass of the phone\'s DNS for com.sync.helper.svc · reason: Intended resolver (test) · by admin")', { timeout: 15000 });
  await page.waitForSelector('.tbl tbody tr:has-text("Mute lifted")');
  ok('event log: detect.muted and detect.unmuted readable (type, application, reason, who)');

  // ---- Commands: erase validity and texts on the limits of the signature
  await page.goto(`${BASE}/commands`, { waitUntil: 'load' });
  await settle(page, '.cmd-list');
  const sl = await page.textContent('[data-testid=server-limits]');
  for (const needle of ['five randomly chosen words', 'only commit the server', 'Only changing the passphrase', 'do not enter the passphrase here any more', 'served by the server']) {
    if (!sl.includes(needle)) fail(`commands: text "${needle}" missing from the signature limits`);
  }
  if (sl.includes('can neither lock nor erase')) fail('commands: old excessive promise still displayed');
  await page.click('button:has-text("Erase the phone…")');
  await page.waitForSelector('dialog[open]');
  await page.check('dialog input[type=checkbox]');
  await page.click('dialog button:has-text("Continue")');
  await page.fill('dialog input[type=text]', 'phone');
  await page.click('dialog button:has-text("Continue")');
  const wipeOpts = await page.locator('dialog select option').allTextContents();
  const wipeSel = await page.locator('dialog select').evaluate((e) => e.options[e.selectedIndex].textContent);
  if (wipeSel !== '15 minutes (default)' || !wipeOpts.includes('24 hours (maximum)') || wipeOpts.some((o) => /days/.test(o))) fail(`erase: validities ${wipeOpts.join(' | ')} (default: ${wipeSel})`); else ok('erase: validity 15 minutes by default, 24 hours at most');
  const dlg = await page.textContent('dialog');
  if (!/only commit the server/.test(dlg) || !/five randomly chosen words/.test(dlg) || !/do not enter the passphrase here any more/.test(dlg)) fail('erase dialog: signature limits not stated'); else ok('dialog: "cancelled / expired only commit the server", high-entropy passphrase, stop entering the passphrase if the server is suspect');
  await page.screenshot({ path: path.join(OUT, 'v12-commands-erase-validity.png') });
  await page.keyboard.press('Escape');
  await page.waitForSelector('dialog[open]', { state: 'detached' });
  // Signed lock pending then cancelled: "server side" only
  await control({ channel: 'offline' });
  await page.reload({ waitUntil: 'load' });
  await settle(page, '.cmd-list');
  await page.click('button:has-text("Lock…")');
  await page.waitForSelector('dialog[open]');
  await page.fill('dialog textarea', 'Test v1.2');
  await page.check('dialog input[type=checkbox]');
  await page.fill('#cmd-code', RIGHT_CODE);
  await page.click('dialog button:has-text("Sign and send")');
  await page.waitForSelector('dialog[open]', { state: 'detached', timeout: 20000 });
  await page.waitForSelector('.cmd-tbl tbody tr:first-child:has-text("Pending")');
  await page.click('.cmd-tbl tbody tr:first-child button:has-text("Cancel")');
  await page.waitForSelector('.cmd-tbl tbody tr:first-child:has-text("Cancelled (server side)")');
  await page.waitForSelector(`.state-warn:has-text("only commits the server")`);
  ok('signed command cancelled: displayed "Cancelled (server side)" with the caveat on the signature');
  await control({ channel: 'stream' });

  const csp = await page.evaluate(() => window.__csp);
  if (csp.length) fail(`v12: CSP violations: ${[...new Set(csp)].join(' | ')}`); else ok('no CSP violation');
  for (const e of state.errors) fail(e);
  const extra = [...state.hosts].filter((h) => h !== TILE_HOST);
  if (extra.length) fail(`v12: third-party hosts: ${extra.join(', ')}`); else ok('no request to a third party');
  await ctx.close();
}

/** "Healthy phone" and "SMS fraud" scenarios: screenshots in the four configurations, and findings. */
async function runV12Scenario(browser, scenario, scenarios) {
  console.log(`\n== version 1.2: scenario ${scenario}`);
  for (const sc of scenarios) {
    const state = { errors: [], hosts: new Set() };
    const ctx = await newContext(browser, sc, state);
    const page = await ctx.newPage();
    instrument(page, `${scenario}-${sc.name}`, state);
    await login(page);
    const named = { ...sc, name: `${scenario}-${sc.name}` };
    const light = sc.name === 'light-desktop';
    // Detections
    await page.goto(`${BASE}/detections`, { waitUntil: 'load' });
    await settle(page, '[data-testid=verdict]');
    const v = await page.textContent('[data-testid=verdict]');
    if (light) {
      if (scenario === 'healthy') {
        if (!/Nothing to report/.test(v) || (await page.locator('[data-testid=detection]').count())) fail('healthy scenario: "Nothing to report" expected'); else ok('healthy scenario: "Nothing to report", no detection');
      } else {
        if (!/to examine/.test(v) || !/Super Wallpapers HD/.test(v)) fail('sms-fraud scenario: most worrying application not designated'); else ok(`sms-fraud scenario: ${v.match(/\d+ detections? to examine/)?.[0]}, most worrying application designated`);
        const sms = await page.locator('[data-testid=detection][data-type="detect.sms_abuse"]').count();
        if (!sms) fail('sms-fraud scenario: no SMS sending detection'); else ok(`sms-fraud scenario: ${sms} abnormal SMS sending detection(s), critical severity`);
        const txt = await page.textContent('[data-testid=detection][data-type="detect.sms_abuse"]');
        if (!/SMS/.test(txt) || !/background/.test(txt)) fail('sms-fraud scenario: SMS sentence without background');
      }
    }
    if (light) {
      const blind = await page.locator('[data-testid=verdict-blind]').count();
      const scope = await page.textContent('[data-testid=verdict-scope]');
      if (scenario === 'healthy') {
        if (!blind || !/SMS sending itself/.test(await page.textContent('[data-testid=verdict-blind]')) || !/SMS guard/.test(scope)) fail('healthy scenario: the green verdict does not say that SMS sending is not monitored'); else ok('healthy scenario: "Nothing to report" AND "not monitored: SMS sending itself" (app_ops disabled), SMS guard recalled');
      } else if (blind) fail('sms-fraud scenario: blind spot announced although app_ops is running');
    }
    await shot(page, named, '10-detections');
    // Overview
    await page.goto(`${BASE}/`, { waitUntil: 'load' });
    await settle(page, '[data-testid=verdict]');
    await shot(page, named, '01-overview');
    // Risk
    await page.goto(`${BASE}/apps`, { waitUntil: 'load' });
    await settle(page, '[data-testid=risk-table]');
    if (light) {
      const high = await page.locator('[data-testid=risk-table] tr.risk-high').count();
      if (scenario === 'healthy' && high) fail(`healthy scenario: ${high} high-risk application(s)`);
      else if (scenario === 'sms-fraud' && high !== 1) fail(`sms-fraud scenario: ${high} high-risk application(s) (1 expected)`);
      else ok(`${scenario}: ${high} high-risk application(s)`);
    }
    await shot(page, named, '05-apps-risk');
    // Operations
    await page.goto(`${BASE}/apps?tab=ops`, { waitUntil: 'load' });
    await settle(page, scenario === 'healthy' ? '[data-testid=ops-empty]' : '[data-testid=ops-cards]');
    if (light) {
      if (scenario === 'healthy') {
        const e = await page.textContent('[data-testid=ops-empty]');
        if (!/grant-adb-permissions/.test(e) || (await page.locator('.state-error').count())) fail('healthy scenario: incorrect operations empty state'); else ok('healthy scenario: app.ops absent, explanatory empty state');
      } else {
        const o = await page.textContent('[data-testid=ops-cards]');
        if (!/1,984/.test(o)) fail('sms-fraud scenario: 1,984 SMS expected'); else ok('sms-fraud scenario: app.ops shows 1,984 SMS of which 1,790 in the background');
      }
    }
    await shot(page, named, '05-apps-operations');
    // Detail page
    if (scenario === 'sms-fraud') {
      await page.goto(`${BASE}/apps/detail?pkg=com.wallpapers.superhd`, { waitUntil: 'load' });
      await settle(page, '.reasons');
      await shot(page, named, '11-app-detail');
    }
    // Roles
    await page.goto(`${BASE}/security?tab=roles`, { waitUntil: 'load' });
    await settle(page, '[data-testid=roles-table]');
    await shot(page, named, '06-security-roles');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    if (overflow > 1) fail(`${named.name}: horizontal scroll (${overflow}px)`);
    const csp = await page.evaluate(() => window.__csp);
    if (csp.length) fail(`${named.name}: CSP violations: ${[...new Set(csp)].join(' | ')}`);
    for (const e of state.errors) fail(e);
    const extra = [...state.hosts].filter((h) => h !== TILE_HOST);
    if (extra.length) fail(`${named.name}: third-party hosts: ${extra.join(', ')}`);
    await ctx.close();
  }
  ok(`${scenario}: four configurations (light/dark, desktop/phone) without console error, CSP violation or third-party request`);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
