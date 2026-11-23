// Drives a real browser (Microsoft Edge, headless) through every case and checks what the attacker received.
// Requires Edge (ships with Windows) or set EDGE_PATH. Node 22+ (global WebSocket).
const fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const assert = require('assert');
const { start, sri, CLEAN, SKIMMER } = require('./server');

const EDGE = process.env.EDGE_PATH || ['C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', 'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium'].find((p) => fs.existsSync(p));
if (!EDGE) throw new Error('No Edge/Chrome found. Set EDGE_PATH.');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function openBrowser(port) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'sri-test-'));
  const proc = spawn(EDGE, ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--no-first-run', '--disable-extensions', 'about:blank'], { stdio: 'ignore' });
  let wsUrl;
  for (let i = 0; i < 60 && !wsUrl; i++) {
    try { wsUrl = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((x) => x.type === 'page')?.webSocketDebuggerUrl; } catch {}
    if (!wsUrl) await sleep(250);
  }
  if (!wsUrl) throw new Error('browser did not start');
  const ws = new WebSocket(wsUrl); await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let id = 1; const pending = new Map();
  ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.method === 'Log.entryAdded' && process.env.DBG) console.log('   browser:', d.params.entry.text.slice(0, 160)); if (d.id && pending.has(d.id)) { pending.get(d.id)(d.result); pending.delete(d.id); } };
  const cdp = (method, params = {}) => new Promise((r) => { const i = id++; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  await cdp('Page.enable'); await cdp('Runtime.enable'); await cdp('Log.enable');
  return { cdp, close: () => { ws.close(); proc.kill(); try { fs.rmSync(profile, { recursive: true, force: true }); } catch {} } };
}

(async () => {
  const srv = start();
  const br = await openBrowser(9444);
  const ev = async (expr) => (await br.cdp('Runtime.evaluate', { expression: expr, returnByValue: true })).result.value;

  // Load the checkout page with a given defense, type a (fake test) card number, click Pay.
  async function visit(defense) {
    srv.state.stolen.length = 0;
    await br.cdp('Page.navigate', { url: 'about:blank' });            // fresh document every time, so no state carries over
    await sleep(150);
    await br.cdp('Page.navigate', { url: `http://localhost:${srv.PORTS.site}/?defense=${defense}` });
    await sleep(900);
    assert.ok((await ev('location.href')).endsWith('defense=' + defense), 'page did not navigate');
    await ev(`(() => { const c = document.getElementById('card'); c.value = '4242 4242 4242 4242'; c.dispatchEvent(new Event('input')); document.getElementById('pay').click(); })()`);
    await sleep(700);
    const out = { vendorRan: await ev('window.__vendorLoaded === true'), stolen: srv.state.stolen.length, chat: await ev('document.getElementById("chat").textContent'), href: await ev('location.href') }; if (process.env.DBG) console.log(defense, out); return out;
  }
  let n = 0;
  const t = async (name, fn) => { await fn(); n++; console.log('ok  ' + name); };

  try {
    await t('sri hash matches the clean file and differs for the tampered one', async () => {
      assert.notStrictEqual(sri(CLEAN), sri(SKIMMER));
      assert.strictEqual(srv.state.pinned, sri(CLEAN));
    });

    srv.state.vendor = 'tampered';
    await t('NO defense: tampered script runs and steals the card number', async () => {
      const r = await visit('none'); assert.strictEqual(r.vendorRan, true); assert.ok(r.stolen > 0, 'expected a leak');
    });
    await t('SRI: tampered script is blocked, nothing stolen', async () => {
      const r = await visit('sri'); assert.strictEqual(r.vendorRan, false); assert.strictEqual(r.stolen, 0);
    });
    await t('CSP: script still RUNS, but it can not send anything out', async () => {
      const r = await visit('csp'); assert.strictEqual(r.vendorRan, true); assert.strictEqual(r.stolen, 0);
    });
    await t('both: blocked and contained', async () => {
      const r = await visit('both'); assert.strictEqual(r.vendorRan, false); assert.strictEqual(r.stolen, 0);
    });

    srv.state.vendor = 'clean';
    await t('clean script works with every defense', async () => {
      for (const d of ['none', 'sri', 'csp', 'both']) { const r = await visit(d); assert.strictEqual(r.vendorRan, true, d); assert.strictEqual(r.stolen, 0, d); }
    });

    srv.state.vendor = 'updated';
    await t('LIMIT: SRI also blocks an honest vendor update (that is why it cannot pin a script that changes)', async () => {
      const r = await visit('sri'); assert.strictEqual(r.vendorRan, false);
      const ok = await visit('csp'); assert.strictEqual(ok.vendorRan, true);
    });
    console.log(`\n${n} tests passed`);
  } finally { br.close(); srv.close(); }
})().catch((e) => { console.error('FAIL', e.message); process.exit(1); });

