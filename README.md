# third-party-script

Day 4. What happens when a script you trust, loaded from someone else's server, changes without you? This repo rebuilds the problem on localhost and tests two defenses in a real browser. Zero dependencies. Needs Node 22+ and Microsoft Edge or Chrome for the tests.

Inspired by the November 2026 incident where researchers reported malicious JavaScript served through a compromised third-party script (Optimizely) to 178+ organizations. This repo is a small model of the *class* of problem. It does not reproduce that attack and uses no real service.

## What is in it

`server.js` starts three local servers:

| Server | Port | Role |
|--------|------|------|
| site | 3100 | A checkout page that loads a third-party chat script |
| vendor | 3101 | Serves the script: clean, tampered (skims the card field), or an honest update |
| attacker | 3102 | A local stand-in that records whatever a malicious script sends it |

The page takes `?defense=none|sri|csp|both`.

## The two defenses

- **Subresource Integrity (SRI):** the page pins the script's hash. If the bytes change, the browser refuses to run it.
- **Content Security Policy (CSP):** the page says where scripts may connect and load images from. A tampered script may still run, but it can not send data out.

## Test results (`npm test`, real Edge, headless)

| Case | Script runs? | Card number stolen? |
|------|--------------|---------------------|
| no defense, tampered | yes | **yes** |
| SRI, tampered | no (blocked) | no |
| CSP, tampered | yes | no (blocked) |
| SRI + CSP, tampered | no | no |
| any defense, clean script | yes | no |
| SRI, honest vendor update | **no (breaks the site)** | no |

The last row is the limit: SRI pins exact bytes, so it can not protect a script the vendor legitimately changes often (A/B testing, tag managers). CSP is the layer that still helps there.

## Caveats

- One browser (Edge/Chromium), one simple page, localhost only.
- A real policy needs more than `connect-src` and `img-src` (forms, frames, workers, reporting). This is a minimal demonstration.
- "Defense in depth" is a lesson from this demo, not a guarantee of safety. Real incidents have more moving parts.

```
npm test
npm start
```

MIT licensed.
