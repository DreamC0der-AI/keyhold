/**
 * Real-browser check: Chromium with a virtual WebAuthn authenticator that supports PRF.
 * Exercises webauthnPrf, Argon2id (WASM, real 64 MiB cost) and IndexedDbDeviceStore.
 *
 *   npm run test:browser      (needs `playwright` with Chromium available)
 */
import { build } from 'esbuild';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const here = fileURLToPath(new URL('.', import.meta.url));

const out = await build({ entryPoints: [here + 'entry.ts'], bundle: true, format: 'esm', write: false, platform: 'browser' });
const js = out.outputFiles[0].text;
const server = createServer((req, res) => {
  if (req.url === '/bundle.js') res.setHeader('content-type', 'text/javascript').end(js);
  else res.setHeader('content-type', 'text/html').end('<!doctype html><script type="module" src="/bundle.js"></script>');
}).listen(0);
const port = server.address().port;

const browser = await chromium.launch();
let failed = false;
try {
  const page = await browser.newPage();
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true,
    },
  });
  await page.goto(`http://localhost:${port}/`);
  await page.waitForFunction(() => window.run);
  const r = await page.evaluate(() => window.run());
  const ok = r.prf === true && r.a.t === 'hi' && r.b.t === 'hi' && r.c.t === 'hi' && r.ext === false;
  console.log(ok ? 'browser check passed' : 'browser check FAILED', JSON.stringify(r));
  failed = !ok;
  const c = await page.evaluate(() => window.runChat());
  const chatOk = c.text === 'hello from the browser' && c.attachment === 300_000 && c.epoch >= 1;
  console.log(chatOk ? 'browser chat check passed' : 'browser chat check FAILED', JSON.stringify(c));
  failed = failed || !chatOk;
} catch (e) {
  console.error(e);
  failed = true;
} finally {
  await browser.close();
  server.close();
}
process.exit(failed ? 1 : 0);
