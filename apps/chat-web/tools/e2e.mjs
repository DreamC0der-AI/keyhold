// End-to-end check against the local mock backend: two people, a DM, a group, a second device.
//   node tools/mock-server.mjs 8787 &   then   node tools/e2e.mjs
import { createRequire } from 'node:module';
const { chromium } = createRequire(import.meta.url)('playwright');

const BASE = process.env.BASE ?? 'http://localhost:8787/';
const SHOTS = process.env.SHOTS ?? '/tmp/e2e';
const browser = await chromium.launch();
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
let failures = 0;
const people = [];
const check = (c, m) => { if (!c) { failures++; log('FAIL', m); } else log('ok  ', m); };

async function person(login) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => log(login, 'PAGEERROR', e.message));
  page.on('console', (m) => m.type() === 'error' && log(login, 'console', m.text()));
  await page.goto(BASE);
  await page.getByLabel('Test account').fill(login);
  await page.getByRole('button', { name: /Sign in/ }).click();
  const p = { ctx, page, login };
  people.push(p);
  return p;
}

async function setup(p) {
  await p.page.getByRole('button', { name: 'Create identity' }).click();
  const code = await p.page.locator('.code-box').innerText({ timeout: 30000 });
  await p.page.getByLabel(/Type the last block/).fill(code.split('-').pop());
  await p.page.getByRole('button', { name: 'Continue to chats' }).click();
  await p.page.getByRole('heading', { name: /Pick a chat/ }).waitFor();
  return code;
}

async function sendMsg(p, text) {
  await p.page.waitForTimeout(500);
  await p.page.locator('#composer').fill(text);
  await p.page.locator('#composer').press('Enter');
}
const bubble = (p, text) => p.page.locator('.bubble', { hasText: text }).first();

try {
  const alice = await person('alice');
  const bob = await person('bob');
  const aliceCode = await setup(alice);
  await setup(bob);
  check(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){6}$/.test(aliceCode), 'recovery code shown');

  // DM
  await alice.page.getByRole('button', { name: 'New chat' }).first().click();
  await alice.page.getByLabel('GitHub username').fill('bob');
  await alice.page.getByRole('button', { name: 'Start chat' }).click();
  await alice.page.locator('.sys', { hasText: 'Invitation sent to @bob' }).waitFor({ timeout: 30000 });
  check(true, 'alice started DM');

  await bob.page.locator('.chat-item', { hasText: 'alice' }).waitFor({ timeout: 45000 });
  check(true, 'bob got the DM by himself');
  await bob.page.locator('.chat-item', { hasText: 'alice' }).click();
  await sendMsg(bob, 'hi alice, it works');
  await bubble(alice, 'hi alice, it works').waitFor({ timeout: 30000 }).catch(() => {});
  await alice.page.locator('.chat-item', { hasText: 'bob' }).click();
  await bubble(alice, 'hi alice, it works').waitFor({ timeout: 30000 });
  check(true, 'alice received bob\'s message');
  await sendMsg(alice, 'hello bob 👋\nsecond line');
  await bubble(bob, 'hello bob').waitFor({ timeout: 30000 });
  check(true, 'bob received alice\'s reply');
  await alice.page.screenshot({ path: `${SHOTS}/dm-alice.png` });

  // Verify safety number match on both sides
  await alice.page.getByRole('button', { name: /Unverified/ }).click();
  const sa = await alice.page.locator('.safety').innerText();
  await bob.page.getByRole('button', { name: /Unverified/ }).click();
  const sb = await bob.page.locator('.safety').innerText();
  check(sa === sb && sa.length > 50, 'safety numbers match');
  await alice.page.getByRole('button', { name: /mark as verified/ }).click();
  await alice.page.getByRole('button', { name: 'Close' }).click();
  await bob.page.getByRole('button', { name: 'Close' }).click();
  await alice.page.getByRole('button', { name: /Verified/ }).waitFor();
  check(true, 'marked verified');

  // attachment
  await alice.page.locator('input[type=file]').setInputFiles({ name: 'note.txt', mimeType: 'text/plain', buffer: Buffer.from('secret file contents') });
  await bob.page.locator('.file', { hasText: 'note.txt' }).waitFor({ timeout: 30000 });
  await bob.page.locator('.file', { hasText: 'note.txt' }).getByRole('button', { name: 'Download' }).click();
  await bob.page.locator('.file', { hasText: 'note.txt' }).getByRole('link', { name: 'Save' }).waitFor({ timeout: 15000 });
  check(true, 'attachment sent and decrypted');

  // Group
  const carol = await person('carol');
  await setup(carol);
  await alice.page.getByRole('button', { name: 'New group' }).click();
  await alice.page.getByLabel('Group name').fill('Weekend hikers');
  await alice.page.getByLabel('Invite people').fill('bob, carol');
  await alice.page.getByRole('button', { name: 'Create group' }).click();
  await alice.page.locator('.sys', { hasText: 'Invitation sent to @carol' }).waitFor({ timeout: 30000 });
  for (const p of [bob, carol]) await p.page.locator('.chat-item', { hasText: 'Weekend hikers' }).waitFor({ timeout: 70000 });
  check(true, 'bob and carol got the group');
  await carol.page.locator('.chat-item', { hasText: 'Weekend hikers' }).click();
  await sendMsg(carol, 'carol here');
  await bob.page.locator('.chat-item', { hasText: 'Weekend hikers' }).click();
  await bubble(bob, 'carol here').waitFor({ timeout: 30000 });
  await bubble(alice, 'carol here').waitFor({ timeout: 30000 });
  check(true, 'group message reached both');
  await bob.page.screenshot({ path: `${SHOTS}/group-bob.png` });

  // remove carol
  await alice.page.getByRole('button', { name: /Members/ }).click();
  alice.page.once('dialog', (d) => d.accept());
  await alice.page.locator('.member', { hasText: 'carol' }).getByRole('button', { name: 'Remove' }).click();
  await alice.page.locator('.sys', { hasText: '@carol left' }).waitFor({ timeout: 30000 }).catch(() => {});
  await carol.page.locator('.sys', { hasText: /You were removed|no longer gives you access/ }).waitFor({ timeout: 45000 });
  await carol.page.screenshot({ path: `${SHOTS}/carol-removed.png` });
  check(true, 'carol removed and told');
  await alice.page.screenshot({ path: `${SHOTS}/group-alice-panel.png` });

  // Second device for alice
  const alice2 = await person('alice');
  await alice2.page.getByLabel('Recovery code').fill(aliceCode);
  await alice2.page.getByRole('button', { name: 'Add this browser' }).click();
  await alice2.page.locator('.chat-item', { hasText: 'bob' }).waitFor({ timeout: 60000 });
  check(true, 'second device joined the DM');
  await alice2.page.locator('.chat-item', { hasText: 'bob' }).click();
  await bob.page.locator('.chat-item', { hasText: 'alice' }).click();
  await sendMsg(bob, 'message for both alice devices');
  await bubble(alice2, 'message for both alice devices').waitFor({ timeout: 45000 });
  await alice.page.locator('.chat-item', { hasText: 'bob' }).click();
  await bubble(alice, 'message for both alice devices').waitFor({ timeout: 45000 });
  check(true, 'both alice devices read the new message');
  await alice2.page.goto(BASE + '#/settings');
  await alice2.page.locator('.label', { hasText: 'This browser' }).waitFor();
  check((await alice2.page.locator('.box-row', { hasText: 'Added' }).count()) === 2, 'two devices listed');
  await alice2.page.screenshot({ path: `${SHOTS}/settings.png` });

  // mobile layout
  await bob.page.setViewportSize({ width: 390, height: 800 });
  await bob.page.screenshot({ path: `${SHOTS}/mobile-chat.png` });
} catch (e) {
  failures++;
  log('ERROR', e.message);
  for (const [i, p] of people.entries()) {
    const sys = await p.page.locator('.sys, .bubble, .flash, .status-bar').allInnerTexts().catch(() => []);
    log(`--- ${p.login}#${i}`, JSON.stringify(sys));
    await p.page.screenshot({ path: `${SHOTS}/fail-${p.login}-${i}.png` }).catch(() => {});
  }
} finally {
  await browser.close();
  log(failures ? `${failures} FAILED` : 'ALL PASSED');
  process.exit(failures ? 1 : 0);
}
