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
  page.on('dialog', (d) => d.accept());
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
async function accept(p, from, timeout = 45000) {
  const row = p.page.locator('div.row', { hasText: `${from} invited you` }).filter({ has: p.page.getByRole('button', { name: 'Accept' }) }).first();
  await row.waitFor({ timeout });
  await row.getByRole('button', { name: 'Accept' }).click();
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

  await bob.page.getByText('alice invited you').waitFor({ timeout: 45000 });
  await bob.page.waitForTimeout(3000);
  check(!(await bob.page.locator('.chat-item', { hasText: 'alice' }).count()), 'bob sees an invitation and nothing joins before he accepts');
  await bob.page.screenshot({ path: `${SHOTS}/invite-accept.png` });
  await accept(bob, 'alice');
  await bob.page.locator('.chat-item', { hasText: 'alice' }).waitFor({ timeout: 45000 });
  check(true, 'bob accepted and joined the DM');
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
  for (const p of [bob, carol]) await accept(p, 'alice', 70000);
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
  await alice.page.getByRole('button', { name: 'Chat options' }).click();
  await alice.page.locator('.member', { hasText: 'carol' }).getByRole('button', { name: 'Remove' }).click();
  await alice.page.locator('.sys', { hasText: '@carol left' }).waitFor({ timeout: 30000 }).catch(() => {});
  await carol.page.locator('.sys, .flash', { hasText: /You were removed|no longer available/ }).first().waitFor({ timeout: 45000 });
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

  // invited before having an identity: joins after the inviter's app confirms it
  const dave = await person('dave');
  await dave.page.getByRole('button', { name: 'Create identity' }).waitFor();
  await alice.page.getByRole('button', { name: 'New chat' }).first().click();
  await alice.page.getByLabel('GitHub username').fill('dave');
  await alice.page.getByRole('button', { name: 'Start chat' }).click();
  await alice.page.locator('.sys', { hasText: 'Invitation sent to @dave' }).waitFor({ timeout: 30000 });
  const t0 = Date.now();
  await setup(dave);
  await accept(dave, 'alice', 60000);
  await dave.page.screenshot({ path: `${SHOTS}/invite-pending.png` });
  await dave.page.locator('.chat-item', { hasText: 'alice' }).waitFor({ timeout: 90000 });
  check(true, `dave (no identity when invited) joined after ${Math.round((Date.now() - t0) / 1000)}s`);
  await dave.page.locator('.chat-item', { hasText: 'alice' }).click();
  await sendMsg(dave, 'dave here');
  await alice.page.locator('.chat-item', { hasText: 'dave' }).click();
  await bubble(alice, 'dave here').waitFor({ timeout: 30000 });
  check(true, 'dave and alice can talk');

  // decline: dave turns down a DM from carol, and it stays gone
  await carol.page.getByRole('button', { name: 'New chat' }).first().click();
  await carol.page.getByLabel('GitHub username').fill('dave');
  await carol.page.getByRole('button', { name: 'Start chat' }).click();
  await carol.page.locator('.sys', { hasText: 'Invitation sent to @dave' }).waitFor({ timeout: 30000 });
  const decl = dave.page.locator('div.row', { hasText: 'carol invited you' }).filter({ has: dave.page.getByRole('button', { name: 'Decline' }) }).first();
  await decl.waitFor({ timeout: 45000 });
  await decl.getByRole('button', { name: 'Decline' }).click();
  await dave.page.getByText('carol invited you').waitFor({ state: 'detached', timeout: 15000 });
  const invs = await dave.page.evaluate(() => fetch('/gh/user/repository_invitations', { headers: { Authorization: 'Bearer tok-dave' } }).then((r) => r.json()).catch(() => []));
  await dave.page.evaluate(() => { location.hash = '#/'; }); await dave.page.reload();
  await dave.page.getByRole('heading', { name: /Pick a chat/ }).waitFor({ timeout: 20000 });
  await dave.page.waitForTimeout(20000);
  check(!(await dave.page.getByText('carol invited you').count()) && !(await dave.page.locator('.chat-item', { hasText: 'carol' }).count()), `dave declined carol's invitation and it stayed gone (open GitHub invitations: ${Array.isArray(invs) ? invs.length : '?'})`);

  const openChat = async (p, name) => {
    await p.page.evaluate(() => { if (location.hash.startsWith('#/settings')) location.hash = '#/'; });
    await p.page.locator('.chat-item', { hasText: name }).first().click();
    await p.page.waitForTimeout(300);
  };
  const details = async (p) => {
    if (!(await p.page.locator('.chat-menu').count())) await p.page.getByRole('button', { name: 'Chat options' }).click();
  };
  const count = (p, name) => p.page.locator('.chat-item .name').getByText(name, { exact: true }).count();

  // Delete chat: bob clears his copy of the DM with alice; the chat stays live
  await openChat(bob, 'alice');
  await details(bob);
  await bob.page.locator('.chat-menu').getByRole('button', { name: 'Delete chat' }).click();
  await bubble(bob, 'hi alice, it works').waitFor({ state: 'detached', timeout: 10000 });
  await openChat(alice, 'bob');
  await sendMsg(alice, 'after the clear');
  await bubble(bob, 'after the clear').waitFor({ timeout: 30000 });
  check(!(await bubble(bob, 'hello bob').count()), 'bob deleted his history, the chat stayed live and new messages arrive');
  check(await bubble(alice, 'hi alice, it works').count() > 0, 'alice kept her copy');

  // Close: alice (owner) closes the DM; bob learns why, keeps his copy, and starts a new one
  await details(alice);
  await alice.page.locator('.chat-menu').getByRole('button', { name: 'Close chat' }).click();
  await alice.page.locator('.sys.divider', { hasText: 'You closed this chat' }).waitFor({ timeout: 30000 });
  await bob.page.locator('.sys.divider', { hasText: '@alice closed this chat' }).waitFor({ timeout: 45000 });
  await openChat(alice2, 'bob');
  await alice2.page.locator('.sys.divider', { hasText: 'You closed this chat' }).waitFor({ timeout: 45000 });
  check(true, "alice's second browser shows the close too");
  check(await bubble(bob, 'after the clear').count() > 0 && (await bob.page.locator('#composer').count()) === 0, 'bob sees "@alice closed this chat", keeps his copy, and can\'t send');
  await bob.page.screenshot({ path: `${SHOTS}/closed-bob.png` });
  await bob.page.getByRole('button', { name: 'Start a new chat with alice' }).click();
  await accept(alice, 'bob', 60000);
  await bob.page.locator('.sys', { hasText: '@alice joined' }).waitFor({ timeout: 60000 });
  await sendMsg(bob, 'new room, same chat');
  await openChat(alice, 'bob');
  await bubble(alice, 'new room, same chat').waitFor({ timeout: 30000 });
  check((await count(alice, 'bob')) === 1 && (await count(bob, 'alice')) === 1, 'one chat-list entry per person after re-creation');
  check(await alice.page.locator('.sys.divider', { hasText: 'new chat started' }).count() > 0 && (await bubble(alice, 'after the clear').count()) > 0, 'old history above a divider, then the new room');
  await alice.page.screenshot({ path: `${SHOTS}/recreated-alice.png` });

  // Delete chat syncs to alice's other browser
  // (her second browser joins the new room by itself, from the synced chat list; it can only
  // read what is sent after it joined)
  await openChat(alice2, 'bob');
  await alice2.page.locator('#composer:enabled').waitFor({ timeout: 60000 });
  await alice2.page.waitForTimeout(3000);
  await sendMsg(bob, 'for both browsers');
  await bubble(alice2, 'for both browsers').waitFor({ timeout: 60000 });
  await bubble(alice, 'for both browsers').waitFor({ timeout: 60000 });
  await details(alice);
  await alice.page.locator('.chat-menu').getByRole('button', { name: 'Delete chat' }).click();
  await bubble(alice, 'for both browsers').waitFor({ state: 'detached', timeout: 10000 });
  await bubble(alice2, 'for both browsers').waitFor({ state: 'detached', timeout: 60000 });
  check((await count(alice2, 'bob')) === 1 && !(await bubble(alice2, 'after the clear').count()), "alice's delete reached her second browser; the chat stays");
  await sendMsg(bob, 'still here after alice cleared');
  await bubble(alice2, 'still here after alice cleared').waitFor({ timeout: 45000 });
  check(true, 'new messages still arrive on both of her browsers');

  // Quit: dave (not the owner) quits; alice sees he left, can't send, and closes
  await openChat(dave, 'alice');
  await details(dave);
  await dave.page.locator('.chat-menu').getByRole('button', { name: 'Quit chat' }).click();
  await dave.page.locator('.sys.divider', { hasText: 'You left this chat' }).waitFor({ timeout: 30000 });
  await openChat(alice, 'dave');
  await alice.page.getByText('dave left this chat.').waitFor({ timeout: 60000 });
  check(await alice.page.locator('#composer').isDisabled(), 'alice sees "dave left", sending is off');
  await alice.page.locator('.banner').getByRole('button', { name: 'Close chat' }).click();
  await alice.page.locator('.sys.divider', { hasText: 'You closed this chat' }).waitFor({ timeout: 30000 });
  check(true, 'alice closed the chat dave quit');
  // Deleting an ended chat removes it from her other browser's list too
  await details(alice);
  await alice.page.locator('.chat-menu').getByRole('button', { name: 'Delete chat' }).click();
  await alice.page.waitForTimeout(500);
  check((await count(alice, 'dave')) === 0, 'ended chat deleted from the list');
  let gone = false;
  for (let i = 0; i < 20 && !gone; i++) {
    gone = (await count(alice2, 'dave')) === 0;
    if (!gone) await alice2.page.waitForTimeout(3000);
  }
  check(gone, "and from alice's second browser");

  // Block: dave blocks alice; her next invitation is turned down without asking
  await details(dave);
  await dave.page.locator('.chat-menu').getByRole('button', { name: 'Block alice' }).click();
  await dave.page.locator('.chat-menu').getByRole('button', { name: 'Unblock alice' }).waitFor();
  await alice.page.getByRole('button', { name: 'New chat' }).first().click();
  await alice.page.getByLabel('GitHub username').fill('dave');
  await alice.page.getByRole('button', { name: 'Start chat' }).click();
  await alice.page.locator('.sys', { hasText: 'Invitation sent to @dave' }).waitFor({ timeout: 30000 });
  await dave.page.waitForTimeout(25000);
  check(!(await dave.page.getByText('alice invited you').count()), 'blocked person\'s invitation never shows');

  // Both start a DM with each other at once: the apps settle on one room (rule 2)
  for (const p of [bob, carol]) await p.page.getByRole('button', { name: 'New chat' }).first().click();
  await bob.page.getByLabel('GitHub username').fill('carol');
  await carol.page.getByLabel('GitHub username').fill('bob');
  await Promise.all([bob.page.getByRole('button', { name: 'Start chat' }).click(), carol.page.getByRole('button', { name: 'Start chat' }).click()]);
  const settled = async () => {
    for (let i = 0; i < 40; i++) {
      const ok = (await count(bob, 'carol')) === 1 && (await count(carol, 'bob')) === 1
        && !(await bob.page.getByText('carol invited you').count()) && !(await carol.page.getByText('bob invited you').count());
      const live = await Promise.all([bob, carol].map((p) => p.page.locator('#composer').isEnabled().catch(() => false)));
      if (ok && live.every(Boolean)) return true;
      await bob.page.waitForTimeout(3000);
    }
    for (const p of [bob, carol]) {
      log(`state ${p.login}`, await count(p, p === bob ? 'carol' : 'bob'), JSON.stringify(await p.page.locator('.chat-list').innerText()));
      await p.page.screenshot({ path: `${SHOTS}/race-${p.login}.png` });
    }
    return false;
  };
  check(await settled(), 'simultaneous DMs settle on one chat');
  await openChat(bob, 'carol');
  await openChat(carol, 'bob');
  await sendMsg(carol, 'one room for us');
  await bubble(bob, 'one room for us').waitFor({ timeout: 45000 });
  check(true, 'messages flow in the surviving room');

  // first run: no install yet -> guided steps -> continues by itself
  const newbie = await person('newbie');
  await newbie.page.getByText('Two quick steps on GitHub').waitFor();
  check(await newbie.page.getByRole('link', { name: /Create chat-home on GitHub/ }).getAttribute('href').then((h) => h.includes('name=chat-home') && h.includes('visibility=private')), 'prefilled new-repo link');
  await newbie.page.screenshot({ path: `${SHOTS}/install.png` });
  await newbie.page.evaluate(() => fetch('/gh/mock/install', { method: 'POST', headers: { Authorization: 'Bearer tok-newbie' } }));
  await newbie.page.getByRole('button', { name: 'Check now' }).click();
  await newbie.page.getByRole('button', { name: 'Create identity' }).waitFor({ timeout: 20000 });
  check(true, 'install detected, onboarding continues');
  await newbie.page.getByRole('button', { name: 'Create identity' }).click();
  await newbie.page.locator('.code-box').waitFor({ timeout: 30000 });
  const homeOk = await newbie.page.evaluate(() => fetch('/gh/repos/newbie/chat-home/contents/vault/root', { headers: { Authorization: 'Bearer tok-newbie' } }).then((r) => r.status));
  check(homeOk === 200, 'root key backup stored in chat-home');

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
