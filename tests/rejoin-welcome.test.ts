// Invited back after leaving: the join must use the new invitation's Welcome, not one left over
// from the first time (which would put the device epochs behind and lose what was sent since).
import { describe, it, expect } from 'vitest';
import { MemoryWorld } from '../src/storage/index.js';
import { makeUser, addDevice, texts, type TestUserOptions } from './chat-helpers.js';
import type { Group } from '../src/chat/index.js';

function setup() {
  let t = Date.UTC(2026, 10, 26);
  const now = () => t;
  const w = new MemoryWorld({ now, claimOnce: false });
  const opts: TestUserOptions = { build: { preKeys: true }, now };
  return { w, opts };
}

describe('invited back with pre-keys', () => {
  it('someone who left joins with the new Welcome and reads what was sent while invited again', async () => {
    const { w, opts } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave', opts);
    for (const u of [carol, dave]) await u.chat.refreshPreKey();
    const g = await bob.chat.createGroup('group', 'team');
    // One Welcome for both: it stays in each drop box after a join (it has secrets for two).
    await g.inviteMany([carol.address, dave.address]);
    const [gc] = await carol.chat.acceptInvites();
    const [gd] = await dave.chat.acceptInvites();
    await gc!.sync();
    await gd!.sync();
    await g.sync();
    await gd!.leave();
    await g.sync();
    await gc!.sync();
    expect(g.members().map((m) => m.address)).not.toContain(dave.address);
    await g.send({ t: 'text', body: 'while you were out' });
    await g.invite(dave.address);
    await g.send({ t: 'text', body: 'welcome back' });
    const [again] = await dave.chat.acceptInvites();
    expect(again).toBeDefined();
    const got = texts(await again!.sync());
    expect(got).toContain('welcome back');
    expect(got).not.toContain('while you were out');
    await again!.send({ t: 'text', body: 'back' });
    expect(texts(await g.sync())).toContain('back');
    expect(texts(await gc!.sync())).toContain('back');
  });

  it('two devices of one person added in one commit to a group with gaps open the Welcome', async () => {
    // Leaves 0-6: bob, carol, erin, frank, gina, hank, ivan. Carol and gina leave (leaves 1 and 4
    // blank), hank rotates (the parent over leaves 4-7 gets a key), then dave's two devices land
    // on leaves 1 and 4: that parent lists [4], the root lists [1, 4]. ts-mls 1.6.4 rejected this
    // valid tree in the Welcome (it wanted every such list equal); see scripts/patch-ts-mls.mjs.
    const { w, opts } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const others = [];
    for (const n of ['carol', 'erin', 'frank', 'gina', 'hank', 'ivan']) others.push(await makeUser(w.session(`mem:${n}`), `mem:${n}`, opts));
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave', opts);
    const phone = await addDevice(dave, opts);
    for (const u of [...others, dave, phone]) await u.chat.refreshPreKey();
    const g = await bob.chat.createGroup('group', 'team');
    const joined: Group[] = [];
    for (const u of others) {
      await g.invite(u.address);
      const [x] = await u.chat.acceptInvites();
      joined.push(x!);
      await x!.sync();
      await g.sync();
    }
    const all = () => [g, ...joined.filter((y) => y.active)];
    for (const y of all()) await y.sync();
    for (const k of [0, 3]) {
      await joined[k]!.leave();
      for (let i = 0; i < 2; i++) for (const y of all()) await y.sync();
    }
    await joined[4]!.rotate();
    for (const y of all()) await y.sync();
    await g.invite(dave.address);
    await g.send({ t: 'text', body: 'hi dave' });
    for (const u of [dave, phone]) {
      const [x] = await u.chat.acceptInvites();
      expect(x).toBeDefined();
      expect(texts(await x!.sync())).toContain('hi dave');
    }
  });
});
