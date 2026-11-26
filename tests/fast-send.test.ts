/**
 * sendFreshMs: a send right after a sync skips its own sync (one write instead of reads + a
 * write). What that can't see, a change that landed since the sync, must not lose a message.
 */
import { describe, expect, it } from 'vitest';
import { MemoryWorld } from '../src/storage/index.js';
import type { Group } from '../src/chat/index.js';
import { makeUser, addDevice, texts, type TestUserOptions } from './chat-helpers.js';

const FRESH = 15_000;
const SETTLE = 4 * FRESH;

async function pair() {
  const clock = { t: 1_700_000_000_000 };
  const now = () => clock.t;
  const w = new MemoryWorld({ claimOnce: false, now });
  const opts: TestUserOptions = { now, sendFreshMs: FRESH };
  const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
  const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
  const g = await bob.chat.createGroup();
  await g.invite(carol.address);
  const [gc] = await carol.chat.acceptInvites();
  for (let r = 0; r < 3; r++) for (const x of [g, gc!]) await x.sync();
  // The group has been quiet for a while.
  clock.t += SETTLE + 1;
  const reads = () => w.calls.get('log.read') ?? 0;
  const posts = () => (w.calls.get('mailbox.post') ?? 0) + (w.calls.get('mailbox.postMany') ?? 0);
  return { w, clock, opts, bob, carol, g, gc: gc!, reads, posts };
}

const ids = (r: { messages: { message: { id: string; t: string } }[] }) => r.messages.filter((m) => m.message.t === 'text').map((m) => m.message.id);

describe('a send right after a sync', () => {
  it('posts without reading first, and reads first again once the sync is old', async () => {
    const { clock, g, gc, reads } = await pair();
    await g.sync();
    const before = reads();
    await g.send({ t: 'text', body: 'quick' });
    expect(reads()).toBe(before);
    expect(texts(await gc.sync())).toEqual(['quick']);

    clock.t += FRESH + 1;
    const later = reads();
    await g.send({ t: 'text', body: 'careful' });
    expect(reads()).toBe(later + 1);
    expect(texts(await gc.sync())).toEqual(['careful']);
  });

  it('always reads first without the option', async () => {
    const w = new MemoryWorld({ claimOnce: false });
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const g = await bob.chat.createGroup();
    await g.sync();
    const before = w.calls.get('log.read') ?? 0;
    await g.send({ t: 'text', body: 'x' });
    expect(w.calls.get('log.read')).toBe(before + 1);
  });

  it('reads first for a while after the group changed', async () => {
    const { clock, g, gc, reads } = await pair();
    await gc.rotate();
    await g.sync(); // sees the change
    const before = reads();
    await g.send({ t: 'text', body: 'just after a change' });
    expect(reads()).toBe(before + 1);
    clock.t += SETTLE + 1;
    await g.sync();
    const quiet = reads();
    await g.send({ t: 'text', body: 'quiet again' });
    expect(reads()).toBe(quiet);
    expect(texts(await gc.sync())).toEqual(['just after a change', 'quiet again']);
  });

  it('reads first while an earlier send is unsettled', async () => {
    const { g, gc, bob, reads } = await pair();
    await g.sync();
    const mailbox = bob.provider.mailbox;
    const post = mailbox.post.bind(mailbox);
    mailbox.post = async () => {
      throw new Error('network');
    };
    await expect(g.send({ t: 'text', body: 'lost?' })).rejects.toThrow('network');
    mailbox.post = post;
    const before = reads();
    await g.send({ t: 'text', body: 'next' });
    expect(reads()).toBeGreaterThan(before);
    await g.resend();
    expect(texts(await gc.sync()).sort()).toEqual(['lost?', 'next']);
  });
});

describe('a fast send that was late after all', () => {
  it('a device that joined unseen gets the message; the others get one more copy with the same id', async () => {
    const { opts, carol, g, gc } = await pair();
    await g.sync(); // bob is up to date...
    const laptop = await addDevice(carol, opts);
    const gl = (await laptop.chat.join(g.space)) as Group; // ...then carol's laptop joins, unseen by bob
    await gc.sync();
    const sent = await g.send({ t: 'text', body: 'did the laptop get this?' }); // encrypted in the old epoch
    // The laptop can't read the old epoch; carol's first device still can.
    const early = await gl.sync();
    expect(texts(early)).toEqual([]);
    expect(early.events).toEqual([]); // from before it joined, as far as its keys go: not an error
    expect(ids(await gc.sync())).toEqual([sent.id]);

    // bob's next sync sees the join and sends it again in the new epoch.
    await g.sync();
    const got = await gl.sync();
    expect(texts(got)).toEqual(['did the laptop get this?']);
    expect(ids(got)).toEqual([sent.id]);
    expect(ids(await gc.sync())).toEqual([sent.id]); // the same message again: apps keep the copy they have
    // Settled: nothing more goes out.
    await g.sync();
    expect(texts(await gl.sync())).toEqual([]);
    expect(texts(await gc.sync())).toEqual([]);
  });

  it('a device that joined after the message went up does not get the repeat', async () => {
    const { w, opts, carol, g, gc } = await pair();
    await g.sync();
    const sent = await g.send({ t: 'text', body: 'before anyone new' }); // fast, in the current epoch
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave', opts);
    await g.invite(dave.address); // a ticket only (no pre-keys): dave joins by his own commit
    const [gd] = await dave.chat.acceptInvites();
    // bob's next sync sees dave's join and repeats the message, which only carol gets.
    await g.sync();
    expect(ids(await gc.sync())).toContain(sent.id);
    expect(texts(await gd!.sync())).toEqual([]);
    void carol;
  });

  it("a new device of someone already in still gets a repeat of what went up just before it joined", async () => {
    const { opts, carol, g, gc } = await pair();
    await g.sync();
    const sent = await g.send({ t: 'text', body: 'sent before the laptop joined' });
    // carol's laptop joins by its own commit after that, unseen by bob: bob repeats his message.
    // carol was in the group when it went up, so her new device may read it.
    const laptop = await addDevice(carol, opts);
    const gl = (await laptop.chat.join(g.space)) as Group;
    await g.sync();
    expect(ids(await gc.sync())).toContain(sent.id);
    expect(texts(await gl.sync())).toEqual(['sent before the laptop joined']);
  });

  it("our own key change right after is not a reason to send again", async () => {
    const { g, gc, posts } = await pair();
    await g.sync();
    await g.send({ t: 'text', body: 'once' });
    const after = posts();
    await g.rotate();
    await g.sync();
    await g.sync();
    expect(posts()).toBe(after);
    expect(texts(await gc.sync())).toEqual(['once']);
  });

  it('a copy that could not be posted is not left as an unsent message, and goes out with a later sync', async () => {
    const { opts, bob, carol, g, gc } = await pair();
    await g.sync();
    const laptop = await addDevice(carol, opts);
    const gl = (await laptop.chat.join(g.space)) as Group;
    await gc.sync();
    await g.send({ t: 'text', body: 'again please' });
    const mailbox = bob.provider.mailbox;
    const post = mailbox.post.bind(mailbox);
    mailbox.post = async () => {
      throw new Error('network');
    };
    await g.sync(); // sees the join; the copy fails to go out
    expect(g.unsent()).toEqual([]);
    mailbox.post = post;
    await g.sync();
    expect(texts(await gl.sync())).toEqual(['again please']);
  });
});

describe('a group made a moment ago', () => {
  it('sends its name and its first invitations without reading the empty space first', async () => {
    const clock = { t: 1_700_000_000_000 };
    const now = () => clock.t;
    const w = new MemoryWorld({ claimOnce: false, now });
    const opts: TestUserOptions = { now, sendFreshMs: FRESH };
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave', opts);
    const reads = () => (w.calls.get('log.read') ?? 0) + (w.calls.get('mailbox.list') ?? 0);

    const before = reads();
    const g = await bob.chat.createGroup('group', 'Hikers');
    await g.invite(carol.address);
    expect(reads()).toBe(before);
    // Only the first: by the second invitation someone else may have written.
    await g.invite(dave.address);
    expect(reads()).toBeGreaterThan(before);

    const [gc] = await carol.chat.acceptInvites();
    const [gd] = await dave.chat.acceptInvites();
    for (let r = 0; r < 3; r++) for (const x of [g, gc!, gd!]) await x.sync();
    expect(g.members().filter((m) => !m.pending).map((m) => m.address).sort()).toEqual(['mem:bob', 'mem:carol', 'mem:dave']);
    await g.send({ t: 'text', body: 'welcome' });
    expect(texts(await gc!.sync())).toEqual(['welcome']);
    expect(texts(await gd!.sync())).toEqual(['welcome']);
  });

  it('reads first when the group was made a while ago, or by an earlier session', async () => {
    const clock = { t: 1_700_000_000_000 };
    const now = () => clock.t;
    const w = new MemoryWorld({ claimOnce: false, now });
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', { now });
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', { now });
    const g = await bob.chat.createGroup();
    clock.t += 31_000;
    const before = w.calls.get('log.read') ?? 0;
    await g.invite(carol.address);
    expect(w.calls.get('log.read')).toBe(before + 1);
  });
});

describe('a fast send that reaches someone just removed', () => {
  it('the removed device is told to take it back; the others keep it', async () => {
    const clock = { t: 1_700_000_000_000 };
    const now = () => clock.t;
    const w = new MemoryWorld({ claimOnce: false, now });
    const opts: TestUserOptions = { now, sendFreshMs: FRESH };
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    const eve = await makeUser(w.session('mem:eve'), 'mem:eve', opts);
    const g = await bob.chat.createGroup();
    await g.invite(carol.address);
    await g.invite(eve.address);
    const [gc] = await carol.chat.acceptInvites();
    const [ge] = await eve.chat.acceptInvites();
    for (let r = 0; r < 3; r++) for (const x of [g, gc!, ge!]) await x.sync();
    clock.t += SETTLE + 1;
    await gc!.sync(); // carol is fresh...
    await g.remove(eve.identity.fingerprint); // ...and bob removes eve now
    w.spaces.get(g.space)!.members.add(eve.address); // a channel whose access removal lags
    const sent = await gc!.send({ t: 'text', body: 'right after' }); // carol hasn't seen it
    expect(sent.fast).toBe(true);
    const r = await ge!.sync();
    expect(r.events).toEqual(expect.arrayContaining([{ type: 'retracted', ids: [sent.id] }, expect.objectContaining({ type: 'removed' })]));
    expect(texts(r)).not.toContain('right after');
    // carol's next sync sends it again in the new epoch; bob has it either way.
    await gc!.sync();
    expect(texts(await g.sync())).toContain('right after');
  });
});

describe('a fast send and someone an admin adds with a pre-key', () => {
  async function trio() {
    const clock = { t: Date.now() }; // pre-key lifetimes are checked against the real clock
    const now = () => clock.t;
    const w = new MemoryWorld({ claimOnce: false, now });
    const opts: TestUserOptions = { now, sendFreshMs: FRESH, build: { preKeys: true } };
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave', opts);
    for (const u of [carol, dave]) await u.chat.refreshPreKey();
    const g = await bob.chat.createGroup();
    await g.invite(carol.address);
    const [gc] = await carol.chat.acceptInvites();
    for (let r = 0; r < 3; r++) for (const x of [g, gc!]) await x.sync();
    clock.t += SETTLE + 1;
    return { bob, carol, dave, g, gc: gc! };
  }

  it('a repeat of what carol sent before bob added dave is not shown to dave', async () => {
    const { dave, g, gc } = await trio();
    await gc.sync();
    const sent = await gc.send({ t: 'text', body: 'before dave' }); // fast
    await g.sync(); // bob has seen it...
    await g.invite(dave.address); // ...then adds dave
    await gc.sync(); // carol sees the add and repeats her message
    expect(ids(await g.sync())).toContain(sent.id);
    const [gd] = await dave.chat.acceptInvites();
    expect(texts(await gd!.sync())).toEqual([]);
    await gc.send({ t: 'text', body: 'after' });
    expect(texts(await gd!.sync())).toEqual(['after']);
  });

  it('what carol sent just after the add, before she saw it, still reaches dave', async () => {
    const { dave, g, gc } = await trio();
    await gc.sync();
    await g.invite(dave.address); // bob adds dave; carol hasn't seen it
    const sent = await gc.send({ t: 'text', body: 'right after the add' }); // fast, old epoch
    await gc.sync(); // carol sees the add and repeats it
    const [gd] = await dave.chat.acceptInvites();
    const got = await gd!.sync();
    expect(texts(got)).toEqual(['right after the add']);
    expect(ids(got)).toEqual([sent.id]);
  });
});
