/** Lost replies, failed writes and app errors: nothing is lost, sent twice, or read as someone else's. */
import { describe, expect, it } from 'vitest';
import { MemoryWorld } from '../src/storage/index.js';
import type { Bytes, Mailbox, OrderedLog, PersonalStore, StorageProvider } from '../src/storage/index.js';
import { Chat, PersonalData, unsentMessages, type Group, type ReceivedMessage } from '../src/chat/index.js';
import { makeUser, texts, type TestUser } from './chat-helpers.js';

const netError = () => new TypeError('Failed to fetch');

/** A provider whose next mailbox post (or log append) misbehaves once. */
function flaky(p: StorageProvider, opts: { noNewId?: boolean } = {}) {
  const ctl = { post: undefined as 'lands' | 'fails' | undefined, append: undefined as 'lands' | 'fails' | undefined };
  const real = p.mailbox;
  const mailbox: Mailbox = {
    ...(opts.noNewId ? {} : { newId: () => real.newId!() }),
    async post(space, data, o) {
      const mode = ctl.post;
      ctl.post = undefined;
      if (mode === 'fails') throw netError();
      const id = await real.post(space, data, opts.noNewId ? undefined : o);
      if (mode === 'lands') throw netError(); // the write happened, the reply was lost
      return id;
    },
    list: (space, cursor) => real.list(space, cursor),
  };
  const log: OrderedLog = {
    read: (space, from) => p.orderedLog.read(space, from),
    async append(space, index, entry) {
      const mode = ctl.append;
      ctl.append = undefined;
      if (mode === 'fails') throw netError();
      const r = await p.orderedLog.append(space, index, entry);
      if (mode === 'lands') throw netError();
      return r;
    },
  };
  return { provider: { ...p, mailbox, orderedLog: log } as StorageProvider, ctl };
}

async function flakyUser(w: MemoryWorld, address: string, o: { noNewId?: boolean; now?: () => number } = {}) {
  const f = flaky(w.session(address), o);
  const u = await makeUser(f.provider, address, { now: o.now });
  return { ...u, ctl: f.ctl };
}

/** Re-open a user's chat with an onMessage callback (same device and storage). */
async function withOnMessage(u: TestUser, onMessage: (g: Group, m: ReceivedMessage) => unknown) {
  return Chat.open({ ...u.chat.opts, onMessage: onMessage as never });
}

async function dm(w: MemoryWorld, bob: TestUser, alice: TestUser, bobChat = bob.chat, aliceChat = alice.chat) {
  const g = await bobChat.createGroup('dm');
  await g.invite(alice.address);
  const [ga] = await aliceChat.acceptInvites();
  await g.sync();
  return { g, ga: ga! };
}

describe('personal store flush', () => {
  it('a change made while its record is being written is not lost', async () => {
    const w = new MemoryWorld();
    const real = w.session('mem:alice').personal;
    let hold: Promise<void> | undefined;
    let release = () => {};
    const store: PersonalStore = {
      ...real,
      async put(id, data, expected) {
        if (hold) await hold;
        return real.put(id, data, expected);
      },
    };
    const K = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const p = await PersonalData.open(store, K, 'laptop');
    await p.set('chats', 'g1', { ended: true }, { ended: 'once' });
    hold = new Promise((r) => (release = r));
    const flushing = p.flush();
    await new Promise((r) => setTimeout(r, 0));
    await p.set('chats', 'g1', { clearedAt: 1234, purged: true });
    expect(await p.isPending('chats', 'g1')).toBe(true);
    hold = undefined;
    release();
    await flushing;
    expect(p.pending).toBe(1); // the second change is still queued
    expect(await p.get('chats', 'g1')).toEqual({ ended: true, clearedAt: 1234, purged: true });
    await p.flush();
    expect(p.pending).toBe(0);
    const other = await PersonalData.open(real, K, 'phone');
    expect(await other.get('chats', 'g1')).toEqual({ ended: true, clearedAt: 1234, purged: true });
  });

  it('a failed write keeps the change queued', async () => {
    const w = new MemoryWorld();
    const real = w.session('mem:alice').personal;
    let fail = false;
    const store: PersonalStore = { ...real, put: (id, d, e) => (fail ? Promise.reject(netError()) : real.put(id, d, e)) };
    const K = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const p = await PersonalData.open(store, K, 'laptop');
    await p.set('settings', 'x', { value: 1 });
    fail = true;
    await expect(p.flush()).rejects.toThrow();
    expect(p.pending).toBe(1);
    fail = false;
    await p.flush();
    expect(await (await PersonalData.open(real, K, 'phone')).get('settings', 'x')).toEqual({ value: 1 });
  });
});

describe('mailbox ids chosen before posting', () => {
  it('posting the same id and bytes twice stores one item; other bytes are a conflict', async () => {
    const w = new MemoryWorld();
    const p = w.session('mem:bob');
    const space = await p.channel.createSpace('x');
    const id = p.mailbox.newId!();
    const a = new Uint8Array([1, 2, 3]);
    expect(await p.mailbox.post(space, a, { id })).toBe(id);
    expect(await p.mailbox.post(space, a, { id })).toBe(id);
    await expect(p.mailbox.post(space, new Uint8Array([9]), { id })).rejects.toThrow();
    const ids = [p.mailbox.newId!(), p.mailbox.newId!()];
    const two: Bytes[] = [new Uint8Array([4]), new Uint8Array([5])];
    expect(await p.mailbox.postMany!(space, two, { ids })).toEqual(ids);
    expect(await p.mailbox.postMany!(space, two, { ids })).toEqual(ids);
    expect((await p.mailbox.list(space)).items.map((i) => i.id)).toEqual([id, ...ids]);
  });
});

describe('a send whose reply was lost', () => {
  for (const noNewId of [false, true]) {
    const label = noNewId ? ' (provider without newId)' : '';
    it(`is found on the next sync as our own, sent once${label}`, async () => {
      const w = new MemoryWorld();
      const bob = await flakyUser(w, 'mem:bob', { noNewId });
      const alice = await makeUser(w.session('mem:alice'), 'mem:alice');
      const mine: string[] = [];
      const bobChat = await withOnMessage(bob, (_g, m) => void mine.push((m.message as { body: string }).body));
      const { g, ga } = await dm(w, bob, alice, bobChat);
      bob.ctl.post = 'lands';
      const err = await g.send({ t: 'text', body: 'hi' }).catch((e) => e);
      expect(unsentMessages(err)?.map((m) => (m as { body: string }).body)).toEqual(['hi']);
      expect(g.unsent()).toHaveLength(1);
      const r = await g.sync();
      expect(r.events.filter((e) => e.type === 'undecryptable')).toEqual([]);
      expect(g.unsent()).toEqual([]);
      expect(mine).toEqual(['hi']); // shown on the sender's own screen
      expect(await g.resend(err && unsentMessages(err)![0]!.id)).toEqual([]); // nothing left to post
      expect(texts(await ga.sync())).toEqual(['hi']);
    });

    it(`Retry posts the same ciphertext: the recipient reads it once${label}`, async () => {
      const w = new MemoryWorld();
      const bob = await flakyUser(w, 'mem:bob', { noNewId });
      const alice = await makeUser(w.session('mem:alice'), 'mem:alice');
      const mine: string[] = [];
      const bobChat = await withOnMessage(bob, (_g, m) => void mine.push((m.message as { body: string }).body));
      const { g, ga } = await dm(w, bob, alice, bobChat);
      bob.ctl.post = 'lands';
      const err = await g.send({ t: 'text', body: 'hi' }).catch((e) => e);
      const [m] = unsentMessages(err)!;
      // Retry right away. Simulate a mailbox listing that doesn't show the item yet, so it is posted again.
      const meta = (g as unknown as { meta: { mailCursor?: string } }).meta;
      const listed = (await w.session('mem:bob').mailbox.list(g.space)).cursor;
      meta.mailCursor = listed;
      const sent = await g.resend(m!.id);
      expect(sent.map((x) => x.id)).toEqual([m!.id]);
      expect(mine).toEqual(['hi']);
      const ra = await ga.sync();
      expect(texts(ra)).toEqual(['hi']);
      expect(ra.events.filter((e) => e.type === 'undecryptable')).toEqual([]);
      meta.mailCursor = undefined; // the sender re-reads everything: its copies are its own
      expect((await g.sync()).events.filter((e) => e.type === 'undecryptable')).toEqual([]);
      if (!noNewId) expect((await w.session('mem:bob').mailbox.list(g.space)).items).toHaveLength(1);
    });
  }

  it('a send saved but never posted (tab closed) is offered again after a restart', async () => {
    const w = new MemoryWorld();
    const bob = await flakyUser(w, 'mem:bob');
    const alice = await makeUser(w.session('mem:alice'), 'mem:alice');
    const { g, ga } = await dm(w, bob, alice);
    bob.ctl.post = 'fails';
    await expect(g.send({ t: 'text', body: 'later' })).rejects.toThrow();
    const mine: string[] = [];
    const again = await withOnMessage(bob, (_g, m) => void mine.push((m.message as { body: string }).body));
    const g2 = again.groups.get(g.id)!;
    expect(g2.unsent().map((m) => (m as { body: string }).body)).toEqual(['later']);
    await g2.resend();
    expect(g2.unsent()).toEqual([]);
    expect(mine).toEqual(['later']);
    expect(texts(await ga.sync())).toEqual(['later']);
    await g2.send({ t: 'text', body: 'next' }); // the ratchet carried on from the saved state
    expect(texts(await ga.sync())).toEqual(['next']);
  });

  it('discardUnsent drops a failed message', async () => {
    const w = new MemoryWorld();
    const bob = await flakyUser(w, 'mem:bob');
    const alice = await makeUser(w.session('mem:alice'), 'mem:alice');
    const { g, ga } = await dm(w, bob, alice);
    bob.ctl.post = 'fails';
    const err = await g.send({ t: 'text', body: 'oops' }).catch((e) => e);
    await g.discardUnsent(unsentMessages(err)![0]!.id);
    expect(g.unsent()).toEqual([]);
    await g.send({ t: 'text', body: 'fine' });
    expect(texts(await ga.sync())).toEqual(['fine']);
  });
});

describe('onMessage errors', () => {
  it('a message the app could not store is handed over again on the next sync, in order', async () => {
    const w = new MemoryWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const alice = await makeUser(w.session('mem:alice'), 'mem:alice');
    let full = true;
    const stored: string[] = [];
    const aliceChat = await withOnMessage(alice, (_g, m) => {
      if (full) throw new Error('QuotaExceededError');
      stored.push((m.message as { body: string }).body);
    });
    const { g, ga } = await dm(w, bob, alice, bob.chat, aliceChat);
    await g.send({ t: 'text', body: 'one' });
    await g.send({ t: 'text', body: 'two' });
    const r1 = await ga.sync();
    expect(r1.events.filter((e) => e.type === 'undecryptable')).toEqual([]);
    expect(r1.events).toContainEqual({ type: 'delivery-failed', reason: 'QuotaExceededError', waiting: 2 });
    expect(stored).toEqual([]);
    // Survives a restart too.
    full = false;
    const reopened = await withOnMessage(alice, (_g, m) => void stored.push((m.message as { body: string }).body));
    await g.send({ t: 'text', body: 'three' });
    const r2 = await reopened.groups.get(ga.id)!.sync();
    expect(stored).toEqual(['one', 'two', 'three']);
    expect(texts(r2)).toEqual(['one', 'two', 'three']);
  });
});

describe('chat creation that fails part way', () => {
  for (const mode of ['fails', 'lands'] as const) {
    it(`is finished later, not left as an empty space (genesis ${mode === 'fails' ? 'not written' : 'written, reply lost'})`, async () => {
      const w = new MemoryWorld();
      let t = Date.now();
      const bob = await flakyUser(w, 'mem:bob', { now: () => t });
      const alice = await makeUser(w.session('mem:alice'), 'mem:alice');
      bob.ctl.append = mode;
      await expect(bob.chat.createGroup('group', 'Trip')).rejects.toThrow();
      expect(bob.chat.groups.size).toBe(0);
      const [space] = await bob.provider.channel.listSpaces();
      expect(await bob.chat.inspectSpace(space!)).toBe('creating');
      expect(await bob.chat.finishCreates()).toEqual([]); // too fresh: another tab may be on it
      t += 61_000;
      const [g] = await bob.chat.finishCreates();
      expect(g!.space).toBe(space);
      expect(g!.name).toBe('Trip');
      expect(await bob.chat.inspectSpace(space!)).toBe('chat');
      await g!.invite(alice.address);
      const [ga] = await alice.chat.acceptInvites();
      await g!.send({ t: 'text', body: 'made it' });
      expect(texts(await ga!.sync())).toEqual(['made it']);
      // Restart: the group is there, the creation record is gone.
      const again = await Chat.open({ ...bob.chat.opts });
      expect([...again.groups.keys()]).toEqual([g!.id]);
      expect(await again.finishCreates()).toEqual([]);
    });
  }

  it('an empty space this device is not creating is reported as empty', async () => {
    const w = new MemoryWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const orphan = await bob.provider.channel.createSpace('group'); // e.g. made by an older client that failed
    expect(await bob.chat.inspectSpace(orphan)).toBe('empty');
    const g = await bob.chat.createGroup();
    expect(await bob.chat.inspectSpace(g.space)).toBe('chat');
  });
});

describe('a proposal whose reply was lost', () => {
  it('is recognised as ours on the next sync', async () => {
    const w = new MemoryWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const carol = await flakyUser(w, 'mem:carol');
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave');
    const g = await bob.chat.createGroup();
    await g.invite(carol.address);
    const [gc] = await carol.chat.acceptInvites();
    await g.invite(dave.address);
    const [gd] = await dave.chat.acceptInvites();
    await g.sync();
    await gc!.sync();
    carol.ctl.append = 'lands';
    await expect(gc!.leave()).rejects.toThrow();
    expect(gc!.active).toBe(true);
    const r = await gc!.sync(); // finds its leave in the log: done leaving
    expect(r.events.filter((e) => e.type === 'rejected')).toEqual([]);
    expect(r.events).toContainEqual({ type: 'removed' });
    expect(gc!.active).toBe(false);
    expect(carol.chat.groups.size).toBe(0);
    await g.sync(); // bob commits carol's leave
    await gd!.sync();
    expect(g.members().map((m) => m.address).sort()).toEqual([bob.address, dave.address]);
    await g.send({ t: 'text', body: 'bye carol' });
    expect(texts(await gd!.sync())).toEqual(['bye carol']);
  });
});
