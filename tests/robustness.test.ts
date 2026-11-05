/** Audit follow-ups: determinism, crash safety, junk resistance, padding, sharding, history. */
import { describe, expect, it } from 'vitest';
import { MemoryWorld, memoryDevice } from '../src/storage/index.js';
import { Chat, PersonalData, historyRecorder, encodeAppMessage, decodeAppMessage, type Group } from '../src/chat/index.js';
import { makeUser, addDevice, githubWorld, texts } from './chat-helpers.js';

const internals = (g: Group) => g as unknown as { meta: { logNext: number; space: string } };

describe('determinism', () => {
  it('members with different clocks agree on a join whose ticket looks expired to one of them', async () => {
    const w = new MemoryWorld();
    const base = Date.now();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', { now: () => base });
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave', { now: () => base + 30 * 86_400_000 }); // a month ahead
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', { now: () => base });
    const g = await bob.chat.createGroup();
    await g.invite(dave.address, { ttlMs: 60 * 86_400_000 });
    const [gd] = await dave.chat.acceptInvites();
    await g.invite(carol.address, { ttlMs: 86_400_000 }); // valid for a day by bob's clock
    const [gc] = await carol.chat.acceptInvites();
    expect(gc).toBeDefined();
    await g.sync();
    const rd = await gd!.sync();
    expect(rd.events.filter((e) => e.type === 'rejected')).toEqual([]);
    expect(gd!.epoch).toBe(g.epoch);
    expect(gd!.members().map((m) => m.address).sort()).toEqual(g.members().map((m) => m.address).sort());
  });

  it('a junk log entry from a member is skipped by everyone, never blocks the group', async () => {
    const w = new MemoryWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const alice = await makeUser(w.session('mem:alice'), 'mem:alice');
    const g = await bob.chat.startDm(alice.address);
    const [ga] = await alice.chat.acceptInvites();
    await g.sync();
    const { space, logNext } = internals(ga!).meta;
    await alice.provider.orderedLog.append(space, logNext, new TextEncoder().encode('not json at all'));
    const r = await g.sync();
    expect(r.events).toContainEqual({ type: 'rejected', index: logNext, reason: 'malformed log entry' });
    await g.rotate(); // the log keeps working after the junk
    await g.send({ t: 'text', body: 'after junk' });
    expect(texts(await ga!.sync())).toEqual(['after junk']);
  });
});

describe('crash safety', () => {
  it('a commit that landed before a crash is adopted on restart', async () => {
    const w = new MemoryWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const alice = await makeUser(w.session('mem:alice'), 'mem:alice');
    const g = await bob.chat.startDm(alice.address);
    const [ga] = await alice.chat.acceptInvites();
    await g.sync();
    // Simulate: the commit is appended, then the app dies before saving the new state.
    const dev = bob.device;
    const saved = new Map<string, Uint8Array>();
    for (const k of await dev.ephemeral.keys('chat/state/')) saved.set(k, (await dev.ephemeral.get(k))!);
    const savedMeta = new Map<string, Uint8Array>();
    for (const k of await dev.keystore.keys('chat/group/')) savedMeta.set(k, (await dev.keystore.get(k))!);
    await g.rotate();
    const epochAfter = g.epoch;
    for (const [k, v] of saved) await dev.ephemeral.put(k, v);
    for (const [k, v] of savedMeta) await dev.keystore.put(k, v);
    // re-create the pending marker that rotate() deleted after success
    const { jsonBytes, b64 } = await import('../src/util/codec.js');
    const { sha256 } = await import('../src/util/bytes.js');
    const mls = await import('ts-mls');
    const raw = await bob.provider.orderedLog.read(g.space, 0);
    const last = raw[raw.length - 1]!;
    await dev.ephemeral.put(`chat/pending/${g.id}`, jsonBytes({ hash: b64(await sha256(last)), state: b64(mls.encodeGroupState((g as unknown as { state: never }).state)) }));
    // restart
    const restarted = await Chat.open({ ...bob.chat.opts });
    const g2 = restarted.groups.get(g.id)!;
    expect(g2.epoch).toBe(epochAfter - 1n);
    await g2.sync();
    expect(g2.epoch).toBe(epochAfter);
    await g2.send({ t: 'text', body: 'survived' });
    expect(texts(await ga!.sync())).toEqual(['survived']);
    void memoryDevice;
  });
});

describe('invites before the invitee has an identity', () => {
  it('address-only invite is upgraded to a root-bound ticket once they publish one', async () => {
    const w = new MemoryWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const g = await bob.chat.createGroup();
    const t = await g.invite('mem:newbie');
    expect(t.toRoot).toBeUndefined();
    const newbie = await makeUser(w.session('mem:newbie'), 'mem:newbie'); // signs up later
    expect(await newbie.chat.acceptInvites()).toEqual([]); // asks bob's app for a bound ticket
    await g.sync(); // bob's app checks newbie's directory and issues it
    const [gn] = await newbie.chat.acceptInvites();
    expect(gn).toBeDefined();
    await g.send({ t: 'text', body: 'welcome newbie' });
    expect(texts(await gn!.sync())).toEqual(['welcome newbie']);
  });

  it('an address-only ticket cannot be used directly (members require a root-bound ticket)', async () => {
    const w = new MemoryWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const g = await bob.chat.createGroup();
    await g.invite('mem:x');
    const { checkCommit } = await import('../src/chat/policy.js');
    const v = checkCommit({
      policy: g.policy,
      members: [{ leafIndex: 0, root: bob.identity.fingerprint, device: bob.identity.cert.device, address: bob.address }],
      committer: undefined,
      proposals: [{ type: 'external_init', sender: undefined }],
      joiner: { leaf: { leafIndex: 1, root: 'r'.repeat(64), device: 'd', address: 'mem:x' }, ticket: { issuerRoot: bob.identity.fingerprint, ticket: { v: 1, group: g.id, to: 'mem:x', by: bob.identity.cert, expiresAt: 0, nonce: 'n', sig: '' } } },
      usedNonces: new Set(),
    });
    expect(v).toEqual({ ok: false, reason: 'the ticket does not name an identity key' });
  });
});

describe('metadata hygiene', () => {
  it('messages are padded to buckets', () => {
    const sizes = ['ok', 'a'.repeat(300), 'b'.repeat(900), 'c'.repeat(20000)].map((body) => encodeAppMessage({ v: 1, id: 'x', ts: 1, t: 'text', body }).length);
    expect(sizes).toEqual([256, 512, 1024, 32768]);
    expect(decodeAppMessage(encodeAppMessage({ v: 1, id: 'x', ts: 1, t: 'text', body: 'ok' }))).toEqual({ v: 1, id: 'x', ts: 1, t: 'text', body: 'ok' });
  });
});

describe('GitHub log sharding', () => {
  it('keeps working past 1,000 entries (folder listing limit)', async () => {
    const w = githubWorld();
    const p = w.session('bob');
    const s = await p.channel.createSpace('chat');
    for (let i = 0; i < 1003; i++) expect(await p.orderedLog.append(s, i, new TextEncoder().encode(String(i)))).toBe('ok');
    const tail = await p.orderedLog.read(s, 998);
    expect(tail.map((b) => new TextDecoder().decode(b))).toEqual(['998', '999', '1000', '1001', '1002']);
    expect([...w.gh.repos.get(s)!.files.keys()].filter((k) => k.startsWith('log/00001/'))).toHaveLength(3);
  });
});

describe('history backup end to end', () => {
  it('a new device restores messages it was never there for', async () => {
    const w = new MemoryWorld();
    const K = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const alicePersonal = await PersonalData.open(w.session('mem:alice').personal, K, 'laptop');
    const rec = historyRecorder(alicePersonal);
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const alice = await makeUser(w.session('mem:alice'), 'mem:alice');
    const chat = await Chat.open({ ...alice.chat.opts, onMessage: rec.onMessage });
    const g = await bob.chat.startDm(alice.address);
    const [ga] = await chat.acceptInvites();
    await g.send({ t: 'text', body: 'one' });
    await g.send({ t: 'text', body: 'two' });
    await ga!.sync();
    await ga!.send({ t: 'text', body: 'three' });
    await rec.flush();
    const phone = await PersonalData.open(w.session('mem:alice').personal, K, 'phone');
    const hist = await phone.readHistory(ga!.id);
    expect(hist.map((h) => (h.body as { body: string }).body)).toEqual(['one', 'two', 'three']);
  });
});

describe('multi-device space owner', () => {
  it("the owner's other device does not revoke someone with a pending invite", async () => {
    const w = githubWorld();
    const bob = await makeUser(w.session('bob'), 'github:bob');
    const g = await bob.chat.createGroup();
    const tablet = await addDevice(bob);
    const [gt] = await tablet.chat.acceptInvites(); // bob's second device self-joins
    expect(gt).toBeDefined();
    const carol = await makeUser(w.session('carol'), 'github:carol');
    await g.invite(carol.address); // from bob's laptop
    expect((await gt!.reconcileChannel(true)).revoked).toEqual([]); // the tablet finds the ticket
    const [gc] = await carol.chat.acceptInvites();
    expect(gc).toBeDefined();
    // and someone with access but no ticket is removed by either device
    const mallory = w.gh.addUser('mallory');
    void mallory;
    await bob.provider.channel.grant(g.space, 'github:mallory');
    expect((await gt!.reconcileChannel(true)).revoked).toEqual(['github:mallory']);
  });
});
