/**
 * Forks: a device that ends up on its own branch of the group (it once rejected a commit the
 * others accepted, and committed on its own state) must come back by rejoining, not by
 * committing again, which the others would reject in turn, forever.
 */
import { describe, expect, it } from 'vitest';
import * as mls from 'ts-mls';
import { MemoryWorld } from '../src/storage/index.js';
import { ciphersuite, type Group } from '../src/chat/index.js';
import { makeUser, addDevice, texts, type TestUserOptions } from './chat-helpers.js';

type Meta = { needsHeal: boolean; logNext: number; lastHash: string; space: string };
const internals = (g: Group) => g as unknown as { state: mls.ClientState; meta: Meta; applyEntry: (e: { kind: string }, out: { events: unknown[] }) => Promise<void> };

async function threeMembers() {
  const w = new MemoryWorld({ claimOnce: false });
  const opts: TestUserOptions = { build: { preKeys: true } };
  const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
  const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
  const dave = await makeUser(w.session('mem:dave'), 'mem:dave', opts);
  const g = await bob.chat.createGroup();
  await g.invite(carol.address);
  await g.invite(dave.address);
  const [gc] = await carol.chat.acceptInvites();
  const [gd] = await dave.chat.acceptInvites();
  for (const x of [g, gc!, gd!]) await x.sync();
  return { w, opts, bob, carol, dave, g, gc: gc!, gd: gd! };
}

/** The old behaviour that forked groups: reject the next commit and heal by committing on our own state. */
function rejectNextCommitOnce(g: Group) {
  const i = internals(g);
  const orig = i.applyEntry.bind(g);
  let done = false;
  i.applyEntry = async (e, out) => {
    if (!done && e.kind === 'commit') {
      done = true;
      out.events.push({ type: 'rejected', index: -1, reason: 'test: rejected once' });
      i.meta.needsHeal = true;
      return;
    }
    return orig(e, out);
  };
}

const logLength = async (g: Group) => (await g.chat.provider.orderedLog.read(internals(g).meta.space, 0)).length;

describe('forks', () => {
  it('a device left on its own branch rejoins, the group converges, and the log stops growing', async () => {
    const { g, gc, gd } = await threeMembers();
    rejectNextCommitOnce(gc);
    await g.rotate(); // carol's app wrongly rejects this one...
    await gc.sync(); // ...and heals on her own state: the group is forked
    await gd.sync();
    expect(gc.epoch).toBe(g.epoch); // same number, different branch
    // The next commit on the main branch (a weekly key change, an invite...) brings carol back.
    await g.rotate();

    // The heals that used to bounce between the branches forever: a few rounds settle it.
    for (let r = 0; r < 4; r++) for (const x of [g, gc, gd]) await x.sync();
    const settled = await logLength(g);
    for (let r = 0; r < 3; r++) for (const x of [g, gc, gd]) await x.sync();
    expect(await logLength(g)).toBe(settled);

    // Everyone on one branch: they can all read each other.
    await gc.send({ t: 'text', body: 'carol is back' });
    expect(texts(await g.sync())).toContain('carol is back');
    expect(texts(await gd.sync())).toContain('carol is back');
    await g.send({ t: 'text', body: 'welcome back' });
    expect(texts(await gc.sync())).toContain('welcome back');
    expect(gc.epoch).toBe(g.epoch);
    expect(gd.epoch).toBe(g.epoch);
    expect(g.members()).toHaveLength(3);
  });

  it('a lagging sibling commit is ignored, not answered with another commit', async () => {
    const { g, gc, gd } = await threeMembers();
    const cs = await ciphersuite();
    // carol's stale client commits on the epoch everyone already left.
    const old = internals(gc).state;
    await g.rotate();
    await gc.sync();
    await gd.sync();
    const res = await mls.createCommit({ state: old, cipherSuite: cs }, { extraProposals: [], ratchetTreeExtension: true });
    const m = internals(g).meta;
    const gi = await mls.createGroupInfoWithExternalPubAndRatchetTree(res.newState, [], cs);
    const { b64, jsonBytes } = await import('../src/util/codec.js');
    const entry = { v: 1, i: m.logNext, prev: m.lastHash, kind: 'commit', epoch: String(res.newState.groupContext.epoch), mls: b64(mls.encodeMlsMessage(res.commit)), gi: b64(mls.encodeMlsMessage({ wireformat: 'mls_group_info', version: 'mls10', groupInfo: gi })) };
    expect(await g.chat.provider.orderedLog.append(m.space, m.logNext, jsonBytes(entry))).toBe('ok');
    const before = await logLength(g);
    for (const x of [g, gd]) {
      const r = await x.sync();
      expect(r.events).toEqual(expect.arrayContaining([expect.objectContaining({ type: 'rejected' })]));
    }
    expect(await logLength(g)).toBe(before); // nobody committed in answer
    await g.send({ t: 'text', body: 'still fine' });
    expect(texts(await gd.sync())).toContain('still fine');
  });
});

describe('a device in the tree twice', () => {
  it("the admin removes a joined device's leftover pre-key leaf at once, so new devices can join", async () => {
    const w = new MemoryWorld({ claimOnce: false });
    const opts: TestUserOptions = { build: { preKeys: true } };
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.chat.refreshPreKey();
    const g = await bob.chat.createGroup('dm');
    await g.invite(carol.address); // carol is added with her pre-key
    expect(g.members().find((m) => m.address === carol.address)?.pending).toBe(true);

    // An older app joined with a ticket next to the pre-key leaf instead of replacing it.
    for (const n of await carol.provider.inviteInbox.list()) await carol.provider.channel.acceptGrant(n.pointer);
    const cs = await ciphersuite();
    const raw = await carol.provider.orderedLog.read(g.space, 0);
    const last = JSON.parse(new TextDecoder().decode(raw[raw.length - 1]!));
    const { unb64, b64, jsonBytes } = await import('../src/util/codec.js');
    const giMsg = mls.decodeMlsMessage(unb64(last.gi), 0)![0];
    if (giMsg.wireformat !== 'mls_group_info') throw new Error('gi');
    const drops = await carol.provider.dropBox.list(g.space, await (await import('../src/chat/index.js')).recipientTag(carol.address));
    const { decodeTicket, encodeTicket } = await import('../src/chat/index.js');
    const ticket = drops.map((d) => decodeTicket(d.data)).find((t) => !!t);
    const kp = await carol.chat.keyPackage();
    const { publicMessage, newState } = await mls.joinGroupExternal(giMsg.groupInfo, kp.publicPackage, kp.privatePackage, false, cs, undefined, carol.chat.clientConfig(), ticket ? encodeTicket(ticket) : new Uint8Array());
    const gi2 = await mls.createGroupInfoWithExternalPubAndRatchetTree(newState, [], cs);
    const { sha256 } = await import('../src/util/bytes.js');
    const entry = { v: 1, i: raw.length, prev: b64(await sha256(raw[raw.length - 1]!)), kind: 'commit', epoch: String(newState.groupContext.epoch), mls: b64(mls.encodeMlsMessage({ wireformat: 'mls_public_message', version: 'mls10', publicMessage })), gi: b64(mls.encodeMlsMessage({ wireformat: 'mls_group_info', version: 'mls10', groupInfo: gi2 })) };
    expect(await carol.provider.orderedLog.append(g.space, raw.length, jsonBytes(entry))).toBe('ok');
    await g.sync();

    // bob's next sync removes the leftover leaf; a new browser of bob can then join.
    await g.sync();
    const carolLeaves = g.members().find((m) => m.address === carol.address)?.devices ?? [];
    expect(carolLeaves).toHaveLength(1);
    const laptop = await addDevice(bob, opts);
    const joined = await laptop.chat.join(g.space);
    expect(joined).toBeTruthy();
  });
});
