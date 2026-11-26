/**
 * Attacker suite: a malicious member (modified client) and a malicious storage operator (or any
 * collaborator who can write the space). Each test is the attack, then what honest clients do.
 */
import { describe, expect, it } from 'vitest';
import * as mls from 'ts-mls';
import { MemoryWorld, memoryDevice, resolveFeatures } from '../src/storage/index.js';
import {
  Chat,
  IdentityRegistry,
  certificateToCredential,
  checkCommit,
  ciphersuite,
  createDeviceIdentity,
  createRootKey,
  defaultPolicy,
  encodeAppMessage,
  encodePolicy,
  encodeTicket,
  issueDeviceCertificate,
  newDeviceId,
  recipientTag,
  signTicket,
  type Group,
  type GroupEvent,
  type RootKey,
} from '../src/chat/index.js';
import { b64, jsonBytes, unb64 } from '../src/util/codec.js';
import { sha256 } from '../src/util/bytes.js';
import { addDevice, makeUser, texts, type TestUserOptions } from './chat-helpers.js';

const internals = (g: Group) =>
  g as unknown as { state: mls.ClientState; meta: { logNext: number; lastHash: string; space: string; groupId: string; ownMail: string[] } };

const enc = (m: mls.MLSMessage) => mls.encodeMlsMessage(m);
const giBytes = async (st: mls.ClientState) =>
  b64(enc({ wireformat: 'mls_group_info', version: 'mls10', groupInfo: await mls.createGroupInfoWithExternalPubAndRatchetTree(st, [], await ciphersuite()) }));

/** Append a commit made from `state` to the log, as a modified client would. */
async function appendCommit(g: Group, res: mls.CreateCommitResult) {
  const { meta } = internals(g);
  const entry = { v: 1, i: meta.logNext, prev: meta.lastHash, kind: 'commit', epoch: String(res.newState.groupContext.epoch), mls: b64(enc(res.commit)), gi: await giBytes(res.newState) };
  expect(await g.chat.provider.orderedLog.append(meta.space, meta.logNext, jsonBytes(entry))).toBe('ok');
}

/** The storage operator appends a well-formed entry of its choosing at the end of the log. */
async function operatorAppend(w: MemoryWorld, space: string, entry: Record<string, unknown>) {
  const log = w.spaces.get(space)!.log;
  const prev = b64(await sha256(log[log.length - 1]!));
  log.push(jsonBytes({ v: 1, i: log.length, prev, ...entry }));
}

/** A device key certified by `root` (default: a brand-new root) claiming `address`. Not in any directory. */
async function forgedChat(w: MemoryWorld, address: string, root: RootKey = createRootKey()) {
  const device = memoryDevice();
  const identity = await createDeviceIdentity(device, root, address, newDeviceId());
  const provider = w.session('mem:mallory');
  return Chat.open({ provider, device, identity, registry: new IdentityRegistry(provider.directory), features: resolveFeatures(provider, { preKeys: true }) });
}

/** The attacker's own MLS group with the real group id, adding the given KeyPackages. */
async function fakeGroup(attacker: Chat, groupId: string, adds: mls.KeyPackage[]) {
  const cs = await ciphersuite();
  const kp = await attacker.keyPackage();
  const policy = { ...defaultPolicy('group', attacker.identity.fingerprint), adds: 'members' as const };
  const st = await mls.createGroup(unb64(groupId), kp.publicPackage, kp.privatePackage, [encodePolicy(policy)], cs, attacker.clientConfig());
  if (!adds.length) return { state: st, welcome: undefined };
  const res = await mls.createCommit({ state: st, cipherSuite: cs }, { extraProposals: adds.map((k) => ({ proposalType: 'add', add: { keyPackage: k } }) as mls.Proposal), ratchetTreeExtension: true });
  return { state: res.newState, welcome: enc({ wireformat: 'mls_welcome', version: 'mls10', welcome: res.welcome! }) };
}

async function preKeyOf(w: MemoryWorld, address: string) {
  const [b] = await w.session('mem:mallory').preKeys!.read(address);
  const m = mls.decodeMlsMessage(b!, 0)![0];
  if (m.wireformat !== 'mls_key_package') throw new Error('kp');
  return m.keyPackage;
}

const isWelcome = (d: Uint8Array) => {
  try {
    return mls.decodeMlsMessage(d, 0)?.[0].wireformat === 'mls_welcome';
  } catch {
    return false;
  }
};

/** The operator puts `data` in someone's drop box; with `replaceWelcomes`, the real Welcome goes. */
async function plantDrop(w: MemoryWorld, space: string, address: string, data: Uint8Array, opts: { replaceWelcomes?: boolean; first?: boolean } = {}) {
  const box = w.spaces.get(space)!.drop;
  const tag = await recipientTag(address);
  let list = box.get(tag) ?? [];
  if (opts.replaceWelcomes) list = list.filter((d) => !isWelcome(d.data));
  const item = { id: `planted-${list.length}`, data };
  box.set(tag, opts.first ? [item, ...list] : [...list, item]);
}

function preKeyWorld() {
  const w = new MemoryWorld({ claimOnce: false });
  const opts: TestUserOptions = { build: { preKeys: true } };
  return { w, opts };
}

async function threeMembers() {
  const { w, opts } = preKeyWorld();
  const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
  const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
  const dave = await makeUser(w.session('mem:dave'), 'mem:dave', opts);
  const g = await bob.chat.createGroup();
  await g.invite(carol.address);
  await g.invite(dave.address);
  const [gc] = await carol.chat.acceptInvites();
  const [gd] = await dave.chat.acceptInvites();
  await g.sync();
  await gc!.sync();
  await gd!.sync();
  return { w, bob, carol, dave, g, gc: gc!, gd: gd! };
}

const rejected = (events: GroupEvent[]) => events.filter((e) => e.type === 'rejected');
const gaps = (events: GroupEvent[]) => events.filter((e): e is Extract<GroupEvent, { type: 'gap' }> => e.type === 'gap');

/** Can bob and the joiner talk in the REAL group (bob reads what the joiner writes)? */
async function talks(g: Group, joined: Group, body: string) {
  await g.sync();
  await joined.send({ t: 'text', body });
  return texts(await g.sync()).includes(body);
}

describe('malicious member: credential succession (C1)', () => {
  it('a commit whose path leaf claims another address under another root is rejected by every member', async () => {
    const { bob, carol, g, gc, gd } = await threeMembers();
    const cs = await ciphersuite();
    // carol's modified client: her leaf now carries a cert from a new root claiming to be mem:bob.
    const forged = issueDeviceCertificate(createRootKey(), carol.identity.publicKey, 'x', 'mem:bob');
    const st = internals(gc).state;
    const at = st.privatePath.leafIndex * 2;
    const node = st.ratchetTree[at] as mls.NodeLeaf;
    const tree = [...st.ratchetTree];
    tree[at] = { ...node, leaf: { ...node.leaf, credential: certificateToCredential(forged) } } as mls.NodeLeaf;
    const res = await mls.createCommit({ state: { ...st, ratchetTree: tree }, cipherSuite: cs }, { extraProposals: [], ratchetTreeExtension: true });
    await appendCommit(gc, res);
    // ...and she writes in the epoch she made, as "mem:bob".
    const app = await mls.createApplicationMessage(res.newState, encodeAppMessage({ v: 1, id: 'm1', ts: 1, t: 'text', body: 'I am bob' }), cs);
    await carol.provider.mailbox.post(g.space, enc({ wireformat: 'mls_private_message', version: 'mls10', privateMessage: app.privateMessage }));

    for (const member of [g, gd]) {
      const r = await member.sync();
      expect(rejected(r.events)).toEqual([expect.objectContaining({ reason: 'a leaf may not change its owner or address' })]);
      expect(r.messages.filter((m) => m.from.address === 'mem:bob' && m.from.fingerprint !== bob.identity.fingerprint)).toEqual([]);
      expect(texts(r)).not.toContain('I am bob');
      const bobs = member.members().filter((m) => m.address === 'mem:bob');
      expect(bobs.map((m) => m.fingerprint)).toEqual([bob.identity.fingerprint]);
    }
    // Both honest members agree on the epoch (one of them healed the fork, the other followed).
    await g.sync();
    await gd.sync();
    expect(gd.epoch).toBe(g.epoch);
  });

  it('an update proposal that changes the owner or address is refused by the rules', () => {
    const policy = defaultPolicy('group', 'root-bob');
    const members = [
      { leafIndex: 0, root: 'root-bob', device: 'd0', address: 'mem:bob' },
      { leafIndex: 1, root: 'root-carol', device: 'd1', address: 'mem:carol' },
    ];
    const check = (leaf: (typeof members)[number] | undefined) =>
      checkCommit({ policy, members, committer: 0, proposals: [{ type: 'update', sender: 1, leaf }], usedNonces: new Set() });
    expect(check({ leafIndex: -1, root: 'root-carol', device: 'd1-new', address: 'mem:carol' })).toEqual({ ok: true });
    expect(check({ leafIndex: -1, root: 'root-evil', device: 'd1', address: 'mem:bob' })).toMatchObject({ ok: false });
    expect(check({ leafIndex: -1, root: 'root-carol', device: 'd1', address: 'mem:bob' })).toMatchObject({ ok: false });
    expect(check(undefined)).toMatchObject({ ok: false });
  });
});

describe('malicious storage operator: forged Welcome and GroupInfo (C2)', () => {
  async function invitedWithPreKey() {
    const { w, opts } = preKeyWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.chat.refreshPreKey();
    const g = await bob.chat.createGroup();
    await g.invite(carol.address); // adds carol's pre-key device and leaves a Welcome and a ticket
    return { w, bob, carol, g };
  }

  it('a Welcome into a look-alike group signed by a fake "mem:bob" is refused; the invitee joins the real group with the ticket', async () => {
    const { w, bob, carol, g } = await invitedWithPreKey();
    const mallory = await forgedChat(w, 'mem:bob');
    const fake = await fakeGroup(mallory, g.id, [await preKeyOf(w, carol.address)]);
    await plantDrop(w, g.space, carol.address, fake.welcome!, { replaceWelcomes: true });

    const [gc] = await carol.chat.acceptInvites();
    expect(gc).toBeDefined();
    expect(gc!.members().find((m) => m.address === 'mem:bob')!.fingerprint).toBe(bob.identity.fingerprint);
    expect(internals(gc!).state.ratchetTree).not.toEqual(fake.state.ratchetTree);
    expect(await talks(g, gc!, 'hello real bob')).toBe(true);
  });

  it('with a forged Welcome first in the drop box, the next (real) Welcome is used', async () => {
    const { w, bob, carol, g } = await invitedWithPreKey();
    const mallory = await forgedChat(w, 'mem:bob');
    const fake = await fakeGroup(mallory, g.id, [await preKeyOf(w, carol.address)]);
    await plantDrop(w, g.space, carol.address, fake.welcome!, { first: true });
    const [gc] = await carol.chat.acceptInvites();
    expect(gc!.members().find((m) => m.address === 'mem:bob')!.fingerprint).toBe(bob.identity.fingerprint);
    expect(await talks(g, gc!, 'via the real welcome')).toBe(true);
  });

  it('a Welcome from a real account whose group holds a leaf claiming someone else\'s address is refused', async () => {
    const { w, bob, carol, g } = await invitedWithPreKey();
    // eve has a real, published identity; a second key under her root claims to be mem:bob.
    const eve = await makeUser(w.session('mem:eve'), 'mem:eve', { build: { preKeys: true } });
    const eveAsBob = await forgedChat(w, 'mem:bob', eve.root);
    const bobKp = (await eveAsBob.keyPackage()).publicPackage;
    const fake = await fakeGroup(eve.chat, g.id, [bobKp, await preKeyOf(w, carol.address)]);
    await plantDrop(w, g.space, carol.address, fake.welcome!, { replaceWelcomes: true });
    const [gc] = await carol.chat.acceptInvites();
    expect(gc!.members().map((m) => m.address).sort()).toEqual(['mem:bob', 'mem:carol']);
    expect(gc!.members().find((m) => m.address === 'mem:bob')!.fingerprint).toBe(bob.identity.fingerprint);
    expect(await talks(g, gc!, 'not eve')).toBe(true);
  });

  it('a look-alike GroupInfo planted in the log (with a forged ticket) is ignored: the join goes to the real group', async () => {
    const { w, opts } = preKeyWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave', opts); // no pre-key: joins by ticket
    const g = await bob.chat.createGroup();
    await g.invite(dave.address);
    // The operator makes a group of its own with the real id, signed by a key claiming mem:bob...
    const mallory = await forgedChat(w, 'mem:bob');
    const fake = await fakeGroup(mallory, g.id, []);
    await operatorAppend(w, g.space, { kind: 'proposal', epoch: String(g.epoch), gi: await giBytes(fake.state) });
    // ...and a ticket for dave from that key, so the external join has an issuer in the tree.
    const cs = await ciphersuite();
    const forgedTicket = await signTicket(
      { group: g.id, to: dave.address, toRoot: dave.identity.fingerprint, by: mallory.identity.cert, expiresAt: Date.now() + 86_400_000, nonce: 'forged' },
      (m) => cs.signature.sign(mallory.identity.signKey, m),
    );
    await plantDrop(w, g.space, dave.address, encodeTicket(forgedTicket));
    // A GroupInfo on an entry members don't apply never steers a joiner: dave joins the real
    // group with the real ticket, and the forged one is never tried.
    const [gd] = await dave.chat.acceptInvites();
    expect(gd!.members().find((m) => m.address === 'mem:bob')!.fingerprint).toBe(bob.identity.fingerprint);
    expect(await talks(g, gd!, 'real group')).toBe(true);
  });

  it('a look-alike GroupInfo that would let a "self-join" through (another device of mine in the tree) is ignored', async () => {
    const { w, opts } = preKeyWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.chat.refreshPreKey();
    const laptop = await addDevice(carol, opts);
    const g = await bob.chat.createGroup();
    await g.invite(carol.address); // adds carol's first device by pre-key; the laptop has none
    const mallory = await forgedChat(w, 'mem:bob');
    const fake = await fakeGroup(mallory, g.id, [await preKeyOf(w, carol.address)]);
    await operatorAppend(w, g.space, { kind: 'proposal', epoch: String(g.epoch), gi: await giBytes(fake.state) });
    for (const n of await laptop.provider.inviteInbox.list()) await laptop.provider.channel.acceptGrant(n.pointer);
    // The planted GroupInfo is ignored: the laptop self-joins the real group.
    const gl = await laptop.chat.join(g.space);
    expect(gl!.members().find((m) => m.address === 'mem:bob')!.fingerprint).toBe(bob.identity.fingerprint);
  });
});

describe('malicious storage operator: dropped messages (M1)', () => {
  async function pair() {
    const { w, opts } = preKeyWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    const g = await bob.chat.createGroup();
    await g.invite(carol.address);
    const [gc] = await carol.chat.acceptInvites();
    await g.sync();
    await gc!.sync();
    return { w, bob, carol, g, gc: gc! };
  }

  it('a message dropped from the middle is reported once, after a later sync still lacks it', async () => {
    const { w, bob, g, gc } = await pair();
    for (const body of ['a', 'b', 'c']) await g.send({ t: 'text', body });
    const mail = w.spaces.get(g.space)!.mail;
    const b = internals(g).meta.ownMail.at(-2)!;
    mail.splice(mail.findIndex((m) => m.id === b), 1);
    const r1 = await gc.sync();
    expect(texts(r1)).toEqual(['a', 'c']);
    expect(gaps(r1.events)).toEqual([]); // could still be on its way
    const r2 = await gc.sync();
    expect(gaps(r2.events)).toEqual([{ type: 'gap', from: expect.objectContaining({ address: 'mem:bob', fingerprint: bob.identity.fingerprint }), epoch: g.epoch, missing: 1 }]);
    expect(gaps((await gc.sync()).events)).toEqual([]); // reported once
  });

  it('a message that is only listed late (out of order) is not reported', async () => {
    const { w, g, gc } = await pair();
    for (const body of ['a', 'b']) await g.send({ t: 'text', body });
    const mail = w.spaces.get(g.space)!.mail;
    const a = internals(g).meta.ownMail.at(-2)!;
    const [held] = mail.splice(mail.findIndex((m) => m.id === a), 1);
    const r1 = await gc.sync();
    expect(texts(r1)).toEqual(['b']);
    mail.push(held!);
    const r2 = await gc.sync();
    expect(texts(r2)).toEqual(['a']);
    expect(gaps(r2.events)).toEqual([]);
    expect(gaps((await gc.sync()).events)).toEqual([]);
  });

  it('normal traffic across epochs and senders reports no gaps', async () => {
    const { g, gc } = await pair();
    const events: GroupEvent[] = [];
    for (let i = 0; i < 3; i++) {
      await g.send({ t: 'text', body: `b${i}` });
      await gc.send({ t: 'text', body: `c${i}` });
      events.push(...(await gc.sync()).events, ...(await g.sync()).events);
      await g.rotate();
    }
    events.push(...(await gc.sync()).events, ...(await gc.sync()).events, ...(await g.sync()).events);
    expect(gaps(events)).toEqual([]);
  });
});

describe('replay and rollback (already handled)', () => {
  it('a replayed application message is not delivered twice', async () => {
    const { w, g, gc } = await threeMembers();
    await g.send({ t: 'text', body: 'once' });
    expect(texts(await gc.sync())).toEqual(['once']);
    const mail = w.spaces.get(g.space)!.mail;
    mail.push({ id: 'replay', data: mail[mail.length - 1]!.data });
    const r = await gc.sync();
    expect(texts(r)).toEqual([]);
  });

  it('an old commit replayed at the end of the log is rejected', async () => {
    const { w, g, gc } = await threeMembers();
    const log = w.spaces.get(g.space)!.log;
    const old = JSON.parse(new TextDecoder().decode(log[1]));
    await operatorAppend(w, g.space, { kind: old.kind, epoch: old.epoch, mls: old.mls, gi: old.gi });
    const before = gc.epoch;
    const r = await gc.sync();
    expect(rejected(r.events).length).toBeGreaterThan(0);
    expect(gc.members()).toHaveLength(3);
    expect(gc.epoch).toBeGreaterThanOrEqual(before);
  });

  it('rolling the log back (dropping entries already seen) is detected', async () => {
    const { w, g, gc } = await threeMembers();
    await g.rotate();
    await gc.sync();
    w.spaces.get(g.space)!.log.pop();
    await expect(gc.sync()).rejects.toMatchObject({ code: 'rewrite_detected' });
  });

  it('replacing a pinned directory with one of another root is flagged as a key change, not trusted', async () => {
    const { w, bob, carol } = await threeMembers();
    expect((await carol.registry.lookup(bob.address)).status).toBe('ok');
    const elsewhere = new MemoryWorld();
    await makeUser(elsewhere.session('mem:bob'), 'mem:bob');
    w.directories.set(bob.address, elsewhere.directories.get('mem:bob')!);
    expect((await carol.registry.lookup(bob.address)).status).toBe('key-changed');
  });
});
