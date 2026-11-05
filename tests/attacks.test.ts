/**
 * Adversarial tests: a malicious member, a stranger with channel access, a storage operator
 * that rewrites history, replayed and forged invites, revoked devices.
 */
import { describe, expect, it } from 'vitest';
import * as mls from 'ts-mls';
import { MemoryWorld } from '../src/storage/index.js';
import { ciphersuite, recipientTag, encodeTicket, signTicket, type Group } from '../src/chat/index.js';
import { b64, jsonBytes } from '../src/util/codec.js';
import { sha256 } from '../src/util/bytes.js';
import { makeUser, addDevice, githubWorld, texts } from './chat-helpers.js';

const internals = (g: Group) => g as unknown as { state: mls.ClientState; meta: { logNext: number; lastHash: string; space: string; groupId: string } };

/** Commit anything, skipping our own policy checks, straight into the log (a modified client). */
async function rogueCommit(g: Group, proposals: mls.Proposal[]) {
  const cs = await ciphersuite();
  await g.sync();
  const { state, meta } = internals(g);
  const res = await mls.createCommit({ state, cipherSuite: cs }, { extraProposals: proposals, ratchetTreeExtension: true });
  const gi = await mls.createGroupInfoWithExternalPubAndRatchetTree(res.newState, [], cs);
  const entry = {
    v: 1, i: meta.logNext, prev: meta.lastHash, kind: 'commit', epoch: String(res.newState.groupContext.epoch),
    mls: b64(mls.encodeMlsMessage(res.commit)),
    gi: b64(mls.encodeMlsMessage({ wireformat: 'mls_group_info', version: 'mls10', groupInfo: gi })),
  };
  expect(await g.chat.provider.orderedLog.append(meta.space, meta.logNext, jsonBytes(entry))).toBe('ok');
  return res;
}

/** Commit an external join by hand (a modified client), carrying any ticket bytes. */
async function rogueExternalJoin(u: { chat: import('../src/chat/index.js').Chat; provider: import('../src/storage/index.js').StorageProvider }, space: string, ticket: Uint8Array) {
  const cs = await ciphersuite();
  const raw = await u.provider.orderedLog.read(space, 0);
  const last = JSON.parse(new TextDecoder().decode(raw[raw.length - 1]));
  const gi = mls.decodeMlsMessage(Uint8Array.from(Buffer.from(last.gi, 'base64url')), 0)![0];
  if (gi.wireformat !== 'mls_group_info') throw new Error('gi');
  const kp = await u.chat.keyPackage();
  const { publicMessage } = await mls.joinGroupExternal(gi.groupInfo, kp.publicPackage, kp.privatePackage, false, cs, undefined, u.chat.clientConfig(), ticket);
  const prev = b64(await sha256(raw[raw.length - 1]!));
  const entry = { v: 1, i: raw.length, prev, kind: 'commit', epoch: '99', mls: b64(mls.encodeMlsMessage({ wireformat: 'mls_public_message', version: 'mls10', publicMessage })) };
  expect(await u.provider.orderedLog.append(space, raw.length, jsonBytes(entry))).toBe('ok');
}

async function setupGroup(w = new MemoryWorld()) {
  const bob = await makeUser(w.session('mem:bob'), 'mem:bob', { build: { offlineAdd: true } });
  const carol = await makeUser(w.session('mem:carol'), 'mem:carol', { build: { offlineAdd: true } });
  const dave = await makeUser(w.session('mem:dave'), 'mem:dave', { build: { offlineAdd: true } });
  const g = await bob.chat.createGroup();
  await g.invite(carol.address);
  const [gc] = await carol.chat.acceptInvites();
  await g.sync();
  return { w, bob, carol, dave, g, gc: gc! };
}

describe('malicious member (modified client)', () => {
  it('a non-admin adding someone is rejected by every honest member, and the group heals', async () => {
    const { w, bob, carol, dave, g, gc } = await setupGroup();
    await dave.chat.publishKeyPackages(1);
    const kpBytes = (await w.session('mem:carol').claimOnce!.claim(dave.address))!;
    const kp = mls.decodeMlsMessage(kpBytes, 0)![0];
    if (kp.wireformat !== 'mls_key_package') throw new Error('kp');
    await rogueCommit(gc, [{ proposalType: 'add', add: { keyPackage: kp.keyPackage } }]);
    const r = await g.sync();
    expect(r.events.find((e) => e.type === 'rejected')).toMatchObject({ reason: expect.stringMatching(/only allowed members may add/) });
    expect(g.members().map((m) => m.address)).not.toContain(dave.address);
    // bob's app posted a heal commit, so the newest GroupInfo is honest again
    expect(r.events.some((e) => e.type === 'rotated')).toBe(true);
    await g.send({ t: 'text', body: 'still just us' });
    void bob;
    void carol;
  });

  it('a non-admin removing someone else is rejected', async () => {
    const { dave, g, gc } = await setupGroup();
    await g.invite(dave.address);
    await dave.chat.acceptInvites();
    await g.sync();
    await gc.sync();
    const daveLeaf = g.members().find((m) => m.address === dave.address)!.devices[0]!.leafIndex;
    await rogueCommit(gc, [{ proposalType: 'remove', remove: { removed: daveLeaf } }]);
    const r = await g.sync();
    expect(r.events.find((e) => e.type === 'rejected')).toMatchObject({ reason: expect.stringMatching(/only admins may remove/) });
    expect(g.members()).toHaveLength(3);
  });

  it('a commit from a member that changes the policy without being admin is rejected', async () => {
    const { g, gc } = await setupGroup();
    await gc.sync();
    const { encodePolicy } = await import('../src/chat/policy.js');
    const st = internals(gc).state;
    const exts = st.groupContext.extensions.filter((e) => e.extensionType !== 0xf0a1);
    await rogueCommit(gc, [{ proposalType: 'group_context_extensions', groupContextExtensions: { extensions: [...exts, encodePolicy({ ...gc.policy, admins: [gc.chat.identity.fingerprint] })] } }]);
    const r = await g.sync();
    expect(r.events.find((e) => e.type === 'rejected')).toMatchObject({ reason: expect.stringMatching(/only admins may change the policy/) });
    expect(g.policy.admins).toEqual([g.chat.identity.fingerprint]);
  });
});

describe('strangers and invites', () => {
  it('channel access alone is not enough: no ticket, no join', async () => {
    const { w, g, dave } = await setupGroup();
    // The space owner's channel lets dave in (or a bug does), but nobody signed a ticket for him.
    const grant = await w.session('mem:bob').channel.grant(g.space, dave.address);
    if (grant.status === 'invited') await w.session('mem:dave').channel.acceptGrant(grant.pointer);
    expect(await dave.chat.join(g.space)).toBeUndefined();
  });

  it('a hand-made external join without a valid ticket is rejected by members', async () => {
    const { w, g, dave } = await setupGroup();
    const grant = await w.session('mem:bob').channel.grant(g.space, dave.address);
    if (grant.status === 'invited') await w.session('mem:dave').channel.acceptGrant(grant.pointer);
    const cs = await ciphersuite();
    const raw = await dave.provider.orderedLog.read(g.space, 0);
    const last = JSON.parse(new TextDecoder().decode(raw[raw.length - 1]));
    const gi = mls.decodeMlsMessage(Uint8Array.from(Buffer.from(last.gi, 'base64url')), 0)![0];
    if (gi.wireformat !== 'mls_group_info') throw new Error('gi');
    const kp = await dave.chat.keyPackage();
    // forge: a ticket signed by dave himself
    const forged = await signTicket(
      { group: internals(g).meta.groupId, to: dave.address, by: dave.identity.cert, expiresAt: Date.now() + 1e6, nonce: 'n1' },
      (m) => cs.signature.sign(dave.identity.signKey, m),
    );
    const { publicMessage } = await mls.joinGroupExternal(gi.groupInfo, kp.publicPackage, kp.privatePackage, false, cs, undefined, dave.chat.clientConfig(), encodeTicket(forged));
    const prev = b64(await sha256(raw[raw.length - 1]!));
    const entry = { v: 1, i: raw.length, prev, kind: 'commit', epoch: '99', mls: b64(mls.encodeMlsMessage({ wireformat: 'mls_public_message', version: 'mls10', publicMessage })) };
    await dave.provider.orderedLog.append(g.space, raw.length, jsonBytes(entry));
    const r = await g.sync();
    expect(r.events.find((e) => e.type === 'rejected')).toMatchObject({ reason: expect.stringMatching(/issuer may not add/) });
    expect(g.members().map((m) => m.address)).not.toContain(dave.address);
  });

  it('a ticket for carol does not let dave in; a used ticket cannot be replayed after removal', async () => {
    const w = new MemoryWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol');
    const g = await bob.chat.createGroup();
    const ticket = await g.invite(carol.address);
    // carol's ticket copied into dave's drop box doesn't work for dave (address and root bound)
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave');
    const grant = await w.session('mem:bob').channel.grant(g.space, dave.address);
    if (grant.status === 'invited') await w.session('mem:dave').channel.acceptGrant(grant.pointer);
    await w.session('mem:bob').dropBox.put(g.space, await recipientTag(dave.address), encodeTicket(ticket));
    expect(await dave.chat.join(g.space)).toBeUndefined();
    // carol joins, is removed, then tries the same ticket again
    const [gc] = await carol.chat.acceptInvites();
    expect(gc).toBeDefined();
    await g.sync();
    await g.remove(carol.identity.fingerprint);
    const grant2 = await w.session('mem:bob').channel.grant(g.space, carol.address);
    if (grant2.status === 'invited') await w.session('mem:carol').channel.acceptGrant(grant2.pointer);
    await w.session('mem:bob').dropBox.put(g.space, await recipientTag(carol.address), encodeTicket(ticket));
    carol.chat.groups.clear();
    expect(await carol.chat.join(g.space)).toBeUndefined(); // her own app refuses a used ticket
    // a modified app sends it anyway: every member rejects the replay
    await rogueExternalJoin(carol, g.space, encodeTicket(ticket));
    const r = await g.sync();
    expect(r.events.find((e) => e.type === 'rejected')).toMatchObject({ reason: expect.stringMatching(/already used/) });
    expect(g.members().map((m) => m.address)).not.toContain(carol.address);
  });

  it('a revoked device is removed and banned, and cannot rejoin', async () => {
    const w = new MemoryWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const alice = await makeUser(w.session('mem:alice'), 'mem:alice');
    const g = await bob.chat.startDm(alice.address);
    await alice.chat.acceptInvites();
    const stolen = await addDevice(alice);
    await alice.writer.revokeDevice(alice.root, stolen.identity.cert.device);
    await bob.registry.lookup(alice.address); // bob's app has the fresh device list
    // The thief still has the GitHub session, so the channel lets it in. Joining is accepted by
    // every member the same way (validity can't depend on caches), then removed and banned.
    const gs = await stolen.chat.join(g.space);
    expect(gs).toBeDefined();
    await g.sync();
    expect(g.members().find((m) => m.address === alice.address)!.devices).toHaveLength(1);
    expect(g.policy.banned.map((b) => b.device)).toEqual([stolen.identity.cert.device]);
    // second attempt: rejected by everyone, deterministically, from the agreed group state
    stolen.chat.groups.clear();
    await stolen.chat.join(g.space);
    const r = await g.sync();
    expect(r.events.find((e) => e.type === 'rejected')).toMatchObject({ reason: expect.stringMatching(/banned/) });
    expect(g.members().find((m) => m.address === alice.address)!.devices).toHaveLength(1);
  });

  it('a non-admin may ban only their own devices', async () => {
    const { g, gc, carol } = await setupGroup();
    const phone = await addDevice(carol);
    await phone.chat.acceptInvites();
    await gc.sync();
    await gc.banDevice(phone.identity.cert.device); // own device: allowed
    await g.sync();
    expect(g.policy.banned).toHaveLength(1);
    await expect(gc.banDevice(g.chat.identity.cert.device)).rejects.toMatchObject({ code: 'policy_rejected' });
  });
});

describe('storage operator', () => {
  it('a rewritten log entry is detected (memory)', async () => {
    const { w, g } = await setupGroup();
    await g.send({ t: 'text', body: 'x' });
    w.rewriteLog(g.space, 1, new TextEncoder().encode('{"v":1}'));
    await expect(g.sync()).rejects.toMatchObject({ code: 'rewrite_detected' });
  });

  it('a force-pushed log on GitHub is detected', async () => {
    const w = githubWorld();
    const bob = await makeUser(w.session('bob'), 'github:bob');
    const alice = await makeUser(w.session('alice'), 'github:alice');
    const g = await bob.chat.startDm(alice.address);
    const [ga] = await alice.chat.acceptInvites();
    await g.sync();
    w.gh.rewrite(g.space, 'log/00000/00000001', new TextEncoder().encode('{"v":1,"i":1}'));
    await expect(ga!.sync()).rejects.toMatchObject({ code: 'rewrite_detected' });
  });

  it('a rewritten directory is detected by anyone who pinned it', async () => {
    const w = new MemoryWorld();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob');
    const alice = await makeUser(w.session('mem:alice'), 'mem:alice');
    await bob.registry.lookup(alice.address);
    const entries = await w.session('mem:x').directory.read(alice.address);
    w.rewriteDirectory(alice.address, 1, entries[0]!);
    await expect(bob.registry.lookup(alice.address)).rejects.toBeTruthy();
  });

  it('GitHub sees only ciphertext: no message, name or contact text in any repo file', async () => {
    const w = githubWorld();
    const bob = await makeUser(w.session('bob'), 'github:bob');
    const alice = await makeUser(w.session('alice'), 'github:alice');
    const g = await bob.chat.createGroup('group', 'Secret Society');
    await g.invite(alice.address);
    const [ga] = await alice.chat.acceptInvites();
    await g.send({ t: 'text', body: 'the password is swordfish' });
    await ga!.send({ t: 'react', ref: 'x', emoji: 'thumbs' });
    await g.sendAttachment(new TextEncoder().encode('attachment plaintext'), { name: 'plans.pdf' });
    expect(texts(await ga!.sync())).toEqual(['the password is swordfish']);
    for (const [name, repo] of w.gh.repos) {
      for (const [path, f] of repo.files) {
        const text = f.content.toString('latin1');
        for (const secret of ['swordfish', 'Secret Society', 'attachment plaintext', 'plans.pdf', 'thumbs']) {
          expect(`${name}/${path}: ${text.includes(secret)}`).toBe(`${name}/${path}: false`);
        }
      }
      expect(repo.description).not.toMatch(/Secret|alice|bob/);
    }
  });
});

describe('forward secrecy', () => {
  it('one-time keys are gone after use; old epochs beyond the retention window are dropped', async () => {
    const w = new MemoryWorld();
    const opts = { build: { offlineAdd: true }, rotation: { maxMessages: 1, maxAgeMs: 1e12 }, retainEpochs: 2 };
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.chat.publishKeyPackages(1);
    const g = await bob.chat.createGroup();
    await g.addOffline(carol.address);
    const [gc] = await carol.chat.acceptInvites();
    expect(await carol.device.ephemeral.keys('chat/kp/')).toEqual([]);
    for (let i = 0; i < 6; i++) {
      await g.send({ t: 'text', body: `m${i}` });
      await gc!.sync();
    }
    expect(gc!.retainedEpochs).toBeLessThanOrEqual(2);
    expect(g.retainedEpochs).toBeLessThanOrEqual(2);
  });
});
