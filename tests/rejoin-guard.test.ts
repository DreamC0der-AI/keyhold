/**
 * Rejoining after a fork takes a GroupInfo from the log. Anyone who can write the log can put
 * one there, so only one that could have come from the group we know is followed.
 */
import { describe, expect, it } from 'vitest';
import * as mls from 'ts-mls';
import { MemoryWorld } from '../src/storage/index.js';
import { ciphersuite, encodePolicy, POLICY_EXTENSION, type Group } from '../src/chat/index.js';
import { b64, jsonBytes, unb64 } from '../src/util/codec.js';
import { sha256 } from '../src/util/bytes.js';
import { makeUser, texts } from './chat-helpers.js';

const I = (g: Group) => g as unknown as { state: mls.ClientState; meta: { needsHeal: boolean } };

async function lastEntry(g: Group) {
  const raw = await g.chat.provider.orderedLog.read(g.space, 0);
  return { raw, last: JSON.parse(new TextDecoder().decode(raw[raw.length - 1]!)), prev: b64(await sha256(raw[raw.length - 1]!)) };
}

/** A commit entry nobody can process (a copied message claiming the next epoch), carrying `gi`. */
async function trigger(g: Group, gi: string) {
  const { raw, prev } = await lastEntry(g);
  const mail = await g.chat.provider.mailbox.list(g.space);
  const m = mls.decodeMlsMessage(mail.items[mail.items.length - 1]!.data, 0)![0];
  if (m.wireformat !== 'mls_private_message') throw new Error('not a private message');
  m.privateMessage.epoch += 1n;
  const entry = { v: 1, i: raw.length, prev, kind: 'commit', epoch: '999', mls: b64(mls.encodeMlsMessage(m)), gi };
  return { index: raw.length, bytes: jsonBytes(entry) };
}

async function three(names: [string, string, string]) {
  const w = new MemoryWorld({ claimOnce: false });
  const [a, b, c] = await Promise.all(names.map((n) => makeUser(w.session(`mem:${n}`), `mem:${n}`)));
  const g = await a!.chat.createGroup();
  await g.invite(b!.address);
  await g.invite(c!.address);
  const [gb] = await b!.chat.acceptInvites();
  const [gc] = await c!.chat.acceptInvites();
  for (const x of [g, gb!, gc!]) await x.sync();
  return { w, a: a!, b: b!, c: c!, g, gb: gb!, gc: gc! };
}

describe('rejoin only from a GroupInfo that could be the group', () => {
  it('an old GroupInfo written again (by the operator) does not bring a removed member back', async () => {
    const { a: bob, b: carol, c: eve, g, gb: gc, gc: ge } = await three(['bob', 'carol', 'eve']);
    const eveOld = I(ge).state;
    const oldGi = (await lastEntry(g)).last.gi as string;
    await g.remove(eve.identity.fingerprint);
    await gc.sync();
    await g.send({ t: 'text', body: 'after removal' });
    const t = await trigger(g, oldGi);
    expect(await carol.provider.orderedLog.append(g.space, t.index, t.bytes)).toBe('ok');
    const r = await gc.sync();
    expect(r.events).toEqual(expect.arrayContaining([expect.objectContaining({ type: 'rejected', reason: expect.stringContaining('could not rejoin') })]));
    expect(gc.members().map((m) => m.address)).not.toContain(eve.address);
    // The group goes on, and eve's saved state opens nothing new.
    await gc.send({ t: 'text', body: 'secret for the group' });
    expect(texts(await g.sync())).toContain('secret for the group');
    const cs = await ciphersuite();
    for (const it of (await bob.provider.mailbox.list(g.space)).items) {
      const res = await mls.processMessage(mls.decodeMlsMessage(it.data, 0)![0] as never, eveOld, mls.emptyPskIndex, () => 'accept', cs).catch(() => undefined);
      if (res?.kind === 'applicationMessage') expect(new TextDecoder().decode(res.message)).not.toContain('secret for the group');
    }
  });

  it('a member cannot make itself admin with a GroupInfo of its own', async () => {
    const { a: bob, c: dave, g, gb: gc, gc: gd } = await three(['bob', 'carol', 'dave']);
    await g.send({ t: 'text', body: 'hi' });
    const cs = await ciphersuite();
    const ds = I(gd).state;
    const exts = ds.groupContext.extensions.filter((e) => (e.extensionType as unknown) !== POLICY_EXTENSION);
    const forged = { ...ds, groupContext: { ...ds.groupContext, epoch: ds.groupContext.epoch + 1n, extensions: [...exts, encodePolicy({ ...gd.policy, admins: [dave.identity.fingerprint] }) as never] } };
    const gi = await mls.createGroupInfoWithExternalPubAndRatchetTree(forged as mls.ClientState, [], cs);
    const t = await trigger(g, b64(mls.encodeMlsMessage({ wireformat: 'mls_group_info', version: 'mls10', groupInfo: gi })));
    expect(await dave.provider.orderedLog.append(g.space, t.index, t.bytes)).toBe('ok');
    for (let r = 0; r < 3; r++) for (const x of [g, gc]) await x.sync();
    expect(g.policy.admins).toEqual([bob.identity.fingerprint]);
    expect(gc.policy.admins).toEqual([bob.identity.fingerprint]);
    await gc.send({ t: 'text', body: 'still one group' });
    expect(texts(await g.sync())).toContain('still one group');
  });

  it('a member cannot leave others out with a GroupInfo of its own', async () => {
    const { a: bob, c: dave, g, gb: gc, gc: gd } = await three(['bob', 'carol', 'dave']);
    await g.send({ t: 'text', body: 'hi' });
    const cs = await ciphersuite();
    // dave's own commit removing bob, never posted: its GroupInfo is a valid one without bob.
    const bobLeaf = gd.members().find((m) => m.fingerprint === bob.identity.fingerprint)!.devices[0]!.leafIndex;
    const res = await mls.createCommit({ state: I(gd).state, cipherSuite: cs }, { extraProposals: [{ proposalType: 'remove', remove: { removed: bobLeaf } }], ratchetTreeExtension: true });
    const gi = await mls.createGroupInfoWithExternalPubAndRatchetTree(res.newState, [], cs);
    const t = await trigger(g, b64(mls.encodeMlsMessage({ wireformat: 'mls_group_info', version: 'mls10', groupInfo: gi })));
    expect(await dave.provider.orderedLog.append(g.space, t.index, t.bytes)).toBe('ok');
    for (let r = 0; r < 3; r++) for (const x of [g, gc]) await x.sync();
    expect(gc.members().map((m) => m.address)).toContain(bob.address);
    await g.send({ t: 'text', body: 'bob is still here' });
    expect(texts(await gc.sync())).toContain('bob is still here');
  });

  it('a refused rejoin keeps a heal that was due', async () => {
    const { g, gb: gc } = await three(['bob', 'carol', 'dave']);
    I(gc).meta.needsHeal = true;
    await g.send({ t: 'text', body: 'hi' });
    const t = await trigger(g, (await lastEntry(g)).last.gi as string); // not newer: refused
    expect(await g.chat.provider.orderedLog.append(g.space, t.index, t.bytes)).toBe('ok');
    const before = (await lastEntry(g)).raw.length;
    await gc.sync();
    expect((await lastEntry(g)).raw.length).toBeGreaterThan(before); // carol's heal commit went out
    void unb64;
  });
});
