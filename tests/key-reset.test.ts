// A person resets their key (lost recovery code): same address, new root key and directory.
import { describe, expect, it } from 'vitest';
import { MemoryWorld } from '../src/storage/index.js';
import { spacesRunByLostKeys, type Chat, type GroupEvent } from '../src/chat/index.js';
import { makeUser, texts, type TestUser } from './chat-helpers.js';

/** Their old key is gone: the directory and pre-keys start over with a new root. */
async function reset(w: MemoryWorld, u: TestUser) {
  w.directories.delete(u.address);
  w.preKeys.delete(u.address);
  return makeUser(w.session(u.address), u.address);
}

/** Read directories on every sync, as if the hour had passed. */
const fresh = (c: Chat) => ((c.opts as { directoryMaxAgeMs: number }).directoryMaxAgeMs = 0);
const of = <T extends GroupEvent['type']>(events: GroupEvent[], type: T) => events.filter((e) => e.type === type) as Extract<GroupEvent, { type: T }>[];

describe('key reset', () => {
  it('an admin removes the old key by itself; inviting the new key brings them back', async () => {
    const w = new MemoryWorld({ ownerManagedSpaces: true });
    const [bob, carol, dave] = [await makeUser(w.session('mem:bob'), 'mem:bob'), await makeUser(w.session('mem:carol'), 'mem:carol'), await makeUser(w.session('mem:dave'), 'mem:dave')];
    const g = await bob.chat.createGroup('group', 'Club');
    await g.inviteMany([carol.address, dave.address]);
    const [gc] = await carol.chat.acceptInvites();
    await dave.chat.acceptInvites();
    await g.sync();
    await gc!.sync();
    const oldDave = dave.identity.fingerprint;

    const dave2 = await reset(w, dave);
    fresh(bob.chat);
    fresh(carol.chat);
    const rb = await g.sync();
    expect(of(rb.events, 'key-reset')).toEqual([{ type: 'key-reset', fingerprint: oldDave, address: dave.address }]);
    expect(of(rb.events, 'left')).toMatchObject([{ address: dave.address, by: { address: bob.address } }]);
    expect(g.members().map((m) => m.address).sort()).toEqual([bob.address, carol.address].sort());
    expect(g.active).toBe(true);
    // The repo access goes with it (the owner's app reconciles).
    expect((await bob.provider.channel.members(g.space)).active).not.toContain(dave.address);
    // carol reads bob's removal before her own directory check: she sees dave removed by bob,
    // and his directory tells why.
    const rc = await gc!.sync();
    expect(of(rc.events, 'left')).toMatchObject([{ address: dave.address, by: { address: bob.address } }]);
    await carol.registry.lookup(dave.address);
    expect(carol.registry.isResetRoot(oldDave, dave.address)).toBe(true);
    // Reported once.
    expect(of((await g.sync()).events, 'key-reset')).toEqual([]);

    // Inviting the new key needs a person to accept it first.
    await expect(g.invite(dave.address)).rejects.toMatchObject({ code: 'key_changed' });
    const look = await bob.registry.lookup(dave.address);
    expect(look.status).toBe('key-changed');
    if (look.status !== 'key-changed') return;
    await bob.registry.acceptKeyChange(dave.address, look.view);
    await g.invite(dave.address);
    const [gd2] = await dave2.chat.acceptInvites();
    expect(gd2).toBeDefined();
    await g.send({ t: 'text', body: 'welcome back' });
    expect(texts(await gd2!.sync())).toEqual(['welcome back']);
    expect(g.members().find((m) => m.address === dave.address)!.fingerprint).toBe(dave2.identity.fingerprint);
  });

  it('inviting the new key before the cleanup ran takes the old key out first (a DM keeps its two seats)', async () => {
    const w = new MemoryWorld({ ownerManagedSpaces: true });
    const [bob, alice] = [await makeUser(w.session('mem:bob'), 'mem:bob'), await makeUser(w.session('mem:alice'), 'mem:alice')];
    const g = await bob.chat.startDm(alice.address);
    await alice.chat.acceptInvites();
    await g.sync();
    const alice2 = await reset(w, alice);
    const look = await bob.registry.lookup(alice.address);
    if (look.status !== 'key-changed') throw new Error('expected a key change');
    await bob.registry.acceptKeyChange(alice.address, look.view);
    const old = alice.identity.fingerprint;
    await g.invite(alice.address);
    expect(g.members().map((m) => m.fingerprint)).not.toContain(old);
    const [ga2] = await alice2.chat.acceptInvites();
    await ga2!.send({ t: 'text', body: 'new key here' });
    expect(texts(await g.sync())).toEqual(['new key here']);
    expect(g.members().map((m) => m.fingerprint).sort()).toEqual([bob.identity.fingerprint, alice2.identity.fingerprint].sort());
  });

  it('when the only admin resets, every member ends the group by itself, and the new key finds it to delete', async () => {
    const w = new MemoryWorld({ ownerManagedSpaces: true });
    const [bob, carol, dave] = [await makeUser(w.session('mem:bob'), 'mem:bob'), await makeUser(w.session('mem:carol'), 'mem:carol'), await makeUser(w.session('mem:dave'), 'mem:dave')];
    const g = await bob.chat.createGroup('group', 'Club');
    await g.inviteMany([carol.address, dave.address]);
    const [gc] = await carol.chat.acceptInvites();
    const [gd] = await dave.chat.acceptInvites();
    await g.sync();
    await gc!.sync();
    await gd!.sync();
    // A group bob is in but doesn't run: not his to delete.
    const other = await carol.chat.createGroup('group', 'Carol’s');
    await other.invite(bob.address);
    await bob.chat.acceptInvites();

    const bob2 = await reset(w, bob);
    fresh(carol.chat);
    fresh(dave.chat);
    for (const x of [gc!, gd!]) {
      const r = await x.sync();
      expect(of(r.events, 'admins-reset')).toEqual([{ type: 'admins-reset', admins: [bob.address] }]);
      expect(x.active).toBe(false);
      expect(x.endedByReset).toBe(true);
      await expect(x.send({ t: 'text', body: 'anyone?' })).rejects.toMatchObject({ code: 'not_member' });
    }
    // Nothing more happens there, even if something shows up (bob's old device still writes).
    await g.send({ t: 'text', body: 'from the old key' });
    expect(texts(await gc!.sync())).toEqual([]);
    expect((await gc!.sync()).events).toEqual([]);
    // In carol's own group, carol (the admin) takes bob's old key out instead.
    const ro = await other.sync();
    expect(of(ro.events, 'left')).toMatchObject([{ address: bob.address }]);
    expect(other.active).toBe(true);

    expect(await spacesRunByLostKeys(bob2.provider, bob.address, bob2.identity.fingerprint)).toEqual([g.space]);
    // Before the reset, the same check finds nothing to delete.
    expect(await spacesRunByLostKeys(bob.provider, bob.address, bob.identity.fingerprint)).toEqual([]);
  });

  it('with a second admin left, the group goes on', async () => {
    const w = new MemoryWorld({ ownerManagedSpaces: true });
    const [bob, carol] = [await makeUser(w.session('mem:bob'), 'mem:bob'), await makeUser(w.session('mem:carol'), 'mem:carol')];
    const g = await bob.chat.createGroup('group');
    await g.invite(carol.address);
    const [gc] = await carol.chat.acceptInvites();
    await g.setPolicy({ ...g.policy, admins: [bob.identity.fingerprint, carol.identity.fingerprint] });
    await gc!.sync();
    await reset(w, bob);
    fresh(carol.chat);
    const r = await gc!.sync();
    expect(of(r.events, 'admins-reset')).toEqual([]);
    expect(of(r.events, 'left')).toMatchObject([{ address: bob.address, by: { address: carol.address } }]);
    expect(gc!.active).toBe(true);
  });

  it('a device of a key reset elsewhere stops changing the group', async () => {
    const w = new MemoryWorld({ ownerManagedSpaces: true });
    const [bob, carol] = [await makeUser(w.session('mem:bob'), 'mem:bob'), await makeUser(w.session('mem:carol'), 'mem:carol')];
    const g = await bob.chat.createGroup('group');
    await g.invite(carol.address);
    await carol.chat.acceptInvites();
    await g.sync();
    await reset(w, carol);
    fresh(bob.chat);
    // bob's old device, still running after bob reset on another device: it removes nobody.
    await reset(w, bob);
    const before = g.members().length;
    await g.sync();
    expect(g.members().length).toBe(before);
  });
});
