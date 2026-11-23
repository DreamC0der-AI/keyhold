import { describe, it, expect } from 'vitest';
import { MemoryWorld } from '../src/storage/index.js';
import { makeUser, addDevice, texts, type TestUserOptions } from './chat-helpers.js';
import type { Group, GroupEvent } from '../src/chat/index.js';

const DAY = 86_400_000;

function setup() {
  let t = Date.UTC(2026, 10, 20);
  const now = () => t;
  const w = new MemoryWorld({ now, claimOnce: false });
  const opts: TestUserOptions = { build: { preKeys: true }, now };
  return { w, opts, now, advance: (ms: number) => (t += ms) };
}

const pendingOf = (g: Group) => g.members().filter((m) => m.pending).map((m) => m.address);
const types = (events: GroupEvent[]) => events.map((e) => e.type);

describe('pre-keys (build option preKeys)', () => {
  it('an account without a pre-key publishes one; it rotates weekly and keeps the old key a week', async () => {
    const { w, opts, advance } = setup();
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    expect(await w.session('mem:bob').preKeys!.read('mem:carol')).toHaveLength(0);
    expect(await carol.chat.refreshPreKey()).toBe(true);
    expect(await w.session('mem:bob').preKeys!.read('mem:carol')).toHaveLength(1);
    expect(await carol.chat.refreshPreKey()).toBe(false);
    const keys = () => carol.device.ephemeral.keys('chat/pk/');
    expect(await keys()).toHaveLength(1);
    advance(7 * DAY);
    expect(await carol.chat.refreshPreKey()).toBe(true);
    expect(await keys()).toHaveLength(2); // retired one kept
    expect(await w.session('mem:bob').preKeys!.read('mem:carol')).toHaveLength(1); // replaced, not added
    advance(7 * DAY);
    await carol.chat.refreshPreKey();
    expect(await keys()).toHaveLength(2); // first one pruned, second retired, third current
  });

  it('a published pre-key that went missing is published again on the next start', async () => {
    const { w, opts } = setup();
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.chat.refreshPreKey();
    w.preKeys.get('mem:carol')!.clear();
    const again = await addDevice(carol, opts); // a fresh Chat on another device has its own key
    await again.chat.refreshPreKey();
    const restarted = await (await import('../src/chat/index.js')).Chat.open({ ...carol.chat.opts });
    expect(await restarted.refreshPreKey()).toBe(true);
    expect(await w.session('mem:bob').preKeys!.read('mem:carol')).toHaveLength(2);
  });

  it('invite adds every device with a pre-key; the group writes before they accept; they read it all', async () => {
    const { w, opts } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    const phone = await addDevice(carol, opts);
    await carol.chat.refreshPreKey();
    await phone.chat.refreshPreKey();
    const g = await bob.chat.createGroup('group', 'team');
    await g.invite(carol.address);
    expect(g.members()).toHaveLength(2);
    expect(pendingOf(g)).toEqual(['mem:carol']);
    const added = await g.sync();
    expect(types(added.events)).not.toContain('joined');
    await g.send({ t: 'text', body: 'before you joined' });
    await g.send({ t: 'text', body: 'still waiting' });

    const [gc] = await carol.chat.acceptInvites();
    expect(texts(await gc!.sync())).toEqual(['before you joined', 'still waiting']);
    // The joiner replaced its reusable key at once.
    const r = await g.sync();
    expect(types(r.events)).toContain('joined');
    expect(pendingOf(g)).toEqual([]);
    const [gp] = await phone.chat.acceptInvites();
    expect(texts(await gp!.sync())).toEqual(['before you joined', 'still waiting']);
    await gc!.send({ t: 'text', body: 'hi all' });
    expect(texts(await g.sync())).toEqual(['hi all']);
  });

  it('the joiner replaces its pre-key leaf even when other commits came first', async () => {
    const { w, opts } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave', opts);
    await carol.chat.refreshPreKey();
    await dave.chat.refreshPreKey();
    const g = await bob.chat.createGroup('group');
    await g.invite(carol.address);
    await g.invite(dave.address); // a commit after carol's add
    await g.rotate();
    const [gc] = await carol.chat.acceptInvites();
    await gc!.sync();
    const r = await g.sync();
    expect(r.events).toContainEqual({ type: 'joined', fingerprint: carol.identity.fingerprint, address: 'mem:carol' });
    expect(pendingOf(g)).toEqual(['mem:dave']);
  });

  it('a DM with pre-keys: both write at once', async () => {
    const { w, opts } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.chat.refreshPreKey();
    const g = await bob.chat.startDm(carol.address);
    await g.send({ t: 'text', body: 'hey' });
    const [gc] = await carol.chat.acceptInvites();
    expect(texts(await gc!.sync())).toEqual(['hey']);
  });

  it('a device without a pre-key joins by itself when they accept', async () => {
    const { w, opts } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    const phone = await addDevice(carol, opts);
    await carol.chat.refreshPreKey(); // the phone never published one
    const g = await bob.chat.createGroup('group');
    await g.invite(carol.address);
    expect(g.members()[1]!.devices).toHaveLength(1);
    await g.send({ t: 'text', body: 'early' });
    const [gp] = await phone.chat.acceptInvites();
    expect(gp).toBeDefined();
    await gp!.sync();
    await g.sync();
    expect(g.members().find((m) => m.address === 'mem:carol')!.devices).toHaveLength(2);
  });

  it('a pre-key rotated after the invite still opens the Welcome', async () => {
    const { w, opts, advance } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.chat.refreshPreKey();
    const g = await bob.chat.createGroup('group');
    advance(6 * DAY);
    await g.invite(carol.address);
    await g.send({ t: 'text', body: 'made with the old key' });
    advance(DAY);
    expect(await carol.chat.refreshPreKey()).toBe(true); // rotated, old kept
    advance(5 * DAY);
    await carol.chat.refreshPreKey(); // within the keep window: still kept
    const [gc] = await carol.chat.acceptInvites();
    expect(texts(await gc!.sync())).toEqual(['made with the old key']);
  });

  it('if the key is gone anyway, the device joins by itself and replaces its added leaf', async () => {
    const { w, opts } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.chat.refreshPreKey();
    const g = await bob.chat.createGroup('group');
    await g.invite(carol.address);
    for (const k of await carol.device.ephemeral.keys('chat/pk/')) await carol.device.ephemeral.delete(k);
    const [gc] = await carol.chat.acceptInvites();
    expect(gc).toBeDefined();
    await g.sync();
    const c = g.members().find((m) => m.address === 'mem:carol')!;
    expect(c.devices).toHaveLength(1);
    expect(c.pending).toBe(false);
    await g.send({ t: 'text', body: 'now' });
    expect(texts(await gc!.sync())).toEqual(['now']);
  });

  it('an admin removes devices that never joined after 14 days', async () => {
    const { w, opts, advance } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.chat.refreshPreKey();
    const g = await bob.chat.createGroup('group');
    await g.invite(carol.address);
    await g.sync();
    advance(13 * DAY);
    expect(types((await g.sync()).events)).not.toContain('left');
    advance(DAY);
    const r = await g.sync();
    expect(r.events).toContainEqual({ type: 'left', fingerprint: carol.identity.fingerprint, address: 'mem:carol', pending: true });
    expect(g.members()).toHaveLength(1);
  });

  it('when their invitation ends (declined or expired), they are removed', async () => {
    const { w, opts, advance } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.chat.refreshPreKey();
    const g = await bob.chat.createGroup('group');
    await g.invite(carol.address);
    await g.sync();
    await w.session('mem:bob').channel.revoke(g.space, carol.address); // what an expired or declined invite looks like
    advance(11 * 60_000);
    await g.reconcileChannel(true);
    expect(g.members()).toHaveLength(1);
  });

  it('skips expired pre-keys and pre-keys of revoked devices; the ticket still works', async () => {
    const { w, opts, advance } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    const phone = await addDevice(carol, opts);
    await carol.chat.refreshPreKey();
    await phone.chat.refreshPreKey();
    await carol.writer.revokeDevice(carol.root, phone.identity.cert.device);
    const g = await bob.chat.createGroup('group');
    await g.invite(carol.address);
    expect(g.members().find((m) => m.address === 'mem:carol')!.devices).toHaveLength(1);
    expect((await carol.chat.acceptInvites()).map((x) => x.id)).toEqual([g.id]);

    const g2 = await bob.chat.createGroup('group');
    advance(31 * DAY); // carol's laptop was offline: its pre-key is past its lifetime
    await g2.invite(carol.address);
    expect(g2.members()).toHaveLength(1);
    const joined = await carol.chat.acceptInvites();
    expect(joined.map((x) => x.id)).toEqual([g2.id]); // by ticket
  });

  it('an invite note is sealed to the invitee\'s pre-keys: each device opens it, nobody else can', async () => {
    const { w, opts } = setup();
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    const phone = await addDevice(carol, opts);
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave', opts);
    for (const u of [carol, phone, dave]) await u.chat.refreshPreKey();
    const g = await bob.chat.createGroup('group', 'team');
    const note = new TextEncoder().encode('{"kind":"group","name":"team"}');
    await g.invite(carol.address, { note });
    const [n] = await w.session('mem:carol').inviteInbox.list();
    expect(n!.payload).toBeDefined();
    expect(new TextDecoder().decode(n!.payload!)).not.toContain('team'); // sealed
    expect(await carol.chat.openInviteNote(n!)).toEqual(note);
    expect(await phone.chat.openInviteNote(n!)).toEqual(note);
    expect(await dave.chat.openInviteNote(n!)).toBeUndefined();
    // Bound to the inviter: the same note under another sender doesn't open.
    expect(await carol.chat.openInviteNote({ ...n!, from: 'mem:dave' })).toBeUndefined();
    // No pre-key, no note; the invite still works.
    const erin = await makeUser(w.session('mem:erin'), 'mem:erin', opts);
    await g.invite(erin.address, { note });
    const [e] = await w.session('mem:erin').inviteInbox.list();
    expect(e!.payload).toBeUndefined();
  });
});
