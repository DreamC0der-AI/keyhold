import { describe, expect, it } from 'vitest';
import { MemoryWorld, type StorageProvider } from '../src/storage/index.js';
import { safetyNumber, PersonalData, backupRootKey, restoreRootKey, createRootKey, DirectoryWriter, IdentityRegistry, MemoryPinStore } from '../src/chat/index.js';
import { makeUser, addDevice, githubWorld, texts, type TestUserOptions } from './chat-helpers.js';

type World = { name: string; session(u: string): StorageProvider; addr(u: string): string; raw: unknown };
const worlds: [string, () => World][] = [
  ['memory', () => {
    const w = new MemoryWorld({ ownerManagedSpaces: true });
    return { name: 'memory', session: (u) => w.session(`mem:${u}`), addr: (u) => `mem:${u}`, raw: w };
  }],
  ['github (mock)', () => {
    const w = githubWorld();
    return { name: 'github', session: (u) => w.session(u), addr: (u) => `github:${u}`, raw: w };
  }],
];

const user = (w: World, name: string, o?: TestUserOptions) => makeUser(w.session(name), w.addr(name), o);

describe.each(worlds)('chat on %s', (_n, make) => {
  it('DM: invite, accept, external join, talk both ways', async () => {
    const w = make();
    const bob = await user(w, 'bob');
    const alice = await user(w, 'alice');
    const g = await bob.chat.startDm(alice.address);
    const [ga] = await alice.chat.acceptInvites();
    expect(ga).toBeDefined();
    await g.send({ t: 'text', body: 'hi alice' });
    expect(texts(await ga!.sync())).toEqual(['hi alice']);
    await ga!.send({ t: 'text', body: 'hi bob' });
    const r = await g.sync();
    expect(texts(r)).toEqual(['hi bob']);
    expect(r.messages[0]!.from.fingerprint).toBe(alice.identity.fingerprint);
    expect(g.members().map((m) => m.address).sort()).toEqual([alice.address, bob.address].sort());
    expect(g.policy.kind).toBe('dm');
  });

  it('DM refuses a third person', async () => {
    const w = make();
    const bob = await user(w, 'bob');
    const alice = await user(w, 'alice');
    await user(w, 'carol');
    const g = await bob.chat.startDm(alice.address);
    await alice.chat.acceptInvites();
    await expect(g.invite(w.addr('carol'))).rejects.toMatchObject({ code: 'policy_rejected' });
  });

  it('group: create, invite several, talk, name, members and admins', async () => {
    const w = make();
    const [bob, carol, dave] = [await user(w, 'bob'), await user(w, 'carol'), await user(w, 'dave')];
    const g = await bob.chat.createGroup('group', 'Hiking club');
    await g.invite(carol.address);
    await g.invite(dave.address);
    const [gc] = await carol.chat.acceptInvites();
    const [gd] = await dave.chat.acceptInvites();
    await g.send({ t: 'text', body: 'welcome both' });
    await gc!.sync();
    expect(texts(await gc!.sync())).toEqual([]); // nothing new the second time
    expect(texts(await gd!.sync())).toEqual(['welcome both']);
    await gc!.send({ t: 'text', body: 'thanks' });
    expect(texts(await gd!.sync())).toEqual(['thanks']);
    expect(texts(await g.sync())).toEqual(['thanks']);
    expect(g.members()).toHaveLength(3);
    expect(g.members().find((m) => m.admin)!.address).toBe(bob.address);
    await g.send({ t: 'meta', name: 'Hiking club 2026' });
    await gd!.sync();
    expect(gd!.name).toBe('Hiking club 2026');
    // a non-admin can't rename
    await gc!.send({ t: 'meta', name: 'hijacked' });
    await gd!.sync();
    expect(gd!.name).toBe('Hiking club 2026');
  });

  it('remove: MLS first, then channel access; the removed member reads nothing new', async () => {
    const w = make();
    const [bob, carol, dave] = [await user(w, 'bob'), await user(w, 'carol'), await user(w, 'dave')];
    const g = await bob.chat.createGroup();
    await g.invite(carol.address);
    await g.invite(dave.address);
    const [gc] = await carol.chat.acceptInvites();
    const [gd] = await dave.chat.acceptInvites();
    await g.remove(carol.identity.fingerprint);
    const rc = await gc!.sync();
    // The owner revokes channel access right after the MLS removal, so carol usually sees the
    // lost access first. Either way she is out.
    expect(rc.events.some((e) => e.type === 'removed' || e.type === 'access-lost')).toBe(true);
    expect(gc!.active).toBe(false);
    await expect(gc!.send({ t: 'text', body: 'still here?' })).rejects.toMatchObject({ code: 'not_member' });
    await g.send({ t: 'text', body: 'carol is gone' });
    expect(texts(await gd!.sync())).toEqual(['carol is gone']);
    // channel access was taken away by the space owner
    expect((await bob.provider.channel.members(g.space)).active).not.toContain(carol.address);
    await expect(carol.provider.mailbox.list(g.space)).rejects.toBeTruthy();
  });

  it('leave: self-remove proposal, committed by another member; last admin hands over', async () => {
    const w = make();
    const [bob, carol] = [await user(w, 'bob'), await user(w, 'carol')];
    const g = await bob.chat.createGroup();
    await g.invite(carol.address);
    const [gc] = await carol.chat.acceptInvites();
    await g.sync();
    await g.leave();
    expect(bob.chat.groups.size).toBe(0);
    const r = await gc!.sync();
    expect(r.events.some((e) => e.type === 'left')).toBe(true);
    expect(gc!.members().map((m) => m.address)).toEqual([carol.address]);
    expect(gc!.policy.admins).toEqual([carol.identity.fingerprint]);
  });

  it('rotation: a new epoch every N messages and every T days', async () => {
    const w = make();
    let t = Date.now();
    const now = () => t;
    const bob = await user(w, 'bob', { rotation: { maxMessages: 3, maxAgeMs: 7 * 86_400_000 }, now });
    const alice = await user(w, 'alice', { now });
    const g = await bob.chat.startDm(alice.address);
    const [ga] = await alice.chat.acceptInvites();
    await g.sync();
    const e0 = g.epoch;
    for (let i = 0; i < 4; i++) await g.send({ t: 'text', body: `m${i}` });
    expect(g.epoch).toBe(e0 + 1n);
    expect(texts(await ga!.sync())).toEqual(['m0', 'm1', 'm2', 'm3']);
    t += 8 * 86_400_000;
    await ga!.sync(); // alice's rotation timer is also due: she rotates
    await g.send({ t: 'text', body: 'later' });
    expect(g.epoch).toBeGreaterThanOrEqual(e0 + 2n);
    expect(texts(await ga!.sync())).toEqual(['later']);
    expect(g.retainedEpochs).toBeLessThanOrEqual(4);
  });

  it('devices: a second device self-joins; a revoked device is removed by others', async () => {
    const w = make();
    const bob = await user(w, 'bob');
    const alice = await user(w, 'alice');
    const g = await bob.chat.startDm(alice.address);
    await alice.chat.acceptInvites();
    const phone = await addDevice(alice);
    const [gp] = await phone.chat.acceptInvites(); // same account sees the space; joins as another device, no ticket
    expect(gp).toBeDefined();
    await g.send({ t: 'text', body: 'to both devices' });
    expect(texts(await gp!.sync())).toEqual(['to both devices']);
    const ga = [...alice.chat.groups.values()][0]!;
    expect(texts(await ga.sync())).toEqual(['to both devices']);
    expect(g.members().find((m) => m.address === alice.address)!.devices).toHaveLength(2);
    // phone lost: revoke it in the directory; bob's app notices and removes it
    await alice.writer.revokeDevice(alice.root, phone.identity.cert.device);
    (bob.chat.opts as { directoryMaxAgeMs: number }).directoryMaxAgeMs = 0;
    await g.sync();
    expect(g.members().find((m) => m.address === alice.address)!.devices).toHaveLength(1);
    expect((await gp!.sync()).events).toContainEqual({ type: 'removed' });
  });

  it('attachments: sealed with their own key, integrity checked', async () => {
    const w = make();
    const bob = await user(w, 'bob');
    const alice = await user(w, 'alice');
    const g = await bob.chat.startDm(alice.address);
    const [ga] = await alice.chat.acceptInvites();
    const file = new Uint8Array(1_500_000).map((_, i) => (i * 7) % 256);
    await g.sendAttachment(file, { name: 'photo.jpg', mime: 'image/jpeg' });
    const r = await ga!.sync();
    const m = r.messages[0]!.message;
    expect(m.t).toBe('attachment');
    if (m.t !== 'attachment') return;
    const got = await ga!.fetchAttachment(m.file);
    expect(Buffer.from(got).equals(Buffer.from(file))).toBe(true);
    await expect(ga!.fetchAttachment({ ...m.file, hash: m.file.hash.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')) })).rejects.toMatchObject({ code: 'decrypt_failed' });
  });

  it('safety numbers match on both sides; a new root key is flagged, not trusted', async () => {
    const w = make();
    const bob = await user(w, 'bob');
    const alice = await user(w, 'alice');
    expect(await safetyNumber(bob.identity.fingerprint, alice.identity.fingerprint)).toBe(await safetyNumber(alice.identity.fingerprint, bob.identity.fingerprint));
    expect((await safetyNumber(bob.identity.fingerprint, alice.identity.fingerprint)).split(' ')).toHaveLength(12);
    const first = await bob.registry.lookup(alice.address);
    expect(first.status === 'ok' && first.firstSeen).toBe(true);
    // Alice "loses" her root key and starts over under the same address. The directory can't be
    // re-initialised in place, so model the attack/loss with a fresh registry view of a new account.
    const fresh = await user(w, 'alice2');
    const pins = new MemoryPinStore();
    await pins.set(fresh.address, { fingerprint: alice.identity.fingerprint, index: 0, hash: 'x' });
    const reg = new IdentityRegistry(bob.provider.directory, pins);
    const look = await reg.lookup(fresh.address);
    expect(look.status).toBe('key-changed');
  });
});

describe('build option: offline add (box 4)', () => {
  it('adds an offline person with a one-time KeyPackage, which is then deleted', async () => {
    const w = new MemoryWorld();
    const opts = { build: { offlineAdd: true } };
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.chat.publishKeyPackages(3);
    const before = (await carol.device.ephemeral.keys('chat/kp/')).length;
    expect(before).toBe(3);
    const g = await bob.chat.createGroup('group');
    await g.addOffline(carol.address); // carol is offline
    await g.send({ t: 'text', body: 'waiting for you' });
    const [gc] = await carol.chat.acceptInvites();
    expect(gc).toBeDefined();
    expect(texts(await gc!.sync())).toEqual(['waiting for you']);
    expect((await carol.device.ephemeral.keys('chat/kp/')).length).toBe(2);
    expect(await w.session('mem:carol').claimOnce!.remaining()).toBe(2);
  });

  it('is unavailable when the provider lacks claim-once (GitHub)', async () => {
    const w = githubWorld();
    const bob = await makeUser(w.session('bob'), 'github:bob', { build: { offlineAdd: true } });
    expect(bob.features.offlineAdd).toBe(false);
    await expect(bob.chat.publishKeyPackages(1)).rejects.toMatchObject({ code: 'unsupported' });
    const g = await bob.chat.createGroup();
    await makeUser(w.session('carol'), 'github:carol');
    await expect(g.addOffline('github:carol')).rejects.toMatchObject({ code: 'unsupported' });
  });

  it('last-resort KeyPackage from the directory when the claim-once store is empty', async () => {
    const w = new MemoryWorld();
    const opts = { build: { offlineAdd: true, lastResortKeyPackages: true } };
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.writer.setLastResortKeyPackage(carol.root, await carol.chat.lastResortKeyPackage());
    const g = await bob.chat.createGroup();
    await g.addOffline(carol.address);
    const [gc] = await carol.chat.acceptInvites();
    expect(gc).toBeDefined();
    expect((await carol.device.ephemeral.keys('chat/kplr/')).length).toBe(1); // reusable: kept
  });
});

describe('owner-managed channels (GitHub): other admins ask the owner app', () => {
  it('a non-owner admin invites; the owner app grants access', async () => {
    const w = githubWorld();
    const bob = await makeUser(w.session('bob'), 'github:bob');
    const carol = await makeUser(w.session('carol'), 'github:carol');
    const dave = await makeUser(w.session('dave'), 'github:dave');
    const g = await bob.chat.createGroup();
    await g.invite(carol.address);
    const [gc] = await carol.chat.acceptInvites();
    await g.sync();
    await g.setPolicy({ ...g.policy, admins: [bob.identity.fingerprint, carol.identity.fingerprint] });
    await gc!.sync();
    await gc!.invite(dave.address); // carol isn't the repo owner: posts a sys.grant request
    expect(await dave.chat.acceptInvites()).toEqual([]); // nothing yet
    await g.sync(); // bob's app sees carol (an admin) asked, and grants channel access
    const [gd] = await dave.chat.acceptInvites();
    expect(gd).toBeDefined();
    await gd!.send({ t: 'text', body: 'hello from dave' });
    expect(texts(await gc!.sync())).toEqual(['hello from dave']);
  });
});

describe('personal synced store (box 12) and root backup (box 9)', () => {
  async function k() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  it.each(worlds)('merges edits from two devices per field, ids and contents are opaque (%s)', async (_n, make) => {
    const w = make();
    const p = w.session('alice');
    const K = await k();
    const laptop = await PersonalData.open(p.personal, K, 'laptop');
    const phone = await PersonalData.open(p.personal, K, 'phone');
    await laptop.setContact('github:bob', { nickname: 'Bobby' });
    await phone.setContact('github:bob', { verified: true });
    await laptop.flush();
    await phone.flush();
    expect(await laptop.contact('github:bob')).toEqual({ nickname: 'Bobby', verified: true });
    // read marks: many changes, one write per flush
    for (let i = 0; i < 50; i++) await phone.setReadMark('group-quokka', `mark-${i}`);
    expect(await phone.flush()).toBe(1);
    expect(await laptop.get('readMarks', 'group-quokka')).toEqual({ at: 'mark-49' });
    // storage sees only opaque ids and ciphertext (markers long enough not to appear in random base64)
    const ids = (await p.personal.list()).map((i) => i.id);
    expect(ids.join(',')).not.toMatch(/github:bob|contacts|readMarks|quokka/);
    for (const id of ids) {
      const raw = Buffer.from((await p.personal.get(id))!.data).toString('latin1');
      expect(raw).not.toMatch(/Bobby|github:bob|quokka|mark-49/);
    }
    // a key without K can't read
    const other = await k();
    await expect(PersonalData.open(p.personal, other, 'x')).rejects.toMatchObject({ code: 'decrypt_failed' });
  });

  it('history backup restores on a new device', async () => {
    const w = new MemoryWorld();
    const K = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const p = w.session('mem:alice');
    const laptop = await PersonalData.open(p.personal, K, 'laptop');
    await laptop.backupHistory('g1', [{ id: 'a', from: 'x', ts: 1, body: 'one' }]);
    await laptop.backupHistory('g1', [{ id: 'b', from: 'x', ts: 2, body: 'two' }]);
    await laptop.flush();
    const newPhone = await PersonalData.open(p.personal, K, 'phone');
    expect((await newPhone.readHistory('g1')).map((r) => r.body)).toEqual(['one', 'two']);
  });

  it.each(worlds)('root key backup in the vault, sealed with K (%s)', async (_n, make) => {
    const w = make();
    const p = w.session('alice');
    const K = await k();
    const root = createRootKey();
    await backupRootKey(p.vault, K, 'acc1', root);
    const back = (await restoreRootKey(p.vault, K, 'acc1'))!;
    expect(Buffer.from(back.publicKey).equals(Buffer.from(root.publicKey))).toBe(true);
    await expect(restoreRootKey(p.vault, K, 'other-account')).rejects.toMatchObject({ code: 'decrypt_failed' });
    // the restored root can certify a new device in the directory
    const writer = new DirectoryWriter(p.directory, w.addr('alice'));
    const { issueDeviceCertificate } = await import('../src/chat/index.js');
    await writer.publish(back, issueDeviceCertificate(back, new Uint8Array(32).fill(1), 'd1', w.addr('alice')));
    const reg = new IdentityRegistry(p.directory);
    const look = await reg.lookup(w.addr('alice'));
    expect(look.status === 'ok' && look.view.devices.size).toBe(1);
  });
});
