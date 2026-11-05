import { describe, expect, it } from 'vitest';
import {
  DATA_TYPES,
  STORAGE_KINDS,
  classify,
  kindOf,
  mayBackUp,
  resolveFeatures,
  NOT_STORED,
  MemoryWorld,
  type StorageProvider,
} from '../src/storage/index.js';
import { githubWorld } from './chat-helpers.js';

// The agreed mapping from the design (group-encryption-design.md, sections 4 and 6).
const EXPECTED: Record<string, number | typeof NOT_STORED> = {
  'root-private-key': 1,
  'device-private-key': 1,
  'decrypted-cache': 1,
  outbox: 1,
  'keypackage-init-private': 2,
  'epoch-secrets': 2,
  'identity-public': 3,
  'device-list': 3,
  'last-resort-keypackage': 3,
  'public-profile': 3,
  'one-time-keypackage': 4,
  commit: 5,
  'group-info': 5,
  'group-policy': 5,
  'app-message': 6,
  attachment: 7,
  welcome: 8,
  'signed-invite': 8,
  'root-key-backup': 9,
  'safety-number': 10,
  'invite-notice': 11,
  contacts: 12,
  'chat-list': 12,
  'read-marks': 12,
  'block-list': 12,
  settings: 12,
  drafts: 12,
  'history-backup': 12,
  'device-approval-relay': 12,
  'typing-presence': NOT_STORED,
};

describe('data types are defined by requirements; kinds are derived', () => {
  it('every data type lands in the agreed storage kind', () => {
    const got = Object.fromEntries(DATA_TYPES.map((d) => [d.id, kindOf(d.id)]));
    expect(got).toEqual(EXPECTED);
  });

  it('all 12 kinds are used, and only kinds 4 and 11 need a server', () => {
    const used = new Set(DATA_TYPES.map((d) => kindOf(d.id)));
    for (const id of Object.keys(STORAGE_KINDS)) expect(used.has(Number(id) as never)).toBe(true);
    expect(Object.values(STORAGE_KINDS).filter((k) => k.needsServer).map((k) => k.id)).toEqual([4, 11]);
    expect(Object.values(STORAGE_KINDS).filter((k) => k.optional).map((k) => k.id)).toEqual([4]);
  });

  it('access rules are exact: a public reader never gets a members-only kind', () => {
    expect(() => classify({ read: 'anyone', write: 'members', lifespan: 'chat-history', needs: [] })).toThrow(/no storage kind/);
    expect(classify({ read: 'members', write: 'members', lifespan: 'chat-history', needs: [] })).toBe(6);
    expect(classify({ read: 'members', write: 'members', lifespan: 'live', needs: [] })).toBe(NOT_STORED);
  });

  it('backups never hold keys that need reliable deletion', () => {
    expect(mayBackUp('epoch-secrets')).toBe(false);
    expect(mayBackUp('keypackage-init-private')).toBe(false);
    expect(mayBackUp('root-key-backup')).toBe(true);
    expect(mayBackUp('history-backup')).toBe(true);
  });

  it('features follow build options and provider capabilities', () => {
    const mem = new MemoryWorld().session('a');
    const noClaim = new MemoryWorld({ claimOnce: false }).session('a');
    const gh = githubWorld().session('a');
    expect(resolveFeatures(mem, { offlineAdd: true }).offlineAdd).toBe(true);
    expect(resolveFeatures(mem, {}).offlineAdd).toBe(false);
    expect(resolveFeatures(noClaim, { offlineAdd: true }).offlineAdd).toBe(false);
    expect(resolveFeatures(gh, { offlineAdd: true }).offlineAdd).toBe(false);
    expect(() => resolveFeatures(gh, { offlineAdd: true }, true)).toThrow(/claim-once/);
    expect(resolveFeatures(gh).ownerManagedSpaces).toBe(true);
    expect(resolveFeatures(gh).historyBackup).toBe(true);
  });
});

// ---- Conformance: the same contract on every provider ----------------------------------------

type Factory = () => { session(user: string): StorageProvider; addr(user: string): string };
const providers: [string, Factory][] = [
  ['memory', () => {
    const w = new MemoryWorld({ ownerManagedSpaces: true });
    return { session: (u) => w.session(`mem:${u}`), addr: (u) => `mem:${u}` };
  }],
  ['github (mock)', () => {
    const w = githubWorld();
    return { session: (u) => w.session(u), addr: (u) => `github:${u}` };
  }],
];
const bytes = (s: string) => new TextEncoder().encode(s);
const str = (b?: Uint8Array) => (b ? new TextDecoder().decode(b) : undefined);

describe.each(providers)('storage conformance: %s', (_name, make) => {
  it('directory (3): owner appends at the next index only; anyone reads', async () => {
    const w = make();
    const a = w.session('alice');
    const b = w.session('bob');
    expect(await a.directory.append(0, bytes('e0'))).toBe('ok');
    expect(await a.directory.append(0, bytes('dup'))).toBe('conflict');
    expect(await a.directory.append(2, bytes('gap'))).toBe('conflict');
    expect(await a.directory.append(1, bytes('e1'))).toBe('ok');
    expect((await b.directory.read(w.addr('alice'))).map(str)).toEqual(['e0', 'e1']);
    expect(await b.directory.read(w.addr('nobody'))).toEqual([]);
  });

  it('spaces: members only, owner manages, revoke takes access away', async () => {
    const w = make();
    const a = w.session('alice');
    const b = w.session('bob');
    const c = w.session('carol');
    const s = await a.channel.createSpace('chat');
    expect(await a.orderedLog.append(s, 0, bytes('genesis'))).toBe('ok');
    await expect(b.orderedLog.read(s, 0)).rejects.toMatchObject({ code: expect.stringMatching(/forbidden|not_found/) });
    const g = await a.channel.grant(s, w.addr('bob'));
    expect(g.status).toBe('invited');
    if (g.status !== 'invited') return;
    await a.inviteInbox.send(w.addr('bob'), { pointer: g.pointer });
    expect(await c.inviteInbox.list()).toEqual([]);
    const [n] = await b.inviteInbox.list();
    expect(n!.from).toBe(w.addr('alice'));
    await b.channel.acceptGrant(n!.pointer);
    await b.channel.acceptGrant(n!.pointer); // twice is harmless
    await b.inviteInbox.delete(n!.id);
    expect(await b.inviteInbox.list()).toEqual([]);
    expect(await b.channel.listSpaces()).toContain(s);
    expect((await b.orderedLog.read(s, 0)).map(str)).toEqual(['genesis']);
    // compare-and-swap: two writers race for index 1, exactly one wins
    const r = await Promise.all([a.orderedLog.append(s, 1, bytes('A')), b.orderedLog.append(s, 1, bytes('B'))]);
    expect(r.filter((x) => x === 'ok')).toHaveLength(1);
    expect(await b.channel.canManage(s)).toBe(false);
    expect((await b.channel.grant(s, w.addr('carol'))).status).toBe('needs-manager');
    expect(await b.channel.revoke(s, w.addr('alice'))).toBe('needs-manager');
    expect((await a.channel.members(s)).active.sort()).toEqual([w.addr('alice'), w.addr('bob')].sort());
    expect(await a.channel.revoke(s, w.addr('bob'))).toBe('done');
    await expect(b.orderedLog.read(s, 0)).rejects.toBeTruthy();
    await expect(b.mailbox.post(s, bytes('x'))).rejects.toBeTruthy();
  });

  it('mailbox (6), blobs (7), drop box (8)', async () => {
    const w = make();
    const a = w.session('alice');
    const s = await a.channel.createSpace('chat');
    const id1 = await a.mailbox.post(s, bytes('m1'));
    const l1 = await a.mailbox.list(s);
    expect(l1.items.map((i) => [i.id, str(i.data)])).toEqual([[id1, 'm1']]);
    await a.mailbox.post(s, bytes('m2'));
    const l2 = await a.mailbox.list(s, l1.cursor);
    expect(l2.items.map((i) => str(i.data))).toEqual(['m2']);
    expect((await a.mailbox.list(s, l2.cursor)).items).toEqual([]);

    const big = new Uint8Array(2 * 1024 * 1024).map((_, i) => i % 251);
    const ref = await a.blobs.put(s, big);
    const back = (await a.blobs.get(s, ref))!;
    expect(back.length).toBe(big.length);
    expect(Buffer.from(back).equals(Buffer.from(big))).toBe(true);
    await a.blobs.delete(s, ref);
    expect(await a.blobs.get(s, ref)).toBeUndefined();

    const d = await a.dropBox.put(s, 'tag1', bytes('welcome'));
    expect((await a.dropBox.list(s, 'tag1')).map((x) => str(x.data))).toEqual(['welcome']);
    expect(await a.dropBox.list(s, 'tag2')).toEqual([]);
    await a.dropBox.delete(s, 'tag1', d);
    expect(await a.dropBox.list(s, 'tag1')).toEqual([]);
  });

  it('vault (9) and personal store (12): only me, compare-and-swap', async () => {
    const w = make();
    const a = w.session('alice');
    const b = w.session('bob');
    expect(await a.vault.put('root', bytes('v1'), null)).toBe('ok');
    expect(await a.vault.put('root', bytes('v2'), null)).toBe('conflict');
    const v = (await a.vault.get('root'))!;
    expect(await a.vault.put('root', bytes('v2'), v.version)).toBe('ok');
    expect(await a.vault.put('root', bytes('v3'), v.version)).toBe('conflict');
    expect(await b.vault.get('root')).toBeUndefined();

    expect(await a.personal.put('x1', bytes('one'), null)).toBe('ok');
    const cur = (await a.personal.get('x1'))!;
    expect(await a.personal.put('x1', bytes('two'), 'stale')).toBe('conflict');
    expect(await a.personal.put('x1', bytes('two'), cur.version)).toBe('ok');
    expect((await a.personal.list()).map((i) => i.id)).toEqual(['x1']);
    expect(await b.personal.list()).toEqual([]);
    const now = (await a.personal.get('x1'))!;
    expect(await a.personal.delete('x1', now.version)).toBe('ok');
    expect(await a.personal.get('x1')).toBeUndefined();
  });
});

describe('claim-once store (4)', () => {
  it('hands each item to exactly one taker, even under concurrency', async () => {
    const w = new MemoryWorld();
    const owner = w.session('mem:carol');
    await owner.claimOnce!.publish(Array.from({ length: 10 }, (_, i) => bytes(`kp${i}`)));
    const takers = Array.from({ length: 25 }, (_, i) => w.session(`mem:t${i}`));
    const got = await Promise.all(takers.map((t) => t.claimOnce!.claim('mem:carol')));
    const taken = got.filter(Boolean).map(str);
    expect(taken).toHaveLength(10);
    expect(new Set(taken).size).toBe(10);
    expect(await owner.claimOnce!.remaining()).toBe(0);
  });

  it('expired items are never handed out', async () => {
    let t = 1_000_000;
    const w = new MemoryWorld({ now: () => t });
    await w.session('mem:c').claimOnce!.publish([bytes('old')], { expiresAt: t + 10 });
    t += 11;
    expect(await w.session('mem:x').claimOnce!.claim('mem:c')).toBeUndefined();
  });

  it('the invite inbox is rate-limited per sender', async () => {
    const w = new MemoryWorld({ inboxRateLimit: 2 });
    const s = w.session('mem:spam');
    await s.inviteInbox.send('mem:v', { pointer: 'p' });
    await s.inviteInbox.send('mem:v', { pointer: 'p' });
    await expect(s.inviteInbox.send('mem:v', { pointer: 'p' })).rejects.toMatchObject({ code: 'too_many_attempts' });
  });
});
