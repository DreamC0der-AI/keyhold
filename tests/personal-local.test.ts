/** The storage operator rolls back or deletes personal records: a device copy puts them back. */
import { describe, expect, it } from 'vitest';
import { MemoryWorld, MemoryKeystore } from '../src/storage/index.js';
import { PersonalData, IdentityRegistry, createRootKey, DirectoryWriter, createDeviceIdentity, newDeviceId } from '../src/chat/index.js';
import { memoryDevice } from '../src/storage/index.js';
import { makeUser } from './chat-helpers.js';

const newK = () => crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

describe('personal store with a device copy', () => {
  it('a wiped pin store does not let a swapped identity key through as first seen', async () => {
    const w = new MemoryWorld({ claimOnce: false });
    const bob = w.session('mem:bob');
    await makeUser(w.session('mem:alice'), 'mem:alice');
    const K = await newK();
    const local = new MemoryKeystore();
    const pd = await PersonalData.open(bob.personal, K, 'dev1', Date.now, { local });
    expect((await new IdentityRegistry(bob.directory, pd.pinStore()).lookup('mem:alice')).status).toBe('ok');
    // The operator swaps alice's directory and wipes bob's whole personal store.
    const evil = createRootKey();
    w.directories.delete('mem:alice');
    const dev = await createDeviceIdentity(memoryDevice(), evil, 'mem:alice', newDeviceId());
    await new DirectoryWriter(w.session('mem:alice').directory, 'mem:alice').publish(evil, dev.cert);
    w.personal.get('mem:bob')!.clear();
    const pd2 = await PersonalData.open(bob.personal, K, 'dev1', Date.now, { local });
    expect((await new IdentityRegistry(bob.directory, pd2.pinStore()).lookup('mem:alice')).status).toBe('key-changed');
    // ...and the next flush writes what this device knew back.
    expect(pd2.repairs).toBeGreaterThan(0);
    await pd2.flush();
    const fresh = await PersonalData.open(bob.personal, K, 'dev2');
    expect((await fresh.contact('mem:alice'))?.fingerprint).toBeTruthy();
  });

  it('a rolled-back record is merged with the device copy and written again', async () => {
    const w = new MemoryWorld();
    const s = w.session('mem:bob');
    const K = await newK();
    const local = new MemoryKeystore();
    const pd = await PersonalData.open(s.personal, K, 'dev1', Date.now, { local });
    await pd.block('mem:mallory');
    await pd.flush();
    const store = w.personal.get('mem:bob')!;
    const old = new Map(store);
    await pd.block('mem:mallory', false);
    await pd.set('blocks', 'mem:eve', { blocked: true });
    await pd.flush();
    // Roll everything back to before the unblock and before eve.
    for (const k of [...store.keys()]) if (!old.has(k)) store.delete(k);
    for (const [k, v] of old) store.set(k, v);
    const keys = (await pd.list('blocks')).map((b) => b.key).sort();
    expect(keys).toEqual(['mem:eve']); // mallory unblocked, eve still blocked
    await pd.flush();
    const other = await PersonalData.open(s.personal, K, 'dev2');
    expect((await other.list('blocks')).map((b) => b.key)).toEqual(['mem:eve']);
  });

  it('a deleted index is put back with the same key, so records stay reachable', async () => {
    const w = new MemoryWorld();
    const s = w.session('mem:bob');
    const K = await newK();
    const local = new MemoryKeystore();
    const pd = await PersonalData.open(s.personal, K, 'dev1', Date.now, { local });
    await pd.setChat('g1', { pinned: true });
    await pd.flush();
    w.personal.get('mem:bob')!.delete('i');
    const again = await PersonalData.open(s.personal, K, 'dev1', Date.now, { local });
    expect((await again.get('chats', 'g1'))?.pinned).toBe(true);
    const other = await PersonalData.open(s.personal, K, 'dev2');
    expect((await other.get('chats', 'g1'))?.pinned).toBe(true);
  });
});
