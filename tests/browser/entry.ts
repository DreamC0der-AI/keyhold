import { webauthnPrf, IndexedDbDeviceStore } from '../../src/keys/browser';
import { KeyEditor, unlockWithPasskey, unlockWithPassword, unlockWithDevice } from '../../src/keys/index';
import { sealJson, openJson } from '../../src/crypto/index';
import { MemoryWorld, memoryDevice, resolveFeatures } from '../../src/storage/index';
import { Chat, createDeviceIdentity, createRootKey, DirectoryWriter, IdentityRegistry, newDeviceId } from '../../src/chat/index';

/** A DM between two in-page users: MLS (ts-mls) and WebCrypto in a real browser. */
window.runChat = async () => {
  const w = new MemoryWorld();
  const mk = async (addr: string) => {
    const p = w.session(addr);
    const root = createRootKey();
    const device = memoryDevice();
    const identity = await createDeviceIdentity(device, root, addr, newDeviceId());
    await new DirectoryWriter(p.directory, addr).publish(root, identity.cert);
    return Chat.open({ provider: p, device, identity, registry: new IdentityRegistry(p.directory), features: resolveFeatures(p) });
  };
  const bob = await mk('mem:bob');
  const alice = await mk('mem:alice');
  const g = await bob.startDm('mem:alice');
  const [ga] = await alice.acceptInvites();
  await g.send({ t: 'text', body: 'hello from the browser' });
  const r = await ga!.sync();
  await g.sendAttachment(new Uint8Array(300_000).fill(7), { name: 'a.bin' });
  const r2 = await ga!.sync();
  const m = r2.messages[0]!.message;
  const file = m.t === 'attachment' ? await ga!.fetchAttachment(m.file) : new Uint8Array();
  return { text: (r.messages[0]?.message as { body?: string })?.body ?? '', attachment: file.length, epoch: Number(g.epoch) };
};
window.run = async () => {
  const cfg = { rpId: location.hostname, rpName: 'Test' };
  const ed = await KeyEditor.create('acc');
  const user = { id: new TextEncoder().encode('acc'), name: 'me', displayName: 'Me' };
  const reg = await ed.addPasskey(cfg, webauthnPrf, user);
  const pw = await ed.addPassword('lantern-cobalt-river-mitten-oak');
  const store = new IndexedDbDeviceStore();
  await ed.rememberDevice(store);
  const k0 = await ed.close();
  const ctx = { type: 'note', account: 'acc', id: '1' };
  const s = await sealJson(k0, { t: 'hi' }, ctx);
  const a = await unlockWithPasskey([reg.envelope!], cfg, webauthnPrf);
  const b = await unlockWithPassword([pw], 'lantern-cobalt-river-mitten-oak');
  const c = await unlockWithDevice(store, 'acc');
  return { prf: reg.prfSupported, a: await openJson(a.key, s, ctx), b: await openJson(b.key, s, ctx), c: await openJson(c!, s, ctx), ext: c!.extractable };
};
declare global {
  interface Window {
    runChat: () => Promise<{ text: string; attachment: number; epoch: number }>;
    run: () => Promise<{ prf: boolean; a: { t: string }; b: { t: string }; c: { t: string }; ext: boolean }>;
  }
}
