import { webauthnPrf, IndexedDbDeviceStore } from '../../src/keys/browser';
import { KeyEditor, unlockWithPasskey, unlockWithPassword, unlockWithDevice } from '../../src/keys/index';
import { sealJson, openJson } from '../../src/crypto/index';
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
    run: () => Promise<{ prf: boolean; a: { t: string }; b: { t: string }; c: { t: string }; ext: boolean }>;
  }
}
