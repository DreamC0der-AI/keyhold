import { describe, expect, it } from 'vitest';
import 'fake-indexeddb/auto';
import {
  KeyEditor,
  unlockWithPasskey,
  unlockWithPassword,
  unlockWithRecovery,
  unlockWithDevice,
  editWithDevice,
  planUnlock,
  parseRecoveryCode,
  confirmRecoveryCode,
  generateRecoveryCode,
  checkVaultPassword,
  suggestPassphrase,
  isEnvelope,
  MemoryDeviceStore,
  NewDeviceApproval,
  ExistingDeviceApproval,
  defaultArgon2id,
  type Envelope,
} from '../src/keys/index.js';
import { IndexedDbDeviceStore } from '../src/keys/browser.js';
import { sealText, openText } from '../src/crypto/index.js';
import { generateSeedPhrase, deriveSeedSecrets } from '../src/seed/index.js';
import { fakeAuthenticator, testArgon2Params, countingArgon2 } from './helpers.js';

const cfg = { rpId: 'example.com', rpName: 'Example' };
const user = { id: new TextEncoder().encode('acc_1'), name: 'me@example.com', displayName: 'Me' };
const ctx = { type: 'note', account: 'acc_1', id: 'n1' };

async function setup() {
  const auth = fakeAuthenticator();
  const editor = await KeyEditor.create('acc_1');
  const { envelope: pk } = await editor.addPasskey(cfg, auth.provider, user, { label: 'iPhone' });
  const pw = await editor.addPassword('lantern-cobalt-river-mitten-oak', { params: testArgon2Params });
  const { code, envelope: rc } = await editor.addRecoveryCode();
  const daily = await editor.notesKey();
  const sealed = await sealText(daily, 'my secret note', ctx);
  await editor.close();
  return { auth, envelopes: [pk!, pw, rc] as Envelope[], code, sealed };
}

describe('envelopes', () => {
  it('first setup makes valid envelopes and every one opens the same key', async () => {
    const { auth, envelopes, code, sealed } = await setup();
    for (const e of envelopes) expect(isEnvelope(JSON.parse(JSON.stringify(e)))).toBe(true);
    expect(JSON.stringify(envelopes)).not.toContain('my secret');

    const a = await unlockWithPasskey(envelopes, cfg, auth.provider);
    expect(a.key.extractable).toBe(false);
    expect(await openText(a.key, sealed, ctx)).toBe('my secret note');

    const b = await unlockWithPassword(envelopes, 'lantern-cobalt-river-mitten-oak', { allowWeakParams: true });
    expect(await openText(b.key, sealed, ctx)).toBe('my secret note');

    const c = await unlockWithRecovery(envelopes, (await parseRecoveryCode(code.words)).bytes);
    expect(await openText(c.key, sealed, ctx)).toBe('my secret note');
  });

  it('wrong secrets fail with wrong_secret', async () => {
    const { envelopes } = await setup();
    await expect(unlockWithPassword(envelopes, 'not-the-password-at-all', { allowWeakParams: true })).rejects.toMatchObject({ code: 'wrong_secret' });
    const other = await generateRecoveryCode();
    await expect(unlockWithRecovery(envelopes, other.bytes)).rejects.toMatchObject({ code: 'wrong_secret' });
    const stranger = fakeAuthenticator();
    await stranger.provider.register({ rpId: 'example.com', rpName: 'x', user, prfSalt: new Uint8Array(32) });
    await expect(unlockWithPasskey(envelopes, cfg, stranger.provider)).rejects.toThrow();
  });

  it('an envelope moved to another account or with edited params does not open', async () => {
    const { envelopes, code } = await setup();
    const rc = envelopes.find((e) => e.kind === 'recovery')!;
    const moved = { ...rc, account: 'acc_2' } as Envelope;
    await expect(unlockWithRecovery([moved], code.bytes)).rejects.toMatchObject({ code: 'wrong_secret' });
    const pw = envelopes.find((e) => e.kind === 'password') as Envelope<'password'>;
    const edited = { ...pw, params: { ...pw.params, t: pw.params.t + 1 } };
    await expect(unlockWithPassword([edited], 'lantern-cobalt-river-mitten-oak', { allowWeakParams: true })).rejects.toMatchObject({ code: 'wrong_secret' });
  });

  it('refuses password envelopes whose Argon2 cost was lowered, unless explicitly allowed', async () => {
    const { envelopes } = await setup();
    await expect(unlockWithPassword(envelopes, 'lantern-cobalt-river-mitten-oak')).rejects.toMatchObject({ code: 'bad_format' });
  });

  it('passkey created without PRF on create() evaluates PRF right after', async () => {
    const auth = fakeAuthenticator({ prfOnCreate: false });
    const editor = await KeyEditor.create('acc_1');
    const res = await editor.addPasskey(cfg, auth.provider, user);
    expect(res.prfSupported).toBe(true);
    const k = await unlockWithPasskey([res.envelope!], cfg, auth.provider);
    expect(k.envelope.params.credentialId).toBe(res.credentialId);
  });

  it('reports a passkey without PRF so the app can fall back to the vault password', async () => {
    const auth = fakeAuthenticator({ prfSupported: false });
    const editor = await KeyEditor.create('acc_1');
    const res = await editor.addPasskey(cfg, auth.provider, user);
    expect(res.prfSupported).toBe(false);
    expect(res.envelope).toBeUndefined();
  });

  it('passkeys for another domain are ignored', async () => {
    const { auth, envelopes } = await setup();
    await expect(unlockWithPasskey(envelopes, { rpId: 'other.app' }, auth.provider)).rejects.toMatchObject({ code: 'prf_unavailable' });
  });

  it('with two passkeys, the one the user picks opens its own envelope', async () => {
    const auth = fakeAuthenticator();
    const editor = await KeyEditor.create('acc_1');
    const a = await editor.addPasskey(cfg, auth.provider, user);
    const b = await editor.addPasskey(cfg, auth.provider, user);
    auth.choose(b.credentialId);
    const res = await unlockWithPasskey([a.envelope!, b.envelope!], cfg, auth.provider);
    expect(res.envelope.id).toBe(b.envelope!.id);
  });

  it('KeyEditor refuses to work after close()', async () => {
    const editor = await KeyEditor.create('acc_1');
    await editor.close();
    await expect(editor.addRecoveryCode()).rejects.toMatchObject({ code: 'config' });
  });

  it('the default Argon2id (hash-wasm) works at the real 64 MiB cost', async () => {
    const editor = await KeyEditor.create('acc_1');
    const env = await editor.addPassword('lantern-cobalt-river-mitten-oak');
    expect(env.params).toMatchObject({ m: 65536, t: 3, p: 1 });
    const spy = countingArgon2(defaultArgon2id);
    const k = await unlockWithPassword([env], 'lantern-cobalt-river-mitten-oak', { argon2: spy.fn });
    expect(k.key.type).toBe('secret');
    expect(spy.calls()).toBe(1);
  });
});

describe('vault password strength', () => {
  it('accepts suggested passphrases and long varied passwords', () => {
    expect(checkVaultPassword(suggestPassphrase()).ok).toBe(true);
    expect(suggestPassphrase().split('-')).toHaveLength(5);
    expect(checkVaultPassword('Tr0ub4dor&3-horse-x').ok).toBe(true);
  });
  it('rejects short, common and repetitive ones', () => {
    expect(checkVaultPassword('password').reason).toBe('common');
    expect(checkVaultPassword('Ab1!').reason).toBe('too_short');
    expect(checkVaultPassword('aaaaaaaaaaaaaaaa').reason).toBe('too_simple');
  });
  it('addPassword enforces it', async () => {
    const editor = await KeyEditor.create('acc_1');
    await expect(editor.addPassword('qwerty', { params: testArgon2Params })).rejects.toMatchObject({ code: 'weak_password' });
  });
});

describe('recovery code', () => {
  it('words and grouped forms are the same code and both parse', async () => {
    const code = await generateRecoveryCode();
    expect(code.words.split(' ')).toHaveLength(12);
    expect(code.grouped).toMatch(/^([0-9A-Z]{4}-){6}[0-9A-Z]{4}$/);
    expect((await parseRecoveryCode(code.words)).bytes).toEqual(code.bytes);
    expect((await parseRecoveryCode(code.grouped.toLowerCase().replace(/-/g, ' '))).bytes).toEqual(code.bytes);
  });
  it('catches typos', async () => {
    const code = await generateRecoveryCode();
    const g = code.grouped;
    const typo = (g[0] === 'A' ? 'B' : 'A') + g.slice(1);
    await expect(parseRecoveryCode(typo)).rejects.toMatchObject({ code: 'bad_recovery_code' });
    const words = code.words.split(' ');
    words[0] = words[0] === 'abandon' ? 'ability' : 'abandon';
    // 12 words carry only a 4-bit checksum, so 1 in 16 typos still parses; then it just won't unlock.
    const parsed = await parseRecoveryCode(words.join(' ')).catch((e) => e);
    if (parsed instanceof Error) expect(parsed).toMatchObject({ code: 'bad_mnemonic' });
    else expect(parsed.bytes).not.toEqual(code.bytes);
  });
  it('setup confirmation accepts the last block or last 3 words', async () => {
    const code = await generateRecoveryCode();
    expect(await confirmRecoveryCode(code, code.grouped.slice(-4))).toBe(true);
    expect(await confirmRecoveryCode(code, code.words.split(' ').slice(-3).join(' '))).toBe(true);
    expect(await confirmRecoveryCode(code, 'nope')).toBe(false);
  });
  it('a new recovery code replaces the old one when the old envelope is deleted', async () => {
    const editor = await KeyEditor.create('acc_1');
    const first = await editor.addRecoveryCode();
    const second = await editor.addRecoveryCode();
    const stored = [second.envelope]; // app deletes first.envelope
    await expect(unlockWithRecovery(stored, first.code.bytes)).rejects.toMatchObject({ code: 'wrong_secret' });
    await expect(unlockWithRecovery(stored, second.code.bytes)).resolves.toBeTruthy();
  });
});

describe('seed phrase as recovery', () => {
  it('the seed phrase unlocks K, and its two derived secrets differ', async () => {
    const phrase = generateSeedPhrase(12);
    const s = await deriveSeedSecrets(phrase);
    expect(Buffer.from(s.identitySeed).equals(Buffer.from(s.recoverySecret))).toBe(false);
    const editor = await KeyEditor.create('acc_seed');
    const env = await editor.addSeedRecovery(s.recoverySecret);
    const again = await deriveSeedSecrets(`  ${phrase.toUpperCase()}  `);
    await expect(unlockWithRecovery([env], again.recoverySecret)).resolves.toBeTruthy();
    await expect(deriveSeedSecrets(phrase.replace(/^\w+/, 'notaword'))).rejects.toMatchObject({ code: 'bad_mnemonic' });
  });
});

describe('device records', () => {
  for (const [name, make] of [
    ['memory', () => new MemoryDeviceStore()],
    ['IndexedDB', () => new IndexedDbDeviceStore(`keyhold-test-${Math.random()}`)],
  ] as const) {
    it(`re-opens K on this device without a gesture (${name})`, async () => {
      const store = make();
      const editor = await KeyEditor.create('acc_1');
      const daily = await editor.notesKey();
      const sealed = await sealText(daily, 'hi', ctx);
      await editor.rememberDevice(store, 'This Mac');
      await editor.close();

      const k = await unlockWithDevice(store, 'acc_1');
      expect(k!.extractable).toBe(false);
      expect(await openText(k!, sealed, ctx)).toBe('hi');
      const rec = await store.get('acc_1');
      expect(rec!.deviceKey.extractable).toBe(false);

      // Later, add a passkey without asking for another unlock.
      const ed = await editWithDevice(store, 'acc_1');
      const auth = fakeAuthenticator();
      const { envelope } = await ed!.addPasskey(cfg, auth.provider, user);
      await ed!.close();
      expect(await openText((await unlockWithPasskey([envelope!], cfg, auth.provider)).key, sealed, ctx)).toBe('hi');

      await store.delete('acc_1');
      expect(await unlockWithDevice(store, 'acc_1')).toBeUndefined();
    });
  }
});

describe('approve a new device by QR', () => {
  async function unlockedOld() {
    const editor = await KeyEditor.create('acc_1');
    const sealed = await sealText(await editor.notesKey(), 'from old device', ctx);
    return { editor, sealed };
  }

  it('moves K to the new device after both show the same 4 words', async () => {
    const { editor, sealed } = await unlockedOld();
    const fresh = await NewDeviceApproval.start({ account: 'acc_1' });
    const old = await ExistingDeviceApproval.accept(fresh.qr, { account: 'acc_1' });
    const newWords = await fresh.receiveHello(JSON.parse(JSON.stringify(old.hello)));
    expect(newWords).toHaveLength(4);
    expect(newWords).toEqual(old.words);
    const msg = await editor.approveDevice(old);
    const k = await fresh.receiveKey(JSON.parse(JSON.stringify(msg)));
    expect(await openText(k, sealed, ctx)).toBe('from old device');

    // The new device can now remember itself.
    const store = new MemoryDeviceStore();
    const ed = KeyEditor.fromKey('acc_1', k);
    await ed.rememberDevice(store);
    await ed.close();
    expect(await openText((await unlockWithDevice(store, 'acc_1'))!, sealed, ctx)).toBe('from old device');
  });

  it('a relay that swaps in its own key gets different words and cannot read K', async () => {
    const { editor } = await unlockedOld();
    const fresh = await NewDeviceApproval.start({ account: 'acc_1' });
    const old = await ExistingDeviceApproval.accept(fresh.qr, { account: 'acc_1' });
    // Attacker answers the new device itself with its own hello.
    const mitm = await ExistingDeviceApproval.accept(fresh.qr, { account: 'acc_1' });
    const shownOnNew = await fresh.receiveHello(mitm.hello);
    expect(shownOnNew).not.toEqual(old.words);
    const msg = await editor.approveDevice(old);
    await expect(fresh.receiveKey(msg)).rejects.toMatchObject({ code: 'approval_failed' });
  });

  it('refuses another account, an expired QR, and reuse', async () => {
    const { editor } = await unlockedOld();
    const fresh = await NewDeviceApproval.start({ account: 'acc_1', now: Date.now() - 10 * 60_000 });
    await expect(ExistingDeviceApproval.accept(fresh.qr, { account: 'acc_1' })).rejects.toMatchObject({ code: 'approval_failed' });
    const f2 = await NewDeviceApproval.start({ account: 'acc_2' });
    await expect(ExistingDeviceApproval.accept(f2.qr, { account: 'acc_1' })).rejects.toMatchObject({ code: 'approval_failed' });
    const f3 = await NewDeviceApproval.start({ account: 'acc_1' });
    const old = await ExistingDeviceApproval.accept(`https://example.com/approve#${encodeURIComponent(f3.qr)}`, { account: 'acc_1' });
    await f3.receiveHello(old.hello);
    const msg = await editor.approveDevice(old);
    await f3.receiveKey(msg);
    await expect(f3.receiveKey(msg)).rejects.toMatchObject({ code: 'approval_failed' });
    await expect(editor.approveDevice(old)).rejects.toMatchObject({ code: 'approval_failed' });
  });
});

describe('planUnlock', () => {
  it('follows the agreed order and skips what is not set up', async () => {
    const { envelopes } = await setup();
    expect(planUnlock({ envelopes, rpId: 'example.com', hasDeviceRecord: true })).toEqual(['device', 'passkey', 'approval', 'password', 'recovery']);
    expect(planUnlock({ envelopes: envelopes.filter((e) => e.kind === 'recovery'), rpId: 'example.com', canApprove: false })).toEqual(['recovery']);
    expect(planUnlock({ envelopes, rpId: 'other.app' })).toEqual(['approval', 'password', 'recovery']);
  });
});
