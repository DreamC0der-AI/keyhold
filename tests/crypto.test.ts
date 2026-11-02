import { describe, expect, it } from 'vitest';
import { seal, open, sealJson, openJson, sealText, openText, isSealed, encodeContext } from '../src/crypto/index.js';
import { KeyEditor } from '../src/keys/index.js';

const ctx = { type: 'note', account: 'acc_1', id: 'note_1' };

async function key() {
  return (await KeyEditor.create('acc_1')).close();
}

describe('keyhold/crypto', () => {
  it('round-trips JSON with a non-extractable key', async () => {
    const k = await key();
    expect(k.extractable).toBe(false);
    const note = { title: 'Bank', body: 'PIN is in the drawer', doc: { type: 'doc', content: [] } };
    const sealed = await sealJson(k, note, ctx);
    expect(isSealed(sealed)).toBe(true);
    expect(sealed).not.toContain('Bank');
    expect(await openJson(k, sealed, ctx)).toEqual(note);
  });

  it('uses a fresh nonce every time', async () => {
    const k = await key();
    expect(await sealText(k, 'same', ctx)).not.toEqual(await sealText(k, 'same', ctx));
  });

  it('compresses large text and still round-trips', async () => {
    const k = await key();
    const text = 'the quick brown fox '.repeat(500);
    const sealed = await sealText(k, text, ctx);
    expect(sealed.length).toBeLessThan(text.length / 4);
    expect(await openText(k, sealed, ctx)).toBe(text);
  });

  it('refuses a ciphertext moved onto another note or account', async () => {
    const k = await key();
    const sealed = await sealText(k, 'secret', ctx);
    await expect(openText(k, sealed, { ...ctx, id: 'note_2' })).rejects.toMatchObject({ code: 'decrypt_failed' });
    await expect(openText(k, sealed, { ...ctx, account: 'acc_2' })).rejects.toMatchObject({ code: 'decrypt_failed' });
    await expect(openText(k, sealed, { ...ctx, type: 'room' })).rejects.toMatchObject({ code: 'decrypt_failed' });
  });

  it('refuses tampered data and the wrong key', async () => {
    const k = await key();
    const bytes = await seal(k, new TextEncoder().encode('hello world'), ctx);
    bytes[bytes.length - 1]! ^= 1;
    await expect(open(k, bytes, ctx)).rejects.toMatchObject({ code: 'decrypt_failed' });
    const good = await sealText(k, 'x', ctx);
    await expect(openText(await key(), good, ctx)).rejects.toMatchObject({ code: 'decrypt_failed' });
  });

  it('context encoding is unambiguous', () => {
    const a = encodeContext({ a: 'bc', d: 'e' });
    const b = encodeContext({ a: 'b', cd: 'e' });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    expect(Buffer.from(encodeContext({ x: '1', y: '2' })).equals(Buffer.from(encodeContext({ y: '2', x: '1' })))).toBe(true);
  });

  it('rejects unknown versions', async () => {
    const k = await key();
    const bytes = await seal(k, new Uint8Array([1, 2, 3]), ctx);
    bytes[0] = 9;
    await expect(open(k, bytes, ctx)).rejects.toMatchObject({ code: 'unsupported_version' });
  });
});
