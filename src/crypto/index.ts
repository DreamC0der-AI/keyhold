/**
 * keyhold/crypto — seal and open app data with the notes key before it syncs.
 *
 * This module knows nothing about logins or how the key was unlocked. Its only input
 * is an AES-256-GCM `CryptoKey` (normally the non-extractable notes key from
 * keyhold/keys) and a context that pins each ciphertext to one object.
 *
 * Sealed format (binary): [version=1][12-byte nonce][AES-GCM ciphertext + 16-byte tag]
 * Plaintext inside starts with one flags byte (bit 0 = deflate-raw compressed).
 * Additional data = "keyhold/v1/seal" + canonical context, so a ciphertext copied onto
 * another note, account or object type fails to open.
 */
import { concat, fromBase64Url, own, randomBytes, toBase64Url, td, utf8 } from '../util/bytes.js';
import { KeyholdError } from '../util/errors.js';

export { KeyholdError } from '../util/errors.js';

export const SEAL_VERSION = 1;
const NONCE_BYTES = 12;
const FLAG_DEFLATE = 1;

/**
 * Binds a ciphertext to where it belongs. Use stable ids, never mutable text.
 * Example: `{ type: 'note', account: 'acc_1', id: 'note_42' }`.
 */
export type SealContext = Readonly<Record<string, string>>;

export interface SealOptions {
  /** Compress before sealing. Default: true for JSON/text, worth it above ~64 bytes. */
  compress?: boolean;
}

/** Canonical, unambiguous encoding of a context: sorted keys, length-prefixed. */
export function encodeContext(context: SealContext): Uint8Array<ArrayBuffer> {
  const keys = Object.keys(context).sort();
  if (keys.length === 0) throw new KeyholdError('config', 'seal context must not be empty');
  const parts: Uint8Array[] = [utf8('keyhold/v1/seal')];
  for (const k of keys) {
    const v = context[k];
    if (typeof v !== 'string') throw new KeyholdError('config', `seal context value for ${k} must be a string`);
    for (const s of [k, v]) {
      const b = utf8(s);
      parts.push(u32(b.length), b);
    }
  }
  return concat(...parts);
}

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

async function pipe(data: Uint8Array, stream: CompressionStream | DecompressionStream): Promise<Uint8Array<ArrayBuffer>> {
  const out = new Response(new Blob([own(data)]).stream().pipeThrough(stream));
  return new Uint8Array(await out.arrayBuffer());
}

export const deflateRaw = (d: Uint8Array) => pipe(d, new CompressionStream('deflate-raw'));
export const inflateRaw = (d: Uint8Array) => pipe(d, new DecompressionStream('deflate-raw'));

/** Encrypt bytes. Returns the binary sealed form. */
export async function seal(
  key: CryptoKey,
  plaintext: Uint8Array,
  context: SealContext,
  options: SealOptions = {},
): Promise<Uint8Array<ArrayBuffer>> {
  let flags = 0;
  let body: Uint8Array = plaintext;
  if (options.compress) {
    const packed = await deflateRaw(plaintext);
    if (packed.length < plaintext.length) {
      flags |= FLAG_DEFLATE;
      body = packed;
    }
  }
  const nonce = randomBytes(NONCE_BYTES);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: encodeContext(context) },
    key,
    concat(new Uint8Array([flags]), body),
  );
  return concat(new Uint8Array([SEAL_VERSION]), nonce, new Uint8Array(ct));
}

/** Decrypt bytes from `seal`. Throws `decrypt_failed` for a wrong key, wrong context or tampering. */
export async function open(key: CryptoKey, sealed: Uint8Array, context: SealContext): Promise<Uint8Array<ArrayBuffer>> {
  if (sealed.length < 1 + NONCE_BYTES + 16 + 1) throw new KeyholdError('bad_format', 'sealed data is too short');
  if (sealed[0] !== SEAL_VERSION) {
    throw new KeyholdError('unsupported_version', `sealed data version ${sealed[0]} is not supported`);
  }
  let pt: Uint8Array;
  try {
    pt = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: own(sealed.subarray(1, 1 + NONCE_BYTES)), additionalData: encodeContext(context) },
        key,
        own(sealed.subarray(1 + NONCE_BYTES)),
      ),
    );
  } catch (e) {
    throw new KeyholdError('decrypt_failed', 'could not decrypt: wrong key, wrong context, or the data was changed', {
      cause: e,
    });
  }
  const flags = pt[0]!;
  const body = pt.subarray(1);
  return flags & FLAG_DEFLATE ? inflateRaw(body) : own(body);
}

/** Seal text. Returns base64url, ready for a JSON API or a TEXT column. Compressed by default. */
export async function sealText(key: CryptoKey, text: string, context: SealContext, options: SealOptions = {}): Promise<string> {
  return toBase64Url(await seal(key, utf8(text), context, { compress: true, ...options }));
}

export async function openText(key: CryptoKey, sealed: string, context: SealContext): Promise<string> {
  return td.decode(await open(key, fromBase64Url(sealed), context));
}

/** Seal any JSON value (e.g. a note's title + body + rich doc together). */
export async function sealJson(key: CryptoKey, value: unknown, context: SealContext, options: SealOptions = {}): Promise<string> {
  return sealText(key, JSON.stringify(value), context, options);
}

export async function openJson<T = unknown>(key: CryptoKey, sealed: string, context: SealContext): Promise<T> {
  return JSON.parse(await openText(key, sealed, context)) as T;
}

/** True if a string looks like keyhold sealed data (cheap check, no decryption). */
export function isSealed(value: string): boolean {
  try {
    const b = fromBase64Url(value);
    return b.length >= 30 && b[0] === SEAL_VERSION;
  } catch {
    return false;
  }
}
