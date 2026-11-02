import { own, utf8 } from './bytes.js';

/** HKDF-SHA256 over WebCrypto, returning raw bytes. `info` is a domain-separation label. */
export async function hkdfBytes(
  ikm: Uint8Array,
  info: string,
  length = 32,
  salt: Uint8Array = new Uint8Array(0),
): Promise<Uint8Array<ArrayBuffer>> {
  const base = await crypto.subtle.importKey('raw', own(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: own(salt), info: utf8(info) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** HKDF-SHA256 straight into a non-extractable AES-256-GCM key. */
export async function hkdfAesKey(
  ikm: Uint8Array,
  info: string,
  usages: KeyUsage[],
  salt: Uint8Array = new Uint8Array(0),
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', own(ikm), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: own(salt), info: utf8(info) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}
