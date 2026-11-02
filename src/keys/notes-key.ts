import { KeyholdError } from '../util/errors.js';

/** A fresh random 256-bit AES-GCM notes key, extractable so it can be wrapped into envelopes. */
export async function generateNotesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

/**
 * Copy an extractable K into a non-extractable one for daily use. The raw bytes exist in
 * page memory only for the moment of the copy and are wiped right after.
 */
export async function lockNotesKey(key: CryptoKey): Promise<CryptoKey> {
  if (!key.extractable) return key;
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  try {
    return await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally {
    raw.fill(0);
  }
}

export function assertExtractable(key: CryptoKey): void {
  if (!key.extractable) throw new KeyholdError('config', 'this step needs the notes key opened for editing');
}
