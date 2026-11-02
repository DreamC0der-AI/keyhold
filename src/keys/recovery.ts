/**
 * Recovery code: 128 random bits, shown once at setup. Two equivalent spellings:
 *   - 12 words (BIP39 list, includes a checksum)          default, matches seed-phrase accounts
 *   - 7 groups of 4 characters, e.g. K7QD-M2XP-9WRT-HB4N-6CFA-YJ3E-QW1Z (Crockford base32 + checksum)
 * For seed-phrase accounts the seed phrase itself is the recovery code (source 'seed').
 */
import { randomBytes, equalBytes, sha256 } from '../util/bytes.js';
import { hkdfAesKey } from '../util/hkdf.js';
import { KeyholdError } from '../util/errors.js';
import { bytesToWords, wordsToBytes, normalizeSeedPhrase } from '../seed/index.js';

export const RECOVERY_INFO = 'keyhold/v1/envelope/recovery';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32

export interface RecoveryCode {
  /** The 16 secret bytes. Keep out of logs and storage. */
  bytes: Uint8Array;
  /** 12 words, space separated. */
  words: string;
  /** XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX */
  grouped: string;
}

export async function generateRecoveryCode(): Promise<RecoveryCode> {
  return recoveryCodeFromBytes(randomBytes(16));
}

export async function recoveryCodeFromBytes(bytes: Uint8Array): Promise<RecoveryCode> {
  if (bytes.length !== 16) throw new KeyholdError('config', 'recovery code must be 16 bytes');
  return { bytes, words: bytesToWords(bytes), grouped: await toGrouped(bytes) };
}

async function toGrouped(bytes: Uint8Array): Promise<string> {
  const check = (await sha256(bytes)).subarray(0, 2); // 12 bits used
  // 128 data bits + 12 check bits = 140 bits = 28 base32 chars.
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  acc = (acc << 12n) | BigInt(((check[0]! << 8) | check[1]!) >> 4);
  let s = '';
  for (let i = 27; i >= 0; i--) s += ALPHABET[Number((acc >> BigInt(i * 5)) & 31n)];
  return s.match(/.{4}/g)!.join('-');
}

async function fromGrouped(input: string): Promise<Uint8Array> {
  const clean = input
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/[OIL]/g, (c) => (c === 'O' ? '0' : '1'));
  if (!/^[0-9A-HJKMNP-TV-Z]{28}$/.test(clean)) {
    throw new KeyholdError('bad_recovery_code', 'A recovery code has 28 letters and digits.');
  }
  let acc = 0n;
  for (const c of clean) acc = (acc << 5n) | BigInt(ALPHABET.indexOf(c));
  const checkBits = Number(acc & 0xfffn);
  acc >>= 12n;
  const bytes = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) {
    bytes[i] = Number(acc & 0xffn);
    acc >>= 8n;
  }
  const check = (await sha256(bytes)).subarray(0, 2);
  if ((((check[0]! << 8) | check[1]!) >> 4) !== checkBits) {
    throw new KeyholdError('bad_recovery_code', 'That recovery code has a typo. Check each block.');
  }
  return bytes;
}

/** Parse either spelling. Throws `bad_recovery_code` / `bad_mnemonic` with a typo-friendly message. */
export async function parseRecoveryCode(input: string): Promise<RecoveryCode> {
  const trimmed = input.trim();
  const looksLikeWords = /[a-z]{3,}\s+[a-z]{3,}/i.test(trimmed) && normalizeSeedPhrase(trimmed).split(' ').length >= 12;
  const bytes = looksLikeWords ? wordsToBytes(trimmed) : await fromGrouped(trimmed);
  if (bytes.length !== 16) throw new KeyholdError('bad_recovery_code', 'That is a seed phrase, not a recovery code.');
  return recoveryCodeFromBytes(bytes);
}

/**
 * "Type the last block back" check at setup, proving the code was saved somewhere readable.
 * Accepts the last group (grouped form) or the last 3 words (word form).
 */
export async function confirmRecoveryCode(code: RecoveryCode, typed: string): Promise<boolean> {
  const t = typed.trim().toLowerCase().replace(/\s+/g, ' ');
  const lastGroup = code.grouped.split('-').pop()!.toLowerCase();
  const lastWords = code.words.split(' ').slice(-3).join(' ');
  return t === lastGroup || t === lastWords || equalBytes((await tryParse(typed)) ?? new Uint8Array(), code.bytes);
}

async function tryParse(s: string): Promise<Uint8Array | undefined> {
  try {
    return (await parseRecoveryCode(s)).bytes;
  } catch {
    return undefined;
  }
}

/** Wrapping key from a recovery secret: 16 bytes (code) or 32 bytes (from a seed phrase). */
export function recoveryWrappingKey(secret: Uint8Array): Promise<CryptoKey> {
  if (secret.length !== 16 && secret.length !== 32) throw new KeyholdError('config', 'recovery secret must be 16 or 32 bytes');
  return hkdfAesKey(secret, RECOVERY_INFO, ['wrapKey', 'unwrapKey']);
}
