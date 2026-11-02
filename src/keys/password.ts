/**
 * Vault password: an optional fallback unlock for devices that can't make a PRF passkey.
 * Separate from login and never sent to the server; only the envelope and its salt are.
 * Argon2id (default 64 MiB, 3 passes) makes every offline guess expensive.
 */
import { randomBytes, toBase64Url, fromBase64Url, utf8 } from '../util/bytes.js';
import { hkdfAesKey } from '../util/hkdf.js';
import { KeyholdError } from '../util/errors.js';
import { englishWordlist } from '../seed/index.js';
import type { Envelope, PasswordParams } from './envelope.js';

export const PASSWORD_INFO = 'keyhold/v1/envelope/password';

export interface Argon2Params {
  /** Memory in KiB. Default 65536 (64 MiB). */
  m: number;
  /** Passes. Default 3. */
  t: number;
  /** Lanes. Default 1 (browsers run it single-threaded anyway). */
  p: number;
}

export const DEFAULT_ARGON2: Argon2Params = { m: 65536, t: 3, p: 1 };

/** Pluggable Argon2id. Must return `length` bytes. */
export type Argon2idFn = (input: {
  password: Uint8Array;
  salt: Uint8Array;
  params: Argon2Params;
  length: number;
}) => Promise<Uint8Array>;

/** Default: hash-wasm (WebAssembly), loaded only when a password is actually used. */
export const defaultArgon2id: Argon2idFn = async ({ password, salt, params, length }) => {
  const { argon2id } = await import('hash-wasm');
  return argon2id({
    password,
    salt,
    parallelism: params.p,
    iterations: params.t,
    memorySize: params.m,
    hashLength: length,
    outputType: 'binary',
  });
};

/** Minimum Argon2 cost accepted when opening an envelope, so a forged envelope can't downgrade it. */
export const MIN_ARGON2: Argon2Params = { m: 19456, t: 2, p: 1 };

export async function passwordWrappingKey(
  password: string,
  params: PasswordParams,
  argon2: Argon2idFn = defaultArgon2id,
  opts: { allowWeakParams?: boolean } = {},
): Promise<CryptoKey> {
  if (!opts.allowWeakParams && (params.m < MIN_ARGON2.m || params.t < MIN_ARGON2.t)) {
    throw new KeyholdError('bad_format', 'password envelope uses Argon2 parameters below the minimum');
  }
  const stretched = await argon2({
    password: utf8(password.normalize('NFKC')),
    salt: fromBase64Url(params.salt),
    params: { m: params.m, t: params.t, p: params.p },
    length: 32,
  });
  try {
    return await hkdfAesKey(stretched, PASSWORD_INFO, ['wrapKey', 'unwrapKey']);
  } finally {
    stretched.fill(0);
  }
}

export function newPasswordParams(params: Argon2Params = DEFAULT_ARGON2): PasswordParams {
  return { kdf: 'argon2id', salt: toBase64Url(randomBytes(16)), m: params.m, t: params.t, p: params.p };
}

export type PasswordEnvelope = Envelope<'password'>;

// ---- strength ------------------------------------------------------------------------

const COMMON = new Set(
  (
    'password,123456,12345678,123456789,1234567890,qwerty,qwertyuiop,abc123,111111,iloveyou,admin,welcome,' +
    'letmein,monkey,dragon,football,baseball,sunshine,princess,passw0rd,password1,password123,trustno1,' +
    'master,shadow,superman,starwars,whatever,qazwsx,zaq12wsx,000000,123123,654321,1q2w3e4r,asdfghjkl'
  ).split(','),
);

export interface PasswordCheck {
  ok: boolean;
  /** Rough entropy estimate in bits. */
  bits: number;
  reason?: 'too_short' | 'common' | 'too_simple';
}

/**
 * Conservative strength check. Accepts a passphrase of 4+ list words, or 12+ characters with
 * an estimated 50+ bits. Apps can layer a richer checker (e.g. zxcvbn) on top.
 */
export function checkVaultPassword(password: string): PasswordCheck {
  const pw = password.normalize('NFKC');
  const lower = pw.toLowerCase();
  if (COMMON.has(lower)) return { ok: false, bits: 0, reason: 'common' };
  const words = lower.split(/[\s\-_.,]+/).filter(Boolean);
  const listWords = words.filter((w) => wordSet().has(w));
  if (listWords.length >= 4 && new Set(listWords).size === listWords.length) {
    return { ok: true, bits: listWords.length * 11 };
  }
  if (pw.length < 12) return { ok: false, bits: estimateBits(pw), reason: 'too_short' };
  const bits = estimateBits(pw);
  if (bits < 50) return { ok: false, bits, reason: 'too_simple' };
  return { ok: true, bits };
}

function estimateBits(pw: string): number {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  const unique = new Set(pw).size;
  // Penalise repetition: count only distinct characters beyond the first few repeats.
  const effectiveLen = Math.min(pw.length, unique * 2);
  return Math.round(effectiveLen * Math.log2(Math.max(pool, 2)));
}

let _wordSet: Set<string> | undefined;
function wordSet(): Set<string> {
  return (_wordSet ??= new Set(englishWordlist));
}

/** Suggest a passphrase of `words` random everyday words (11 bits each), e.g. "lantern-cobalt-river-mitten-oak". */
export function suggestPassphrase(words = 5, separator = '-'): string {
  const out: string[] = [];
  const buf = new Uint16Array(words);
  crypto.getRandomValues(buf);
  for (let i = 0; i < words; i++) out.push(englishWordlist[buf[i]! & 0x7ff]!);
  return out.join(separator);
}
