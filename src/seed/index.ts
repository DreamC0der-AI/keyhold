/**
 * keyhold/seed — BIP39 seed phrases for the self-custody route.
 *
 * One seed phrase yields two unrelated secrets, each through its own HKDF label:
 *   - the identity seed (Ed25519 secret key; its public key is the account id), used by keyhold/auth
 *   - the recovery secret, used by keyhold/keys to wrap the notes key
 * Knowing one derived secret reveals nothing about the other.
 *
 * The same word list is used to show ordinary recovery codes as 12 words, and for the
 * 4-word check on device approval and passphrase suggestions.
 */
import {
  generateMnemonic as bip39Generate,
  mnemonicToSeedWebcrypto,
  validateMnemonic,
  mnemonicToEntropy,
  entropyToMnemonic,
} from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { hkdfBytes } from '../util/hkdf.js';
import { KeyholdError } from '../util/errors.js';

export { wordlist as englishWordlist };

export const SEED_INFO_IDENTITY = 'keyhold/v1/seed/identity-ed25519';
export const SEED_INFO_RECOVERY = 'keyhold/v1/seed/recovery';

/** 12 words = 128 bits, 24 words = 256 bits. */
export type SeedWords = 12 | 24;

export function generateSeedPhrase(words: SeedWords = 12): string {
  return bip39Generate(wordlist, words === 24 ? 256 : 128);
}

/** Lower-cases, trims and collapses whitespace so hand-typed phrases still match. */
export function normalizeSeedPhrase(phrase: string): string {
  return phrase.normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' ');
}

export function isValidSeedPhrase(phrase: string): boolean {
  return validateMnemonic(normalizeSeedPhrase(phrase), wordlist);
}

export interface SeedSecrets {
  /** 32 bytes: the Ed25519 secret key for challenge-response login. */
  identitySeed: Uint8Array;
  /** 32 bytes: input to the recovery envelope in keyhold/keys. */
  recoverySecret: Uint8Array;
}

/** Derive both secrets from a phrase. Throws `bad_mnemonic` on a typo or bad checksum. */
export async function deriveSeedSecrets(phrase: string): Promise<SeedSecrets> {
  const norm = normalizeSeedPhrase(phrase);
  if (!validateMnemonic(norm, wordlist)) {
    throw new KeyholdError('bad_mnemonic', 'That seed phrase is not valid. Check each word.');
  }
  const seed = await mnemonicToSeedWebcrypto(norm);
  try {
    const [identitySeed, recoverySecret] = await Promise.all([
      hkdfBytes(seed, SEED_INFO_IDENTITY, 32),
      hkdfBytes(seed, SEED_INFO_RECOVERY, 32),
    ]);
    return { identitySeed, recoverySecret };
  } finally {
    seed.fill(0);
  }
}

/** Words <-> bytes for 16/32-byte values (recovery codes shown as words). */
export function bytesToWords(entropy: Uint8Array): string {
  return entropyToMnemonic(entropy, wordlist);
}

export function wordsToBytes(words: string): Uint8Array {
  try {
    return mnemonicToEntropy(normalizeSeedPhrase(words), wordlist);
  } catch (e) {
    throw new KeyholdError('bad_mnemonic', 'Those words are not a valid code. Check each word.', { cause: e });
  }
}

/** Pick `count` words, `bits` bits each from `bytes` (big-endian). 11 bits = one BIP39 word. */
export function bytesToWordIndices(bytes: Uint8Array, count: number): number[] {
  const out: number[] = [];
  let acc = 0;
  let accBits = 0;
  let i = 0;
  while (out.length < count) {
    if (i >= bytes.length) throw new KeyholdError('config', 'not enough bytes for word indices');
    acc = (acc << 8) | bytes[i++]!;
    accBits += 8;
    if (accBits >= 11) {
      accBits -= 11;
      out.push((acc >>> accBits) & 0x7ff);
      acc &= (1 << accBits) - 1;
    }
  }
  return out;
}
