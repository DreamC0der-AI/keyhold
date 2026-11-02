/**
 * Seed-phrase login, server side: hand out a one-time challenge, check the Ed25519
 * signature against the public key. The server stores no email and no password; the public
 * key is the subject.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { fromBase64Url, randomBytes, toBase64Url } from '../../util/bytes.js';
import { KeyholdError } from '../../util/errors.js';
import { seedChallengeMessage, type Identity, type SeedChallenge } from '../types.js';
import type { TokenStore } from './store.js';

export interface SeedLoginConfig {
  store: TokenStore;
  /** Your site's origin, e.g. https://app.example.com. */
  origin: string;
  ttlMs?: number;
  now?: () => number;
}

const keyFor = (id: string) => `seed-challenge:${id}`;

export async function issueSeedChallenge(cfg: SeedLoginConfig): Promise<SeedChallenge> {
  const now = (cfg.now ?? Date.now)();
  const c: SeedChallenge = {
    id: toBase64Url(randomBytes(16)),
    nonce: toBase64Url(randomBytes(32)),
    origin: cfg.origin,
    expiresAt: now + (cfg.ttlMs ?? 5 * 60_000),
  };
  await cfg.store.put(keyFor(c.id), JSON.stringify(c), c.expiresAt);
  return c;
}

/** Verify `{ challengeId, publicKey, signature }` from the browser. Each challenge works once. */
export async function verifySeedLogin(
  cfg: SeedLoginConfig,
  input: { challengeId: string; publicKey: string; signature: string },
): Promise<Identity> {
  const raw = await cfg.store.take(keyFor(input.challengeId));
  if (!raw) throw new KeyholdError('code_expired', 'login challenge expired or already used; try again');
  const c = JSON.parse(raw) as SeedChallenge;
  if (c.expiresAt <= (cfg.now ?? Date.now)() || c.origin !== cfg.origin) {
    throw new KeyholdError('code_expired', 'login challenge expired; try again');
  }
  let ok = false;
  try {
    const pk = fromBase64Url(input.publicKey);
    ok = pk.length === 32 && ed25519.verify(fromBase64Url(input.signature), seedChallengeMessage(c), pk);
  } catch {
    ok = false;
  }
  if (!ok) throw new KeyholdError('auth_failed', 'seed login signature is invalid');
  return { provider: 'seed', subject: input.publicKey };
}
