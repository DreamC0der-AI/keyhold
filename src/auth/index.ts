/**
 * keyhold/auth — browser side of login.
 *
 * Google, Apple and email-code login are redirects / form posts handled by your server
 * with keyhold/auth/server; the browser just navigates. The only client-side crypto is the
 * self-custody seed route: derive the Ed25519 identity from the seed and sign a challenge.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { toBase64Url } from '../util/bytes.js';
import { KeyholdError } from '../util/errors.js';
import { deriveSeedSecrets } from '../seed/index.js';
import { seedChallengeMessage, type SeedChallenge } from './types.js';

export * from './types.js';
export { KeyholdError } from '../util/errors.js';

export interface SeedIdentity {
  /** base64url Ed25519 public key. This is the account's id on the server. */
  publicKey: string;
  /** Sign a server challenge. Checks the challenge is for `expectedOrigin` and not expired. */
  signChallenge(challenge: SeedChallenge, expectedOrigin: string, now?: number): string;
  /** Forget the secret key. */
  destroy(): void;
}

/** Build the identity from `deriveSeedSecrets(phrase).identitySeed`. */
export function seedIdentityFromSecret(identitySeed: Uint8Array): SeedIdentity {
  if (identitySeed.length !== 32) throw new KeyholdError('config', 'identity seed must be 32 bytes');
  let sk: Uint8Array | undefined = Uint8Array.from(identitySeed);
  const publicKey = toBase64Url(ed25519.getPublicKey(sk));
  return {
    publicKey,
    signChallenge(challenge, expectedOrigin, now = Date.now()) {
      if (!sk) throw new KeyholdError('config', 'identity was destroyed');
      if (challenge.origin !== expectedOrigin) {
        throw new KeyholdError('auth_failed', `refusing to sign a login for ${challenge.origin}`);
      }
      if (challenge.expiresAt < now) throw new KeyholdError('code_expired', 'login challenge expired; try again');
      return toBase64Url(ed25519.sign(seedChallengeMessage(challenge), sk));
    },
    destroy() {
      sk?.fill(0);
      sk = undefined;
    },
  };
}

/**
 * From a seed phrase to both halves at once: the login identity and the recovery secret
 * for keyhold/keys (`KeyEditor.addSeedRecovery` / `unlockWithRecovery`).
 */
export async function seedLogin(phrase: string): Promise<{ identity: SeedIdentity; recoverySecret: Uint8Array }> {
  const { identitySeed, recoverySecret } = await deriveSeedSecrets(phrase);
  try {
    return { identity: seedIdentityFromSecret(identitySeed), recoverySecret };
  } finally {
    identitySeed.fill(0);
  }
}
