/**
 * What every login method returns: proof of WHO the user is, nothing more.
 * Logging in never unlocks notes; that is keyhold/keys' job.
 *
 * Map (provider, subject) to your own account id in an identities table. Don't merge accounts
 * by email automatically: Apple often hands out private relay addresses.
 */
export interface Identity {
  /** 'google' | 'apple' | 'email' | 'seed', or your own OIDC provider id. */
  provider: string;
  /** Stable id within the provider: OIDC `sub`, the normalized email, or the seed public key. */
  subject: string;
  email?: string;
  emailVerified?: boolean;
  /** Apple: true for @privaterelay.appleid.com addresses. */
  privateEmail?: boolean;
  name?: string;
  picture?: string;
}

/** A seed-login challenge as the server hands it to the browser. */
export interface SeedChallenge {
  id: string;
  /** base64url random nonce. */
  nonce: string;
  /** The site the login is for. The browser refuses to sign a challenge for another origin. */
  origin: string;
  /** Unix ms. */
  expiresAt: number;
}

/** The exact bytes a seed identity signs. Domain-separated so the signature means nothing elsewhere. */
export function seedChallengeMessage(c: SeedChallenge): Uint8Array {
  return new TextEncoder().encode(['keyhold-login-v1', c.origin, c.id, c.nonce, String(c.expiresAt)].join('\n'));
}
