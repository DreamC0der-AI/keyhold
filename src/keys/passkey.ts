/**
 * Passkey envelopes via the WebAuthn PRF extension.
 *
 * A PRF-capable passkey turns a salt into 32 secret bytes that only that passkey can
 * produce (after Face ID / Touch ID / fingerprint / PIN). HKDF turns them into the key that
 * wraps K. The PRF output never leaves the browser.
 *
 * The WebAuthn calls live behind `PrfProvider` so apps can test with a fake and so the
 * pure parts work anywhere. `webauthnPrf` (keyhold/keys/browser) is the real one.
 */
import { randomBytes, toBase64Url } from '../util/bytes.js';
import { hkdfAesKey } from '../util/hkdf.js';
import { KeyholdError } from '../util/errors.js';
import type { Envelope, PasskeyParams } from './envelope.js';

export const PASSKEY_INFO = 'keyhold/v1/envelope/passkey';

export interface PrfCredential {
  /** base64url credential id. */
  credentialId: string;
  /** base64url PRF salt for this credential. */
  prfSalt: string;
}

export interface PrfResult {
  credentialId: string;
  /** 32 bytes. Wipe after use. */
  output: Uint8Array;
}

export interface PasskeyRegistration {
  credentialId: string;
  /** Present when the authenticator evaluated PRF during creation (or right after). */
  prf?: PrfResult & { prfSalt: string };
  /** False when the authenticator said it can't do PRF. Fall back to the vault password. */
  prfSupported: boolean;
}

export interface PasskeyUser {
  /** Opaque, stable user handle (max 64 bytes), e.g. the account id bytes. */
  id: Uint8Array;
  name: string;
  displayName: string;
}

/** The two WebAuthn operations keyhold needs. */
export interface PrfProvider {
  /** Make a new passkey and, if possible, evaluate PRF with `prfSalt`. */
  register(input: { rpId: string; rpName: string; user: PasskeyUser; prfSalt: Uint8Array; excludeCredentialIds?: string[] }): Promise<PasskeyRegistration>;
  /** Ask for any of `credentials` (empty = let the user pick a discoverable one) and evaluate its PRF. */
  evaluate(input: { rpId: string; credentials: PrfCredential[] }): Promise<PrfResult>;
}

export function newPrfSalt(): Uint8Array<ArrayBuffer> {
  return randomBytes(32);
}

export function passkeyParams(credentialId: string, prfSalt: Uint8Array, rpId: string): PasskeyParams {
  return { credentialId, prfSalt: toBase64Url(prfSalt), rpId };
}

export async function passkeyWrappingKey(prfOutput: Uint8Array): Promise<CryptoKey> {
  if (prfOutput.length < 32) throw new KeyholdError('prf_unavailable', 'PRF output too short');
  return hkdfAesKey(prfOutput, PASSKEY_INFO, ['wrapKey', 'unwrapKey']);
}

export type PasskeyEnvelope = Envelope<'passkey'>;
