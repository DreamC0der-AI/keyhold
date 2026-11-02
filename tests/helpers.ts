import type { PrfProvider } from '../src/keys/index.js';
import { fromBase64Url, toBase64Url, randomBytes } from '../src/util/bytes.js';
import type { Argon2idFn } from '../src/keys/index.js';

/**
 * Fake authenticator: each credential has a secret; PRF(salt) = HMAC(secret, "WebAuthn PRF\0" || salt),
 * the same shape as real hmac-secret.
 */
export function fakeAuthenticator(opts: { prfOnCreate?: boolean; prfSupported?: boolean } = {}) {
  const creds = new Map<string, Uint8Array>();
  let pick: string | undefined;
  async function prf(secret: Uint8Array, salt: Uint8Array) {
    const key = await crypto.subtle.importKey('raw', secret as Uint8Array<ArrayBuffer>, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const input = new Uint8Array([...new TextEncoder().encode('WebAuthn PRF'), 0, ...salt]);
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, input));
  }
  const provider: PrfProvider = {
    async register({ prfSalt }) {
      const id = toBase64Url(randomBytes(16));
      creds.set(id, randomBytes(32));
      if (opts.prfSupported === false) return { credentialId: id, prfSupported: false };
      if (opts.prfOnCreate === false) return { credentialId: id, prfSupported: true };
      return { credentialId: id, prfSupported: true, prf: { credentialId: id, output: await prf(creds.get(id)!, prfSalt), prfSalt: toBase64Url(prfSalt) } };
    },
    async evaluate({ credentials }) {
      const c = (pick && credentials.find((x) => x.credentialId === pick)) || credentials.find((x) => creds.has(x.credentialId));
      if (!c) throw new Error('no matching passkey on this fake device');
      return { credentialId: c.credentialId, output: await prf(creds.get(c.credentialId)!, fromBase64Url(c.prfSalt)) };
    },
  };
  return {
    provider,
    creds,
    /** Make the "user" choose this credential next. */
    choose(id: string | undefined) {
      pick = id;
    },
  };
}

/** Cheap Argon2 params for tests (real default is 64 MiB / 3 passes). */
export const testArgon2Params = { m: 256, t: 1, p: 1 };

export const countingArgon2 = (inner: Argon2idFn) => {
  let calls = 0;
  const fn: Argon2idFn = async (x) => {
    calls++;
    return inner(x);
  };
  return { fn, calls: () => calls };
};
