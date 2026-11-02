/**
 * keyhold/keys/browser — the browser-only pieces: real WebAuthn PRF and IndexedDB storage.
 * Import this only in front-end code.
 */
import { fromBase64Url, own, randomBytes, toBase64Url } from '../util/bytes.js';
import { KeyholdError } from '../util/errors.js';
import type { PrfProvider, PasskeyRegistration, PrfResult } from './passkey.js';
import type { DeviceRecord, DeviceStore } from './device.js';

type PrfOutputs = { enabled?: boolean; results?: { first?: BufferSource } };

function prfFrom(cred: PublicKeyCredential): PrfOutputs | undefined {
  return (cred.getClientExtensionResults() as { prf?: PrfOutputs }).prf;
}

function bytesOf(src: BufferSource): Uint8Array {
  return src instanceof ArrayBuffer ? new Uint8Array(src) : new Uint8Array(src.buffer, src.byteOffset, src.byteLength);
}

/** True when this browser exposes WebAuthn at all. PRF support is only known after a ceremony. */
export function webauthnAvailable(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function' && !!navigator.credentials;
}

/**
 * Real WebAuthn PRF. The challenge is random and local: unlocking doesn't need the server to
 * verify an assertion, only the PRF secret. (Passkey *sign-in* is a separate, server-checked flow.)
 */
export const webauthnPrf: PrfProvider = {
  async register({ rpId, rpName, user, prfSalt, excludeCredentialIds }): Promise<PasskeyRegistration> {
    if (!webauthnAvailable()) throw new KeyholdError('prf_unavailable', 'this browser has no passkey support');
    const cred = (await navigator.credentials.create({
      publicKey: {
        rp: { id: rpId, name: rpName },
        user: { id: own(user.id), name: user.name, displayName: user.displayName },
        challenge: randomBytes(32),
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 }, // ES256
          { type: 'public-key', alg: -257 }, // RS256
        ],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        excludeCredentials: (excludeCredentialIds ?? []).map((id) => ({ type: 'public-key' as const, id: fromBase64Url(id) })),
        extensions: { prf: { eval: { first: own(prfSalt) } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential | null;
    if (!cred) throw new KeyholdError('prf_unavailable', 'passkey creation was cancelled');
    const credentialId = toBase64Url(new Uint8Array(cred.rawId));
    const prf = prfFrom(cred);
    const first = prf?.results?.first;
    if (first) {
      return { credentialId, prfSupported: true, prf: { credentialId, output: own(bytesOf(first)), prfSalt: toBase64Url(prfSalt) } };
    }
    return { credentialId, prfSupported: prf?.enabled === true };
  },

  async evaluate({ rpId, credentials }): Promise<PrfResult> {
    if (!webauthnAvailable()) throw new KeyholdError('prf_unavailable', 'this browser has no passkey support');
    const evalByCredential: Record<string, { first: BufferSource }> = {};
    for (const c of credentials) evalByCredential[c.credentialId] = { first: fromBase64Url(c.prfSalt) };
    const cred = (await navigator.credentials.get({
      publicKey: {
        rpId,
        challenge: randomBytes(32),
        userVerification: 'required',
        allowCredentials: credentials.map((c) => ({ type: 'public-key' as const, id: fromBase64Url(c.credentialId) })),
        extensions: { prf: { evalByCredential } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential | null;
    if (!cred) throw new KeyholdError('prf_unavailable', 'passkey request was cancelled');
    const first = prfFrom(cred)?.results?.first;
    if (!first) throw new KeyholdError('prf_unavailable', 'this passkey or browser cannot unlock notes (no PRF)');
    return { credentialId: toBase64Url(new Uint8Array(cred.rawId)), output: own(bytesOf(first)) };
  },
};

/** Device records in IndexedDB. CryptoKeys are stored as-is (structured clone keeps them non-extractable). */
export class IndexedDbDeviceStore implements DeviceStore {
  constructor(
    private readonly dbName = 'keyhold',
    private readonly storeName = 'devices',
    private readonly idb: IDBFactory = globalThis.indexedDB,
  ) {}

  private db(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = this.idb.open(this.dbName, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(this.storeName)) req.result.createObjectStore(this.storeName, { keyPath: 'account' });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  private async run<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest): Promise<T> {
    const db = await this.db();
    try {
      return await new Promise<T>((resolve, reject) => {
        const tx = db.transaction(this.storeName, mode);
        const req = fn(tx.objectStore(this.storeName));
        tx.oncomplete = () => resolve(req.result as T);
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  }

  get(account: string) {
    return this.run<DeviceRecord | undefined>('readonly', (s) => s.get(account));
  }
  async put(record: DeviceRecord) {
    await this.run('readwrite', (s) => s.put(record));
  }
  async delete(account: string) {
    await this.run('readwrite', (s) => s.delete(account));
  }
}
