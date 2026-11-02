/**
 * Device envelopes: a per-device AES key, generated non-extractable and kept in the
 * browser (IndexedDB), wraps K. The envelope stays on the device too.
 *
 * Opening it needs no user gesture, so it is what "keep unlocked on this device" means,
 * and it is what lets an unlocked device re-open K for editing (new envelope, approving
 * another device) without asking for the passkey again. Apps that want a passkey tap on
 * every visit should not keep a device record, or should gate it behind their own lock screen.
 */
import { toBase64Url, randomBytes } from '../util/bytes.js';
import type { Envelope } from './envelope.js';

export interface DeviceRecord {
  account: string;
  deviceId: string;
  /** Non-extractable AES-GCM key with wrapKey/unwrapKey usages. Structured-cloneable into IndexedDB. */
  deviceKey: CryptoKey;
  envelope: Envelope<'device'>;
}

/** Where a device keeps its record. `IndexedDbDeviceStore` in keyhold/keys/browser; `MemoryDeviceStore` for tests. */
export interface DeviceStore {
  get(account: string): Promise<DeviceRecord | undefined>;
  put(record: DeviceRecord): Promise<void>;
  delete(account: string): Promise<void>;
}

export class MemoryDeviceStore implements DeviceStore {
  private map = new Map<string, DeviceRecord>();
  async get(account: string) {
    return this.map.get(account);
  }
  async put(record: DeviceRecord) {
    this.map.set(record.account, record);
  }
  async delete(account: string) {
    this.map.delete(account);
  }
}

export function newDeviceId(): string {
  return toBase64Url(randomBytes(12));
}

export async function generateDeviceKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}
