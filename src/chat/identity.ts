/**
 * Identity: who someone is, separately from where to find them.
 *
 *   address (github:alice)  ->  where to find you. Never proof.
 *   root key (Ed25519)      ->  who you are. Years. Cold: only used to add or revoke devices.
 *   device key              ->  one per device, certified by the root. MLS members are devices.
 *
 * The public directory (box 3) holds a hash-chained, root-signed log: init, device-add,
 * device-revoke, profile, last-resort KeyPackage. Readers pin the root fingerprint and the
 * chain head on first use (TOFU) and detect a key change or a rewritten history after that.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 as sha256Sync } from '@noble/hashes/sha2.js';
import { concat, equalBytes, randomBytes, sha256, toHex, utf8, wipe } from '../util/bytes.js';
import { b64, canonicalJson, jsonBytes, parseJsonBytes, unb64 } from '../util/codec.js';
import { KeyholdError } from '../util/errors.js';
import type { Address, Bytes, PublicDirectory } from '../storage/interfaces.js';

const CERT_LABEL = 'keyhold/v1/device-cert';
const DIR_LABEL = 'keyhold/v1/directory';

export interface RootKey {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export function createRootKey(): RootKey {
  const secretKey = ed25519.utils.randomSecretKey();
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

export function rootFromSecret(secretKey: Uint8Array): RootKey {
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

export function wipeRoot(root: RootKey) {
  wipe(root.secretKey);
}

/** Hex SHA-256 of the root public key, domain-separated. This IS the identity. Synchronous. */
export function fingerprint(rootPublic: Uint8Array): string {
  return toHex(sha256Sync(concat(utf8('keyhold/v1/root:'), rootPublic)));
}

/**
 * Safety number for two identities: 60 digits in 12 groups of 5, the same on both sides.
 * Compared out of band (box 10). Built from both fingerprints, iterated to slow brute force.
 */
export async function safetyNumber(fpA: string, fpB: string): Promise<string> {
  const [x, y] = [fpA, fpB].sort();
  let h: Uint8Array = utf8(`keyhold/v1/safety:${x}:${y}`);
  for (let i = 0; i < 5200; i++) h = await sha256(h);
  const more = await sha256(concat(h, utf8('2')));
  const bytes = concat(h, more);
  const groups: string[] = [];
  for (let i = 0; i < 12; i++) {
    const n = ((bytes[i * 5]! << 24) | (bytes[i * 5 + 1]! << 16) | (bytes[i * 5 + 2]! << 8) | bytes[i * 5 + 3]!) >>> 0;
    groups.push(String((n * 256 + bytes[i * 5 + 4]!) % 100000).padStart(5, '0'));
  }
  return groups.join(' ');
}

// ---- Device certificates -------------------------------------------------------------------

export interface DeviceCertificate {
  v: 1;
  /** Root public key, base64url. */
  root: string;
  /** Device signature public key (the MLS leaf key), base64url. */
  device: string;
  deviceId: string;
  /** Address the owner claims. Self-asserted: the channel fence and invites check it, not this. */
  address: Address;
  issuedAt: number;
  sig: string;
}

function certBody(c: Omit<DeviceCertificate, 'sig'> | DeviceCertificate): Uint8Array {
  const { sig: _s, ...rest } = c as DeviceCertificate;
  return concat(utf8(CERT_LABEL), jsonBytes(rest));
}

export function issueDeviceCertificate(root: RootKey, devicePublic: Uint8Array, deviceId: string, address: Address, now = Date.now()): DeviceCertificate {
  const body = { v: 1 as const, root: b64(root.publicKey), device: b64(devicePublic), deviceId, address, issuedAt: now };
  return { ...body, sig: b64(ed25519.sign(certBody(body), root.secretKey)) };
}

export function verifyDeviceCertificate(c: DeviceCertificate): boolean {
  try {
    return c.v === 1 && ed25519.verify(unb64(c.sig), certBody(c), unb64(c.root));
  } catch {
    return false;
  }
}

/** The certificate travels as the MLS basic credential's identity bytes. */
export function certificateToCredential(c: DeviceCertificate): { credentialType: 'basic'; identity: Uint8Array } {
  return { credentialType: 'basic', identity: utf8(canonicalJson(c)) };
}

export function certificateFromCredential(cred: { credentialType: string; identity?: Uint8Array }): DeviceCertificate | undefined {
  if (cred.credentialType !== 'basic' || !cred.identity) return undefined;
  try {
    const c = parseJsonBytes<DeviceCertificate>(cred.identity);
    return c && c.v === 1 && typeof c.root === 'string' && typeof c.device === 'string' ? c : undefined;
  } catch {
    return undefined;
  }
}

// ---- Directory log -------------------------------------------------------------------------

export type DirectoryEntryType = 'init' | 'device-add' | 'device-revoke' | 'profile' | 'last-resort-kp';

export interface DirectoryEntry {
  v: 1;
  i: number;
  /** base64url SHA-256 of the previous entry's bytes; "" for the first. */
  prev: string;
  root: string;
  t: DirectoryEntryType;
  ts: number;
  body: Record<string, unknown>;
  sig: string;
}

export interface Profile {
  name?: string;
  avatar?: string;
}

export interface DirectoryView {
  root: Uint8Array;
  fingerprint: string;
  address: Address;
  /** Active devices by device public key (base64url). */
  devices: Map<string, DeviceCertificate>;
  revoked: Set<string>;
  profile: Profile;
  /** Encoded MLS KeyPackage message, if one is published. */
  lastResortKeyPackage?: Uint8Array;
  /** base64url hash of each entry, by index. */
  hashes: string[];
}

function entryBody(e: Omit<DirectoryEntry, 'sig'> | DirectoryEntry) {
  const { sig: _s, ...rest } = e as DirectoryEntry;
  return concat(utf8(DIR_LABEL), jsonBytes(rest));
}

/** Verify a whole directory: signatures, one root, intact hash chain. Throws on any problem. */
export async function verifyDirectory(entries: Bytes[]): Promise<DirectoryView | undefined> {
  if (entries.length === 0) return undefined;
  let prev = '';
  let view: DirectoryView | undefined;
  for (let i = 0; i < entries.length; i++) {
    const bytes = entries[i]!;
    const e = parseJsonBytes<DirectoryEntry>(bytes, 'directory entry');
    if (e.v !== 1 || e.i !== i || e.prev !== prev) throw new KeyholdError('rewrite_detected', `directory chain broken at ${i}`);
    const rootPub = unb64(e.root);
    let ok = false;
    try {
      ok = ed25519.verify(unb64(e.sig), entryBody(e), rootPub);
    } catch {
      ok = false;
    }
    if (!ok) throw new KeyholdError('bad_signature', `directory entry ${i} has a bad signature`);
    if (i === 0) {
      if (e.t !== 'init' || typeof e.body.address !== 'string') throw new KeyholdError('bad_format', 'directory must start with init');
      view = { root: rootPub, fingerprint: fingerprint(rootPub), address: e.body.address, devices: new Map(), revoked: new Set(), profile: {}, hashes: [] };
    } else if (!equalBytes(rootPub, view!.root)) {
      throw new KeyholdError('bad_signature', `directory entry ${i} is signed by a different root`);
    }
    const v = view!;
    if (e.t === 'device-add') {
      const cert = e.body.cert as DeviceCertificate;
      if (!verifyDeviceCertificate(cert) || cert.root !== e.root) throw new KeyholdError('bad_signature', 'bad device certificate');
      if (!v.revoked.has(cert.device)) v.devices.set(cert.device, cert);
    } else if (e.t === 'device-revoke') {
      const d = String(e.body.device);
      v.devices.delete(d);
      v.revoked.add(d);
    } else if (e.t === 'profile') {
      v.profile = { name: e.body.name as string | undefined, avatar: e.body.avatar as string | undefined };
    } else if (e.t === 'last-resort-kp') {
      v.lastResortKeyPackage = e.body.kp ? unb64(String(e.body.kp)) : undefined;
    }
    prev = b64(await sha256(bytes));
    v.hashes.push(prev);
  }
  return view;
}

/** Writes the caller's own directory. Needs the root key, so it runs on a device that holds it. */
export class DirectoryWriter {
  constructor(
    private directory: PublicDirectory,
    private self: Address,
    private now: () => number = Date.now,
  ) {}

  async append(root: RootKey, t: DirectoryEntryType, body: Record<string, unknown>): Promise<DirectoryView> {
    for (let attempt = 0; attempt < 5; attempt++) {
      const current = await this.directory.read(this.self);
      const view = await verifyDirectory(current);
      if (view && !equalBytes(view.root, root.publicKey)) throw new KeyholdError('key_changed', 'this directory belongs to another root key');
      if (!view && t !== 'init') throw new KeyholdError('config', 'publish the identity (init) first');
      const i = current.length;
      const base = { v: 1 as const, i, prev: view ? view.hashes[i - 1]! : '', root: b64(root.publicKey), t, ts: this.now(), body };
      const entry: DirectoryEntry = { ...base, sig: b64(ed25519.sign(entryBody(base), root.secretKey)) };
      if ((await this.directory.append(i, jsonBytes(entry))) === 'ok') {
        return (await verifyDirectory([...current, jsonBytes(entry)]))!;
      }
    }
    throw new KeyholdError('conflict', 'directory kept changing; try again');
  }

  /** First publish: the identity plus this device. */
  async publish(root: RootKey, firstDevice: DeviceCertificate, profile?: Profile) {
    const existing = await verifyDirectory(await this.directory.read(this.self));
    if (!existing) await this.append(root, 'init', { address: this.self });
    let v = await this.append(root, 'device-add', { cert: firstDevice });
    if (profile) v = await this.append(root, 'profile', { ...profile });
    return v;
  }

  addDevice(root: RootKey, cert: DeviceCertificate) {
    return this.append(root, 'device-add', { cert });
  }

  revokeDevice(root: RootKey, devicePublicB64: string) {
    return this.append(root, 'device-revoke', { device: devicePublicB64 });
  }

  setProfile(root: RootKey, profile: Profile) {
    return this.append(root, 'profile', { ...profile });
  }

  setLastResortKeyPackage(root: RootKey, kp: Uint8Array | undefined) {
    return this.append(root, 'last-resort-kp', { kp: kp ? b64(kp) : '' });
  }
}

// ---- Trust on first use --------------------------------------------------------------------

export interface Pin {
  fingerprint: string;
  index: number;
  hash: string;
  /** Set when the user compared safety numbers. */
  verified?: boolean;
}

/** Where pins live. The chat client backs this with contacts in the personal store (box 12). */
export interface PinStore {
  get(address: Address): Promise<Pin | undefined>;
  set(address: Address, pin: Pin): Promise<void>;
}

export class MemoryPinStore implements PinStore {
  readonly pins = new Map<Address, Pin>();
  async get(a: Address) {
    return this.pins.get(a);
  }
  async set(a: Address, p: Pin) {
    this.pins.set(a, p);
  }
}

export type LookupResult =
  | { status: 'ok'; view: DirectoryView; firstSeen: boolean }
  | { status: 'none' }
  /** The root key differs from the pinned one: a new identity or an attack. Never auto-accepted. */
  | { status: 'key-changed'; view: DirectoryView; pinned: Pin };

/**
 * Looks up and caches directories. A rewritten history throws `rewrite_detected`;
 * a different root returns `key-changed` and keeps the old pin until the user accepts.
 */
export class IdentityRegistry {
  private cache = new Map<Address, { view: DirectoryView; at: number }>();
  constructor(
    private directory: PublicDirectory,
    readonly pins: PinStore = new MemoryPinStore(),
    private now: () => number = Date.now,
  ) {}

  async lookup(address: Address): Promise<LookupResult> {
    const view = await verifyDirectory(await this.directory.read(address));
    if (!view) return { status: 'none' };
    if (view.address !== address) throw new KeyholdError('bad_format', `directory of ${address} claims to be ${view.address}`);
    const pin = await this.pins.get(address);
    if (pin && pin.fingerprint !== view.fingerprint) return { status: 'key-changed', view, pinned: pin };
    if (pin && view.hashes[pin.index] !== pin.hash) {
      throw new KeyholdError('rewrite_detected', `the directory of ${address} was rewritten`);
    }
    const head = view.hashes.length - 1;
    await this.pins.set(address, { ...(pin ?? {}), fingerprint: view.fingerprint, index: head, hash: view.hashes[head]! });
    this.cache.set(address, { view, at: this.now() });
    return { status: 'ok', view, firstSeen: !pin };
  }

  /** User accepted a key change (after comparing safety numbers, ideally). */
  async acceptKeyChange(address: Address, view: DirectoryView) {
    const head = view.hashes.length - 1;
    await this.pins.set(address, { fingerprint: view.fingerprint, index: head, hash: view.hashes[head]! });
    this.cache.set(address, { view, at: this.now() });
  }

  async markVerified(address: Address) {
    const pin = await this.pins.get(address);
    if (pin) await this.pins.set(address, { ...pin, verified: true });
  }

  cached(address: Address): DirectoryView | undefined {
    return this.cache.get(address)?.view;
  }

  cachedAt(address: Address): number | undefined {
    return this.cache.get(address)?.at;
  }

  /** Synchronous check against cached directories (used inside MLS validation callbacks). */
  isRevoked(devicePublicB64: string, address: Address): boolean {
    return this.cache.get(address)?.view.revoked.has(devicePublicB64) ?? false;
  }
}

/** Random device id, stable for the device's life. */
export function newDeviceId(): string {
  return toHex(randomBytes(8));
}
