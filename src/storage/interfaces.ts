/**
 * keyhold/storage — provider interfaces.
 *
 * One small interface per storage kind. A provider (GitHub, in-memory, a server, ...) is a
 * set of these, bound to one signed-in user, plus `ChannelAccess` for the channel side
 * effects (create a shared space, let someone in, take access away).
 *
 * Everything that crosses these interfaces is opaque bytes produced by keyhold: providers
 * never see plaintext and never make a security decision. Access rules are a second fence;
 * secrecy and integrity come from the encryption and signatures above.
 */
import type { StorageKindKey } from './requirements.js';

export type Bytes = Uint8Array;

/** Where to find someone on a channel, e.g. "github:alice". An address is never proof of identity. */
export type Address = string;

/** A shared, members-only container for one conversation (on GitHub: one private repo). */
export type SpaceRef = string;

/** Result of a compare-and-swap write. */
export type CasResult = 'ok' | 'conflict';

// ---- Device (1, 2) -------------------------------------------------------------------------

/** Box 1. Never leaves the device. */
export interface DeviceKeystore {
  get(key: string): Promise<Bytes | undefined>;
  put(key: string, value: Bytes): Promise<void>;
  delete(key: string): Promise<void>;
  keys(prefix?: string): Promise<string[]>;
}

/** Box 2. Must really delete; entries may carry an expiry. */
export interface EphemeralKeyStore {
  get(key: string): Promise<Bytes | undefined>;
  put(key: string, value: Bytes, options?: { expiresAt?: number }): Promise<void>;
  /** Read and delete in one step. */
  take(key: string): Promise<Bytes | undefined>;
  delete(key: string): Promise<void>;
  /** Delete everything past its expiry. Returns how many entries were removed. */
  purgeExpired(now?: number): Promise<number>;
  keys(prefix?: string): Promise<string[]>;
}

// ---- Public (3) ----------------------------------------------------------------------------

/** Box 3. Anyone reads, only the owner appends. Readers detect rewrites with the hash chain. */
export interface PublicDirectory {
  /** All entries of `owner`'s directory in order, or [] if they have none. */
  read(owner: Address): Promise<Bytes[]>;
  /** Append to the caller's own directory at exactly `index`. */
  append(index: number, entry: Bytes): Promise<CasResult>;
}

/**
 * Box 3b (build option preKeys): one reusable pre-key (an MLS KeyPackage) per device, public,
 * replaced on rotation. Each one is signed by its device key and carries the root-signed device
 * certificate, so readers check it against the owner's directory; the store itself is trusted
 * for nothing but availability.
 */
export interface PreKeyStore {
  /** Replace this device's pre-key. */
  publish(deviceId: string, data: Bytes): Promise<void>;
  /** Every pre-key `owner` has published, one per device, in no particular order. */
  read(owner: Address): Promise<Bytes[]>;
}

// ---- Server-enforced (4, 11) ---------------------------------------------------------------

/** Box 4 (build option). The owner uploads items; each is handed to exactly one taker. */
export interface ClaimOnceStore {
  publish(items: Bytes[], options?: { expiresAt?: number }): Promise<void>;
  claim(owner: Address): Promise<Bytes | undefined>;
  remaining(): Promise<number>;
}

export interface InviteNotice {
  /** Channel-specific pointer that `ChannelAccess.acceptGrant` understands (a GitHub invitation id). */
  pointer: string;
  /** Optional opaque payload; only when the provider has the `inbox-payload` capability. */
  payload?: Bytes;
}

export interface ReceivedNotice extends InviteNotice {
  id: string;
  from: Address;
  expiresAt: number;
}

/** Box 11. Anyone writes, only the recipient reads; rate-limited and expiring. */
export interface InviteInbox {
  send(to: Address, notice: InviteNotice): Promise<void>;
  list(): Promise<ReceivedNotice[]>;
  delete(id: string): Promise<void>;
}

// ---- Members of one space (5, 6, 7, 8) -----------------------------------------------------

/** Box 5. One agreed order: an append succeeds only at the next free index. */
export interface OrderedLog {
  read(space: SpaceRef, fromIndex: number): Promise<Bytes[]>;
  append(space: SpaceRef, index: number, entry: Bytes): Promise<CasResult>;
}

export interface MailboxItem {
  id: string;
  data: Bytes;
}

/**
 * Box 6. Append in any order. The cursor is opaque and provider-defined.
 *
 * Retries (optional, with `newId`): a caller that lost the reply to a post doesn't know whether
 * it landed. It takes an id from `newId()` before the first try and passes the same id on every
 * try, so the item lands once. Posting with an id that already holds the same bytes is a
 * success; the same id with different bytes is a 'conflict' error. The provider may still store
 * the item under another id (say, when the id is too old for its listing order) and returns the
 * id it used: callers always keep the returned id. Providers without `newId` ignore `options`.
 */
export interface Mailbox {
  /** Optional: a fresh item id for a later `post` / `postMany`, made locally (no network). */
  newId?(): string;
  post(space: SpaceRef, data: Bytes, options?: { id?: string }): Promise<string>;
  /**
   * Optional: post several items in one write, all or none, and return their ids in order.
   * Readers see them as ordinary items, listed in the order given. Without it, callers post
   * one at a time. `options.ids` (one per item, from `newId`) works as for `post`.
   */
  postMany?(space: SpaceRef, data: Bytes[], options?: { ids?: string[] }): Promise<string[]>;
  list(space: SpaceRef, cursor?: string): Promise<{ items: MailboxItem[]; cursor: string }>;
}

/** Box 7. Large objects, each sealed with its own key by the caller. */
export interface BlobStore {
  put(space: SpaceRef, data: Bytes): Promise<string>;
  get(space: SpaceRef, ref: string): Promise<Bytes | undefined>;
  delete(space: SpaceRef, ref: string): Promise<void>;
}

/** Box 8. Items for one recipient inside a space; deleted after reading. */
export interface DropBox {
  put(space: SpaceRef, recipientTag: string, data: Bytes): Promise<string>;
  /** Optional: several items, for any recipients, in one write. Returns their ids in order. */
  putMany?(space: SpaceRef, items: { tag: string; data: Bytes }[]): Promise<string[]>;
  list(space: SpaceRef, recipientTag: string): Promise<MailboxItem[]>;
  delete(space: SpaceRef, recipientTag: string, id: string): Promise<void>;
}

// ---- Only me (9, 12) -----------------------------------------------------------------------

export interface Versioned {
  data: Bytes;
  version: string;
}

/** Box 9. Cold, one sealed document per name. `expected` null = must not exist yet. */
export interface BackupVault {
  get(name: string): Promise<Versioned | undefined>;
  put(name: string, data: Bytes, expected: string | null): Promise<CasResult>;
}

/** Box 12. Many small sealed items with opaque ids, compare-and-swap per item. */
export interface PersonalStore {
  list(): Promise<{ id: string; version: string }[]>;
  get(id: string): Promise<Versioned | undefined>;
  /** `expected` null = create only. */
  put(id: string, data: Bytes, expected: string | null): Promise<CasResult>;
  delete(id: string, expected: string): Promise<CasResult>;
}

// ---- Channel side effects ------------------------------------------------------------------

export type GrantResult =
  | { status: 'invited'; pointer: string }
  | { status: 'already-member' }
  /** This caller can't change access on this channel (on GitHub: not the repo owner). */
  | { status: 'needs-manager' };

export interface ChannelAccess {
  readonly self: Address;
  /** Create a new members-only space. `label` must be neutral: the channel sees it. */
  createSpace(label: string): Promise<SpaceRef>;
  /** Spaces the caller can open now. */
  listSpaces(): Promise<SpaceRef[]>;
  /** Whether the caller can grant and revoke access in this space. */
  canManage(space: SpaceRef): Promise<boolean>;
  /** Addresses with access, and those with a pending invitation. */
  members(space: SpaceRef): Promise<{ active: Address[]; pending: Address[] }>;
  grant(space: SpaceRef, address: Address): Promise<GrantResult>;
  /** Accept a grant using the pointer from an invite notice. Accepting twice is harmless. */
  acceptGrant(pointer: string): Promise<void>;
  revoke(space: SpaceRef, address: Address): Promise<'done' | 'needs-manager'>;
}

// ---- The provider --------------------------------------------------------------------------

/**
 * Optional features a provider may or may not have. Products turn features on to match.
 * - `claim-once`: provides box 4, so offline adds are possible.
 * - `inbox-payload`: invite notices can carry an opaque payload (else only a pointer).
 * - `true-delete`: deleted items are gone from the channel (GitHub keeps git history).
 * - `owner-managed-spaces`: only the space creator can grant or revoke access.
 */
export type Capability = 'claim-once' | 'inbox-payload' | 'true-delete' | 'owner-managed-spaces' | 'pre-keys';

export interface ProviderLimits {
  maxBlobBytes: number;
  maxItemBytes: number;
}

/** A provider bound to one signed-in user. Kinds 1, 2 and 10 are device-side and not included. */
export interface StorageProvider {
  readonly name: string;
  readonly capabilities: ReadonlySet<Capability>;
  readonly limits: ProviderLimits;
  readonly directory: PublicDirectory;
  readonly claimOnce?: ClaimOnceStore;
  readonly preKeys?: PreKeyStore;
  readonly inviteInbox: InviteInbox;
  readonly orderedLog: OrderedLog;
  readonly mailbox: Mailbox;
  readonly blobs: BlobStore;
  readonly dropBox: DropBox;
  readonly vault: BackupVault;
  readonly personal: PersonalStore;
  readonly channel: ChannelAccess;
}

/** Device-side stores (boxes 1 and 2). In a browser: IndexedDB with non-extractable keys. */
export interface DeviceStorage {
  readonly keystore: DeviceKeystore;
  readonly ephemeral: EphemeralKeyStore;
}

/** Which provider field implements each remote kind. */
export const PROVIDER_FIELD: Partial<Record<StorageKindKey, keyof StorageProvider>> = {
  directory: 'directory',
  claimOnce: 'claimOnce',
  inviteInbox: 'inviteInbox',
  orderedLog: 'orderedLog',
  mailbox: 'mailbox',
  blobs: 'blobs',
  dropBox: 'dropBox',
  vault: 'vault',
  personal: 'personal',
};
