/**
 * The chat client: MLS groups (a DM is a group of two) on top of the storage kinds.
 *
 *   box 5 ordered log  : genesis, commits, proposals; each entry carries the GroupInfo of the
 *                        epoch it creates, so anyone invited can external-join. Hash-chained.
 *   box 6 mailbox      : MLS application messages.
 *   box 7 blobs        : attachments, each sealed with its own key.
 *   box 8 drop box     : invite tickets and Welcomes for one recipient, deleted after reading.
 *   box 11 inbox       : "you have an invite" pointers.
 *   box 1 / box 2      : device identity / MLS group state and one-time KeyPackage secrets.
 *
 * Joining is "join on accept": the inviter writes a signed ticket and grants channel access;
 * the invitee accepts, then commits its own external join carrying the ticket. With the
 * offlineAdd build option (box 4), a member can instead add someone who is offline.
 */
import * as mls from 'ts-mls';
import { unprotectPrivateMessage } from 'ts-mls/messageProtection.js';
import { makeKeyPackageRef } from 'ts-mls/keyPackage.js';
import { decodeRatchetTree } from 'ts-mls/ratchetTree.js';
import { decryptSenderData } from 'ts-mls/privateMessage.js';
import { decryptGroupInfo, decryptGroupSecrets } from 'ts-mls/welcome.js';
import { accumulatePskSecret } from 'ts-mls/pskIndex.js';
import { randomBytes, sha256, toHex, utf8 } from '../util/bytes.js';
import { b64, canonicalJson, jsonBytes, parseJsonBytes, unb64 } from '../util/codec.js';
import { KeyholdError } from '../util/errors.js';
import { open as openSealed, seal } from '../crypto/index.js';
import type { Address, Bytes, DeviceStorage, SpaceRef, StorageProvider } from '../storage/interfaces.js';
import type { Features } from '../storage/features.js';
import {
  certificateFromCredential,
  certificateToCredential,
  fingerprint,
  issueDeviceCertificate,
  verifyDeviceCertificate,
  type DeviceCertificate,
  type DirectoryView,
  type IdentityRegistry,
  type LookupResult,
  type RootKey,
} from './identity.js';
import {
  checkCommit,
  decodePolicy,
  decodeTicket,
  defaultPolicy,
  encodePolicy,
  encodeTicket,
  signTicket,
  verifyTicket,
  assertAllowed,
  sameOwner,
  type GroupPolicy,
  type InviteTicket,
  type MemberLeaf,
  type ProposalSummary,
  type VerifiedTicket,
  POLICY_EXTENSION,
} from './policy.js';
import { decodeAppMessage, encodeAppMessage, newMessageId, type AppContent, type AppMessage, type AttachmentRef } from './messages.js';

export const CIPHERSUITE: mls.CiphersuiteName = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';
const DAY = 86_400_000;
let implPromise: Promise<mls.CiphersuiteImpl> | undefined;
export const ciphersuite = () => (implPromise ??= mls.getCiphersuiteImpl(mls.getCiphersuiteFromName(CIPHERSUITE)));

// ---- Device identity (box 1) ---------------------------------------------------------------

export interface DeviceIdentity {
  deviceId: string;
  address: Address;
  cert: DeviceCertificate;
  /** Root fingerprint: who this device belongs to. */
  fingerprint: string;
  publicKey: Uint8Array;
  signKey: Uint8Array;
}

const IDENTITY_KEY = 'chat/device-identity';

/** Make this device's signing key and have the root certify it. Kept in the device keystore. */
export async function createDeviceIdentity(device: DeviceStorage, root: RootKey, address: Address, deviceId: string, now = Date.now()): Promise<DeviceIdentity> {
  const cs = await ciphersuite();
  const kp = await cs.signature.keygen();
  const cert = issueDeviceCertificate(root, kp.publicKey, deviceId, address, now);
  const id: DeviceIdentity = { deviceId, address, cert, fingerprint: fingerprint(root.publicKey), publicKey: kp.publicKey, signKey: kp.signKey };
  await saveDeviceIdentity(device, id);
  return id;
}

/** Two-step version for a new device: make the key here, get it certified by a device with the root. */
export async function newDeviceKey() {
  return (await ciphersuite()).signature.keygen();
}

export async function saveDeviceIdentity(device: DeviceStorage, id: DeviceIdentity) {
  await device.keystore.put(IDENTITY_KEY, jsonBytes({ ...id, publicKey: b64(id.publicKey), signKey: b64(id.signKey) }));
}

export async function loadDeviceIdentity(device: DeviceStorage): Promise<DeviceIdentity | undefined> {
  const raw = await device.keystore.get(IDENTITY_KEY);
  if (!raw) return undefined;
  const j = parseJsonBytes<DeviceIdentity & { publicKey: string; signKey: string }>(raw);
  return { ...j, publicKey: unb64(j.publicKey), signKey: unb64(j.signKey) };
}

// ---- Log entries (box 5) -------------------------------------------------------------------

interface LogEntry {
  v: 1;
  i: number;
  prev: string;
  kind: 'genesis' | 'commit' | 'proposal';
  /** Epoch after this entry (decimal string). */
  epoch: string;
  mls?: string;
  /** GroupInfo (with ratchet tree and external pub) for `epoch`. */
  gi?: string;
  /**
   * The committer's mailbox cursor when it made this commit: mail listed after it may have been
   * posted after the commit. Someone this commit adds reads repeated fast sends only from there.
   */
  mail?: string;
}

const hashEntry = async (b: Bytes) => b64(await sha256(b));
const canonical = (v: unknown) => canonicalJson(v);

function encodeMsg(m: mls.MLSMessage): Uint8Array {
  return mls.encodeMlsMessage(m);
}

function decodeMsg(b: Uint8Array): mls.MLSMessage {
  const d = mls.decodeMlsMessage(b, 0);
  if (!d) throw new KeyholdError('bad_format', 'not an MLS message');
  return d[0];
}

async function groupInfoBytes(state: mls.ClientState, cs: mls.CiphersuiteImpl) {
  const gi = await mls.createGroupInfoWithExternalPubAndRatchetTree(state, [], cs);
  return b64(encodeMsg({ wireformat: 'mls_group_info', version: 'mls10', groupInfo: gi }));
}

// ---- Persistent group metadata (box 1) and state (box 2) -----------------------------------

interface GroupMeta {
  v: 1;
  groupId: string;
  space: SpaceRef;
  logNext: number;
  lastHash: string;
  /** Hashes of processed entries, by index, to notice a rewrite of what we already saw. */
  hashes: string[];
  ownEntries: number[];
  mailCursor?: string;
  ownMail: string[];
  pending: { id: string; data: string; epoch: string }[];
  usedNonces: string[];
  sentSinceUpdate: number;
  lastUpdateAt: number;
  needsHeal: boolean;
  /** When this device last made channel access follow the group (space managers only). */
  lastReconcile?: number;
  /** This device issued an address-only invite that expires at this time. */
  awaitingUpgradeUntil?: number;
  name?: string;
  /** Group picture from the newest admin `meta` message ('' = removed). Opaque to keyhold. */
  avatar?: string;
  removed?: boolean;
  /** The channel refuses us (for example the owner revoked access after removing us). */
  accessLost?: boolean;
  /** Our leaf came from a pre-key: commit a fresh one (cleared only by a commit of ours). */
  freshLeaf?: boolean;
  /** Epoch we joined at: older mail can't be ours to read, so it is skipped quietly. */
  joinedEpoch?: string;
  /**
   * The group went on in a way this device can't follow (a fork, or a commit we missed): rejoin
   * from `gi`, the newest GroupInfo of the log, at the next automation step. `at` is its index.
   */
  rejoin?: { at: number; gi: string };
  /** When this device first saw each device leaf that was added but hasn't joined (admins clean up). */
  unjoinedSince?: Record<string, number>;
  /**
   * When this device last made a channel invitation for each address. Once that invitation is
   * gone (declined, expired, withdrawn), their unjoined leaves go at once, with no grace period.
   */
  grantedAt?: Record<string, number>;
  /** Our messages, encrypted and saved, not yet known to be posted. A retry posts the same bytes. */
  outbox?: OutboxItem[];
  /**
   * Messages sent without a sync first (`sendFreshMs`), with the epoch they were encrypted in.
   * If a later sync finds the group had already moved on, they are sent again in the new epoch.
   */
  fastSent?: { message: AppMessage; epoch: string; at: number; tries?: number; hash?: string }[];
  /**
   * Joined by our own commit (no Welcome), so mail from before the join was never listed here. A
   * repeated fast send (`orig`) is then ours to read only if we saw its original (`seenHashes`),
   * i.e. it was posted after we joined; one posted before we joined stays unread, as it would
   * have without the repeat.
   */
  joinedByCommit?: boolean;
  /**
   * Added by someone else's Welcome (and no device of ours was in before): the adder's mailbox
   * cursor at the add (`LogEntry.mail`). A repeated fast send is ours only if its original was
   * listed after that cursor, i.e. it may have been posted after we were added.
   */
  addedAtMail?: string;
  /** When we joined by that Welcome: the check above stops after a day (repeats come soon). */
  addedAtMailSince?: number;
  /** Recent messages from others marked `fast`, by epoch: retracted if we turn out to be removed. */
  fastSeen?: { id: string; epoch: string }[];
  /** Hashes of our recent ciphertexts: our own mail even when we never learnt its id. */
  ownHashes?: string[];
  /** Hashes of recent mail from others: a copy posted twice is opened once. */
  seenHashes?: string[];
  /** Decrypted messages not yet taken by `onMessage` (it threw), oldest first. */
  undelivered?: StoredMessage[];
  /** Application-message generations seen, by "epoch:senderLeaf", to notice dropped messages. */
  gens?: Record<string, GenTrack>;
}

interface OutboxItem {
  message: AppMessage;
  /** The MLS ciphertext (base64) and its hash. */
  wire: string;
  hash: string;
  /** Mail id chosen before the first post (providers with `mailbox.newId`). */
  id?: string;
  epoch: string;
}

interface StoredMessage {
  message: AppMessage;
  from: ReceivedMessage['from'];
  epoch: string;
  own?: boolean;
}

/** In-progress chat creation (box 2: holds the new group's secrets). */
interface Creating {
  groupId: string;
  kind: 'dm' | 'group';
  name?: string;
  avatar?: string;
  /** The genesis log entry and the group state, base64. */
  entry: string;
  state: string;
  at: number;
  /** Set once the channel made the space. */
  space?: SpaceRef;
}
const CREATING = 'chat/creating/';

/** Sends that failed, by the error they failed with: see `unsentMessages`. */
const unsentByError = new WeakMap<object, AppMessage[]>();

/**
 * The messages a failed `send` (or `resend`) left unsent, from the error it threw. They are
 * kept encrypted on this device: retry with `group.resend(message.id)` (never a fresh send,
 * which would be a second message), or drop with `group.discardUnsent(message.id)`.
 */
export function unsentMessages(error: unknown): AppMessage[] | undefined {
  return typeof error === 'object' && error !== null ? unsentByError.get(error) : undefined;
}

/**
 * Each sender's application messages in an epoch are numbered 0, 1, 2... by MLS (the generation,
 * authenticated by the key it selects). A number we skipped over is a hole: noticed in one sync
 * (`fresh`), reported if the next sync still hasn't filled it (`waiting`), since the mailbox may
 * list messages out of order. Holes in epochs whose keys are gone are reported at once.
 */
interface GenTrack {
  hi: number;
  fresh: number[];
  waiting: number[];
  from: ReceivedMessage['from'];
}

export interface RotationPolicy {
  maxAgeMs: number;
  maxMessages: number;
}

export const DEFAULT_ROTATION: RotationPolicy = { maxAgeMs: 7 * DAY, maxMessages: 100 };

/**
 * Pre-keys (build option preKeys). A device makes a new one on its first sync after `rotateMs`
 * and keeps a retired private key until its first sync `keepMs` after retiring it, so a Welcome
 * made just before a rotation still opens: invites expire after 7 days, and pruning runs only
 * after that sync has opened what it can. Inviters skip pre-keys past `lifetimeMs`.
 */
export interface PreKeyPolicy {
  rotateMs: number;
  keepMs: number;
  lifetimeMs: number;
  /** Admins remove devices added with a pre-key that haven't joined after this long. */
  joinDeadlineMs: number;
}

export const DEFAULT_PREKEYS: PreKeyPolicy = { rotateMs: 7 * DAY, keepMs: 7 * DAY, lifetimeMs: 30 * DAY, joinDeadlineMs: 14 * DAY };

/**
 * Leaf extension on pre-keys. A leaf that still has it (and was never replaced by a commit of
 * its own) was added while offline and hasn't joined yet. Every member sees the same tree, so
 * every member agrees who is only "added".
 */
export const PREKEY_EXTENSION = 0xf0a2;
/** A send skips its sync only if the epoch has been the same for this many `sendFreshMs`. */
const EPOCH_SETTLE = 4;
/** How long a group this device created counts as holding nothing but what this device wrote. */
const JUST_CREATED_MS = 30_000;
const MAX_FAST_SENT = 50;

interface PreKeyInfo {
  ref: string;
  at: number;
  pub: string;
  retired: { ref: string; at: number }[];
}
const PREKEY_INFO = 'chat/prekey';

export interface ChatOptions {
  provider: StorageProvider;
  device: DeviceStorage;
  identity: DeviceIdentity;
  registry: IdentityRegistry;
  features: Features;
  rotation?: RotationPolicy;
  /** Old epochs whose keys are kept for late messages. Fewer is better for forward secrecy. */
  retainEpochs?: number;
  /** How old a cached directory may be before members' device lists are re-read. */
  directoryMaxAgeMs?: number;
  /** Pre-key rotation (build option preKeys). */
  preKeys?: PreKeyPolicy;
  /**
   * Send without syncing first when a sync of this group finished less than this long ago
   * (0, the default: always sync first). For apps that sync a chat every few seconds anyway,
   * on channels where each round trip is slow. See `Group.send`.
   */
  sendFreshMs?: number;
  /** Called with every decrypted message (for example, the history backup). */
  onMessage?: (group: Group, m: ReceivedMessage) => Promise<void> | void;
  now?: () => number;
}

export interface Member {
  fingerprint: string;
  address: Address;
  devices: { leafIndex: number; deviceId: string; device: string }[];
  admin: boolean;
  /** Added with pre-keys while offline and hasn't joined yet (none of their devices has). */
  pending: boolean;
}

export interface ReceivedMessage {
  message: AppMessage;
  from: { fingerprint: string; address: Address; deviceId: string };
  epoch: bigint;
}

/** The person whose app committed (or proposed) a removal. */
export interface Remover {
  fingerprint: string;
  address: Address;
}

/**
 * Who removed each person that these removes take out (all of their devices), keyed by the
 * removed person's fingerprint. Not in the map: someone whose own device proposed it (a leave),
 * and someone who keeps other devices (one device revoked or replaced).
 */
function removersOf(members: MemberLeaf[], removes: { removed: number; sender: number | undefined }[]) {
  const out = new Map<string, Remover>();
  const gone = new Set(removes.map((r) => r.removed));
  for (const r of removes) {
    const target = members.find((l) => l.leafIndex === r.removed);
    const sender = r.sender === undefined ? undefined : members.find((l) => l.leafIndex === r.sender);
    if (!target || !sender || sender.root === target.root) continue;
    if (members.some((l) => l.root === target.root && !gone.has(l.leafIndex))) continue;
    out.set(target.root, { fingerprint: sender.root, address: sender.address });
  }
  return out;
}

export type GroupEvent =
  /** Someone was added with pre-keys; they can read what is sent from now on once they join. */
  | { type: 'added'; fingerprint: string; address: Address }
  | { type: 'joined'; fingerprint: string; address: Address }
  /**
   * `pending`: they were added but never joined (declined, expired, or removed before joining).
   * `by`: someone else removed them (an admin); absent when they left on their own.
   */
  | { type: 'left'; fingerprint: string; address: Address; pending?: boolean; by?: Remover }
  | { type: 'policy'; policy: GroupPolicy }
  | { type: 'rejected'; index: number; reason: string }
  | { type: 'undecryptable'; id: string; reason: string }
  /**
   * `onMessage` threw: the message (and any after it) is kept, decrypted, and handed to
   * `onMessage` again first thing on the next sync, in order. `waiting` is how many wait.
   */
  | { type: 'delivery-failed'; reason: string; waiting: number }
  /**
   * `missing` messages from this sender in `epoch` never arrived: the storage may have dropped
   * them (or the sender's upload failed). Reported once, after a later sync still lacked them.
   * A dropped LAST message of an epoch can't be noticed this way.
   */
  | { type: 'gap'; from: ReceivedMessage['from']; epoch: bigint; missing: number }
  /**
   * Comes with `removed`: messages that reached this device although it was already removed
   * (sent with `sendFreshMs` by someone who hadn't synced the removal yet). An honest app
   * deletes them from this device, and from any history backup. See `ChatOptions.sendFreshMs`.
   */
  | { type: 'retracted'; ids: string[] }
  /** We are out of the group. `by`: who removed us, when we can tell (absent when we left). */
  | { type: 'removed'; by?: Remover }
  | { type: 'rotated'; epoch: bigint }
  /** The channel no longer lets this account in. Usually follows a removal. */
  | { type: 'access-lost' };

export interface SyncResult {
  messages: ReceivedMessage[];
  events: GroupEvent[];
}

export const recipientTag = async (address: Address) => toHex(await sha256(utf8(`keyhold/v1/recipient:${address}`))).slice(0, 32);

function leaves(state: mls.ClientState): MemberLeaf[] {
  const out: MemberLeaf[] = [];
  state.ratchetTree.forEach((node, i) => {
    if (i % 2 !== 0 || !node || node.nodeType !== 'leaf') return;
    const cert = certificateFromCredential(node.leaf.credential as never);
    if (!cert) return;
    out.push({ leafIndex: i / 2, root: fingerprint(unb64(cert.root)), device: cert.device, address: cert.address });
  });
  return out;
}

/** Added with a pre-key and never replaced by a commit of its own: this device hasn't joined. */
function unjoinedLeaf(node: mls.NodeLeaf): boolean {
  const leaf = node.leaf as mls.LeafNode;
  return leaf.leafNodeSource === 'key_package' && leaf.extensions.some((e) => (e.extensionType as unknown) === PREKEY_EXTENSION);
}

/**
 * RFC 9420 5.3.1: a leaf replaced in place (commit path, update) must carry a valid successor of
 * its credential. For us that is the same root and the same address. Leaves removed by the
 * commit may be refilled by an add, so they are not compared. Deterministic: trees only.
 */
function successionViolation(before: mls.ClientState, after: mls.ClientState, removed: ReadonlySet<number>): string | undefined {
  const old = new Map(leaves(before).map((l) => [l.leafIndex, l]));
  for (const l of leaves(after)) {
    const o = old.get(l.leafIndex);
    if (o && !removed.has(l.leafIndex) && !sameOwner(o, l)) return 'a leaf may not change its owner or address';
  }
  return undefined;
}

function leafFromCredential(cred: mls.Credential, index = -1): MemberLeaf | undefined {
  const cert = certificateFromCredential(cred as never);
  if (!cert || !verifyDeviceCertificate(cert)) return undefined;
  return { leafIndex: index, root: fingerprint(unb64(cert.root)), device: cert.device, address: cert.address };
}

function summarize(p: mls.ProposalWithSender): ProposalSummary {
  const sender = p.senderLeafIndex;
  const prop = p.proposal;
  switch (prop.proposalType) {
    case 'add': {
      const leaf = leafFromCredential(prop.add.keyPackage.leafNode.credential);
      return leaf ? { type: 'add', sender, leaf } : { type: 'other', sender, name: 'add-with-bad-credential' };
    }
    case 'remove':
      return { type: 'remove', sender, removed: prop.remove.removed };
    case 'update':
      return { type: 'update', sender, leaf: leafFromCredential(prop.update.leafNode.credential) };
    case 'external_init':
      return { type: 'external_init', sender };
    case 'group_context_extensions': {
      let policy: GroupPolicy | undefined;
      try {
        policy = decodePolicy(prop.groupContextExtensions.extensions as never);
      } catch {
        policy = undefined;
      }
      return { type: 'policy', sender, policy };
    }
    default:
      return { type: 'other', sender, name: String(prop.proposalType) };
  }
}

/** One device's view of all its chats. */
export class Chat {
  readonly groups = new Map<string, Group>();
  /** Joins in flight, by space: a second join of the same space waits for the first. */
  private joining = new Map<SpaceRef, Promise<Group | undefined>>();
  readonly opts: Required<Omit<ChatOptions, 'onMessage'>> & Pick<ChatOptions, 'onMessage'>;

  private constructor(opts: ChatOptions) {
    this.opts = {
      rotation: DEFAULT_ROTATION,
      preKeys: DEFAULT_PREKEYS,
      retainEpochs: 4,
      directoryMaxAgeMs: 60 * 60 * 1000,
      sendFreshMs: 0,
      now: Date.now,
      ...(Object.fromEntries(Object.entries(opts).filter(([, v]) => v !== undefined)) as ChatOptions),
    };
  }

  static async open(opts: ChatOptions): Promise<Chat> {
    const chat = new Chat(opts);
    for (const key of await opts.device.keystore.keys('chat/group/')) {
      const meta = parseJsonBytes<GroupMeta>((await opts.device.keystore.get(key))!);
      if (meta.removed) continue;
      const raw = await opts.device.ephemeral.get(`chat/state/${meta.groupId}`);
      if (!raw) continue;
      const g = new Group(chat, meta, chat.decodeState(raw));
      chat.groups.set(meta.groupId, g);
    }
    return chat;
  }

  /** Remove what's left of an ended room on this device (its bookkeeping), so nothing of it remains. */
  async purge(groupId: string) {
    const g = this.groups.get(groupId);
    if (g) await g.end();
    const dev = this.opts.device;
    await dev.keystore.delete(`chat/group/${groupId}`);
    await dev.ephemeral.delete(`chat/state/${groupId}`);
    await dev.ephemeral.delete(`chat/pending/${groupId}`);
  }

  get identity() {
    return this.opts.identity;
  }
  get provider() {
    return this.opts.provider;
  }
  now() {
    return this.opts.now();
  }

  clientConfig(): mls.ClientConfig {
    return {
      keyRetentionConfig: { ...mls.defaultKeyRetentionConfig, retainKeysForEpochs: this.opts.retainEpochs },
      lifetimeConfig: mls.defaultLifetimeConfig,
      keyPackageEqualityConfig: mls.defaultKeyPackageEqualityConfig,
      paddingConfig: { kind: 'padUntilLength', padUntilLength: 256 },
      authService: {
        // Every leaf's credential must be a root-signed device certificate for exactly this
        // signature key. Revocation is NOT checked here: it depends on each member's cached
        // directory, and validity must be the same for every member. Revoked devices are
        // removed and banned through commits instead (see Group.automate).
        async validateCredential(cred, signaturePublicKey) {
          const cert = certificateFromCredential(cred as never);
          if (!cert || !verifyDeviceCertificate(cert)) return false;
          return cert.device === b64(signaturePublicKey);
        },
      },
    };
  }

  decodeState(raw: Uint8Array): mls.ClientState {
    const d = mls.decodeGroupState(raw, 0);
    if (!d) throw new KeyholdError('bad_format', 'bad group state');
    return { ...d[0], clientConfig: this.clientConfig() };
  }

  capabilities(): mls.Capabilities {
    const caps = mls.defaultCapabilities();
    return { ...caps, ciphersuites: [CIPHERSUITE], extensions: [...caps.extensions, POLICY_EXTENSION, PREKEY_EXTENSION] };
  }

  async keyPackage(lifetimeMs = 30 * DAY, preKey = false) {
    const cs = await ciphersuite();
    const id = this.identity;
    const now = BigInt(Math.floor(this.now() / 1000));
    return mls.generateKeyPackageWithKey(
      certificateToCredential(id.cert),
      this.capabilities(),
      { notBefore: now - 3600n, notAfter: now + BigInt(Math.floor(lifetimeMs / 1000)) },
      [],
      { signKey: id.signKey, publicKey: id.publicKey },
      cs,
      preKey ? [{ extensionType: PREKEY_EXTENSION, extensionData: new Uint8Array() } as never] : [],
    );
  }

  /**
   * Create a group (or a DM: a group limited to two people) in a new space.
   *
   * Everything is prepared and saved on this device before the space is made, so a failure
   * after that (the genesis entry not written, or its reply lost) can be finished later by
   * `finishCreates()` instead of leaving an empty space behind.
   */
  /** `avatar`: an opaque picture string, sent with the name in the first `meta` message. */
  async createGroup(kind: 'dm' | 'group' = 'group', name?: string, opts: { avatar?: string } = {}): Promise<Group> {
    const avatar = opts.avatar || undefined;
    const cs = await ciphersuite();
    const kp = await this.keyPackage();
    const groupId = randomBytes(16);
    const policy = defaultPolicy(kind, this.identity.fingerprint);
    const state = await mls.createGroup(groupId, kp.publicPackage, kp.privatePackage, [encodePolicy(policy)], cs, this.clientConfig());
    const entry: LogEntry = { v: 1, i: 0, prev: '', kind: 'genesis', epoch: '0', gi: await groupInfoBytes(state, cs) };
    const rec: Creating = { groupId: b64(groupId), kind, name, avatar, entry: b64(jsonBytes(entry)), state: b64(mls.encodeGroupState(state)), at: this.now() };
    const eph = this.opts.device.ephemeral;
    this.creatingNow.add(rec.groupId);
    try {
      await eph.put(CREATING + rec.groupId, jsonBytes(rec));
      rec.space = await this.provider.channel.createSpace(kind);
      await eph.put(CREATING + rec.groupId, jsonBytes(rec));
      const g = await this.finishCreate(rec, state);
      if (!g) throw new KeyholdError('conflict', 'new space already has a log');
      if (name || avatar) await g.send({ t: 'meta', name, avatar });
      return g;
    } finally {
      this.creatingNow.delete(rec.groupId);
    }
  }

  /** Creations running in this Chat now (finishCreates leaves them alone). */
  private creatingNow = new Set<string>();

  /** Write the genesis entry of a prepared creation (or find it already written) and open the group. */
  private async finishCreate(rec: Creating, state?: mls.ClientState): Promise<Group | undefined> {
    const key = CREATING + rec.groupId;
    const bytes = unb64(rec.entry);
    const hash = await hashEntry(bytes);
    const log = this.provider.orderedLog;
    const wrote = (await log.append(rec.space!, 0, bytes)) === 'ok';
    if (!wrote) {
      // Maybe ours, from a try whose reply was lost.
      const [first] = await log.read(rec.space!, 0);
      if (!first || (await hashEntry(first)) !== hash) {
        await this.opts.device.ephemeral.delete(key);
        return undefined;
      }
    }
    const meta = this.newMeta(rec.groupId, rec.space!, 1, hash, rec.name);
    meta.ownEntries.push(0);
    const g = new Group(this, meta, state ?? this.decodeState(unb64(rec.state)));
    // Our first entry went into an empty log just now: the space holds nothing we don't know.
    if (wrote) g.justCreated();
    await g.persist();
    this.groups.set(meta.groupId, g);
    await this.opts.device.ephemeral.delete(key);
    return g;
  }

  /**
   * Finish chat creations that failed part way on this device (say, the tab closed or the
   * network dropped after the space was made). Returns the groups now open. A creation that
   * never got its space is forgotten. Creations younger than a minute are left alone, as
   * another tab may still be running them. Errors on one creation don't stop the others.
   */
  async finishCreates(): Promise<Group[]> {
    const eph = this.opts.device.ephemeral;
    const out: Group[] = [];
    for (const key of await eph.keys(CREATING)) {
      const raw = await eph.get(key);
      if (!raw) continue;
      const rec = parseJsonBytes<Creating>(raw);
      if (this.creatingNow.has(rec.groupId) || this.now() - rec.at < 60_000) continue;
      if (!rec.space) {
        await eph.delete(key);
        continue;
      }
      try {
        const g = await this.finishCreate(rec);
        if (!g) continue;
        out.push(g);
        if (rec.name || rec.avatar) await g.send({ t: 'meta', name: rec.name, avatar: rec.avatar }).catch(() => undefined);
      } catch (e) {
        const code = (e as KeyholdError).code;
        if (code === 'forbidden' || code === 'not_found') await eph.delete(key); // the space is gone
      }
    }
    return out;
  }

  /**
   * What a space the caller can open holds, for spaces no group here knows:
   * - 'chat': it has a log; `join` may let us in.
   * - 'creating': this device is making a chat there; `finishCreates()` completes it.
   * - 'empty': no log, and not ours to finish. A space we own that stays empty is a creation
   *   that failed on a device that can't finish it: once it has been empty for a while (another
   *   device may be creating it right now), the app can treat it as abandoned and delete it.
   */
  async inspectSpace(space: SpaceRef): Promise<'chat' | 'creating' | 'empty'> {
    const eph = this.opts.device.ephemeral;
    for (const key of await eph.keys(CREATING)) {
      const raw = await eph.get(key);
      if (raw && parseJsonBytes<Creating>(raw).space === space) return 'creating';
    }
    return (await this.provider.orderedLog.read(space, 0)).length > 0 ? 'chat' : 'empty';
  }

  /** Start a DM with someone: a two-person group plus an invite. */
  async startDm(address: Address): Promise<Group> {
    const g = await this.createGroup('dm');
    await g.invite(address);
    return g;
  }

  newMeta(groupId: string, space: SpaceRef, logNext: number, lastHash: string, name?: string): GroupMeta {
    return {
      v: 1,
      groupId,
      space,
      logNext,
      lastHash,
      // hashes[i] = hash of log entry i; we always know the last one we processed.
      hashes: Object.assign(new Array<string>(logNext).fill(''), { [logNext - 1]: lastHash }),
      ownEntries: [],
      ownMail: [],
      pending: [],
      usedNonces: [],
      sentSinceUpdate: 0,
      lastUpdateAt: this.now(),
      needsHeal: false,
      name,
    };
  }

  /**
   * Pick up invites: accept channel grants from the inbox, then join every space that
   * has a ticket (or a Welcome) for this device. Returns the groups joined (and any of our own
   * creations `finishCreates` completed).
   */
  async acceptInvites(): Promise<Group[]> {
    const p = this.provider;
    const finished = await this.finishCreates(); // our own creations that failed part way
    for (const n of await p.inviteInbox.list()) {
      await p.channel.acceptGrant(n.pointer);
      await p.inviteInbox.delete(n.id);
    }
    const known = new Set([...this.groups.values()].map((g) => g.space));
    const joined: Group[] = [...finished];
    for (const space of await p.channel.listSpaces()) {
      if (known.has(space)) continue;
      const g = await this.join(space);
      if (g) joined.push(g);
    }
    return joined;
  }

  /**
   * Join one space: with a Welcome (offline add), as another device of a member (self-join),
   * or with a valid ticket for this address. Returns undefined when nothing lets us in.
   */
  join(space: SpaceRef): Promise<Group | undefined> {
    // Two joins of one space must never both succeed: each would hold its own copy of the group
    // state, both would commit, and each copy rejects the other's commits, so the device forks off
    // the group. A join that overlaps one in flight shares its result; a space already joined
    // returns the group we have.
    const have = this.groupInSpace(space);
    if (have) return Promise.resolve(have);
    let run = this.joining.get(space);
    if (!run) {
      run = this.joinNow(space).finally(() => this.joining.delete(space));
      this.joining.set(space, run);
    }
    return run;
  }

  private groupInSpace(space: SpaceRef): Group | undefined {
    for (const g of this.groups.values()) if (g.space === space && g.active) return g;
    return undefined;
  }

  private async joinNow(space: SpaceRef): Promise<Group | undefined> {
    const p = this.provider;
    const cs = await ciphersuite();
    const tag = await recipientTag(this.identity.address);
    const drops = await p.dropBox.list(space, tag);

    // 1. A Welcome for one of our KeyPackages (offline add, box 4).
    for (const d of drops) {
      let msg: mls.MLSMessage;
      try {
        msg = decodeMsg(d.data);
      } catch {
        continue;
      }
      if (msg.wireformat !== 'mls_welcome') continue;
      const g = await this.joinWithWelcome(space, msg.welcome);
      if (g) {
        // One Welcome can carry secrets for several of this person's devices: leave it for the others.
        if (msg.welcome.secrets.length === 1) await p.dropBox.delete(space, tag, d.id);
        // Our ticket for this group went unused: drop it, or it would keep our channel access
        // (the owner's app spares anyone holding a live ticket) after a later removal.
        for (const t of drops) {
          const ticket = decodeTicket(t.data);
          if (ticket && ticket.to === this.identity.address && ticket.group === g.id) await p.dropBox.delete(space, tag, t.id).catch(() => undefined);
        }
        return g;
      }
    }

    // 2. External join: read the log, check the chain, take the newest GroupInfo.
    for (let attempt = 0; attempt < 5; attempt++) {
      const raw = await p.orderedLog.read(space, 0);
      if (raw.length === 0) return undefined;
      const scan = await scanLog(raw);
      const giMsg = decodeMsg(unb64(scan.lastGi));
      if (giMsg.wireformat !== 'mls_group_info') throw new KeyholdError('bad_format', 'bad GroupInfo');
      const gi = giMsg.groupInfo;
      const groupId = gi.groupContext.groupId;
      const policy = decodePolicy(gi.groupContext.extensions as never);
      const treeLeaves = leavesOfGroupInfo(gi);
      // Anyone who can write the log can put a GroupInfo of a group they made there. Only join a
      // tree signed by someone we can verify (joinGroupExternal checks the signature itself).
      const tree = ratchetTreeOfGroupInfo(gi);
      if (!tree || (await this.untrustedTree(tree, gi.signer))) return undefined;
      // Another device of ours is in: join as one more device. A leaf of this very device (added
      // with a pre-key we can't open) doesn't count: it is replaced, so we need a ticket.
      const myDevice = b64(this.identity.publicKey);
      const selfJoin = treeLeaves.some((l) => l.root === this.identity.fingerprint && l.device !== myDevice);

      let ticketBytes: Uint8Array = new Uint8Array();
      let ticketDropId: string | undefined;
      if (!selfJoin) {
        const found = await this.pickTicket(drops, groupId, scan.usedNonces, treeLeaves, policy);
        if (!found) {
          await this.requestUpgrade(space, drops, groupId, scan.usedNonces, treeLeaves, policy);
          return undefined;
        }
        ticketBytes = encodeTicket(found.ticket);
        ticketDropId = found.dropId;
      }
      const kp = await this.keyPackage();
      // A leaf of this very device already there (added with a pre-key whose Welcome we couldn't
      // open): replace it, so no leaf stays on the reusable key.
      const resync = treeLeaves.some((l) => l.device === myDevice);
      const { publicMessage, newState } = await mls.joinGroupExternal(gi, kp.publicPackage, kp.privatePackage, resync, cs, undefined, this.clientConfig(), ticketBytes);
      const index = raw.length;
      const entry: LogEntry = {
        v: 1,
        i: index,
        prev: scan.lastHash,
        kind: 'commit',
        epoch: String(newState.groupContext.epoch),
        mls: b64(encodeMsg({ wireformat: 'mls_public_message', version: 'mls10', publicMessage })),
        gi: await groupInfoBytes(newState, cs),
      };
      const bytes = jsonBytes(entry);
      if ((await p.orderedLog.append(space, index, bytes)) !== 'ok') continue; // someone committed first: retry on the new epoch
      const meta = this.newMeta(b64(groupId), space, index + 1, await hashEntry(bytes));
      meta.hashes = [...scan.hashes, meta.lastHash];
      meta.ownEntries.push(index);
      meta.usedNonces = [...scan.usedNonces];
      const t = decodeTicket(ticketBytes);
      if (t) meta.usedNonces.push(t.nonce);
      // Messages from before we joined can't be read (MLS has no pre-join history); skip them.
      meta.mailCursor = (await p.mailbox.list(space)).cursor;
      // Also one posted after this, by someone who had not seen us join yet: not an error.
      meta.joinedEpoch = String(newState.groupContext.epoch);
      // Another device of ours was in already: this person may read what went up just before.
      if (!selfJoin) meta.joinedByCommit = true;
      const g = new Group(this, meta, newState);
      await g.persist();
      this.groups.set(meta.groupId, g);
      if (ticketDropId) await p.dropBox.delete(space, tag, ticketDropId);
      return g;
    }
    throw new KeyholdError('conflict', 'the group kept changing while joining; try again');
  }

  /**
   * We were invited before we had an identity, so the ticket names only our address. Ask the
   * issuer's app for a ticket bound to our root key; it checks our directory first.
   */
  private async requestUpgrade(space: SpaceRef, drops: { id: string; data: Bytes }[], groupId: Uint8Array, used: Set<string>, members: MemberLeaf[], policy: GroupPolicy) {
    const t = await this.pickTicket(drops, groupId, used, members, policy, true);
    if (!t) return;
    const req: JoinRequest = { t: 'join-request', nonce: t.ticket.nonce, cert: this.identity.cert };
    await this.provider.dropBox.put(space, await recipientTag(t.ticket.by.address), jsonBytes(req));
  }

  private async pickTicket(drops: { id: string; data: Bytes }[], groupId: Uint8Array, used: Set<string>, members: MemberLeaf[], policy: GroupPolicy, addressOnly = false) {
    const cs = await ciphersuite();
    for (const d of drops) {
      const t = decodeTicket(d.data);
      if (!t || t.to !== this.identity.address || used.has(t.nonce)) continue;
      if (addressOnly ? t.toRoot !== undefined : t.toRoot !== this.identity.fingerprint) continue;
      const v = await verifyTicket(t, groupId, this.now(), (pk, m, s) => cs.signature.verify(pk, m, s));
      if (!v) continue;
      // The issuer must be in the group we are about to join, with the device that signed.
      if (!members.some((m) => m.device === t.by.device && m.root === v.issuerRoot)) continue;
      if (!policy.admins.includes(v.issuerRoot) && policy.adds !== 'members') continue;
      return { ticket: t, dropId: d.id };
    }
    return undefined;
  }

  private async joinWithWelcome(space: SpaceRef, welcome: mls.Welcome): Promise<Group | undefined> {
    const cs = await ciphersuite();
    const eph = this.opts.device.ephemeral;
    for (const s of welcome.secrets) {
      const ref = b64(s.newMember);
      let key: string | undefined;
      for (const prefix of ['chat/kp/', 'chat/pk/', 'chat/kplr/']) if (!key && (await eph.get(`${prefix}${ref}`))) key = `${prefix}${ref}`;
      if (!key) continue;
      const stored = parseJsonBytes<{ pub: string; priv: Record<string, string> }>((await eph.get(key))!);
      const pubMsg = decodeMsg(unb64(stored.pub));
      if (pubMsg.wireformat !== 'mls_key_package') continue;
      const priv: mls.PrivateKeyPackage = {
        initPrivateKey: unb64(stored.priv.init!),
        hpkePrivateKey: unb64(stored.priv.hpke!),
        signaturePrivateKey: this.identity.signKey,
      };
      // Anyone who can write our drop box (the storage operator, any collaborator) can make a
      // Welcome for our published pre-key into a group of their own with the real group id. So a
      // Welcome counts only when its signer is a verified device and its tree matches the log; a
      // bad one is skipped, and the next Welcome or the ticket is tried instead.
      let state: mls.ClientState;
      let signer: number;
      try {
        signer = await welcomeSigner(welcome, s.newMember, priv.initPrivateKey, cs);
        state = await mls.joinGroup(welcome, pubMsg.keyPackage, priv, mls.emptyPskIndex, cs, undefined, undefined, this.clientConfig());
      } catch {
        continue;
      }
      if (await this.untrustedTree(state.ratchetTree, signer)) continue;
      // Already in this group (e.g. joined in another call): never keep a second copy of it.
      const existing = this.groups.get(b64(state.groupContext.groupId));
      if (existing?.active) return existing;
      const raw = await this.provider.orderedLog.read(space, 0);
      const scan = await scanLog(raw);
      const at = await logIndexOf(raw, state.groupContext);
      if (at === undefined) continue; // the commit that added us is not in the log: not this group
      // One-time keys are deleted the moment they are used (box 2). Last-resort keys stay.
      if (key.startsWith('chat/kp/')) await eph.delete(key);
      const meta = this.newMeta(b64(state.groupContext.groupId), space, at + 1, scan.hashes[at]!);
      meta.hashes = scan.hashes.slice(0, at + 1);
      // Only tickets burned up to the add: later entries are replayed and burn their own.
      meta.usedNonces = [...(await scanLog(raw.slice(0, at + 1))).usedNonces];
      meta.mailCursor = undefined; // messages after the add are readable; older ones are skipped
      meta.joinedEpoch = String(state.groupContext.epoch);
      // Someone new to the group (no device of ours had joined it): note where the add happened in
      // the mail, so a repeat of something sent before it isn't read here.
      const mine = leaves(state).some((l) => l.root === this.identity.fingerprint && l.device !== b64(this.identity.publicKey) && !unjoinedLeaf(state.ratchetTree[l.leafIndex * 2] as mls.NodeLeaf));
      const addEntry = (() => {
        try {
          return parseJsonBytes<LogEntry>(raw[at]!, 'log entry');
        } catch {
          return undefined;
        }
      })();
      if (!mine && typeof addEntry?.mail === 'string') {
        meta.addedAtMail = addEntry.mail;
        meta.addedAtMailSince = this.now();
      }
      // Our leaf still holds the reusable pre-key: replace it with a fresh key on the next sync.
      meta.freshLeaf = true;
      const g = new Group(this, meta, state);
      await g.persist();
      this.groups.set(meta.groupId, g);
      return g;
    }
    return undefined;
  }

  /**
   * Why we must not join a group with this tree, signed by leaf `signer`; undefined when we may.
   * Device certificates are self-issued, so a leaf can claim any address; the directory (with
   * our TOFU pins) says which root an address belongs to. The signer (who added us, or who made
   * the GroupInfo) must be a current device of the root its address publishes, and no leaf may
   * claim an address whose directory names another root. Addresses with no directory can't be
   * checked; the app shows them as unverified.
   */
  async untrustedTree(tree: mls.RatchetTree, signer: number): Promise<string | undefined> {
    const me = this.identity;
    const all = leaves({ ratchetTree: tree } as unknown as mls.ClientState);
    const looked = new Map<Address, LookupResult | null>();
    const look = async (a: Address) => {
      if (!looked.has(a)) looked.set(a, await this.opts.registry.lookup(a).catch(() => null));
      return looked.get(a)!;
    };
    const s = all.find((l) => l.leafIndex === signer);
    if (!s) return 'the signer is not in the group';
    for (const l of [s, ...all]) {
      const isSigner = l === s;
      if (l.address === me.address) {
        if (l.root !== me.fingerprint) return `a leaf claims our address ${l.address} with another key`;
        continue;
      }
      const r = await look(l.address);
      if (!r) return `cannot verify ${l.address}`;
      if (r.status === 'none') {
        if (isSigner) return `the inviter ${l.address} has no identity`;
        continue;
      }
      if (r.status === 'key-changed') {
        if (isSigner) return `the inviter ${l.address} has a new identity key`;
        if (l.root !== r.pinned.fingerprint && l.root !== r.view.fingerprint) return `${l.address} is in the group with another key`;
        continue;
      }
      if (l.root !== r.view.fingerprint) return `${l.address} is in the group with another key`;
      if (isSigner && r.view.revoked.has(l.device)) return `the inviter's device was revoked`;
    }
    return undefined;
  }

  // ---- Offline add (box 4, build option) ----

  private requireOfflineAdd() {
    if (!this.opts.features.offlineAdd) throw new KeyholdError('unsupported', 'offline add is not enabled (build option offlineAdd, provider capability claim-once)');
  }

  /** Upload one-time KeyPackages to the claim-once store. Private halves stay in box 2. */
  async publishKeyPackages(count: number, lifetimeMs = 30 * DAY) {
    this.requireOfflineAdd();
    const items: Bytes[] = [];
    for (let i = 0; i < count; i++) items.push(await this.storeKeyPackage('chat/kp/', lifetimeMs));
    await this.provider.claimOnce!.publish(items, { expiresAt: this.now() + lifetimeMs });
  }

  /** Make a reusable last-resort KeyPackage; publish it with DirectoryWriter.setLastResortKeyPackage. */
  async lastResortKeyPackage(lifetimeMs = 30 * DAY): Promise<Bytes> {
    for (const k of await this.opts.device.ephemeral.keys('chat/kplr/')) await this.opts.device.ephemeral.delete(k);
    return this.storeKeyPackage('chat/kplr/', lifetimeMs);
  }

  // ---- Pre-keys (box 3b, build option) ----

  /**
   * Keep this device's pre-key published and fresh, and prune retired ones. Call it after
   * joining what can be joined, so a retired key is never pruned before its Welcome was tried.
   * Publishes when there is none yet (also for accounts made before pre-keys existed), when the
   * published one went missing, or when it is due for rotation. Returns true if it published.
   */
  async refreshPreKey(): Promise<boolean> {
    if (!this.opts.features.preKeys) return false;
    const pol = this.opts.preKeys;
    const now = this.now();
    const eph = this.opts.device.ephemeral;
    const ks = this.opts.device.keystore;
    const raw = await ks.get(PREKEY_INFO);
    let info = raw ? parseJsonBytes<PreKeyInfo>(raw) : undefined;
    let due = !info || !(await eph.get(`chat/pk/${info.ref}`)) || now - info.at >= pol.rotateMs;
    if (!due && !this.preKeyChecked) {
      // Once per start: is it still there? (The public repo may have been reset.)
      const mine = await this.provider.preKeys!.read(this.identity.address);
      due = !mine.some((b) => b64(b) === info!.pub);
    }
    this.preKeyChecked = true;
    let published = false;
    if (due) {
      const { ref, pub } = await this.makeKeyPackage('chat/pk/', pol.lifetimeMs, pol.lifetimeMs + 14 * DAY, true);
      await this.provider.preKeys!.publish(this.identity.deviceId, pub);
      const retired = [...(info?.retired ?? [])];
      if (info && info.ref !== ref) retired.push({ ref: info.ref, at: now });
      info = { ref, at: now, pub: b64(pub), retired };
      published = true;
    }
    const keep: PreKeyInfo['retired'] = [];
    for (const r of info!.retired) {
      if (now - r.at >= pol.keepMs) await eph.delete(`chat/pk/${r.ref}`);
      else keep.push(r);
    }
    info!.retired = keep;
    await ks.put(PREKEY_INFO, jsonBytes(info));
    return published;
  }

  private preKeyChecked = false;

  /**
   * Open the note an inviter sealed to this device's pre-key (see `InviteOptions.note`). Undefined
   * when there is none, it was sealed to other devices, or the pre-key is gone. The inviter's
   * address is bound in, so a note can't be moved to another person's invitation; what it says is
   * still only the inviter's word until the chat is joined.
   */
  async openInviteNote(notice: { from: Address; payload?: Bytes }): Promise<Bytes | undefined> {
    if (!notice.payload) return undefined;
    let sealed: SealedNote;
    try {
      sealed = parseJsonBytes<SealedNote>(notice.payload);
    } catch {
      return undefined;
    }
    if (sealed?.v !== 1 || !Array.isArray(sealed.to)) return undefined;
    const cs = await ciphersuite();
    for (const t of sealed.to) {
      const raw = await this.opts.device.ephemeral.get(`chat/pk/${t.ref}`);
      if (!raw) continue;
      try {
        const { priv } = parseJsonBytes<{ priv: { init: string } }>(raw);
        const key = await cs.hpke.importPrivateKey(unb64(priv.init));
        return await cs.hpke.open(key, unb64(t.enc), unb64(t.ct), utf8(NOTE_INFO), utf8(notice.from));
      } catch {
        continue;
      }
    }
    return undefined;
  }

  /** Valid pre-keys of a person: one per current device, signed by it, certified by their root, not expired. */
  async preKeysOf(view: DirectoryView): Promise<mls.KeyPackage[]> {
    if (!this.opts.features.preKeys) return [];
    const nowS = BigInt(Math.floor(this.now() / 1000));
    const byDevice = new Map<string, mls.KeyPackage>();
    let items: Bytes[] = [];
    try {
      items = await this.provider.preKeys!.read(view.address);
    } catch {
      return [];
    }
    for (const b of items) {
      let msg: mls.MLSMessage;
      try {
        msg = decodeMsg(b);
      } catch {
        continue;
      }
      if (msg.wireformat !== 'mls_key_package') continue;
      const kp = msg.keyPackage;
      const leaf = kp.leafNode as mls.LeafNode & { lifetime?: { notBefore: bigint; notAfter: bigint } };
      const cert = certificateFromCredential(leaf.credential as never);
      if (!cert || !verifyDeviceCertificate(cert) || cert.address !== view.address) continue;
      if (fingerprint(unb64(cert.root)) !== view.fingerprint || !view.devices.has(cert.device)) continue;
      if (cert.device !== b64(leaf.signaturePublicKey)) continue;
      if (!leaf.extensions.some((e) => (e.extensionType as unknown) === PREKEY_EXTENSION)) continue;
      // An hour of slack for clocks; the device only keeps it a while past lifetime.
      if (!leaf.lifetime || leaf.lifetime.notAfter <= nowS + 3600n || leaf.lifetime.notBefore > nowS + 3600n) continue;
      const prev = byDevice.get(cert.device) as (mls.KeyPackage & { leafNode: { lifetime?: { notBefore: bigint } } }) | undefined;
      if (!prev || (prev.leafNode.lifetime?.notBefore ?? 0n) < leaf.lifetime.notBefore) byDevice.set(cert.device, kp);
    }
    return [...byDevice.values()];
  }

  private async storeKeyPackage(prefix: string, lifetimeMs: number): Promise<Bytes> {
    return (await this.makeKeyPackage(prefix, lifetimeMs, lifetimeMs)).pub;
  }

  private async makeKeyPackage(prefix: string, lifetimeMs: number, keepMs: number, preKey = false): Promise<{ ref: string; pub: Bytes }> {
    const cs = await ciphersuite();
    const kp = await this.keyPackage(lifetimeMs, preKey);
    const ref = b64(await makeKeyPackageRef(kp.publicPackage, cs.hash));
    const pub = encodeMsg({ wireformat: 'mls_key_package', version: 'mls10', keyPackage: kp.publicPackage });
    // The signature key is the device key (box 1): it is not copied into box 2.
    const priv = { init: b64(kp.privatePackage.initPrivateKey), hpke: b64(kp.privatePackage.hpkePrivateKey) };
    await this.opts.device.ephemeral.put(`${prefix}${ref}`, jsonBytes({ pub: b64(pub), priv }), { expiresAt: this.now() + keepMs });
    return { ref, pub };
  }

  /** Members check tickets without a clock (see verifyTicket). */
  async verifyTicketSig(t: InviteTicket, groupId: Uint8Array): Promise<VerifiedTicket | undefined> {
    const cs = await ciphersuite();
    return verifyTicket(t, groupId, undefined, (pk, m, s) => cs.signature.verify(pk, m, s));
  }
}

/** One person's outcome of `inviteMany`. */
export interface InviteResult {
  address: Address;
  ticket?: InviteTicket;
  error?: Error;
}

interface PreparedInvite {
  address: Address;
  view?: DirectoryView;
  kps: mls.KeyPackage[];
  ticket?: InviteTicket;
  error?: Error;
}

export interface InviteOptions {
  /** Only accept people who already have an identity. */
  requireIdentity?: boolean;
  ttlMs?: number;
  /**
   * A short note for the invitee to read before accepting (e.g. what kind of chat it is). It is
   * sealed to each of their devices' pre-keys and rides in the invite notice, so it needs the
   * `inbox-payload` capability and a published pre-key; otherwise it is left out.
   */
  note?: Bytes;
}

const NOTE_INFO = 'keyhold/invite-note/v1';
const NOTE_MAX = 2048;

interface SealedNote {
  v: 1;
  to: { ref: string; enc: string; ct: string }[];
}

async function sealInviteNote(note: Bytes, kps: mls.KeyPackage[], from: Address): Promise<Bytes | undefined> {
  if (note.length > NOTE_MAX) throw new KeyholdError('config', `invite note is over ${NOTE_MAX} bytes`);
  const cs = await ciphersuite();
  const to: SealedNote['to'] = [];
  for (const kp of kps) {
    const ref = b64(await makeKeyPackageRef(kp, cs.hash));
    const { enc, ct } = await cs.hpke.seal(await cs.hpke.importPublicKey(kp.initKey), note, utf8(NOTE_INFO), utf8(from));
    to.push({ ref, enc: b64(enc), ct: b64(ct) });
  }
  return to.length ? jsonBytes({ v: 1, to } satisfies SealedNote) : undefined;
}

interface JoinRequest {
  t: 'join-request';
  nonce: string;
  cert: DeviceCertificate;
}

interface LogScan {
  hashes: string[];
  lastHash: string;
  lastGi: string;
  usedNonces: Set<string>;
  epochIndex: Map<string, number>;
}

function giEpoch(gi: string): bigint | undefined {
  try {
    const m = decodeMsg(unb64(gi));
    return m.wireformat === 'mls_group_info' ? m.groupInfo.groupContext.epoch : undefined;
  } catch {
    return undefined;
  }
}

/** Check the hash chain of a whole log and collect what a joiner needs. */
async function scanLog(raw: Bytes[]): Promise<LogScan> {
  const hashes: string[] = [];
  const usedNonces = new Set<string>();
  const epochIndex = new Map<string, number>();
  let prev = '';
  let lastGi = '';
  let lastGiEpoch: bigint | undefined;
  for (let i = 0; i < raw.length; i++) {
    let e: LogEntry | undefined;
    try {
      e = parseJsonBytes<LogEntry>(raw[i]!, 'log entry');
    } catch {
      e = undefined;
    }
    const wellFormed = !!e && e.v === 1 && e.i === i && e.prev === prev;
    prev = await hashEntry(raw[i]!);
    hashes.push(prev);
    // A malformed entry (garbage from a member, or a broken chain) is skipped, never fatal:
    // otherwise any member could block the group by writing junk.
    if (!wellFormed || !e) continue;
    // The GroupInfo to join from: only the genesis entry's and those of commits (an entry with a
    // GroupInfo but nothing members apply is ignored by members, so it must not steer joiners),
    // and of those the one with the highest epoch, so an old GroupInfo written again later (which
    // would put a joiner into an old epoch with people removed since) never wins.
    if (e.gi && ((i === 0 && e.kind === 'genesis') || (e.kind === 'commit' && e.mls))) {
      const ep = giEpoch(e.gi);
      if (ep !== undefined && (lastGiEpoch === undefined || ep >= lastGiEpoch)) {
        lastGi = e.gi;
        lastGiEpoch = ep;
      }
    }
    if (!epochIndex.has(e.epoch)) epochIndex.set(e.epoch, i);
    if (e.kind === 'commit' && e.mls) {
      try {
        const m = decodeMsg(unb64(e.mls));
        if (m.wireformat === 'mls_public_message') {
          const t = decodeTicket(m.publicMessage.content.authenticatedData);
          if (t) usedNonces.add(t.nonce);
        }
      } catch {
        /* not ours to judge here */
      }
    }
  }
  if (!lastGi) throw new KeyholdError('bad_format', 'log has no GroupInfo');
  return { hashes, lastHash: prev, lastGi, usedNonces, epochIndex };
}

/** Leaf index of the member that signed a Welcome's GroupInfo (joinGroup verifies the signature). */
async function welcomeSigner(welcome: mls.Welcome, ref: Uint8Array, initPrivateKey: Uint8Array, cs: mls.CiphersuiteImpl): Promise<number> {
  const secrets = await decryptGroupSecrets(await cs.hpke.importPrivateKey(initPrivateKey), ref, welcome, cs.hpke);
  if (!secrets) throw new KeyholdError('bad_format', 'bad Welcome');
  const [psk] = await accumulatePskSecret(secrets.psks, mls.emptyPskIndex, cs, new Uint8Array(cs.kdf.size));
  const gi = await decryptGroupInfo(welcome, secrets.joinerSecret, psk, cs);
  if (!gi) throw new KeyholdError('bad_format', 'bad Welcome');
  return gi.signer;
}

/**
 * Index of the log entry that created this exact epoch: same epoch, tree and transcript as the
 * GroupInfo it carries. Old entries without a GroupInfo match on the epoch alone.
 */
async function logIndexOf(raw: Bytes[], ctx: mls.GroupContext): Promise<number | undefined> {
  const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
  let prev = '';
  let loose: number | undefined;
  for (let i = 0; i < raw.length; i++) {
    let e: LogEntry | undefined;
    try {
      e = parseJsonBytes<LogEntry>(raw[i]!, 'log entry');
    } catch {
      e = undefined;
    }
    const ok = !!e && e.v === 1 && e.i === i && e.prev === prev;
    prev = await hashEntry(raw[i]!);
    if (!ok || !e || e.epoch !== String(ctx.epoch)) continue;
    if (!e.gi) {
      loose ??= i;
      continue;
    }
    try {
      const m = decodeMsg(unb64(e.gi));
      if (m.wireformat !== 'mls_group_info') continue;
      const g = m.groupInfo.groupContext;
      if (same(g.groupId, ctx.groupId) && same(g.treeHash, ctx.treeHash) && same(g.confirmedTranscriptHash, ctx.confirmedTranscriptHash)) return i;
    } catch {
      continue;
    }
  }
  return loose;
}

function ratchetTreeOfGroupInfo(gi: mls.GroupInfo): mls.RatchetTree | undefined {
  const ext = gi.extensions.find((e) => e.extensionType === 'ratchet_tree' || e.extensionType === 2);
  return ext ? decodeTree(ext.extensionData) : undefined;
}

function leavesOfGroupInfo(gi: mls.GroupInfo): MemberLeaf[] {
  const tree = ratchetTreeOfGroupInfo(gi);
  return tree ? leaves({ ratchetTree: tree } as unknown as mls.ClientState) : [];
}

function decodeTree(b: Uint8Array): mls.RatchetTree {
  const r = decodeRatchetTree(b, 0);
  if (!r) throw new KeyholdError('bad_format', 'bad ratchet tree');
  return r[0];
}

/** Most messages posted in one write. */
const MAX_BATCH = 50;

interface PendingSend {
  content: AppContent;
  resolve: (m: AppMessage) => void;
  reject: (e: unknown) => void;
}

/** One conversation on this device. */
export class Group {
  private syncing: Promise<SyncResult> | undefined;
  /**
   * Every change to the MLS state runs one at a time. Two sends started together would
   * otherwise both encrypt from the same state: same generation, so the same key and nonce
   * twice, and each receiver could open only one of them. A sync racing a send or commit
   * would likewise overwrite the other's new state. Public methods queue here; internal
   * helpers (the *Now methods, pull, commit) assume the queue is already held.
   */
  private queue: Promise<unknown> = Promise.resolve();
  private lastMembership = '';
  private lastRequests = 0;
  /** Messages and events found by internal syncs (before a send or commit), returned by the next sync(). */
  private buffered: SyncResult = { messages: [], events: [] };
  /** When the last complete sync of this group started (this session only). */
  private pulledAt = -Infinity;
  /** When this device made the group, while that still counts as "just now" (see justCreated). */
  private createdAt = -Infinity;
  /**
   * This device created the group and wrote its first log entry a moment ago. Until someone is
   * invited nobody else can reach the space, so it counts as synced: a first message (the
   * group's name) and the first invitations go out without reading the empty space first.
   */
  justCreated() {
    this.createdAt = this.pulledAt = this.chat.now();
  }
  /** When this device last saw the group change epoch (this session only), and that epoch. */
  private epochChangedAt = -Infinity;
  private epochSeen?: bigint;
  private noteEpoch() {
    if (this.epochSeen !== undefined && this.epochSeen !== this.epoch) this.epochChangedAt = this.chat.now();
    this.epochSeen = this.epoch;
  }

  constructor(
    readonly chat: Chat,
    private meta: GroupMeta,
    private state: mls.ClientState,
  ) {}

  get id() {
    return this.meta.groupId;
  }
  get space() {
    return this.meta.space;
  }
  get epoch() {
    return this.state.groupContext.epoch;
  }
  get name() {
    return this.meta.name;
  }
  /** The group picture admins set (an opaque string; '' or undefined = none). */
  get avatar() {
    return this.meta.avatar;
  }
  get active() {
    return !this.meta.removed && !this.meta.accessLost && this.state.groupActiveState.kind === 'active';
  }
  get policy(): GroupPolicy {
    return decodePolicy(this.state.groupContext.extensions as never);
  }
  get myLeaf() {
    return this.state.privatePath.leafIndex;
  }
  /** For tests and audits: size of retained per-epoch receiver data. */
  get retainedEpochs() {
    return this.state.historicalReceiverData.size;
  }

  members(): Member[] {
    const policy = this.policy;
    const by = new Map<string, Member>();
    for (const l of leaves(this.state)) {
      const node = this.state.ratchetTree[l.leafIndex * 2] as mls.NodeLeaf;
      const cert = certificateFromCredential(node.leaf.credential as never)!;
      const m: Member = by.get(l.root) ?? { fingerprint: l.root, address: l.address, devices: [], admin: policy.admins.includes(l.root), pending: true };
      m.devices.push({ leafIndex: l.leafIndex, deviceId: cert.deviceId, device: l.device });
      if (!unjoinedLeaf(node) || l.leafIndex === this.myLeaf) m.pending = false;
      by.set(l.root, m);
    }
    return [...by.values()];
  }

  async persist() {
    const dev = this.chat.opts.device;
    // Group state holds epoch and ratchet secrets: box 2, overwritten (and the old copy wiped) each change.
    await dev.ephemeral.put(`chat/state/${this.meta.groupId}`, mls.encodeGroupState(this.state));
    this.meta.ownMail = this.meta.ownMail.slice(-500);
    if (this.meta.ownHashes) this.meta.ownHashes = this.meta.ownHashes.slice(-200);
    if (this.meta.seenHashes) this.meta.seenHashes = this.meta.seenHashes.slice(-200);
    await dev.keystore.put(`chat/group/${this.meta.groupId}`, jsonBytes(this.meta));
  }

  private requireActive() {
    if (!this.active) throw new KeyholdError('not_member', 'not a member of this group any more');
  }

  // ---- Sending ----

  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    // Anything queued after an open batch runs after it, so later sends must not join it.
    this.openBatch = undefined;
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  /**
   * Sends waiting for their turn, shipped together when it comes. A send that finds the queue
   * free goes out at once (a batch of one); sends made while it is in flight collect here and
   * go out as one write when it finishes, each still its own message with its own key.
   */
  private openBatch: PendingSend[] | undefined;

  /**
   * Encrypt and post one message. Rotates keys first when the rotation policy says so.
   * Sends made while an earlier one is still going out are posted together, in order.
   */
  send(content: AppContent): Promise<AppMessage> {
    return new Promise<AppMessage>((resolve, reject) => {
      const item: PendingSend = { content, resolve, reject };
      if (this.openBatch && this.openBatch.length < MAX_BATCH) {
        this.openBatch.push(item);
        return;
      }
      const batch: PendingSend[] = [item];
      void this.exclusive(async () => {
        if (this.openBatch === batch) this.openBatch = undefined; // its turn: it is closed now
        try {
          const sent = await this.sendNow(batch.map((b) => b.content));
          batch.forEach((b, i) => b.resolve(sent[i]!));
        } catch (e) {
          batch.forEach((b) => b.reject(e));
        }
      });
      this.openBatch = batch;
    });
  }

  /** Encrypt several messages in order, each with its own key, and post them in one write. */
  private async sendNow(contents: AppContent[]): Promise<AppMessage[]> {
    this.requireActive();
    // Never encrypt for a stale epoch: members who joined or rotated since couldn't read it.
    // A sync that finished a moment ago is as good (see syncedJustNow), and saves the round trips.
    const fast = this.syncedJustNow();
    if (!fast) {
      await this.pull();
      this.requireActive();
      if (this.rotationDue()) await this.commit([]);
    }
    const messages = contents.map((content) => {
      // Strictly increasing times, so a burst keeps its order wherever it is sorted by time.
      const ts = Math.max(this.chat.now(), this.lastSentTs + 1);
      this.lastSentTs = ts;
      return { v: 1, id: newMessageId(), ts, ...content, ...(fast ? { fast: true } : {}) } as AppMessage;
    });
    return this.encryptAndPost(messages, fast);
  }

  /**
   * May a send skip its sync? Only when everything this device knows says the group is quiet:
   * a full sync finished within `sendFreshMs`, the epoch has been the same for a while (people
   * joining or being removed come in bursts, and a removed member must not get one more
   * message), and nothing is waiting for a sync to sort out. What this can't know, a change that
   * landed since that sync, is caught afterwards (repostStale).
   */
  private syncedJustNow(): boolean {
    const fresh = this.chat.opts.sendFreshMs;
    if (!(fresh > 0)) return false;
    this.noteEpoch();
    const now = this.chat.now();
    const age = now - this.pulledAt;
    if (!(age >= 0 && age < fresh)) return false; // also a clock that jumped back
    if (now - this.epochChangedAt < fresh * EPOCH_SETTLE) return false;
    if (this.rotationDue() || this.meta.needsHeal || this.meta.rejoin || this.meta.freshLeaf || this.meta.accessLost) return false;
    if (Object.keys(this.state.unappliedProposals).length > 0) return false;
    if (this.meta.outbox?.length) return false; // an earlier send is unsettled: a sync sorts it out
    if (this.meta.pending.some((m) => BigInt(m.epoch) > this.epoch)) return false; // mail from an epoch we haven't reached
    if (this.meta.fastSent?.some((f) => BigInt(f.epoch) < this.epoch)) return false; // a repost is due
    if ((this.meta.fastSent?.length ?? 0) >= MAX_FAST_SENT) return false; // tracking is full: sync, which settles it
    return true;
  }

  /** Encrypt these messages in order, each with its own key, save them, then post them in one write. */
  private async encryptAndPost(messages: AppMessage[], fast: boolean): Promise<AppMessage[]> {
    const cs = await ciphersuite();
    const mailbox = this.chat.provider.mailbox;
    const batch: OutboxItem[] = [];
    for (const message of messages) {
      const res = await mls.createApplicationMessage(this.state, encodeAppMessage(message), cs);
      this.state = res.newState;
      this.meta.sentSinceUpdate++;
      res.consumed.forEach(mls.zeroOutUint8Array);
      const wire = encodeMsg({ wireformat: 'mls_private_message', version: 'mls10', privateMessage: res.privateMessage });
      batch.push({ message, wire: b64(wire), hash: await hashEntry(wire), id: mailbox.newId?.(), epoch: String(this.epoch) });
    }
    // Persist the advanced ratchet BEFORE the ciphertext leaves: a crash must never lead to a
    // second message with the same generation (nonce reuse). The ciphertext (and its mail id) is
    // saved with it, so a retry posts the very same message and our own copy is never foreign.
    this.meta.outbox = [...(this.meta.outbox ?? []), ...batch];
    this.meta.ownHashes = [...(this.meta.ownHashes ?? []), ...batch.map((b) => b.hash)];
    if (fast) {
      const at = this.chat.now();
      this.meta.fastSent = [...(this.meta.fastSent ?? []), ...batch.map((b) => ({ message: b.message, epoch: b.epoch, at, hash: b.hash }))].slice(-MAX_FAST_SENT);
    }
    await this.persist();
    await this.postOutbox(batch);
    return batch.map((b) => b.message);
  }

  /**
   * After a sync: what was sent without one first (fastSent) and turned out to be encrypted in an
   * epoch the group had already left is sent again in the current epoch, with the same message
   * id. Someone who joined in between gets it; everyone else already has it and, delivery being
   * at least once, keeps the copy they have. The rest is settled once it has been watched for a
   * while (a commit can show up late on a channel whose reads lag).
   */
  private async repostStale(): Promise<void> {
    const list = this.meta.fastSent;
    if (!list?.length) return;
    const now = this.chat.now();
    const stale = list.filter((f) => BigInt(f.epoch) < this.epoch);
    const watch = list.filter((f) => BigInt(f.epoch) >= this.epoch && now - f.at < this.chat.opts.sendFreshMs * EPOCH_SETTLE);
    const set = (l: NonNullable<GroupMeta['fastSent']>) => {
      if (l.length) this.meta.fastSent = l;
      else delete this.meta.fastSent;
    };
    set(watch);
    if (!stale.length) return;
    try {
      // The copy went out after a sync: not `fast` (it is the one a removed device never gets).
      await this.encryptAndPost(
        stale.map(({ message: { fast: _f, ...m }, hash }) => (hash ? { ...m, orig: hash } : m) as AppMessage),
        false,
      );
    } catch {
      // The originals are sent; a copy that did not go out is not an unsent message. Try again
      // at the next sync, a few times.
      const ids = new Set(stale.map((f) => f.message.id));
      const left = (this.meta.outbox ?? []).filter((o) => !ids.has(o.message.id));
      if (left.length) this.meta.outbox = left;
      else delete this.meta.outbox;
      set([...stale.map((f) => ({ ...f, tries: (f.tries ?? 0) + 1 })).filter((f) => f.tries < 3), ...watch]);
      await this.persist();
    }
  }

  /** Post saved ciphertexts (all or none where the provider can batch), then deliver them as ours. */
  private async postOutbox(items: OutboxItem[]) {
    const mailbox = this.chat.provider.mailbox;
    const space = this.meta.space;
    const posted: OutboxItem[] = [];
    try {
      if (items.length > 1 && mailbox.postMany) {
        const ids = await mailbox.postMany(space, items.map((i) => unb64(i.wire)), items.every((i) => i.id) ? { ids: items.map((i) => i.id!) } : undefined);
        await this.landed(items, ids);
        posted.push(...items);
      } else {
        for (const item of items) {
          const id = await mailbox.post(space, unb64(item.wire), item.id ? { id: item.id } : undefined);
          await this.landed([item], [id]);
          posted.push(item);
        }
      }
    } catch (e) {
      if (typeof e === 'object' && e !== null) unsentByError.set(e, items.filter((i) => !posted.includes(i)).map((i) => i.message));
      throw e;
    }
    await this.redeliver(this.buffered);
    await this.persist();
  }

  /** These saved messages are in the mailbox (under `ids`): ours, to hand to the app. */
  private async landed(items: OutboxItem[], ids: string[]) {
    const done = new Set(items.map((i) => i.hash));
    this.meta.outbox = (this.meta.outbox ?? []).filter((o) => !done.has(o.hash));
    if (!this.meta.outbox.length) delete this.meta.outbox;
    this.meta.ownMail.push(...ids);
    const me = this.chat.identity;
    // Our own name or picture change holds here too (others apply it when they receive it).
    if (this.policy.admins.includes(me.fingerprint)) for (const i of items) if (i.message.t === 'meta') this.applyMeta(i.message);
    const from = { fingerprint: me.fingerprint, address: me.address, deviceId: me.deviceId };
    this.meta.undelivered = [...(this.meta.undelivered ?? []), ...items.map((i) => ({ message: i.message, from, epoch: i.epoch, own: true }))];
    // Saved before onMessage runs: if the tab closes now, the next sync hands them over.
    await this.persist();
  }

  /** Messages this device encrypted and saved, not yet known to be posted (oldest first). */
  unsent(): AppMessage[] {
    return (this.meta.outbox ?? []).map((o) => o.message);
  }

  /**
   * Post again what a failed send left (all of it, or only `messageId`): the same ciphertext,
   * and the same mail id where the provider has `mailbox.newId`, so a message whose first post
   * did land is not sent twice. A sync first looks for copies that landed. Resolves with the
   * messages that are now sent; throws (see `unsentMessages`) if posting fails again.
   */
  resend(messageId?: string): Promise<AppMessage[]> {
    return this.exclusive(async () => {
      const want = this.unsent().filter((m) => messageId === undefined || m.id === messageId);
      if (!want.length) return [];
      this.requireActive();
      await this.pull(); // finds copies that landed, and moves them out of the outbox
      const ids = new Set(want.map((m) => m.id));
      const items = (this.meta.outbox ?? []).filter((o) => ids.has(o.message.id));
      if (items.length) await this.postOutbox(items);
      return want;
    });
  }

  /** Stop trying to send this message (it may still have landed, if a reply was lost). */
  discardUnsent(messageId: string): Promise<void> {
    return this.exclusive(async () => {
      const left = (this.meta.outbox ?? []).filter((o) => o.message.id !== messageId);
      if (left.length === (this.meta.outbox ?? []).length) return;
      if (left.length) this.meta.outbox = left;
      else delete this.meta.outbox;
      await this.persist();
    });
  }

  /**
   * Hand decrypted messages to `onMessage`, oldest first. If it throws, this one and the rest
   * stay for the next sync (they are saved with the group state, whose keys for them are spent).
   */
  private async redeliver(out: SyncResult): Promise<void> {
    const list = this.meta.undelivered;
    if (!list?.length) return;
    let n = 0;
    try {
      for (const u of list) {
        const m: ReceivedMessage = { message: u.message, from: u.from, epoch: BigInt(u.epoch) };
        await this.chat.opts.onMessage?.(this, m);
        n++;
        if (!u.own) out.messages.push(m);
      }
    } catch (e) {
      if (!out.events.some((ev) => ev.type === 'delivery-failed')) out.events.push({ type: 'delivery-failed', reason: (e as Error)?.message ?? String(e), waiting: list.length - n });
    }
    const rest = list.slice(n);
    // An app that never takes them must not grow this forever (it is saved on every change).
    for (const d of rest.splice(0, Math.max(0, rest.length - 1000))) out.events.push({ type: 'undecryptable', id: d.message.id, reason: 'the app did not take it' });
    if (rest.length) this.meta.undelivered = rest;
    else delete this.meta.undelivered;
  }
  private lastSentTs = 0;

  /** Seal an attachment with a fresh key, upload it (box 7) and send the reference. */
  async sendAttachment(data: Uint8Array, info: { name?: string; mime?: string; caption?: string } = {}) {
    const p = this.chat.provider;
    if (data.length > p.limits.maxBlobBytes) throw new KeyholdError('config', 'attachment too large for this provider');
    const raw = randomBytes(32);
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const sealed = await seal(key, data, { type: 'attachment', group: this.meta.groupId });
    const ref = await p.blobs.put(this.meta.space, sealed);
    const file: AttachmentRef = { ref, key: b64(raw), hash: b64(await sha256(sealed)), size: data.length, mime: info.mime, name: info.name };
    raw.fill(0);
    return this.send({ t: 'attachment', file, caption: info.caption });
  }

  async fetchAttachment(file: AttachmentRef): Promise<Uint8Array> {
    const sealed = await this.chat.provider.blobs.get(this.meta.space, file.ref);
    if (!sealed) throw new KeyholdError('not_found', 'attachment is gone');
    if (b64(await sha256(sealed)) !== file.hash) throw new KeyholdError('decrypt_failed', 'attachment was changed');
    const key = await crypto.subtle.importKey('raw', unb64(file.key), 'AES-GCM', false, ['decrypt']);
    return openSealed(key, sealed, { type: 'attachment', group: this.meta.groupId });
  }

  // ---- Membership ----

  /**
   * Invite someone: write an admin-signed ticket to their drop box (box 8), give them channel
   * access and drop a notice in their inbox (box 11). They join when they accept.
   */
  invite(address: Address, options: InviteOptions = {}): Promise<InviteTicket> {
    return this.inviteMany([address], options).then(([r]) => {
      if (r!.error) throw r!.error;
      return r!.ticket!;
    });
  }

  /**
   * Invite several people at once. Their identities and pre-keys are read side by side, every
   * pre-key device is added in ONE commit, all tickets and Welcomes go up together (one write
   * where the provider can batch), and the channel invitations go out in parallel. Each person
   * gets their own result: one failing doesn't stop the others.
   */
  async inviteMany(addresses: Address[], options: InviteOptions = {}): Promise<InviteResult[]> {
    // Reads that don't depend on group state run before taking the lock, all at once.
    const prepared = await Promise.all(addresses.map((a) => this.prepareInvite(a, options)));
    return this.exclusive(() => this.inviteManyNow(prepared, options));
  }

  private async prepareInvite(address: Address, options: InviteOptions): Promise<PreparedInvite> {
    try {
      const look = await this.chat.opts.registry.lookup(address);
      if (look.status === 'key-changed') throw new KeyholdError('key_changed', `${address} has a new identity key; confirm it first`);
      if (look.status === 'none' && options.requireIdentity) throw new KeyholdError('not_found', `${address} has no identity yet`);
      const view = look.status === 'ok' ? look.view : undefined;
      const kps = view ? await this.chat.preKeysOf(view) : [];
      return { address, view, kps };
    } catch (error) {
      return { address, kps: [], error: error as Error };
    }
  }

  private async inviteManyNow(people: PreparedInvite[], options: InviteOptions): Promise<InviteResult[]> {
    this.requireActive();
    // The first invitation into a group made a moment ago: nobody else can have written to its
    // space yet, so there is nothing to read first. (Were that ever wrong, the commit below
    // would not land: log entries are create-only.)
    const fresh = this.chat.now() - this.createdAt < JUST_CREATED_MS;
    this.createdAt = -Infinity;
    if (!fresh) await this.pull();
    const me = this.chat.identity;
    const policy = this.policy;
    if (policy.adds === 'none' || (policy.adds === 'admins' && !policy.admins.includes(me.fingerprint))) {
      throw new KeyholdError('policy_rejected', 'you may not invite people to this group');
    }
    const inGroup = new Set(leaves(this.state).map((l) => l.root));
    // People with a device that joined: their channel access is theirs to keep.
    const joined = new Set(leaves(this.state).filter((l) => !unjoinedLeaf(this.state.ratchetTree[l.leafIndex * 2] as mls.NodeLeaf)).map((l) => l.address));
    let room = policy.maxPeople > 0 ? policy.maxPeople - inGroup.size : Infinity;
    for (const p of people) {
      if (p.error) continue;
      if (p.view && inGroup.has(p.view.fingerprint)) continue; // already in: no extra seat
      if (room <= 0) p.error = new KeyholdError('policy_rejected', `at most ${policy.maxPeople} people`);
      else room--;
    }
    const ok = people.filter((p) => !p.error);
    await this.dropEndedInvitees(ok.filter((p) => !joined.has(p.address)).map((p) => p.address));
    // With pre-keys, add every device of theirs that has one now, so the group can write to
    // them before they accept. The ticket still goes out: it lets a device that has no usable
    // pre-key (or whose Welcome can't be opened) join when they accept.
    const drops: { tag: string; data: Bytes }[] = [];
    const welcome = await this.addWithPreKeys(ok.flatMap((p) => p.kps));
    const expiresAt = this.chat.now() + (options.ttlMs ?? 7 * DAY);
    const cs = await ciphersuite();
    for (const p of ok) {
      const tag = await recipientTag(p.address);
      if (welcome && p.kps.length) drops.push({ tag, data: welcome });
      p.ticket = await signTicket({ group: this.meta.groupId, to: p.address, toRoot: p.view?.fingerprint, by: me.cert, expiresAt, nonce: b64(randomBytes(16)) }, (m) =>
        cs.signature.sign(me.signKey, m),
      );
      drops.push({ tag, data: encodeTicket(p.ticket) });
      if (!p.ticket.toRoot) this.meta.awaitingUpgradeUntil = Math.max(this.meta.awaitingUpgradeUntil ?? 0, p.ticket.expiresAt);
    }
    await this.putDrops(drops);
    // Channel invitations are independent of each other. Only a space owner's are; anyone else
    // asks the owner's app through the group, one message at a time.
    const owner = await this.chat.provider.channel.canManage(this.meta.space);
    const grant = async (p: PreparedInvite) => {
      try {
        const payload = options.note && p.kps.length && this.chat.opts.features.inboxPayload ? await sealInviteNote(options.note, p.kps, me.address) : undefined;
        await this.grantChannel(p.address, expiresAt, payload, !joined.has(p.address));
      } catch (error) {
        p.error = error as Error;
      }
    };
    if (owner) await Promise.all(ok.map(grant));
    else for (const p of ok) await grant(p);
    return people.map((p) => (p.error ? { address: p.address, error: p.error } : { address: p.address, ticket: p.ticket! }));
  }

  /** All drop-box items in one write when the provider can batch, else one by one. */
  private async putDrops(items: { tag: string; data: Bytes }[]) {
    const box = this.chat.provider.dropBox;
    if (!items.length) return;
    if (box.putMany && items.length > 1) await box.putMany(this.meta.space, items);
    else for (const it of items) await box.put(this.meta.space, it.tag, it.data);
  }

  /** Add these pre-key devices in one commit. Returns the encoded Welcome, if one was made. */
  private async addWithPreKeys(kps: mls.KeyPackage[]): Promise<Bytes | undefined> {
    if (!kps.length) return undefined;
    const fresh = () => {
      const inTree = new Set(leaves(this.state).map((l) => l.device));
      const seen = new Set<string>();
      return kps.filter((kp) => {
        const d = b64(kp.leafNode.signaturePublicKey);
        if (inTree.has(d) || seen.has(d)) return false;
        seen.add(d);
        return true;
      });
    };
    if (!fresh().length) return undefined;
    let res: mls.CreateCommitResult | undefined;
    try {
      res = await this.commit(() => fresh().map((kp) => ({ proposalType: 'add', add: { keyPackage: kp } }) as mls.Proposal), () => fresh().length > 0);
    } catch (err) {
      // A broken or stale pre-key must not block the invite: the ticket still works.
      if ((err as KeyholdError).code === 'conflict' || (err as KeyholdError).code === 'policy_rejected') throw err;
      return undefined;
    }
    if (!res?.welcome) return undefined;
    return encodeMsg({ wireformat: 'mls_welcome', version: 'mls10', welcome: res.welcome });
  }

  /**
   * Sign a ticket and leave it in the invitee's drop box. Without a known root key the ticket
   * names only the address: members won't accept it, but it lets the invitee ask for a
   * root-bound one once they have an identity (see `answerJoinRequests`).
   */
  private async issueTicket(address: Address, toRoot: string | undefined, expiresAt: number) {
    const me = this.chat.identity;
    const cs = await ciphersuite();
    const ticket = await signTicket({ group: this.meta.groupId, to: address, toRoot, by: me.cert, expiresAt, nonce: b64(randomBytes(16)) }, (m) =>
      cs.signature.sign(me.signKey, m),
    );
    await this.chat.provider.dropBox.put(this.meta.space, await recipientTag(address), encodeTicket(ticket));
    return ticket;
  }

  /**
   * Upgrade address-only invites for people who now have an identity. Stateless, so any device
   * of the issuer (or any admin reading the request) can answer: the original ticket is found
   * in the invitee's drop box and checked like any other.
   */
  private async answerJoinRequests() {
    const p = this.chat.provider;
    const tag = await recipientTag(this.chat.identity.address);
    for (const d of await p.dropBox.list(this.meta.space, tag)) {
      let req: JoinRequest | undefined;
      try {
        req = parseJsonBytes<JoinRequest>(d.data);
      } catch {
        req = undefined;
      }
      if (!req || req.t !== 'join-request') continue;
      await p.dropBox.delete(this.meta.space, tag, d.id);
      if (!verifyDeviceCertificate(req.cert)) continue;
      const address = req.cert.address;
      const original = await this.findTicket(address, (t) => t.nonce === req!.nonce && t.toRoot === undefined);
      if (!original) continue;
      // The channel is the authority for addresses: only the owner of the address can write
      // its directory, so the requester's root must be the one published there.
      const look = await this.chat.opts.registry.lookup(address).catch(() => undefined);
      if (look?.status !== 'ok' || look.view.fingerprint !== fingerprint(unb64(req.cert.root))) continue;
      await this.issueTicket(address, look.view.fingerprint, original.expiresAt);
    }
  }

  /** An unexpired ticket for this group in someone's drop box, signed by someone allowed to add. */
  private async findTicket(address: Address, match: (t: InviteTicket) => boolean = () => true): Promise<InviteTicket | undefined> {
    const policy = this.policy;
    for (const d of await this.chat.provider.dropBox.list(this.meta.space, await recipientTag(address))) {
      const t = decodeTicket(d.data);
      if (!t || t.to !== address || !match(t)) continue;
      const cs = await ciphersuite();
      const v = await verifyTicket(t, unb64(this.meta.groupId), this.chat.now(), (pk, m, sg) => cs.signature.verify(pk, m, sg));
      if (v && (policy.admins.includes(v.issuerRoot) || policy.adds === 'members')) return t;
    }
    return undefined;
  }

  /**
   * `fresh`: they aren't in the group, so they must get an invitation they can see and accept.
   * Still having channel access (left over from before a removal) would send none: take it away
   * and invite again.
   */
  private async grantChannel(address: Address, expiresAt: number, payload?: Bytes, fresh = false) {
    const p = this.chat.provider;
    let r = await p.channel.grant(this.meta.space, address);
    if (r.status === 'already-member' && fresh && (await p.channel.revoke(this.meta.space, address)) === 'done') r = await p.channel.grant(this.meta.space, address);
    if (r.status === 'invited' || r.status === 'already-member') (this.meta.grantedAt ??= {})[address] = this.chat.now();
    if (r.status === 'invited') {
      await p.inviteInbox.send(address, payload ? { pointer: r.pointer, payload } : { pointer: r.pointer });
    } else if (r.status === 'needs-manager') {
      // Only the space owner can let people in on this channel: ask their app (it checks we are an admin).
      await this.sendNow([{ t: 'sys.grant', address, expiresAt }]);
    }
  }

  /** Add someone who is offline, using a one-time KeyPackage from box 4 (build option). */
  addOffline(address: Address) {
    return this.exclusive(() => this.addOfflineNow(address));
  }

  private async addOfflineNow(address: Address) {
    this.requireActive();
    const f = this.chat.opts.features;
    if (!f.offlineAdd) throw new KeyholdError('unsupported', 'offline add is not enabled');
    const look = await this.chat.opts.registry.lookup(address);
    if (look.status !== 'ok') throw new KeyholdError(look.status === 'none' ? 'not_found' : 'key_changed', `cannot verify ${address}`);
    let kpBytes = await this.chat.provider.claimOnce!.claim(address);
    if (!kpBytes && f.lastResortKeyPackages) kpBytes = look.view.lastResortKeyPackage;
    if (!kpBytes) throw new KeyholdError('not_found', `${address} has no KeyPackages left; invite them instead`);
    const msg = decodeMsg(kpBytes);
    if (msg.wireformat !== 'mls_key_package') throw new KeyholdError('bad_format', 'not a KeyPackage');
    const cert = certificateFromCredential(msg.keyPackage.leafNode.credential as never);
    if (!cert || !verifyDeviceCertificate(cert) || fingerprint(unb64(cert.root)) !== look.view.fingerprint || !look.view.devices.has(cert.device)) {
      throw new KeyholdError('bad_signature', 'the KeyPackage is not from a current device of that person');
    }
    const res = await this.commit([{ proposalType: 'add', add: { keyPackage: msg.keyPackage } }]);
    if (!res.welcome) throw new KeyholdError('config', 'no Welcome produced');
    const p = this.chat.provider;
    await p.dropBox.put(this.meta.space, await recipientTag(address), encodeMsg({ wireformat: 'mls_welcome', version: 'mls10', welcome: res.welcome }));
    await this.grantChannel(address, this.chat.now() + 7 * DAY);
  }

  /** Remove a person (all their devices). MLS first, then channel access. */
  remove(fingerprintToRemove: string) {
    return this.exclusive(() => this.removeNow(fingerprintToRemove));
  }

  private async removeNow(fingerprintToRemove: string) {
    this.requireActive();
    await this.pull();
    const targets = leaves(this.state).filter((l) => l.root === fingerprintToRemove);
    if (targets.length === 0) return;
    const address = targets[0]!.address;
    await this.commit(targets.map((t) => ({ proposalType: 'remove', remove: { removed: t.leafIndex } }) as mls.Proposal));
    await this.persist();
    // Tickets and Welcomes still waiting for them would let them back in, and a live ticket keeps
    // their channel access (reconcile spares invitees): a removal ends both.
    await this.clearDrops(address);
    await this.reconcileNow(true);
  }

  /** Remove one of my own other devices (lost or replaced). */
  removeDevice(devicePublicB64: string) {
    return this.exclusive(async () => {
      const t = leaves(this.state).find((l) => l.device === devicePublicB64);
      if (t) await this.commit([{ proposalType: 'remove', remove: { removed: t.leafIndex } }]);
    });
  }

  /** Leave: remove my other devices, propose removing this one; another member commits it. */
  leave() {
    return this.exclusive(() => this.leaveNow());
  }

  private async leaveNow() {
    this.requireActive();
    await this.pull();
    const me = this.chat.identity.fingerprint;
    const policy = this.policy;
    const others = leaves(this.state).filter((l) => l.root !== me);
    if (policy.admins.length === 1 && policy.admins[0] === me && others.length > 0) {
      // Don't strand the group without an admin: promote the longest-standing other member.
      const next = others.sort((a, b) => a.leafIndex - b.leafIndex)[0]!.root;
      await this.setPolicyNow({ ...policy, admins: [next] });
    }
    const mine = leaves(this.state).filter((l) => l.root === me && l.leafIndex !== this.myLeaf);
    if (mine.length) await this.commit(mine.map((t) => ({ proposalType: 'remove', remove: { removed: t.leafIndex } }) as mls.Proposal));
    if (others.length > 0) await this.propose({ proposalType: 'remove', remove: { removed: this.myLeaf } }, true);
    await this.forget();
  }

  private policyProposal(policy: GroupPolicy): mls.Proposal {
    const exts = this.state.groupContext.extensions.filter((e) => e.extensionType !== POLICY_EXTENSION);
    return { proposalType: 'group_context_extensions', groupContextExtensions: { extensions: [...exts, encodePolicy(policy)] } };
  }

  /** Change the policy (admins only). `change` gets the current policy, so a retry after a race re-applies the change. */
  setPolicy(policy: GroupPolicy | ((current: GroupPolicy) => GroupPolicy)) {
    return this.exclusive(() => this.setPolicyNow(policy));
  }

  private async setPolicyNow(policy: GroupPolicy | ((current: GroupPolicy) => GroupPolicy)) {
    await this.commit(() => [this.policyProposal(typeof policy === 'function' ? policy(this.policy) : policy)]);
  }

  /** Ban a device (one of mine, or anyone's if I'm an admin) so it can never rejoin, and remove it. */
  banDevice(devicePublicB64: string) {
    return this.exclusive(async () => {
      const l = leaves(this.state).find((x) => x.device === devicePublicB64);
      await this.banAndRemove([{ device: devicePublicB64, root: l?.root ?? this.chat.identity.fingerprint }]);
    });
  }

  /**
   * Ban first, then remove, in two commits. (ts-mls 1.6.4 produces a commit that receivers
   * can't decrypt when a group-context change and a remove share one commit, so policy
   * changes always travel alone.)
   */
  private async banAndRemove(devices: { device: string; root: string }[]) {
    const fresh = () => devices.filter((d) => !this.policy.banned.some((b) => b.device === d.device));
    if (fresh().length) {
      await this.commit(() => [this.policyProposal({ ...this.policy, banned: [...this.policy.banned, ...fresh()] })], () => fresh().length > 0);
    }
    const targets = () => leaves(this.state).filter((l) => devices.some((d) => d.device === l.device) && l.leafIndex !== this.myLeaf);
    if (targets().length) {
      await this.commit(() => targets().map((t) => ({ proposalType: 'remove', remove: { removed: t.leafIndex } }) as mls.Proposal), () => targets().length > 0);
    }
  }

  /** Post a fresh key update (new epoch). Done automatically by the rotation policy. */
  rotate() {
    return this.exclusive(async () => {
      await this.commit([]);
    });
  }

  rotationDue(): boolean {
    const r = this.chat.opts.rotation;
    return this.meta.sentSinceUpdate >= r.maxMessages || this.chat.now() - this.meta.lastUpdateAt >= r.maxAgeMs;
  }

  /**
   * End this room on this device (after Close, Quit, or a close from the owner): delete the
   * epoch and ratchet secrets right away. Messages already decrypted are the app's business.
   */
  end() {
    return this.exclusive(async () => {
      if (!this.meta.removed) await this.forget();
    });
  }

  private async forget() {
    this.meta.removed = true;
    this.state = { ...this.state, groupActiveState: { kind: 'removedFromGroup', epoch: this.epoch } as never };
    const dev = this.chat.opts.device;
    await dev.ephemeral.delete(`chat/state/${this.meta.groupId}`);
    await dev.keystore.put(`chat/group/${this.meta.groupId}`, jsonBytes(this.meta));
    this.chat.groups.delete(this.meta.groupId);
  }

  private checkLocal(proposals: mls.Proposal[]) {
    const me = this.myLeaf;
    assertAllowed(
      checkCommit({
        policy: this.policy,
        members: leaves(this.state),
        committer: me,
        proposals: proposals.map((p) => summarize({ proposal: p, senderLeafIndex: me })),
        usedNonces: new Set(this.meta.usedNonces),
      }),
    );
  }

  /** Commit with compare-and-swap on the log; on a lost race, sync and try again. */
  private async commit(make: mls.Proposal[] | (() => mls.Proposal[]), stillNeeded: () => boolean = () => true): Promise<mls.CreateCommitResult> {
    const cs = await ciphersuite();
    for (let attempt = 0; attempt < 6; attempt++) {
      if (attempt > 0) await this.syncInner(false);
      this.requireActive();
      if (!stillNeeded()) return undefined as never;
      // Rebuilt on every attempt: after a lost race, leaf indexes and the policy may have changed.
      const proposals = typeof make === 'function' ? make() : make;
      this.checkLocal(proposals);
      const res = await mls.createCommit({ state: this.state, cipherSuite: cs }, { extraProposals: proposals, ratchetTreeExtension: true });
      const entry: LogEntry = {
        v: 1,
        i: this.meta.logNext,
        prev: this.meta.lastHash,
        kind: 'commit',
        epoch: String(res.newState.groupContext.epoch),
        mls: b64(encodeMsg(res.commit)),
        gi: await groupInfoBytes(res.newState, cs),
        ...(this.meta.mailCursor !== undefined && res.welcome ? { mail: this.meta.mailCursor } : {}),
      };
      const bytes = jsonBytes(entry);
      // Keep the would-be state until we know whether the append landed: if the app dies right
      // after a successful append, the next sync recognises our entry and adopts this state
      // (we can't process our own commit, and without it we'd be stuck on the old epoch).
      const pendingKey = `chat/pending/${this.meta.groupId}`;
      const dev = this.chat.opts.device;
      await dev.ephemeral.put(pendingKey, jsonBytes({ hash: await hashEntry(bytes), state: b64(mls.encodeGroupState(res.newState)) }));
      const appended = await this.chat.provider.orderedLog.append(this.meta.space, entry.i, bytes);
      if (appended !== 'ok') await dev.ephemeral.delete(pendingKey);
      if (appended === 'ok') {
        const before = this.members();
        // Proposals waiting in the state go into the commit too (a leave someone proposed).
        const removers = removersOf(leaves(this.state), [
          ...Object.values(this.state.unappliedProposals).flatMap((p) => (p.proposal.proposalType === 'remove' ? [{ removed: p.proposal.remove.removed, sender: p.senderLeafIndex }] : [])),
          ...proposals.flatMap((p) => (p.proposalType === 'remove' ? [{ removed: p.remove.removed, sender: this.myLeaf as number | undefined }] : [])),
        ]);
        // Our entry took the next place in the log: nobody changed the group before it, so what
        // was sent fast in the epoch it was built on was in the newest epoch after all.
        const builtOn = String(this.epoch);
        if (this.meta.fastSent) {
          this.meta.fastSent = this.meta.fastSent.filter((f) => f.epoch !== builtOn);
          if (!this.meta.fastSent.length) delete this.meta.fastSent;
        }
        this.state = res.newState;
        res.consumed.forEach(mls.zeroOutUint8Array);
        await this.recordEntry(bytes, true);
        this.diffMembers(before, this.buffered, removers);
        this.meta.sentSinceUpdate = 0;
        this.meta.lastUpdateAt = this.chat.now();
        this.meta.needsHeal = false;
        // An add-only commit carries no new key for our leaf.
        if (this.meta.freshLeaf) this.meta.freshLeaf = unjoinedLeaf(this.state.ratchetTree[this.myLeaf * 2] as mls.NodeLeaf);
        await this.persist();
        await dev.ephemeral.delete(pendingKey);
        return res;
      }
    }
    throw new KeyholdError('conflict', 'the group kept changing; try again');
  }

  /** `leaving`: this proposal removes us, so once it lands the group is forgotten (also when found after a lost reply). */
  private async propose(p: mls.Proposal, leaving = false) {
    const cs = await ciphersuite();
    for (let attempt = 0; attempt < 6; attempt++) {
      if (attempt > 0) await this.syncInner(false);
      const res = await mls.createProposal(this.state, false, p, cs);
      const entry: LogEntry = { v: 1, i: this.meta.logNext, prev: this.meta.lastHash, kind: 'proposal', epoch: String(this.epoch), mls: b64(encodeMsg(res.message)) };
      const bytes = jsonBytes(entry);
      // As in commit: keep the would-be state until we know whether the append landed, so a
      // lost reply doesn't make the next sync read our own proposal as someone else's.
      const pendingKey = `chat/pending/${this.meta.groupId}`;
      const dev = this.chat.opts.device;
      await dev.ephemeral.put(pendingKey, jsonBytes({ hash: await hashEntry(bytes), state: b64(mls.encodeGroupState(res.newState)), ...(leaving ? { leaving } : {}) }));
      const appended = await this.chat.provider.orderedLog.append(this.meta.space, entry.i, bytes);
      if (appended !== 'ok') await dev.ephemeral.delete(pendingKey);
      if (appended === 'ok') {
        this.state = res.newState;
        await this.recordEntry(bytes, true);
        await this.persist();
        await dev.ephemeral.delete(pendingKey);
        return;
      }
    }
    throw new KeyholdError('conflict', 'the group kept changing; try again');
  }

  private async recordEntry(bytes: Bytes, own: boolean) {
    const h = await hashEntry(bytes);
    if (own) this.meta.ownEntries.push(this.meta.logNext);
    this.meta.hashes[this.meta.logNext] = h;
    this.meta.lastHash = h;
    this.meta.logNext++;
  }

  // ---- Receiving ----

  /** Pull the log and the mailbox, apply commits in order, decrypt messages. */
  async sync(): Promise<SyncResult> {
    // Calls that overlap share one queued pull.
    if (!this.syncing) this.syncing = this.exclusive(() => this.syncInner(true)).finally(() => (this.syncing = undefined));
    await this.syncing;
    const out = this.buffered;
    this.buffered = { messages: [], events: [] };
    return out;
  }

  /** Bring the group up to date; results are buffered for the next sync(). Caller holds the queue. */
  private async pull(): Promise<void> {
    await this.syncInner(true);
  }

  private async syncInner(withAutomation: boolean): Promise<SyncResult> {
    const out = this.buffered;
    if (this.meta.removed) return out;
    const p = this.chat.provider;
    const space = this.meta.space;

    // The log is read while the mailbox is listed (they don't depend on each other: two round
    // trips at once, not one after the other), but applied after it, as before.
    const startedAt = this.chat.now();
    const from = Math.max(0, this.meta.logNext - 1);
    const logRead = p.orderedLog.read(space, from);
    logRead.catch(() => undefined); // handled where it is awaited; not if the mailbox fails first
    // Mailbox first, bucketed by epoch, so each message is opened with the right epoch's keys.
    let mail: Awaited<ReturnType<typeof p.mailbox.list>>;
    try {
      mail = await p.mailbox.list(space, this.meta.mailCursor);
    } catch (err) {
      if ((err as KeyholdError).code !== 'forbidden') throw err;
      if (!this.meta.accessLost) out.events.push({ type: 'access-lost' });
      this.meta.accessLost = true;
      await this.persist();
      return out;
    }
    this.meta.accessLost = false;
    const own = new Set(this.meta.ownMail);
    const ownHashes = new Set([...(this.meta.ownHashes ?? []), ...(this.meta.outbox ?? []).map((o) => o.hash)]);
    const seen = new Set(this.meta.seenHashes ?? []);
    for (const item of mail.items) {
      if (own.has(item.id)) continue;
      const hash = await hashEntry(item.data);
      if (ownHashes.has(hash)) {
        // Ours, though the reply to the post was lost: it landed, so it is sent.
        const sent = (this.meta.outbox ?? []).filter((o) => o.hash === hash);
        if (sent.length) await this.landed(sent, [item.id]);
        else this.meta.ownMail.push(item.id);
        continue;
      }
      if (seen.has(hash)) continue; // the same ciphertext posted twice (a retried send): open it once
      seen.add(hash);
      (this.meta.seenHashes ??= []).push(hash);
      let epoch = '0';
      try {
        const m = decodeMsg(item.data);
        if (m.wireformat !== 'mls_private_message') continue;
        epoch = String(m.privateMessage.epoch);
      } catch {
        out.events.push({ type: 'undecryptable', id: item.id, reason: 'not an MLS message' });
        continue;
      }
      // Written before we were in the group: not for us, and nothing to report.
      if (this.meta.joinedEpoch !== undefined && BigInt(epoch) < BigInt(this.meta.joinedEpoch)) continue;
      this.meta.pending.push({ id: item.id, data: b64(item.data), epoch });
    }
    this.meta.mailCursor = mail.cursor;

    // Log: verify that what we already processed is unchanged, then apply new entries.
    const raw = await logRead;
    if (this.meta.logNext > 0) {
      const first = raw[0];
      const known = this.meta.hashes[from] ?? (from === this.meta.logNext - 1 ? this.meta.lastHash : undefined);
      if (!first || (known && (await hashEntry(first)) !== known)) throw new KeyholdError('rewrite_detected', `the log of ${space} was rewritten`);
    }
    const pendingKey = `chat/pending/${this.meta.groupId}`;
    const pendingRaw = await this.chat.opts.device.ephemeral.get(pendingKey);
    const pendingCommit = pendingRaw ? parseJsonBytes<{ hash: string; state: string; leaving?: boolean }>(pendingRaw) : undefined;
    for (const bytes of raw.slice(this.meta.logNext > 0 ? 1 : 0)) {
      if (pendingCommit && (await hashEntry(bytes)) === pendingCommit.hash) {
        // Our own commit from before a crash: adopt the state we prepared for it.
        this.state = this.chat.decodeState(unb64(pendingCommit.state));
        await this.recordEntry(bytes, true);
        await this.chat.opts.device.ephemeral.delete(pendingKey);
        if (pendingCommit.leaving) {
          // Our leave landed before the reply was lost: finish leaving.
          await this.forget();
          out.events.push({ type: 'removed' });
          return out;
        }
        continue;
      }
      let e: LogEntry | undefined;
      try {
        e = parseJsonBytes<LogEntry>(bytes, 'log entry');
      } catch {
        e = undefined;
      }
      if (!e || e.v !== 1 || e.i !== this.meta.logNext || e.prev !== this.meta.lastHash) {
        // Junk or a broken link at a NEW index: skip it (everyone skips it). History we already
        // processed is checked separately above, and a change there is fatal.
        out.events.push({ type: 'rejected', index: this.meta.logNext, reason: 'malformed log entry' });
        await this.recordEntry(bytes, false);
        continue;
      }
      await this.drainPending(out, (ep) => ep === String(this.epoch));
      if (this.active) await this.applyEntry(e, out);
      await this.recordEntry(bytes, false);
      if (!this.active) break;
    }
    await this.drainPending(out, (ep) => BigInt(ep) <= this.epoch);
    if (withAutomation && this.active) this.reportGaps(out); // not on the retries inside one sync
    if (pendingCommit) await this.chat.opts.device.ephemeral.delete(pendingKey); // it never landed
    await this.persist();

    if (withAutomation && this.active) {
      // Before our own housekeeping commits: only what others did makes a fast send stale.
      await this.repostStale();
      if (this.active) await this.automate(out);
    }
    if (this.active) {
      this.noteEpoch();
      // The group as it was when this sync started, at least: what a send may rely on for a moment.
      this.pulledAt = startedAt;
    }
    return out;
  }

  /** Hashes of mail listed after `addedAtMail` (read once per sync, only when a repeat needs it). */
  private mailAfterAdd?: Set<string>;

  /** A repeat (`orig`) of a fast send: readable here unless its original went up before we joined. */
  private async mayReadRepeat(orig: string): Promise<boolean> {
    if (this.meta.joinedByCommit) return !!this.meta.seenHashes?.includes(orig);
    if (this.meta.addedAtMail === undefined) return true;
    if (this.chat.now() - (this.meta.addedAtMailSince ?? 0) > DAY) {
      delete this.meta.addedAtMail;
      delete this.meta.addedAtMailSince;
      return true;
    }
    if (!this.mailAfterAdd) {
      try {
        const { items } = await this.chat.provider.mailbox.list(this.meta.space, this.meta.addedAtMail);
        this.mailAfterAdd = new Set(await Promise.all(items.map((i) => hashEntry(i.data))));
      } catch {
        return true; // can't tell: better a message too many than one lost
      }
    }
    return this.mailAfterAdd.has(orig);
  }

  private async drainPending(out: SyncResult, ready: (epoch: string) => boolean) {
    this.mailAfterAdd = undefined;
    if (!this.active) return;
    const keep: GroupMeta['pending'] = [];
    for (const item of this.meta.pending) {
      if (!ready(item.epoch)) {
        keep.push(item);
        continue;
      }
      try {
        const m = await this.openApplication(unb64(item.data));
        // A repeat of a fast send whose original went up before we joined: not ours to read.
        if (m && m.message.orig && !(await this.mayReadRepeat(m.message.orig))) continue;
        if (m) {
          if (m.message.fast) this.meta.fastSeen = [...(this.meta.fastSeen ?? []), { id: m.message.id, epoch: String(m.epoch) }].slice(-200);
          await this.handleSystem(m);
          // Kept with the state that spent its key, so an app error can't lose it (see redeliver).
          (this.meta.undelivered ??= []).push({ message: m.message, from: m.from, epoch: String(m.epoch) });
        }
      } catch (e) {
        out.events.push({ type: 'undecryptable', id: item.id, reason: (e as Error).message });
      }
    }
    await this.redeliver(out);
    // Messages for epochs that never arrive (or junk) must not pile up forever.
    const MAX_PENDING = 2000;
    for (const dropped of keep.splice(0, Math.max(0, keep.length - MAX_PENDING))) {
      out.events.push({ type: 'undecryptable', id: dropped.id, reason: 'waited too long for its epoch' });
    }
    this.meta.pending = keep;
  }

  /** Decrypt an application message and learn who sent it (ts-mls doesn't return the sender). */
  private async openApplication(data: Uint8Array): Promise<ReceivedMessage | undefined> {
    const cs = await ciphersuite();
    const msg = decodeMsg(data);
    if (msg.wireformat !== 'mls_private_message' || msg.privateMessage.contentType !== 'application') return undefined;
    const pm = msg.privateMessage;
    const st = this.state;
    const cfg = st.clientConfig.keyRetentionConfig;
    let res: Awaited<ReturnType<typeof unprotectPrivateMessage>>;
    let tree: mls.RatchetTree;
    let senderDataSecret: Uint8Array;
    if (pm.epoch === st.groupContext.epoch) {
      senderDataSecret = st.keySchedule.senderDataSecret;
      res = await unprotectPrivateMessage(st.keySchedule.senderDataSecret, pm, st.secretTree, st.ratchetTree, st.groupContext, cfg, cs);
      tree = st.ratchetTree;
      this.state = { ...st, secretTree: res.tree };
    } else {
      const r = st.historicalReceiverData.get(pm.epoch);
      if (!r) throw new KeyholdError('decrypt_failed', `keys for epoch ${pm.epoch} are gone`);
      senderDataSecret = r.senderDataSecret;
      res = await unprotectPrivateMessage(r.senderDataSecret, pm, r.secretTree, r.ratchetTree, r.groupContext, cfg, cs);
      tree = r.ratchetTree;
      const hist = new Map(st.historicalReceiverData);
      hist.set(pm.epoch, { ...r, secretTree: res.tree });
      this.state = { ...st, historicalReceiverData: hist };
    }
    res.consumed.forEach(mls.zeroOutUint8Array);
    const content = res.content.content;
    if (content.contentType !== 'application' || content.sender.senderType !== 'member') return undefined;
    const node = tree[content.sender.leafIndex * 2];
    if (!node || node.nodeType !== 'leaf') throw new KeyholdError('bad_format', 'unknown sender');
    const cert = certificateFromCredential(node.leaf.credential as never)!;
    const from = { fingerprint: fingerprint(unb64(cert.root)), address: cert.address, deviceId: cert.deviceId };
    // The message opened, so the generation in its sender data is the one its key came from.
    const sd = await decryptSenderData(pm, senderDataSecret, cs);
    if (sd) this.noteGeneration(pm.epoch, content.sender.leafIndex, sd.generation, from);
    return {
      message: decodeAppMessage(content.applicationData),
      from,
      epoch: pm.epoch,
    };
  }

  private noteGeneration(epoch: bigint, leaf: number, gen: number, from: ReceivedMessage['from']) {
    const all = (this.meta.gens ??= {});
    const t = (all[`${epoch}:${leaf}`] ??= { hi: -1, fresh: [], waiting: [], from });
    if (gen > t.hi) {
      // MLS ratchets at most a few hundred steps ahead, so this stays small.
      for (let g = Math.max(t.hi + 1, gen - 1000); g < gen; g++) t.fresh.push(g);
      t.hi = gen;
    } else {
      t.fresh = t.fresh.filter((g) => g !== gen);
      t.waiting = t.waiting.filter((g) => g !== gen);
    }
  }

  /** End of a sync: report holes a previous sync already saw (see GenTrack). */
  private reportGaps(out: SyncResult) {
    const all = this.meta.gens;
    if (!all) return;
    const oldest = this.epoch - BigInt(this.chat.opts.retainEpochs);
    for (const [k, t] of Object.entries(all)) {
      const epoch = BigInt(k.slice(0, k.indexOf(':')));
      const gone = epoch < oldest; // its keys are gone: nothing can fill a hole any more
      const due = gone ? t.waiting.length + t.fresh.length : t.waiting.length;
      if (due) out.events.push({ type: 'gap', from: t.from, epoch, missing: due });
      if (gone) delete all[k];
      else {
        t.waiting = t.fresh;
        t.fresh = [];
      }
    }
  }

  private applyMeta(msg: AppMessage & { t: 'meta' }) {
    if (typeof msg.name === 'string') this.meta.name = msg.name;
    if (typeof msg.avatar === 'string') this.meta.avatar = msg.avatar;
  }

  private async handleSystem(m: ReceivedMessage) {
    const msg = m.message;
    const isAdmin = this.policy.admins.includes(m.from.fingerprint);
    if (msg.t === 'meta' && isAdmin) this.applyMeta(msg);
    if (msg.t === 'sys.grant' && isAdmin && msg.expiresAt > this.chat.now()) {
      if (await this.chat.provider.channel.canManage(this.meta.space)) await this.grantChannel(msg.address, msg.expiresAt);
    }
  }

  private async applyEntry(e: LogEntry, out: SyncResult) {
    if (e.kind === 'genesis' || !e.mls) return;
    const cs = await ciphersuite();
    const before = this.members();
    const msg = decodeMsg(unb64(e.mls));
    const reject = (reason: string) => {
      out.events.push({ type: 'rejected', index: e.i, reason });
      if (e.kind === 'commit') this.meta.needsHeal = true;
    };
    // A commit we can't even process (built on another epoch, or on another branch of this one):
    // not a bad commit to answer with our own, which the others couldn't process either, so both
    // sides would keep committing forever. If it is newer than our state, the group went on
    // without us: rejoin from it. An older one (a lagging branch) is ignored.
    const cannotFollow = (reason: string, builtOn: bigint) => {
      out.events.push({ type: 'rejected', index: e.i, reason });
      if (e.kind === 'commit' && e.gi && builtOn >= this.epoch) {
        // Kept until the rejoin happens: if the GroupInfo turns out not to be a safe place to
        // rejoin (see rejoinProblem), a pending heal must still go out.
        this.meta.rejoin = { at: e.i, gi: e.gi };
      }
    };
    if (msg.wireformat !== 'mls_private_message' && msg.wireformat !== 'mls_public_message') return reject('not a handshake message');
    // Rule shared with joiners (scanLog): a ticket is burned the first time it appears in any
    // external commit in the log, whether or not that commit is accepted.
    const used = new Set(this.meta.usedNonces);
    if (msg.wireformat === 'mls_public_message') {
      const t0 = decodeTicket(msg.publicMessage.content.authenticatedData);
      if (t0 && !used.has(t0.nonce)) this.meta.usedNonces.push(t0.nonce);
    }
    const epoch = msg.wireformat === 'mls_private_message' ? msg.privateMessage.epoch : msg.publicMessage.content.epoch;
    if (epoch !== this.epoch) return cannotFollow(`built on epoch ${epoch}, we are at ${this.epoch}`, epoch);

    const members = leaves(this.state);
    let joiner: { leaf: MemberLeaf; ticket?: VerifiedTicket } | undefined;
    if (msg.wireformat === 'mls_public_message') {
      const c = msg.publicMessage.content;
      if (c.sender.senderType !== 'new_member_commit') return reject('only external commits may be public');
      if (c.contentType !== 'commit' || !c.commit.path) return reject('external commit without path');
      const leaf = leafFromCredential(c.commit.path.leafNode.credential);
      if (!leaf) return reject('joiner has no valid device certificate');
      const t = decodeTicket(c.authenticatedData);
      let ticket: VerifiedTicket | undefined;
      if (t) {
        ticket = await this.chat.verifyTicketSig(t, this.state.groupContext.groupId);
      }
      joiner = { leaf, ticket };
    }

    let verdict: { ok: boolean; reason?: string } = { ok: true };
    const policy = this.policy;
    const removed = new Set<number>();
    const removes: { removed: number; sender: number | undefined }[] = [];
    const callback: mls.IncomingMessageCallback = (incoming) => {
      const proposals = incoming.kind === 'commit' ? incoming.proposals : [incoming.proposal];
      const summaries = proposals.map(summarize);
      for (const s of summaries) if (s.type === 'remove') removed.add(s.removed);
      if (incoming.kind === 'commit') for (const s of summaries) if (s.type === 'remove') removes.push({ removed: s.removed, sender: s.sender });
      if (incoming.kind === 'proposal') {
        const s = summaries[0]!;
        // Standalone proposals: only key updates and removes (leaving) are allowed.
        if (s.type !== 'remove' && s.type !== 'update') {
          verdict = { ok: false, reason: `standalone ${s.type} proposals are not allowed` };
          return 'reject';
        }
      }
      verdict = checkCommit({
        policy,
        members,
        committer: incoming.kind === 'commit' ? incoming.senderLeafIndex : (proposals[0]?.senderLeafIndex ?? undefined),
        proposals: summaries,
        joiner: incoming.kind === 'commit' && incoming.senderLeafIndex === undefined ? joiner : undefined,
        usedNonces: used,
      });
      if (incoming.kind === 'commit' && incoming.senderLeafIndex === undefined && !joiner) verdict = { ok: false, reason: 'external commit not understood' };
      return verdict.ok ? 'accept' : 'reject';
    };
    let result: mls.ProcessMessageResult;
    try {
      result = await mls.processMessage(msg, this.state, mls.emptyPskIndex, callback, cs);
    } catch (err) {
      // Policy and succession verdicts don't throw: this is a commit our keys can't open or check.
      return cannotFollow((err as Error).message, epoch);
    }
    if (result.kind !== 'newState' || result.actionTaken === 'reject' || !verdict.ok) return reject(verdict.reason ?? 'rejected');
    // The committer's new path leaf (and any update) replaces a leaf in place: it must stay the
    // same person under the same address. The callback can't see the path, so compare the trees.
    const swapped = successionViolation(this.state, result.newState, removed);
    if (swapped) return reject(swapped);
    this.state = result.newState;
    result.consumed.forEach(mls.zeroOutUint8Array);
    if (e.kind === 'commit') {
      this.meta.needsHeal = false;
      this.meta.rejoin = undefined;
    }

    const removers = removersOf(members, removes);
    if (this.state.groupActiveState.kind !== 'active') {
      // Sent fast in the epoch that removed us: the sender hadn't seen the removal yet.
      const late = (this.meta.fastSeen ?? []).filter((f) => f.epoch === String(epoch)).map((f) => f.id);
      if (late.length) {
        const gone = new Set(late);
        out.messages = out.messages.filter((m) => !gone.has(m.message.id));
        if (this.meta.undelivered) this.meta.undelivered = this.meta.undelivered.filter((u) => !gone.has(u.message.id));
        out.events.push({ type: 'retracted', ids: late });
      }
      delete this.meta.fastSeen;
      const by = removers.get(this.chat.identity.fingerprint);
      out.events.push(by ? { type: 'removed', by } : { type: 'removed' });
      await this.forget();
      return;
    }
    if (e.kind !== 'commit') return;
    const after = this.members();
    this.diffMembers(before, out, removers);
    const np = this.policy;
    if (JSON.stringify(np) !== JSON.stringify(policy)) out.events.push({ type: 'policy', policy: np });
  }

  /** `removers`: who removed whom in this commit (see removersOf); anyone else gone left. */
  private diffMembers(before: Member[], out: SyncResult, removers?: Map<string, Remover>) {
    const after = this.members();
    for (const m of after) {
      const b = before.find((x) => x.fingerprint === m.fingerprint);
      if (!b) out.events.push({ type: m.pending ? 'added' : 'joined', fingerprint: m.fingerprint, address: m.address });
      else if (b.pending && !m.pending) out.events.push({ type: 'joined', fingerprint: m.fingerprint, address: m.address });
    }
    for (const b of before) {
      if (after.some((m) => m.fingerprint === b.fingerprint)) continue;
      const by = removers?.get(b.fingerprint);
      out.events.push({ type: 'left', fingerprint: b.fingerprint, address: b.address, ...(b.pending ? { pending: true } : {}), ...(by ? { by } : {}) });
    }
  }

  /** Housekeeping after a sync: heal forks, commit pending removes, drop revoked devices, rotate, fix channel access. */
  private async automate(out: SyncResult) {
    const registry = this.chat.opts.registry;
    // Re-read members' directories now and then, so revoked devices get removed.
    for (const m of this.members()) {
      const at = registry.cachedAt(m.address);
      if (at === undefined || this.chat.now() - at > this.chat.opts.directoryMaxAgeMs) {
        try {
          await registry.lookup(m.address);
        } catch {
          /* a broken directory is reported by the app; it never blocks the chat */
        }
      }
    }
    // Devices revoked in their owner's directory: removed and banned by an admin or by another
    // device of the same person (the only members the policy lets do it).
    const me = this.chat.identity.fingerprint;
    const mayActOn = (l: MemberLeaf) => this.policy.admins.includes(me) || l.root === me;
    const revokedNow = () => leaves(this.state).filter((l) => l.leafIndex !== this.myLeaf && registry.isRevoked(l.device, l.address) && mayActOn(l));
    if (this.meta.rejoin) await this.rejoinNow(out);
    const pendingProposals = Object.keys(this.state.unappliedProposals).length > 0;
    if (revokedNow().length || pendingProposals || this.meta.needsHeal || this.meta.freshLeaf) {
      try {
        const revoked = revokedNow();
        if (revoked.length) await this.banAndRemove(revoked.map((l) => ({ device: l.device, root: l.root })));
        await this.commit([], () => this.meta.needsHeal || !!this.meta.freshLeaf || Object.keys(this.state.unappliedProposals).length > 0);
        out.events.push({ type: 'rotated', epoch: this.epoch });
      } catch (err) {
        if ((err as KeyholdError).code !== 'policy_rejected') throw err;
      }
    } else if (this.rotationDue()) {
      await this.commit([]);
      out.events.push({ type: 'rotated', epoch: this.epoch });
    }
    await this.removeUnjoined();
    await this.removeTwins();
    // Only admins issue tickets, so only they answer join requests: on every sync while this
    // device has an address-only invite out, else every 10 minutes (for invites from my other devices).
    const now = this.chat.now();
    const waiting = (this.meta.awaitingUpgradeUntil ?? 0) > now;
    if (this.policy.admins.includes(this.chat.identity.fingerprint) && (waiting || now - this.lastRequests > 10 * 60_000)) {
      this.lastRequests = now;
      await this.answerJoinRequests();
    }
    await this.reconcileNow();
  }

  /**
   * Make channel access follow the group: members and people holding an unexpired ticket keep
   * access; everyone else loses it. Only where this device may manage the space. Stateless (it
   * reads tickets from the drop boxes), so every device of the space owner gets the same answer.
   * Runs when membership changed, or at most every 10 minutes.
   */
  reconcileChannel(force = false): Promise<{ revoked: Address[] }> {
    return this.exclusive(() => this.reconcileNow(force));
  }

  /**
   * Rejoin the group from the newest GroupInfo with an external commit that replaces this device's
   * own leaf (resync). For a device left on a branch the others don't follow: committing there
   * would only grow the fork. Messages sent on the other branch before this are lost to it.
   */
  private async rejoinNow(out: SyncResult) {
    const cs = await ciphersuite();
    const p = this.chat.provider;
    const giveUp = (reason: string) => {
      out.events.push({ type: 'rejected', index: this.meta.rejoin?.at ?? this.meta.logNext, reason: `could not rejoin: ${reason}` });
      this.meta.rejoin = undefined;
    };
    for (let attempt = 0; attempt < 4; attempt++) {
      if (attempt > 0) await this.syncInner(false);
      const want = this.meta.rejoin;
      if (!want || !this.active) return;
      let gi: mls.GroupInfo;
      try {
        const m = decodeMsg(unb64(want.gi));
        if (m.wireformat !== 'mls_group_info') return giveUp('bad GroupInfo');
        gi = m.groupInfo;
      } catch {
        return giveUp('bad GroupInfo');
      }
      if (b64(gi.groupContext.groupId) !== this.meta.groupId) return giveUp('GroupInfo of another group');
      const tree = ratchetTreeOfGroupInfo(gi);
      const untrusted = tree ? await this.chat.untrustedTree(tree, gi.signer) : 'no tree';
      if (untrusted) return giveUp(untrusted);
      const problem = this.rejoinProblem(gi);
      if (problem) return giveUp(problem);
      const myDevice = b64(this.chat.identity.publicKey);
      // Not in the group on that branch: nothing to rejoin (an invitation brings us back).
      if (!leavesOfGroupInfo(gi).some((l) => l.device === myDevice)) return giveUp('this device is not in the group there');
      const kp = await this.chat.keyPackage();
      let made: Awaited<ReturnType<typeof mls.joinGroupExternal>>;
      try {
        made = await mls.joinGroupExternal(gi, kp.publicPackage, kp.privatePackage, true, cs, undefined, this.chat.clientConfig(), new Uint8Array());
      } catch (err) {
        return giveUp((err as Error).message);
      }
      const { publicMessage, newState } = made;
      const entry: LogEntry = {
        v: 1,
        i: this.meta.logNext,
        prev: this.meta.lastHash,
        kind: 'commit',
        epoch: String(newState.groupContext.epoch),
        mls: b64(encodeMsg({ wireformat: 'mls_public_message', version: 'mls10', publicMessage })),
        gi: await groupInfoBytes(newState, cs),
      };
      const bytes = jsonBytes(entry);
      // As in commit: keep the would-be state until we know whether the append landed.
      const pendingKey = `chat/pending/${this.meta.groupId}`;
      const dev = this.chat.opts.device;
      await dev.ephemeral.put(pendingKey, jsonBytes({ hash: await hashEntry(bytes), state: b64(mls.encodeGroupState(newState)) }));
      const appended = await p.orderedLog.append(this.meta.space, entry.i, bytes);
      if (appended !== 'ok') {
        await dev.ephemeral.delete(pendingKey);
        continue; // someone wrote first: read it, then try again on the newest state
      }
      const before = this.members();
      this.state = newState;
      await this.recordEntry(bytes, true);
      this.diffMembers(before, out);
      this.meta.rejoin = undefined;
      this.meta.needsHeal = false;
      this.meta.freshLeaf = undefined;
      this.meta.sentSinceUpdate = 0;
      this.meta.lastUpdateAt = this.chat.now();
      // Like any joiner: what was written before this epoch can't be opened here.
      this.meta.joinedEpoch = String(newState.groupContext.epoch);
      this.meta.pending = this.meta.pending.filter((m) => BigInt(m.epoch) >= newState.groupContext.epoch);
      await this.persist();
      await dev.ephemeral.delete(pendingKey);
      out.events.push({ type: 'rotated', epoch: this.epoch });
      return;
    }
    giveUp('the group kept changing');
  }

  /**
   * Why we must not rejoin from this GroupInfo; undefined when we may. Anyone who can write the
   * log can put a GroupInfo there, so it only counts as "the group went on without us" when it
   * could have come from the group we know:
   * - it is newer than our state (an old one, replayed, would bring back removed people);
   * - it is signed by a device that is a member in our state (not a removed one);
   * - its rules are ours, or a change the signer may make under our rules (admins only);
   * - the people in it are ours, or the signer may add and remove under our rules;
   * - no device in it is banned.
   * Otherwise this device stays where it is and reports it (a `rejected` event): a fork it
   * can't safely leave is better than a group someone else wrote.
   */
  private rejoinProblem(gi: mls.GroupInfo): string | undefined {
    if (gi.groupContext.epoch <= this.epoch) return 'the GroupInfo is not newer than our state';
    let theirs: GroupPolicy;
    try {
      theirs = decodePolicy(gi.groupContext.extensions as never);
    } catch {
      return 'the GroupInfo has no valid policy';
    }
    const ours = this.policy;
    const mine = leaves(this.state);
    const tree = leavesOfGroupInfo(gi);
    const signer = tree.find((l) => l.leafIndex === gi.signer);
    const signerHere = signer && mine.find((l) => l.device === signer.device && l.root === signer.root);
    if (!signerHere) return 'the GroupInfo is signed by a device that is not a member here';
    const admin = ours.admins.includes(signerHere.root);
    if (canonical(theirs) !== canonical(ours)) {
      if (!admin) return 'the GroupInfo changes the group rules';
      if (theirs.kind !== ours.kind) return 'the GroupInfo changes the kind of chat';
    }
    const rootsHere = new Set(mine.map((l) => l.root));
    const rootsThere = new Set(tree.map((l) => l.root));
    for (const r of rootsThere) {
      if (rootsHere.has(r)) continue;
      const mayAdd = ours.adds === 'members' || (ours.adds === 'admins' && admin);
      if (!mayAdd) return 'the GroupInfo has people the signer may not add';
    }
    for (const r of rootsHere) if (!rootsThere.has(r) && !admin && r !== signerHere.root && r !== this.chat.identity.fingerprint) return 'the GroupInfo leaves out people the signer may not remove';
    const banned = new Set([...ours.banned, ...theirs.banned].map((b) => b.device));
    if (tree.some((l) => banned.has(l.device))) return 'the GroupInfo has a banned device';
    if (ours.maxPeople > 0 && rootsThere.size > ours.maxPeople) return `the GroupInfo has more than ${ours.maxPeople} people`;
    return undefined;
  }

  /**
   * Devices added with pre-keys that never joined: removed by an admin after the join deadline,
   * or earlier when `gone` says they no longer can (their channel invitation ended).
   */
  /**
   * One device in the tree twice, both leaves joined (an older app joined a chat twice at once).
   * Anyone joining then fails ("signature keys not unique"). The device itself removes the twin it
   * doesn't use; an admin removes the twins it hasn't heard from, keeping the leaf that last sent.
   * With nothing heard from either, the admin can't tell which is live and leaves them.
   */
  private async removeTwins() {
    const myDevice = b64(this.chat.identity.publicKey);
    const isAdmin = this.policy.admins.includes(this.chat.identity.fingerprint);
    // Newest epoch this leaf sent in. Leaf indexes are reused after removals, so only entries
    // from this very device count.
    const heard = (leaf: number) => {
      const node = this.state.ratchetTree[leaf * 2] as mls.NodeLeaf | undefined;
      const deviceId = node ? certificateFromCredential(node.leaf.credential as never)?.deviceId : undefined;
      let best = -1n;
      for (const [k, t] of Object.entries(this.meta.gens ?? {})) {
        const [e, l] = k.split(':');
        if (Number(l) === leaf && t.from.deviceId === deviceId && BigInt(e!) > best) best = BigInt(e!);
      }
      return best;
    };
    const doomed = () => {
      const byDevice = new Map<string, MemberLeaf[]>();
      for (const l of leaves(this.state)) byDevice.set(l.device, [...(byDevice.get(l.device) ?? []), l]);
      const out: number[] = [];
      for (const [device, ls] of byDevice) {
        if (ls.length < 2) continue;
        if (device === myDevice) {
          out.push(...ls.filter((l) => l.leafIndex !== this.myLeaf).map((l) => l.leafIndex));
          continue;
        }
        if (!isAdmin) continue;
        const ranked = ls.map((l) => ({ l, at: heard(l.leafIndex) })).sort((a, b) => (a.at === b.at ? 0 : a.at > b.at ? -1 : 1));
        if (ranked[0]!.at < 0n || ranked[0]!.at === ranked[1]!.at) continue; // can't tell which one is live
        out.push(...ranked.slice(1).map((x) => x.l.leafIndex));
      }
      return out;
    };
    if (!doomed().length) return;
    try {
      await this.commit(() => doomed().map((i) => ({ proposalType: 'remove', remove: { removed: i } }) as mls.Proposal), () => doomed().length > 0);
    } catch (err) {
      if ((err as KeyholdError).code !== 'policy_rejected') throw err;
    }
  }

  /** `gone(leaf, unjoinedFor)`: their invitation ended, so the leaf goes now. */
  private async removeUnjoined(gone?: (l: MemberLeaf, unjoinedForMs: number) => boolean) {
    const now = this.chat.now();
    const since = (this.meta.unjoinedSince ??= {});
    const unjoined = () => leaves(this.state).filter((l) => l.leafIndex !== this.myLeaf && unjoinedLeaf(this.state.ratchetTree[l.leafIndex * 2] as mls.NodeLeaf));
    const current = unjoined();
    for (const k of Object.keys(since)) if (!current.some((l) => l.device === k)) delete since[k];
    for (const l of current) since[l.device] ??= now;
    if (!this.policy.admins.includes(this.chat.identity.fingerprint)) return;
    const deadline = this.chat.opts.preKeys.joinDeadlineMs;
    // A grace period for the channel check: the invitation is made right after the add.
    // A pre-key leaf of a device that also joined with a leaf of its own is a leftover: two leaves
    // with one signature key make the tree invalid for anyone joining, so it goes at once.
    const joinedTwice = (l: MemberLeaf) => leaves(this.state).some((o) => o.leafIndex !== l.leafIndex && o.device === l.device && !unjoinedLeaf(this.state.ratchetTree[o.leafIndex * 2] as mls.NodeLeaf));
    const due = () => unjoined().filter((l) => joinedTwice(l) || now - (since[l.device] ?? now) >= deadline || gone?.(l, now - (since[l.device] ?? now)));
    if (!due().length) return;
    const goneBefore = new Set(due().filter((l) => gone?.(l, now - (since[l.device] ?? now))).map((l) => l.address));
    try {
      await this.commit(() => due().map((l) => ({ proposalType: 'remove', remove: { removed: l.leafIndex } }) as mls.Proposal), () => due().length > 0);
    } catch (err) {
      if ((err as KeyholdError).code !== 'policy_rejected') throw err;
      return;
    }
    // Their invitation ended: the Welcome and ticket left for them would still let them in later,
    // at the epoch of that old add, so they could read what was sent after they said no.
    const left = new Set(leaves(this.state).map((l) => l.address));
    for (const a of goneBefore) if (!left.has(a)) await this.clearDrops(a);
  }

  /** Delete every Welcome and ticket waiting for this address in the space. */
  private async clearDrops(address: Address) {
    const box = this.chat.provider.dropBox;
    const tag = await recipientTag(address);
    for (const d of await box.list(this.meta.space, tag).catch(() => [])) await box.delete(this.meta.space, tag, d.id).catch(() => undefined);
  }

  /**
   * Before inviting people again: anyone whose earlier invitation ended (declined, expired,
   * withdrawn) but whose pre-key leaves are still in the group loses those leaves and their old
   * Welcome first, so the new invite adds them afresh and they can't read the gap in between.
   */
  private async dropEndedInvitees(addresses: Address[]) {
    const unjoinedOf = (a: Address) =>
      leaves(this.state).some((l) => l.address === a && l.leafIndex !== this.myLeaf && unjoinedLeaf(this.state.ratchetTree[l.leafIndex * 2] as mls.NodeLeaf));
    const stale = addresses.filter(unjoinedOf);
    if (!stale.length) return;
    const ch = this.chat.provider.channel;
    if (!(await ch.canManage(this.meta.space))) return;
    const { active, pending } = await ch.members(this.meta.space);
    const invited = new Set<Address>([...active, ...pending]);
    const ended = new Set(stale.filter((a) => !invited.has(a)));
    if (ended.size) await this.removeUnjoined((l) => ended.has(l.address));
  }

  private async reconcileNow(force = false): Promise<{ revoked: Address[] }> {
    const ch = this.chat.provider.channel;
    if (!this.active || !(await ch.canManage(this.meta.space))) return { revoked: [] };
    const now = this.chat.now();
    const sig = leaves(this.state).map((l) => l.leafIndex + l.root).join();
    // While someone this device invited hasn't joined, look every 2 minutes: a decline should take
    // them out of the encryption soon. Otherwise every 10 minutes.
    const granted = this.meta.grantedAt ?? {};
    const waiting = leaves(this.state).some((l) => granted[l.address] !== undefined && unjoinedLeaf(this.state.ratchetTree[l.leafIndex * 2] as mls.NodeLeaf));
    const every = waiting ? 2 * 60_000 : 10 * 60_000;
    if (!force && this.lastMembership === sig && now - (this.meta.lastReconcile ?? 0) < every) return { revoked: [] };
    this.lastMembership = sig;
    this.meta.lastReconcile = now;
    const { active, pending } = await ch.members(this.meta.space);
    // Added with pre-keys, but their channel invitation is gone (declined or expired): they can
    // never join, so take them out of the group too.
    const invited = new Set<Address>([...active, ...pending]);
    // A grace period for invitations made elsewhere (another device, or the owner's app on an
    // admin's behalf): the invitation follows the add, so give it 10 minutes to show up.
    await this.removeUnjoined((l, unjoinedFor) => !invited.has(l.address) && (granted[l.address] !== undefined || unjoinedFor >= 10 * 60_000));
    // Forget invitations of people who are gone and not invited any more.
    const inTree = new Set(leaves(this.state).map((l) => l.address));
    for (const a of Object.keys(granted)) if (!inTree.has(a) && !invited.has(a)) delete granted[a];
    const candidates: Address[] = [];
    const keep0 = new Set<Address>([ch.self, ...leaves(this.state).map((l) => l.address)]);
    for (const a of new Set([...active, ...pending])) if (!keep0.has(a) && !(await this.findTicket(a))) candidates.push(a);
    const revoked: Address[] = [];
    if (candidates.length === 0) return { revoked };
    // Someone may have joined (and deleted their ticket) since our last read: re-read the log first.
    await this.syncInner(false);
    const keep = new Set<Address>([ch.self, ...leaves(this.state).map((l) => l.address)]);
    for (const a of candidates) {
      if (keep.has(a)) continue;
      if ((await ch.revoke(this.meta.space, a)) === 'done') revoked.push(a);
    }
    await this.persist();
    return { revoked };
  }
}
