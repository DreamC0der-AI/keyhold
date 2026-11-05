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
import { randomBytes, sha256, toHex, utf8 } from '../util/bytes.js';
import { b64, jsonBytes, parseJsonBytes, unb64 } from '../util/codec.js';
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
  type IdentityRegistry,
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
}

const hashEntry = async (b: Bytes) => b64(await sha256(b));

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
  removed?: boolean;
  /** The channel refuses us (for example the owner revoked access after removing us). */
  accessLost?: boolean;
}

export interface RotationPolicy {
  maxAgeMs: number;
  maxMessages: number;
}

export const DEFAULT_ROTATION: RotationPolicy = { maxAgeMs: 7 * DAY, maxMessages: 100 };

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
  /** Called with every decrypted message (for example, the history backup). */
  onMessage?: (group: Group, m: ReceivedMessage) => Promise<void> | void;
  now?: () => number;
}

export interface Member {
  fingerprint: string;
  address: Address;
  devices: { leafIndex: number; deviceId: string; device: string }[];
  admin: boolean;
}

export interface ReceivedMessage {
  message: AppMessage;
  from: { fingerprint: string; address: Address; deviceId: string };
  epoch: bigint;
}

export type GroupEvent =
  | { type: 'joined'; fingerprint: string; address: Address }
  | { type: 'left'; fingerprint: string; address: Address }
  | { type: 'policy'; policy: GroupPolicy }
  | { type: 'rejected'; index: number; reason: string }
  | { type: 'undecryptable'; id: string; reason: string }
  | { type: 'removed' }
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
      return { type: 'update', sender };
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
  readonly opts: Required<Omit<ChatOptions, 'onMessage'>> & Pick<ChatOptions, 'onMessage'>;

  private constructor(opts: ChatOptions) {
    this.opts = {
      rotation: DEFAULT_ROTATION,
      retainEpochs: 4,
      directoryMaxAgeMs: 60 * 60 * 1000,
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
    return { ...caps, ciphersuites: [CIPHERSUITE], extensions: [...caps.extensions, POLICY_EXTENSION] };
  }

  async keyPackage(lifetimeMs = 30 * DAY) {
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
    );
  }

  /** Create a group (or a DM: a group limited to two people) in a new space. */
  async createGroup(kind: 'dm' | 'group' = 'group', name?: string): Promise<Group> {
    const cs = await ciphersuite();
    const space = await this.provider.channel.createSpace(kind);
    const kp = await this.keyPackage();
    const groupId = randomBytes(16);
    const policy = defaultPolicy(kind, this.identity.fingerprint);
    const state = await mls.createGroup(groupId, kp.publicPackage, kp.privatePackage, [encodePolicy(policy)], cs, this.clientConfig());
    const entry: LogEntry = { v: 1, i: 0, prev: '', kind: 'genesis', epoch: '0', gi: await groupInfoBytes(state, cs) };
    const bytes = jsonBytes(entry);
    if ((await this.provider.orderedLog.append(space, 0, bytes)) !== 'ok') throw new KeyholdError('conflict', 'new space already has a log');
    const meta = this.newMeta(b64(groupId), space, 1, await hashEntry(bytes), name);
    meta.ownEntries.push(0);
    const g = new Group(this, meta, state);
    await g.persist();
    this.groups.set(meta.groupId, g);
    if (name) await g.send({ t: 'meta', name });
    return g;
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
   * has a ticket (or a Welcome) for this device. Returns the groups joined.
   */
  async acceptInvites(): Promise<Group[]> {
    const p = this.provider;
    for (const n of await p.inviteInbox.list()) {
      await p.channel.acceptGrant(n.pointer);
      await p.inviteInbox.delete(n.id);
    }
    const known = new Set([...this.groups.values()].map((g) => g.space));
    const joined: Group[] = [];
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
  async join(space: SpaceRef): Promise<Group | undefined> {
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
        await p.dropBox.delete(space, tag, d.id);
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
      const selfJoin = treeLeaves.some((l) => l.root === this.identity.fingerprint);

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
      const { publicMessage, newState } = await mls.joinGroupExternal(gi, kp.publicPackage, kp.privatePackage, false, cs, undefined, this.clientConfig(), ticketBytes);
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
      const key = (await eph.get(`chat/kp/${ref}`)) ? `chat/kp/${ref}` : (await eph.get(`chat/kplr/${ref}`)) ? `chat/kplr/${ref}` : undefined;
      if (!key) continue;
      const stored = parseJsonBytes<{ pub: string; priv: Record<string, string> }>((await eph.get(key))!);
      const pubMsg = decodeMsg(unb64(stored.pub));
      if (pubMsg.wireformat !== 'mls_key_package') continue;
      const priv: mls.PrivateKeyPackage = {
        initPrivateKey: unb64(stored.priv.init!),
        hpkePrivateKey: unb64(stored.priv.hpke!),
        signaturePrivateKey: this.identity.signKey,
      };
      const state = await mls.joinGroup(welcome, pubMsg.keyPackage, priv, mls.emptyPskIndex, cs, undefined, undefined, this.clientConfig());
      // One-time keys are deleted the moment they are used (box 2). Last-resort keys stay.
      if (key.startsWith('chat/kp/')) await eph.delete(key);
      const raw = await this.provider.orderedLog.read(space, 0);
      const scan = await scanLog(raw);
      const at = scan.epochIndex.get(String(state.groupContext.epoch));
      if (at === undefined) throw new KeyholdError('bad_format', 'the commit that added us is not in the log');
      const meta = this.newMeta(b64(state.groupContext.groupId), space, at + 1, scan.hashes[at]!);
      meta.hashes = scan.hashes.slice(0, at + 1);
      meta.usedNonces = [...scan.usedNonces];
      meta.mailCursor = undefined; // messages after the add are readable; older ones fail quietly
      const g = new Group(this, meta, state);
      await g.persist();
      this.groups.set(meta.groupId, g);
      return g;
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

  private async storeKeyPackage(prefix: string, lifetimeMs: number): Promise<Bytes> {
    const cs = await ciphersuite();
    const kp = await this.keyPackage(lifetimeMs);
    const ref = b64(await makeKeyPackageRef(kp.publicPackage, cs.hash));
    const pub = encodeMsg({ wireformat: 'mls_key_package', version: 'mls10', keyPackage: kp.publicPackage });
    // The signature key is the device key (box 1): it is not copied into box 2.
    const priv = { init: b64(kp.privatePackage.initPrivateKey), hpke: b64(kp.privatePackage.hpkePrivateKey) };
    await this.opts.device.ephemeral.put(`${prefix}${ref}`, jsonBytes({ pub: b64(pub), priv }), { expiresAt: this.now() + lifetimeMs });
    return pub;
  }

  /** Members check tickets without a clock (see verifyTicket). */
  async verifyTicketSig(t: InviteTicket, groupId: Uint8Array): Promise<VerifiedTicket | undefined> {
    const cs = await ciphersuite();
    return verifyTicket(t, groupId, undefined, (pk, m, s) => cs.signature.verify(pk, m, s));
  }
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

/** Check the hash chain of a whole log and collect what a joiner needs. */
async function scanLog(raw: Bytes[]): Promise<LogScan> {
  const hashes: string[] = [];
  const usedNonces = new Set<string>();
  const epochIndex = new Map<string, number>();
  let prev = '';
  let lastGi = '';
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
    if (e.gi) lastGi = e.gi;
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

function leavesOfGroupInfo(gi: mls.GroupInfo): MemberLeaf[] {
  const ext = gi.extensions.find((e) => e.extensionType === 'ratchet_tree' || e.extensionType === 2);
  if (!ext) return [];
  return leaves({ ratchetTree: decodeTree(ext.extensionData) } as unknown as mls.ClientState);
}

function decodeTree(b: Uint8Array): mls.RatchetTree {
  const r = decodeRatchetTree(b, 0);
  if (!r) throw new KeyholdError('bad_format', 'bad ratchet tree');
  return r[0];
}

/** One conversation on this device. */
export class Group {
  private syncing: Promise<SyncResult> | undefined;
  private lastMembership = '';
  private lastRequests = 0;
  /** Messages and events found by internal syncs (before a send or commit), returned by the next sync(). */
  private buffered: SyncResult = { messages: [], events: [] };

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
      const m = by.get(l.root) ?? { fingerprint: l.root, address: l.address, devices: [], admin: policy.admins.includes(l.root) };
      m.devices.push({ leafIndex: l.leafIndex, deviceId: cert.deviceId, device: l.device });
      by.set(l.root, m);
    }
    return [...by.values()];
  }

  async persist() {
    const dev = this.chat.opts.device;
    // Group state holds epoch and ratchet secrets: box 2, overwritten (and the old copy wiped) each change.
    await dev.ephemeral.put(`chat/state/${this.meta.groupId}`, mls.encodeGroupState(this.state));
    this.meta.ownMail = this.meta.ownMail.slice(-500);
    await dev.keystore.put(`chat/group/${this.meta.groupId}`, jsonBytes(this.meta));
  }

  private requireActive() {
    if (!this.active) throw new KeyholdError('not_member', 'not a member of this group any more');
  }

  // ---- Sending ----

  /** Encrypt and post one message. Rotates keys first when the rotation policy says so. */
  async send(content: AppContent): Promise<AppMessage> {
    this.requireActive();
    // Never encrypt for a stale epoch: members who joined or rotated since couldn't read it.
    await this.pull();
    this.requireActive();
    if (this.rotationDue()) await this.rotate();
    const cs = await ciphersuite();
    const message = { v: 1, id: newMessageId(), ts: this.chat.now(), ...content } as AppMessage;
    const res = await mls.createApplicationMessage(this.state, encodeAppMessage(message), cs);
    this.state = res.newState;
    this.meta.sentSinceUpdate++;
    // Persist the advanced ratchet BEFORE the ciphertext leaves: a crash must never lead to a
    // second message with the same generation (nonce reuse).
    await this.persist();
    res.consumed.forEach(mls.zeroOutUint8Array);
    const wire = encodeMsg({ wireformat: 'mls_private_message', version: 'mls10', privateMessage: res.privateMessage });
    const id = await this.chat.provider.mailbox.post(this.meta.space, wire);
    this.meta.ownMail.push(id);
    await this.persist();
    const me = this.chat.identity;
    await this.chat.opts.onMessage?.(this, { message, from: { fingerprint: me.fingerprint, address: me.address, deviceId: me.deviceId }, epoch: this.epoch });
    return message;
  }

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
  async invite(address: Address, options: { requireIdentity?: boolean; ttlMs?: number } = {}): Promise<InviteTicket> {
    this.requireActive();
    await this.pull();
    const me = this.chat.identity;
    const policy = this.policy;
    if (policy.adds === 'none' || (policy.adds === 'admins' && !policy.admins.includes(me.fingerprint))) {
      throw new KeyholdError('policy_rejected', 'you may not invite people to this group');
    }
    const people = new Set(leaves(this.state).map((l) => l.root));
    if (policy.maxPeople > 0 && people.size >= policy.maxPeople) throw new KeyholdError('policy_rejected', `at most ${policy.maxPeople} people`);
    const look = await this.chat.opts.registry.lookup(address);
    if (look.status === 'key-changed') throw new KeyholdError('key_changed', `${address} has a new identity key; confirm it first`);
    if (look.status === 'none' && options.requireIdentity) throw new KeyholdError('not_found', `${address} has no identity yet`);
    const ticket = await this.issueTicket(address, look.status === 'ok' ? look.view.fingerprint : undefined, this.chat.now() + (options.ttlMs ?? 7 * DAY));
    if (!ticket.toRoot) this.meta.awaitingUpgradeUntil = Math.max(this.meta.awaitingUpgradeUntil ?? 0, ticket.expiresAt);
    await this.grantChannel(address, ticket.expiresAt);
    return ticket;
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

  private async grantChannel(address: Address, expiresAt: number) {
    const p = this.chat.provider;
    const r = await p.channel.grant(this.meta.space, address);
    if (r.status === 'invited') {
      await p.inviteInbox.send(address, { pointer: r.pointer });
    } else if (r.status === 'needs-manager') {
      // Only the space owner can let people in on this channel: ask their app (it checks we are an admin).
      await this.send({ t: 'sys.grant', address, expiresAt });
    }
  }

  /** Add someone who is offline, using a one-time KeyPackage from box 4 (build option). */
  async addOffline(address: Address) {
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
  async remove(fingerprintToRemove: string) {
    this.requireActive();
    await this.pull();
    const targets = leaves(this.state).filter((l) => l.root === fingerprintToRemove);
    if (targets.length === 0) return;
    const address = targets[0]!.address;
    await this.commit(targets.map((t) => ({ proposalType: 'remove', remove: { removed: t.leafIndex } }) as mls.Proposal));
    await this.persist();
    await this.reconcileChannel(true);
  }

  /** Remove one of my own other devices (lost or replaced). */
  async removeDevice(devicePublicB64: string) {
    const t = leaves(this.state).find((l) => l.device === devicePublicB64);
    if (t) await this.commit([{ proposalType: 'remove', remove: { removed: t.leafIndex } }]);
  }

  /** Leave: remove my other devices, propose removing this one; another member commits it. */
  async leave() {
    this.requireActive();
    await this.pull();
    const me = this.chat.identity.fingerprint;
    const policy = this.policy;
    const others = leaves(this.state).filter((l) => l.root !== me);
    if (policy.admins.length === 1 && policy.admins[0] === me && others.length > 0) {
      // Don't strand the group without an admin: promote the longest-standing other member.
      const next = others.sort((a, b) => a.leafIndex - b.leafIndex)[0]!.root;
      await this.setPolicy({ ...policy, admins: [next] });
    }
    const mine = leaves(this.state).filter((l) => l.root === me && l.leafIndex !== this.myLeaf);
    if (mine.length) await this.commit(mine.map((t) => ({ proposalType: 'remove', remove: { removed: t.leafIndex } }) as mls.Proposal));
    if (others.length > 0) await this.propose({ proposalType: 'remove', remove: { removed: this.myLeaf } });
    await this.forget();
  }

  private policyProposal(policy: GroupPolicy): mls.Proposal {
    const exts = this.state.groupContext.extensions.filter((e) => e.extensionType !== POLICY_EXTENSION);
    return { proposalType: 'group_context_extensions', groupContextExtensions: { extensions: [...exts, encodePolicy(policy)] } };
  }

  /** Change the policy (admins only). `change` gets the current policy, so a retry after a race re-applies the change. */
  async setPolicy(policy: GroupPolicy | ((current: GroupPolicy) => GroupPolicy)) {
    await this.commit(() => [this.policyProposal(typeof policy === 'function' ? policy(this.policy) : policy)]);
  }

  /** Ban a device (one of mine, or anyone's if I'm an admin) so it can never rejoin, and remove it. */
  async banDevice(devicePublicB64: string) {
    const l = leaves(this.state).find((x) => x.device === devicePublicB64);
    await this.banAndRemove([{ device: devicePublicB64, root: l?.root ?? this.chat.identity.fingerprint }]);
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
  async rotate() {
    await this.commit([]);
  }

  rotationDue(): boolean {
    const r = this.chat.opts.rotation;
    return this.meta.sentSinceUpdate >= r.maxMessages || this.chat.now() - this.meta.lastUpdateAt >= r.maxAgeMs;
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
        this.state = res.newState;
        res.consumed.forEach(mls.zeroOutUint8Array);
        await this.recordEntry(bytes, true);
        this.diffMembers(before, this.buffered);
        this.meta.sentSinceUpdate = 0;
        this.meta.lastUpdateAt = this.chat.now();
        this.meta.needsHeal = false;
        await this.persist();
        await dev.ephemeral.delete(pendingKey);
        return res;
      }
    }
    throw new KeyholdError('conflict', 'the group kept changing; try again');
  }

  private async propose(p: mls.Proposal) {
    const cs = await ciphersuite();
    for (let attempt = 0; attempt < 6; attempt++) {
      if (attempt > 0) await this.syncInner(false);
      const res = await mls.createProposal(this.state, false, p, cs);
      const entry: LogEntry = { v: 1, i: this.meta.logNext, prev: this.meta.lastHash, kind: 'proposal', epoch: String(this.epoch), mls: b64(encodeMsg(res.message)) };
      const bytes = jsonBytes(entry);
      if ((await this.chat.provider.orderedLog.append(this.meta.space, entry.i, bytes)) === 'ok') {
        this.state = res.newState;
        await this.recordEntry(bytes, true);
        await this.persist();
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
    await this.pull();
    const out = this.buffered;
    this.buffered = { messages: [], events: [] };
    return out;
  }

  /** Bring the group up to date; results are buffered for the next sync(). */
  private async pull(): Promise<void> {
    if (!this.syncing) this.syncing = this.syncInner(true).finally(() => (this.syncing = undefined));
    await this.syncing;
  }

  private async syncInner(withAutomation: boolean): Promise<SyncResult> {
    const out = this.buffered;
    if (this.meta.removed) return out;
    const p = this.chat.provider;
    const space = this.meta.space;

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
    for (const item of mail.items) {
      if (own.has(item.id)) continue;
      let epoch = '0';
      try {
        const m = decodeMsg(item.data);
        if (m.wireformat !== 'mls_private_message') continue;
        epoch = String(m.privateMessage.epoch);
      } catch {
        out.events.push({ type: 'undecryptable', id: item.id, reason: 'not an MLS message' });
        continue;
      }
      this.meta.pending.push({ id: item.id, data: b64(item.data), epoch });
    }
    this.meta.mailCursor = mail.cursor;

    // Log: verify that what we already processed is unchanged, then apply new entries.
    const from = Math.max(0, this.meta.logNext - 1);
    const raw = await p.orderedLog.read(space, from);
    if (this.meta.logNext > 0) {
      const first = raw[0];
      const known = this.meta.hashes[from] ?? (from === this.meta.logNext - 1 ? this.meta.lastHash : undefined);
      if (!first || (known && (await hashEntry(first)) !== known)) throw new KeyholdError('rewrite_detected', `the log of ${space} was rewritten`);
    }
    const pendingKey = `chat/pending/${this.meta.groupId}`;
    const pendingRaw = await this.chat.opts.device.ephemeral.get(pendingKey);
    const pendingCommit = pendingRaw ? parseJsonBytes<{ hash: string; state: string }>(pendingRaw) : undefined;
    for (const bytes of raw.slice(this.meta.logNext > 0 ? 1 : 0)) {
      if (pendingCommit && (await hashEntry(bytes)) === pendingCommit.hash) {
        // Our own commit from before a crash: adopt the state we prepared for it.
        this.state = this.chat.decodeState(unb64(pendingCommit.state));
        await this.recordEntry(bytes, true);
        await this.chat.opts.device.ephemeral.delete(pendingKey);
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
    if (pendingCommit) await this.chat.opts.device.ephemeral.delete(pendingKey); // it never landed
    await this.persist();

    if (withAutomation && this.active) await this.automate(out);
    return out;
  }

  private async drainPending(out: SyncResult, ready: (epoch: string) => boolean) {
    if (!this.active) return;
    const keep: GroupMeta['pending'] = [];
    for (const item of this.meta.pending) {
      if (!ready(item.epoch)) {
        keep.push(item);
        continue;
      }
      try {
        const m = await this.openApplication(unb64(item.data));
        if (m) {
          out.messages.push(m);
          await this.handleSystem(m);
          await this.chat.opts.onMessage?.(this, m);
        }
      } catch (e) {
        out.events.push({ type: 'undecryptable', id: item.id, reason: (e as Error).message });
      }
    }
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
    if (pm.epoch === st.groupContext.epoch) {
      res = await unprotectPrivateMessage(st.keySchedule.senderDataSecret, pm, st.secretTree, st.ratchetTree, st.groupContext, cfg, cs);
      tree = st.ratchetTree;
      this.state = { ...st, secretTree: res.tree };
    } else {
      const r = st.historicalReceiverData.get(pm.epoch);
      if (!r) throw new KeyholdError('decrypt_failed', `keys for epoch ${pm.epoch} are gone`);
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
    return {
      message: decodeAppMessage(content.applicationData),
      from: { fingerprint: fingerprint(unb64(cert.root)), address: cert.address, deviceId: cert.deviceId },
      epoch: pm.epoch,
    };
  }

  private async handleSystem(m: ReceivedMessage) {
    const msg = m.message;
    const isAdmin = this.policy.admins.includes(m.from.fingerprint);
    if (msg.t === 'meta' && isAdmin && msg.name !== undefined) this.meta.name = msg.name;
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
    if (msg.wireformat !== 'mls_private_message' && msg.wireformat !== 'mls_public_message') return reject('not a handshake message');
    // Rule shared with joiners (scanLog): a ticket is burned the first time it appears in any
    // external commit in the log, whether or not that commit is accepted.
    const used = new Set(this.meta.usedNonces);
    if (msg.wireformat === 'mls_public_message') {
      const t0 = decodeTicket(msg.publicMessage.content.authenticatedData);
      if (t0 && !used.has(t0.nonce)) this.meta.usedNonces.push(t0.nonce);
    }
    const epoch = msg.wireformat === 'mls_private_message' ? msg.privateMessage.epoch : msg.publicMessage.content.epoch;
    if (epoch !== this.epoch) return reject(`built on epoch ${epoch}, we are at ${this.epoch}`);

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
    const callback: mls.IncomingMessageCallback = (incoming) => {
      const proposals = incoming.kind === 'commit' ? incoming.proposals : [incoming.proposal];
      const summaries = proposals.map(summarize);
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
      return reject((err as Error).message);
    }
    if (result.kind !== 'newState' || result.actionTaken === 'reject' || !verdict.ok) return reject(verdict.reason ?? 'rejected');
    this.state = result.newState;
    result.consumed.forEach(mls.zeroOutUint8Array);
    if (e.kind === 'commit') this.meta.needsHeal = false;

    if (this.state.groupActiveState.kind !== 'active') {
      out.events.push({ type: 'removed' });
      await this.forget();
      return;
    }
    if (e.kind !== 'commit') return;
    const after = this.members();
    this.diffMembers(before, out);
    const np = this.policy;
    if (JSON.stringify(np) !== JSON.stringify(policy)) out.events.push({ type: 'policy', policy: np });
  }

  private diffMembers(before: Member[], out: SyncResult) {
    const after = this.members();
    for (const m of after) if (!before.some((b) => b.fingerprint === m.fingerprint)) out.events.push({ type: 'joined', fingerprint: m.fingerprint, address: m.address });
    for (const b of before) if (!after.some((m) => m.fingerprint === b.fingerprint)) out.events.push({ type: 'left', fingerprint: b.fingerprint, address: b.address });
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
    const pendingProposals = Object.keys(this.state.unappliedProposals).length > 0;
    if (revokedNow().length || pendingProposals || this.meta.needsHeal) {
      try {
        const revoked = revokedNow();
        if (revoked.length) await this.banAndRemove(revoked.map((l) => ({ device: l.device, root: l.root })));
        await this.commit([], () => this.meta.needsHeal || Object.keys(this.state.unappliedProposals).length > 0);
        out.events.push({ type: 'rotated', epoch: this.epoch });
      } catch (err) {
        if ((err as KeyholdError).code !== 'policy_rejected') throw err;
      }
    } else if (this.rotationDue()) {
      await this.rotate();
      out.events.push({ type: 'rotated', epoch: this.epoch });
    }
    // Only admins issue tickets, so only they answer join requests: on every sync while this
    // device has an address-only invite out, else every 10 minutes (for invites from my other devices).
    const now = this.chat.now();
    const waiting = (this.meta.awaitingUpgradeUntil ?? 0) > now;
    if (this.policy.admins.includes(this.chat.identity.fingerprint) && (waiting || now - this.lastRequests > 10 * 60_000)) {
      this.lastRequests = now;
      await this.answerJoinRequests();
    }
    await this.reconcileChannel();
  }

  /**
   * Make channel access follow the group: members and people holding an unexpired ticket keep
   * access; everyone else loses it. Only where this device may manage the space. Stateless (it
   * reads tickets from the drop boxes), so every device of the space owner gets the same answer.
   * Runs when membership changed, or at most every 10 minutes.
   */
  async reconcileChannel(force = false): Promise<{ revoked: Address[] }> {
    const ch = this.chat.provider.channel;
    if (!this.active || !(await ch.canManage(this.meta.space))) return { revoked: [] };
    const now = this.chat.now();
    const sig = leaves(this.state).map((l) => l.leafIndex + l.root).join();
    if (!force && this.lastMembership === sig && now - (this.meta.lastReconcile ?? 0) < 10 * 60_000) return { revoked: [] };
    this.lastMembership = sig;
    this.meta.lastReconcile = now;
    const { active, pending } = await ch.members(this.meta.space);
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
