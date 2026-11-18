/**
 * Group policy (layer 2): a Keyhold mechanism whose rules the app chooses.
 *
 * The policy lives in the MLS group context as a private-use extension, so it is part of the
 * authenticated group state that every member agrees on, and it can only change through a
 * commit. Every client checks every commit against it with the same deterministic rules; a
 * commit that breaks a rule is rejected by all honest members. Storage adapters never decide.
 *
 * Joining by external commit needs an admin-signed invite ticket for that person, carried in
 * the commit's authenticated data. Repository access alone is not enough.
 */
import { concat, utf8 } from '../util/bytes.js';
import { b64, jsonBytes, parseJsonBytes, unb64 } from '../util/codec.js';
import { KeyholdError } from '../util/errors.js';
import type { Address } from '../storage/interfaces.js';
import { fingerprint, verifyDeviceCertificate, type DeviceCertificate } from './identity.js';

/** Private-use MLS extension type carrying the policy. */
export const POLICY_EXTENSION = 0xf0a1;
const TICKET_LABEL = 'keyhold/v1/invite-ticket';

export interface GroupPolicy {
  v: 1;
  kind: 'dm' | 'group';
  /** Root fingerprints of the admins. */
  admins: string[];
  /** Who may invite or add people. */
  adds: 'admins' | 'members' | 'none';
  /** Most distinct people (roots) allowed. 0 = no limit. DMs use 2. */
  maxPeople: number;
  /**
   * Devices that may never join again (lost or stolen). Part of the agreed group state, so
   * every member decides joins the same way without looking anything up.
   */
  banned: { device: string; root: string }[];
}

export function defaultPolicy(kind: 'dm' | 'group', creator: string): GroupPolicy {
  return kind === 'dm'
    ? { v: 1, kind, admins: [creator], adds: 'admins', maxPeople: 2, banned: [] }
    : { v: 1, kind, admins: [creator], adds: 'admins', maxPeople: 0, banned: [] };
}

export function encodePolicy(p: GroupPolicy) {
  return { extensionType: POLICY_EXTENSION, extensionData: jsonBytes(p) };
}

export function decodePolicy(extensions: { extensionType: unknown; extensionData: Uint8Array }[]): GroupPolicy {
  const e = extensions.find((x) => x.extensionType === POLICY_EXTENSION);
  if (!e) throw new KeyholdError('bad_format', 'group has no keyhold policy');
  const p = parseJsonBytes<GroupPolicy>(e.extensionData, 'policy');
  validatePolicyShape(p);
  return p;
}

export function validatePolicyShape(p: GroupPolicy) {
  if (p.v !== 1 || (p.kind !== 'dm' && p.kind !== 'group') || !Array.isArray(p.admins) || p.admins.length === 0) {
    throw new KeyholdError('bad_format', 'invalid group policy');
  }
  if (!['admins', 'members', 'none'].includes(p.adds) || !Number.isInteger(p.maxPeople) || p.maxPeople < 0 || !Array.isArray(p.banned)) {
    throw new KeyholdError('bad_format', 'invalid group policy');
  }
}

// ---- Invite tickets ------------------------------------------------------------------------

export interface InviteTicket {
  v: 1;
  /** Group id, base64url. */
  group: string;
  to: Address;
  /** Invitee's root fingerprint when known (from the directory). Without it the invite is address-only. */
  toRoot?: string;
  /** Certificate of the issuing device; its root must be allowed to add. */
  by: DeviceCertificate;
  expiresAt: number;
  nonce: string;
  sig: string;
}

export type TicketSigner = (message: Uint8Array) => Promise<Uint8Array>;
export type TicketVerifier = (publicKey: Uint8Array, message: Uint8Array, sig: Uint8Array) => Promise<boolean>;

function ticketBody(t: Omit<InviteTicket, 'sig'> | InviteTicket) {
  const { sig: _s, ...rest } = t as InviteTicket;
  return concat(utf8(TICKET_LABEL), jsonBytes(rest));
}

export async function signTicket(body: Omit<InviteTicket, 'sig' | 'v'>, sign: TicketSigner): Promise<InviteTicket> {
  const t = { v: 1 as const, ...body };
  return { ...t, sig: b64(await sign(ticketBody(t))) };
}

export function encodeTicket(t: InviteTicket): Uint8Array {
  return jsonBytes(t);
}

export function decodeTicket(b: Uint8Array): InviteTicket | undefined {
  if (b.length === 0) return undefined;
  try {
    const t = parseJsonBytes<InviteTicket>(b, 'ticket');
    return t && t.v === 1 && typeof t.nonce === 'string' ? t : undefined;
  } catch {
    return undefined;
  }
}

export interface VerifiedTicket {
  ticket: InviteTicket;
  issuerRoot: string;
}

/**
 * Signature, issuer certificate, group and (optionally) expiry. Policy checks come later.
 * Members validating a commit pass `now` undefined: commit validity must not depend on each
 * member's clock, or members would disagree. Expiry is enforced by the joiner's app and by
 * channel access (which the space manager removes when the invite expires).
 */
export async function verifyTicket(t: InviteTicket, groupId: Uint8Array, now: number | undefined, verify: TicketVerifier): Promise<VerifiedTicket | undefined> {
  if (t.group !== b64(groupId) || (now !== undefined && t.expiresAt <= now)) return undefined;
  if (!verifyDeviceCertificate(t.by)) return undefined;
  if (!(await verify(unb64(t.by.device), ticketBody(t), unb64(t.sig)))) return undefined;
  return { ticket: t, issuerRoot: fingerprint(unb64(t.by.root)) };
}

// ---- Rules ---------------------------------------------------------------------------------

export interface MemberLeaf {
  leafIndex: number;
  root: string; // fingerprint
  device: string; // device public key, base64url
  address: Address;
}

export type ProposalSummary =
  | { type: 'add'; sender: number | undefined; leaf: MemberLeaf }
  | { type: 'remove'; sender: number | undefined; removed: number }
  | { type: 'update'; sender: number | undefined }
  | { type: 'policy'; sender: number | undefined; policy: GroupPolicy | undefined }
  | { type: 'external_init'; sender: number | undefined }
  | { type: 'other'; sender: number | undefined; name: string };

export interface CommitCheck {
  policy: GroupPolicy;
  members: MemberLeaf[];
  /** Leaf index of the committer; undefined for an external commit. */
  committer: number | undefined;
  proposals: ProposalSummary[];
  /** Set for external commits: who is joining and the ticket they carried, if valid. */
  joiner?: { leaf: MemberLeaf; ticket?: VerifiedTicket };
  /** Ticket nonces already used in this group (burned the first time they appear in the log). */
  usedNonces: ReadonlySet<string>;
}

/**
 * The rules may only use the inputs above, all of which come from the agreed group state and
 * the log. Nothing here may depend on a member's clock, cache or network: two members who
 * process the same log must always reach the same verdict.
 */

export type Verdict = { ok: true } | { ok: false; reason: string };

const deny = (reason: string): Verdict => ({ ok: false, reason });

function mayAdd(policy: GroupPolicy, root: string | undefined) {
  if (root === undefined) return false;
  if (policy.adds === 'none') return false;
  return policy.adds === 'members' || policy.admins.includes(root);
}

/** The deterministic rule set every client runs on every commit. */
export function checkCommit(c: CommitCheck): Verdict {
  const byLeaf = new Map(c.members.map((m) => [m.leafIndex, m]));
  const rootOf = (leaf: number | undefined) => (leaf === undefined ? undefined : byLeaf.get(leaf)?.root);
  const roots = new Set(c.members.map((m) => m.root));
  const removedLeaves = new Set<number>();
  let nextPolicy = c.policy;

  for (const p of c.proposals) {
    const actorLeaf = p.sender ?? c.committer;
    const actor = c.joiner && c.committer === undefined && p.sender === undefined ? c.joiner.leaf.root : rootOf(actorLeaf);
    switch (p.type) {
      case 'update':
        break;
      case 'add':
        if (!mayAdd(c.policy, actor)) return deny('only allowed members may add people');
        if (isBanned(c.policy, p.leaf)) return deny('cannot add a banned device');
        roots.add(p.leaf.root);
        break;
      case 'remove': {
        const target = byLeaf.get(p.removed);
        if (!target) return deny('remove of an unknown leaf');
        const self = actor !== undefined && target.root === actor;
        const admin = actor !== undefined && c.policy.admins.includes(actor);
        if (!self && !admin) return deny('only admins may remove other people');
        removedLeaves.add(p.removed);
        break;
      }
      case 'policy': {
        if (!p.policy) return deny('policy extension missing from the new group context');
        if (p.policy.kind !== c.policy.kind) return deny('a DM cannot become a group or the other way round');
        const admin = actor !== undefined && c.policy.admins.includes(actor);
        // Anyone may ban their own devices; everything else is for admins.
        if (!admin && !(actor !== undefined && onlyBansOwnDevices(c.policy, p.policy, actor))) return deny('only admins may change the policy');
        nextPolicy = p.policy;
        break;
      }
      case 'external_init':
        if (!c.joiner) return deny('external init outside an external commit');
        break;
      default:
        return deny(`proposal type ${(p as { name: string }).name} is not allowed`);
    }
  }

  if (c.joiner) {
    const j = c.joiner;
    if (c.committer !== undefined) return deny('joiner set on a member commit');
    if (isBanned(c.policy, j.leaf)) return deny('banned device cannot join');
    for (const p of c.proposals) {
      if (p.type === 'remove' && byLeaf.get(p.removed)?.root !== j.leaf.root) return deny('an external commit may only remove its own old leaves');
      if (p.type !== 'remove' && p.type !== 'external_init') return deny('external commits may only carry external init and own removes');
    }
    const ownRootPresent = c.members.some((m) => m.root === j.leaf.root && !removedLeaves.has(m.leafIndex));
    if (ownRootPresent) {
      // Another device of a member: it must claim the same address as that member's other devices.
      const same = c.members.find((m) => m.root === j.leaf.root && !removedLeaves.has(m.leafIndex))!;
      if (same.address !== j.leaf.address) return deny('a device must use the address of its owner');
    } else {
      // A new person: needs a valid, unused ticket from someone allowed to add them.
      const t = j.ticket;
      if (!t) return deny('joining needs a valid invite ticket');
      if (!mayAdd(c.policy, t.issuerRoot)) return deny('the ticket issuer may not add people');
      if (!c.members.some((m) => m.root === t.issuerRoot)) return deny('the ticket issuer is no longer a member');
      if (c.usedNonces.has(t.ticket.nonce)) return deny('this invite ticket was already used');
      if (t.ticket.to !== j.leaf.address) return deny('the ticket is for another address');
      // Tickets must name the invitee's root key: an address alone can be claimed by anyone
      // who can read the space. (Address-only invites are upgraded first; see Group.invite.)
      if (t.ticket.toRoot === undefined) return deny('the ticket does not name an identity key');
      if (t.ticket.toRoot !== j.leaf.root) return deny('the ticket is for another identity');
      roots.add(j.leaf.root);
    }
  }

  for (const leaf of removedLeaves) {
    const r = byLeaf.get(leaf)!.root;
    const stillThere = c.members.some((m) => m.root === r && !removedLeaves.has(m.leafIndex));
    if (!stillThere) roots.delete(r);
  }
  if (c.policy.maxPeople > 0 && roots.size > c.policy.maxPeople) return deny(`at most ${c.policy.maxPeople} people`);
  if (roots.size > 0 && !nextPolicy.admins.some((a) => roots.has(a))) return deny('the group must keep at least one admin who is a member');
  return { ok: true };
}

function isBanned(p: GroupPolicy, leaf: MemberLeaf) {
  return p.banned.some((b) => b.device === leaf.device);
}

function onlyBansOwnDevices(before: GroupPolicy, after: GroupPolicy, actor: string) {
  const { banned: b0, ...rest0 } = before;
  const { banned: b1, ...rest1 } = after;
  if (JSON.stringify(rest0) !== JSON.stringify(rest1)) return false;
  if (b1.length < b0.length || b0.some((x, i) => b1[i]?.device !== x.device || b1[i]?.root !== x.root)) return false;
  return b1.slice(b0.length).every((x) => x.root === actor);
}

export function assertAllowed(v: Verdict) {
  if (!v.ok) throw new KeyholdError('policy_rejected', v.reason);
}
