/**
 * keyhold/storage — requirements.
 *
 * This file is the "nature of the chat system": every piece of data the system handles is
 * described only by WHO may read it, WHO may write it, HOW LONG it lives and WHAT the storage
 * must guarantee. Nothing here knows about GitHub, servers or browsers.
 *
 * The 12 storage kinds are derived from those requirements, not the other way round:
 * `classify(requirement)` picks the kind whose access rule matches exactly and whose
 * guarantees cover the requirement with the fewest extras. Providers (GitHub, memory, ...)
 * implement kinds; they never decide which data goes where.
 */
import { KeyholdError } from '../util/errors.js';

/** Who may read or write. Matching is exact. */
export type Party =
  | 'device' // this one device only
  | 'owner' // only the user, on any of their devices
  | 'anyone' // the public
  | 'taker' // anyone, but each item goes to exactly one reader
  | 'members' // current members of one conversation
  | 'recipient' // the one addressee
  | 'pair'; // two people or devices side by side

/** How long the data must live, shortest first. */
export const LIFESPANS = [
  'live', // never stored (typing, online)
  'moment', // the duration of a check (safety numbers, QR)
  'seconds-to-days', // ratchet and one-time secrets
  'until-read', // delivered once, then gone
  'days-to-weeks', // one-time KeyPackages, invites
  'chat-history', // as long as the chat history is kept
  'years', // identity keys
  'permanent',
] as const;
export type Lifespan = (typeof LIFESPANS)[number];

/** What the storage must promise. */
export type Guarantee =
  | 'never-leaves-device'
  | 'reliable-delete' // deleting really destroys it (forward secrecy depends on this)
  | 'expiry' // entries vanish after a time limit
  | 'append-only' // writers add; nobody silently edits
  | 'rewrite-detectable' // a rewrite of history is noticed by readers (hash chain)
  | 'total-order' // all readers agree on one order (compare-and-swap appends)
  | 'claim-once' // each item is handed to exactly one taker
  | 'large-objects' // multi-megabyte items
  | 'delete-after-read'
  | 'encrypted-at-rest' // storage only sees ciphertext under the user's key K
  | 'cold' // written rarely, read rarely (backups)
  | 'multi-device-merge' // concurrent edits from several devices merge
  | 'frequent-writes'
  | 'server-enforced' // a server must enforce rules on writes from non-members
  | 'rate-limited'
  | 'discoverable' // findable from an address alone
  | 'no-storage';

export interface Requirement {
  read: Party;
  write: Party;
  lifespan: Lifespan;
  /** Guarantees the data needs. The chosen kind must provide all of them. */
  needs: readonly Guarantee[];
}

export type StorageKindId = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12;

export interface StorageKind {
  id: StorageKindId;
  key: StorageKindKey;
  name: string;
  read: Party;
  write: Party;
  lifespans: readonly Lifespan[];
  guarantees: readonly Guarantee[];
  /** Needs a server that enforces rules on writes from non-members (cannot be dumb storage). */
  needsServer: boolean;
  /** A build option: products may leave it out and lose only the features that need it. */
  optional: boolean;
}

export type StorageKindKey =
  | 'keystore'
  | 'ephemeral'
  | 'directory'
  | 'claimOnce'
  | 'orderedLog'
  | 'mailbox'
  | 'blobs'
  | 'dropBox'
  | 'vault'
  | 'outOfBand'
  | 'inviteInbox'
  | 'personal';

const L = LIFESPANS;
const upTo = (max: Lifespan, min: Lifespan = 'moment') => L.slice(L.indexOf(min), L.indexOf(max) + 1);

export const STORAGE_KINDS: Readonly<Record<StorageKindId, StorageKind>> = {
  1: { id: 1, key: 'keystore', name: 'Secure keystore', read: 'device', write: 'device', lifespans: upTo('permanent'), guarantees: ['never-leaves-device'], needsServer: false, optional: false },
  2: { id: 2, key: 'ephemeral', name: 'Ephemeral key store', read: 'device', write: 'device', lifespans: upTo('days-to-weeks'), guarantees: ['never-leaves-device', 'reliable-delete', 'expiry'], needsServer: false, optional: false },
  3: { id: 3, key: 'directory', name: 'Public directory', read: 'anyone', write: 'owner', lifespans: upTo('permanent', 'days-to-weeks'), guarantees: ['append-only', 'rewrite-detectable', 'discoverable'], needsServer: false, optional: false },
  4: { id: 4, key: 'claimOnce', name: 'Claim-once store', read: 'taker', write: 'owner', lifespans: ['days-to-weeks'], guarantees: ['claim-once', 'server-enforced', 'expiry', 'discoverable'], needsServer: true, optional: true },
  5: { id: 5, key: 'orderedLog', name: 'Ordered log', read: 'members', write: 'members', lifespans: upTo('permanent', 'chat-history'), guarantees: ['append-only', 'total-order', 'rewrite-detectable'], needsServer: false, optional: false },
  6: { id: 6, key: 'mailbox', name: 'Mailbox', read: 'members', write: 'members', lifespans: ['chat-history'], guarantees: ['append-only'], needsServer: false, optional: false },
  7: { id: 7, key: 'blobs', name: 'Blob store', read: 'members', write: 'members', lifespans: ['chat-history'], guarantees: ['append-only', 'large-objects'], needsServer: false, optional: false },
  8: { id: 8, key: 'dropBox', name: 'Drop box', read: 'members', write: 'members', lifespans: ['until-read', 'days-to-weeks'], guarantees: ['delete-after-read'], needsServer: false, optional: false },
  9: { id: 9, key: 'vault', name: 'Backup vault (cold)', read: 'owner', write: 'owner', lifespans: ['years', 'permanent'], guarantees: ['encrypted-at-rest', 'cold'], needsServer: false, optional: false },
  10: { id: 10, key: 'outOfBand', name: 'Out of band', read: 'pair', write: 'pair', lifespans: ['moment'], guarantees: ['no-storage'], needsServer: false, optional: false },
  11: { id: 11, key: 'inviteInbox', name: 'Invite inbox', read: 'recipient', write: 'anyone', lifespans: ['until-read', 'days-to-weeks'], guarantees: ['server-enforced', 'rate-limited', 'expiry'], needsServer: true, optional: false },
  12: { id: 12, key: 'personal', name: 'Personal synced store', read: 'owner', write: 'owner', lifespans: upTo('permanent', 'chat-history'), guarantees: ['encrypted-at-rest', 'multi-device-merge', 'frequent-writes'], needsServer: false, optional: false },
};

export const NOT_STORED = 'not-stored' as const;

/**
 * Derive the storage kind from a requirement: exact access match, lifespan allowed, all needed
 * guarantees provided; among those, the kind with the fewest extra guarantees wins.
 */
export function classify(req: Requirement): StorageKindId | typeof NOT_STORED {
  if (req.lifespan === 'live') return NOT_STORED;
  const fits = Object.values(STORAGE_KINDS).filter(
    (k) =>
      k.read === req.read &&
      k.write === req.write &&
      k.lifespans.includes(req.lifespan) &&
      req.needs.every((g) => k.guarantees.includes(g)),
  );
  if (fits.length === 0) throw new KeyholdError('config', `no storage kind satisfies ${JSON.stringify(req)}`);
  const extras = (k: StorageKind) => k.guarantees.filter((g) => !req.needs.includes(g)).length;
  fits.sort((a, b) => extras(a) - extras(b));
  if (fits.length > 1 && extras(fits[0]!) === extras(fits[1]!)) {
    throw new KeyholdError('config', `ambiguous requirement, kinds ${fits[0]!.id} and ${fits[1]!.id} both fit`);
  }
  return fits[0]!.id;
}

/** Protocol data (needed by MLS and identity) and app data (needed by the chat product). */
export interface DataType {
  id: string;
  layer: 'protocol' | 'app';
  description: string;
  requirement: Requirement;
}

const dt = (id: string, layer: DataType['layer'], description: string, read: Party, write: Party, lifespan: Lifespan, needs: Guarantee[] = []): DataType => ({
  id,
  layer,
  description,
  requirement: { read, write, lifespan, needs },
});

/** Every data type in the system. The tests pin each to the box agreed in the design. */
export const DATA_TYPES: readonly DataType[] = [
  // Device only
  dt('root-private-key', 'protocol', 'Root identity private key (only on devices that hold it)', 'device', 'device', 'years', ['never-leaves-device']),
  dt('device-private-key', 'protocol', 'Device signing private key, the MLS leaf key', 'device', 'device', 'years', ['never-leaves-device']),
  dt('keypackage-init-private', 'protocol', 'Private half of a one-time KeyPackage', 'device', 'device', 'days-to-weeks', ['never-leaves-device', 'reliable-delete']),
  dt('epoch-secrets', 'protocol', 'MLS group state: epoch and ratchet secrets', 'device', 'device', 'seconds-to-days', ['never-leaves-device', 'reliable-delete']),
  dt('decrypted-cache', 'app', 'Decrypted messages and search index', 'device', 'device', 'chat-history', ['never-leaves-device']),
  dt('outbox', 'app', 'Messages waiting to be sent', 'device', 'device', 'days-to-weeks', ['never-leaves-device']),
  // Public
  dt('identity-public', 'protocol', 'Root identity public key', 'anyone', 'owner', 'years', ['append-only', 'discoverable']),
  dt('device-list', 'protocol', 'Signed device list and revocations', 'anyone', 'owner', 'years', ['append-only', 'rewrite-detectable']),
  dt('last-resort-keypackage', 'protocol', 'Reusable KeyPackage for occasional offline adds', 'anyone', 'owner', 'days-to-weeks', ['discoverable']),
  dt('public-profile', 'app', 'Display name and avatar', 'anyone', 'owner', 'years', ['discoverable']),
  // Server-enforced
  dt('one-time-keypackage', 'protocol', 'One-time KeyPackage for offline add (build option)', 'taker', 'owner', 'days-to-weeks', ['claim-once']),
  dt('invite-notice', 'app', 'Contact request or invite notice', 'recipient', 'anyone', 'days-to-weeks', ['server-enforced', 'rate-limited']),
  // Members of one conversation
  dt('commit', 'protocol', 'MLS commits and proposals', 'members', 'members', 'permanent', ['total-order', 'rewrite-detectable']),
  dt('group-info', 'protocol', 'GroupInfo for external join, per epoch', 'members', 'members', 'permanent', ['total-order']),
  dt('group-policy', 'protocol', 'Admins and who may add or remove (inside group state)', 'members', 'members', 'permanent', ['total-order']),
  dt('app-message', 'app', 'Messages, edits, deletes, replies, reactions, receipts, group name', 'members', 'members', 'chat-history', ['append-only']),
  dt('attachment', 'app', 'Attachments, each with its own key', 'members', 'members', 'chat-history', ['large-objects']),
  dt('welcome', 'protocol', 'MLS Welcome for an added member', 'members', 'members', 'until-read', ['delete-after-read']),
  dt('signed-invite', 'protocol', 'Admin-signed invite ticket that gates external join', 'members', 'members', 'days-to-weeks', ['delete-after-read']),
  // Only me
  dt('root-key-backup', 'protocol', 'Root key backup, sealed with K', 'owner', 'owner', 'permanent', ['encrypted-at-rest']),
  dt('contacts', 'app', 'Contacts and pinned fingerprints', 'owner', 'owner', 'permanent', ['encrypted-at-rest', 'multi-device-merge']),
  dt('chat-list', 'app', 'Chats with pinned, muted, archived flags', 'owner', 'owner', 'permanent', ['encrypted-at-rest', 'multi-device-merge']),
  dt('read-marks', 'app', 'Read position per chat', 'owner', 'owner', 'permanent', ['encrypted-at-rest', 'frequent-writes']),
  dt('block-list', 'app', 'Blocked addresses', 'owner', 'owner', 'permanent', ['encrypted-at-rest', 'multi-device-merge']),
  dt('settings', 'app', 'Settings', 'owner', 'owner', 'permanent', ['encrypted-at-rest', 'multi-device-merge']),
  dt('drafts', 'app', 'Unsent drafts (optional sync)', 'owner', 'owner', 'chat-history', ['encrypted-at-rest', 'multi-device-merge']),
  dt('history-backup', 'app', 'Message history for new devices', 'owner', 'owner', 'chat-history', ['encrypted-at-rest', 'multi-device-merge']),
  dt('device-approval-relay', 'protocol', 'Messages of the QR device approval', 'owner', 'owner', 'chat-history', ['frequent-writes']),
  // No storage
  dt('safety-number', 'protocol', 'Safety number comparison and QR scan', 'pair', 'pair', 'moment', ['no-storage']),
  dt('typing-presence', 'app', 'Typing and online status', 'members', 'members', 'live'),
];

export function dataType(id: string): DataType {
  const d = DATA_TYPES.find((x) => x.id === id);
  if (!d) throw new KeyholdError('config', `unknown data type ${id}`);
  return d;
}

/** The storage kind a data type lives in, derived from its requirement. */
export function kindOf(id: string): StorageKindId | typeof NOT_STORED {
  return classify(dataType(id).requirement);
}

/** Retention rule: backups (kinds 9 and 12) must never hold data that needs reliable deletion. */
export function mayBackUp(id: string): boolean {
  return !dataType(id).requirement.needs.includes('reliable-delete');
}
