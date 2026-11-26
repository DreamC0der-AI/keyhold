# Chat and storage: design

Keyhold's chat side is built in three layers. Only the bottom one knows which channel is used.

| Layer | Module | Owns | Channel-specific? |
| --- | --- | --- | --- |
| 1. Requirements | `keyhold/storage` (`requirements.ts`) | Every data type, described only by who reads it, who writes it, how long it lives and what the storage must guarantee. The 12 storage kinds are **derived** from those requirements. | No |
| 2. Protocol and policy | `keyhold/chat` | Identity (root key, device certificates, directory), MLS groups (RFC 9420, via ts-mls), group policy, invite tickets, personal synced store, root key backup | No |
| 3. Providers | `keyhold/storage` interfaces and `MemoryWorld`; channel providers live in apps | How each kind is stored, plus channel side effects (create a space, grant access, revoke access) | Yes |

Providers never see plaintext and never make a security decision. Channel access (for example GitHub collaborators) is a second fence against strangers and spam. Secrecy and integrity come from the encryption and signatures in layer 2.

## 1. Data types are requirements

`DATA_TYPES` lists the 30 data types of the system. Each has a requirement:

```ts
{ read: 'members', write: 'members', lifespan: 'chat-history', needs: ['append-only'] } // app-message
```

`classify(requirement)` picks the storage kind whose access rule matches exactly, whose lifespans include the data's lifespan, and whose guarantees cover everything the data needs. If several fit, the one with the fewest extra guarantees wins, and a tie is an error. The test `tests/storage.test.ts` pins every data type to the kind agreed in the design discussion, so changing a requirement that would move data to another kind fails the build.

| # | Kind | Read / write | Lifespan | Guarantees | Data types |
| --- | --- | --- | --- | --- | --- |
| 1 | Secure keystore | device / device | moment to permanent | never leaves device | root and device private keys, decrypted cache, outbox |
| 2 | Ephemeral key store | device / device | up to weeks | never leaves device, reliable delete, expiry | KeyPackage init keys, MLS group state (epoch and ratchet secrets) |
| 3 | Public directory | anyone / owner | weeks to permanent | append-only, rewrite-detectable, discoverable | identity key, device list, last-resort KeyPackage, public profile |
| 4 | Claim-once (build option) | taker / owner | days to weeks | claim-once, server-enforced, expiry | one-time KeyPackages |
| 5 | Ordered log | members / members | history to permanent | append-only, total order, rewrite-detectable | commits, proposals, GroupInfo, group policy |
| 6 | Mailbox | members / members | chat history | append-only | messages, edits, deletes, reactions, receipts, group name |
| 7 | Blob store | members / members | chat history | append-only, large objects | attachments |
| 8 | Drop box | members / members | until read, days | delete after read | Welcome, invite tickets, join requests |
| 9 | Backup vault (cold) | owner / owner | years | encrypted with K, cold | root key backup |
| 10 | Out of band | pair / pair | moment | no storage | safety numbers, QR device approval |
| 11 | Invite inbox | recipient / anyone | until read, days | server-enforced, rate-limited, expiry | invite notices |
| 12 | Personal synced store | owner / owner | history to permanent | encrypted with K, multi-device merge, frequent writes | contacts and pins, chat list, read marks, block list, settings, drafts, history backup, device approval relay |

Typing and presence are `live`: not stored.

Rule enforced in code: `mayBackUp(type)` is false for anything that needs reliable deletion, and the personal store and vault refuse such data. Backups never contain one-time or ratchet keys.

## 2. Providers

`StorageProvider` (in `src/storage/interfaces.ts`) is one small interface per remote kind (3 to 9, 11, 12) plus `ChannelAccess`. Device kinds 1 and 2 are a separate `DeviceStorage`. Kind 10 has no storage.

Providers declare **capabilities**; the product declares **build options**; `resolveFeatures` turns a feature on only when both agree:

| Capability | Meaning | Feature it enables |
| --- | --- | --- |
| `claim-once` | provides box 4 | `offlineAdd` (add someone who is offline) |
| `inbox-payload` | invite notices can carry bytes | richer notices (GitHub: off, pointer only) |
| `true-delete` | deleted items are gone | (GitHub: off, git keeps history) |
| `owner-managed-spaces` | only the space creator may grant or revoke | other admins ask the owner's app (`sys.grant`) |

The same conformance tests (`tests/storage.test.ts`) run against every provider.

### Providers live in apps

Keyhold ships only the in-memory provider. Channel providers belong to the apps that use them. The GitHub provider, with its repo layout and its own run of these conformance tests, is in [chat-over-github](https://github.com/DreamC0der-AI/chat-over-github).

## 3. Identity

- **Address** (`github:alice`): where to find someone. Never proof.
- **Root key** (Ed25519): who you are. Its fingerprint is the identity. Cold: only used to add or revoke devices and to write the directory.
- **Device key**: the MLS signature key, certified by the root (`DeviceCertificate`, carried as the MLS credential).
- **Directory** (box 3): a root-signed, hash-chained log of `init`, `device-add`, `device-revoke`, `profile`, `last-resort-kp`.
- **Trust on first use**: `IdentityRegistry` pins the fingerprint and chain head. A different root gives `key-changed` (never auto-accepted). A rewritten chain throws `rewrite_detected`. `PersonalData.pinStore()` keeps pins with contacts, so all your devices trust the same keys.
- `safetyNumber(a, b)`: 60 digits, the same on both sides, for comparison out of band.
- **Key reset**: a person who lost their root key publishes a new directory under the same address. A member's device whose certificate names the old root is dead (`IdentityRegistry.isResetRoot`). Each group reports `key-reset` once per such key; an admin's device removes those devices by itself, and the person comes back only when someone invites the new key (after `acceptKeyChange`; inviting removes any old-key devices first). When every admin in a group reset, the group is over: each member's device reports `admins-reset` and from then on applies and sends nothing (`Group.endedByReset`). `spacesRunByLostKeys` finds the spaces the new key may delete for that reason. A device whose own address publishes another root stops changing its groups.

## 4. Groups

A DM is a group with `maxPeople: 2`. Each log entry carries the GroupInfo of the epoch it creates, so anyone holding an invite can join with an MLS external commit.

**Join on accept (default):**

1. An admin calls `group.invite(address)`. Their app signs a ticket bound to the invitee's root key (from the directory), puts it in the invitee's drop box, grants channel access and leaves a notice in the inbox.
2. The invitee's app calls `chat.acceptInvites()`: it accepts the channel grant, finds the ticket, and commits its own external join with the ticket in the commit's authenticated data.
3. Every member checks the join against the policy: valid signature, the issuer may add people and is still a member, the ticket names this address and root, and its nonce hasn't appeared before.

If the invitee has no identity yet, the ticket names only the address. Members won't accept it. The invitee's app asks the issuer for a root-bound ticket (a join request in the drop box), and the issuer's app checks the invitee's directory before issuing one.

**Offline add (build option, box 4):** `chat.publishKeyPackages(n)` uploads one-time KeyPackages. `group.addOffline(address)` claims one, commits an Add, and puts the Welcome in the drop box. The private init key is deleted the moment it is used.

**Other devices** of a member join by themselves (no ticket), because their root is already in the group.

**Policy** (`GroupPolicy`, carried in the MLS group context, changed only by commits): admins, who may add, the most people allowed, and banned devices. `checkCommit` is the one rule set every client runs. It uses only the group state and the log, never a clock, cache or network, so all members reach the same verdict.

| Change | Allowed for |
| --- | --- |
| Add or invite | admins (or members, if `adds: 'members'`); never in a full DM |
| Remove someone | admins; anyone for their own devices |
| Change the policy | admins; anyone may ban their own devices |
| External join | a new person with a valid ticket, or another device of a member; never a banned device |

Commits that break a rule are rejected by every honest member, and the first member to notice posts a fresh commit so the newest GroupInfo is honest again.

**Removing**: the MLS remove comes first, then the space manager's app removes channel access. Channel access always follows the group (`reconcileChannel`): members and people holding an unexpired ticket keep it, everyone else loses it.

**Leaving**: the leaving device removes its owner's other devices, proposes its own removal, and the next member to sync commits it. If the last admin leaves, the longest-standing member becomes admin first.

**Lost device**: revoke it in the directory. An admin, or another device of the same person, then bans and removes it in every group.

**Rotation**: each device commits a fresh key update after 100 messages or 7 days (`RotationPolicy`). Removals rotate automatically. Old epoch keys are kept for 4 epochs for late messages (`retainEpochs`).

## 5. Personal data

`PersonalData` (box 12) seals every item with K, under an opaque id (an HMAC of the logical key), and merges concurrent edits per field, last writer wins. Writes are queued and flushed. Open it with `{ local: device.keystore }`: each record (except the history backup) is then also kept on the device and merged with what the store returns, so the storage can't roll a record back or delete it unnoticed. That includes the TOFU pins (`pinStore()`): without the device copy, a deleted contact record resets trust in that person's key. `historyRecorder` wires the message history backup to a chat client. `backupRootKey` / `restoreRootKey` keep the root key in the vault (box 9).

## 6. Using it

```ts
import { MemoryWorld, resolveFeatures } from 'keyhold/storage';
// Any StorageProvider works. This one is from the chat-over-github app.
import { githubProvider } from 'chat-over-github-provider';
import { Chat, createRootKey, createDeviceIdentity, DirectoryWriter, IdentityRegistry, newDeviceId } from 'keyhold/chat';

const provider = githubProvider({ fetch, token, login, workerUrl });
const root = createRootKey();                       // first device only; back it up with backupRootKey
const identity = await createDeviceIdentity(device, root, `github:${login}`, newDeviceId());
await new DirectoryWriter(provider.directory, identity.address).publish(root, identity.cert);
const chat = await Chat.open({
  provider, device, identity,
  registry: new IdentityRegistry(provider.directory, personal.pinStore()),
  features: resolveFeatures(provider, { offlineAdd: false }),
});

const dm = await chat.startDm('github:alice');
await dm.send({ t: 'text', body: 'hi' });
const { messages, events } = await dm.sync();     // call on a timer (polling)
await chat.acceptInvites();                        // also on a timer
```

`device` is a `DeviceStorage`. Tests use `memoryDevice()`. A browser app needs an IndexedDB version (not included yet).

## 7. What an app must do

These are part of the API contract, not suggestions.

**One `Chat` per device.** A device is one `DeviceStorage` (boxes 1 and 2). Run at most one `Chat` on it at a time: two would encrypt from the same ratchet state (nonce reuse) and fork the device off its groups. Keyhold doesn't lock; the app must (for example one active tab, with a takeover that stops the old one first).

**Dedupe messages by sender and id.** Delivery is at least once. The same message can arrive twice with the same `id`: a send retried after a lost reply, or a fast send posted again in a newer epoch (see below). Keep the first copy of each `(from.fingerprint, message.id)`. Don't dedupe by `id` alone: ids are chosen by senders, so another member could reuse one.

**Fast sends (`sendFreshMs`) and removals.** With `sendFreshMs > 0`, a send right after a sync skips its own sync. If someone was removed after that sync, the message is encrypted in the epoch the removal ended, and the removed device still has those keys. So, for at most about `sendFreshMs` after a removal:

- The removed device can receive that message. Keyhold marks such messages `fast`. When a device processes its own removal, it emits `{ type: 'retracted', ids }` (before `removed`) with the fast messages it got in that last epoch, and drops any not yet delivered. An honest app deletes them from the device, from its history backup and from any notification.
- A modified app can ignore `retracted` and keep them. That is the price of the option. Leave `sendFreshMs` at 0 where it is not acceptable (for example groups where removals are for safety).
- The sender's next sync notices the newer epoch and posts the message again for the current members (same `id`, without `fast`). Members who joined in between get it too.
- `retracted` can also name fast messages that were sent before the removal in that epoch. Losing them on the removed device is harmless: that device is leaving the chat anyway.

**Provider errors.** Providers throw `KeyholdError` with these codes, and keyhold relies on them:

| Code | When | What keyhold does |
| --- | --- | --- |
| `forbidden` | the channel no longer lets this account in (mailbox list) | group marked `accessLost`, event `access-lost`, no further syncs until access returns |
| `forbidden` or `not_found` | the space of an unfinished creation is gone | the creation is forgotten |
| `conflict` | a write lost a race the caller can't retry (mailbox post with a used id and other bytes) | thrown to the app |
| anything else | network, rate limits, bugs | thrown to the app; the next call retries. Never map a transient failure to `forbidden`. |

**Forks.** A device that can't follow the log rejoins from the newest GroupInfo only when that GroupInfo could have come from its group: newer than its state, signed by a current member, the same rules (or a change the signer may make), the same people (or changes the signer may make), no banned device. Otherwise it stays where it is and reports `{ type: 'rejected', reason: 'could not rejoin: ...' }`. Show it as a sync problem; the next honest commit usually settles it.

See `docs/chat-audit.md` for the audit, known limits and what was not tested against real GitHub.
