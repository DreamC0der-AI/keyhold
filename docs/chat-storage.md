# Chat and storage: design

Keyhold's chat side is built in three layers. Only the bottom one knows which channel is used.

| Layer | Module | Owns | Channel-specific? |
| --- | --- | --- | --- |
| 1. Requirements | `keyhold/storage` (`requirements.ts`) | Every data type, described only by who reads it, who writes it, how long it lives and what the storage must guarantee. The 12 storage kinds are **derived** from those requirements. | No |
| 2. Protocol and policy | `keyhold/chat` | Identity (root key, device certificates, directory), MLS groups (RFC 9420, via ts-mls), group policy, invite tickets, personal synced store, root key backup | No |
| 3. Providers | `keyhold/storage` interfaces; `keyhold/providers/github`; `MemoryWorld` | How each kind is stored, plus channel side effects (create a space, grant access, revoke access) | Yes |

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

### GitHub provider

| Kind | Where |
| --- | --- |
| 3 | public repo `{login}/keyhold-id`, `dir/{index}` (create-only files) |
| 9, 12 | private repo `{login}/keyhold-home`, `vault/{name}` and `items/{opaque id}` |
| 5 | chat repo `log/{shard}/{index}`, create-only, 1,000 per shard |
| 6 | chat repo `mail/{day}/{id}` |
| 7 | chat repo `blob/{id}` (over 1 MB read through the git blob API) |
| 8 | chat repo `drop/{recipient tag}/{id}` |
| 11 | the existing Cloudflare Worker (`POST/GET/DELETE /invites`) |
| 4 | not provided |

Compare-and-swap comes from the Contents API: creating a path that exists fails, and an update needs the current blob sha. Channel side effects use the collaborator API. Chat repos are named `ghchat-<random>` with one neutral description and the topic `keyhold-chat`.

## 3. Identity

- **Address** (`github:alice`): where to find someone. Never proof.
- **Root key** (Ed25519): who you are. Its fingerprint is the identity. Cold: only used to add or revoke devices and to write the directory.
- **Device key**: the MLS signature key, certified by the root (`DeviceCertificate`, carried as the MLS credential).
- **Directory** (box 3): a root-signed, hash-chained log of `init`, `device-add`, `device-revoke`, `profile`, `last-resort-kp`.
- **Trust on first use**: `IdentityRegistry` pins the fingerprint and chain head. A different root gives `key-changed` (never auto-accepted). A rewritten chain throws `rewrite_detected`. `PersonalData.pinStore()` keeps pins with contacts, so all your devices trust the same keys.
- `safetyNumber(a, b)`: 60 digits, the same on both sides, for comparison out of band.

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

`PersonalData` (box 12) seals every item with K, under an opaque id (an HMAC of the logical key), and merges concurrent edits per field, last writer wins. Writes are queued and flushed. `historyRecorder` wires the message history backup to a chat client. `backupRootKey` / `restoreRootKey` keep the root key in the vault (box 9).

## 6. Using it

```ts
import { MemoryWorld, resolveFeatures } from 'keyhold/storage';
import { githubProvider } from 'keyhold/providers/github';
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

See `docs/chat-audit.md` for the audit, known limits and what was not tested against real GitHub.
