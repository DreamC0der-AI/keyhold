# Chat and storage: audit

Scope: `src/storage`, `src/chat`, `src/providers/github`, as of this change. Method: a review of the design and code against the threat model below, then a test for each finding. ts-mls itself was not audited (its own README says it has had no formal audit).

## Threat model

| Actor | Can | Must not be able to |
| --- | --- | --- |
| Storage operator (GitHub, Cloudflare) | read and rewrite everything it stores, see metadata | read messages, names, contacts or attachments; forge or silently rewrite history |
| Stranger | read public directories, send invite notices | read or join any chat |
| Someone with channel access but no ticket (a bug, a stolen GitHub token) | read ciphertext in a space | join the group |
| Malicious member (modified app) | everything an honest member can, plus write any bytes to the space | add, remove or ban others without being an admin; fork honest members; block the group |
| Removed member | keep old keys | read anything sent after the removal |
| Thief of a device | use its keys and GitHub session | stay in or rejoin groups after the owner revokes it |

## Findings fixed in this change

Each has a test (file in brackets).

| # | Severity | Finding | Fix |
| --- | --- | --- | --- |
| 1 | High | Members checked ticket expiry against their own clock, and device revocation against their own directory cache. Two members could reach different verdicts on the same join and split the group. | Commit validity now depends only on the group state and the log. Expiry is enforced by the joiner's app and by channel access. Revocation became a **ban list** in the group policy: an admin or the device's owner bans and removes a revoked device, and every member then rejects it the same way. [robustness: "different clocks"; attacks: "revoked device"] |
| 2 | High | Ticket nonces were only recorded when a join was accepted, but joiners collected them from every entry. A rejected attempt could make later joiners disagree with older members. | One rule everywhere: a nonce is burned the first time it appears in any external commit in the log. [attacks: "replayed after removal"] |
| 3 | High | Address-only tickets (invitee had no identity yet) could be used by anyone able to read the space and claim that address in a self-made certificate. | Members accept only tickets bound to the invitee's root key. Address-only invites are upgraded: the invitee asks, and the issuer's app checks the invitee's directory (which only the address owner can write) before signing a bound ticket. [robustness: "address-only invite"] |
| 4 | High | A device sent at its current epoch without reading the log first, so a member who had just joined couldn't read the message. | `send()` pulls the log first. Found by the GitHub test. [chat: DM on GitHub] |
| 5 | High | Saved group metadata held a sparse array that the canonical JSON writer turned into invalid JSON, so a restarted app couldn't load groups it created. | The writer emits holes as `null` and the metadata no longer has holes. [robustness: "crash safety"] |
| 6 | Medium | One junk entry in the log (not JSON, or a broken link) made every member's sync throw, so any member could block a group. | Junk at a new index is skipped by everyone. A change to history already processed is still fatal (`rewrite_detected`). [robustness: "junk log entry"] |
| 7 | Medium | If the app died after its commit reached the log but before saving the new state, it could never process that epoch again. | The prepared state is kept in box 2 until the append is confirmed. On restart, the app recognises its own entry and adopts that state. [robustness: "crash safety"] |
| 8 | Medium | Channel reconciliation used invites remembered by one device, so the owner's other device could revoke someone whose invite was still pending. | Reconciliation reads tickets from the drop boxes (no per-device state), and re-reads the log before revoking anyone. [robustness: "multi-device space owner"] |
| 9 | Medium | KeyPackage private material in box 2 included a copy of the long-term device signing key. | Only the init and leaf HPKE keys go to box 2. The signing key stays in box 1. |
| 10 | Medium | ts-mls 1.6.4 produces a commit that receivers can't decrypt when a group-context change (policy) and a remove are in the same commit. | Policy changes always travel in their own commit. A modified client that mixes them is rejected by everyone (it can't be decrypted). |
| 11 | Low | Message lengths leaked: MLS padding only pads up to 256 bytes. | Application messages are padded to 256, 512, ... 16 KiB, then multiples of 16 KiB. [robustness: "padded"] |
| 12 | Low | A GitHub folder listing stops at 1,000 files, so the log would stop growing. | The log is sharded, 1,000 entries per folder. [robustness: "sharding"] |
| 13 | Low | Messages for an epoch that never arrives were kept forever. | Capped at 2,000; older ones are reported as undecryptable. |

## Checked and holding

All with tests in `tests/attacks.test.ts` and `tests/chat.test.ts`:

- A non-admin adding, removing or changing the policy is rejected by every member. The group heals with a fresh commit.
- Channel access without a ticket doesn't let anyone join. A forged ticket (signed by a non-admin) and a ticket for someone else are rejected.
- A removed member can't send, and reads nothing new.
- Rewrites by the storage (memory hook, a GitHub force-push of a log file, a rewritten directory) are detected.
- GitHub sees no message text, group name, file name, reaction or contact in any file, description or repo name.
- One-time KeyPackage keys are deleted after use. Old epoch keys are dropped after the retention window.
- The claim-once store hands each item to exactly one of 25 concurrent takers.
- Personal-store ids and contents are opaque. A different K can't open them.
- The full DM flow works in real Chromium (`npm run test:browser`).

## Known limits (not fixed)

1. **Joining a fork.** A joiner takes the newest GroupInfo in the log. If the newest entry is a commit that members rejected, and no honest member has synced since to post a healing commit, the joiner ends up in a fork with only the malicious member. It notices when the next honest commit fails to apply, but recovery (rejoin) is manual. A fix is to have joiners wait for a later honest commit, or have members sign the "current head".
2. **Revoked device window.** A stolen device with a working GitHub session can rejoin until an admin's or its owner's app notices the revocation (directories are re-read every hour by default). Revoking the GitHub session is still the user's job.
3. **Space owner leaves.** On GitHub only the repo owner can change access. If the owner leaves or deletes their account, the group keeps working cryptographically, but nobody can let people in or out at the channel level. Organisation-owned repos would fix this.
4. **Address claims of added members.** In an offline add (box 4), the adder checks the KeyPackage against the invitee's directory; other members trust the adder (an admin) on that.
5. **Metadata.** GitHub sees who is in which chat, when they post, how big each item is (in buckets), and every GroupInfo, which lists members' device certificates (root keys and addresses). Repo names are random.
6. **Deleted data stays in git history.** Drop box items and blobs are deleted, but GitHub keeps them. That's safe for Welcomes (their private keys are gone) and tickets (not secret), and attachments are encrypted.
7. **Invite inbox rate limit.** The Worker relies on GitHub's own invitation limits; it has no limit of its own.
8. **Deep imports from ts-mls.** The client uses three internal ts-mls modules (`messageProtection`, `keyPackage`, `ratchetTree`) to learn the sender of a message, which ts-mls doesn't return. The version is pinned exactly (1.6.4).
9. **History backup tradeoff.** On by default. Anyone who gets K can read the backed-up history.

## Live run against real GitHub

On 2026-11-05, `scripts/live-github.ts` passed all 16 steps with two real accounts. Each account had the GitHub App installed with "Only select repositories". The run checked:

- publishing directories and looking them up across accounts;
- a DM (repo, ticket, collaborator invite, Worker inbox, accept, external join, messages both ways);
- a 1.5 MB attachment through the git blob API;
- compare-and-swap with two writers racing on the same log index five times (exactly one won each time);
- a group invite, join and talk;
- a member leaving, which removed them as a collaborator;
- a removal, after which the removed member sees `access-lost` and can't read the log.

An idle sync costs 5 requests for both owner and member, the same as against the mock.

Still not covered live:

- 409s caused by unrelated commits racing on the branch under heavy load;
- files near the size limit;
- the request budget over hours of polling (at 5,000 requests an hour, polling every minute covers about 16 chats, so a real app should poll quiet chats less often);
- the offline add path (box 4), which the GitHub provider doesn't offer.

Run it again with `npm run build:live && node scripts/live-github.mjs <loginA> <loginB>`. The script uses its own repo names (`keyhold-live-*`, `ghchat-live-*`), deletes them at the end, and never writes tokens or keys to its report.
