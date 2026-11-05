# keyhold

Login, key management and end-to-end encryption for web apps, as three modules that only
meet through small interfaces. Diorama Memory is the first user; nothing here is specific to it.

| Module | Import | Job | Runs in |
| --- | --- | --- | --- |
| Login | `keyhold/auth`, `keyhold/auth/server` | Prove **who** the user is: Google, Apple, 6-digit email code, or a self-custody seed phrase. Returns an `Identity`. Never unlocks anything. | browser + server (Workers, Node) |
| Key management | `keyhold/keys`, `keyhold/keys/browser` | The notes key **K** and every way to unlock it: passkey (WebAuthn PRF), vault password (Argon2id), recovery code, this device, approval from another device by QR. | browser (envelope checks also on server) |
| Encryption | `keyhold/crypto` | Seal and open data with K before it syncs. Takes a `CryptoKey`, nothing else. | anywhere with WebCrypto |
| Seed phrases | `keyhold/seed` | BIP39 helpers shared by the seed login and seed recovery. | anywhere |
| Storage model | `keyhold/storage` | Every chat data type as a requirement (who reads, who writes, how long it lives), the 12 storage kinds derived from them, provider interfaces and capabilities, and an in-memory provider. | anywhere |
| Chat | `keyhold/chat` | End-to-end encrypted DMs and groups on MLS (RFC 9420): identity and directory, group policy and invite tickets, personal synced store, root key backup. Channel-free. | anywhere with WebCrypto |
| GitHub provider | `keyhold/providers/github` | Stores each kind in GitHub repos and uses collaborator access as the channel fence. Never sees plaintext. | browser, Workers, Node |

The interfaces between them:

- auth → app: `Identity { provider, subject, email?, … }`. The app maps it to its own account id.
- keys → crypto: a non-extractable AES-256-GCM `CryptoKey`.
- seed → auth and keys: `deriveSeedSecrets(phrase)` gives an `identitySeed` (Ed25519 login key) and a separate `recoverySecret` (wraps K). Neither reveals the other.

The design these follow is in the "E2E encrypted notes with Apple and Google login" doc.

## How the key scheme works

One random 256-bit key K per account encrypts everything. The server only ever stores
**envelopes**: copies of K locked by one unlock secret each. Adding or removing a way to
unlock adds or deletes an envelope; no data is re-encrypted.

| Envelope | Unlocked by | Lock key |
| --- | --- | --- |
| `passkey` | Face ID / Touch ID / fingerprint / PIN on a PRF passkey | WebAuthn PRF output → HKDF-SHA256 → AES-256-GCM |
| `password` | Vault password (optional fallback) | Argon2id (64 MiB, 3 passes, 16-byte salt) → HKDF → AES-256-GCM |
| `recovery` | Recovery code (128 bits, shown once) or the seed phrase | HKDF → AES-256-GCM |
| `device` | Nothing (kept on this device only) | Non-extractable AES key in IndexedDB |

Every envelope binds its kind, id, account and parameters as AES-GCM additional data, so an
envelope can't be moved to another account and its Argon2 cost can't be lowered unnoticed.

K is non-extractable for daily use. It is opened as extractable only inside a `KeyEditor`,
for the few moments when it must be wrapped again (first setup, adding a passkey, changing
the vault password, a new recovery code, approving a device), and the editor is closed right after.

New-device unlock order (`planUnlock`): this device's record → passkey → approve from another
of your devices → vault password → recovery code. Emailed unlock links and trusted-person
recovery are deliberately not supported.

## Quick tour

### First setup (browser)

```ts
import { KeyEditor, confirmRecoveryCode } from 'keyhold/keys';
import { webauthnPrf, IndexedDbDeviceStore } from 'keyhold/keys/browser';

const keys = { rpId: 'app.example.com', rpName: 'Example' };
const editor = await KeyEditor.create(accountId);

const passkey = await editor.addPasskey(keys, webauthnPrf, { id: userHandle, name: email, displayName: name });
if (!passkey.prfSupported) {
  // No PRF on this device: require a vault password instead.
}
const password = await editor.addPassword(vaultPassword);           // optional when a passkey worked
const { code, envelope: recovery } = await editor.addRecoveryCode(); // show code.words once
// ... user types the last 3 words back: await confirmRecoveryCode(code, typed)
await editor.rememberDevice(new IndexedDbDeviceStore());             // "keep unlocked on this device"

await api.saveEnvelopes([passkey.envelope, password, recovery]);    // never K itself
const notesKey = await editor.close();                              // non-extractable, for keyhold/crypto
```

### Each visit

```ts
import { unlockWithDevice, unlockWithPasskey, planUnlock } from 'keyhold/keys';

const key =
  (await unlockWithDevice(store, accountId)) ??
  (await unlockWithPasskey(envelopes, keys, webauthnPrf)).key;
```

### Seal notes before sync

```ts
import { sealJson, openJson } from 'keyhold/crypto';

const ctx = { type: 'note', account: accountId, id: note.id };
const blob = await sealJson(key, { title, body, doc }, ctx); // compressed, then AES-256-GCM
const note = await openJson(key, blob, ctx);                 // fails if blob was moved to another note
```

### Approve a new device by QR

```ts
// New device (signed in, locked):
const req = await NewDeviceApproval.start({ account: accountId });
showQr(req.qr);                         // relay messages via your server, keyed by req.session
const words = await req.receiveHello(await relay.waitFor('hello'));
const k = await req.receiveKey(await relay.waitFor('key'));
const ed = KeyEditor.fromKey(accountId, k);
await ed.rememberDevice(store);         // and offer ed.addPasskey(...)
const key = await ed.close();

// Existing, unlocked device:
const appr = await ExistingDeviceApproval.accept(scannedText, { account: accountId });
await relay.send('hello', appr.hello);
// show appr.words; user checks both screens show the same 4 words, taps Approve
const editor = await editWithDevice(store, accountId); // or re-unlock with { extractable: true }
await relay.send('key', await editor.approveDevice(appr));
await editor.close();
```

The relay sees two public keys and a ciphertext. A relay that swaps keys changes the words.

### Login (server)

```ts
import { googleProvider, appleProvider, startLogin, finishLogin,
         sendEmailCode, verifyEmailCode, resendEmailSender,
         issueSeedChallenge, verifySeedLogin, D1TokenStore } from 'keyhold/auth/server';

const providers = [
  env.GOOGLE_CLIENT_ID && googleProvider({ clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET }),
  env.APPLE_SERVICES_ID && appleProvider({ servicesId: env.APPLE_SERVICES_ID, teamId: env.APPLE_TEAM_ID,
                                           keyId: env.APPLE_KEY_ID, privateKey: env.APPLE_PRIVATE_KEY }),
].filter(Boolean);

const { url, state } = await startLogin(google, { redirectUri });  // keep `state` in a short-lived cookie
const identity = await finishLogin(google, { code, redirectUri, state, returnedState });
```

Apple posts its callback cross-site (`form_post`), so the cookie holding `state` must be
`SameSite=None; Secure`. Its `user` form field (name) arrives on the first sign-in only: pass it as `appleUser`.

Email codes: `sendEmailCode(cfg, email)` and `verifyEmailCode(cfg, email, code)` with any
`EmailSender` (a Resend one is included) and any `TokenStore` (`D1TokenStore`, `MemoryTokenStore`).

Seed phrase: the browser calls `seedLogin(phrase)` (from `keyhold/auth`), the server
`issueSeedChallenge` / `verifySeedLogin`. The account's subject is the Ed25519 public key.
The browser refuses to sign a challenge issued for another origin.

See [docs/integration.md](docs/integration.md) for tables, endpoints and the order of screens.

## Security notes

- Protects against database leaks, backups, hosting staff and anyone with server access.
  It can't protect against a server that ships altered app code; that's true for every
  browser-based E2E app. A strict CSP and no third-party scripts on the app's pages matter.
- Passkeys belong to one domain (`rpId`). Pick the production domain before real users make passkeys.
- A `device` record means anyone using this browser profile can open the notes. Apps that want a
  passkey tap every visit should skip `rememberDevice` (re-open K with `{ extractable: true }` when editing).
- 12-word codes carry a 4-bit checksum, so 1 in 16 typos still parses and then just fails to unlock.
- Argon2id runs in the browser (WebAssembly). It is not meant for Workers, which can't compile WASM at runtime.

## Development

```sh
npm install
npm test              # vitest: crypto, keys, auth (fake IdPs, fake authenticator, fake IndexedDB, SQLite as D1)
npm run typecheck
npm run test:browser  # real Chromium + virtual PRF authenticator (needs playwright)
npm run build         # dist/
```

Consume it from another repo with `"keyhold": "github:DreamC0der-AI/keyhold"` (built on install).

Chat design: [docs/chat-storage.md](docs/chat-storage.md). Audit and known limits: [docs/chat-audit.md](docs/chat-audit.md).
