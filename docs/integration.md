# Integrating keyhold

What an app adds around the library. Diorama Memory (Cloudflare Worker + D1) is the example,
but nothing here depends on it.

## Tables

```sql
-- One account can have several sign-in identities. Never merge by email automatically.
CREATE TABLE identities (
  provider   TEXT NOT NULL,      -- 'google' | 'apple' | 'email' | 'seed'
  subject    TEXT NOT NULL,      -- OIDC sub, normalized email, or Ed25519 public key
  account_id TEXT NOT NULL REFERENCES users(id),
  email      TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (provider, subject)
);

-- Locked copies of the notes key. Opaque JSON; validate with isEnvelope() before saving.
CREATE TABLE key_envelopes (
  id         TEXT PRIMARY KEY,   -- envelope.id
  account_id TEXT NOT NULL,      -- must equal envelope.account and the signed-in account
  kind       TEXT NOT NULL,      -- passkey | password | recovery   (device envelopes stay on the device)
  label      TEXT,
  body       TEXT NOT NULL,      -- JSON.stringify(envelope)
  created_at INTEGER NOT NULL
);
CREATE INDEX key_envelopes_account ON key_envelopes (account_id);

-- Email codes and seed challenges (D1TokenStore). Also exported as D1_TOKEN_TABLE_SQL.
CREATE TABLE keyhold_tokens (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL);

-- Device approval relay: two messages per session, gone after 5 minutes.
CREATE TABLE device_approvals (
  session    TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  hello      TEXT,
  key_msg    TEXT,
  expires_at INTEGER NOT NULL
);
```

Encrypted notes: replace the plaintext title/body/doc columns with one `sealed TEXT` column,
written by `sealJson(K, {title, body, doc}, { type: 'note', account, id })`.
Rooms the same way with `type: 'room'`.

## Endpoints

| Route | Does |
| --- | --- |
| `GET /api/auth/{google,apple}/start` | `startLogin`, store `LoginState` in a 10-minute HttpOnly cookie (`SameSite=None; Secure` for Apple) |
| `GET /api/auth/google/callback`, `POST /api/auth/apple/callback` | `finishLogin` → identity → account → session |
| `POST /api/auth/email/send`, `POST /api/auth/email/verify` | `sendEmailCode`, `verifyEmailCode` |
| `POST /api/auth/seed/challenge`, `POST /api/auth/seed/verify` | `issueSeedChallenge`, `verifySeedLogin` |
| `POST /api/auth/link/{provider}` | "Also sign in with …": same flows while signed in, adds an `identities` row |
| `GET/PUT/DELETE /api/keys/envelopes` | the signed-in account's envelopes |
| `POST /api/keys/approvals/:session/{hello,key}`, `GET …` | relay for device approval (signed-in account must match) |

Login and unlock are separate: every route above that needs an account needs only the
session, never K.

## Screens, in order

**Sign-up:** sign in (any method) → create passkey (`addPasskey`) → if no PRF, set a vault
password (required) else offer one (optional) → show recovery code, have the last 3 words typed
back → `rememberDevice` if the user keeps this device unlocked → upload envelopes → done.
Seed accounts: show the phrase instead of a recovery code (`addSeedRecovery`).

**New device:** sign in → `planUnlock(...)` and offer the methods in that order →
once unlocked, offer "Create a passkey on this device".

**Settings:** list envelopes by label; add passkey; change vault password (add new, delete old);
new recovery code (add new, delete old: the old code stops working); remove a lost passkey.

## Open questions (from the design doc, still to decide)

1. **Apple login** needs the US$99/year Apple Developer Program. `appleProvider` is ready; the
   app only turns it on when the four `APPLE_*` secrets exist.
2. **Production domain** decides the passkey `rpId` and the email From address. Both are config
   (`KeysConfig.rpId`, `resendEmailSender({ from })`), so nothing in keyhold changes.
3. **Unlock frequency**: `rememberDevice` = keep unlocked; skip it for a tap every visit.
4. Recovery storage (password manager / print), encryption default-on, encrypting rooms,
   passkey sign-in: app decisions; keyhold supports each.
