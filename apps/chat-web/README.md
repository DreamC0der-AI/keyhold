# Keyhold Chat (web)

End-to-end encrypted 1:1 and group chat in the browser, with GitHub as the only backend. Built on `keyhold/chat` (MLS) and the GitHub provider. Live at https://chat-over-github.akagishigerutokyo.workers.dev, served by the chat-over-github Worker (static assets), which also does the OAuth exchange and the invite inbox.

## What it does

- Sign in with the GitHub App (web flow with PKCE, or device flow with a one-time code). Tokens refresh through the Worker.
- Checks the app is installed on the account ("Only select repositories").
- Identity setup: a root key made in the browser, a device key certified by it, public keys in `<login>/keyhold-id`, the root key backed up to `<login>/keyhold-home` sealed with a recovery code. Another browser joins with the recovery code.
- Chats list, DMs and groups (`ghchat-<random>` private repos), invites through the Worker inbox, accept and join automatically.
- Text, files up to 10 MB (sealed per file), reactions, delete, group rename, members panel, invite and remove (admins), leave.
- Safety numbers and verification, key-change warning.
- Devices list and revoke (needs the recovery code), sign out, forget this browser, reset identity.

Decrypted messages are kept only in this browser (IndexedDB). Keys live in IndexedDB too (box 1 and box 2).

## Polling and rate limit

Each chat's repo is checked with a conditional `GET /repos/{space}/commits?per_page=1` (`If-None-Match`). A 304 doesn't count against GitHub's rate limit, so the full `sync()` only runs when something was written. The open chat is checked every 4 s, recently active ones every 6 s, others every 20 s, everything every 90 s while the tab is hidden. The invite inbox is checked every 15 s and the list of repos once a minute.

## Develop

```
npm install            # in the repo root too (keyhold's own dependencies)
npm run dev            # against real GitHub; sign-in needs the Worker origin, so use a mock build for local work
npm run build          # dist/ -> copy to the Worker's public/
```

Local end-to-end test against the in-memory GitHub mock (`tests/github-mock.ts`), with three people, a DM, a group, removal and a second device:

```
npm run build:mock
npx esbuild tools/mock-server.ts --bundle --platform=node --format=esm --outfile=tools/mock-server.mjs
node tools/mock-server.mjs 8787 &
node tools/e2e.mjs      # needs playwright
```
