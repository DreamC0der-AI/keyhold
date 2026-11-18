/**
 * Root key backup (box 9, the cold vault). Sealed with the account key K, which keyhold/keys
 * unlocks with a passkey (PRF) or the recovery code. Only the root key goes here: never
 * one-time or ratchet keys (they need reliable deletion, and a backup would undo it).
 */
import { jsonBytes, parseJsonBytes, b64, unb64 } from '../util/codec.js';
import { KeyholdError } from '../util/errors.js';
import { open, seal } from '../crypto/index.js';
import type { BackupVault } from '../storage/interfaces.js';
import { mayBackUp } from '../storage/requirements.js';
import { rootFromSecret, type RootKey } from './identity.js';

const NAME = 'root';

export async function backupRootKey(vault: BackupVault, key: CryptoKey, account: string, root: RootKey): Promise<void> {
  if (!mayBackUp('root-key-backup')) throw new KeyholdError('config', 'root key must not be backed up');
  const ctx = { type: 'root-backup', account };
  const sealed = await seal(key, jsonBytes({ v: 1, root: b64(root.secretKey) }), ctx);
  for (let attempt = 0; attempt < 5; attempt++) {
    const cur = await vault.get(NAME);
    if ((await vault.put(NAME, sealed, cur?.version ?? null)) === 'ok') return;
  }
  throw new KeyholdError('conflict', 'vault kept changing');
}

export async function restoreRootKey(vault: BackupVault, key: CryptoKey, account: string): Promise<RootKey | undefined> {
  const cur = await vault.get(NAME);
  if (!cur) return undefined;
  const j = parseJsonBytes<{ v: 1; root: string }>(await open(key, cur.data, { type: 'root-backup', account }));
  return rootFromSecret(unb64(j.root));
}
