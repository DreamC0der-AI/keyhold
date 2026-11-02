/**
 * The high-level key API: create K, add/remove unlock methods, unlock.
 *
 * Two shapes of K:
 *   - daily use: non-extractable CryptoKey (encrypt/decrypt). This is what keyhold/crypto takes.
 *   - KeyEditor: holds an extractable K for a short editing window (first setup, adding a
 *     passkey, changing the vault password, new recovery code, approving a device). Call
 *     `close()` when done; it hands back nothing extractable.
 */
import { toBase64Url } from '../util/bytes.js';
import { KeyholdError } from '../util/errors.js';
import { wrapNotesKey, unwrapNotesKey, envelopesOfKind, type Envelope } from './envelope.js';
import { generateNotesKey, lockNotesKey } from './notes-key.js';
import { passkeyWrappingKey, passkeyParams, newPrfSalt, type PrfProvider, type PasskeyUser, type PrfResult } from './passkey.js';
import {
  passwordWrappingKey,
  newPasswordParams,
  checkVaultPassword,
  defaultArgon2id,
  type Argon2idFn,
  type Argon2Params,
} from './password.js';
import { recoveryWrappingKey, generateRecoveryCode, type RecoveryCode } from './recovery.js';
import { generateDeviceKey, newDeviceId, type DeviceStore, type DeviceRecord } from './device.js';
import type { ExistingDeviceApproval, ApprovalKeyMessage } from './approval.js';

export interface KeysConfig {
  /** WebAuthn relying party id: the site's registrable domain. Passkeys only work on this domain. */
  rpId: string;
  /** Shown in the passkey prompt. */
  rpName: string;
  argon2?: Argon2idFn;
  argon2Params?: Argon2Params;
}

export class KeyEditor {
  private key: CryptoKey | undefined;

  private constructor(
    readonly account: string,
    key: CryptoKey,
  ) {
    if (!key.extractable) throw new KeyholdError('config', 'KeyEditor needs an extractable key');
    this.key = key;
  }

  /** First setup: a brand-new random K. Upload the envelopes you add; never K itself. */
  static async create(account: string): Promise<KeyEditor> {
    return new KeyEditor(account, await generateNotesKey());
  }

  /** Wrap an extractable K obtained from `openEnvelope(..., { extractable: true })` or device approval. */
  static fromKey(account: string, extractableKey: CryptoKey): KeyEditor {
    return new KeyEditor(account, extractableKey);
  }

  private k(): CryptoKey {
    if (!this.key) throw new KeyholdError('config', 'KeyEditor is closed');
    return this.key;
  }

  /** A non-extractable copy for daily use (pass it to keyhold/crypto). */
  async notesKey(): Promise<CryptoKey> {
    return lockNotesKey(this.k());
  }

  /**
   * Make a passkey and wrap K for it. Returns `undefined` envelope when the authenticator
   * can't do PRF; offer the vault password instead.
   */
  async addPasskey(
    cfg: KeysConfig,
    prf: PrfProvider,
    user: PasskeyUser,
    opts: { label?: string; excludeCredentialIds?: string[] } = {},
  ): Promise<{ envelope?: Envelope<'passkey'>; credentialId: string; prfSupported: boolean }> {
    const salt = newPrfSalt();
    const reg = await prf.register({ rpId: cfg.rpId, rpName: cfg.rpName, user, prfSalt: salt, excludeCredentialIds: opts.excludeCredentialIds });
    let result: PrfResult | undefined = reg.prf;
    if (!result && reg.prfSupported) {
      // Some authenticators only evaluate PRF on get(), not create().
      result = await prf.evaluate({ rpId: cfg.rpId, credentials: [{ credentialId: reg.credentialId, prfSalt: toBase64Url(salt) }] });
    }
    if (!result) return { credentialId: reg.credentialId, prfSupported: false };
    const envelope = await this.addPasskeyFromPrf(cfg.rpId, reg.credentialId, salt, result.output, opts.label);
    return { envelope, credentialId: reg.credentialId, prfSupported: true };
  }

  /** Lower-level: wrap K for a PRF output you already have. Wipes `prfOutput`. */
  async addPasskeyFromPrf(rpId: string, credentialId: string, prfSalt: Uint8Array, prfOutput: Uint8Array, label?: string): Promise<Envelope<'passkey'>> {
    try {
      const wk = await passkeyWrappingKey(prfOutput);
      return wrapNotesKey(this.k(), wk, { kind: 'passkey', account: this.account, params: passkeyParams(credentialId, prfSalt, rpId), label });
    } finally {
      prfOutput.fill(0);
    }
  }

  /** Set (or change: add the new one, then delete the old envelope) the vault password. */
  async addPassword(
    password: string,
    opts: { argon2?: Argon2idFn; params?: Argon2Params; skipStrengthCheck?: boolean; label?: string } = {},
  ): Promise<Envelope<'password'>> {
    if (!opts.skipStrengthCheck) {
      const check = checkVaultPassword(password);
      if (!check.ok) throw new KeyholdError('weak_password', `vault password rejected: ${check.reason}`);
    }
    const params = newPasswordParams(opts.params);
    const wk = await passwordWrappingKey(password, params, opts.argon2 ?? defaultArgon2id, { allowWeakParams: !!opts.params });
    return wrapNotesKey(this.k(), wk, { kind: 'password', account: this.account, params, label: opts.label });
  }

  /**
   * New random recovery code. Show `code.words` (or `code.grouped`) once, have the user type
   * the last block back (`confirmRecoveryCode`), then store the envelope and delete older
   * recovery envelopes so the old code stops working.
   */
  async addRecoveryCode(code?: RecoveryCode): Promise<{ code: RecoveryCode; envelope: Envelope<'recovery'> }> {
    const c = code ?? (await generateRecoveryCode());
    const envelope = await wrapNotesKey(this.k(), await recoveryWrappingKey(c.bytes), {
      kind: 'recovery',
      account: this.account,
      params: { source: 'code' },
    });
    return { code: c, envelope };
  }

  /** Seed-phrase accounts: the seed is the recovery code. Pass `deriveSeedSecrets(phrase).recoverySecret`. */
  async addSeedRecovery(recoverySecret: Uint8Array): Promise<Envelope<'recovery'>> {
    return wrapNotesKey(this.k(), await recoveryWrappingKey(recoverySecret), {
      kind: 'recovery',
      account: this.account,
      params: { source: 'seed' },
    });
  }

  /** Remember this device: a local, non-extractable device key wraps K; both stay on the device. */
  async rememberDevice(store: DeviceStore, label?: string): Promise<DeviceRecord> {
    const deviceKey = await generateDeviceKey();
    const deviceId = newDeviceId();
    const envelope = await wrapNotesKey(this.k(), deviceKey, { kind: 'device', account: this.account, params: { deviceId }, label });
    const record: DeviceRecord = { account: this.account, deviceId, deviceKey, envelope };
    await store.put(record);
    return record;
  }

  /** On the unlocked device: send K to a new device after the user confirmed the 4 words. */
  async approveDevice(approval: ExistingDeviceApproval): Promise<ApprovalKeyMessage> {
    if (approval.account !== this.account) throw new KeyholdError('approval_failed', 'approval is for another account');
    return approval.approve(this.k());
  }

  /** Forget the extractable key. Returns a non-extractable copy for continued use. */
  async close(): Promise<CryptoKey> {
    const locked = await lockNotesKey(this.k());
    this.key = undefined;
    return locked;
  }
}

// ---- unlocking ------------------------------------------------------------------------

export interface OpenOptions {
  /** true = return a KeyEditor-ready extractable key. Default false (daily use). */
  extractable?: boolean;
}

/**
 * Unlock with a passkey. Asks the user for any passkey that has an envelope here, then opens
 * that envelope. Throws `prf_unavailable` if there are no passkey envelopes for this rpId.
 */
export async function unlockWithPasskey(
  envelopes: readonly Envelope[],
  cfg: Pick<KeysConfig, 'rpId'>,
  prf: PrfProvider,
  opts: OpenOptions = {},
): Promise<{ key: CryptoKey; envelope: Envelope<'passkey'> }> {
  const mine = envelopesOfKind(envelopes, 'passkey').filter((e) => e.params.rpId === cfg.rpId);
  if (mine.length === 0) throw new KeyholdError('prf_unavailable', 'no passkey is set up for this site');
  const result = await prf.evaluate({
    rpId: cfg.rpId,
    credentials: mine.map((e) => ({ credentialId: e.params.credentialId, prfSalt: e.params.prfSalt })),
  });
  const envelope = mine.find((e) => e.params.credentialId === result.credentialId);
  if (!envelope) {
    result.output.fill(0);
    throw new KeyholdError('wrong_secret', 'that passkey is not set up to unlock these notes');
  }
  try {
    const wk = await passkeyWrappingKey(result.output);
    return { key: await unwrapNotesKey(envelope, wk, opts), envelope };
  } finally {
    result.output.fill(0);
  }
}

/** Unlock with the vault password. Tries every password envelope (normally there is one). */
export async function unlockWithPassword(
  envelopes: readonly Envelope[],
  password: string,
  opts: OpenOptions & { argon2?: Argon2idFn; allowWeakParams?: boolean } = {},
): Promise<{ key: CryptoKey; envelope: Envelope<'password'> }> {
  const list = envelopesOfKind(envelopes, 'password');
  if (list.length === 0) throw new KeyholdError('wrong_secret', 'no vault password is set');
  let lastErr: unknown;
  for (const envelope of list) {
    try {
      const wk = await passwordWrappingKey(password, envelope.params, opts.argon2 ?? defaultArgon2id, { allowWeakParams: opts.allowWeakParams });
      return { key: await unwrapNotesKey(envelope, wk, opts), envelope };
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr instanceof KeyholdError ? lastErr : new KeyholdError('wrong_secret', 'wrong vault password', { cause: lastErr });
}

/** Unlock with the recovery code bytes (from `parseRecoveryCode`) or a seed's recovery secret. */
export async function unlockWithRecovery(
  envelopes: readonly Envelope[],
  secret: Uint8Array,
  opts: OpenOptions = {},
): Promise<{ key: CryptoKey; envelope: Envelope<'recovery'> }> {
  const source = secret.length === 32 ? 'seed' : 'code';
  const list = envelopesOfKind(envelopes, 'recovery').filter((e) => e.params.source === source);
  if (list.length === 0) throw new KeyholdError('wrong_secret', `no ${source === 'seed' ? 'seed phrase' : 'recovery code'} is set up`);
  const wk = await recoveryWrappingKey(secret);
  for (const envelope of list) {
    try {
      return { key: await unwrapNotesKey(envelope, wk, opts), envelope };
    } catch {
      /* try the next one */
    }
  }
  throw new KeyholdError('wrong_secret', 'that recovery code does not match');
}

/** Re-open K from this device's own record (no user gesture). `undefined` if the device isn't remembered. */
export async function unlockWithDevice(store: DeviceStore, account: string, opts: OpenOptions = {}): Promise<CryptoKey | undefined> {
  const rec = await store.get(account);
  if (!rec) return undefined;
  return unwrapNotesKey(rec.envelope, rec.deviceKey, opts);
}

/** Open a KeyEditor from this device's record, e.g. to add a passkey later without re-auth. */
export async function editWithDevice(store: DeviceStore, account: string): Promise<KeyEditor | undefined> {
  const k = await unlockWithDevice(store, account, { extractable: true });
  return k && KeyEditor.fromKey(account, k);
}

// ---- unlock order ----------------------------------------------------------------------

export type UnlockMethod = 'device' | 'passkey' | 'approval' | 'password' | 'recovery';

/**
 * Which unlock options to offer, in the agreed order:
 * this device's own record, passkey, approval from another of your devices, vault password,
 * recovery code. Methods with nothing set up are left out.
 */
export function planUnlock(input: {
  envelopes: readonly Envelope[];
  rpId: string;
  /** This device already has a record (from `rememberDevice`). */
  hasDeviceRecord?: boolean;
  /** At least one other device is known to be able to approve (app knows its device list). Default true. */
  canApprove?: boolean;
}): UnlockMethod[] {
  const out: UnlockMethod[] = [];
  if (input.hasDeviceRecord) out.push('device');
  if (input.envelopes.some((e) => e.kind === 'passkey' && e.params.rpId === input.rpId)) out.push('passkey');
  if (input.canApprove ?? true) out.push('approval');
  if (input.envelopes.some((e) => e.kind === 'password')) out.push('password');
  if (input.envelopes.some((e) => e.kind === 'recovery')) out.push('recovery');
  return out;
}
