/**
 * Envelopes: locked copies of the notes key K.
 *
 * K is a random 256-bit AES-GCM key. Each way of unlocking (a passkey, the vault password,
 * the recovery code, a device) gets its own envelope: K wrapped with AES-256-GCM under a key
 * derived from that unlock secret. Envelopes are safe to store on the server.
 * Adding or removing an unlock method only adds or deletes an envelope; no data is re-encrypted.
 */
import { fromBase64Url, randomBytes, toBase64Url, utf8 } from '../util/bytes.js';
import { KeyholdError } from '../util/errors.js';

export const ENVELOPE_VERSION = 1;

export type EnvelopeKind = 'passkey' | 'password' | 'recovery' | 'device';

export interface PasskeyParams {
  /** base64url WebAuthn credential id. */
  credentialId: string;
  /** base64url 32-byte PRF input, random per envelope. */
  prfSalt: string;
  /** The WebAuthn RP id (domain) the passkey belongs to. */
  rpId: string;
}

export interface PasswordParams {
  kdf: 'argon2id';
  /** base64url 16-byte salt. */
  salt: string;
  /** Memory in KiB, iterations, parallelism. */
  m: number;
  t: number;
  p: number;
}

export interface RecoveryParams {
  /** 'code' = a random recovery code; 'seed' = the account's BIP39 seed phrase. */
  source: 'code' | 'seed';
}

export interface DeviceParams {
  deviceId: string;
}

export type EnvelopeParams = PasskeyParams | PasswordParams | RecoveryParams | DeviceParams;

export interface ParamsByKind {
  passkey: PasskeyParams;
  password: PasswordParams;
  recovery: RecoveryParams;
  device: DeviceParams;
}

/** One locked copy of K. A discriminated union on `kind` when K is left as the default. */
export type Envelope<K extends EnvelopeKind = EnvelopeKind> = K extends EnvelopeKind ? EnvelopeOf<K> : never;

export interface EnvelopeOf<K extends EnvelopeKind> {
  v: typeof ENVELOPE_VERSION;
  /** Random id; stable for the envelope's life. */
  id: string;
  kind: K;
  /** The account the key belongs to. Bound into the ciphertext. */
  account: string;
  /** ISO time. Informational. */
  createdAt: string;
  /** User-facing name, e.g. "iPhone passkey". Not bound into the ciphertext, so it can be renamed. */
  label?: string;
  params: ParamsByKind[K];
  /** base64url 12-byte nonce and wrapped key (32 bytes + 16-byte tag). */
  iv: string;
  ct: string;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .sort()
    .filter((k) => obj[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
    .join(',')}}`;
}

/** Everything that must not be swapped between envelopes is bound in as AES-GCM additional data. */
function envelopeAad(e: Pick<Envelope, 'v' | 'id' | 'kind' | 'account' | 'params'>): Uint8Array<ArrayBuffer> {
  return utf8(`keyhold/v1/envelope\n${canonicalJson([e.v, e.kind, e.id, e.account, e.params])}`);
}

export function newEnvelopeId(): string {
  return toBase64Url(randomBytes(12));
}

/** Wrap an extractable K under `wrappingKey` (AES-GCM, usage wrapKey). */
export async function wrapNotesKey<K extends EnvelopeKind>(
  notesKey: CryptoKey,
  wrappingKey: CryptoKey,
  meta: { id?: string; kind: K; account: string; params: ParamsByKind[K]; label?: string },
): Promise<Envelope<K>> {
  if (!notesKey.extractable) {
    throw new KeyholdError('config', 'wrapping needs the extractable notes key (use a KeyEditor)');
  }
  const head = {
    v: ENVELOPE_VERSION,
    id: meta.id ?? newEnvelopeId(),
    kind: meta.kind,
    account: meta.account,
    params: meta.params,
  } as const;
  const iv = randomBytes(12);
  const ct = await crypto.subtle.wrapKey('raw', notesKey, wrappingKey, {
    name: 'AES-GCM',
    iv,
    additionalData: envelopeAad(head),
  });
  const env = {
    ...head,
    createdAt: new Date().toISOString(),
    iv: toBase64Url(iv),
    ct: toBase64Url(new Uint8Array(ct)),
  } as EnvelopeOf<K> as Envelope<K>;
  if (meta.label !== undefined) env.label = meta.label;
  return env;
}

/**
 * Unwrap K. By default K comes back non-extractable (encrypt/decrypt only), which is what
 * daily use needs. `extractable: true` is only for re-wrapping (new envelope, device approval).
 */
export async function unwrapNotesKey(
  envelope: Envelope,
  wrappingKey: CryptoKey,
  options: { extractable?: boolean } = {},
): Promise<CryptoKey> {
  assertEnvelope(envelope);
  try {
    return await crypto.subtle.unwrapKey(
      'raw',
      fromBase64Url(envelope.ct),
      wrappingKey,
      { name: 'AES-GCM', iv: fromBase64Url(envelope.iv), additionalData: envelopeAad(envelope) },
      { name: 'AES-GCM', length: 256 },
      options.extractable ?? false,
      ['encrypt', 'decrypt'],
    );
  } catch (e) {
    throw new KeyholdError('wrong_secret', `this ${envelope.kind} did not unlock the notes key`, { cause: e });
  }
}

const isStr = (x: unknown): x is string => typeof x === 'string' && x.length > 0;
const isB64 = (x: unknown): x is string => typeof x === 'string' && /^[A-Za-z0-9_-]+$/.test(x);
const isPosInt = (x: unknown): x is number => typeof x === 'number' && Number.isInteger(x) && x > 0;

/** Shape check for envelopes arriving from storage or the network. Servers can use it before saving. */
export function isEnvelope(x: unknown): x is Envelope {
  if (!x || typeof x !== 'object') return false;
  const e = x as Record<string, unknown>;
  if (e.v !== ENVELOPE_VERSION || !isB64(e.id) || !isStr(e.account) || !isStr(e.createdAt)) return false;
  if (!isB64(e.iv) || !isB64(e.ct)) return false;
  if (e.label !== undefined && typeof e.label !== 'string') return false;
  const p = e.params as Record<string, unknown> | undefined;
  if (!p || typeof p !== 'object') return false;
  switch (e.kind) {
    case 'passkey':
      return isB64(p.credentialId) && isB64(p.prfSalt) && isStr(p.rpId);
    case 'password':
      return p.kdf === 'argon2id' && isB64(p.salt) && isPosInt(p.m) && isPosInt(p.t) && isPosInt(p.p);
    case 'recovery':
      return p.source === 'code' || p.source === 'seed';
    case 'device':
      return isStr(p.deviceId);
    default:
      return false;
  }
}

export function assertEnvelope(x: unknown): asserts x is Envelope {
  if (!isEnvelope(x)) throw new KeyholdError('bad_format', 'not a keyhold envelope');
}

export function envelopesOfKind<K extends EnvelopeKind>(list: readonly Envelope[], kind: K): Envelope<K>[] {
  return list.filter((e): e is Envelope<K> => e.kind === kind);
}
