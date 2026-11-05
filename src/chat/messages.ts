/**
 * Application messages (box 6). Everything a member says travels as one of these, encrypted
 * as an MLS application message. Edits, deletes, reactions and receipts refer to a message id.
 */
import { randomBytes, toHex } from '../util/bytes.js';
import { jsonBytes, parseJsonBytes } from '../util/codec.js';
import { KeyholdError } from '../util/errors.js';

export interface AttachmentRef {
  /** Blob store reference. */
  ref: string;
  /** base64url AES-256 key for this attachment only. */
  key: string;
  /** base64url SHA-256 of the sealed blob, checked before opening. */
  hash: string;
  size: number;
  mime?: string;
  name?: string;
}

export type AppContent =
  | { t: 'text'; body: string; reply?: string }
  | { t: 'edit'; ref: string; body: string }
  | { t: 'delete'; ref: string }
  | { t: 'react'; ref: string; emoji: string }
  | { t: 'receipt'; ref: string; kind: 'delivered' | 'read' }
  | { t: 'attachment'; file: AttachmentRef; caption?: string }
  /** Group name and avatar. Receivers accept it only from admins. */
  | { t: 'meta'; name?: string; avatar?: string }
  /** A non-owner admin asks the space manager's app to grant channel access. */
  | { t: 'sys.grant'; address: string; expiresAt: number };

export type AppMessage = AppContent & { v: 1; id: string; ts: number };

const TYPES = new Set(['text', 'edit', 'delete', 'react', 'receipt', 'attachment', 'meta', 'sys.grant']);

export function newMessageId(): string {
  return toHex(randomBytes(12));
}

/**
 * Encode with padding, so the storage can't tell "ok" from a paragraph: lengths are rounded up
 * to 256, 512, 1024, ... 16 KiB, then to multiples of 16 KiB. MLS pads only small messages.
 */
export function encodeAppMessage(m: AppMessage): Uint8Array {
  const base = jsonBytes(m).length;
  const overhead = 7; // ,"~":""
  const need = base + overhead;
  let target = 256;
  while (target < need && target < 16384) target *= 2;
  if (target < need) target = Math.ceil(need / 16384) * 16384;
  return jsonBytes({ ...m, '~': ' '.repeat(target - need) });
}

export function decodeAppMessage(b: Uint8Array): AppMessage {
  const m = parseJsonBytes<AppMessage & { '~'?: string }>(b, 'message');
  delete m['~'];
  if (!m || m.v !== 1 || typeof m.id !== 'string' || !TYPES.has(m.t)) throw new KeyholdError('bad_format', 'unknown message');
  return m;
}
