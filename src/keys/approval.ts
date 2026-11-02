/**
 * Approve a new device from an already-unlocked one ("scan the QR, check the 4 words").
 *
 *   new device                          relay (your server)               unlocked device
 *   ----------                          -------------------               ---------------
 *   startDeviceApproval()
 *     shows QR(session, account, pubN)  ───────── scanned by camera ────► acceptDeviceApproval(qr)
 *                                       ◄──── hello {session, pubE} ────    shows 4 words
 *   receiveHello(hello)
 *     shows 4 words
 *                                         user checks the words match and taps Approve
 *                                       ◄──── key {session, iv, ct} ────  approve(editableK)
 *   receiveKey(msg) -> K
 *
 * Ephemeral ECDH P-256 on both sides (private keys non-extractable). The transfer key and the
 * 4 words both come from HKDF over the shared secret with the full transcript as salt, so the
 * relay sees only public keys and ciphertext, and a swapped public key changes the words.
 * The QR carries the new device's public key optically, out of the relay's reach.
 *
 * Transport is the app's job: it only has to pass the two small JSON messages along.
 */
import { concat, fromBase64Url, own, randomBytes, sha256, toBase64Url, utf8 } from '../util/bytes.js';
import { hkdfBytes } from '../util/hkdf.js';
import { KeyholdError } from '../util/errors.js';
import { bytesToWordIndices, englishWordlist } from '../seed/index.js';
import { assertExtractable } from './notes-key.js';

const QR_PREFIX = 'keyhold-approve:1:';
const ECDH = { name: 'ECDH', namedCurve: 'P-256' } as const;
const TRANSFER_INFO = 'keyhold/v1/approve/transfer';
const SAS_INFO = 'keyhold/v1/approve/words';

/** How long a QR code stays valid. */
export const APPROVAL_TTL_MS = 5 * 60 * 1000;

export interface ApprovalHello {
  type: 'keyhold-approve-hello';
  session: string;
  /** base64url raw P-256 public key of the approving device. */
  pub: string;
}

export interface ApprovalKeyMessage {
  type: 'keyhold-approve-key';
  session: string;
  iv: string;
  ct: string;
}

interface QrPayload {
  session: string;
  account: string;
  /** Unix ms when the QR was made. */
  t: number;
  pub: string;
}

function encodeQr(p: QrPayload): string {
  return QR_PREFIX + toBase64Url(utf8(JSON.stringify([p.session, p.account, p.t, p.pub])));
}

/** Parse a scanned QR. Also accepts a URL whose `#` fragment is the QR string. */
export function parseApprovalQr(text: string): QrPayload {
  const raw = text.includes('#') && !text.startsWith(QR_PREFIX) ? decodeURIComponent(text.slice(text.indexOf('#') + 1)) : text;
  if (!raw.startsWith(QR_PREFIX)) throw new KeyholdError('bad_format', 'not a keyhold approval code');
  try {
    const [session, account, t, pub] = JSON.parse(new TextDecoder().decode(fromBase64Url(raw.slice(QR_PREFIX.length))));
    if (typeof session !== 'string' || typeof account !== 'string' || typeof t !== 'number' || typeof pub !== 'string') {
      throw new Error('shape');
    }
    return { session, account, t, pub };
  } catch (e) {
    throw new KeyholdError('bad_format', 'not a keyhold approval code', { cause: e });
  }
}

async function exportPub(key: CryptoKey): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
}

async function importPub(b64: string): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey('raw', fromBase64Url(b64), ECDH, false, []);
  } catch (e) {
    throw new KeyholdError('approval_failed', 'bad public key in approval message', { cause: e });
  }
}

interface Derived {
  transferKey: CryptoKey;
  words: string[];
  aad: Uint8Array<ArrayBuffer>;
}

async function derive(priv: CryptoKey, peerPub: CryptoKey, qr: QrPayload, pubE: string): Promise<Derived> {
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPub }, priv, 256));
  const transcript = utf8(['keyhold/v1/approve', qr.session, qr.account, String(qr.t), qr.pub, pubE].join('\n'));
  const salt = await sha256(transcript);
  try {
    const [keyBytes, sasBytes] = await Promise.all([hkdfBytes(shared, TRANSFER_INFO, 32, salt), hkdfBytes(shared, SAS_INFO, 6, salt)]);
    const transferKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
    keyBytes.fill(0);
    const words = bytesToWordIndices(sasBytes, 4).map((i) => englishWordlist[i]!);
    return { transferKey, words, aad: transcript };
  } finally {
    shared.fill(0);
  }
}

/** Runs on the NEW device, which is signed in but can't open the notes yet. */
export class NewDeviceApproval {
  /** Show this as a QR code (or a link with it after `#`). */
  readonly qr: string;
  readonly session: string;
  private derived?: Derived;
  private done = false;

  private constructor(
    private readonly payload: QrPayload,
    private readonly priv: CryptoKey,
  ) {
    this.qr = encodeQr(payload);
    this.session = payload.session;
  }

  static async start(input: { account: string; now?: number }): Promise<NewDeviceApproval> {
    const pair = await crypto.subtle.generateKey(ECDH, false, ['deriveBits']);
    const payload: QrPayload = {
      session: toBase64Url(randomBytes(16)),
      account: input.account,
      t: input.now ?? Date.now(),
      pub: await exportPub(pair.publicKey),
    };
    return new NewDeviceApproval(payload, pair.privateKey);
  }

  /** Feed the approving device's hello. Returns the 4 words to show. */
  async receiveHello(hello: ApprovalHello): Promise<string[]> {
    if (hello?.type !== 'keyhold-approve-hello' || hello.session !== this.session) {
      throw new KeyholdError('approval_failed', 'approval message is for another session');
    }
    this.derived = await derive(this.priv, await importPub(hello.pub), this.payload, hello.pub);
    return this.derived.words;
  }

  get words(): string[] | undefined {
    return this.derived?.words;
  }

  /**
   * Feed the key message. Returns K, extractable so the caller can immediately wrap a
   * device envelope / passkey envelope for this device (use `KeyEditor.fromApproval`).
   */
  async receiveKey(msg: ApprovalKeyMessage): Promise<CryptoKey> {
    if (!this.derived) throw new KeyholdError('approval_failed', 'receiveHello must come first');
    if (this.done) throw new KeyholdError('approval_failed', 'this approval was already used');
    if (msg?.type !== 'keyhold-approve-key' || msg.session !== this.session) {
      throw new KeyholdError('approval_failed', 'approval message is for another session');
    }
    let raw: Uint8Array | undefined;
    try {
      raw = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: fromBase64Url(msg.iv), additionalData: concat(this.derived.aad, utf8('\nkey')) },
          this.derived.transferKey,
          fromBase64Url(msg.ct),
        ),
      );
      this.done = true;
      return await crypto.subtle.importKey('raw', own(raw), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    } catch (e) {
      if (e instanceof KeyholdError) throw e;
      throw new KeyholdError('approval_failed', 'could not open the approved key', { cause: e });
    } finally {
      raw?.fill(0);
    }
  }
}

/** Runs on the EXISTING, unlocked device after scanning the QR. */
export class ExistingDeviceApproval {
  private used = false;
  private constructor(
    private readonly payload: QrPayload,
    private readonly derived: Derived,
    /** Send this to the new device through your relay. */
    readonly hello: ApprovalHello,
  ) {}

  /** The 4 words to show; the user checks they match the new device's screen. */
  get words(): string[] {
    return this.derived.words;
  }

  get account(): string {
    return this.payload.account;
  }

  static async accept(qrText: string, input: { account: string; now?: number; ttlMs?: number }): Promise<ExistingDeviceApproval> {
    const qr = parseApprovalQr(qrText);
    if (qr.account !== input.account) {
      throw new KeyholdError('approval_failed', 'this code is for a different account');
    }
    const age = (input.now ?? Date.now()) - qr.t;
    if (age > (input.ttlMs ?? APPROVAL_TTL_MS) || age < -60_000) {
      throw new KeyholdError('approval_failed', 'this code has expired; make a new one on the other device');
    }
    const pair = await crypto.subtle.generateKey(ECDH, false, ['deriveBits']);
    const pub = await exportPub(pair.publicKey);
    const derived = await derive(pair.privateKey, await importPub(qr.pub), qr, pub);
    return new ExistingDeviceApproval(qr, derived, { type: 'keyhold-approve-hello', session: qr.session, pub });
  }

  /**
   * Call only after the user confirmed the words match. `editableKey` is K opened for
   * editing (see `KeyEditor.approveDevice`); its raw bytes exist only during this call.
   */
  async approve(editableKey: CryptoKey): Promise<ApprovalKeyMessage> {
    if (this.used) throw new KeyholdError('approval_failed', 'this approval was already used');
    assertExtractable(editableKey);
    this.used = true;
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', editableKey));
    try {
      const iv = randomBytes(12);
      const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: concat(this.derived.aad, utf8('\nkey')) },
        this.derived.transferKey,
        raw,
      );
      return { type: 'keyhold-approve-key', session: this.payload.session, iv: toBase64Url(iv), ct: toBase64Url(new Uint8Array(ct)) };
    } finally {
      raw.fill(0);
    }
  }
}
