/**
 * Email login with a 6-digit code (valid 10 minutes, 5 tries). A code, not a magic link:
 * on phones a link often opens in another browser where the user isn't signed in.
 *
 * Only an HMAC of the code is stored. Sending is behind `EmailSender`, so the provider
 * (Cloudflare Email, Resend, Postmark, ...) and the From domain are configuration.
 */
import { equalBytes, toBase64Url, utf8, fromBase64Url } from '../../util/bytes.js';
import { KeyholdError } from '../../util/errors.js';
import type { TokenStore } from './store.js';
import type { Identity } from '../types.js';
import type { FetchFn } from './jwt.js';

export interface EmailSender {
  send(message: { to: string; code: string; expiresInMinutes: number }): Promise<void>;
}

export interface EmailCodeConfig {
  store: TokenStore;
  sender: EmailSender;
  /** Server secret (>= 32 random bytes, base64url or plain string) used to HMAC codes. */
  secret: string;
  ttlMs?: number;
  maxAttempts?: number;
  /** Minimum gap between two codes to the same address. */
  resendAfterMs?: number;
  now?: () => number;
}

interface CodeRecord {
  h: string; // base64url HMAC(email|code)
  exp: number;
  sent: number;
  tries: number;
}

export function normalizeEmail(email: string): string {
  const e = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) || e.length > 254) throw new KeyholdError('auth_failed', 'that is not an email address');
  return e;
}

async function hmac(secret: string, msg: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(msg)));
}

function sixDigits(): string {
  // Rejection sampling for an unbiased 000000-999999.
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0]! < 4_294_000_000) return String(buf[0]! % 1_000_000).padStart(6, '0');
  }
}

const keyFor = (email: string) => `email-code:${email}`;

/** Send a code. Throws `too_many_attempts` if asked again within `resendAfterMs`. */
export async function sendEmailCode(cfg: EmailCodeConfig, rawEmail: string): Promise<{ email: string; expiresAt: number }> {
  const email = normalizeEmail(rawEmail);
  const now = (cfg.now ?? Date.now)();
  const prev = await cfg.store.get(keyFor(email));
  if (prev) {
    const rec = JSON.parse(prev) as CodeRecord;
    if (now - rec.sent < (cfg.resendAfterMs ?? 30_000)) {
      throw new KeyholdError('too_many_attempts', 'a code was just sent; wait a moment before asking again');
    }
  }
  const ttl = cfg.ttlMs ?? 10 * 60_000;
  const code = sixDigits();
  const rec: CodeRecord = { h: toBase64Url(await hmac(cfg.secret, `${email}|${code}`)), exp: now + ttl, sent: now, tries: 0 };
  await cfg.store.put(keyFor(email), JSON.stringify(rec), rec.exp);
  await cfg.sender.send({ to: email, code, expiresInMinutes: Math.round(ttl / 60_000) });
  return { email, expiresAt: rec.exp };
}

/** Check a typed code. On success the code is used up and the email is the identity. */
export async function verifyEmailCode(cfg: EmailCodeConfig, rawEmail: string, rawCode: string): Promise<Identity> {
  const email = normalizeEmail(rawEmail);
  const now = (cfg.now ?? Date.now)();
  const stored = await cfg.store.get(keyFor(email));
  if (!stored) throw new KeyholdError('code_expired', 'that code has expired; ask for a new one');
  const rec = JSON.parse(stored) as CodeRecord;
  if (rec.exp <= now) {
    await cfg.store.delete(keyFor(email));
    throw new KeyholdError('code_expired', 'that code has expired; ask for a new one');
  }
  if (rec.tries >= (cfg.maxAttempts ?? 5)) {
    await cfg.store.delete(keyFor(email));
    throw new KeyholdError('too_many_attempts', 'too many wrong codes; ask for a new one');
  }
  const code = rawCode.replace(/\D/g, '');
  const ok = code.length === 6 && equalBytes(await hmac(cfg.secret, `${email}|${code}`), fromBase64Url(rec.h));
  if (!ok) {
    rec.tries++;
    await cfg.store.put(keyFor(email), JSON.stringify(rec), rec.exp);
    throw new KeyholdError('auth_failed', 'wrong code');
  }
  // Single use: take() so two parallel correct submissions can't both win.
  if ((await cfg.store.take(keyFor(email))) === undefined) throw new KeyholdError('code_expired', 'that code was already used');
  return { provider: 'email', subject: email, email, emailVerified: true };
}

/** A sender for Resend's HTTP API. Any other service only needs an `EmailSender`. */
export function resendEmailSender(cfg: {
  apiKey: string;
  /** e.g. "Diorama Memory <login@yourdomain.com>". Needs a verified domain. */
  from: string;
  subject?: string;
  appName?: string;
  fetch?: FetchFn;
}): EmailSender {
  return {
    async send({ to, code, expiresInMinutes }) {
      const app = cfg.appName ?? 'your account';
      const res = await (cfg.fetch ?? fetch)('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: `Bearer ${cfg.apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          from: cfg.from,
          to: [to],
          subject: cfg.subject ?? `${code} is your sign-in code`,
          text: `Your sign-in code for ${app} is ${code}.\nIt expires in ${expiresInMinutes} minutes. If you didn't ask for it, ignore this email.`,
        }),
      });
      if (!res.ok) throw new KeyholdError('auth_failed', `email send failed (${res.status})`);
    },
  };
}
