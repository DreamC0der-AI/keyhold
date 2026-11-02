/** Minimal JWT (JWS compact) verify/sign over WebCrypto. RS256 and ES256 only. */
import { fromBase64Url, own, toBase64Url, utf8, td } from '../../util/bytes.js';
import { KeyholdError } from '../../util/errors.js';

export type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

export interface Jwk extends JsonWebKey {
  kid?: string;
  alg?: string;
}

const ALGS = {
  RS256: { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verify: { name: 'RSASSA-PKCS1-v1_5' } },
  ES256: { import: { name: 'ECDSA', namedCurve: 'P-256' }, verify: { name: 'ECDSA', hash: 'SHA-256' } },
} as const;

type Alg = keyof typeof ALGS;

export interface DecodedJwt {
  header: { alg: string; kid?: string; typ?: string };
  payload: Record<string, unknown>;
}

export function decodeJwt(token: string): DecodedJwt & { signingInput: Uint8Array; signature: Uint8Array } {
  const parts = token.split('.');
  if (parts.length !== 3) throw new KeyholdError('auth_failed', 'malformed token');
  try {
    return {
      header: JSON.parse(td.decode(fromBase64Url(parts[0]!))),
      payload: JSON.parse(td.decode(fromBase64Url(parts[1]!))),
      signingInput: utf8(`${parts[0]}.${parts[1]}`),
      signature: fromBase64Url(parts[2]!),
    };
  } catch (e) {
    throw new KeyholdError('auth_failed', 'malformed token', { cause: e });
  }
}

/** Caches JWKS per URL for `ttlMs` (per isolate/process). Refetches once on an unknown kid. */
export class JwksCache {
  private cache = new Map<string, { at: number; keys: Jwk[] }>();
  constructor(private readonly ttlMs = 60 * 60 * 1000) {}

  async key(url: string, kid: string | undefined, fetchFn: FetchFn, now = Date.now()): Promise<Jwk> {
    let entry = this.cache.get(url);
    const find = () => entry?.keys.find((k) => (kid ? k.kid === kid : true));
    if (!entry || now - entry.at > this.ttlMs || !find()) {
      const res = await fetchFn(url);
      if (!res.ok) throw new KeyholdError('auth_failed', `could not fetch signing keys (${res.status})`);
      const body = (await res.json()) as { keys?: Jwk[] };
      entry = { at: now, keys: body.keys ?? [] };
      this.cache.set(url, entry);
    }
    const k = find();
    if (!k) throw new KeyholdError('auth_failed', 'token signed with an unknown key');
    return k;
  }
}

export const sharedJwks = new JwksCache();

export interface VerifyOptions {
  jwksUri: string;
  /** Accepted `iss` values. */
  issuers: string[];
  /** Accepted `aud` (your client id). */
  audience: string;
  /** Expected `nonce` claim, if you sent one. */
  nonce?: string;
  fetch?: FetchFn;
  jwks?: JwksCache;
  now?: number;
  /** Allowed clock skew, seconds. Default 60. */
  skew?: number;
}

export async function verifyJwt(token: string, opts: VerifyOptions): Promise<Record<string, unknown>> {
  const { header, payload, signingInput, signature } = decodeJwt(token);
  const alg = header.alg as Alg;
  if (!(alg in ALGS)) throw new KeyholdError('auth_failed', `unsupported token algorithm ${header.alg}`);
  const jwk = await (opts.jwks ?? sharedJwks).key(opts.jwksUri, header.kid, opts.fetch ?? fetch, opts.now);
  if (jwk.alg && jwk.alg !== alg) throw new KeyholdError('auth_failed', 'token algorithm does not match key');
  const { kid: _kid, alg: _alg, ...rawJwk } = jwk;
  const key = await crypto.subtle.importKey('jwk', rawJwk as JsonWebKey, ALGS[alg].import, false, ['verify']);
  const ok = await crypto.subtle.verify(ALGS[alg].verify, key, own(signature), own(signingInput));
  if (!ok) throw new KeyholdError('auth_failed', 'token signature is invalid');

  const now = Math.floor((opts.now ?? Date.now()) / 1000);
  const skew = opts.skew ?? 60;
  if (typeof payload.iss !== 'string' || !opts.issuers.includes(payload.iss)) throw new KeyholdError('auth_failed', 'token issuer mismatch');
  const aud = payload.aud;
  if (!(aud === opts.audience || (Array.isArray(aud) && aud.includes(opts.audience)))) throw new KeyholdError('auth_failed', 'token audience mismatch');
  if (typeof payload.exp !== 'number' || payload.exp + skew < now) throw new KeyholdError('auth_failed', 'token expired');
  if (typeof payload.iat === 'number' && payload.iat - skew > now) throw new KeyholdError('auth_failed', 'token issued in the future');
  if (opts.nonce !== undefined && payload.nonce !== opts.nonce) throw new KeyholdError('auth_failed', 'token nonce mismatch');
  if (typeof payload.sub !== 'string' || !payload.sub) throw new KeyholdError('auth_failed', 'token has no subject');
  return payload;
}

/** Sign an ES256 JWT (used for Apple's client secret). `pkcs8Pem` is the .p8 file's contents. */
export async function signEs256Jwt(header: Record<string, unknown>, payload: Record<string, unknown>, pkcs8Pem: string): Promise<string> {
  const der = fromBase64Url(
    pkcs8Pem
      .replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '')
      .replace(/\s+/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, ''),
  );
  const key = await crypto.subtle.importKey('pkcs8', der, ALGS.ES256.import, false, ['sign']);
  const input = `${toBase64Url(utf8(JSON.stringify({ alg: 'ES256', typ: 'JWT', ...header })))}.${toBase64Url(utf8(JSON.stringify(payload)))}`;
  const sig = await crypto.subtle.sign(ALGS.ES256.verify, key, utf8(input));
  return `${input}.${toBase64Url(new Uint8Array(sig))}`;
}
