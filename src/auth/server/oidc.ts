/**
 * Google and Apple sign-in (OpenID Connect, authorization-code flow), runnable in a
 * Cloudflare Worker, Node or any WebCrypto runtime.
 *
 *   const { url, state } = await startLogin(provider, { redirectUri })
 *   // store `state` (state, nonce, codeVerifier) in a short-lived HttpOnly cookie, redirect to url
 *   // ... callback: GET ?code&state (Google) or POST form (Apple)
 *   const identity = await finishLogin(provider, { code, redirectUri, state: fromCookie, returnedState })
 *
 * Providers are plain config objects, so an app turns each one on or off from its environment.
 */
import { randomBytes, sha256, toBase64Url, utf8 } from '../../util/bytes.js';
import { KeyholdError } from '../../util/errors.js';
import { verifyJwt, signEs256Jwt, type FetchFn, type JwksCache } from './jwt.js';
import type { Identity } from '../types.js';

export interface OidcProvider {
  id: string;
  issuers: string[];
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  clientId: string;
  /** A fixed secret, or a function (Apple signs a fresh JWT). */
  clientSecret: string | (() => Promise<string>);
  scopes: string[];
  /** Apple needs 'form_post' when asking for name/email. */
  responseMode?: 'query' | 'form_post';
  /** Send a PKCE challenge. On for Google; off for Apple (not documented there). */
  pkce: boolean;
  extraAuthParams?: Record<string, string>;
  /** Turn verified claims into an Identity. */
  toIdentity(claims: Record<string, unknown>, extra: { appleUser?: AppleUserField }): Identity;
}

export interface LoginState {
  state: string;
  nonce: string;
  codeVerifier?: string;
}

export async function startLogin(
  provider: OidcProvider,
  input: { redirectUri: string; loginHint?: string; prompt?: string },
): Promise<{ url: string; state: LoginState }> {
  const state: LoginState = { state: toBase64Url(randomBytes(16)), nonce: toBase64Url(randomBytes(16)) };
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: provider.clientId,
    redirect_uri: input.redirectUri,
    scope: provider.scopes.join(' '),
    state: state.state,
    nonce: state.nonce,
    ...provider.extraAuthParams,
  });
  if (provider.responseMode) params.set('response_mode', provider.responseMode);
  if (input.loginHint) params.set('login_hint', input.loginHint);
  if (input.prompt) params.set('prompt', input.prompt);
  if (provider.pkce) {
    state.codeVerifier = toBase64Url(randomBytes(32));
    params.set('code_challenge', toBase64Url(await sha256(utf8(state.codeVerifier))));
    params.set('code_challenge_method', 'S256');
  }
  return { url: `${provider.authorizationEndpoint}?${params}`, state };
}

export async function finishLogin(
  provider: OidcProvider,
  input: {
    code: string;
    redirectUri: string;
    /** What you stored at start. */
    state: LoginState;
    /** The `state` the provider sent back. */
    returnedState: string;
    /** Apple form_post `user` field (JSON), sent only on the first sign-in. */
    appleUser?: string | null;
    fetch?: FetchFn;
    jwks?: JwksCache;
    now?: number;
  },
): Promise<Identity> {
  if (!input.returnedState || input.returnedState !== input.state.state) {
    throw new KeyholdError('auth_failed', 'login state mismatch; start the login again');
  }
  const f = input.fetch ?? fetch;
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: input.code,
    redirect_uri: input.redirectUri,
    client_id: provider.clientId,
    client_secret: typeof provider.clientSecret === 'string' ? provider.clientSecret : await provider.clientSecret(),
  });
  if (provider.pkce) {
    if (!input.state.codeVerifier) throw new KeyholdError('auth_failed', 'missing PKCE verifier');
    body.set('code_verifier', input.state.codeVerifier);
  }
  const res = await f(provider.tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body,
  });
  if (!res.ok) throw new KeyholdError('auth_failed', `${provider.id} token exchange failed (${res.status})`);
  const tokens = (await res.json()) as { id_token?: string };
  if (!tokens.id_token) throw new KeyholdError('auth_failed', `${provider.id} returned no id_token`);
  const claims = await verifyJwt(tokens.id_token, {
    jwksUri: provider.jwksUri,
    issuers: provider.issuers,
    audience: provider.clientId,
    nonce: input.state.nonce,
    fetch: f,
    jwks: input.jwks,
    now: input.now,
  });
  return provider.toIdentity(claims, { appleUser: parseAppleUser(input.appleUser) });
}

const truthy = (v: unknown) => v === true || v === 'true';

// ---- Google ------------------------------------------------------------------------------

export function googleProvider(cfg: { clientId: string; clientSecret: string; scopes?: string[] }): OidcProvider {
  return {
    id: 'google',
    issuers: ['https://accounts.google.com', 'accounts.google.com'],
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
    clientId: cfg.clientId,
    clientSecret: cfg.clientSecret,
    scopes: cfg.scopes ?? ['openid', 'email', 'profile'],
    pkce: true,
    toIdentity: (c) => ({
      provider: 'google',
      subject: c.sub as string,
      email: typeof c.email === 'string' ? c.email : undefined,
      emailVerified: truthy(c.email_verified),
      name: typeof c.name === 'string' ? c.name : undefined,
      picture: typeof c.picture === 'string' ? c.picture : undefined,
    }),
  };
}

// ---- Apple -------------------------------------------------------------------------------

export interface AppleConfig {
  /** Services ID, e.g. com.example.app.web. This is the web client id. */
  servicesId: string;
  teamId: string;
  keyId: string;
  /** Contents of the AuthKey_XXXX.p8 file. */
  privateKey: string;
  scopes?: string[];
}

export interface AppleUserField {
  name?: { firstName?: string; lastName?: string };
  email?: string;
}

export function parseAppleUser(raw: string | null | undefined): AppleUserField | undefined {
  if (!raw) return undefined;
  try {
    const v = JSON.parse(raw) as AppleUserField;
    return v && typeof v === 'object' ? v : undefined;
  } catch {
    return undefined;
  }
}

/** Apple's client secret is an ES256 JWT signed with your key, valid up to 6 months. Cached ~1 day. */
export function appleClientSecret(cfg: AppleConfig, ttlSeconds = 86400): () => Promise<string> {
  let cached: { jwt: string; exp: number } | undefined;
  return async () => {
    const now = Math.floor(Date.now() / 1000);
    if (cached && cached.exp - 300 > now) return cached.jwt;
    const exp = now + ttlSeconds;
    const jwt = await signEs256Jwt(
      { kid: cfg.keyId },
      { iss: cfg.teamId, iat: now, exp, aud: 'https://appleid.apple.com', sub: cfg.servicesId },
      cfg.privateKey,
    );
    cached = { jwt, exp };
    return jwt;
  };
}

export function appleProvider(cfg: AppleConfig): OidcProvider {
  return {
    id: 'apple',
    issuers: ['https://appleid.apple.com'],
    authorizationEndpoint: 'https://appleid.apple.com/auth/authorize',
    tokenEndpoint: 'https://appleid.apple.com/auth/token',
    jwksUri: 'https://appleid.apple.com/auth/keys',
    clientId: cfg.servicesId,
    clientSecret: appleClientSecret(cfg),
    scopes: cfg.scopes ?? ['name', 'email'],
    responseMode: 'form_post',
    pkce: false,
    toIdentity: (c, { appleUser }) => {
      const name = [appleUser?.name?.firstName, appleUser?.name?.lastName].filter(Boolean).join(' ') || undefined;
      return {
        provider: 'apple',
        subject: c.sub as string,
        email: typeof c.email === 'string' ? c.email : undefined,
        emailVerified: truthy(c.email_verified),
        privateEmail: truthy(c.is_private_email),
        name,
      };
    },
  };
}
