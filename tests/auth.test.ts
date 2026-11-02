import { describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { seedLogin } from '../src/auth/index.js';
import {
  issueSeedChallenge,
  verifySeedLogin,
  sendEmailCode,
  verifyEmailCode,
  MemoryTokenStore,
  D1TokenStore,
  D1_TOKEN_TABLE_SQL,
  googleProvider,
  appleProvider,
  startLogin,
  finishLogin,
  JwksCache,
  decodeJwt,
  type D1Like,
  type EmailCodeConfig,
  type TokenStore,
} from '../src/auth/server.js';
import { generateSeedPhrase } from '../src/seed/index.js';
import { KeyEditor, unlockWithRecovery } from '../src/keys/index.js';
import { toBase64Url, utf8 } from '../src/util/bytes.js';

const ORIGIN = 'https://notes.example.com';

describe('seed-phrase login', () => {
  it('signs up, logs in from the phrase alone, and the same phrase recovers the notes key', async () => {
    const store = new MemoryTokenStore();
    const phrase = generateSeedPhrase();
    const { identity, recoverySecret } = await seedLogin(phrase);
    const editor = await KeyEditor.create(identity.publicKey);
    const env = await editor.addSeedRecovery(recoverySecret);

    // New device: only the phrase.
    const again = await seedLogin(phrase);
    expect(again.identity.publicKey).toBe(identity.publicKey);
    const challenge = await issueSeedChallenge({ store, origin: ORIGIN });
    const signature = again.identity.signChallenge(challenge, ORIGIN);
    const who = await verifySeedLogin({ store, origin: ORIGIN }, { challengeId: challenge.id, publicKey: again.identity.publicKey, signature });
    expect(who).toEqual({ provider: 'seed', subject: identity.publicKey });
    await expect(unlockWithRecovery([env], again.recoverySecret)).resolves.toBeTruthy();

    // Single use.
    await expect(
      verifySeedLogin({ store, origin: ORIGIN }, { challengeId: challenge.id, publicKey: again.identity.publicKey, signature }),
    ).rejects.toMatchObject({ code: 'code_expired' });
  });

  it('rejects another key, and the browser refuses to sign for a different site', async () => {
    const store = new MemoryTokenStore();
    const me = (await seedLogin(generateSeedPhrase())).identity;
    const other = (await seedLogin(generateSeedPhrase())).identity;
    const c = await issueSeedChallenge({ store, origin: ORIGIN });
    const sig = other.signChallenge(c, ORIGIN);
    await expect(verifySeedLogin({ store, origin: ORIGIN }, { challengeId: c.id, publicKey: me.publicKey, signature: sig })).rejects.toMatchObject({
      code: 'auth_failed',
    });
    const phishing = await issueSeedChallenge({ store, origin: 'https://evil.example' });
    expect(() => me.signChallenge(phishing, ORIGIN)).toThrow(/refusing/);
    me.destroy();
    expect(() => me.signChallenge(c, ORIGIN)).toThrow();
  });

  it('expired challenges fail', async () => {
    let now = 1_000_000;
    const store = new MemoryTokenStore(() => now);
    const me = (await seedLogin(generateSeedPhrase())).identity;
    const c = await issueSeedChallenge({ store, origin: ORIGIN, now: () => now });
    now += 6 * 60_000;
    expect(() => me.signChallenge(c, ORIGIN, now)).toThrow();
    const sig = me.signChallenge(c, ORIGIN, c.expiresAt - 1);
    await expect(
      verifySeedLogin({ store, origin: ORIGIN, now: () => now }, { challengeId: c.id, publicKey: me.publicKey, signature: sig }),
    ).rejects.toMatchObject({ code: 'code_expired' });
  });
});

function emailCfg(now: { t: number }, store: TokenStore = new MemoryTokenStore(() => now.t)) {
  const outbox: { to: string; code: string }[] = [];
  const cfg: EmailCodeConfig = {
    store,
    secret: 'test-secret-test-secret-test-secret',
    sender: { send: async (m) => void outbox.push(m) },
    now: () => now.t,
  };
  return { cfg, outbox };
}

describe('email code login', () => {
  it('sends a 6-digit code and accepts it once', async () => {
    const now = { t: 1_000_000 };
    const { cfg, outbox } = emailCfg(now);
    await sendEmailCode(cfg, ' Me@Example.com ');
    expect(outbox[0]!.to).toBe('me@example.com');
    expect(outbox[0]!.code).toMatch(/^\d{6}$/);
    const id = await verifyEmailCode(cfg, 'me@example.com', outbox[0]!.code.replace(/(\d{3})/, '$1 '));
    expect(id).toEqual({ provider: 'email', subject: 'me@example.com', email: 'me@example.com', emailVerified: true });
    await expect(verifyEmailCode(cfg, 'me@example.com', outbox[0]!.code)).rejects.toMatchObject({ code: 'code_expired' });
  });

  it('limits wrong tries, expires after 10 minutes and rate-limits resends', async () => {
    const now = { t: 1_000_000 };
    const { cfg, outbox } = emailCfg(now);
    await sendEmailCode(cfg, 'me@example.com');
    await expect(sendEmailCode(cfg, 'me@example.com')).rejects.toMatchObject({ code: 'too_many_attempts' });
    const wrong = outbox[0]!.code === '000000' ? '111111' : '000000';
    for (let i = 0; i < 5; i++) await expect(verifyEmailCode(cfg, 'me@example.com', wrong)).rejects.toMatchObject({ code: 'auth_failed' });
    await expect(verifyEmailCode(cfg, 'me@example.com', outbox[0]!.code)).rejects.toMatchObject({ code: 'too_many_attempts' });

    now.t += 60_000;
    await sendEmailCode(cfg, 'me@example.com');
    now.t += 11 * 60_000;
    await expect(verifyEmailCode(cfg, 'me@example.com', outbox[1]!.code)).rejects.toMatchObject({ code: 'code_expired' });
  });

  it('only stores an HMAC of the code', async () => {
    const now = { t: 1_000_000 };
    const store = new MemoryTokenStore(() => now.t);
    const { cfg, outbox } = emailCfg(now, store);
    await sendEmailCode(cfg, 'me@example.com');
    const raw = await store.get('email-code:me@example.com');
    expect(raw).not.toContain(outbox[0]!.code);
  });

  it('works on a D1-compatible SQL store', async () => {
    const db = new DatabaseSync(':memory:');
    db.exec(D1_TOKEN_TABLE_SQL);
    const d1: D1Like = {
      prepare(sql) {
        const st = db.prepare(sql.replace(/\?(\d+)/g, '?'));
        return {
          bind: (...v: unknown[]) => ({
            first: async <T>() => (st.get(...(v as never[])) as T) ?? null,
            run: async () => st.run(...(v as never[])),
          }),
        };
      },
    };
    const now = { t: 1_000_000 };
    const { cfg, outbox } = emailCfg(now, new D1TokenStore(d1, 'keyhold_tokens', () => now.t));
    await sendEmailCode(cfg, 'me@example.com');
    await expect(verifyEmailCode(cfg, 'me@example.com', '12345')).rejects.toMatchObject({ code: 'auth_failed' });
    await expect(verifyEmailCode(cfg, 'me@example.com', outbox[0]!.code)).resolves.toMatchObject({ subject: 'me@example.com' });
    expect(db.prepare('SELECT count(*) AS n FROM keyhold_tokens').get()).toEqual({ n: 0 });
  });
});

// ---- OIDC with a fake provider ---------------------------------------------------------------

async function fakeIdp(alg: 'RS256' | 'ES256') {
  const params = alg === 'RS256'
    ? { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }
    : { name: 'ECDSA', namedCurve: 'P-256' };
  const pair = (await crypto.subtle.generateKey(params, true, ['sign', 'verify'])) as CryptoKeyPair;
  const jwk = { ...(await crypto.subtle.exportKey('jwk', pair.publicKey)), kid: 'k1', alg };
  async function sign(payload: Record<string, unknown>) {
    const input = `${toBase64Url(utf8(JSON.stringify({ alg, kid: 'k1', typ: 'JWT' })))}.${toBase64Url(utf8(JSON.stringify(payload)))}`;
    const sig = await crypto.subtle.sign(alg === 'RS256' ? 'RSASSA-PKCS1-v1_5' : { name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, utf8(input));
    return `${input}.${toBase64Url(new Uint8Array(sig))}`;
  }
  return { jwk, sign };
}

async function applePem() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const b64 = Buffer.from(der).toString('base64');
  return { pem: `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----\n`, pub: pair.publicKey };
}

describe('Google and Apple sign-in', () => {
  it('Google: PKCE + nonce, verifies the id_token and returns the identity', async () => {
    const idp = await fakeIdp('RS256');
    const google = googleProvider({ clientId: 'cid.apps.googleusercontent.com', clientSecret: 'shh' });
    const { url, state } = await startLogin(google, { redirectUri: `${ORIGIN}/api/auth/google/callback` });
    const u = new URL(url);
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('nonce')).toBe(state.nonce);

    let tokenBody: URLSearchParams | undefined;
    const fetchFn = async (input: string, init?: RequestInit) => {
      if (input === google.jwksUri) return Response.json({ keys: [idp.jwk] });
      if (input === google.tokenEndpoint) {
        tokenBody = init!.body as URLSearchParams;
        const now = Math.floor(Date.now() / 1000);
        return Response.json({
          id_token: await idp.sign({
            iss: 'https://accounts.google.com', aud: google.clientId, sub: '1234', email: 'me@gmail.com',
            email_verified: true, name: 'Me', iat: now, exp: now + 3600, nonce: state.nonce,
          }),
        });
      }
      return new Response('nope', { status: 404 });
    };
    const id = await finishLogin(google, {
      code: 'abc', redirectUri: `${ORIGIN}/api/auth/google/callback`, state, returnedState: state.state, fetch: fetchFn, jwks: new JwksCache(),
    });
    expect(id).toMatchObject({ provider: 'google', subject: '1234', email: 'me@gmail.com', emailVerified: true, name: 'Me' });
    expect(tokenBody!.get('code_verifier')).toBe(state.codeVerifier);

    await expect(
      finishLogin(google, { code: 'abc', redirectUri: 'x', state, returnedState: 'forged', fetch: fetchFn }),
    ).rejects.toMatchObject({ code: 'auth_failed' });
  });

  it('rejects a token for another client, a bad nonce, an expired token and a forged signature', async () => {
    const idp = await fakeIdp('RS256');
    const evil = await fakeIdp('RS256');
    const google = googleProvider({ clientId: 'cid', clientSecret: 'shh' });
    const { state } = await startLogin(google, { redirectUri: 'r' });
    const now = Math.floor(Date.now() / 1000);
    const good = { iss: 'accounts.google.com', aud: 'cid', sub: '1', iat: now, exp: now + 60, nonce: state.nonce };
    const cases: [Record<string, unknown>, typeof idp][] = [
      [{ ...good, aud: 'other' }, idp],
      [{ ...good, nonce: 'x' }, idp],
      [{ ...good, exp: now - 3600 }, idp],
      [{ ...good, iss: 'https://evil.example' }, idp],
      [good, evil],
    ];
    for (const [claims, signer] of cases) {
      const token = await signer.sign(claims);
      const fetchFn = async (input: string) =>
        input === google.jwksUri ? Response.json({ keys: [idp.jwk] }) : Response.json({ id_token: token });
      await expect(
        finishLogin(google, { code: 'c', redirectUri: 'r', state, returnedState: state.state, fetch: fetchFn, jwks: new JwksCache() }),
      ).rejects.toMatchObject({ code: 'auth_failed' });
    }
  });

  it('Apple: signs the client secret with the .p8 key, reads the first-login name and private relay flag', async () => {
    const idp = await fakeIdp('RS256');
    const { pem, pub } = await applePem();
    const apple = appleProvider({ servicesId: 'com.example.web', teamId: 'TEAM123', keyId: 'KEY123', privateKey: pem });
    const { url, state } = await startLogin(apple, { redirectUri: `${ORIGIN}/api/auth/apple/callback` });
    expect(new URL(url).searchParams.get('response_mode')).toBe('form_post');
    expect(new URL(url).searchParams.get('code_challenge')).toBeNull();

    let secret = '';
    const fetchFn = async (input: string, init?: RequestInit) => {
      if (input === apple.jwksUri) return Response.json({ keys: [idp.jwk] });
      secret = (init!.body as URLSearchParams).get('client_secret')!;
      const now = Math.floor(Date.now() / 1000);
      return Response.json({
        id_token: await idp.sign({
          iss: 'https://appleid.apple.com', aud: 'com.example.web', sub: '001.abc', email: 'x@privaterelay.appleid.com',
          email_verified: 'true', is_private_email: 'true', iat: now, exp: now + 600, nonce: state.nonce,
        }),
      });
    };
    const id = await finishLogin(apple, {
      code: 'c', redirectUri: 'r', state, returnedState: state.state, fetch: fetchFn, jwks: new JwksCache(),
      appleUser: JSON.stringify({ name: { firstName: 'Ada', lastName: 'L' }, email: 'x@privaterelay.appleid.com' }),
    });
    expect(id).toMatchObject({ provider: 'apple', subject: '001.abc', privateEmail: true, emailVerified: true, name: 'Ada L' });

    const jwt = decodeJwt(secret);
    expect(jwt.header).toMatchObject({ alg: 'ES256', kid: 'KEY123' });
    expect(jwt.payload).toMatchObject({ iss: 'TEAM123', sub: 'com.example.web', aud: 'https://appleid.apple.com' });
    expect(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, jwt.signature as Uint8Array<ArrayBuffer>, jwt.signingInput as Uint8Array<ArrayBuffer>)).toBe(true);
  });

  it('ES256 id_tokens verify too', async () => {
    const idp = await fakeIdp('ES256');
    const google = googleProvider({ clientId: 'cid', clientSecret: 's' });
    const { state } = await startLogin(google, { redirectUri: 'r' });
    const now = Math.floor(Date.now() / 1000);
    const token = await idp.sign({ iss: 'accounts.google.com', aud: 'cid', sub: '9', iat: now, exp: now + 60, nonce: state.nonce });
    const fetchFn = async (input: string) => (input === google.jwksUri ? Response.json({ keys: [idp.jwk] }) : Response.json({ id_token: token }));
    await expect(finishLogin(google, { code: 'c', redirectUri: 'r', state, returnedState: state.state, fetch: fetchFn, jwks: new JwksCache() })).resolves.toMatchObject({ subject: '9' });
  });
});
