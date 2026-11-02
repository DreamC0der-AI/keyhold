/**
 * keyhold/auth/server — server side of login (Workers, Node, Deno, Bun: anything with WebCrypto).
 * Each method returns an `Identity`. Sessions and the accounts table stay in your app.
 */
export * from './types.js';
export * from './server/jwt.js';
export * from './server/oidc.js';
export * from './server/email-code.js';
export * from './server/seed.js';
export * from './server/store.js';
export { KeyholdError, type KeyholdErrorCode } from '../util/errors.js';
