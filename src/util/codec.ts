/** JSON <-> bytes with a stable key order, plus base64url fields. Used for signed structures. */
import { fromBase64Url, td, toBase64Url, utf8 } from './bytes.js';
import { KeyholdError } from './errors.js';

/** Deterministic JSON: object keys sorted, no whitespace. Only plain JSON values. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new KeyholdError('config', 'non-finite number');
    return JSON.stringify(value);
  }
  // Array.from visits holes too (as undefined), which JSON writes as null, like JSON.stringify.
  if (Array.isArray(value)) return '[' + Array.from(value, (x) => canonicalJson(x === undefined ? null : x)).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

export function jsonBytes(value: unknown): Uint8Array<ArrayBuffer> {
  return utf8(canonicalJson(value));
}

export function parseJsonBytes<T>(b: Uint8Array, what = 'data'): T {
  try {
    return JSON.parse(td.decode(b)) as T;
  } catch (e) {
    throw new KeyholdError('bad_format', `${what} is not valid JSON`, { cause: e });
  }
}

export const b64 = toBase64Url;
export const unb64 = fromBase64Url;
