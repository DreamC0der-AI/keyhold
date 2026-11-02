/** Every error keyhold throws on purpose. `code` is stable; the message is for humans. */
export class KeyholdError extends Error {
  readonly code: KeyholdErrorCode;
  constructor(code: KeyholdErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'KeyholdError';
    this.code = code;
  }
}

export type KeyholdErrorCode =
  | 'bad_format' // input is not something keyhold produced
  | 'unsupported_version'
  | 'decrypt_failed' // wrong key, wrong context, or tampered data
  | 'wrong_secret' // the passkey/password/recovery code did not open the envelope
  | 'prf_unavailable' // the authenticator or browser can't do WebAuthn PRF
  | 'weak_password'
  | 'bad_recovery_code'
  | 'bad_mnemonic'
  | 'approval_failed'
  | 'auth_failed'
  | 'code_expired'
  | 'too_many_attempts'
  | 'config';
