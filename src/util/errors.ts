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
  | 'config'
  // storage and chat
  | 'forbidden' // the storage refused this caller (access rule of the storage kind)
  | 'conflict' // a compare-and-swap write lost a race; re-read and retry
  | 'not_found'
  | 'unsupported' // the storage provider lacks a capability this feature needs
  | 'rewrite_detected' // a hash-chained log or directory was rewritten
  | 'key_changed' // a contact's root identity key differs from the pinned one
  | 'bad_signature'
  | 'policy_rejected' // the group policy forbids this change
  | 'not_member'
  | 'expired';
