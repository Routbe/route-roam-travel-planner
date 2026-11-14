/**
 * Shared constants of the ROUT password engine (OPAQUE, RFC 9807, suite
 * ristretto255 + SHA-512 + 3DH, KSF Argon2id RFC 9106). Imported by the crypto
 * worker, the server and the tests; contains no secrets and no crypto code.
 */

/** Owner floor (Stap 3): Argon2id with at least 64 MiB and 4 passes. Enforced inside the Wasm too. */
export const OPAQUE_KSF = Object.freeze({ mKiB: 65_536, t: 4, p: 1 });

/** Bound into every login transcript (RFC 9807 `context`), on both sides. */
export const OPAQUE_CONTEXT = "rout.opaque.v1";

export const OPAQUE_LEN = Object.freeze({
  registrationRequest: 32,
  registrationResponse: 64,
  registrationUpload: 192,
  record: 192,
  ke1: 96,
  ke2: 320,
  ke3: 64,
  sessionKey: 64,
  exportKey: 64,
  publicKey: 32,
  stateMax: 512,
});

/** Fixed linear memory per operation (64 KiB pages): initial == maximum, never grown. */
export const ENGINE_PAGES = Object.freeze({
  /** Protocol steps without key stretching (starts, all server steps). */
  small: 32,
  /** Steps that run Argon2id over 64 MiB: the client's finishes. */
  ksf: 1088,
});

/** Paranoid password input: bytes per slot (UTF-8), held only in a fixed Wasm memory. */
export const PASSWORD_MAX_BYTES = 1024;
export const PASSWORD_MIN_CHARS = 12;

/** Hashcash: SHA-256(label || challenge(32) || nonce(8)) must start with `bits` zero bits. */
export const POW_LABEL = "rout.pow.v1";
export const POW_CHALLENGE_BYTES = 32;
export const POW_NONCE_BYTES = 8;
export const POW_MIN_BITS = 16;
export const POW_MAX_BITS = 26;
