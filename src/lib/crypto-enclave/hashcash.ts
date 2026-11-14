/**
 * Hashcash proof-of-work used before every OPAQUE handshake.
 *
 *   digest = SHA-256("rout.pow.v1" || challenge(32) || nonce(8, little endian))
 *   valid  = digest starts with `bits` zero bits
 *
 * The server issues one-time challenges with a strict TTL and verifies in SQL
 * (vault_enclave.auth_pow_consume, db-pending/0270), so the database clock and
 * the spent flag decide. This module solves in the crypto worker and verifies
 * in tests; it never touches a secret.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { POW_CHALLENGE_BYTES, POW_LABEL, POW_MAX_BITS, POW_MIN_BITS, POW_NONCE_BYTES } from "./opaque-wire";

const LABEL = new TextEncoder().encode(POW_LABEL);

export class PowError extends Error {
  constructor(code: "pow_invalid" | "pow_aborted" | "pow_exhausted") {
    super(code);
    this.name = "PowError";
  }
}

export function leadingZeroBits(digest: Uint8Array): number {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

function preimage(challenge: Uint8Array): Uint8Array {
  if (challenge.length !== POW_CHALLENGE_BYTES) throw new PowError("pow_invalid");
  const buf = new Uint8Array(LABEL.length + POW_CHALLENGE_BYTES + POW_NONCE_BYTES);
  buf.set(LABEL);
  buf.set(challenge, LABEL.length);
  return buf;
}

export function powDigest(challenge: Uint8Array, nonce: Uint8Array): Uint8Array {
  if (nonce.length !== POW_NONCE_BYTES) throw new PowError("pow_invalid");
  const buf = preimage(challenge);
  buf.set(nonce, LABEL.length + POW_CHALLENGE_BYTES);
  return sha256(buf);
}

export function verifyPow(challenge: Uint8Array, nonce: Uint8Array, bits: number): boolean {
  if (!Number.isInteger(bits) || bits < 0 || bits > 64) return false;
  try {
    return leadingZeroBits(powDigest(challenge, nonce)) >= bits;
  } catch {
    return false;
  }
}

export function isPowBits(bits: unknown): bits is number {
  return typeof bits === "number" && Number.isInteger(bits) && bits >= POW_MIN_BITS && bits <= POW_MAX_BITS;
}

/**
 * Tries `count` consecutive nonces from `startAt`; returns the first that meets
 * `bits`, or null. Callers loop over batches (the worker yields between them so
 * an abort can arrive, H.1).
 */
export function searchPow(challenge: Uint8Array, bits: number, startAt: number, count: number): Uint8Array | null {
  if (!Number.isInteger(bits) || bits < 1 || bits > POW_MAX_BITS) throw new PowError("pow_invalid");
  const buf = preimage(challenge);
  const view = new DataView(buf.buffer, LABEL.length + POW_CHALLENGE_BYTES, POW_NONCE_BYTES);
  for (let i = 0, counter = startAt; i < count; i++, counter++) {
    view.setUint32(0, counter >>> 0, true);
    view.setUint32(4, Math.floor(counter / 2 ** 32) >>> 0, true);
    if (leadingZeroBits(sha256(buf)) >= bits) return buf.slice(LABEL.length + POW_CHALLENGE_BYTES);
  }
  return null;
}

/** Synchronous solver (tests, tools). Gives up after 2^(bits+6) attempts. */
export function solvePow(challenge: Uint8Array, bits: number, minBits = POW_MIN_BITS): Uint8Array {
  if (!Number.isInteger(bits) || bits < minBits || bits > POW_MAX_BITS) throw new PowError("pow_invalid");
  const hit = searchPow(challenge, bits, 0, 2 ** (bits + 6));
  if (!hit) throw new PowError("pow_exhausted");
  return hit;
}
