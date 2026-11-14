/**
 * Server side of password sign-in with OPAQUE (RFC 9807) and Hashcash PoW
 * (Stap 3). The password never reaches the server, not even as a hash: the
 * browser's crypto worker stretches it with Argon2id (64 MiB, 4 passes) inside
 * the pinned Wasm engine, and the server only ever sees OPAQUE messages.
 *
 * What the server holds:
 *   - the OPAQUE setup (OPRF seed + AKE key pair) only as an RVE1 envelope of
 *     kind opk, opened per request with the Master KEK (server-vault.server.ts)
 *     and wiped after use; a database dump alone cannot evaluate the OPRF, so it
 *     cannot run a dictionary attack against any record;
 *   - per account one 192-byte registration record, found by
 *     lookup = HMAC-SHA-256(K_lookup, normalized e-mail), never by the e-mail;
 *   - between the two login requests the server's KE2 state, sealed with
 *     XChaCha20-Poly1305 under K_state and bound to the handshake id and lookup.
 * K_lookup, K_cred, K_pow and K_state are HKDF-SHA-256 keys derived from the
 * setup, so they rotate with it and are as protected as it is.
 *
 * Unknown e-mail addresses run the RFC 9807 fake-record path with a credential
 * id derived from the lookup: the answer has the same shape and timing class
 * and is stable per address, so sign-in does not reveal who has a password.
 *
 * Every request first spends a one-time PoW challenge (db clock, 120 s); the
 * difficulty rises with failed handshakes for the same address and with load.
 * All state transitions are single SQL statements (pooled-connection safe).
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { OPAQUE_CONTEXT, OPAQUE_LEN, POW_NONCE_BYTES } from "@/lib/crypto-enclave/opaque-wire";
import type { VaultKek } from "@/lib/vault/server-kek";
import { openPakeSetup, sealPakeSetup } from "@/lib/vault/server-vault.server";
import { vaultPort, type AuthPowChallenge, type AuthPowPurpose, type IVaultPort, type PakeRegistrationWrite, type PasskeyStepUp, type VaultCaller } from "@/lib/vault/vault-port.server";

export type OpaqueDeps = {
  port?: IVaultPort;
  kek?: VaultKek;
  /** Test seam for the engine (defaults to the pinned Wasm engine). */
  engine?: typeof import("@/lib/crypto-enclave/opaque-engine");
};

export type OpaqueFailure =
  | "opaque_unavailable"
  | "pow_invalid"
  | "invalid_input"
  | "busy"
  | "auth_failed"
  | "registration_refused";

export class OpaqueServerError extends Error {
  constructor(readonly code: OpaqueFailure) {
    super(code);
    this.name = "OpaqueServerError";
  }
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const enc = new TextEncoder();
const SALT = enc.encode("rout.opaque.v1");
const NONCE_LEN = 24;

/** Lowercased and trimmed; null when it is not an address. */
export function normalizeEmail(email: unknown): string | null {
  if (typeof email !== "string") return null;
  const e = email.trim().toLowerCase();
  return e.length >= 3 && e.length <= 254 && EMAIL_RE.test(e) ? e : null;
}

// ---------------------------------------------------------------- base64url

export function b64u(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decodes base64url of exactly `len` bytes; throws invalid_input otherwise. */
export function fromB64u(text: unknown, len: number): Uint8Array {
  if (typeof text !== "string" || text.length > Math.ceil((len * 4) / 3) + 2 || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new OpaqueServerError("invalid_input");
  }
  let raw: string;
  try {
    raw = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
  } catch {
    throw new OpaqueServerError("invalid_input");
  }
  if (raw.length !== len) throw new OpaqueServerError("invalid_input");
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = raw.charCodeAt(i);
  return out;
}

// ---------------------------------------------------------------- setup keys

type SetupKeys = {
  kid: Uint8Array;
  setup: Uint8Array;
  lookup: (email: string) => Uint8Array;
  credentialId: (lookup: Uint8Array) => Uint8Array;
  powScope: (purpose: AuthPowPurpose, subject: string) => Uint8Array;
  sealState: (handshakeId: string, lookup: Uint8Array, state: Uint8Array) => Uint8Array;
  openState: (handshakeId: string, lookup: Uint8Array, sealed: Uint8Array) => Uint8Array | null;
  wipe: () => void;
};

function keysOf(kid: Uint8Array, setup: Uint8Array): SetupKeys {
  const derive = (info: string) => hkdf(sha256, setup, SALT, enc.encode(info), 32);
  const kLookup = derive("rout.opaque.lookup.v1");
  const kCred = derive("rout.opaque.credential-id.v1");
  const kPow = derive("rout.opaque.pow-scope.v1");
  const kState = derive("rout.opaque.ke2-state.v1");
  const aad = (id: string, lookup: Uint8Array) => {
    const out = new Uint8Array(36 + lookup.length);
    out.set(enc.encode(id));
    out.set(lookup, 36);
    return out;
  };
  return {
    kid,
    setup,
    lookup: (email) => hmac(sha256, kLookup, enc.encode(`email:${email}`)),
    credentialId: (lookup) => hmac(sha256, kCred, lookup),
    // Login uses the lookup itself as scope, so failed handshakes raise its difficulty.
    powScope: (purpose, subject) =>
      purpose === "opaque_login" ? hmac(sha256, kLookup, enc.encode(`email:${subject}`)) : hmac(sha256, kPow, enc.encode(`${purpose}:${subject}`)),
    sealState: (id, lookup, state) => {
      const nonce = randomBytes(NONCE_LEN);
      const body = xchacha20poly1305(kState, nonce, aad(id, lookup)).encrypt(state);
      const out = new Uint8Array(NONCE_LEN + body.length);
      out.set(nonce);
      out.set(body, NONCE_LEN);
      return out;
    },
    openState: (id, lookup, sealed) => {
      try {
        return xchacha20poly1305(kState, sealed.subarray(0, NONCE_LEN), aad(id, lookup)).decrypt(sealed.subarray(NONCE_LEN));
      } catch {
        return null;
      }
    },
    wipe: () => {
      for (const k of [kLookup, kCred, kPow, kState, setup]) k.fill(0);
    },
  };
}

async function engineOf(deps: OpaqueDeps) {
  return deps.engine ?? (await import("@/lib/crypto-enclave/opaque-engine"));
}

/** Opens the active setup for one request; null when none exists yet. */
async function withSetup<T>(deps: OpaqueDeps, create: VaultCaller | null, use: (k: SetupKeys) => Promise<T>): Promise<T> {
  const port = deps.port ?? vaultPort();
  if (!(await port.pakeAvailable())) throw new OpaqueServerError("opaque_unavailable");
  let active = await port.activePakeSetup();
  if (!active && create) {
    const engine = await engineOf(deps);
    const fresh = await engine.serverSetupNew();
    try {
      const sealed = await sealPakeSetup(create, fresh, { port, kek: deps.kek });
      // First writer wins; a concurrent request's setup is then the active one.
      await port.registerPakeSetup(create, sealed);
    } finally {
      fresh.fill(0);
    }
    active = await port.activePakeSetup();
  }
  if (!active) throw new OpaqueServerError("opaque_unavailable");
  let setup: Uint8Array;
  try {
    setup = await openPakeSetup(active.envelope, { port, kek: deps.kek });
  } catch {
    throw new OpaqueServerError("opaque_unavailable");
  }
  const keys = keysOf(active.kid, setup);
  try {
    return await use(keys);
  } finally {
    keys.wipe();
  }
}

// ---------------------------------------------------------------- proof-of-work

export type PowAnswer = { id: string; nonce: string };

function powWire(c: AuthPowChallenge) {
  return { id: c.id, challenge: b64u(c.challenge), bits: c.bits, expiresAt: c.expiresAt };
}
export type PowWire = ReturnType<typeof powWire>;

/** One-time challenge for `purpose`; subject is the e-mail (login/signup) or the member id (register). */
export async function issuePow(purpose: AuthPowPurpose, subject: string, deps: OpaqueDeps = {}, create: VaultCaller | null = null): Promise<PowWire> {
  const port = deps.port ?? vaultPort();
  return withSetup(deps, create, async (k) => {
    const challenge = await port.issueAuthPow(purpose, k.powScope(purpose, subject));
    if (!challenge) throw new OpaqueServerError("invalid_input");
    return powWire(challenge);
  });
}

async function spendPow(port: IVaultPort, k: SetupKeys, purpose: AuthPowPurpose, subject: string, pow: unknown): Promise<void> {
  const p = pow as Partial<PowAnswer> | null;
  if (!p || typeof p.id !== "string" || !UUID_RE.test(p.id)) throw new OpaqueServerError("pow_invalid");
  let nonce: Uint8Array;
  try {
    nonce = fromB64u(p.nonce, POW_NONCE_BYTES);
  } catch {
    throw new OpaqueServerError("pow_invalid");
  }
  if (!(await port.consumeAuthPow(p.id, nonce, purpose, k.powScope(purpose, subject)))) throw new OpaqueServerError("pow_invalid");
}

// ---------------------------------------------------------------- login

/** KE1 -> KE2 plus a one-time handshake id. Unknown addresses get a fake but stable KE2. */
export async function loginStart(input: { email: unknown; pow: unknown; ke1: unknown }, deps: OpaqueDeps = {}): Promise<{ handshake: string; ke2: string }> {
  const email = normalizeEmail(input.email);
  if (!email) throw new OpaqueServerError("invalid_input");
  const ke1 = fromB64u(input.ke1, OPAQUE_LEN.ke1);
  const port = deps.port ?? vaultPort();
  return withSetup(deps, null, async (k) => {
    await spendPow(port, k, "opaque_login", email, input.pow);
    const lookup = k.lookup(email);
    const reg = await port.pakeRegistrationForLogin(lookup);
    const usable = reg && reg.setupKid.length === k.kid.length && reg.setupKid.every((b, i) => b === k.kid[i]) ? reg : null;
    const engine = await engineOf(deps);
    let started: { ke2: Uint8Array; state: Uint8Array } | null = null;
    try {
      started = await engine.serverLoginStart(k.setup, usable?.record ?? null, ke1, usable?.credentialId ?? k.credentialId(lookup), OPAQUE_CONTEXT);
    } catch {
      throw new OpaqueServerError("invalid_input");
    }
    const handshake = crypto.randomUUID();
    try {
      const sealed = k.sealState(handshake, lookup, started.state);
      if (!(await port.beginPakeLogin(handshake, lookup, sealed))) throw new OpaqueServerError("busy");
      return { handshake, ke2: b64u(started.ke2) };
    } finally {
      started.state.fill(0);
    }
  });
}

/** KE3 -> the Better Auth identity, once per handshake; null for a wrong password or an unknown address. */
export async function loginFinish(input: { handshake: unknown; ke3: unknown }, deps: OpaqueDeps = {}): Promise<string | null> {
  if (typeof input.handshake !== "string" || !UUID_RE.test(input.handshake)) throw new OpaqueServerError("invalid_input");
  const handshake = input.handshake;
  const ke3 = fromB64u(input.ke3, OPAQUE_LEN.ke3);
  const port = deps.port ?? vaultPort();
  return withSetup(deps, null, async (k) => {
    const claimed = await port.claimPakeLogin(handshake);
    if (!claimed) return null;
    const state = k.openState(handshake, claimed.lookup, claimed.stateSealed);
    if (!state) {
      await port.denyPakeLogin(handshake);
      return null;
    }
    const engine = await engineOf(deps);
    try {
      const sessionKey = await engine.serverLoginFinish(state, ke3, OPAQUE_CONTEXT);
      // ROUT issues its own session cookie; the OPAQUE session key only proves the password.
      sessionKey.fill(0);
    } catch {
      await port.denyPakeLogin(handshake);
      return null;
    } finally {
      state.fill(0);
    }
    return port.grantPakeLogin(handshake);
  });
}

// ---------------------------------------------------------------- registration

export type RegistrationKind =
  | { kind: "member"; caller: VaultCaller; stepUp: PasskeyStepUp }
  | { kind: "signup"; caller: VaultCaller };

/** Registration request -> response. `subject` is the PoW subject (member id or e-mail). */
export async function registerStart(
  input: { email: string; request: unknown; pow: unknown },
  purpose: "opaque_register" | "opaque_signup",
  subject: string,
  creator: VaultCaller,
  deps: OpaqueDeps = {},
): Promise<{ response: string }> {
  const email = normalizeEmail(input.email);
  if (!email) throw new OpaqueServerError("invalid_input");
  const request = fromB64u(input.request, OPAQUE_LEN.registrationRequest);
  const port = deps.port ?? vaultPort();
  return withSetup(deps, creator, async (k) => {
    await spendPow(port, k, purpose, subject, input.pow);
    const engine = await engineOf(deps);
    try {
      const response = await engine.serverRegisterStart(k.setup, request, k.credentialId(k.lookup(email)));
      return { response: b64u(response) };
    } catch {
      throw new OpaqueServerError("invalid_input");
    }
  });
}

/** Validates the upload (every point decodes) and returns what to store; stores nothing. */
export async function buildRegistration(input: { email: string; upload: unknown }, deps: OpaqueDeps = {}): Promise<PakeRegistrationWrite> {
  const email = normalizeEmail(input.email);
  if (!email) throw new OpaqueServerError("invalid_input");
  const upload = fromB64u(input.upload, OPAQUE_LEN.registrationUpload);
  return withSetup(deps, null, async (k) => {
    const engine = await engineOf(deps);
    let record: Uint8Array;
    try {
      record = await engine.serverRegisterFinish(upload);
    } catch {
      throw new OpaqueServerError("invalid_input");
    }
    const lookup = k.lookup(email);
    return { lookup, credentialId: k.credentialId(lookup), record, setupKid: k.kid.slice() };
  });
}

/** Stores a built registration for the member (passkey proof) or the fresh sign-up identity. */
export async function storeRegistration(reg: PakeRegistrationWrite, who: RegistrationKind, deps: OpaqueDeps = {}): Promise<void> {
  const port = deps.port ?? vaultPort();
  const ok = who.kind === "member" ? await port.storePakeRegistration(who.caller, reg, who.stepUp) : await port.storePakeSignupRegistration(who.caller, reg);
  if (!ok) throw new OpaqueServerError("registration_refused");
}

/** buildRegistration + storeRegistration. */
export async function registerFinish(input: { email: string; upload: unknown }, who: RegistrationKind, deps: OpaqueDeps = {}): Promise<void> {
  await storeRegistration(await buildRegistration(input, deps), who, deps);
}

/** True once an OPAQUE setup exists (needed before a password sign-up can start). */
export async function opaqueSetupReady(deps: OpaqueDeps = {}): Promise<boolean> {
  try {
    const port = deps.port ?? vaultPort();
    return (await port.pakeAvailable()) && (await port.activePakeSetup()) !== null;
  } catch {
    return false;
  }
}

/** Whether password sign-in can be offered (schema live). Never throws. */
export async function opaqueAvailable(deps: OpaqueDeps = {}): Promise<boolean> {
  try {
    return await (deps.port ?? vaultPort()).pakeAvailable();
  } catch {
    return false;
  }
}
