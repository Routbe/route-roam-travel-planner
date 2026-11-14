/**
 * Host side of the ROUT password engine (wasm/rout-opaque): OPAQUE (RFC 9807,
 * opaque-ke 4.0.1, ristretto255 + SHA-512 + 3DH) with Argon2id as KSF.
 *
 * Runs in the crypto worker (client steps) and in server-only handlers
 * (server steps); never on the UI thread.
 *
 * Memory discipline (owner rules H.1, I.6, F.2):
 *   - the module bytes are checked against the pinned SHA-384 before compiling;
 *   - every operation gets its own WebAssembly.Memory with initial == maximum
 *     (the module has no allocator and no memory.grow);
 *   - inputs are copied in, outputs copied out, and the whole linear memory is
 *     zero-filled in `finally`, on success, error and trap alike;
 *   - `wipeEngineMemory()` zero-fills every memory still alive (teardown).
 * Inputs stay owned (and wiped) by the caller; outputs are the caller's to wipe.
 */
import { sha384 } from "@noble/hashes/sha2.js";
import { ROUT_OPAQUE_WASM_SHA384 } from "./opaque-wasm-pin";
import { ENGINE_PAGES, OPAQUE_KSF, OPAQUE_LEN } from "./opaque-wire";

export type KsfParams = { mKiB: number; t: number; p: number };

export class OpaqueEngineError extends Error {
  constructor(readonly code: "opaque_engine_unavailable" | "opaque_engine_integrity" | "opaque_invalid_input" | "opaque_auth_failed" | "opaque_ksf_refused") {
    super(code);
    this.name = "OpaqueEngineError";
  }
}

type Exports = {
  rout_abi_version(): number;
  rout_heap_base(): number;
  rout_len(which: number): number;
  rout_argon2id(...a: number[]): number;
  rout_client_register_start(...a: number[]): number;
  rout_client_register_finish(...a: number[]): number;
  rout_client_login_start(...a: number[]): number;
  rout_client_login_finish(...a: number[]): number;
  rout_server_setup_new(...a: number[]): number;
  rout_server_public_key(...a: number[]): number;
  rout_server_register_start(...a: number[]): number;
  rout_server_register_finish(...a: number[]): number;
  rout_server_login_start(...a: number[]): number;
  rout_server_login_finish(...a: number[]): number;
};

const PAGE = 65_536;
const SCRATCH = 64 * 1024;
const BLOCK_ALIGN = 1024;

let compiled: Promise<WebAssembly.Module> | null = null;
const live = new Set<WebAssembly.Memory>();

function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function decodeBase64(text: string): Uint8Array {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/** Verifies the pinned SHA-384, then compiles once per context. */
export function engineModule(): Promise<WebAssembly.Module> {
  if (!compiled) {
    compiled = (async () => {
      if (typeof WebAssembly === "undefined") throw new OpaqueEngineError("opaque_engine_unavailable");
      const { ROUT_OPAQUE_WASM_BASE64 } = await import("./wasm/rout-opaque.wasm.base64");
      const bytes = decodeBase64(ROUT_OPAQUE_WASM_BASE64);
      if (hexOf(sha384(bytes)) !== ROUT_OPAQUE_WASM_SHA384) throw new OpaqueEngineError("opaque_engine_integrity");
      try {
        return await WebAssembly.compile(bytes as BufferSource);
      } catch {
        throw new OpaqueEngineError("opaque_engine_unavailable");
      }
    })();
    compiled.catch(() => {
      compiled = null;
    });
  }
  return compiled;
}

/** Zero-fills every engine memory that is still alive (worker teardown / lock). Returns how many. */
export function wipeEngineMemory(): number {
  let n = 0;
  for (const memory of live) {
    new Uint8Array(memory.buffer).fill(0);
    n++;
  }
  return n;
}

/** Test hook: the memories of finished operations must all read back as zeros. */
let lastMemory: WebAssembly.Memory | null = null;
export function lastEngineMemoryForTest(): Uint8Array | null {
  return lastMemory ? new Uint8Array(lastMemory.buffer) : null;
}

type Frame = {
  ex: Exports;
  /** Copies bytes into scratch; returns the offset. */
  put(bytes: Uint8Array): number;
  /** Reserves `len` scratch bytes; returns the offset. */
  reserve(len: number): number;
  /** Copies `len` bytes out (a fresh, caller-owned array). */
  take(ptr: number, len: number): Uint8Array;
  /** Reads a u32 little-endian length written by the module. */
  u32(ptr: number): number;
  blocks: number;
};

async function withFrame<T>(pages: number, fn: (f: Frame) => T): Promise<T> {
  const module = await engineModule();
  const memory = new WebAssembly.Memory({ initial: pages, maximum: pages });
  live.add(memory);
  lastMemory = memory;
  try {
    const instance = await WebAssembly.instantiate(module, {
      env: {
        memory,
        rout_random(ptr: number, len: number) {
          crypto.getRandomValues(new Uint8Array(memory.buffer, ptr, len));
        },
      },
    });
    const ex = instance.exports as unknown as Exports;
    if (ex.rout_abi_version() !== 1) throw new OpaqueEngineError("opaque_engine_integrity");
    const base = (ex.rout_heap_base() + 63) & ~63;
    let cursor = base;
    const end = base + SCRATCH;
    const reserve = (len: number) => {
      const at = (cursor + 7) & ~7;
      if (at + len > end) throw new OpaqueEngineError("opaque_invalid_input");
      cursor = at + len;
      return at;
    };
    const frame: Frame = {
      ex,
      reserve,
      put(bytes) {
        const at = reserve(Math.max(bytes.length, 1));
        new Uint8Array(memory.buffer, at, bytes.length).set(bytes);
        return at;
      },
      take(ptr, len) {
        return new Uint8Array(memory.buffer, ptr, len).slice();
      },
      u32(ptr) {
        return new DataView(memory.buffer).getUint32(ptr, true);
      },
      blocks: (end + BLOCK_ALIGN - 1) & ~(BLOCK_ALIGN - 1),
    };
    return fn(frame);
  } catch (e) {
    if (e instanceof OpaqueEngineError) throw e;
    // A trap (unreachable) or link error: no detail, no oracle.
    throw new OpaqueEngineError("opaque_engine_unavailable");
  } finally {
    new Uint8Array(memory.buffer).fill(0);
    live.delete(memory);
  }
}

function check(rc: number): void {
  if (rc === 0) return;
  if (rc === -4) throw new OpaqueEngineError("opaque_ksf_refused");
  if (rc === -3 || rc === -2) throw new OpaqueEngineError("opaque_auth_failed");
  throw new OpaqueEngineError("opaque_invalid_input");
}

function need(bytes: Uint8Array, len: number): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== len) throw new OpaqueEngineError("opaque_invalid_input");
  return bytes;
}

function needState(bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > OPAQUE_LEN.stateMax) throw new OpaqueEngineError("opaque_invalid_input");
  return bytes;
}

function needPassword(pwd: Uint8Array): Uint8Array {
  if (!(pwd instanceof Uint8Array) || pwd.length === 0 || pwd.length > 4096) throw new OpaqueEngineError("opaque_invalid_input");
  return pwd;
}

function ksfPages(k: KsfParams): number {
  return Math.max(ENGINE_PAGES.small, Math.ceil((2 * 1024 * 1024 + SCRATCH + BLOCK_ALIGN + k.mKiB * 1024) / PAGE));
}

const enc = new TextEncoder();
const contextBytes = (context: string) => {
  const b = enc.encode(context);
  if (b.length > 256) throw new OpaqueEngineError("opaque_invalid_input");
  return b;
};

// ------------------------------------------------------------------ raw KDF

/** Argon2id (RFC 9106, v1.3) over a fixed memory sized for exactly this call. */
export async function argon2id(password: Uint8Array, salt: Uint8Array, outLen: number, k: KsfParams): Promise<Uint8Array> {
  if (!Number.isInteger(outLen) || outLen < 4 || outLen > 1024 || k.mKiB < 8 * k.p || k.mKiB > OPAQUE_KSF.mKiB) {
    return Promise.reject(new OpaqueEngineError("opaque_invalid_input"));
  }
  return withFrame(ksfPages(k), (f) => {
    const pw = f.put(password);
    const sa = f.put(salt);
    const out = f.reserve(outLen);
    check(f.ex.rout_argon2id(pw, password.length, sa, salt.length, out, outLen, k.mKiB, k.t, k.p, f.blocks));
    return f.take(out, outLen);
  });
}

// ------------------------------------------------------------------ client

export async function clientRegisterStart(password: Uint8Array): Promise<{ request: Uint8Array; state: Uint8Array }> {
  needPassword(password);
  return withFrame(ENGINE_PAGES.small, (f) => {
    const pw = f.put(password);
    const req = f.reserve(OPAQUE_LEN.registrationRequest);
    const st = f.reserve(OPAQUE_LEN.stateMax);
    const stLen = f.reserve(4);
    check(f.ex.rout_client_register_start(pw, password.length, req, st, stLen));
    return { request: f.take(req, OPAQUE_LEN.registrationRequest), state: f.take(st, f.u32(stLen)) };
  });
}

export async function clientRegisterFinish(
  password: Uint8Array,
  state: Uint8Array,
  response: Uint8Array,
  k: KsfParams = OPAQUE_KSF,
): Promise<{ upload: Uint8Array; exportKey: Uint8Array; serverPublicKey: Uint8Array }> {
  needPassword(password);
  needState(state);
  need(response, OPAQUE_LEN.registrationResponse);
  return withFrame(ENGINE_PAGES.ksf, (f) => {
    const pw = f.put(password);
    const st = f.put(state);
    const rs = f.put(response);
    const up = f.reserve(OPAQUE_LEN.registrationUpload);
    const ek = f.reserve(OPAQUE_LEN.exportKey);
    const pk = f.reserve(OPAQUE_LEN.publicKey);
    check(f.ex.rout_client_register_finish(pw, password.length, st, state.length, rs, k.mKiB, k.t, k.p, f.blocks, up, ek, pk));
    return {
      upload: f.take(up, OPAQUE_LEN.registrationUpload),
      exportKey: f.take(ek, OPAQUE_LEN.exportKey),
      serverPublicKey: f.take(pk, OPAQUE_LEN.publicKey),
    };
  });
}

export async function clientLoginStart(password: Uint8Array): Promise<{ ke1: Uint8Array; state: Uint8Array }> {
  needPassword(password);
  return withFrame(ENGINE_PAGES.small, (f) => {
    const pw = f.put(password);
    const ke1 = f.reserve(OPAQUE_LEN.ke1);
    const st = f.reserve(OPAQUE_LEN.stateMax);
    const stLen = f.reserve(4);
    check(f.ex.rout_client_login_start(pw, password.length, ke1, st, stLen));
    return { ke1: f.take(ke1, OPAQUE_LEN.ke1), state: f.take(st, f.u32(stLen)) };
  });
}

export async function clientLoginFinish(
  password: Uint8Array,
  state: Uint8Array,
  ke2: Uint8Array,
  context: string,
  k: KsfParams = OPAQUE_KSF,
): Promise<{ ke3: Uint8Array; sessionKey: Uint8Array; exportKey: Uint8Array; serverPublicKey: Uint8Array }> {
  needPassword(password);
  needState(state);
  need(ke2, OPAQUE_LEN.ke2);
  const ctx = contextBytes(context);
  return withFrame(ENGINE_PAGES.ksf, (f) => {
    const pw = f.put(password);
    const st = f.put(state);
    const k2 = f.put(ke2);
    const cx = f.put(ctx);
    const k3 = f.reserve(OPAQUE_LEN.ke3);
    const sk = f.reserve(OPAQUE_LEN.sessionKey);
    const ek = f.reserve(OPAQUE_LEN.exportKey);
    const pk = f.reserve(OPAQUE_LEN.publicKey);
    check(f.ex.rout_client_login_finish(pw, password.length, st, state.length, k2, cx, ctx.length, k.mKiB, k.t, k.p, f.blocks, k3, sk, ek, pk));
    return {
      ke3: f.take(k3, OPAQUE_LEN.ke3),
      sessionKey: f.take(sk, OPAQUE_LEN.sessionKey),
      exportKey: f.take(ek, OPAQUE_LEN.exportKey),
      serverPublicKey: f.take(pk, OPAQUE_LEN.publicKey),
    };
  });
}

// ------------------------------------------------------------------ server

export async function serverSetupNew(): Promise<Uint8Array> {
  return withFrame(ENGINE_PAGES.small, (f) => {
    const out = f.reserve(OPAQUE_LEN.stateMax);
    const len = f.reserve(4);
    check(f.ex.rout_server_setup_new(out, len));
    return f.take(out, f.u32(len));
  });
}

export async function serverPublicKey(setup: Uint8Array): Promise<Uint8Array> {
  needState(setup);
  return withFrame(ENGINE_PAGES.small, (f) => {
    const st = f.put(setup);
    const pk = f.reserve(OPAQUE_LEN.publicKey);
    check(f.ex.rout_server_public_key(st, setup.length, pk));
    return f.take(pk, OPAQUE_LEN.publicKey);
  });
}

export async function serverRegisterStart(setup: Uint8Array, request: Uint8Array, credentialId: Uint8Array): Promise<Uint8Array> {
  needState(setup);
  need(request, OPAQUE_LEN.registrationRequest);
  if (credentialId.length === 0 || credentialId.length > 64) return Promise.reject(new OpaqueEngineError("opaque_invalid_input"));
  return withFrame(ENGINE_PAGES.small, (f) => {
    const st = f.put(setup);
    const rq = f.put(request);
    const cr = f.put(credentialId);
    const out = f.reserve(OPAQUE_LEN.registrationResponse);
    check(f.ex.rout_server_register_start(st, setup.length, rq, cr, credentialId.length, out));
    return f.take(out, OPAQUE_LEN.registrationResponse);
  });
}

/** Validates the client's upload (every point decodes) and returns the record to store. */
export async function serverRegisterFinish(upload: Uint8Array): Promise<Uint8Array> {
  need(upload, OPAQUE_LEN.registrationUpload);
  return withFrame(ENGINE_PAGES.small, (f) => {
    const up = f.put(upload);
    const out = f.reserve(OPAQUE_LEN.record);
    check(f.ex.rout_server_register_finish(up, out));
    return f.take(out, OPAQUE_LEN.record);
  });
}

/** `record === null` runs the RFC 9807 fake-record path for unknown accounts. */
export async function serverLoginStart(
  setup: Uint8Array,
  record: Uint8Array | null,
  ke1: Uint8Array,
  credentialId: Uint8Array,
  context: string,
): Promise<{ ke2: Uint8Array; state: Uint8Array }> {
  needState(setup);
  if (record) need(record, OPAQUE_LEN.record);
  need(ke1, OPAQUE_LEN.ke1);
  if (credentialId.length === 0 || credentialId.length > 64) return Promise.reject(new OpaqueEngineError("opaque_invalid_input"));
  const ctx = contextBytes(context);
  return withFrame(ENGINE_PAGES.small, (f) => {
    const st = f.put(setup);
    const rc = record ? f.put(record) : 0;
    const k1 = f.put(ke1);
    const cr = f.put(credentialId);
    const cx = f.put(ctx);
    const k2 = f.reserve(OPAQUE_LEN.ke2);
    const out = f.reserve(OPAQUE_LEN.stateMax);
    const len = f.reserve(4);
    check(f.ex.rout_server_login_start(st, setup.length, rc, k1, cr, credentialId.length, cx, ctx.length, k2, out, len));
    return { ke2: f.take(k2, OPAQUE_LEN.ke2), state: f.take(out, f.u32(len)) };
  });
}

/** Throws opaque_auth_failed for a wrong password, a fake record or a tampered KE3. */
export async function serverLoginFinish(state: Uint8Array, ke3: Uint8Array, context: string): Promise<Uint8Array> {
  needState(state);
  need(ke3, OPAQUE_LEN.ke3);
  const ctx = contextBytes(context);
  return withFrame(ENGINE_PAGES.small, (f) => {
    const st = f.put(state);
    const k3 = f.put(ke3);
    const cx = f.put(ctx);
    const sk = f.reserve(OPAQUE_LEN.sessionKey);
    check(f.ex.rout_server_login_finish(st, state.length, k3, cx, ctx.length, sk));
    return f.take(sk, OPAQUE_LEN.sessionKey);
  });
}
