/**
 * Crypto-worker side of the password engine (Stap 3). Imported only by
 * enclave-core.ts, so it runs only inside crypto.worker.ts.
 *
 *   password.*   paranoid input: each slot is its own fixed WebAssembly.Memory
 *                (1 page, initial == maximum); key bytes are appended there and
 *                never become a JS string. Backspace removes one UTF-8 character.
 *   pow.solve    Hashcash in batches; yields between batches so an abort
 *                (operation-control.ts) can stop it, then nothing is left.
 *   opaque.*     OPAQUE (RFC 9807) via the pinned engine (opaque-engine.ts);
 *                Argon2id 64 MiB / 4 passes runs inside the engine's own fixed
 *                memory, which the engine zero-fills after every call.
 *   secure.wipe  queued like any request, so it only runs when the worker is
 *                idle; wipes every slot, handshake, vault key and engine memory.
 *
 * Between start and finish a handshake keeps the password and the protocol
 * state in its own 1-page Wasm memory, wiped on finish, discard, expiry and
 * secure.wipe. The OPAQUE export key never leaves the worker: it becomes a
 * non-extractable AES-GCM "password vault key" (HKDF-SHA-256) and is wiped.
 */
import { wipe } from "@/lib/crypto/wipe";
import { fail } from "./enclave-failure";
import { searchPow, isPowBits } from "./hashcash";
import {
  OpaqueEngineError,
  clientLoginFinish,
  clientLoginStart,
  clientRegisterFinish,
  clientRegisterStart,
  wipeEngineMemory,
} from "./opaque-engine";
import { OPAQUE_CONTEXT, OPAQUE_LEN, PASSWORD_MAX_BYTES, PASSWORD_MIN_CHARS, POW_CHALLENGE_BYTES } from "./opaque-wire";
import { shouldStop, yieldToEvents } from "./operation-control";
import type { EnclaveOps, PasswordSource } from "./protocol";

export type PasswordOp =
  | "password.open"
  | "password.key"
  | "password.backspace"
  | "password.clear"
  | "password.close"
  | "password.equal"
  | "pow.solve"
  | "opaque.registerStart"
  | "opaque.registerFinish"
  | "opaque.loginStart"
  | "opaque.loginFinish"
  | "opaque.commit"
  | "opaque.discard"
  | "opaque.vaultKey"
  | "secure.wipe";

type PasswordHandlers = { [K in PasswordOp]: (args: EnclaveOps[K]["req"]) => Promise<EnclaveOps[K]["res"]> };

const MINUTE = 60_000;
const SLOT_TTL = 10 * MINUTE;
const HANDSHAKE_TTL = { register: 5 * MINUTE, login: 2 * MINUTE } as const;
const MAX_SLOTS = 4;
const MAX_HANDSHAKES = 4;
const POW_BATCH = 16_384;
const STATE_AT = 2048; // password at [0, 1024), state at [2048, 2560) in the handshake memory
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const newHandle = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
const isHandle = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{32}$/.test(v);
const bytesOf = (v: unknown): Uint8Array => (v instanceof Uint8Array && v.buffer instanceof ArrayBuffer ? v : fail("invalid_input"));

/** One page, fixed: initial == maximum, so nothing can grow or move the bytes. */
function fixedPage(): WebAssembly.Memory {
  return new WebAssembly.Memory({ initial: 1, maximum: 1 });
}
const zero = (memory: WebAssembly.Memory) => new Uint8Array(memory.buffer).fill(0);

/** Characters in UTF-8 bytes, without decoding them into a string. */
function charCount(view: Uint8Array): number {
  let n = 0;
  for (const b of view) if ((b & 0xc0) !== 0x80) n++;
  return n;
}

// ---- Paranoid input slots ----------------------------------------------------

type Slot = { memory: WebAssembly.Memory; len: number; expiresAt: number; timer: ReturnType<typeof setTimeout> };
const slots = new Map<string, Slot>();

function closeSlot(id: string) {
  const s = slots.get(id);
  if (!s) return;
  clearTimeout(s.timer);
  zero(s.memory);
  s.len = 0;
  slots.delete(id);
}

function liveSlot(id: unknown): Slot {
  if (!isHandle(id)) fail("invalid_input");
  const s = slots.get(id as string) ?? fail("unknown_handle");
  if (s.expiresAt <= Date.now()) {
    closeSlot(id as string);
    fail("unknown_handle");
  }
  return s;
}

/** Test/diagnostic view: true when every byte of every slot beyond its length is zero. */
export function slotResidueForTest(id: string): { length: number; tailZero: boolean } | null {
  const s = slots.get(id);
  if (!s) return null;
  const all = new Uint8Array(s.memory.buffer);
  return { length: s.len, tailZero: all.subarray(s.len).every((b) => b === 0) };
}

// ---- Handshakes ----------------------------------------------------------------

type Handshake = {
  kind: "register" | "login";
  memory: WebAssembly.Memory;
  pwLen: number;
  stateLen: number;
  /** Pending vault key after a successful finish; installed by opaque.commit. */
  pending: { key: CryptoKey; keyId: string } | null;
  expiresAt: number;
  timer: ReturnType<typeof setTimeout>;
};
const handshakes = new Map<string, Handshake>();
const vaultKeys = new Map<string, { key: CryptoKey; keyId: string }>();

function discardHandshake(handle: string) {
  const h = handshakes.get(handle);
  if (!h) return;
  clearTimeout(h.timer);
  zero(h.memory);
  h.pending = null;
  handshakes.delete(handle);
}

function liveHandshake(handle: unknown, kind: Handshake["kind"]): Handshake {
  if (!isHandle(handle)) fail("invalid_input");
  const h = handshakes.get(handle as string) ?? fail("unknown_handle");
  if (h.kind !== kind || h.expiresAt <= Date.now()) {
    if (h.expiresAt <= Date.now()) discardHandshake(handle as string);
    fail("unknown_handle");
  }
  return h;
}

const view = (h: Handshake) => ({
  password: new Uint8Array(h.memory.buffer, 0, h.pwLen),
  state: new Uint8Array(h.memory.buffer, STATE_AT, h.stateLen),
});

/**
 * Copies the password into a fresh handshake memory and consumes its source:
 * a paranoid slot is wiped and closed, typed bytes are wiped.
 */
function takePassword(source: PasswordSource, minChars: number): { memory: WebAssembly.Memory; len: number } {
  if (!source || typeof source !== "object") fail("invalid_input");
  const memory = fixedPage();
  try {
    let len: number;
    if ("slot" in source) {
      const s = liveSlot(source.slot);
      len = s.len;
      new Uint8Array(memory.buffer).set(new Uint8Array(s.memory.buffer, 0, len));
      closeSlot(source.slot);
    } else {
      const typed = bytesOf((source as { bytes?: unknown }).bytes);
      try {
        len = typed.length;
        if (len > PASSWORD_MAX_BYTES) fail("password_too_long");
        new Uint8Array(memory.buffer).set(typed);
      } finally {
        wipe(typed);
      }
    }
    const pw = new Uint8Array(memory.buffer, 0, len);
    if (len === 0 || charCount(pw) < minChars) fail(minChars > 1 ? "password_too_short" : "invalid_input");
    return { memory, len };
  } catch (e) {
    zero(memory);
    throw e;
  }
}

function openHandshake(kind: Handshake["kind"], memory: WebAssembly.Memory, pwLen: number, state: Uint8Array): string {
  if (handshakes.size >= MAX_HANDSHAKES) {
    const oldest = handshakes.keys().next().value;
    if (oldest) discardHandshake(oldest);
  }
  if (state.length === 0 || state.length > OPAQUE_LEN.stateMax) fail("internal");
  new Uint8Array(memory.buffer, STATE_AT, state.length).set(state);
  const handle = newHandle();
  const ttl = HANDSHAKE_TTL[kind];
  handshakes.set(handle, { kind, memory, pwLen, stateLen: state.length, pending: null, expiresAt: Date.now() + ttl, timer: setTimeout(() => discardHandshake(handle), ttl) });
  return handle;
}

/** HKDF-SHA-256 from the OPAQUE export key: a non-extractable AES-GCM key and its public id. */
async function vaultKeyFrom(exportKey: Uint8Array): Promise<{ key: CryptoKey; keyId: string }> {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey("raw", exportKey as BufferSource, "HKDF", false, ["deriveKey", "deriveBits"]);
  const salt = enc.encode(OPAQUE_CONTEXT);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: enc.encode("rout.password-vault-key.v1") },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
  );
  const idBits = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode("rout.password-vault-key-id.v1") }, base, 128));
  const keyId = Array.from(idBits, (b) => b.toString(16).padStart(2, "0")).join("");
  wipe(idBits);
  return { key, keyId };
}

function engineFailure(e: unknown): never {
  if (e instanceof OpaqueEngineError) {
    if (e.code === "opaque_auth_failed") fail("auth_failed");
    if (e.code === "opaque_invalid_input") fail("invalid_input");
  }
  throw e;
}

export function wipeAllPasswordState(): number {
  let n = 0;
  for (const id of [...slots.keys()]) {
    closeSlot(id);
    n++;
  }
  for (const handle of [...handshakes.keys()]) {
    discardHandshake(handle);
    n++;
  }
  n += vaultKeys.size;
  vaultKeys.clear();
  n += wipeEngineMemory();
  return n;
}

export const passwordHandlers: PasswordHandlers = {
  async "password.open"() {
    if (slots.size >= MAX_SLOTS) {
      const oldest = slots.keys().next().value;
      if (oldest) closeSlot(oldest);
    }
    const slot = newHandle();
    slots.set(slot, { memory: fixedPage(), len: 0, expiresAt: Date.now() + SLOT_TTL, timer: setTimeout(() => closeSlot(slot), SLOT_TTL) });
    return { slot, maxBytes: PASSWORD_MAX_BYTES };
  },

  async "password.key"({ slot, key }) {
    const k = bytesOf(key);
    try {
      const s = liveSlot(slot);
      // One key event: one UTF-8 character of 1-4 bytes, never a control byte.
      if (k.length < 1 || k.length > 4 || (k[0] ?? 0) < 0x20 || (k[0] ?? 0) === 0x7f || charCount(k) !== 1 || ((k[0] ?? 0) & 0xc0) === 0x80) fail("invalid_input");
      if (s.len + k.length > PASSWORD_MAX_BYTES) fail("password_too_long");
      new Uint8Array(s.memory.buffer, s.len, k.length).set(k);
      s.len += k.length;
      return { length: charCount(new Uint8Array(s.memory.buffer, 0, s.len)) };
    } finally {
      wipe(k);
    }
  },

  async "password.backspace"({ slot }) {
    const s = liveSlot(slot);
    const all = new Uint8Array(s.memory.buffer);
    let at = s.len;
    while (at > 0) {
      at--;
      const b = all[at] ?? 0;
      all[at] = 0;
      if ((b & 0xc0) !== 0x80) break;
    }
    s.len = at;
    return { length: charCount(all.subarray(0, s.len)) };
  },

  async "password.clear"({ slot }) {
    const s = liveSlot(slot);
    zero(s.memory);
    s.len = 0;
    return { length: 0 };
  },

  async "password.close"({ slot }) {
    if (isHandle(slot)) closeSlot(slot);
    return null;
  },

  async "password.equal"({ a, b }) {
    const x = liveSlot(a);
    const y = liveSlot(b);
    // Constant time: every byte of both fixed pages is compared, whatever the lengths.
    const p = new Uint8Array(x.memory.buffer);
    const q = new Uint8Array(y.memory.buffer);
    let diff = x.len ^ y.len;
    for (let i = 0; i < p.length; i++) diff |= (p[i] ?? 0) ^ (q[i] ?? 0);
    return { equal: diff === 0 && x !== y };
  },

  async "pow.solve"({ challenge, bits }) {
    const c = bytesOf(challenge);
    try {
      if (c.length !== POW_CHALLENGE_BYTES || !isPowBits(bits)) fail("invalid_input");
      const start = crypto.getRandomValues(new Uint32Array(1))[0] ?? 0;
      const limit = 2 ** (bits + 6);
      for (let done = 0; done < limit; done += POW_BATCH) {
        if (shouldStop()) fail("aborted");
        const hit = searchPow(c, bits, start + done, POW_BATCH);
        if (hit) return { nonce: hit };
        await yieldToEvents();
      }
      return fail("pow_failed");
    } finally {
      wipe(c);
    }
  },

  async "opaque.registerStart"({ password }) {
    const { memory, len } = takePassword(password, PASSWORD_MIN_CHARS);
    try {
      const started = await clientRegisterStart(new Uint8Array(memory.buffer, 0, len)).catch(engineFailure);
      try {
        return { handle: openHandshake("register", memory, len, started.state), request: started.request };
      } finally {
        wipe(started.state);
      }
    } catch (e) {
      zero(memory);
      throw e;
    }
  },

  async "opaque.registerFinish"({ handle, response }) {
    const r = bytesOf(response);
    const h = liveHandshake(handle, "register");
    let out: { upload: Uint8Array; exportKey: Uint8Array; serverPublicKey: Uint8Array } | null = null;
    try {
      if (r.length !== OPAQUE_LEN.registrationResponse) fail("invalid_input");
      if (shouldStop()) fail("aborted");
      const v = view(h);
      out = await clientRegisterFinish(v.password, v.state, r).catch(engineFailure);
      h.pending = await vaultKeyFrom(out.exportKey);
      // The password is no longer needed: only the pending key survives until commit.
      new Uint8Array(h.memory.buffer).fill(0);
      h.pwLen = 0;
      h.stateLen = 0;
      return { upload: out.upload, keyId: h.pending.keyId };
    } catch (e) {
      discardHandshake(handle);
      throw e;
    } finally {
      wipe(r, out?.exportKey, out?.serverPublicKey);
    }
  },

  async "opaque.loginStart"({ password }) {
    const { memory, len } = takePassword(password, 1);
    try {
      const started = await clientLoginStart(new Uint8Array(memory.buffer, 0, len)).catch(engineFailure);
      try {
        return { handle: openHandshake("login", memory, len, started.state), ke1: started.ke1 };
      } finally {
        wipe(started.state);
      }
    } catch (e) {
      zero(memory);
      throw e;
    }
  },

  async "opaque.loginFinish"({ handle, ke2 }) {
    const k2 = bytesOf(ke2);
    const h = liveHandshake(handle, "login");
    let out: { ke3: Uint8Array; sessionKey: Uint8Array; exportKey: Uint8Array; serverPublicKey: Uint8Array } | null = null;
    try {
      if (k2.length !== OPAQUE_LEN.ke2) fail("invalid_input");
      if (shouldStop()) fail("aborted");
      const v = view(h);
      out = await clientLoginFinish(v.password, v.state, k2, OPAQUE_CONTEXT).catch(engineFailure);
      h.pending = await vaultKeyFrom(out.exportKey);
      new Uint8Array(h.memory.buffer).fill(0);
      h.pwLen = 0;
      h.stateLen = 0;
      return { ke3: out.ke3, keyId: h.pending.keyId };
    } catch (e) {
      discardHandshake(handle);
      throw e;
    } finally {
      wipe(k2, out?.sessionKey, out?.exportKey, out?.serverPublicKey);
    }
  },

  async "opaque.commit"({ handle, userId }) {
    if (typeof userId !== "string" || !UUID.test(userId)) fail("invalid_input");
    if (!isHandle(handle)) fail("invalid_input");
    const h = handshakes.get(handle) ?? fail("unknown_handle");
    const pending = h.pending ?? fail("unknown_handle");
    if (h.expiresAt <= Date.now()) {
      discardHandshake(handle);
      fail("unknown_handle");
    }
    vaultKeys.set(userId, pending);
    discardHandshake(handle);
    return { keyId: pending.keyId };
  },

  async "opaque.discard"({ handle }) {
    if (isHandle(handle)) discardHandshake(handle);
    return null;
  },

  async "opaque.vaultKey"({ userId }) {
    if (typeof userId !== "string" || !UUID.test(userId)) fail("invalid_input");
    const k = vaultKeys.get(userId);
    return k ? { keyId: k.keyId } : null;
  },

  async "secure.wipe"() {
    return { wiped: wipeAllPasswordState() };
  },
};
