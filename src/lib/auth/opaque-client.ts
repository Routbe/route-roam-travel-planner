/**
 * Browser side of password sign-in, sign-up and set-up with OPAQUE (Stap 3).
 * Orchestrates the crypto worker (Hashcash, OPAQUE, Argon2id in the pinned
 * Wasm) and the server steps; the password only ever exists in the worker.
 * Runs only on /secure/* documents (full page load, COOP/COEP).
 *
 *   sign-in : pow -> solve -> KE1 -> server KE2 -> Argon2id + KE3 -> server -> session
 *   sign-up : pow -> solve -> request -> server response -> Argon2id + upload -> account + session
 *   member  : the same registration, stored after a fresh passkey step-up
 *
 * A wrong password and an unknown address end in the same `invalid_credentials`.
 */
import type { PasswordSource } from "@/lib/crypto-enclave/protocol";

export type OpaqueClientFailure =
  | "invalid_credentials"
  | "unavailable"
  | "pow_failed"
  | "busy"
  | "account_exists"
  | "ticket_invalid"
  | "too_short"
  | "too_long"
  | "aborted"
  | "passkey_required"
  | "refused"
  | "failed";

export class OpaqueClientError extends Error {
  constructor(readonly code: OpaqueClientFailure) {
    super(code);
    this.name = "OpaqueClientError";
  }
}

export type PowWire = { id: string; challenge: string; bits: number; expiresAt: string };

/** The crypto worker calls this flow needs (enclave.pow / enclave.opaque in client.ts). */
export type OpaqueWorker = {
  solve: (challenge: Uint8Array, bits: number) => Promise<{ nonce: Uint8Array }>;
  loginStart: (password: PasswordSource) => Promise<{ handle: string; ke1: Uint8Array }>;
  loginFinish: (handle: string, ke2: Uint8Array) => Promise<{ ke3: Uint8Array; keyId: string }>;
  registerStart: (password: PasswordSource) => Promise<{ handle: string; request: Uint8Array }>;
  registerFinish: (handle: string, response: Uint8Array) => Promise<{ upload: Uint8Array; keyId: string }>;
  commit: (handle: string, userId: string) => Promise<{ keyId: string }>;
  discard: (handle: string) => Promise<null>;
};

export type ServerCall = (path: string, body: Record<string, unknown>) => Promise<{ ok: boolean; status: number; json: Record<string, unknown> }>;

export function toB64u(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64u(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new OpaqueClientError("failed");
  const raw = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/** Maps a worker failure (EnclaveError.code) onto what the page shows. */
export function workerFailure(e: unknown): OpaqueClientError {
  if (e instanceof OpaqueClientError) return e;
  const code = (e as { code?: unknown } | null)?.code;
  switch (code) {
    case "auth_failed":
      return new OpaqueClientError("invalid_credentials");
    case "password_too_short":
      return new OpaqueClientError("too_short");
    case "password_too_long":
      return new OpaqueClientError("too_long");
    case "aborted":
      return new OpaqueClientError("aborted");
    case "pow_failed":
      return new OpaqueClientError("pow_failed");
    default:
      return new OpaqueClientError("failed");
  }
}

/** Maps a server answer (code from opaque-password-plugin.ts / opaque-member.functions.ts). */
export function serverFailure(code: unknown, status = 0): OpaqueClientError {
  switch (code) {
    case "invalid_credentials":
      return new OpaqueClientError("invalid_credentials");
    case "opaque_unavailable":
    case "unavailable":
      return new OpaqueClientError("unavailable");
    case "pow_invalid":
      return new OpaqueClientError("pow_failed");
    case "busy":
      return new OpaqueClientError("busy");
    case "account_exists":
      return new OpaqueClientError("account_exists");
    case "signup_ticket_invalid":
      return new OpaqueClientError("ticket_invalid");
    case "passkey_required":
      return new OpaqueClientError("passkey_required");
    case "registration_refused":
    case "refused":
      return new OpaqueClientError("refused");
    default:
      return new OpaqueClientError(status === 401 ? "invalid_credentials" : status === 429 ? "busy" : status === 503 ? "unavailable" : "failed");
  }
}

async function solvePow(worker: OpaqueWorker, pow: unknown): Promise<{ id: string; nonce: string }> {
  const p = pow as Partial<PowWire> | null;
  if (!p || typeof p.id !== "string" || typeof p.challenge !== "string" || typeof p.bits !== "number") throw new OpaqueClientError("failed");
  try {
    const { nonce } = await worker.solve(fromB64u(p.challenge), p.bits);
    return { id: p.id, nonce: toB64u(nonce) };
  } catch (e) {
    throw workerFailure(e);
  }
}

async function post(call: ServerCall, path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const r = await call(path, body);
  if (!r.ok) throw serverFailure(r.json["code"], r.status);
  return r.json;
}

/** fetch() against Better Auth's /api/auth (same origin, session cookie). */
export const authFetch: ServerCall = async (path, body) => {
  const res = await fetch(`/api/auth${path}`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { ok: res.ok, status: res.status, json };
};

export type SignInResult = { kind: "signed_in"; memberId: string | null } | { kind: "second_factor" };

/** Password sign-in. The password source is consumed by the worker. */
export async function signInWithPassword(email: string, password: PasswordSource, worker: OpaqueWorker, call: ServerCall = authFetch): Promise<SignInResult> {
  const address = email.trim().toLowerCase();
  const pow = await solvePow(worker, await post(call, "/opaque/login/pow", { email: address }));
  let handle: string | null = null;
  try {
    let started: { handle: string; ke1: Uint8Array };
    try {
      started = await worker.loginStart(password);
    } catch (e) {
      throw workerFailure(e);
    }
    handle = started.handle;
    const ke2 = await post(call, "/opaque/login/start", { email: address, pow, ke1: toB64u(started.ke1) });
    if (typeof ke2["handshake"] !== "string" || typeof ke2["ke2"] !== "string") throw new OpaqueClientError("failed");
    let finished: { ke3: Uint8Array };
    try {
      finished = await worker.loginFinish(handle, fromB64u(ke2["ke2"]));
    } catch (e) {
      // Wrong password or unknown address: the server's handshake expires as a failure.
      throw workerFailure(e);
    }
    const done = await post(call, "/opaque/login/finish", { handshake: ke2["handshake"], ke3: toB64u(finished.ke3) });
    if (done["twoFactorRedirect"] === true) return { kind: "second_factor" };
    const memberId = typeof done["memberId"] === "string" ? done["memberId"] : null;
    if (memberId) {
      await worker.commit(handle, memberId).catch(() => null);
      handle = null;
    }
    return { kind: "signed_in", memberId };
  } finally {
    if (handle) await worker.discard(handle).catch(() => null);
  }
}

/** Shared registration: request -> response -> upload; `respond` and `store` reach the server. */
async function register(
  password: PasswordSource,
  worker: OpaqueWorker,
  respond: (request: string) => Promise<string>,
  store: (upload: string) => Promise<string | null>,
): Promise<{ memberId: string | null }> {
  let handle: string | null = null;
  try {
    let started: { handle: string; request: Uint8Array };
    try {
      started = await worker.registerStart(password);
    } catch (e) {
      throw workerFailure(e);
    }
    handle = started.handle;
    const response = await respond(toB64u(started.request));
    let finished: { upload: Uint8Array };
    try {
      finished = await worker.registerFinish(handle, fromB64u(response));
    } catch (e) {
      throw workerFailure(e);
    }
    const memberId = await store(toB64u(finished.upload));
    if (memberId) {
      await worker.commit(handle, memberId).catch(() => null);
      handle = null;
    }
    return { memberId };
  } finally {
    if (handle) await worker.discard(handle).catch(() => null);
  }
}

/** New account with a password, behind the signed sign-up ticket (consent, age). */
export async function signUpWithPassword(ticket: string, password: PasswordSource, worker: OpaqueWorker, call: ServerCall = authFetch): Promise<{ memberId: string | null }> {
  const pow = await solvePow(worker, await post(call, "/opaque/signup/pow", { ticket }));
  return register(
    password,
    worker,
    async (request) => {
      const r = await post(call, "/opaque/signup/start", { ticket, pow, request });
      if (typeof r["response"] !== "string") throw new OpaqueClientError("failed");
      return r["response"];
    },
    async (upload) => {
      const r = await post(call, "/opaque/signup/finish", { ticket, upload });
      return typeof r["memberId"] === "string" ? r["memberId"] : null;
    },
  );
}

type MemberResult<T> = ({ ok: true } & T) | { ok: false; error: string };

/** The signed-in member's server functions (opaque-member.functions.ts); `finish` already wraps the step-up. */
export type MemberCalls = {
  begin: () => Promise<MemberResult<{ pow: PowWire }>>;
  answer: (data: { request: string; pow: { id: string; nonce: string } }) => Promise<MemberResult<{ response: string }>>;
  finish: (data: { upload: string }) => Promise<MemberResult<{ memberId: string }>>;
};

function unwrap<T>(r: MemberResult<T>): T {
  if (!r.ok) throw serverFailure(r.error);
  return r;
}

/** Sets or replaces the signed-in member's password. */
export async function setMemberPassword(password: PasswordSource, worker: OpaqueWorker, calls: MemberCalls): Promise<void> {
  const { pow } = unwrap(await calls.begin());
  const answer = await solvePow(worker, pow);
  await register(
    password,
    worker,
    async (request) => unwrap(await calls.answer({ request, pow: answer })).response,
    async (upload) => unwrap(await calls.finish({ upload })).memberId,
  );
}
