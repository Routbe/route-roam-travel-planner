// @vitest-environment node
/**
 * Browser orchestration of OPAQUE sign-in, sign-up and member set-up (Stap 3):
 * the order of worker and server steps, that a failed handshake is always
 * discarded in the worker, and that a wrong password and an unknown address
 * end in the same answer.
 */
import { describe, expect, it, vi } from "vitest";
import {
  fromB64u,
  OpaqueClientError,
  serverFailure,
  setMemberPassword,
  signInWithPassword,
  signUpWithPassword,
  toB64u,
  workerFailure,
  type OpaqueWorker,
  type ServerCall,
} from "./opaque-client";

const POW = { id: "11111111-1111-4111-8111-111111111111", challenge: toB64u(new Uint8Array(32).fill(7)), bits: 12, expiresAt: "2099-01-01T00:00:00Z" };

function fakeWorker(over: Partial<OpaqueWorker> = {}) {
  const log: string[] = [];
  const w: OpaqueWorker = {
    solve: vi.fn(async () => { log.push("solve"); return { nonce: Uint8Array.of(1, 2, 3) }; }),
    loginStart: vi.fn(async () => { log.push("loginStart"); return { handle: "h1", ke1: Uint8Array.of(9) }; }),
    loginFinish: vi.fn(async () => { log.push("loginFinish"); return { ke3: Uint8Array.of(8), keyId: "k" }; }),
    registerStart: vi.fn(async () => { log.push("registerStart"); return { handle: "h2", request: Uint8Array.of(5) }; }),
    registerFinish: vi.fn(async () => { log.push("registerFinish"); return { upload: Uint8Array.of(6), keyId: "k" }; }),
    commit: vi.fn(async () => { log.push("commit"); return { keyId: "k" }; }),
    discard: vi.fn(async () => { log.push("discard"); return null; }),
    ...over,
  };
  return { w, log };
}

function fakeServer(answers: Record<string, { ok?: boolean; status?: number; json: Record<string, unknown> }>) {
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  const call: ServerCall = async (path, body) => {
    calls.push({ path, body });
    const a = answers[path];
    if (!a) throw new Error(`unexpected ${path}`);
    return { ok: a.ok ?? true, status: a.status ?? 200, json: a.json };
  };
  return { call, calls };
}

describe("base64url", () => {
  it("round-trips bytes and refuses other alphabets", () => {
    const bytes = Uint8Array.from({ length: 70 }, (_, i) => (i * 37) & 255);
    expect([...fromB64u(toB64u(bytes))]).toEqual([...bytes]);
    expect(toB64u(Uint8Array.of(251, 255))).toBe("-_8");
    expect(() => fromB64u("ab+/")).toThrow(OpaqueClientError);
  });
});

describe("password sign-in", () => {
  it("solves the puzzle, runs KE1 -> KE2 -> KE3 in order and commits the vault key to the member", async () => {
    const { w, log } = fakeWorker();
    const { call, calls } = fakeServer({
      "/opaque/login/pow": { json: POW },
      "/opaque/login/start": { json: { handshake: "hs", ke2: toB64u(Uint8Array.of(4)) } },
      "/opaque/login/finish": { json: { ok: true, memberId: "m1" } },
    });
    await expect(signInWithPassword(" Jan@Example.be ", { bytes: Uint8Array.of(1) }, w, call)).resolves.toEqual({ kind: "signed_in", memberId: "m1" });
    expect(log).toEqual(["solve", "loginStart", "loginFinish", "commit"]);
    expect(calls.map((c) => c.path)).toEqual(["/opaque/login/pow", "/opaque/login/start", "/opaque/login/finish"]);
    expect(calls[0]?.body).toEqual({ email: "jan@example.be" });
    expect(calls[1]?.body).toEqual({ email: "jan@example.be", pow: { id: POW.id, nonce: toB64u(Uint8Array.of(1, 2, 3)) }, ke1: toB64u(Uint8Array.of(9)) });
    expect(calls[2]?.body).toEqual({ handshake: "hs", ke3: toB64u(Uint8Array.of(8)) });
    // The password is never part of any request.
    expect(JSON.stringify(calls)).not.toContain("password");
  });

  it("a wrong password (worker auth_failed) is invalid_credentials and the handshake is discarded", async () => {
    const { w, log } = fakeWorker({ loginFinish: vi.fn(async () => { throw Object.assign(new Error("x"), { code: "auth_failed" }); }) });
    const { call, calls } = fakeServer({
      "/opaque/login/pow": { json: POW },
      "/opaque/login/start": { json: { handshake: "hs", ke2: "BA" } },
    });
    await expect(signInWithPassword("a@b.be", { slot: "s" }, w, call)).rejects.toMatchObject({ code: "invalid_credentials" });
    expect(log.at(-1)).toBe("discard");
    expect(log).not.toContain("commit");
    expect(calls.map((c) => c.path)).not.toContain("/opaque/login/finish");
  });

  it("an unknown address answers exactly like a wrong password", async () => {
    const { w } = fakeWorker();
    const { call } = fakeServer({
      "/opaque/login/pow": { json: POW },
      "/opaque/login/start": { json: { handshake: "hs", ke2: "BA" } },
      "/opaque/login/finish": { ok: false, status: 401, json: { code: "invalid_credentials" } },
    });
    await expect(signInWithPassword("nobody@b.be", { slot: "s" }, w, call)).rejects.toMatchObject({ code: "invalid_credentials" });
  });

  it("hands over to the second sign-in step without committing a key", async () => {
    const { w, log } = fakeWorker();
    const { call } = fakeServer({
      "/opaque/login/pow": { json: POW },
      "/opaque/login/start": { json: { handshake: "hs", ke2: "BA" } },
      "/opaque/login/finish": { json: { ok: true, twoFactorRedirect: true } },
    });
    await expect(signInWithPassword("a@b.be", { slot: "s" }, w, call)).resolves.toEqual({ kind: "second_factor" });
    expect(log).not.toContain("commit");
    expect(log.at(-1)).toBe("discard");
  });

  it("stops before any password work when password sign-in is not live yet", async () => {
    const { w, log } = fakeWorker();
    const { call } = fakeServer({ "/opaque/login/pow": { ok: false, status: 503, json: { code: "opaque_unavailable" } } });
    await expect(signInWithPassword("a@b.be", { slot: "s" }, w, call)).rejects.toMatchObject({ code: "unavailable" });
    expect(log).toEqual([]);
  });
});

describe("password sign-up", () => {
  it("runs the ticket-bound registration and commits under the new member id", async () => {
    const { w, log } = fakeWorker();
    const { call, calls } = fakeServer({
      "/opaque/signup/pow": { json: POW },
      "/opaque/signup/start": { json: { response: toB64u(Uint8Array.of(3)) } },
      "/opaque/signup/finish": { json: { ok: true, memberId: "m2" } },
    });
    await expect(signUpWithPassword("su.a.b", { slot: "s" }, w, call)).resolves.toEqual({ memberId: "m2" });
    expect(log).toEqual(["solve", "registerStart", "registerFinish", "commit"]);
    expect(calls.every((c) => c.body["ticket"] === "su.a.b")).toBe(true);
  });

  it("an existing address is account_exists and nothing is kept in the worker", async () => {
    const { w, log } = fakeWorker();
    const { call } = fakeServer({
      "/opaque/signup/pow": { json: POW },
      "/opaque/signup/start": { ok: false, status: 400, json: { code: "account_exists" } },
    });
    await expect(signUpWithPassword("su.a.b", { slot: "s" }, w, call)).rejects.toMatchObject({ code: "account_exists" });
    expect(log.at(-1)).toBe("discard");
  });
});

describe("member password set-up", () => {
  it("asks the step-up only at the store step and commits afterwards", async () => {
    const { w, log } = fakeWorker();
    const order: string[] = [];
    await setMemberPassword({ slot: "s" }, w, {
      begin: async () => { order.push("begin"); return { ok: true, pow: POW }; },
      answer: async (d) => { order.push(`answer:${d.request}`); return { ok: true, response: toB64u(Uint8Array.of(3)) }; },
      finish: async (d) => { order.push(`finish:${d.upload}`); return { ok: true, memberId: "m3" }; },
    });
    expect(order).toEqual(["begin", `answer:${toB64u(Uint8Array.of(5))}`, `finish:${toB64u(Uint8Array.of(6))}`]);
    expect(log).toEqual(["solve", "registerStart", "registerFinish", "commit"]);
  });

  it("without a passkey nothing is started in the worker", async () => {
    const { w, log } = fakeWorker();
    await expect(setMemberPassword({ slot: "s" }, w, {
      begin: async () => ({ ok: false, error: "passkey_required" }),
      answer: async () => { throw new Error("not reached"); },
      finish: async () => { throw new Error("not reached"); },
    })).rejects.toMatchObject({ code: "passkey_required" });
    expect(log).toEqual([]);
  });

  it("a refused store discards the pending key", async () => {
    const { w, log } = fakeWorker();
    await expect(setMemberPassword({ slot: "s" }, w, {
      begin: async () => ({ ok: true, pow: POW }),
      answer: async () => ({ ok: true, response: "Aw" }),
      finish: async () => ({ ok: false, error: "refused" }),
    })).rejects.toMatchObject({ code: "refused" });
    expect(log.at(-1)).toBe("discard");
    expect(log).not.toContain("commit");
  });
});

describe("failure mapping", () => {
  it("maps worker and server codes onto what the page shows", () => {
    expect(workerFailure({ code: "password_too_short" }).code).toBe("too_short");
    expect(workerFailure({ code: "aborted" }).code).toBe("aborted");
    expect(workerFailure({ code: "timeout" }).code).toBe("failed");
    expect(serverFailure("pow_invalid").code).toBe("pow_failed");
    expect(serverFailure("signup_ticket_invalid").code).toBe("ticket_invalid");
    expect(serverFailure(undefined, 429).code).toBe("busy");
    expect(serverFailure(undefined, 401).code).toBe("invalid_credentials");
  });
});
