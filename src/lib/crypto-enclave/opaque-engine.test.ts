// @vitest-environment node
/**
 * The pinned password engine (wasm/rout-opaque): integrity pin, fixed memory
 * with no memory.grow, zero-filled memory after every call (success and error),
 * the Argon2id floor (64 MiB, 4 passes) enforced inside the module, a
 * cross-check of raw Argon2id against @noble/hashes, and the OPAQUE round trip.
 */
import { argon2id as nobleArgon2id } from "@noble/hashes/argon2.js";
import { sha384 } from "@noble/hashes/sha2.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import * as engine from "./opaque-engine";
import { ROUT_OPAQUE_WASM_SHA384 } from "./opaque-wasm-pin";
import { ENGINE_PAGES, OPAQUE_CONTEXT, OPAQUE_KSF } from "./opaque-wire";
import { ROUT_OPAQUE_WASM_BASE64 } from "./wasm/rout-opaque.wasm.base64";

const WASM = readFileSync(join(__dirname, "wasm", "rout-opaque.wasm"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const pw = (s: string) => new TextEncoder().encode(s);
const allZero = () => engine.lastEngineMemoryForTest()!.every((b) => b === 0);

describe("module integrity and shape", () => {
  it("the committed binary, its base64 copy and the SHA-384 pin agree", () => {
    expect(hex(sha384(WASM))).toBe(ROUT_OPAQUE_WASM_SHA384);
    expect(Buffer.from(ROUT_OPAQUE_WASM_BASE64, "base64").equals(WASM)).toBe(true);
  });

  it("imports one fixed memory and contains no memory.grow", async () => {
    const mod = await WebAssembly.compile(WASM);
    const imports = WebAssembly.Module.imports(mod);
    expect(imports.map((i) => `${i.module}.${i.name}:${i.kind}`).sort()).toEqual(["env.memory:memory", "env.rout_random:function"]);
    expect(WebAssembly.Module.exports(mod).some((e) => e.kind === "memory")).toBe(false);
    const wabt = await (await import("wabt")).default();
    const text = wabt.readWasm(WASM, { readDebugNames: false }).toText({});
    expect(text).not.toMatch(/memory\.grow/);
    const limits = /\(import "env" "memory" \(memory \(;\d+;\) (\d+) (\d+)\)\)/.exec(text);
    expect(limits?.slice(1).map(Number)).toEqual([ENGINE_PAGES.small, ENGINE_PAGES.ksf]);
  });
});

describe("Argon2id", () => {
  it("matches @noble/hashes (RFC 9106 v1.3) and wipes its memory", async () => {
    const out = await engine.argon2id(pw("password"), pw("somesaltsomesalt"), 32, { mKiB: 256, t: 3, p: 2 });
    expect(hex(out)).toBe(hex(nobleArgon2id(pw("password"), pw("somesaltsomesalt"), { m: 256, t: 3, p: 2, dkLen: 32 })));
    expect(allZero()).toBe(true);
  });

  it("refuses OPAQUE below the owner floor inside the module", async () => {
    const reg = await engine.clientRegisterStart(pw("a long enough password"));
    const setup = await engine.serverSetupNew();
    const response = await engine.serverRegisterStart(setup, reg.request, new Uint8Array(32).fill(7));
    for (const weak of [{ ...OPAQUE_KSF, mKiB: 32_768 }, { ...OPAQUE_KSF, t: 3 }]) {
      await expect(engine.clientRegisterFinish(pw("a long enough password"), reg.state, response, weak)).rejects.toMatchObject({ code: "opaque_ksf_refused" });
      expect(allZero()).toBe(true);
    }
  });
});

describe("OPAQUE round trip (RFC 9807, ristretto255/SHA-512/3DH, Argon2id 64 MiB x 4)", () => {
  it("registers, logs in, agrees on keys, and rejects a wrong password", { timeout: 60_000 }, async () => {
    const setup = await engine.serverSetupNew();
    const cred = new Uint8Array(32).fill(9);
    const r1 = await engine.clientRegisterStart(pw("correct horse battery staple"));
    const resp = await engine.serverRegisterStart(setup, r1.request, cred);
    const fin = await engine.clientRegisterFinish(pw("correct horse battery staple"), r1.state, resp);
    expect(allZero()).toBe(true);
    const record = await engine.serverRegisterFinish(fin.upload);
    expect(hex(fin.serverPublicKey)).toBe(hex(await engine.serverPublicKey(setup)));

    const l1 = await engine.clientLoginStart(pw("correct horse battery staple"));
    const s1 = await engine.serverLoginStart(setup, record, l1.ke1, cred, OPAQUE_CONTEXT);
    const c = await engine.clientLoginFinish(pw("correct horse battery staple"), l1.state, s1.ke2, OPAQUE_CONTEXT);
    const serverKey = await engine.serverLoginFinish(s1.state, c.ke3, OPAQUE_CONTEXT);
    expect(hex(serverKey)).toBe(hex(c.sessionKey));
    expect(hex(c.exportKey)).toBe(hex(fin.exportKey));

    const bad = await engine.clientLoginStart(pw("correct horse battery stapler"));
    const s2 = await engine.serverLoginStart(setup, record, bad.ke1, cred, OPAQUE_CONTEXT);
    await expect(engine.clientLoginFinish(pw("correct horse battery stapler"), bad.state, s2.ke2, OPAQUE_CONTEXT)).rejects.toMatchObject({ code: "opaque_auth_failed" });
    expect(allZero()).toBe(true);
  });

  it("a tampered KE3 fails on the server; a client on another context cannot finish", { timeout: 60_000 }, async () => {
    const setup = await engine.serverSetupNew();
    const cred = new Uint8Array(32).fill(1);
    const r = await engine.clientRegisterStart(pw("another fine password"));
    const fin = await engine.clientRegisterFinish(pw("another fine password"), r.state, await engine.serverRegisterStart(setup, r.request, cred));
    const record = await engine.serverRegisterFinish(fin.upload);
    const l = await engine.clientLoginStart(pw("another fine password"));
    const s = await engine.serverLoginStart(setup, record, l.ke1, cred, OPAQUE_CONTEXT);
    const c = await engine.clientLoginFinish(pw("another fine password"), l.state, s.ke2, OPAQUE_CONTEXT);
    const tampered = c.ke3.slice();
    tampered[0] = (tampered[0] ?? 0) ^ 1;
    await expect(engine.serverLoginFinish(s.state, tampered, OPAQUE_CONTEXT)).rejects.toMatchObject({ code: "opaque_auth_failed" });
    // The context is bound into the transcript at KE2: a client using another one fails.
    const l2 = await engine.clientLoginStart(pw("another fine password"));
    const s2 = await engine.serverLoginStart(setup, record, l2.ke1, cred, OPAQUE_CONTEXT);
    await expect(engine.clientLoginFinish(pw("another fine password"), l2.state, s2.ke2, "rout.other.v1")).rejects.toMatchObject({ code: "opaque_auth_failed" });
  });

  it("unknown accounts get a well-formed fake KE2 the client cannot finish", async () => {
    const setup = await engine.serverSetupNew();
    const l = await engine.clientLoginStart(pw("whatever password"));
    const s = await engine.serverLoginStart(setup, null, l.ke1, new Uint8Array(32).fill(3), OPAQUE_CONTEXT);
    expect(s.ke2.length).toBe(320);
    await expect(engine.clientLoginFinish(pw("whatever password"), l.state, s.ke2, OPAQUE_CONTEXT)).rejects.toMatchObject({ code: "opaque_auth_failed" });
  });

  it("malformed inputs are refused without a trap leaking state", async () => {
    await expect(engine.serverRegisterFinish(new Uint8Array(192))).rejects.toBeInstanceOf(engine.OpaqueEngineError);
    expect(allZero()).toBe(true);
    await expect(engine.clientLoginStart(new Uint8Array(0))).rejects.toMatchObject({ code: "opaque_invalid_input" });
    expect(engine.wipeEngineMemory()).toBe(0);
  });
});
