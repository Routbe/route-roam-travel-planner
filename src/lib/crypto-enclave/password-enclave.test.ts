// @vitest-environment node
/**
 * Worker side of the password engine: paranoid input slots in fixed Wasm
 * memory, PoW with cooperative abort (H.1), the OPAQUE client flow against the
 * real server engine, and secure.wipe leaving nothing behind.
 */
import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { leadingZeroBits, powDigest } from "./hashcash";
import { runEnclaveOp } from "./enclave-core";
import * as engine from "./opaque-engine";
import { requestAbort } from "./operation-control";
import { OPAQUE_CONTEXT } from "./opaque-wire";
import { slotResidueForTest } from "./password-enclave";
import type { EnclaveOp, EnclaveOps } from "./protocol";

async function call<K extends EnclaveOp>(op: K, args: EnclaveOps[K]["req"]): Promise<EnclaveOps[K]["res"]> {
  const r = await runEnclaveOp(op, args);
  if (!r.ok) throw new Error(r.code);
  return r.result as EnclaveOps[K]["res"];
}
const code = async (op: EnclaveOp, args: unknown) => {
  const r = await runEnclaveOp(op, args);
  return r.ok ? "ok" : r.code;
};
const key = (ch: string) => new TextEncoder().encode(ch);
const USER = "00000000-0000-4000-8000-0000000000e1";

async function typeInto(slot: string, text: string) {
  for (const ch of Array.from(text)) await call("password.key", { slot, key: key(ch) });
}

describe("paranoid password slots", () => {
  it("collects UTF-8 key bytes, backspaces whole characters and zeroes what it drops", async () => {
    const { slot } = await call("password.open", {});
    await typeInto(slot, "pä€😀");
    expect(slotResidueForTest(slot)).toEqual({ length: 1 + 2 + 3 + 4, tailZero: true });
    expect((await call("password.backspace", { slot })).length).toBe(3);
    expect(slotResidueForTest(slot)).toEqual({ length: 6, tailZero: true });
    expect((await call("password.clear", { slot })).length).toBe(0);
    expect(slotResidueForTest(slot)).toEqual({ length: 0, tailZero: true });
    await call("password.close", { slot });
    expect(slotResidueForTest(slot)).toBeNull();
  });

  it("refuses control bytes, partial characters and several characters per event; wipes the event buffer", async () => {
    const { slot } = await call("password.open", {});
    for (const bad of [Uint8Array.of(0x0a), Uint8Array.of(0x7f), Uint8Array.of(0x80), key("ab"), new Uint8Array(0)]) {
      expect(await code("password.key", { slot, key: bad })).toBe("invalid_input");
    }
    const k = key("x");
    await call("password.key", { slot, key: k });
    expect([...k]).toEqual([0]);
    await call("password.close", { slot });
  });

  it("a consumed slot is wiped and closed, too-short passwords are refused for registration", async () => {
    const { slot } = await call("password.open", {});
    await typeInto(slot, "short");
    expect(await code("opaque.registerStart", { password: { slot } })).toBe("password_too_short");
    expect(slotResidueForTest(slot)).toBeNull();
  });
});

describe("pow.solve", () => {
  it("finds a nonce meeting the server's bits", async () => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const copy = challenge.slice();
    const { nonce } = await call("pow.solve", { challenge, bits: 16 });
    expect(leadingZeroBits(powDigest(copy, nonce))).toBeGreaterThanOrEqual(16);
    expect(challenge.every((b) => b === 0)).toBe(true);
  });

  it("stops at the next batch boundary after an abort for the running operation only", async () => {
    requestAbort(41); // before it runs: ignored
    const running = runEnclaveOp("pow.solve", { challenge: crypto.getRandomValues(new Uint8Array(32)), bits: 26 }, 41);
    requestAbort(40); // another operation: ignored
    await new Promise((r) => setTimeout(r, 5));
    requestAbort(41);
    expect(await running).toEqual({ ok: false, code: "aborted" });
    // The next operation with the same id is not pre-aborted.
    expect((await runEnclaveOp("pow.solve", { challenge: new Uint8Array(32).fill(1), bits: 16 }, 41)).ok).toBe(true);
  });

  it("refuses difficulties outside the server range", async () => {
    expect(await code("pow.solve", { challenge: new Uint8Array(32), bits: 8 })).toBe("invalid_input");
  });
});

describe("OPAQUE client in the worker against the server engine", () => {
  it("registers from a paranoid slot and logs in from typed bytes; same vault key id; nothing survives secure.wipe", { timeout: 60_000 }, async () => {
    const setup = await engine.serverSetupNew();
    const cred = new Uint8Array(32).fill(5);
    const { slot } = await call("password.open", {});
    await typeInto(slot, "a sufficiently long passphrase");
    const reg = await call("opaque.registerStart", { password: { slot } });
    expect(slotResidueForTest(slot)).toBeNull();
    const response = await engine.serverRegisterStart(setup, reg.request, cred);
    const fin = await call("opaque.registerFinish", { handle: reg.handle, response });
    const record = await engine.serverRegisterFinish(fin.upload);
    await call("opaque.commit", { handle: reg.handle, userId: USER });
    expect(await call("opaque.vaultKey", { userId: USER })).toEqual({ keyId: fin.keyId });

    const typed = key("a sufficiently long passphrase");
    const login = await call("opaque.loginStart", { password: { bytes: typed } });
    expect(typed.every((b) => b === 0)).toBe(true);
    const s = await engine.serverLoginStart(setup, record, login.ke1, cred, OPAQUE_CONTEXT);
    const done = await call("opaque.loginFinish", { handle: login.handle, ke2: s.ke2 });
    expect(done.keyId).toBe(fin.keyId);
    await engine.serverLoginFinish(s.state, done.ke3, OPAQUE_CONTEXT);

    expect((await call("secure.wipe", {})).wiped).toBeGreaterThan(0);
    expect(await call("opaque.vaultKey", { userId: USER })).toBeNull();
    expect(await code("opaque.commit", { handle: login.handle, userId: USER })).toBe("unknown_handle");
  });

  it("a wrong password ends in auth_failed and discards the handshake", { timeout: 60_000 }, async () => {
    const setup = await engine.serverSetupNew();
    const cred = new Uint8Array(32).fill(6);
    const reg = await call("opaque.registerStart", { password: { bytes: key("the right long passphrase") } });
    const fin = await call("opaque.registerFinish", { handle: reg.handle, response: await engine.serverRegisterStart(setup, reg.request, cred) });
    const record = await engine.serverRegisterFinish(fin.upload);
    const login = await call("opaque.loginStart", { password: { bytes: key("the wrong long passphrase") } });
    const s = await engine.serverLoginStart(setup, record, login.ke1, cred, OPAQUE_CONTEXT);
    expect(await code("opaque.loginFinish", { handle: login.handle, ke2: s.ke2 })).toBe("auth_failed");
    expect(await code("opaque.loginFinish", { handle: login.handle, ke2: s.ke2 })).toBe("unknown_handle");
  });
});
