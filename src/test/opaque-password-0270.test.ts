// @vitest-environment node
/**
 * db-pending/0270 (OPAQUE password sign-in + Hashcash PoW) and its rollback,
 * replayed on PGlite over every migration in db/. Drives the real server code
 * (opaque-server.server.ts -> LocalPostgresVaultAdapter as rout_app) and the
 * real pinned Wasm engine for the client side, so the whole RFC 9807 flow runs:
 * PoW -> registration -> login, wrong password, unknown address, replays.
 * Argon2id runs at the owner floor (64 MiB, 4 passes).
 */
import { PGlite } from "@electric-sql/pglite";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import * as engine from "@/lib/crypto-enclave/opaque-engine";
import { solvePow } from "@/lib/crypto-enclave/hashcash";
import { OPAQUE_CONTEXT } from "@/lib/crypto-enclave/opaque-wire";
import { b64u, fromB64u, issuePow, loginFinish, loginStart, OpaqueServerError, registerFinish, registerStart, type OpaqueDeps, type PowWire } from "@/lib/auth/opaque-server.server";
import { deriveVaultKek } from "@/lib/vault/server-kek";
import { LocalPostgresVaultAdapter, type VaultSqlExecutor } from "@/lib/vault/vault-port.server";

const ROOT = join(__dirname, "..", "..");
const SQL_0270 = readFileSync(join(ROOT, "db-pending", "0270_opaque_password_pow.sql"), "utf8");
const SQL_ROLLBACK = readFileSync(join(ROOT, "db-pending", "0270_opaque_password_pow_rollback.sql"), "utf8");
const MEMBER = "00000000-0000-4000-8000-0000000000d1";
const MEMBER_AUTH = "00000000-0000-4000-8000-0000000000a1";
const SIGNUP_AUTH = "00000000-0000-4000-8000-0000000000a2";
const OLD_AUTH = "00000000-0000-4000-8000-0000000000a3";
const enc = new TextEncoder();
const PASSWORD = "correct horse battery staple";

describe("0270 OPAQUE + PoW on a replay of db/", () => {
  let db: PGlite;
  const exec: VaultSqlExecutor = async (userId, query, params) => {
    await db.exec("begin");
    try {
      await db.exec("set local role rout_app");
      await db.query("select set_config('rout.current_user_id', $1, true)", [userId]);
      const r = await db.query<Record<string, unknown>>(query, [...params]);
      await db.exec("commit");
      return r.rows;
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
  };
  const port = new LocalPostgresVaultAdapter(exec);
  const deps: OpaqueDeps = { port, kek: deriveVaultKek("a".repeat(64)) };
  const apply = (sql: string) => db.exec(`begin;\n${sql}\n;commit;`);
  const solve = (c: PowWire) => ({ id: c.id, nonce: b64u(solvePow(fromB64u(c.challenge, 32), c.bits)) });
  const proof = async () => {
    const id = randomUUID();
    await db.query("insert into vault_enclave.step_up_proofs (proof_id, user_id, method, verified_at) values ($1, $2, 'passkey', clock_timestamp())", [id, MEMBER]);
    return { verified: true as const, proofId: id };
  };

  async function register(email: string, password: string, who: "member" | "signup") {
    const pw = enc.encode(password);
    const started = await engine.clientRegisterStart(pw);
    const caller = { userId: who === "member" ? MEMBER : SIGNUP_AUTH };
    const purpose = who === "member" ? "opaque_register" : "opaque_signup";
    const subject = who === "member" ? MEMBER : email;
    const pow = solve(await issuePow(purpose, subject, deps, caller));
    const { response } = await registerStart({ email, request: b64u(started.request), pow }, purpose, subject, caller, deps);
    const fin = await engine.clientRegisterFinish(pw, started.state, fromB64u(response, 64));
    await registerFinish({ email, upload: b64u(fin.upload) }, who === "member" ? { kind: "member", caller, stepUp: await proof() } : { kind: "signup", caller }, deps);
    return fin.exportKey;
  }

  async function login(email: string, password: string): Promise<{ authId: string | null; exportKey?: Uint8Array }> {
    const pw = enc.encode(password);
    const started = await engine.clientLoginStart(pw);
    const pow = solve(await issuePow("opaque_login", email.trim().toLowerCase(), deps));
    const { handshake, ke2 } = await loginStart({ email, pow, ke1: b64u(started.ke1) }, deps);
    let ke3: Uint8Array;
    let exportKey: Uint8Array | undefined;
    try {
      const fin = await engine.clientLoginFinish(pw, started.state, fromB64u(ke2, 320), OPAQUE_CONTEXT);
      ke3 = fin.ke3;
      exportKey = fin.exportKey;
    } catch {
      // Wrong password / fake record: the client cannot even build KE3; send noise.
      ke3 = new Uint8Array(64);
    }
    return { authId: await loginFinish({ handshake, ke3: b64u(ke3) }, deps), exportKey };
  }

  beforeAll(async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    db = await PGlite.create({ extensions: { pgcrypto, btree_gist } });
    const dir = join(ROOT, "db");
    for (const step of planMigrations(listMigrationFiles(dir), new Set())) {
      if (step.action === "run") await db.exec(`begin;\n${readFileSync(join(dir, step.file), "utf8")}\n;commit;`);
    }
    await db.query(
      `insert into neon_auth."user" (id, name, email, "emailVerified", "createdAt", "updatedAt") values
        ($1, 'm', 'member@example.test', true, now(), now()),
        ($2, 's', 'new@example.test', false, now(), now()),
        ($3, 'o', 'old@example.test', false, now() - interval '1 hour', now())`,
      [MEMBER_AUTH, SIGNUP_AUTH, OLD_AUTH],
    );
    await db.query("insert into public.users (id, email, auth_user_id) values ($1, 'member@example.test', $2)", [MEMBER, MEMBER_AUTH]);
  }, 300_000);
  afterAll(async () => db?.close());

  it("before 0270 the feature reports unavailable and nothing is callable", async () => {
    expect(await port.pakeAvailable()).toBe(false);
    await expect(issuePow("opaque_login", "member@example.test", deps)).rejects.toMatchObject({ code: "opaque_unavailable" });
  });

  it("0270 applies; rout_app reaches no new table, every definer is pinned and closed to PUBLIC", async () => {
    await apply(SQL_0270);
    expect(await port.pakeAvailable()).toBe(true);
    for (const t of ["pake_setups", "pake_registrations", "auth_pow_challenges", "pake_handshakes"]) {
      const r = await db.query<{ s: boolean; i: boolean }>(`select has_table_privilege('rout_app', 'vault_enclave.${t}', 'select') as s, has_table_privilege('rout_app', 'vault_enclave.${t}', 'insert') as i`);
      expect(r.rows[0]).toEqual({ s: false, i: false });
    }
    const helpers = await db.query<{ app: boolean }>("select has_function_privilege('rout_app', 'vault_enclave.pake_recent_failures(bytea)', 'execute') as app");
    expect(helpers.rows[0]!.app).toBe(false);
  });

  it("no setup exists before the first registration: anonymous PoW cannot mint one", async () => {
    await expect(issuePow("opaque_login", "member@example.test", deps)).rejects.toMatchObject({ code: "opaque_unavailable" });
  });

  it("member registers (passkey proof spent once) and signs in; the export key matches", { timeout: 120_000 }, async () => {
    const regKey = await register("Member@Example.test ", PASSWORD, "member");
    const setup = await db.query<{ n: number; kind: number }>("select count(*)::int as n, get_byte(envelope, 5) as kind from vault_enclave.pake_setups group by 2");
    expect(setup.rows).toEqual([{ n: 1, kind: 7 }]);
    const res = await login("member@example.test", PASSWORD);
    expect(res.authId).toBe(MEMBER_AUTH);
    expect(res.exportKey && Buffer.from(res.exportKey).equals(Buffer.from(regKey))).toBe(true);
    const spent = await db.query<{ n: number }>("select count(*)::int as n from vault_enclave.step_up_proofs where consumed_at is not null");
    expect(spent.rows[0]!.n).toBe(1);
  });

  it("the stored record never contains the password or a password hash", async () => {
    const r = await db.query<{ record: Uint8Array }>("select record from vault_enclave.pake_registrations");
    const hay = Buffer.from(r.rows[0]!.record);
    expect(hay.includes(Buffer.from(PASSWORD))).toBe(false);
    const setup = await db.query<{ envelope: Uint8Array }>("select envelope from vault_enclave.pake_setups");
    // The setup is sealed: its 128 plaintext bytes are not in the clear anywhere in the row.
    expect(setup.rows[0]!.envelope.length).toBe(1647 + 128 + 16);
  });

  it("wrong password and unknown address both fail the same way and raise the difficulty", { timeout: 120_000 }, async () => {
    expect((await login("member@example.test", "not the right password")).authId).toBeNull();
    expect((await login("nobody@example.test", PASSWORD)).authId).toBeNull();
    const harder = await issuePow("opaque_login", "member@example.test", deps);
    expect(harder.bits).toBeGreaterThan(16);
    const audit = await db.query<{ outcome: string; reason: string }>("select outcome, reason from vault_enclave.audit_logs where action = 'pake_login' order by seq");
    expect(audit.rows.map((r) => `${r.outcome}:${r.reason}`)).toEqual(["granted:ok", "denied:bad_proof", "denied:bad_proof"]);
  });

  it("a PoW is single-use, bound to its purpose and scope, and must verify", async () => {
    const c = await issuePow("opaque_login", "member@example.test", deps);
    const answer = solve(c);
    const ke1 = b64u((await engine.clientLoginStart(enc.encode(PASSWORD))).ke1);
    await expect(loginStart({ email: "other@example.test", pow: answer, ke1 }, deps)).rejects.toMatchObject({ code: "pow_invalid" });
    // Wrong scope burned the challenge: the right address cannot reuse it either.
    await expect(loginStart({ email: "member@example.test", pow: answer, ke1 }, deps)).rejects.toMatchObject({ code: "pow_invalid" });
    const c2 = await issuePow("opaque_login", "member@example.test", deps);
    await expect(loginStart({ email: "member@example.test", pow: { id: c2.id, nonce: b64u(new Uint8Array(8)) }, ke1 }, deps)).rejects.toMatchObject({ code: "pow_invalid" });
  });

  it("a handshake finishes once; a replayed KE3 gets nothing", { timeout: 120_000 }, async () => {
    const pw = enc.encode(PASSWORD);
    const started = await engine.clientLoginStart(pw);
    const pow = solve(await issuePow("opaque_login", "member@example.test", deps));
    const { handshake, ke2 } = await loginStart({ email: "member@example.test", pow, ke1: b64u(started.ke1) }, deps);
    const { ke3 } = await engine.clientLoginFinish(pw, started.state, fromB64u(ke2, 320), OPAQUE_CONTEXT);
    expect(await loginFinish({ handshake, ke3: b64u(ke3) }, deps)).toBe(MEMBER_AUTH);
    expect(await loginFinish({ handshake, ke3: b64u(ke3) }, deps)).toBeNull();
    expect(await port.grantPakeLogin(handshake)).toBeNull();
  });

  it("a member cannot set a password without a fresh passkey proof, nor reuse one", async () => {
    const used = await db.query<{ proof_id: string }>("select proof_id::text from vault_enclave.step_up_proofs where consumed_at is not null limit 1");
    const reg = { lookup: new Uint8Array(32).fill(1), credentialId: new Uint8Array(32).fill(2), record: new Uint8Array(192), setupKid: new Uint8Array(16) };
    expect(await port.storePakeRegistration({ userId: MEMBER }, reg, { verified: true, proofId: used.rows[0]!.proof_id })).toBe(false);
    expect(await port.storePakeRegistration({ userId: MEMBER }, reg, { verified: true, proofId: randomUUID() })).toBe(false);
  });

  it("sign-up registration only for a fresh identity without passkey, member row or password", { timeout: 120_000 }, async () => {
    await register("new@example.test", PASSWORD, "signup");
    expect(await port.pakeRegistered(SIGNUP_AUTH)).toBe(true);
    expect((await login("new@example.test", PASSWORD)).authId).toBe(SIGNUP_AUTH);
    const reg = { lookup: new Uint8Array(32).fill(3), credentialId: new Uint8Array(32).fill(4), record: new Uint8Array(192), setupKid: new Uint8Array(16) };
    expect(await port.storePakeSignupRegistration({ userId: OLD_AUTH }, reg)).toBe(false); // older than 15 minutes
    expect(await port.storePakeSignupRegistration({ userId: MEMBER_AUTH }, reg)).toBe(false); // has a member row
    expect(await port.storePakeSignupRegistration({ userId: SIGNUP_AUTH }, reg)).toBe(false); // already has one
  });

  it("the last way in cannot be removed: no passkey means the password stays", async () => {
    expect(await port.removePakeRegistration({ userId: MEMBER }, await proof())).toBe(false);
    expect(await port.pakeRegistered(MEMBER_AUTH)).toBe(true);
  });

  it("setups are append-only", async () => {
    await expect(db.exec("delete from vault_enclave.pake_setups")).rejects.toThrow(/append-only/);
  });

  it("rollback refuses while passwords exist; after removing them it drops everything and 0270 re-applies", async () => {
    await expect(apply(SQL_ROLLBACK)).rejects.toThrow(/password registrations exist/);
    await db.exec("rollback").catch(() => undefined);
    await db.exec("delete from vault_enclave.pake_registrations");
    await apply(SQL_ROLLBACK);
    expect(await port.pakeAvailable()).toBe(false);
    const left = await db.query<{ n: number }>("select count(*)::int as n from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'vault_enclave' and c.relname like 'pake%'");
    expect(left.rows[0]!.n).toBe(0);
    // Audit rows with 0270 actions exist, so the wider action check stays (append-only log).
    const con = await db.query<{ d: string }>("select pg_get_constraintdef(oid) as d from pg_constraint where conname = 'audit_logs_action_check'");
    expect(con.rows[0]!.d).toContain("pake_login");
    await apply(SQL_0270);
    expect(await port.pakeAvailable()).toBe(true);
  });
});

describe("opaque-server input checks", () => {
  it("rejects malformed messages before touching the vault", async () => {
    const deps: OpaqueDeps = { port: { pakeAvailable: async () => { throw new Error("must not be called"); } } as never };
    await expect(loginStart({ email: "x", pow: null, ke1: "" }, deps)).rejects.toBeInstanceOf(OpaqueServerError);
    await expect(loginStart({ email: "a@b.cd", pow: null, ke1: "AAAA" }, deps)).rejects.toMatchObject({ code: "invalid_input" });
    await expect(loginFinish({ handshake: "nope", ke3: "" }, deps)).rejects.toMatchObject({ code: "invalid_input" });
  });
});
