/**
 * Better Auth plugin: password sign-in and password sign-up with OPAQUE
 * (RFC 9807) behind Hashcash proof-of-work (Stap 3, db-pending/0270).
 *
 *   POST /opaque/login/pow     { email }                  -> PoW challenge
 *   POST /opaque/login/start   { email, pow, ke1 }        -> { handshake, ke2 }
 *   POST /opaque/login/finish  { handshake, ke3 }         -> session, or a pending 2FA step
 *   POST /opaque/signup/pow    { ticket }                 -> PoW challenge
 *   POST /opaque/signup/start  { ticket, pow, request }   -> { response }
 *   POST /opaque/signup/finish { ticket, upload }         -> new account + session
 *
 * The password never reaches these endpoints, not even as a hash. Better Auth's
 * own e-mail + password is switched off and its paths answer 410. Every
 * failure of a login answers the same `invalid_credentials`, whether the
 * address is unknown or the password is wrong. A new account is created only
 * inside runOpaqueAccountCreation, after the upload validated and with the same
 * signed sign-up ticket (consent, age) the passkey sign-up uses.
 */
import { APIError, createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";

type User = { id: string; email: string; twoFactorEnabled?: boolean | null };
type Adapter = {
  findUserById: (id: string) => Promise<User | null>;
  findUserByEmail: (email: string) => Promise<{ user: User } | null>;
  createUser: (u: { email: string; name: string; emailVerified: boolean }) => Promise<User | null>;
  deleteUser: (id: string) => Promise<void>;
  createSession: (userId: string) => Promise<{ token: string } | null>;
};
type Ctx = {
  body?: unknown;
  context: { internalAdapter: Adapter; setNewSession: (s: unknown) => void; secret: string };
  json: (body: unknown) => unknown;
};

async function fail(e: unknown): Promise<never> {
  const { OpaqueServerError } = await import("./opaque-server.server");
  if (e instanceof APIError) throw e;
  if (e instanceof OpaqueServerError) {
    if (e.code === "opaque_unavailable") throw new APIError("SERVICE_UNAVAILABLE", { code: "opaque_unavailable", message: "Inloggen met wachtwoord is nog niet beschikbaar." });
    if (e.code === "pow_invalid") throw new APIError("BAD_REQUEST", { code: "pow_invalid", message: "De rekenpuzzel is verlopen. Probeer het opnieuw." });
    if (e.code === "busy") throw new APIError("TOO_MANY_REQUESTS", { code: "busy", message: "Te veel pogingen tegelijk. Wacht even." });
    if (e.code === "registration_refused") throw new APIError("FORBIDDEN", { code: "registration_refused", message: "Dit wachtwoord kon niet worden ingesteld." });
    throw new APIError("BAD_REQUEST", { code: "invalid_input", message: "Ongeldige aanvraag." });
  }
  console.error("[opaque] unexpected", e instanceof Error ? e.name : typeof e);
  throw new APIError("SERVICE_UNAVAILABLE", { code: "opaque_unavailable", message: "Inloggen met wachtwoord is tijdelijk niet beschikbaar." });
}

const bodyOf = (ctx: Ctx) => (ctx.body && typeof ctx.body === "object" ? (ctx.body as Record<string, unknown>) : {});

async function ticketOf(ctx: Ctx) {
  const ticket = bodyOf(ctx)["ticket"];
  const { verifySignupTicket } = await import("./signup-ticket");
  const t = typeof ticket === "string" ? await verifySignupTicket(ctx.context.secret, ticket, Math.floor(Date.now() / 1000)) : null;
  if (!t) throw new APIError("BAD_REQUEST", { code: "signup_ticket_invalid", message: "Je aanmelding is verlopen. Begin opnieuw." });
  return t;
}

async function memberIdFor(authId: string): Promise<string> {
  const { sql } = await import("@/lib/neon");
  const rows = await sql`select id from public.users where auth_user_id::text = ${authId} or user_metadata->>'neon_auth_id' = ${authId} limit 1`;
  const id = rows[0]?.["id"];
  return typeof id === "string" ? id : authId;
}

async function openSession(raw: unknown, user: User) {
  const ctx = raw as Ctx;
  const session = await ctx.context.internalAdapter.createSession(user.id);
  if (!session) throw new APIError("SERVICE_UNAVAILABLE", { message: "Session unavailable" });
  await setSessionCookie(raw as never, { user, session } as never);
  ctx.context.setNewSession({ user, session });
}

export function opaquePasswordAuth() {
  return {
    id: "rout-opaque-password",
    endpoints: {
      opaqueLoginPow: createAuthEndpoint("/opaque/login/pow", { method: "POST" }, async (raw) => {
        const ctx = raw as unknown as Ctx;
        const s = await import("./opaque-server.server");
        const email = s.normalizeEmail(bodyOf(ctx)["email"]);
        if (!email) throw new APIError("BAD_REQUEST", { code: "invalid_input", message: "Vul een geldig e-mailadres in." });
        try {
          return ctx.json(await s.issuePow("opaque_login", email));
        } catch (e) {
          return fail(e);
        }
      }),
      opaqueLoginStart: createAuthEndpoint("/opaque/login/start", { method: "POST" }, async (raw) => {
        const ctx = raw as unknown as Ctx;
        const b = bodyOf(ctx);
        const s = await import("./opaque-server.server");
        try {
          return ctx.json(await s.loginStart({ email: b["email"], pow: b["pow"], ke1: b["ke1"] }));
        } catch (e) {
          return fail(e);
        }
      }),
      opaqueLoginFinish: createAuthEndpoint("/opaque/login/finish", { method: "POST" }, async (raw) => {
        const ctx = raw as unknown as Ctx;
        const b = bodyOf(ctx);
        const s = await import("./opaque-server.server");
        let authId: string | null;
        try {
          authId = await s.loginFinish({ handshake: b["handshake"], ke3: b["ke3"] });
        } catch (e) {
          return fail(e);
        }
        const user = authId ? await ctx.context.internalAdapter.findUserById(authId) : null;
        if (!user) throw new APIError("UNAUTHORIZED", { code: "invalid_credentials", message: "E-mailadres of wachtwoord klopt niet." });
        if (user.twoFactorEnabled) {
          const { startSecondFactorChallenge } = await import("./magic-link-two-factor");
          await startSecondFactorChallenge(raw, user.id);
          return ctx.json({ ok: true, twoFactorRedirect: true });
        }
        await openSession(raw, user);
        return ctx.json({ ok: true, memberId: await memberIdFor(user.id) });
      }),
      opaqueSignupPow: createAuthEndpoint("/opaque/signup/pow", { method: "POST" }, async (raw) => {
        const ctx = raw as unknown as Ctx;
        const t = await ticketOf(ctx);
        const s = await import("./opaque-server.server");
        try {
          return ctx.json(await s.issuePow("opaque_signup", t.email));
        } catch (e) {
          return fail(e);
        }
      }),
      opaqueSignupStart: createAuthEndpoint("/opaque/signup/start", { method: "POST" }, async (raw) => {
        const ctx = raw as unknown as Ctx;
        const t = await ticketOf(ctx);
        if (await ctx.context.internalAdapter.findUserByEmail(t.email)) throw new APIError("BAD_REQUEST", { code: "account_exists", message: "Er bestaat al een account met dit e-mailadres." });
        const b = bodyOf(ctx);
        const s = await import("./opaque-server.server");
        // No member exists yet, so no request may create the OPAQUE setup here (anonymous).
        if (!(await s.opaqueSetupReady())) return fail(new s.OpaqueServerError("opaque_unavailable"));
        try {
          return ctx.json(await s.registerStart({ email: t.email, request: b["request"], pow: b["pow"] }, "opaque_signup", t.email, { userId: "" }));
        } catch (e) {
          return fail(e);
        }
      }),
      opaqueSignupFinish: createAuthEndpoint("/opaque/signup/finish", { method: "POST" }, async (raw) => {
        const ctx = raw as unknown as Ctx;
        const t = await ticketOf(ctx);
        const adapter = ctx.context.internalAdapter;
        if (await adapter.findUserByEmail(t.email)) throw new APIError("BAD_REQUEST", { code: "account_exists", message: "Er bestaat al een account met dit e-mailadres." });
        const s = await import("./opaque-server.server");
        let reg: Awaited<ReturnType<typeof s.buildRegistration>>;
        try {
          reg = await s.buildRegistration({ email: t.email, upload: bodyOf(ctx)["upload"] });
        } catch (e) {
          return fail(e);
        }
        const { runOpaqueAccountCreation } = await import("./account-creation-scope");
        // The only other place a new account may be created: after a valid OPAQUE upload.
        const user = await runOpaqueAccountCreation(() => adapter.createUser({ email: t.email, name: t.name || t.email.split("@")[0] || t.email, emailVerified: false }));
        if (!user?.id) throw new APIError("SERVICE_UNAVAILABLE", { code: "account_create_failed", message: "Account aanmaken mislukt." });
        try {
          await s.storeRegistration(reg, { kind: "signup", caller: { userId: user.id } });
        } catch (e) {
          // No identity may survive without its credential.
          await adapter.deleteUser(user.id).catch(() => undefined);
          return fail(e);
        }
        try {
          const { recordSignupAge } = await import("@/lib/minor-safety.server");
          await recordSignupAge(t.email, t.dob, t.parentEmail);
        } catch (e) {
          console.error("[opaque-signup] recording age failed", e instanceof Error ? e.message : e);
        }
        await openSession(raw, user);
        return ctx.json({ ok: true, memberId: await memberIdFor(user.id) });
      }),
    },
  };
}
