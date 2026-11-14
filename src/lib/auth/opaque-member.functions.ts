/**
 * Signed-in member: set, replace or remove their OPAQUE password (Stap 3).
 * The password never reaches these functions, only OPAQUE messages and a
 * Hashcash answer. Storing or removing needs a fresh passkey step-up
 * (action password_set, passkey-only, single use); the vault enclave spends
 * the proof again on the database clock (db-pending/0270
 * store_pake_registration). The e-mail that keys the record is the member's
 * own sign-in address, taken from the session, never from the request.
 * Until 0270 is live every function answers `unavailable` and stores nothing.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "@/lib/auth/middleware";

const b64u = z.string().min(1).max(400).regex(/^[A-Za-z0-9_-]+$/);
const powAnswer = z.object({ id: z.string().uuid(), nonce: b64u }).strict();

type Failure = "unavailable" | "passkey_required" | "pow_invalid" | "busy" | "invalid_input" | "refused" | "no_email";

async function failureOf(e: unknown): Promise<{ ok: false; error: Failure }> {
  const { OpaqueServerError } = await import("./opaque-server.server");
  if (e instanceof OpaqueServerError) {
    const map: Record<string, Failure> = {
      opaque_unavailable: "unavailable",
      pow_invalid: "pow_invalid",
      busy: "busy",
      registration_refused: "refused",
    };
    return { ok: false, error: map[e.code] ?? "invalid_input" };
  }
  throw e;
}

async function memberEmail(user: { email?: string | null }): Promise<string | null> {
  const { normalizeEmail } = await import("./opaque-server.server");
  return normalizeEmail(user.email ?? null);
}

async function hasPasskey(userId: string): Promise<boolean> {
  const { enrolledFactors } = await import("./step-up.server");
  return (await enrolledFactors(userId)).passkey;
}

async function authIdOf(userId: string): Promise<string | null> {
  const { enrolledFactors } = await import("./step-up.server");
  return (await enrolledFactors(userId)).authUserId;
}

/** Whether passwords can be set here, whether this member has one, and whether a passkey (needed to set one) exists. */
export const getPasswordStatus = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { opaqueAvailable } = await import("./opaque-server.server");
    const available = await opaqueAvailable();
    const passkey = await hasPasskey(context.userId);
    let hasPassword = false;
    if (available) {
      const authId = await authIdOf(context.userId);
      if (authId) {
        const { vaultPort } = await import("@/lib/vault/vault-port.server");
        hasPassword = await vaultPort().pakeRegistered(authId).catch(() => false);
      }
    }
    return { available, passkey, hasPassword };
  });

/** One-time Hashcash challenge for a registration by this member. */
export const beginPasswordRegistration = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    if (!(await hasPasskey(context.userId))) return { ok: false as const, error: "passkey_required" as Failure };
    const { issuePow } = await import("./opaque-server.server");
    try {
      // The first registration on this database may create the OPAQUE setup (sealed under the Master KEK).
      return { ok: true as const, pow: await issuePow("opaque_register", context.userId, {}, { userId: context.userId }) };
    } catch (e) {
      return failureOf(e);
    }
  });

/** Registration request -> response (spends the PoW). Stores nothing. */
export const answerPasswordRegistration = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ request: b64u, pow: powAnswer }).strict().parse(d))
  .handler(async ({ data, context }) => {
    const email = await memberEmail(context.user as { email?: string | null });
    if (!email) return { ok: false as const, error: "no_email" as Failure };
    if (!(await hasPasskey(context.userId))) return { ok: false as const, error: "passkey_required" as Failure };
    const { registerStart } = await import("./opaque-server.server");
    try {
      const r = await registerStart({ email, request: data.request, pow: data.pow }, "opaque_register", context.userId, { userId: context.userId });
      return { ok: true as const, response: r.response };
    } catch (e) {
      return failureOf(e);
    }
  });

/** Validates the upload, then stores it after a fresh passkey step-up (401 StepUpRequired otherwise). */
export const finishPasswordRegistration = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ upload: b64u }).strict().parse(d))
  .handler(async ({ data, context }) => {
    const email = await memberEmail(context.user as { email?: string | null });
    if (!email) return { ok: false as const, error: "no_email" as Failure };
    const s = await import("./opaque-server.server");
    if (!(await s.opaqueAvailable())) return { ok: false as const, error: "unavailable" as Failure };
    // Validated before the step-up, so a passkey confirmation is never spent on an upload that cannot be stored.
    let reg: Awaited<ReturnType<typeof s.buildRegistration>>;
    try {
      reg = await s.buildRegistration({ email, upload: data.upload });
    } catch (e) {
      return failureOf(e);
    }
    const { ensureStepUpProof } = await import("./step-up.server");
    const { PASSWORD_SET_ACTION } = await import("./step-up-rules");
    const proof = await ensureStepUpProof(context.userId, PASSWORD_SET_ACTION);
    const { stepUpProofId } = await import("@/lib/vault/step-up-proof-id");
    try {
      await s.storeRegistration(reg, { kind: "member", caller: { userId: context.userId }, stepUp: { verified: true, proofId: stepUpProofId(proof.jti) } });
    } catch (e) {
      return failureOf(e);
    }
    const { recordSecurityEvent } = await import("@/lib/audit-log.server");
    void recordSecurityEvent({ eventType: "password.opaque_set", userId: context.userId, payload: {} });
    return { ok: true as const, memberId: context.userId };
  });

/** Removes the password after a fresh passkey step-up; the vault refuses when it is the last way in. */
export const removePassword = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { opaqueAvailable } = await import("./opaque-server.server");
    if (!(await opaqueAvailable())) return { ok: false as const, error: "unavailable" as Failure };
    const { ensureStepUpProof } = await import("./step-up.server");
    const { PASSWORD_SET_ACTION } = await import("./step-up-rules");
    const proof = await ensureStepUpProof(context.userId, PASSWORD_SET_ACTION);
    const { stepUpProofId } = await import("@/lib/vault/step-up-proof-id");
    const { vaultPort } = await import("@/lib/vault/vault-port.server");
    const ok = await vaultPort().removePakeRegistration({ userId: context.userId }, { verified: true, proofId: stepUpProofId(proof.jti) });
    if (!ok) return { ok: false as const, error: "refused" as Failure };
    const { recordSecurityEvent } = await import("@/lib/audit-log.server");
    void recordSecurityEvent({ eventType: "password.opaque_removed", userId: context.userId, payload: {} });
    return { ok: true as const };
  });
