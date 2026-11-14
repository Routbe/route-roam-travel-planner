/**
 * Reads the facts behind the Veiligheidsschild for one signed-in member. Read-only:
 * passkeys (neon_auth.passkey), the OPAQUE registration (vault_enclave.pake_registered,
 * db/0270), the physical card (vault_enclave.member_card_factor, db/0250) and the root
 * card freeze state (card_freezes via rout_card_status_by_serial). Every failed lookup
 * becomes null, never "present": the shield then claims a lower level or none.
 */
import type { CardShieldState, SovereigntyFacts } from "./sovereignty-score";

function logFailure(what: string, err: unknown) {
  console.error(`[shield] ${what} lookup failed`, err instanceof Error ? err.message : "unknown error");
}

export async function sovereigntyFacts(userId: string): Promise<SovereigntyFacts> {
  const { sql } = await import("@/lib/neon");
  let authUserId: string | null = null;
  let passkeys: SovereigntyFacts["passkeys"] = null;
  try {
    // neon_auth.passkey."userId" is text while "user".id is uuid: compare as text.
    const rows = (await sql`
      select bu.id::text as auth_id,
             count(p.id)::int as n,
             coalesce(bool_or(p."deviceType" = 'singleDevice' and not p."backedUp"), false) as device_bound,
             coalesce(bool_or(p."backedUp"), false) as synced
        from public.users u
        join neon_auth."user" bu on bu.id::text = coalesce(u.auth_user_id::text, u.user_metadata->>'neon_auth_id')
        left join neon_auth.passkey p on p."userId"::text = bu.id::text
       where u.id = ${userId}
       group by bu.id
       limit 1`) as { auth_id: string; n: number; device_bound: boolean; synced: boolean }[];
    const r = rows[0];
    if (r) {
      authUserId = r.auth_id;
      passkeys = { count: Number(r.n) || 0, deviceBound: r.device_bound === true, synced: r.synced === true };
    }
  } catch (err) {
    logFailure("passkey", err);
  }

  let password: boolean | null = null;
  if (authUserId) {
    try {
      const rows = (await sql`select vault_enclave.pake_registered(${authUserId}::uuid) as ok`) as { ok: boolean | null }[];
      password = rows[0]?.ok === true;
    } catch (err) {
      logFailure("password", err);
    }
  }

  let card: boolean | null = null;
  try {
    const { vaultPort } = await import("@/lib/vault/vault-port.server");
    card = await vaultPort().memberCardFactor({ userId });
  } catch (err) {
    logFailure("card", err);
  }

  let cardState: CardShieldState = null;
  if (card === true) {
    try {
      const { myRootCard } = await import("@/lib/wallet/card-owner.server");
      cardState = (await myRootCard(userId))?.state ?? null;
    } catch (err) {
      logFailure("card state", err);
      cardState = "unavailable";
    }
  }

  // Stap 5 (FIDO MDS3) is not built: passkeys are registered without attestation.
  return { password, passkeys, card, cardState, attestedKey: false };
}
