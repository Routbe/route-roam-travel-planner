import { describe, expect, it } from "vitest";
import { getSovereigntyHealthScore, shieldChange, type SovereigntyFacts } from "./sovereignty-score";

const base: SovereigntyFacts = { password: false, passkeys: { count: 0, deviceBound: false, synced: false }, card: false, cardState: null, attestedKey: false };
const pk = (deviceBound = true, synced = false) => ({ count: 1, deviceBound, synced });
const score = (f: Partial<SovereigntyFacts>) => getSovereigntyHealthScore({ ...base, ...f });

describe("Veiligheidsschild: levels", () => {
  it("only an OPAQUE password is level 1 (Basis) with the hint to add a passkey", () => {
    const s = score({ password: true });
    expect(s.level).toBe(1);
    expect(s.nextStep).toBe("add_passkey");
    expect(s.notices).toEqual([]);
  });

  it("a passkey is level 2 (Soeverein digitaal), with or without a password", () => {
    expect(score({ passkeys: pk() }).level).toBe(2);
    expect(score({ password: true, passkeys: pk() }).level).toBe(2);
    expect(score({ passkeys: pk() }).nextStep).toBe("add_card");
  });

  it("decision A: an active ROUT Card plus a passkey is level 3 (Hardware-enclave)", () => {
    const s = score({ passkeys: pk(), card: true, cardState: "active" });
    expect(s.level).toBe(3);
    expect(s.nextStep).toBeNull();
    expect(s.notices).toEqual([]);
  });

  it("decision A: an active card with only a password stays level 1 and asks for a passkey", () => {
    const s = score({ password: true, card: true, cardState: "active" });
    expect(s.level).toBe(1);
    expect(s.notices).toEqual(["card_needs_passkey"]);
    expect(s.nextStep).toBe("add_passkey");
  });

  it("decision B: a frozen card suspends level 3 back to 2, with the frozen notice and an unfreeze step", () => {
    const s = score({ passkeys: pk(), card: true, cardState: "frozen" });
    expect(s.level).toBe(2);
    expect(s.notices).toEqual(["card_frozen"]);
    expect(s.nextStep).toBe("unfreeze_card");
    expect(s.factors.card).toBe("frozen");
  });

  it("decision B: a frozen card next to only a password is level 1 with the frozen notice", () => {
    const s = score({ password: true, card: true, cardState: "frozen" });
    expect(s.level).toBe(1);
    expect(s.notices).toEqual(["card_frozen"]);
    expect(s.nextStep).toBe("add_passkey");
  });

  it("a blocked card never counts for level 3", () => {
    expect(score({ passkeys: pk(), card: true, cardState: "blocked" }).level).toBe(2);
  });

  it("an attested hardware key (Stap 5) counts for level 3 only together with a passkey", () => {
    expect(score({ passkeys: pk(), attestedKey: true }).level).toBe(3);
    expect(score({ password: true, attestedKey: true }).level).toBe(1);
  });
});

describe("Veiligheidsschild: unknown facts never raise the level", () => {
  it("failed passkey lookup claims no level at all", () => {
    expect(score({ password: true, passkeys: null }).level).toBeNull();
    expect(score({ password: true, passkeys: null, card: true, cardState: "active" }).level).toBeNull();
  });

  it("no passkey and an unknown password claims no level", () => {
    expect(score({ password: null }).level).toBeNull();
  });

  it("no factor at all claims no level", () => {
    const s = score({});
    expect(s.level).toBeNull();
    expect(s.nextStep).toBeNull();
    expect(s.notices).toEqual([]);
  });

  it("a failed card lookup gives level 2, not 3, and says the card could not be checked", () => {
    const s = score({ passkeys: pk(), card: null });
    expect(s.level).toBe(2);
    expect(s.notices).toEqual(["card_status_unknown"]);
    expect(s.nextStep).toBeNull();
  });

  it("an unreadable card state (storage down or no root card) is never level 3", () => {
    for (const cardState of ["unavailable", null] as const) {
      const s = score({ passkeys: pk(), card: true, cardState });
      expect(s.level).toBe(2);
      expect(s.notices).toEqual(["card_status_unknown"]);
    }
  });
});

describe("Veiligheidsschild: passkey storage detail", () => {
  it("reports device-bound, synced or mixed passkeys", () => {
    expect(score({ passkeys: pk(true, false) }).passkeyStorage).toBe("device");
    expect(score({ passkeys: pk(false, true) }).passkeyStorage).toBe("synced");
    expect(score({ passkeys: { count: 2, deviceBound: true, synced: true } }).passkeyStorage).toBe("mixed");
    expect(score({ password: true }).passkeyStorage).toBeNull();
  });
});

describe("Veiligheidsschild: promotion and demotion", () => {
  const l1 = score({ password: true });
  const l2 = score({ password: true, passkeys: pk() });
  const l3 = score({ password: true, passkeys: pk(), card: true, cardState: "active" });

  it("adding a factor promotes", () => {
    expect(shieldChange(l1, l2)).toEqual({ direction: "up", level: 2 });
    expect(shieldChange(l2, l3)).toEqual({ direction: "up", level: 3 });
  });

  it("removing the passkey demotes with that reason, also from level 3", () => {
    expect(shieldChange(l2, l1)).toEqual({ direction: "down", level: 1, reason: "passkey_removed" });
    expect(shieldChange(l3, score({ password: true, card: true, cardState: "active" }))).toEqual({ direction: "down", level: 1, reason: "passkey_removed" });
  });

  it("freezing or losing the card demotes 3 to 2 with the matching reason", () => {
    expect(shieldChange(l3, score({ password: true, passkeys: pk(), card: true, cardState: "frozen" }))).toEqual({ direction: "down", level: 2, reason: "card_frozen" });
    expect(shieldChange(l3, score({ password: true, passkeys: pk(), card: false }))).toEqual({ direction: "down", level: 2, reason: "card_removed" });
  });

  it("no change, or an unknown reading, reports nothing", () => {
    expect(shieldChange(l2, l2)).toBeNull();
    expect(shieldChange(l2, score({ passkeys: null }))).toBeNull();
    expect(shieldChange(score({ passkeys: null }), l2)).toBeNull();
  });
});
