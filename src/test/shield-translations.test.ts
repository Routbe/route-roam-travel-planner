import { describe, expect, it } from "vitest";
import nl from "@/locales/pages/shield.nl.json";
import en from "@/locales/pages/shield.en.json";
import fr from "@/locales/pages/shield.fr.json";
import de from "@/locales/pages/shield.de.json";

const bundles = { nl, en, fr, de } as Record<string, Record<string, string>>;
const placeholders = (s: string) => (s.match(/\{\{\w+\}\}/g) ?? []).sort();

describe("Veiligheidsschild in four languages", () => {
  it("every shield text exists and is filled in for nl, en, fr and de", () => {
    const keys = Object.keys(nl).sort();
    for (const [locale, bundle] of Object.entries(bundles)) {
      expect(Object.keys(bundle).sort(), locale).toEqual(keys);
      for (const k of keys) expect(bundle[k]?.trim(), `${locale}:${k}`).toBeTruthy();
    }
  });

  it("interpolated values ({{level}}) are kept in every language", () => {
    for (const k of Object.keys(nl)) for (const [locale, bundle] of Object.entries(bundles)) expect(placeholders(bundle[k]!), `${locale}:${k}`).toEqual(placeholders(nl[k as keyof typeof nl]));
  });

  it("covers every level, notice, next step and demotion reason the score can produce", () => {
    const needed = [
      ...[1, 2, 3].flatMap((l) => [`shield.level.${l}.short`, `shield.level.${l}.title`, `shield.level.${l}.body`]),
      "shield.notice.card_frozen", "shield.notice.card_needs_passkey", "shield.notice.card_status_unknown",
      "shield.next.add_passkey", "shield.next.add_card", "shield.next.unfreeze_card",
      "shield.change.down.passkey_removed", "shield.change.down.card_frozen", "shield.change.down.card_removed", "shield.change.down.factor_removed",
      "shield.factor.card.active", "shield.factor.card.frozen", "shield.factor.card.none", "shield.factor.card.unknown",
      "shield.factor.passkey.device", "shield.factor.passkey.synced", "shield.factor.passkey.mixed",
    ];
    for (const k of needed) expect(Object.keys(nl), k).toContain(k);
  });

  it("uses the approved wording: no Secure Enclave claim and no absolute 'onschendbaar'", () => {
    for (const bundle of Object.values(bundles)) {
      const all = Object.values(bundle).join(" ").toLowerCase();
      expect(all).not.toContain("secure enclave");
      expect(all).not.toMatch(/onschendba|invulnerab|inviolab|unverletzlich/);
    }
  });
});
