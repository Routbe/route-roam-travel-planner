// TEMPORARY visual harness for the Veiligheidsschild; removed after the check.
import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { ShieldBadge, ShieldPanel } from "@/components/security/SovereigntyShield";
import type { SovereigntyHealthScore } from "@/lib/security/sovereignty-score";

export const Route = createFileRoute("/shield-preview")({
  head: () => ({ meta: [{ title: "Shield preview" }, { name: "robots", content: "noindex" }] }),
  component: Preview,
});

const l1: SovereigntyHealthScore = { level: 1, factors: { password: true, passkey: false, card: "active" }, passkeyStorage: null, notices: ["card_needs_passkey"], nextStep: "add_passkey" };
const l2: SovereigntyHealthScore = { level: 2, factors: { password: true, passkey: true, card: "frozen" }, passkeyStorage: "device", notices: ["card_frozen"], nextStep: "unfreeze_card" };
const l3: SovereigntyHealthScore = { level: 3, factors: { password: false, passkey: true, card: "active" }, passkeyStorage: "synced", notices: [], nextStep: null };

function Row() {
  const { t } = useTranslation();
  return (
    <div className="flex h-16 items-center gap-2 border-b border-border bg-background px-4" data-row>
      {([1, 2, 3, null] as const).map((l) => (
        <span key={String(l)} className="relative inline-flex h-11 w-11 items-center justify-center sm:w-[7.5rem] sm:justify-start">
          <ShieldBadge level={l} label={l ? t(`shield.level.${l}.short`) : t("shield.unknown.short")} />
        </span>
      ))}
    </div>
  );
}

function Preview() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Row />
      <div className="dark bg-background text-foreground"><Row /></div>
      <div className="grid gap-4 p-4 sm:grid-cols-3">
        {[l1, l2, l3].map((s) => <div key={s.level} className="w-80 rounded-md border bg-popover text-popover-foreground"><ShieldPanel score={s} changeText={s.level === 2 ? "Je schild staat nu op Soeverein digitaal omdat je kaart tijdelijk bevroren is." : null} onNavigate={() => {}} /></div>)}
      </div>
      <div className="dark grid gap-4 bg-background p-4 text-foreground sm:grid-cols-3">
        {[l3].map((s) => <div key={s.level} className="w-80 rounded-md border bg-popover text-popover-foreground"><ShieldPanel score={s} changeText={null} onNavigate={() => {}} /></div>)}
      </div>
    </div>
  );
}
