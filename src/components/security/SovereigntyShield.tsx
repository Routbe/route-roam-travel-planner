import { useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { Link } from "@tanstack/react-router";
import { Check, Circle, Crown, ShieldAlert, ShieldCheck, ShieldQuestion, type LucideIcon } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { useIsMobile } from "@/hooks/use-mobile";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { HeaderControl } from "@/components/layout/HeaderControls";
import { getSovereigntyShield } from "@/lib/security/sovereignty-shield.functions";
import { onSecurityFactorsChanged } from "@/lib/security/shield-events";
import { shieldChange, type ShieldChange, type ShieldLevel, type SovereigntyHealthScore } from "@/lib/security/sovereignty-score";
import { cn } from "@/lib/utils";

/** Owner-keyed: another member's reading can never be shown after an account switch. */
export const shieldQueryKey = (ownerId: string | null) => ["sovereignty-shield", ownerId] as const;

const UNKNOWN: SovereigntyHealthScore = { level: null, factors: { password: null, passkey: null, card: "unknown" }, passkeyStorage: null, notices: [], nextStep: null };

const LOOK: Record<ShieldLevel | "unknown", { icon: LucideIcon; pill: string }> = {
  1: { icon: ShieldAlert, pill: "bg-shield-basic text-shield-basic-foreground" },
  2: { icon: ShieldCheck, pill: "bg-shield-sovereign text-shield-sovereign-foreground" },
  3: { icon: Crown, pill: "bg-shield-hardware text-shield-hardware-foreground ring-1 ring-shield-hardware-foreground/40" },
  unknown: { icon: ShieldQuestion, pill: "bg-muted text-foreground" },
};

/* One box for placeholder and every level: 44×44 on phones, fixed width from sm, so nothing shifts. */
const TRIGGER_BOX = "relative inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-full p-0 sm:w-[7.5rem] sm:justify-start";
const PILL_BOX = "inline-flex h-8 w-8 items-center justify-center gap-1.5 rounded-full text-xs font-medium sm:w-full sm:justify-start sm:px-2.5";

const NEXT_LINK = { add_passkey: "security", add_card: "wallet", unfreeze_card: "wallet" } as const;

/**
 * Veiligheidsschild in the top bar of the signed-in app. Quiet by design: no
 * pop-ups, no blocking; the panel shows the ladder and the one next step.
 */
export function SovereigntyShield() {
  const { t } = useTranslation();
  const { user, loading } = useAuth();
  const ownerId = user?.id ?? null;
  const fetchShield = useServerFn(getSovereigntyShield);
  const queryClient = useQueryClient();
  const isMobile = useIsMobile();
  const [open, setOpen] = useState(false);
  const [change, setChange] = useState<ShieldChange | null>(null);
  const [glow, setGlow] = useState(false);
  const previous = useRef<{ owner: string; score: SovereigntyHealthScore } | null>(null);

  const query = useQuery({
    queryKey: shieldQueryKey(ownerId),
    queryFn: () => fetchShield(),
    enabled: ownerId !== null,
    staleTime: 60_000,
    refetchOnWindowFocus: true,
    retry: 1,
  });

  useEffect(() => onSecurityFactorsChanged(() => void queryClient.invalidateQueries({ queryKey: ["sovereignty-shield"] })), [queryClient]);

  useEffect(() => {
    const data = query.data;
    if (!ownerId || !data) return;
    const prev = previous.current;
    const next = prev && prev.owner === ownerId ? shieldChange(prev.score, data) : null;
    if (prev?.owner !== ownerId) setChange(null);
    else if (next) {
      setChange(next);
      setGlow(next.direction === "up");
    }
    previous.current = { owner: ownerId, score: data };
  }, [ownerId, query.data]);

  if (loading || (ownerId !== null && query.isPending)) {
    return (
      <HeaderControl name="shield">
        <span role="status" aria-busy="true" aria-label={t("shield.trigger.loading")} className={TRIGGER_BOX} data-testid="shield-placeholder">
          <span aria-hidden className={cn(PILL_BOX, "bg-muted motion-safe:animate-pulse")} />
        </span>
      </HeaderControl>
    );
  }
  if (!ownerId) return null;

  const score = query.data ?? UNKNOWN;
  const look = LOOK[score.level ?? "unknown"];
  const Icon = look.icon;
  const levelTitle = score.level ? t(`shield.level.${score.level}.title`) : t("shield.unknown.title");
  const short = score.level ? t(`shield.level.${score.level}.short`) : t("shield.unknown.short");
  const changeText = change ? (change.direction === "up" ? t("shield.change.up", { level: t(`shield.level.${change.level}.title`) }) : t(`shield.change.down.${change.reason}`, { level: t(`shield.level.${change.level}.title`) })) : null;
  const panel = <ShieldPanel score={score} changeText={changeText} onNavigate={() => setOpen(false)} />;

  return (
    <HeaderControl name="shield">
      <Popover open={open && !isMobile} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            type="button"
            variant="ghost"
            aria-label={t("shield.trigger.aria", { level: levelTitle })}
            data-testid="shield-trigger"
            data-level={score.level ?? "unknown"}
            className={TRIGGER_BOX}
          >
            <span aria-hidden className={cn(PILL_BOX, look.pill, glow && "shield-promoted")} onAnimationEnd={() => setGlow(false)}>
              <Icon className="h-4 w-4 shrink-0" strokeWidth={2} />
              <span className="hidden truncate sm:inline">{short}</span>
            </span>
          </Button>
        </PopoverTrigger>
        <PopoverContent align="end" className="w-80 p-0" aria-label={t("shield.name")}>
          {panel}
        </PopoverContent>
      </Popover>
      <Sheet open={open && isMobile} onOpenChange={setOpen}>
        <SheetContent side="bottom" className="max-h-[85vh] rounded-t-2xl p-0">
          <SheetTitle className="sr-only">{t("shield.name")}</SheetTitle>
          <SheetDescription className="sr-only">{levelTitle}</SheetDescription>
          {panel}
          <div className="px-5 pb-5">
            <Button type="button" variant="outline" className="h-11 w-full" onClick={() => setOpen(false)}>{t("shield.close")}</Button>
          </div>
        </SheetContent>
      </Sheet>
      {/* Announced once, politely, also when the panel is closed. */}
      <span className="sr-only" aria-live="polite" data-testid="shield-live">{changeText ?? ""}</span>
    </HeaderControl>
  );
}

function ShieldPanel({ score, changeText, onNavigate }: { score: SovereigntyHealthScore; changeText: string | null; onNavigate: () => void }) {
  const { t } = useTranslation();
  const look = LOOK[score.level ?? "unknown"];
  const Icon = look.icon;
  const f = score.factors;
  const passkeyLine = f.passkey === null ? t("shield.factor.passkey.unknown") : !f.passkey ? t("shield.factor.passkey.off") : t(score.passkeyStorage ? `shield.factor.passkey.${score.passkeyStorage}` : "shield.factor.passkey.on");
  const passwordLine = f.password === null ? t("shield.factor.password.unknown") : t(f.password ? "shield.factor.password.on" : "shield.factor.password.off");
  const factors: { key: string; on: boolean; text: string }[] = [
    { key: "password", on: f.password === true, text: passwordLine },
    { key: "passkey", on: f.passkey === true, text: passkeyLine },
    { key: "card", on: f.card === "active", text: t(`shield.factor.card.${f.card}`) },
  ];

  return (
    <div className="space-y-4 p-5 text-sm" data-testid="shield-panel">
      <div className="flex items-start gap-3">
        <span aria-hidden className={cn("inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-full", look.pill)}>
          <Icon className="h-5 w-5" />
        </span>
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground">{t("shield.name")}</p>
          <p className="text-base font-medium text-foreground">{score.level ? t(`shield.level.${score.level}.title`) : t("shield.unknown.title")}</p>
        </div>
      </div>
      <p className="text-foreground">{score.level ? t(`shield.level.${score.level}.body`) : t("shield.unknown.body")}</p>
      {changeText ? <p className="rounded-lg border border-border px-3 py-2 text-foreground">{changeText}</p> : null}
      {score.notices.map((n) => <p key={n} className="rounded-lg border border-border px-3 py-2 text-foreground">{t(`shield.notice.${n}`)}</p>)}

      {score.level ? (
        <ol aria-label={t("shield.ladder.label")} className="space-y-1.5">
          {([1, 2, 3] as const).map((l) => {
            const current = l === score.level;
            const reached = l <= (score.level ?? 0);
            return (
              <li key={l} aria-current={current ? "step" : undefined} className={cn("flex min-h-11 items-center gap-3 rounded-lg px-3", current ? LOOK[l].pill : "text-foreground")}>
                <span aria-hidden className="w-4 text-center font-mono text-xs">{l}</span>
                <span className="flex-1">{t(`shield.level.${l}.title`)}</span>
                {reached ? <Check className="h-4 w-4" aria-hidden /> : <Circle className="h-4 w-4" aria-hidden />}
                <span className="sr-only">{current ? t("shield.ladder.current") : reached ? t("shield.ladder.reached") : t("shield.ladder.open")}</span>
              </li>
            );
          })}
        </ol>
      ) : null}

      <ul aria-label={t("shield.factors.label")} className="space-y-1 text-foreground">
        {factors.map((x) => (
          <li key={x.key} className="flex items-center gap-2">
            {x.on ? <Check className="h-4 w-4 shrink-0" aria-hidden /> : <Circle className="h-4 w-4 shrink-0" aria-hidden />}
            <span>{x.text}</span>
          </li>
        ))}
      </ul>

      <div className="flex flex-col gap-2">
        {score.nextStep ? (
          <PanelLink target={NEXT_LINK[score.nextStep]} primary onNavigate={onNavigate}>{t(`shield.next.${score.nextStep}`)}</PanelLink>
        ) : null}
        <PanelLink target="security" onNavigate={onNavigate}>{t("shield.manage")}</PanelLink>
      </div>
      <p className="text-xs text-muted-foreground">{t("shield.info")}</p>
    </div>
  );
}

function PanelLink({ target, primary, onNavigate, children }: { target: "security" | "wallet"; primary?: boolean; onNavigate: () => void; children: ReactNode }) {
  return (
    <Button asChild variant={primary ? "default" : "outline"} className="h-11 w-full">
      {target === "wallet" ? (
        <Link to="/wallet" onClick={onNavigate}>{children}</Link>
      ) : (
        <Link to="/studio/account" search={{ tab: "security" } as never} onClick={onNavigate}>{children}</Link>
      )}
    </Button>
  );
}
