import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { ShieldCheck } from "lucide-react";
import { RoutLogo } from "@/components/RoutLogo";

/**
 * Frame for /secure/* documents: no app navigation, no third-party widgets.
 * Links out of these pages are plain <a href> (full page load), never router
 * links, so the cross-origin-isolated document boundary stays hard (rule F.1).
 */
export function SecureShell({ title, children }: { title: string; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <main className="min-h-screen bg-background px-5 py-10 text-foreground">
      <div className="mx-auto flex w-full max-w-md flex-col gap-6">
        <div className="flex items-center justify-between gap-3">
          <a href="/" className="inline-flex min-h-11 items-center" aria-label="ROUT">
            <RoutLogo size={26} />
          </a>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border px-3 py-1 text-xs text-muted-foreground">
            <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
            {t("secure.pw.badge")}
          </span>
        </div>
        <h1 className="font-display text-3xl leading-tight">{title}</h1>
        {children}
      </div>
    </main>
  );
}

export function SecureMessage({ tone = "info", children }: { tone?: "info" | "error" | "success"; children: ReactNode }) {
  const cls =
    tone === "error"
      ? "border-destructive/40 bg-destructive/10 text-foreground"
      : tone === "success"
        ? "border-primary/40 bg-primary/10 text-foreground"
        : "border-border bg-muted/40 text-foreground";
  return (
    <p role={tone === "error" ? "alert" : "status"} className={`rounded-lg border px-3 py-2 text-sm ${cls}`}>
      {children}
    </p>
  );
}
