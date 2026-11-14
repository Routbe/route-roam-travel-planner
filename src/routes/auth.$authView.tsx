import i18next from "i18next";
import { createFileRoute, notFound } from "@tanstack/react-router";

import AuthNeon from "@/components/imported-pages/AuthNeon";
import { isAdminMode } from "@/lib/app-mode";
import { getAuthProviders } from "@/lib/auth-providers.functions";

/**
 * `/auth/sign-in` (passkey, e-maillink of wachtwoord + tweede stap),
 * `/auth/sign-up` (account + passkey in één stap), `/auth/reset-password`
 * (wachtwoord instellen of herstellen) en `/auth/recovery` (handmatig herstel).
 */
export const Route = createFileRoute("/auth/$authView")({
  head: () => ({
    meta: [
      { title: isAdminMode() ? i18next.t("auth.meta.admin") : i18next.t("auth.meta.signin") },
      {
        name: "description",
        content: isAdminMode() ? i18next.t("auth.meta.adminDescription") : i18next.t("auth.meta.description"),
      },
      { property: "og:title", content: isAdminMode() ? i18next.t("auth.meta.admin") : i18next.t("auth.meta.signin") },
      {
        property: "og:description",
        content: isAdminMode() ? i18next.t("auth.meta.adminDescription") : i18next.t("auth.meta.description"),
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  // Providers and readiness come with the first render, so nothing is inserted above the form later.
  loader: () => getAuthProviders().catch(() => null),
  component: AuthPage,
});

function AuthPage() {
  const { authView } = Route.useParams();
  const info = Route.useLoaderData();
  if (authView === "sign-in") return <AuthNeon initialMode="signin" initialProviders={info} />;
  if (authView === "recovery") return <AuthNeon initialMode="recovery" initialProviders={info} />;
  if (authView === "reset-password") return <AuthNeon initialMode="reset" initialProviders={info} />;
  if (authView === "sign-up") return <AuthNeon initialMode="signup" initialProviders={info} />;
  throw notFound();
}
