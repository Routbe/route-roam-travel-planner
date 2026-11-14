import i18next from "i18next";
import { createFileRoute } from "@tanstack/react-router";
import { PasswordSignInPage } from "@/components/secure/PasswordSignInPage";
import { getAuthProviders } from "@/lib/auth-providers.functions";

/** Password sign-in (OPAQUE). Secure document (COOP/COEP from src/server.ts); reached only by a full page load. */
export const Route = createFileRoute("/secure/password")({
  head: () => ({
    meta: [
      { title: i18next.t("secure.pw.metaTitle") },
      { name: "description", content: i18next.t("secure.pw.metaDescription") },
      { property: "og:title", content: i18next.t("secure.pw.metaTitle") },
      { property: "og:description", content: i18next.t("secure.pw.metaDescription") },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "robots", content: "noindex" },
    ],
  }),
  loader: () => getAuthProviders().catch(() => null),
  component: function SecurePasswordRoute() {
    const info = Route.useLoaderData();
    return <PasswordSignInPage available={info?.password === true} />;
  },
});
