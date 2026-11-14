import i18next from "i18next";
import { createFileRoute } from "@tanstack/react-router";
import { PasswordSignUpPage } from "@/components/secure/PasswordSignUpPage";
import { getAuthProviders } from "@/lib/auth-providers.functions";

/** Sign-up with a password (OPAQUE). Secure document (COOP/COEP from src/server.ts); reached only by a full page load. */
export const Route = createFileRoute("/secure/password_/new")({
  head: () => ({
    meta: [
      { title: i18next.t("secure.pw.signupMetaTitle") },
      { name: "description", content: i18next.t("secure.pw.metaDescription") },
      { property: "og:title", content: i18next.t("secure.pw.signupMetaTitle") },
      { property: "og:description", content: i18next.t("secure.pw.metaDescription") },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "robots", content: "noindex" },
    ],
  }),
  loader: () => getAuthProviders().catch(() => null),
  component: function SecurePasswordNewRoute() {
    const info = Route.useLoaderData();
    return <PasswordSignUpPage available={info?.password === true} />;
  },
});
