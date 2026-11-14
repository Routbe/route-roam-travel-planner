import i18next from "i18next";
import { createFileRoute } from "@tanstack/react-router";
import { PasswordSetPage } from "@/components/secure/PasswordSetPage";

/** Set, replace or remove the signed-in member's password (OPAQUE). Secure document (COOP/COEP from src/server.ts); reached only by a full page load. */
export const Route = createFileRoute("/secure/password_/set")({
  head: () => ({
    meta: [
      { title: i18next.t("secure.pw.setMetaTitle") },
      { name: "description", content: i18next.t("secure.pw.metaDescription") },
      { property: "og:title", content: i18next.t("secure.pw.setMetaTitle") },
      { property: "og:description", content: i18next.t("secure.pw.metaDescription") },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: PasswordSetPage,
});
