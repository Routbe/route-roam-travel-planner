import { createServerFn } from "@tanstack/react-start";
import { authConfigurationReadiness, type AuthReadiness } from "@/lib/auth-readiness";

export type AuthProvidersInfo = {
  providers: string[];
  readiness: AuthReadiness;
  /** OPAQUE password sign-in is live (db/0270 applied); false hides every password option. */
  password?: boolean;
};

async function passwordAvailable(databaseReady: boolean): Promise<boolean> {
  if (!databaseReady) return false;
  try {
    const { opaqueAvailable } = await import("@/lib/auth/opaque-server.server");
    return await opaqueAvailable();
  } catch {
    return false;
  }
}

/**
 * Same answer as GET /api/public/auth/providers (names only, never values), so
 * the sign-in route can render its final layout on the server instead of
 * inserting provider buttons and the "unavailable" notice after hydration.
 */
export const getAuthProviders = createServerFn({ method: "GET" }).handler(async (): Promise<AuthProvidersInfo> => {
  const { enabledProviders, resolveAuthSecret } = await import("@/lib/better-auth.server");
  const { hasDatabase } = await import("@/lib/neon");
  const fediverse = process.env["APP_SESSION_SECRET"] || process.env["NEON_AUTH_COOKIE_SECRET"] ? ["mastodon", "bluesky"] : [];
  const readiness = authConfigurationReadiness(hasDatabase(), Boolean(resolveAuthSecret()));
  return {
    providers: [...enabledProviders(), ...fediverse],
    readiness,
    password: await passwordAvailable(readiness.ready),
  };
});
