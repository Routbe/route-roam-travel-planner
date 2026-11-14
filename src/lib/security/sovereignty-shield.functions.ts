/** Server function behind the Veiligheidsschild in the top bar (owner only, read-only). */
import { createServerFn } from "@tanstack/react-start";
import { requireAuth } from "@/lib/auth/middleware";
import { getSovereigntyHealthScore, type SovereigntyHealthScore } from "./sovereignty-score";

export const getSovereigntyShield = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .handler(async ({ context }): Promise<SovereigntyHealthScore> => {
    const { setResponseHeader } = await import("@tanstack/react-start/server");
    setResponseHeader("cache-control", "private, no-store");
    const { sovereigntyFacts } = await import("./sovereignty-shield.server");
    return getSovereigntyHealthScore(await sovereigntyFacts(context.userId));
  });
