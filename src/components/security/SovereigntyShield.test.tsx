/**
 * Veiligheidsschild in the top bar: the placeholder has the trigger's exact box
 * (no layout shift), the trigger is a 44×44 target with a level label for screen
 * readers, a factor change re-reads the server, and mounting/unmounting leaves no
 * listener or query observer behind.
 */
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { SovereigntyHealthScore } from "@/lib/security/sovereignty-score";

const auth = vi.hoisted(() => ({ user: { id: "member-1" } as { id: string } | null, loading: false }));
const server = vi.hoisted(() => ({ fn: vi.fn() }));
vi.mock("@/hooks/useAuth", () => ({ useAuth: () => auth }));
vi.mock("@tanstack/react-start", () => ({ useServerFn: (fn: unknown) => fn }));
vi.mock("@/lib/security/sovereignty-shield.functions", () => ({ getSovereigntyShield: (...a: unknown[]) => server.fn(...a) }));
vi.mock("@tanstack/react-router", () => ({ Link: ({ to, children, onClick }: { to: string; children: React.ReactNode; onClick?: () => void }) => <a href={to} onClick={onClick}>{children}</a> }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (k: string, o?: { level?: string }) => (o?.level ? `${k}|${o.level}` : k) }) }));

import { SovereigntyShield, shieldQueryKey } from "./SovereigntyShield";
import { signalSecurityFactorsChanged } from "@/lib/security/shield-events";

const s = (level: 1 | 2 | 3 | null, extra: Partial<SovereigntyHealthScore> = {}): SovereigntyHealthScore => ({
  level,
  factors: { password: true, passkey: level !== null && level >= 2, card: level === 3 ? "active" : "none" },
  passkeyStorage: level !== null && level >= 2 ? "device" : null,
  notices: [],
  nextStep: level === 1 ? "add_passkey" : level === 2 ? "add_card" : null,
  ...extra,
});

beforeAll(() => {
  globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver;
});
afterEach(() => { server.fn.mockReset(); auth.user = { id: "member-1" }; auth.loading = false; });

function mount(client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  const view = render(<QueryClientProvider client={client}><SovereigntyShield /></QueryClientProvider>);
  return { client, ...view };
}

describe("Veiligheidsschild", () => {
  it("shows a placeholder with the trigger's exact box while loading, then the level", async () => {
    let resolve!: (v: SovereigntyHealthScore) => void;
    server.fn.mockReturnValue(new Promise((r) => { resolve = r; }));
    mount();
    const placeholder = screen.getByTestId("shield-placeholder");
    const box = placeholder.className;
    expect(box).toContain("h-11");
    expect(box).toContain("w-11");
    await act(async () => resolve(s(2)));
    const trigger = await screen.findByTestId("shield-trigger");
    for (const c of box.split(" ")) expect(trigger.className.split(" ")).toContain(c);
    expect(trigger.getAttribute("data-level")).toBe("2");
    expect(trigger.getAttribute("aria-label")).toBe("shield.trigger.aria|shield.level.2.title");
  });

  it("opens the panel with the current level marked as the step on the ladder", async () => {
    server.fn.mockResolvedValue(s(2));
    mount();
    fireEvent.click(await screen.findByTestId("shield-trigger"));
    const panel = await screen.findByTestId("shield-panel");
    const current = panel.querySelector('[aria-current="step"]');
    expect(current?.textContent).toContain("shield.level.2.title");
    expect(panel.textContent).toContain("shield.next.add_card");
  });

  it("re-reads the server after a factor change and announces a demotion once", async () => {
    server.fn.mockResolvedValueOnce(s(2)).mockResolvedValueOnce(s(1));
    mount();
    expect((await screen.findByTestId("shield-trigger")).getAttribute("data-level")).toBe("2");
    act(() => signalSecurityFactorsChanged());
    await waitFor(() => expect(screen.getByTestId("shield-trigger").getAttribute("data-level")).toBe("1"));
    expect(server.fn).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("shield-live").textContent).toBe("shield.change.down.passkey_removed|shield.level.1.title");
  });

  it("a failed lookup shows 'unknown' and never claims a level", async () => {
    server.fn.mockRejectedValue(new Error("down"));
    mount();
    await waitFor(() => expect(screen.getByTestId("shield-trigger").getAttribute("data-level")).toBe("unknown"));
  });

  it("renders nothing for a signed-out visitor and asks the server nothing", () => {
    auth.user = null;
    const { container } = mount();
    expect(container.textContent).toBe("");
    expect(server.fn).not.toHaveBeenCalled();
  });

  it("keys the reading by owner, so another member's level is never reused", () => {
    expect(shieldQueryKey("a")).not.toEqual(shieldQueryKey("b"));
  });

  it("leaves no event listener or query observer behind after 30 mount/unmount cycles", async () => {
    server.fn.mockResolvedValue(s(3));
    const add = vi.spyOn(window, "addEventListener");
    const remove = vi.spyOn(window, "removeEventListener");
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    for (let i = 0; i < 30; i++) {
      const view = mount(client);
      await screen.findByTestId("shield-trigger");
      view.unmount();
    }
    const ours = (spy: typeof add) => spy.mock.calls.filter(([type]) => type === "rout:security-factors-changed").length;
    expect(ours(add)).toBeGreaterThan(0);
    expect(ours(remove)).toBe(ours(add));
    expect(client.getQueryCache().find({ queryKey: shieldQueryKey("member-1") })?.getObserversCount()).toBe(0);
    add.mockRestore(); remove.mockRestore();
    client.clear();
  });
});
