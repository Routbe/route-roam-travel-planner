/**
 * Paranoid password field: keys go to the worker in typing order, only dots
 * are shown, pasting is refused, and handing the password over consumes the
 * slot and opens a fresh one. The normal field is emptied the moment it is taken.
 */
import { createRef } from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const worker = vi.hoisted(() => ({ slots: new Map<string, string[]>(), next: 0, order: [] as string[] }));
vi.mock("@/lib/crypto-enclave/client", () => ({
  enclave: {
    password: {
      open: vi.fn(async () => { const slot = `s${++worker.next}`; worker.slots.set(slot, []); return { slot, maxBytes: 256 }; }),
      key: vi.fn(async (slot: string, ch: string) => {
        await new Promise((r) => setTimeout(r, ch === "a" ? 5 : 0)); // a slow first key must not be overtaken
        const s = worker.slots.get(slot);
        if (!s) throw Object.assign(new Error("x"), { code: "unknown_handle" });
        s.push(ch);
        worker.order.push(ch);
        return { length: s.length };
      }),
      backspace: vi.fn(async (slot: string) => { const s = worker.slots.get(slot)!; s.pop(); return { length: s.length }; }),
      close: vi.fn(async (slot: string) => { worker.slots.delete(slot); return null; }),
      equal: vi.fn(async (a: string, b: string) => ({ equal: a !== b && worker.slots.get(a)?.join("") === worker.slots.get(b)?.join("") })),
    },
  },
}));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (k: string) => k }) }));

import { SecurePasswordInput, type SecurePasswordHandle } from "./SecurePasswordInput";

beforeEach(() => { worker.slots.clear(); worker.next = 0; worker.order = []; });
const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 30)); });

describe("paranoid mode", () => {
  it("sends keys in typing order, shows only dots and never holds a value", async () => {
    const ref = createRef<SecurePasswordHandle>();
    render(<SecurePasswordInput ref={ref} id="p" label="Wachtwoord" mode="paranoid" autoComplete="current-password" />);
    await flush();
    const box = screen.getByRole("textbox", { name: "Wachtwoord" });
    for (const k of ["a", "b", "c"]) fireEvent.keyDown(box, { key: k });
    fireEvent.keyDown(box, { key: "Backspace" });
    await flush();
    expect(worker.order).toEqual(["a", "b", "c"]);
    expect(worker.slots.get("s1")).toEqual(["a", "b"]);
    expect(box.textContent).toBe("••");
    expect(box.textContent).not.toContain("a");
    expect(ref.current?.length()).toBe(2);
  });

  it("refuses paste and ignores shortcuts", async () => {
    render(<SecurePasswordInput id="p" label="Wachtwoord" mode="paranoid" autoComplete="current-password" />);
    await flush();
    const box = screen.getByRole("textbox", { name: "Wachtwoord" });
    const paste = new Event("paste", { bubbles: true, cancelable: true });
    box.dispatchEvent(paste);
    expect(paste.defaultPrevented).toBe(true);
    fireEvent.keyDown(box, { key: "v", ctrlKey: true });
    await flush();
    expect(worker.slots.get("s1")).toEqual([]);
  });

  it("hands over the slot itself and opens a fresh, empty one", async () => {
    const ref = createRef<SecurePasswordHandle>();
    render(<SecurePasswordInput ref={ref} id="p" label="Wachtwoord" mode="paranoid" autoComplete="current-password" />);
    await flush();
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "x" });
    await flush();
    let source: unknown;
    await act(async () => { source = await ref.current?.take(); });
    await flush();
    expect(source).toEqual({ slot: "s1" });
    expect(ref.current?.slot()).toBe("s2");
    expect(ref.current?.length()).toBe(0);
  });

  it("after a wipe the next key starts again in a new slot", async () => {
    render(<SecurePasswordInput id="p" label="Wachtwoord" mode="paranoid" autoComplete="current-password" />);
    await flush();
    worker.slots.delete("s1"); // secure.wipe closed every slot
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "x" });
    await flush();
    expect(worker.slots.has("s2")).toBe(true);
  });
});

describe("normal mode", () => {
  it("returns the typed bytes once and empties the field at once", async () => {
    const ref = createRef<SecurePasswordHandle>();
    render(<SecurePasswordInput ref={ref} id="n" label="Wachtwoord" mode="normal" autoComplete="new-password" />);
    const input = screen.getByLabelText("Wachtwoord") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "lang-genoeg-wachtwoord" } });
    let source: { bytes?: Uint8Array } | null = null;
    await act(async () => { source = (await ref.current?.take()) as { bytes?: Uint8Array } | null; });
    expect(new TextDecoder().decode(source!.bytes)).toBe("lang-genoeg-wachtwoord");
    expect(input.value).toBe("");
    await act(async () => { expect(await ref.current?.take()).toBeNull(); });
  });
});
