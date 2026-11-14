import { forwardRef, useCallback, useEffect, useImperativeHandle, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { enclave } from "@/lib/crypto-enclave/client";
import type { PasswordSource } from "@/lib/crypto-enclave/protocol";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

export type PasswordInputMode = "normal" | "paranoid";

export type SecurePasswordHandle = {
  /** Characters typed so far (for the 12-character floor). */
  length: () => number;
  /** Same password as another field; paranoid slots are compared inside the worker. */
  sameAs: (other: SecurePasswordHandle | null) => Promise<boolean>;
  /**
   * Hands the password to the worker as a source and empties this field: the
   * normal field's bytes are transferred (and its value cleared at once), a
   * paranoid slot is consumed by the worker and a fresh one is opened.
   */
  take: () => Promise<PasswordSource | null>;
  /** After a wipe: drop local state and open a new slot. */
  reset: () => void;
  /** Internal: the paranoid slot handle, for sameAs. */
  slot: () => string | null;
  mode: PasswordInputMode;
};

type Props = {
  id: string;
  label: string;
  mode: PasswordInputMode;
  autoComplete: "current-password" | "new-password";
  onEnter?: () => void;
  describedBy?: string;
};

const isOneCharacter = (key: string) => Array.from(key).length === 1;

/**
 * Password field for /secure/* documents.
 * - normal: a plain password field (paste and password managers work); its
 *   value is read once, sent to the worker as bytes and cleared immediately.
 * - paranoid (opt-in, H.7): no value at all; every key event's character goes
 *   to a fixed Wasm memory in the crypto worker and only dots are shown. The
 *   browser still creates a short `event.key` string per key, which nobody can
 *   erase; paste and password managers do not work here.
 */
export const SecurePasswordInput = forwardRef<SecurePasswordHandle, Props>(function SecurePasswordInput({ id, label, mode, autoComplete, onEnter, describedBy }, ref) {
  const { t } = useTranslation();
  const input = useRef<HTMLInputElement>(null);
  const slotRef = useRef<string | null>(null);
  const [dots, setDots] = useState(0);
  const [normalLength, setNormalLength] = useState(0);
  const queue = useRef<Promise<unknown>>(Promise.resolve());

  const openSlot = useCallback(async () => {
    const { slot } = await enclave.password.open();
    slotRef.current = slot;
    setDots(0);
    return slot;
  }, []);

  useEffect(() => {
    if (mode !== "paranoid") return;
    void openSlot().catch(() => null);
    return () => {
      const s = slotRef.current;
      slotRef.current = null;
      if (s) void enclave.password.close(s).catch(() => null);
    };
  }, [mode, openSlot]);

  /** Key events run one after another, so the worker sees them in typing order. */
  const enqueue = (job: () => Promise<void>) => {
    queue.current = queue.current.then(job).catch(async (e: unknown) => {
      // The slot was wiped (30 s hidden) or expired: start again with an empty one.
      if ((e as { code?: string } | null)?.code === "unknown_handle") await openSlot().catch(() => null);
    });
  };

  const onParanoidKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Tab") return;
    if (e.key === "Enter") {
      e.preventDefault();
      void queue.current.then(() => onEnter?.());
      return;
    }
    if (e.key === "Backspace") {
      e.preventDefault();
      enqueue(async () => {
        const s = slotRef.current ?? (await openSlot());
        setDots((await enclave.password.backspace(s)).length);
      });
      return;
    }
    if (e.ctrlKey || e.metaKey || !isOneCharacter(e.key)) return;
    e.preventDefault();
    const character = e.key;
    enqueue(async () => {
      const s = slotRef.current ?? (await openSlot());
      setDots((await enclave.password.key(s, character)).length);
    });
  };

  useImperativeHandle(ref, () => ({
    mode,
    slot: () => slotRef.current,
    length: () => (mode === "paranoid" ? dots : normalLength),
    sameAs: async (other) => {
      if (!other || other.mode !== mode) return false;
      if (mode === "normal") {
        const a = input.current?.value ?? "";
        const b = (other as SecurePasswordHandle & { _value?: () => string })._value?.() ?? "";
        return a.length > 0 && a === b;
      }
      await queue.current;
      const a = slotRef.current;
      const b = other.slot();
      if (!a || !b) return false;
      return (await enclave.password.equal(a, b)).equal;
    },
    take: async () => {
      if (mode === "normal") {
        const el = input.current;
        if (!el || !el.value) return null;
        const bytes = new TextEncoder().encode(el.value);
        el.value = "";
        setNormalLength(0);
        return { bytes };
      }
      await queue.current;
      const s = slotRef.current;
      if (!s || dots === 0) return null;
      slotRef.current = null;
      setDots(0);
      // The worker consumes (wipes and closes) this slot; typing again opens a new one.
      void openSlot().catch(() => null);
      return { slot: s };
    },
    reset: () => {
      if (input.current) input.current.value = "";
      setNormalLength(0);
      slotRef.current = null;
      setDots(0);
      if (mode === "paranoid") void openSlot().catch(() => null);
    },
    _value: () => input.current?.value ?? "",
  }) as SecurePasswordHandle, [mode, dots, normalLength, openSlot]);

  return (
    <div className="space-y-1">
      <Label htmlFor={id} className="text-sm">{label}</Label>
      {mode === "normal" ? (
        <Input
          ref={input}
          id={id}
          type="password"
          autoComplete={autoComplete}
          maxLength={256}
          required
          aria-describedby={describedBy}
          onChange={(e) => setNormalLength(Array.from(e.target.value).length)}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); onEnter?.(); } }}
          className="h-11 rounded-lg"
        />
      ) : (
        <div
          id={id}
          role="textbox"
          tabIndex={0}
          aria-label={label}
          aria-describedby={describedBy}
          aria-multiline={false}
          onKeyDown={onParanoidKey}
          onPaste={(e) => e.preventDefault()}
          onDrop={(e) => e.preventDefault()}
          className={cn(
            "flex h-11 w-full items-center rounded-lg border border-input bg-background px-3 font-mono text-base tracking-[0.3em] text-foreground",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          )}
        >
          {dots > 0 ? "•".repeat(Math.min(dots, 64)) : <span className="tracking-normal text-muted-foreground">{t("secure.pw.paranoidPlaceholder")}</span>}
        </div>
      )}
    </div>
  );
});
