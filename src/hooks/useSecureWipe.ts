import { useEffect } from "react";
import { abortRunningEnclaveOperation, enclave } from "@/lib/crypto-enclave/client";

/** H.1: a short switch (password manager) keeps the handshake; after this long hidden everything is wiped. */
export const SECURE_HIDDEN_WIPE_MS = 30_000;

/**
 * Wipes the crypto worker's password state on /secure/* documents (owner rule H.1):
 * after 30 s hidden and when the page goes away, a running operation is asked to
 * stop at its next safe point (OperationAborted), then `secure.wipe` runs; it is
 * queued like any request, so it never interrupts a Wasm instruction. `onWiped`
 * lets the page reset paranoid slots and show that it was locked.
 */
export function useSecureWipe(onWiped?: () => void): void {
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | null = null;
    const wipeNow = () => {
      abortRunningEnclaveOperation();
      void enclave.secure.wipe().catch(() => null).then(() => onWiped?.());
    };
    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        if (!timer) timer = setTimeout(() => { timer = null; wipeNow(); }, SECURE_HIDDEN_WIPE_MS);
      } else if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    };
    const onLeave = () => {
      abortRunningEnclaveOperation();
      void enclave.secure.wipe().catch(() => null);
    };
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("pagehide", onLeave);
    return () => {
      if (timer) clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("pagehide", onLeave);
      onLeave();
    };
  }, [onWiped]);
}
