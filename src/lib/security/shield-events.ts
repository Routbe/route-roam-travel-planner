/**
 * "A sign-in factor changed" signal for the Veiligheidsschild. Pages that add or
 * remove a passkey or change the ROUT Card fire it after the server confirmed the
 * change, so the shield re-reads the real factors instead of trusting the click.
 */
const EVENT = "rout:security-factors-changed";

export function signalSecurityFactorsChanged(): void {
  if (typeof window !== "undefined") window.dispatchEvent(new Event(EVENT));
}

/** Subscribes; returns the unsubscribe function (always call it on unmount). */
export function onSecurityFactorsChanged(listener: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  window.addEventListener(EVENT, listener);
  return () => window.removeEventListener(EVENT, listener);
}
