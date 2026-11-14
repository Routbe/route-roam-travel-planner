/**
 * Cooperative abort for the operation the worker is running (owner rule H.1).
 *
 * The UI posts `{ control: "abort", id }` outside the ordered queue; a
 * long-running handler polls `shouldStop()` between steps (never inside a
 * Wasm call or a hash), stops with `aborted` and wipes in its `finally`.
 * An abort aimed at an operation that already finished is ignored.
 */
let current: number | null = null;
let abortedId: number | null = null;

export function beginOperation(id: number | null): void {
  current = id;
  if (abortedId !== id) abortedId = null;
}

export function endOperation(id: number | null): void {
  if (current === id) current = null;
  if (abortedId === id) abortedId = null;
}

export function requestAbort(id: unknown): void {
  if (typeof id === "number" && Number.isSafeInteger(id) && id === current) abortedId = id;
}

export function shouldStop(): boolean {
  return current !== null && abortedId === current;
}

/** Lets queued control messages (an abort) run between batches of work. */
export const yieldToEvents = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));
