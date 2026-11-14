import { enclave } from "@/lib/crypto-enclave/client";
import type { OpaqueWorker } from "./opaque-client";

/** The real crypto worker behind opaque-client.ts (tests pass their own). */
export const opaqueWorker: OpaqueWorker = {
  solve: enclave.pow.solve,
  loginStart: enclave.opaque.loginStart,
  loginFinish: enclave.opaque.loginFinish,
  registerStart: enclave.opaque.registerStart,
  registerFinish: enclave.opaque.registerFinish,
  commit: enclave.opaque.commit,
  discard: enclave.opaque.discard,
};
