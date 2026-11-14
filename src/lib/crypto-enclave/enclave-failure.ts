import type { EnclaveErrorCode } from "./protocol";

export class EnclaveFailure extends Error {
  constructor(readonly code: EnclaveErrorCode) {
    super(code);
  }
}

export const fail = (code: EnclaveErrorCode): never => {
  throw new EnclaveFailure(code);
};
