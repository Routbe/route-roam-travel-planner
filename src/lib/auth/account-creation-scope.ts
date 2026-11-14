import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Account creation only through a verified first sign-in method.
 *
 * A Better Auth user row may only be created while
 *   - a verified first-passkey ceremony (signed sign-up ticket) is finalising, or
 *   - an OPAQUE password registration (RFC 9807, same signed sign-up ticket) is
 *     finalising: the password never reached the server, only its OPAQUE record.
 * Every other path — e-mail sign-up, plain password, magic link, social/OIDC
 * callbacks, plugins — is refused by the `user.create.before` database hook in
 * better-auth.server.ts.
 */
type Via = "passkey-signup" | "opaque-signup";
const scope = new AsyncLocalStorage<{ via: Via }>();

export function runPasskeyAccountCreation<T>(fn: () => Promise<T>): Promise<T> {
  return scope.run({ via: "passkey-signup" }, fn);
}

export function runOpaqueAccountCreation<T>(fn: () => Promise<T>): Promise<T> {
  return scope.run({ via: "opaque-signup" }, fn);
}

export function isPasskeyAccountCreation(): boolean {
  return scope.getStore()?.via === "passkey-signup";
}

/** True only inside one of the two approved creation scopes. */
export function isApprovedAccountCreation(): boolean {
  const via = scope.getStore()?.via;
  return via === "passkey-signup" || via === "opaque-signup";
}

export const PASSKEY_SIGNUP_REQUIRED = "passkey_signup_required";
