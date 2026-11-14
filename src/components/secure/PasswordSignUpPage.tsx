import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { OpaqueClientError, signUpWithPassword } from "@/lib/auth/opaque-client";
import { opaqueWorker } from "@/lib/auth/opaque-worker";
import { POST_AUTH_PATH } from "@/lib/auth/post-auth";
import { useSecureWipe } from "@/hooks/useSecureWipe";
import { SecureMessage, SecureShell } from "./SecureShell";
import { ParanoidToggle } from "./ParanoidToggle";
import { SecurePasswordInput, type PasswordInputMode, type SecurePasswordHandle } from "./SecurePasswordInput";
import { MIN_PASSWORD_CHARS } from "./PasswordSetPage";

const SIGN_UP_PATH = "/auth/sign-up";
const TICKET = /^su\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * /secure/password/new: finishes a sign-up with a password instead of a passkey.
 * /auth/sign-up hands over its signed ticket (consent, age, e-mail) in the URL
 * fragment, which the browser never sends; the page removes it at once.
 */
export function PasswordSignUpPage({ available }: { available: boolean }) {
  const { t } = useTranslation();
  const [ticket, setTicket] = useState<string | null>(null);
  const [email, setEmail] = useState<string>("");
  const [ready, setReady] = useState(false);
  const [mode, setMode] = useState<PasswordInputMode>("normal");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [wiped, setWiped] = useState(false);
  const first = useRef<SecurePasswordHandle>(null);
  const second = useRef<SecurePasswordHandle>(null);

  useEffect(() => {
    const hash = new URLSearchParams(window.location.hash.slice(1));
    const given = hash.get("ticket");
    if (given && TICKET.test(given) && given.length < 2048) {
      setTicket(given);
      setEmail((hash.get("email") ?? "").slice(0, 254));
    }
    if (window.location.hash) window.history.replaceState(null, "", window.location.pathname);
    setReady(true);
  }, []);

  const onWiped = useCallback(() => {
    first.current?.reset();
    second.current?.reset();
    setWiped(true);
  }, []);
  useSecureWipe(onWiped);

  const submit = async () => {
    if (busy || !ticket) return;
    setError(null);
    setWiped(false);
    if ((first.current?.length() ?? 0) < MIN_PASSWORD_CHARS) { setError(t("secure.pw.err.too_short")); return; }
    if (!(await first.current?.sameAs(second.current))) { setError(t("secure.pw.err.mismatch")); return; }
    const source = await first.current?.take();
    second.current?.reset();
    if (!source) return;
    setBusy(true);
    try {
      await signUpWithPassword(ticket, source, opaqueWorker);
      window.location.assign(POST_AUTH_PATH);
    } catch (e) {
      const code = e instanceof OpaqueClientError ? e.code : "failed";
      setError(t(`secure.pw.err.${code}`));
      setBusy(false);
    }
  };

  const back = <a href={SIGN_UP_PATH} className="inline-flex min-h-11 items-center text-sm underline underline-offset-4">{t("secure.pw.backToSignup")}</a>;

  return (
    <SecureShell title={t("secure.pw.signupTitle")}>
      {!available ? (
        <SecureMessage tone="error">{t("secure.pw.err.unavailable")}</SecureMessage>
      ) : !ready ? null : !ticket ? (
        <SecureMessage tone="error">{t("secure.pw.signupMissing")}</SecureMessage>
      ) : (
        <>
          <p className="text-sm text-muted-foreground">{t("secure.pw.signupBody")}</p>
          {email && <p className="text-sm font-medium break-all">{t("secure.pw.signupFor", { email })}</p>}
          <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); void submit(); }} noValidate>
            <SecurePasswordInput key={`a-${mode}`} ref={first} id="secure-new" label={t("secure.pw.password")} mode={mode} autoComplete="new-password" />
            <SecurePasswordInput key={`b-${mode}`} ref={second} id="secure-repeat" label={t("secure.pw.repeat")} mode={mode} autoComplete="new-password" onEnter={() => void submit()} />
            <ParanoidToggle id="secure-paranoid" checked={mode === "paranoid"} onChange={(v) => setMode(v ? "paranoid" : "normal")} />
            {wiped && <SecureMessage>{t("secure.pw.wiped")}</SecureMessage>}
            {error && <SecureMessage tone="error">{error}</SecureMessage>}
            {busy && <SecureMessage>{t("secure.pw.working")}</SecureMessage>}
            <Button type="submit" className="h-11 w-full" disabled={busy}>{t("secure.pw.signupCta")}</Button>
          </form>
        </>
      )}
      {back}
    </SecureShell>
  );
}
