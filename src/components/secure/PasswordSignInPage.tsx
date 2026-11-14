import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { opaqueWorker } from "@/lib/auth/opaque-worker";
import { OpaqueClientError, signInWithPassword } from "@/lib/auth/opaque-client";
import { POST_AUTH_PATH, SIGN_IN_PATH } from "@/lib/auth/post-auth";
import { useSecureWipe } from "@/hooks/useSecureWipe";
import { SecureMessage, SecureShell } from "./SecureShell";
import { ParanoidToggle } from "./ParanoidToggle";
import { SecurePasswordInput, type PasswordInputMode, type SecurePasswordHandle } from "./SecurePasswordInput";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** /secure/password: OPAQUE sign-in. Every exit is a full page load. */
export function PasswordSignInPage({ available }: { available: boolean }) {
  const { t } = useTranslation();
  const [email, setEmail] = useState("");
  const [mode, setMode] = useState<PasswordInputMode>("normal");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [wiped, setWiped] = useState(false);
  const field = useRef<SecurePasswordHandle>(null);
  const formRef = useRef<HTMLFormElement>(null);

  // An address handed over by /auth/sign-in travels in the fragment, never to the server.
  useEffect(() => {
    const hash = new URLSearchParams(window.location.hash.slice(1));
    const given = hash.get("email");
    if (given && EMAIL.test(given)) setEmail(given);
    if (window.location.hash) window.history.replaceState(null, "", window.location.pathname);
  }, []);

  const onWiped = useCallback(() => {
    field.current?.reset();
    setWiped(true);
  }, []);
  useSecureWipe(onWiped);

  const submit = async () => {
    if (busy) return;
    setError(null);
    setWiped(false);
    const address = email.trim().toLowerCase();
    if (!EMAIL.test(address)) { setError(t("secure.pw.err.email")); return; }
    if ((field.current?.length() ?? 0) === 0) { setError(t("secure.pw.err.invalid_credentials")); return; }
    const source = await field.current?.take();
    if (!source) return;
    setBusy(true);
    try {
      const result = await signInWithPassword(address, source, opaqueWorker);
      window.location.assign(result.kind === "second_factor" ? `${SIGN_IN_PATH}?second_factor=1` : POST_AUTH_PATH);
    } catch (e) {
      const code = e instanceof OpaqueClientError ? e.code : "failed";
      setError(t(`secure.pw.err.${code}`));
      setBusy(false);
    }
  };

  return (
    <SecureShell title={t("secure.pw.signinTitle")}>
      <p className="text-sm text-muted-foreground">{t("secure.pw.signinBody")}</p>
      {!available ? (
        <SecureMessage tone="error">{t("secure.pw.err.unavailable")}</SecureMessage>
      ) : (
        <form ref={formRef} className="space-y-4" onSubmit={(e) => { e.preventDefault(); void submit(); }} noValidate>
          <div className="space-y-1">
            <Label htmlFor="secure-email" className="text-sm">{t("secure.pw.email")}</Label>
            <Input id="secure-email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} className="h-11 rounded-lg" required />
          </div>
          <SecurePasswordInput key={mode} ref={field} id="secure-password" label={t("secure.pw.password")} mode={mode} autoComplete="current-password" onEnter={() => void submit()} />
          <ParanoidToggle id="secure-paranoid" checked={mode === "paranoid"} onChange={(v) => setMode(v ? "paranoid" : "normal")} />
          {wiped && <SecureMessage>{t("secure.pw.wiped")}</SecureMessage>}
          {error && <SecureMessage tone="error">{error}</SecureMessage>}
          {busy && <SecureMessage>{t("secure.pw.working")}</SecureMessage>}
          <Button type="submit" className="h-11 w-full" disabled={busy}>{t("secure.pw.signinCta")}</Button>
        </form>
      )}
      <p className="text-xs text-muted-foreground">{t("secure.pw.forgot")}</p>
      <a href={SIGN_IN_PATH} className="inline-flex min-h-11 items-center text-sm underline underline-offset-4">{t("secure.pw.otherMethods")}</a>
    </SecureShell>
  );
}
