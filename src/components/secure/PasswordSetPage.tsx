import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useServerFn } from "@tanstack/react-start";
import { Button } from "@/components/ui/button";
import { withStepUp } from "@/components/auth/StepUpDialog";
import {
  answerPasswordRegistration,
  beginPasswordRegistration,
  finishPasswordRegistration,
  getPasswordStatus,
  removePassword,
} from "@/lib/auth/opaque-member.functions";
import { OpaqueClientError, serverFailure, setMemberPassword } from "@/lib/auth/opaque-client";
import { opaqueWorker } from "@/lib/auth/opaque-worker";
import { SIGN_IN_PATH } from "@/lib/auth/post-auth";
import { useSecureWipe } from "@/hooks/useSecureWipe";
import { SecureMessage, SecureShell } from "./SecureShell";
import { ParanoidToggle } from "./ParanoidToggle";
import { SecurePasswordInput, type PasswordInputMode, type SecurePasswordHandle } from "./SecurePasswordInput";

export const ACCOUNT_PATH = "/studio/account";
export const MIN_PASSWORD_CHARS = 12;
type Status = { available: boolean; passkey: boolean; hasPassword: boolean };

/** /secure/password/set: a signed-in member sets, replaces or removes their password. */
export function PasswordSetPage() {
  const { t } = useTranslation();
  const status = useServerFn(getPasswordStatus);
  const begin = useServerFn(beginPasswordRegistration);
  const answer = useServerFn(answerPasswordRegistration);
  const finish = useServerFn(finishPasswordRegistration);
  const remove = useServerFn(removePassword);
  const [state, setState] = useState<Status | "loading" | "signed_out">("loading");
  const [mode, setMode] = useState<PasswordInputMode>("normal");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [wiped, setWiped] = useState(false);
  const first = useRef<SecurePasswordHandle>(null);
  const second = useRef<SecurePasswordHandle>(null);

  const load = useCallback(async () => {
    try {
      setState(await status());
    } catch (e) {
      setState((e as { statusCode?: number } | null)?.statusCode === 401 || /Unauthorized/.test(String((e as Error)?.message)) ? "signed_out" : { available: false, passkey: false, hasPassword: false });
    }
  }, [status]);
  useEffect(() => { void load(); }, [load]);

  const onWiped = useCallback(() => {
    first.current?.reset();
    second.current?.reset();
    setWiped(true);
  }, []);
  useSecureWipe(onWiped);

  const failure = (e: unknown) => {
    const code = e instanceof OpaqueClientError ? e.code : "failed";
    setError(t(`secure.pw.err.${code}`));
  };

  const save = async () => {
    if (busy) return;
    setError(null);
    setNotice(null);
    setWiped(false);
    if ((first.current?.length() ?? 0) < MIN_PASSWORD_CHARS) { setError(t("secure.pw.err.too_short")); return; }
    if (!(await first.current?.sameAs(second.current))) { setError(t("secure.pw.err.mismatch")); return; }
    const source = await first.current?.take();
    second.current?.reset();
    if (!source) return;
    setBusy(true);
    try {
      await setMemberPassword(source, opaqueWorker, {
        begin: () => begin(),
        answer: (data) => answer({ data }),
        // The passkey confirmation is asked only here, after the upload validated.
        finish: (data) => withStepUp(() => finish({ data }), "password_set"),
      });
      setNotice(t("secure.pw.saved"));
      await load();
    } catch (e) {
      failure(e);
    } finally {
      setBusy(false);
    }
  };

  const drop = async () => {
    if (busy) return;
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const r = await withStepUp(() => remove(), "password_set");
      if (!r.ok) throw serverFailure(r.error);
      setNotice(t("secure.pw.removed"));
      await load();
    } catch (e) {
      failure(e);
    } finally {
      setBusy(false);
    }
  };

  const back = <a href={ACCOUNT_PATH} className="inline-flex min-h-11 items-center text-sm underline underline-offset-4">{t("secure.pw.toAccount")}</a>;

  if (state === "loading") return <SecureShell title={t("secure.pw.setTitle")}><SecureMessage>{t("secure.pw.working")}</SecureMessage></SecureShell>;
  if (state === "signed_out") {
    return (
      <SecureShell title={t("secure.pw.setTitle")}>
        <SecureMessage>{t("secure.pw.signedOut")}</SecureMessage>
        <a href={`${SIGN_IN_PATH}?next=${encodeURIComponent("/secure/password/set")}`} className="inline-flex min-h-11 items-center text-sm underline underline-offset-4">{t("secure.pw.toSignIn")}</a>
      </SecureShell>
    );
  }
  if (!state.available) return <SecureShell title={t("secure.pw.setTitle")}><SecureMessage tone="error">{t("secure.pw.err.unavailable")}</SecureMessage>{back}</SecureShell>;
  if (!state.passkey) return <SecureShell title={t("secure.pw.setTitle")}><SecureMessage>{t("secure.pw.needPasskey")}</SecureMessage>{back}</SecureShell>;

  return (
    <SecureShell title={t("secure.pw.setTitle")}>
      <p className="text-sm text-muted-foreground">{state.hasPassword ? t("secure.pw.setBodyHas") : t("secure.pw.setBodyNew")}</p>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); void save(); }} noValidate>
        <SecurePasswordInput key={`a-${mode}`} ref={first} id="secure-new" label={t("secure.pw.newPassword")} mode={mode} autoComplete="new-password" />
        <SecurePasswordInput key={`b-${mode}`} ref={second} id="secure-repeat" label={t("secure.pw.repeat")} mode={mode} autoComplete="new-password" onEnter={() => void save()} />
        <ParanoidToggle id="secure-paranoid" checked={mode === "paranoid"} onChange={(v) => setMode(v ? "paranoid" : "normal")} />
        {wiped && <SecureMessage>{t("secure.pw.wiped")}</SecureMessage>}
        {error && <SecureMessage tone="error">{error}</SecureMessage>}
        {notice && <SecureMessage tone="success">{notice}</SecureMessage>}
        {busy && <SecureMessage>{t("secure.pw.working")}</SecureMessage>}
        <Button type="submit" className="h-11 w-full" disabled={busy}>{t("secure.pw.setCta")}</Button>
        {state.hasPassword && (
          <Button type="button" variant="outline" className="h-11 w-full" disabled={busy} onClick={() => void drop()}>{t("secure.pw.removeCta")}</Button>
        )}
      </form>
      {back}
    </SecureShell>
  );
}
