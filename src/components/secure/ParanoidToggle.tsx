import { useTranslation } from "react-i18next";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";

export function ParanoidToggle({ id, checked, onChange }: { id: string; checked: boolean; onChange: (v: boolean) => void }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-1">
      <div className="flex min-h-11 items-center gap-3">
        <Switch id={id} checked={checked} onCheckedChange={onChange} aria-describedby={`${id}-help`} />
        <Label htmlFor={id} className="text-sm">{t("secure.pw.paranoidToggle")}</Label>
      </div>
      <p id={`${id}-help`} className="text-xs text-muted-foreground">{t("secure.pw.paranoidHelp")}</p>
    </div>
  );
}
