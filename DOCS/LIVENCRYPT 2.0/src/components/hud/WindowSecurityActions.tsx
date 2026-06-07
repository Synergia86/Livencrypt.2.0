import { useEffect, useState } from "react";
import invoke from "../../invoke";
import { useTranslation } from "../../context/LanguageContext";
import {
  DESTRUCTIVE_PANIC_STORAGE_KEY,
  SECURITY_SETTINGS_CHANGED_EVENT,
  readBooleanSetting,
} from "../../securitySettings";

interface Props {
  onError?: (error: string) => void;
}

export default function WindowSecurityActions({ onError }: Props) {
  const { t } = useTranslation();
  const [destructiveEnabled, setDestructiveEnabled] = useState(() =>
    readBooleanSetting(DESTRUCTIVE_PANIC_STORAGE_KEY),
  );
  const [destructiveLoading, setDestructiveLoading] = useState(false);

  useEffect(() => {
    const refresh = () => setDestructiveEnabled(readBooleanSetting(DESTRUCTIVE_PANIC_STORAGE_KEY));
    window.addEventListener("storage", refresh);
    window.addEventListener(SECURITY_SETTINGS_CHANGED_EVENT, refresh);
    return () => {
      window.removeEventListener("storage", refresh);
      window.removeEventListener(SECURITY_SETTINGS_CHANGED_EVENT, refresh);
    };
  }, []);

  const reportError = (error: unknown) => {
    onError?.(String(error));
  };

  const handlePanic = async () => {
    if (!invoke) return;
    try {
      await invoke("panic_wipe_and_exit");
    } catch (error) {
      reportError(error);
    }
  };

  const handleDestructivePanic = async () => {
    if (!invoke || !destructiveEnabled) return;
    try {
      setDestructiveLoading(true);
      await invoke("destructive_wipe_and_exit", {
        confirmation: "DESTRUIR VAULT Y PLANTILLAS",
      });
    } catch (error) {
      setDestructiveLoading(false);
      reportError(error);
    }
  };

  return (
    <div className="flex items-center gap-2">
      <button
        type="button"
        disabled={!invoke}
        onClick={() => void handlePanic()}
        className="px-3 py-1.5 rounded border border-rose-600/50 bg-rose-950/20 text-rose-400 font-bold text-[9px] hover:bg-rose-900/40 hover:scale-105 transition-all cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
        title={t("dashboard.panicTitle")}
      >
        ⚠️ {t("dashboard.panic")}
      </button>
      {destructiveEnabled ? (
        <button
          type="button"
          disabled={!invoke || destructiveLoading}
          onClick={() => void handleDestructivePanic()}
          className="px-3 py-1.5 rounded border border-sky-500/50 bg-sky-950/20 text-sky-300 font-black text-[9px] hover:bg-sky-900/40 hover:scale-105 transition-all cursor-pointer disabled:cursor-wait disabled:opacity-60"
          title={t("dashboard.helpTitle")}
          aria-label={t("dashboard.helpTitle")}
        >
          ? {t("dashboard.help")}
        </button>
      ) : null}
    </div>
  );
}
