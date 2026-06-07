// SPDX-License-Identifier: GPL-3.0-or-later

import { useEffect, useMemo, useState } from "react";
import ReactDOM from "react-dom/client";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/700.css";
import "@fontsource/jetbrains-mono/800.css";
import "@fontsource/noto-sans-sc/chinese-simplified-400.css";
import "@fontsource/noto-sans-sc/chinese-simplified-700.css";
import "@fontsource/noto-sans-sc/chinese-simplified-800.css";
import "@fontsource/noto-sans-sc/chinese-simplified-900.css";
import "@fontsource/noto-sans-jp/japanese-400.css";
import "@fontsource/noto-sans-jp/japanese-700.css";
import "@fontsource/noto-sans-jp/japanese-800.css";
import "@fontsource/noto-sans-jp/japanese-900.css";
import "@fontsource/noto-sans-kr/korean-400.css";
import "@fontsource/noto-sans-kr/korean-700.css";
import "@fontsource/noto-sans-kr/korean-800.css";
import "@fontsource/noto-sans-kr/korean-900.css";
import "@fontsource/noto-sans-arabic/arabic-400.css";
import "@fontsource/noto-sans-arabic/arabic-700.css";
import "@fontsource/noto-sans-arabic/arabic-800.css";
import "@fontsource/noto-sans-arabic/arabic-900.css";
import "@fontsource/noto-sans-armenian/armenian-400.css";
import "@fontsource/noto-sans-armenian/armenian-700.css";
import "@fontsource/noto-sans-armenian/armenian-800.css";
import "@fontsource/noto-sans-armenian/armenian-900.css";
import "@fontsource/noto-sans-bengali/bengali-400.css";
import "@fontsource/noto-sans-bengali/bengali-700.css";
import "@fontsource/noto-sans-bengali/bengali-800.css";
import "@fontsource/noto-sans-bengali/bengali-900.css";
import "@fontsource/noto-sans-myanmar/myanmar-400.css";
import "@fontsource/noto-sans-myanmar/myanmar-700.css";
import "@fontsource/noto-sans-myanmar/myanmar-800.css";
import "@fontsource/noto-sans-myanmar/myanmar-900.css";
import "@fontsource/noto-sans-cherokee/cherokee-400.css";
import "@fontsource/noto-sans-cherokee/cherokee-700.css";
import "@fontsource/noto-sans-cherokee/cherokee-800.css";
import "@fontsource/noto-sans-cherokee/cherokee-900.css";
import "@fontsource/noto-sans-devanagari/devanagari-400.css";
import "@fontsource/noto-sans-devanagari/devanagari-700.css";
import "@fontsource/noto-sans-devanagari/devanagari-800.css";
import "@fontsource/noto-sans-devanagari/devanagari-900.css";
import "@fontsource/noto-sans-ethiopic/ethiopic-400.css";
import "@fontsource/noto-sans-ethiopic/ethiopic-700.css";
import "@fontsource/noto-sans-ethiopic/ethiopic-800.css";
import "@fontsource/noto-sans-ethiopic/ethiopic-900.css";
import "@fontsource/noto-sans-georgian/georgian-400.css";
import "@fontsource/noto-sans-georgian/georgian-700.css";
import "@fontsource/noto-sans-georgian/georgian-800.css";
import "@fontsource/noto-sans-georgian/georgian-900.css";
import "@fontsource/noto-sans-kannada/kannada-400.css";
import "@fontsource/noto-sans-kannada/kannada-700.css";
import "@fontsource/noto-sans-kannada/kannada-800.css";
import "@fontsource/noto-sans-kannada/kannada-900.css";
import "@fontsource/noto-sans-khmer/khmer-400.css";
import "@fontsource/noto-sans-khmer/khmer-700.css";
import "@fontsource/noto-sans-khmer/khmer-800.css";
import "@fontsource/noto-sans-khmer/khmer-900.css";
import "@fontsource/noto-sans-thai/thai-400.css";
import "@fontsource/noto-sans-thai/thai-700.css";
import "@fontsource/noto-sans-thai/thai-800.css";
import "@fontsource/noto-sans-thai/thai-900.css";
import "@fontsource/noto-sans-sinhala/sinhala-400.css";
import "@fontsource/noto-sans-sinhala/sinhala-700.css";
import "@fontsource/noto-sans-sinhala/sinhala-800.css";
import "@fontsource/noto-sans-sinhala/sinhala-900.css";
import "@fontsource/noto-serif-tibetan/tibetan-400.css";
import "@fontsource/noto-serif-tibetan/tibetan-700.css";
import "@fontsource/noto-serif-tibetan/tibetan-800.css";
import "@fontsource/noto-serif-tibetan/tibetan-900.css";
import "@fontsource/noto-sans-symbols/symbols-400.css";
import "@fontsource/noto-sans-symbols/symbols-700.css";
import "@fontsource/noto-sans-symbols/symbols-800.css";
import "@fontsource/noto-sans-symbols/symbols-900.css";
import "@fontsource/noto-sans-symbols-2/symbols-400.css";
import "./index.css";
import type { TemplateData } from "./components/dashboard/TemplateSelector";
import LivencryptIcon from "./components/hud/LivencryptIcon";
import WindowSecurityActions from "./components/hud/WindowSecurityActions";
import FileCipherWindow from "./pages/FileCipherWindow";
import TemplateEditorWindow from "./pages/TemplateEditorWindow";
import TextCipherWindow from "./pages/TextCipherWindow";
import invoke from "./invoke";
import { LanguageProvider, useTranslation } from "./context/LanguageContext";
import { SUPPORTED_LANGUAGES, type Language } from "./i18n";
import { parseBootCajas } from "./i18n/numerals";
import {
  DESTRUCTIVE_PANIC_STORAGE_KEY,
  INACTIVITY_CLOSE_ENABLED_KEY,
  INACTIVITY_CLOSE_SECONDS_KEY,
  SECURITY_SETTINGS_CHANGED_EVENT,
  readBooleanSetting,
  readNumberSetting,
  writeBooleanSetting,
  writeNumberSetting,
} from "./securitySettings";

type TemplateEntry = { name: string; data: TemplateData };
type ToolLabel = "text-cipher" | "file-cipher" | "template-editor";
type BootShieldStatus = {
  state: "not_configured" | "locked" | "unlocked";
  network_profile: string;
  credential_mode: "single" | "double";
};

type ProcessHardeningStatus = {
  core_dumps_disabled: boolean;
  dumpable_disabled: boolean;
  dumpable_requested: boolean;
  mlockall_applied: boolean;
  mlockall_requested: boolean;
  running_as_root: boolean;
  ld_preload_present: boolean;
  binary_sha256: string;
  expected_sha256: string | null;
  binary_integrity_ok: boolean | null;
  warnings: string[];
};

const LANGUAGE_FLAGS: Record<Language, string> = {
  es: "🇪🇸",
  en: "🇬🇧",
  zh: "🇨🇳",
  ru: "🇷🇺",
  pt: "🇵🇹",
  de: "🇩🇪",
  fr: "🇫🇷",
  hi: "🇮🇳",
  ja: "🇯🇵",
  ko: "🇰🇷",
  id: "🇮🇩",
};

const LANGUAGE_KEYS: Record<Language, string> = {
  es: "spanish",
  en: "english",
  zh: "chinese",
  ru: "russian",
  pt: "portuguese",
  de: "german",
  fr: "french",
  hi: "hindi",
  ja: "japanese",
  ko: "korean",
  id: "indonesian",
};

function normalizeHash() {
  return window.location.hash.replace(/^#\/?/, "");
}

function useHashRoute() {
  const [hash, setHash] = useState(normalizeHash);

  useEffect(() => {
    const handleHashChange = () => setHash(normalizeHash());
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  return hash;
}

function useTemplates(bootState: BootShieldStatus["state"] | "loading") {
  const [templates, setTemplates] = useState<TemplateEntry[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    if (bootState === "loading" || bootState === "locked") {
      setTemplates([]);
      setError("");
      return;
    }

    if (!invoke) {
      setError("Bridge Tauri no disponible");
      return;
    }

    invoke("load_templates")
      .then((value: unknown) => {
        const loaded = value as Record<string, TemplateData>;
        setTemplates(Object.entries(loaded).map(([name, data]) => ({ name, data })));
        setError("");
      })
      .catch((cause: unknown) => setError(String(cause)));
  }, [bootState]);

  const selectedTemplate = useMemo(() => templates[0] ?? null, [templates]);
  return { templates, selectedTemplate, error };
}

function parseCajas(values: string[], t: (path: string) => string) {
  return parseBootCajas(values, {
    missing: t("boot.missingBoxes"),
    numeric: t("boot.numericBoxes"),
    range: t("boot.boxRange"),
  });
}

function LanguageFlagSelector() {
  const { language, setLanguage, t } = useTranslation();
  const [open, setOpen] = useState(false);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="min-w-10 px-2.5 py-1.5 rounded border border-cyan-900/40 bg-slate-950 text-base leading-none hover:border-cyan-500/50 hover:bg-cyan-950/20 transition-all cursor-pointer"
        title={t("settings.languageSelect")}
        aria-label={t("settings.languageSelect")}
      >
        {LANGUAGE_FLAGS[language]}
      </button>
      {open ? (
        <div className="absolute right-0 top-full z-50 mt-2 w-44 rounded-lg border border-cyan-900/40 bg-slate-950 p-1 shadow-2xl">
          {SUPPORTED_LANGUAGES.map((item) => (
            <button
              key={item}
              type="button"
              onClick={() => {
                setLanguage(item);
                setOpen(false);
              }}
              className={`flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-[10px] font-bold uppercase transition-all ${
                item === language
                  ? "bg-cyan-950/40 text-cyan-300"
                  : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
              }`}
            >
              <span className="text-base leading-none">{LANGUAGE_FLAGS[item]}</span>
              <span>{t(`language.${LANGUAGE_KEYS[item]}`)}</span>
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function LockScreen({
  credentialMode,
  onUnlock,
}: {
  credentialMode: BootShieldStatus["credential_mode"];
  onUnlock: (status: BootShieldStatus) => void | Promise<void>;
}) {
  const { t } = useTranslation();
  const [c1, setC1] = useState("");
  const [c2, setC2] = useState("");
  const [c3, setC3] = useState("");
  const [c4, setC4] = useState("");
  const [c5, setC5] = useState("");
  const [frase, setFrase] = useState("");
  const [s2c1, setS2c1] = useState("");
  const [s2c2, setS2c2] = useState("");
  const [s2c3, setS2c3] = useState("");
  const [s2c4, setS2c4] = useState("");
  const [s2c5, setS2c5] = useState("");
  const [frase2, setFrase2] = useState("");
  const [errorMsg, setErrorMsg] = useState("");
  const [resetOpen, setResetOpen] = useState(false);
  const [resetConfirmation, setResetConfirmation] = useState("");
  const [resetLoading, setResetLoading] = useState(false);
  const initialLockLogs = useMemo(
    () => [
      t("boot.logInit"),
      t("boot.logShieldDetected"),
      t("boot.logEncryptedAccess"),
      t("boot.logEnterSequence"),
    ],
    [t]
  );
  const [logs, setLogs] = useState<string[]>(initialLockLogs);

  const [networkDisabled, setNetworkDisabled] = useState(false);
  const [networkLoading, setNetworkLoading] = useState(false);

  useEffect(() => {
    setLogs(initialLockLogs);
  }, [initialLockLogs]);

  const clearUnlockFields = () => {
    setC1("");
    setC2("");
    setC3("");
    setC4("");
    setC5("");
    setFrase("");
    setS2c1("");
    setS2c2("");
    setS2c3("");
    setS2c4("");
    setS2c5("");
    setFrase2("");
  };

  useEffect(() => {
    const clearOnBlur = () => clearUnlockFields();
    const clearOnVisibility = () => {
      if (document.visibilityState !== "visible") clearUnlockFields();
    };
    window.addEventListener("blur", clearOnBlur);
    document.addEventListener("visibilitychange", clearOnVisibility);
    return () => {
      window.removeEventListener("blur", clearOnBlur);
      document.removeEventListener("visibilitychange", clearOnVisibility);
    };
  }, []);

  const handleToggleNetwork = async () => {
    if (!invoke) return;
    try {
      setNetworkLoading(true);
      setErrorMsg("");
      const isOnline: any = await invoke("toggle_network", { disable: !networkDisabled });
      setNetworkDisabled(!isOnline);
      setLogs((prev) => [
        ...prev,
        t("boot.logNetworkChanged", { state: !isOnline ? "OFFLINE (AIR-GAP)" : "ONLINE" })
      ]);
    } catch (error) {
      setErrorMsg(String(error));
    } finally {
      setNetworkLoading(false);
    }
  };

  const handlePanic = async () => {
    if (!invoke) return;
    try {
      await invoke("panic_wipe_and_exit");
    } catch (error) {
      setErrorMsg(String(error));
    }
  };

  const handleUnlock = async () => {
    if (!invoke) return;

    try {
      const cajas = parseCajas([c1, c2, c3, c4, c5], t);
      if (!frase.trim()) {
        throw new Error(t("boot.emptyPhrase"));
      }
      const secondaryRequired = credentialMode === "double";
      const secondaryCajas = secondaryRequired ? parseCajas([s2c1, s2c2, s2c3, s2c4, s2c5], t) : null;
      if (secondaryRequired && !frase2.trim()) {
        throw new Error(t("boot.emptySecondaryPhrase"));
      }
      const status = (await invoke("boot_shield_unlock", {
        cajas,
        frase: frase.trim(),
        secondaryCajas,
        secondaryFrase: secondaryRequired ? frase2.trim() : null,
      })) as BootShieldStatus;
      setLogs((prev) => [
        ...prev,
        t("boot.logSuccessKeys"),
        t("boot.logDecrypting"),
        t("boot.logGranted")
      ]);
      setErrorMsg("");
      await onUnlock(status);
    } catch {
      setErrorMsg(t("boot.invalidCredentials"));
      setLogs((prev) => [
        ...prev,
        t("boot.logRejected")
      ]);
    } finally {
      clearUnlockFields();
    }
  };

  const handleFactoryReset = async () => {
    if (!invoke) return;

    try {
      setResetLoading(true);
      setErrorMsg("");
      await invoke("boot_shield_factory_reset", { confirmation: resetConfirmation });
      setLogs((prev) => [
        ...prev,
        t("boot.logReset")
      ]);
      await invoke("panic_wipe_and_exit");
    } catch (error) {
      setErrorMsg(String(error));
    } finally {
      setResetLoading(false);
      setResetConfirmation("");
    }
  };

  return (
    <main className="min-h-screen bg-[#020617] text-cyan-300 font-mono flex flex-col">
      {/* Encabezado Útil de Seguridad en la Pantalla de Bloqueo */}
      <header className="flex items-center justify-between border-b border-red-950/40 bg-slate-950/50 px-6 py-4 flex-shrink-0">
        <div className="flex items-center gap-3">
          <span className="text-lg">🔒</span>
          <div>
            <h1 className="text-xs font-black tracking-[0.25em] text-red-500 uppercase">{t("boot.title")}</h1>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {invoke && (
            <>
              <button
                type="button"
                disabled={networkLoading}
                onClick={handleToggleNetwork}
                className={`px-3 py-1.5 rounded border text-[9px] font-bold transition-all hover:scale-105 cursor-pointer ${
                  networkDisabled
                    ? "border-red-500/40 text-red-400 bg-red-950/20 hover:bg-red-900/30"
                    : "border-emerald-500/40 text-emerald-400 bg-emerald-950/20 hover:bg-emerald-900/30"
                }`}
                title={networkDisabled ? "Activar conexión a Internet" : "Desactivar conexión a Internet (Air-Gap seguro)"}
              >
                🌐 {t("dashboard.network")}: {networkDisabled ? t("dashboard.offline") : t("dashboard.online")}
              </button>
              <button
                type="button"
                onClick={handlePanic}
                className="px-3 py-1.5 rounded border border-rose-600/50 bg-rose-950/20 text-rose-400 font-bold text-[9px] hover:bg-rose-900/40 hover:scale-105 transition-all cursor-pointer"
                title="Cerrar la aplicación inmediatamente"
              >
                ⚠️ {t("dashboard.panic")}
              </button>
            </>
          )}
        </div>
      </header>

      <div className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-xl border border-red-900/40 bg-slate-950/80 rounded-xl p-6 shadow-2xl backdrop-blur-md">
          <div className="text-center mb-6 border-b border-red-950 pb-4">
            <span className="text-[28px] block mb-2">🔑</span>
            <h2 className="text-xs font-black tracking-[0.2em] text-slate-300 uppercase">{t("boot.secureUnlockTitle")}</h2>
            <p className="text-[9px] text-slate-500 mt-1 uppercase">{t("boot.secureUnlockSubtitle")}</p>
          </div>

          <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-900 h-[110px] overflow-y-auto text-[8px] text-slate-400 space-y-1 mb-5">
            {logs.map((l, idx) => (
              <div key={idx} className={l.includes("[SUCCESS]") ? "text-emerald-400" : l.includes("[FATAL]") || l.includes("[WARN]") ? "text-red-400" : ""}>
                {l}
              </div>
            ))}
          </div>

          <div className="space-y-4">
            <div>
              <label className="text-[9px] font-bold block mb-1 text-slate-400 uppercase">{t("boot.boxes")}</label>
              <div className="grid grid-cols-5 gap-2">
                {[
                  { value: c1, setter: setC1 },
                  { value: c2, setter: setC2 },
                  { value: c3, setter: setC3 },
                  { value: c4, setter: setC4 },
                  { value: c5, setter: setC5 },
                ].map(({ value, setter }, idx) => (
                  <input
                    key={idx}
                    type="text"
                    inputMode="text"
                    placeholder={t("boot.primaryBoxPlaceholder", { index: idx + 1 })}
                    value={value}
                    onChange={(e) => setter(e.target.value)}
                    onCopy={(event) => event.preventDefault()}
                    onCut={(event) => event.preventDefault()}
                    onPaste={(event) => event.preventDefault()}
                    onContextMenu={(event) => event.preventDefault()}
                    className="bg-slate-950 border border-red-950/60 rounded text-center py-1.5 text-xs font-bold text-slate-200 outline-none focus:border-red-500 transition-all"
                  />
                ))}
              </div>
            </div>

            <div>
              <label className="text-[9px] font-bold block mb-1 text-slate-400 uppercase">{t("boot.accessPhrase")}</label>
              <input
                type="password"
                placeholder={t("boot.accessPhrasePlaceholder")}
                value={frase}
                onChange={(e) => setFrase(e.target.value)}
                onCopy={(event) => event.preventDefault()}
                onCut={(event) => event.preventDefault()}
                onPaste={(event) => event.preventDefault()}
                onContextMenu={(event) => event.preventDefault()}
                className="w-full bg-slate-950 border border-red-950/60 rounded px-3 py-2 text-xs text-slate-200 outline-none focus:border-red-500 transition-all"
              />
            </div>

            {credentialMode === "double" && (
              <div className="border-t border-red-950/60 pt-4 space-y-4">
                <div>
                  <label className="text-[9px] font-bold block mb-1 text-slate-400 uppercase">{t("boot.secondaryBoxes")}</label>
                  <div className="grid grid-cols-5 gap-2">
                    {[
                      { value: s2c1, setter: setS2c1 },
                      { value: s2c2, setter: setS2c2 },
                      { value: s2c3, setter: setS2c3 },
                      { value: s2c4, setter: setS2c4 },
                      { value: s2c5, setter: setS2c5 },
                    ].map(({ value, setter }, idx) => (
                      <input
                        key={idx}
                        type="text"
                        inputMode="text"
                        placeholder={t("boot.secondaryBoxPlaceholder", { index: idx + 1 })}
                        value={value}
                        onChange={(e) => setter(e.target.value)}
                        onCopy={(event) => event.preventDefault()}
                        onCut={(event) => event.preventDefault()}
                        onPaste={(event) => event.preventDefault()}
                        onContextMenu={(event) => event.preventDefault()}
                        className="bg-slate-950 border border-red-950/60 rounded text-center py-1.5 text-xs font-bold text-slate-200 outline-none focus:border-red-500 transition-all"
                      />
                    ))}
                  </div>
                </div>

                <div>
                  <label className="text-[9px] font-bold block mb-1 text-slate-400 uppercase">{t("boot.secondaryPhrase")}</label>
                  <input
                    type="password"
                    placeholder={t("boot.secondaryPhrasePlaceholder")}
                    value={frase2}
                    onChange={(e) => setFrase2(e.target.value)}
                    onCopy={(event) => event.preventDefault()}
                    onCut={(event) => event.preventDefault()}
                    onPaste={(event) => event.preventDefault()}
                    onContextMenu={(event) => event.preventDefault()}
                    className="w-full bg-slate-950 border border-red-950/60 rounded px-3 py-2 text-xs text-slate-200 outline-none focus:border-red-500 transition-all"
                  />
                </div>
              </div>
            )}

            {errorMsg && (
              <div className="border border-red-600/40 bg-red-950/20 text-red-400 rounded p-2 text-center text-[9px] font-bold uppercase tracking-wider">
                ⚠️ {errorMsg}
              </div>
            )}

            <button
              onClick={handleUnlock}
              className="w-full py-2.5 bg-red-950/30 hover:bg-red-900/30 border border-red-500/40 hover:border-red-500 text-red-400 hover:text-red-300 font-black uppercase text-[10px] rounded transition-all cursor-pointer hover:scale-[1.01]"
            >
              {t("boot.unlock")}
            </button>

            <button
              type="button"
              onClick={() => {
                setResetOpen((value) => !value);
                setResetConfirmation("");
              }}
              className="w-full py-2 border border-slate-800 bg-slate-950/70 hover:bg-slate-900 text-slate-500 hover:text-slate-300 font-bold uppercase text-[9px] rounded transition-all cursor-pointer"
            >
              {t("boot.resetInstall")}
            </button>

            {resetOpen && (
              <div className="border border-amber-600/40 bg-amber-950/10 rounded p-3 space-y-2">
                <p className="text-[8px] text-amber-300 uppercase leading-4">
                  {t("boot.resetWarning")}
                </p>
                <input
                  type="text"
                  value={resetConfirmation}
                  onChange={(event) => setResetConfirmation(event.target.value)}
                  placeholder={t("boot.resetConfirm")}
                  className="w-full bg-slate-950 border border-amber-900/60 rounded px-3 py-2 text-xs text-amber-100 outline-none focus:border-amber-500 transition-all"
                />
                <button
                  type="button"
                  disabled={resetLoading || resetConfirmation.trim() !== "RESTABLECER"}
                  onClick={() => void handleFactoryReset()}
                  className="w-full py-2 bg-amber-950/30 hover:bg-amber-900/30 border border-amber-500/40 text-amber-300 disabled:opacity-40 disabled:cursor-not-allowed font-black uppercase text-[9px] rounded transition-all cursor-pointer"
                >
                  {t("boot.resetAndClose")}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </main>
  );
}

function Launcher({
  bootStatus,
  refreshBootStatus,
  templates,
  hardeningStatus,
  inactivityCloseEnabled,
  setInactivityCloseEnabled,
  inactivityCloseSeconds,
  setInactivityCloseSeconds,
}: {
  bootStatus: BootShieldStatus;
  refreshBootStatus: () => Promise<void>;
  templates: TemplateEntry[];
  hardeningStatus: ProcessHardeningStatus | null;
  inactivityCloseEnabled: boolean;
  setInactivityCloseEnabled: (value: boolean) => void;
  inactivityCloseSeconds: number;
  setInactivityCloseSeconds: (value: number) => void;
}) {
  const { t } = useTranslation();
  const [launchError, setLaunchError] = useState("");
  const [networkDisabled, setNetworkDisabled] = useState(false);
  const [networkLoading, setNetworkLoading] = useState(false);
  const [configOpen, setConfigOpen] = useState(false);
  const [settingShield, setSettingShield] = useState(false);
  const [shieldProcessing, setShieldProcessing] = useState(false);
  const [networkProfile, setNetworkProfile] = useState(bootStatus.network_profile || "mock");
  const [networkConfirmation, setNetworkConfirmation] = useState("");
  const [bootTemplateName, setBootTemplateName] = useState("Livencrypt");
  const [destructivePanicEnabled, setDestructivePanicEnabled] = useState(() => {
    return readBooleanSetting(DESTRUCTIVE_PANIC_STORAGE_KEY);
  });
  const [closeNoticeOpen, setCloseNoticeOpen] = useState(false);
  const [closeNoticeLoading, setCloseNoticeLoading] = useState(false);
  const shieldActive = bootStatus.state !== "not_configured";

  // Variables de configuración de la firma
  const [sc1, setSc1] = useState("");
  const [sc2, setSc2] = useState("");
  const [sc3, setSc3] = useState("");
  const [sc4, setSc4] = useState("");
  const [sc5, setSc5] = useState("");
  const [sFrase, setSFrase] = useState("");
  const [doubleCredential, setDoubleCredential] = useState(true);
  const [s2c1, setS2c1] = useState("");
  const [s2c2, setS2c2] = useState("");
  const [s2c3, setS2c3] = useState("");
  const [s2c4, setS2c4] = useState("");
  const [s2c5, setS2c5] = useState("");
  const [sFrase2, setSFrase2] = useState("");
  const toolRoutes = useMemo(
    () => [
      {
        label: "text-cipher" as const,
        title: t("tools.textTitle"),
        description: t("tools.textDescription"),
      },
      {
        label: "file-cipher" as const,
        title: t("tools.fileTitle"),
        description: t("tools.fileDescription"),
      },
      {
        label: "template-editor" as const,
        title: t("tools.templateTitle"),
        description: t("tools.templateDescription"),
      },
    ],
    [t]
  );

  useEffect(() => {
    setNetworkProfile(bootStatus.network_profile || "mock");
  }, [bootStatus.network_profile]);

  useEffect(() => {
    writeBooleanSetting(DESTRUCTIVE_PANIC_STORAGE_KEY, destructivePanicEnabled);
  }, [destructivePanicEnabled]);

  useEffect(() => {
    if (templates.length === 0) return;
    if (!templates.some((template) => template.name === bootTemplateName)) {
      setBootTemplateName(templates.some((template) => template.name === "Livencrypt") ? "Livencrypt" : templates[0].name);
    }
  }, [bootTemplateName, templates]);

  const clearShieldFields = () => {
    setSc1("");
    setSc2("");
    setSc3("");
    setSc4("");
    setSc5("");
    setSFrase("");
    setS2c1("");
    setS2c2("");
    setS2c3("");
    setS2c4("");
    setS2c5("");
    setSFrase2("");
  };

  const handleApplyShield = async () => {
    if (!invoke) return;

    try {
      setShieldProcessing(true);
      setLaunchError("");
      const cajas = parseCajas([sc1, sc2, sc3, sc4, sc5], t);
      if (!sFrase.trim()) {
        throw new Error(t("boot.emptyPhrase"));
      }
      const secondaryRequired = (!shieldActive && doubleCredential) || (shieldActive && bootStatus.credential_mode === "double");
      const secondaryCajas = secondaryRequired ? parseCajas([s2c1, s2c2, s2c3, s2c4, s2c5], t) : null;
      if (secondaryRequired && !sFrase2.trim()) {
        throw new Error(t("boot.emptySecondaryPhrase"));
      }
      await invoke(shieldActive ? "boot_shield_disable" : "boot_shield_enable", {
        cajas,
        frase: sFrase.trim(),
        bootTemplateName: shieldActive ? null : bootTemplateName,
        secondaryCajas,
        secondaryFrase: secondaryRequired ? sFrase2.trim() : null,
      });
      clearShieldFields();
      if (!shieldActive) {
        setSettingShield(false);
        setShieldProcessing(false);
        setCloseNoticeOpen(true);
        setLaunchError(t("settings.bootEnabledMessage"));
        return;
      }
      setSettingShield(false);
      setShieldProcessing(false);
      await refreshBootStatus();
      setLaunchError("");
    } catch (error) {
      setShieldProcessing(false);
      setLaunchError(String(error));
    }
  };

  const handleConfirmedClose = async () => {
    if (!invoke) return;
    try {
      setCloseNoticeLoading(true);
      await invoke("panic_wipe_and_exit");
    } catch (error) {
      setCloseNoticeLoading(false);
      setLaunchError(String(error));
    }
  };

  const handleSaveNetworkProfile = async () => {
    if (!invoke) return;

    try {
      await invoke("set_network_profile", {
        profile: networkProfile,
        confirmation: networkConfirmation.trim() || null,
      });
      setNetworkConfirmation("");
      await refreshBootStatus();
      setLaunchError("");
    } catch (error) {
      setLaunchError(String(error));
    }
  };

  const handleToggleNetwork = async () => {
    if (!invoke) return;
    try {
      setNetworkLoading(true);
      setLaunchError("");
      const isOnline: any = await invoke("toggle_network", { disable: !networkDisabled });
      setNetworkDisabled(!isOnline);
    } catch (error) {
      setLaunchError(String(error));
    } finally {
      setNetworkLoading(false);
    }
  };

  const openTool = async (label: ToolLabel) => {
    if (!invoke) {
      window.location.hash = label;
      return;
    }

    try {
      setLaunchError("");
      await invoke("open_tool_window", { label });
    } catch (error) {
      setLaunchError(String(error));
    }
  };

  return (
    <main className="min-h-screen bg-[#020617] text-slate-200 font-mono">
      <div className="mx-auto flex min-h-screen w-full max-w-5xl flex-col px-6 py-8">
        <header className="flex items-center justify-between border-b border-cyan-900/30 pb-5">
          <div className="flex items-center gap-3">
            <LivencryptIcon size={44} darkMode />
            <div>
              <h1 className="text-sm font-black tracking-[0.28em] text-cyan-300">LIVENCRYPT 2.0</h1>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {invoke && (
              <>
                <button
                  type="button"
                  disabled={networkLoading}
                  onClick={handleToggleNetwork}
                  className={`px-3 py-1.5 rounded border text-[9px] font-bold transition-all hover:scale-105 cursor-pointer ${
                    networkDisabled
                      ? "border-red-500/40 text-red-400 bg-red-950/20 hover:bg-red-900/30"
                      : "border-emerald-500/40 text-emerald-400 bg-emerald-950/20 hover:bg-emerald-900/30"
                  }`}
                  title={networkDisabled ? "Activar conexión a Internet" : "Desactivar conexión a Internet (Air-Gap seguro)"}
                >
                  🌐 {t("dashboard.network")}: {networkDisabled ? t("dashboard.offline") : t("dashboard.online")}
                </button>
                <LanguageFlagSelector />
                <button
                  type="button"
                  onClick={() => setConfigOpen(true)}
                  className="px-3 py-1.5 rounded border border-slate-700 bg-slate-900 text-slate-300 font-bold text-[9px] hover:bg-slate-800 hover:scale-105 transition-all cursor-pointer"
                  title={t("dashboard.settings")}
                >
                  ⚙️ {t("dashboard.settings")}
                </button>
                <WindowSecurityActions onError={setLaunchError} />
              </>
            )}
          </div>
        </header>

        <section className="grid flex-1 place-items-center py-10">
          <div className="grid w-full gap-4 md:grid-cols-3">
            {toolRoutes.map((tool) => {
              return (
                <button
                  key={tool.label}
                  type="button"
                  onClick={() => void openTool(tool.label)}
                  className="group grid min-h-[150px] grid-rows-[3rem_1fr] rounded-lg border border-cyan-900/30 bg-slate-950/70 p-5 text-left transition-all hover:-translate-y-0.5 hover:border-cyan-500/50 hover:bg-cyan-950/20"
                >
                  <h2 className="self-start text-[12px] font-black leading-5 tracking-[0.1em] text-slate-100">
                    {tool.title}
                  </h2>
                  <p className="text-[10px] leading-5 text-slate-500">{tool.description}</p>
                </button>
              );
            })}
          </div>
        </section>

        {launchError ? (
          <div className="mb-4 rounded border border-red-500/30 bg-red-500/10 px-4 py-3 text-[10px] font-bold text-red-300">
            {launchError}
          </div>
        ) : null}
      </div>

      {configOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-6 animate-fade-in">
          <div className="w-full max-w-md max-h-[calc(100vh-3rem)] overflow-y-auto border border-cyan-900/30 bg-[#0B1120] rounded-xl p-5 shadow-2xl font-mono text-slate-200">
            <div className="flex items-center justify-between border-b border-cyan-900/30 pb-3 mb-4">
              <h3 className="text-xs font-black tracking-widest text-cyan-400">{t("settings.title")}</h3>
              <button
                onClick={() => setConfigOpen(false)}
                className="text-slate-500 hover:text-slate-200 text-xs font-bold cursor-pointer"
              >
                ✖
              </button>
            </div>

            <div className="mb-4">
              <span className="text-[10px] font-black text-amber-500 tracking-wider uppercase block mb-3">{t("settings.accessSection")}</span>
              <div className="border border-slate-800 rounded-lg p-3 bg-slate-950/40">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-[9px] font-bold text-slate-300">{t("settings.bootAutoEncrypt")}</span>
                  <button
                    onClick={() => {
                      setSettingShield((value) => !value);
                      clearShieldFields();
                    }}
                    className={`px-2 py-1 rounded text-[8px] font-bold border transition-all cursor-pointer ${
                      shieldActive
                        ? "border-red-500/40 text-red-400 bg-red-950/20 hover:bg-red-900/30"
                        : "border-slate-700 text-slate-400 bg-slate-900 hover:bg-slate-800"
                    }`}
                  >
                    {shieldActive ? t("settings.deactivate") : t("settings.activate")}
                  </button>
                </div>

                <p className="text-[8px] text-slate-500 leading-4 mb-3 uppercase">
                  {t("settings.bootShieldDescription")}
                </p>

                {settingShield && (
                  <div className="border-t border-slate-900 pt-3 mt-2 space-y-3">
                    {!shieldActive && (
                      <div>
                        <label className="text-[8px] font-bold block mb-1 text-slate-400 uppercase">{t("settings.bootTemplate")}</label>
                        <select
                          value={bootTemplateName}
                          onChange={(event) => setBootTemplateName(event.target.value)}
                          className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-[10px] text-slate-200 outline-none focus:border-cyan-500"
                          style={{
                            colorScheme: "dark",
                            backgroundColor: "#020617",
                            color: "#e2e8f0",
                          }}
                        >
                          {templates.length === 0 ? (
                            <option className="bg-slate-950 text-slate-200" value="Livencrypt">Livencrypt</option>
                          ) : (
                            templates.map((template) => (
                              <option className="bg-slate-950 text-slate-200" key={template.name} value={template.name}>
                                {template.name}
                              </option>
                            ))
                          )}
                        </select>
                        <p className="mt-1 text-[7px] leading-3 text-slate-600 uppercase">
                          {t("settings.bootTemplateHelp")}
                        </p>
                      </div>
                    )}

                    {!shieldActive && (
                      <label className="flex items-center justify-between rounded border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-[8px] font-bold uppercase text-slate-400">
                        <span>{t("settings.doubleCredential")}</span>
                        <input
                          type="checkbox"
                          checked={doubleCredential}
                          onChange={(event) => setDoubleCredential(event.target.checked)}
                          className="accent-cyan-500"
                        />
                      </label>
                    )}

                    <div>
                      <label className="text-[8px] font-bold block mb-1 text-slate-400 uppercase">{t("settings.boxes")}</label>
                      <div className="grid grid-cols-5 gap-1.5">
                        {[sc1, sc2, sc3, sc4, sc5].map((val, idx) => (
                          <input
                            key={idx}
                            type="text"
                            inputMode="text"
                            placeholder={t("boot.primaryBoxPlaceholder", { index: idx + 1 })}
                            value={val}
                            onChange={(e) => [setSc1, setSc2, setSc3, setSc4, setSc5][idx](e.target.value)}
                            onCopy={(event) => event.preventDefault()}
                            onCut={(event) => event.preventDefault()}
                            onPaste={(event) => event.preventDefault()}
                            onContextMenu={(event) => event.preventDefault()}
                            className="bg-slate-950 border border-slate-800 rounded text-center py-1 text-[10px] text-slate-200 outline-none focus:border-cyan-500 transition-all"
                          />
                        ))}
                      </div>
                    </div>

                    <div>
                      <label className="text-[8px] font-bold block mb-1 text-slate-400 uppercase">{t("settings.bootPhrase")}</label>
                      <input
                        type="password"
                        placeholder={shieldActive ? t("settings.bootDisablePhrasePlaceholder") : t("settings.bootPhrasePlaceholder")}
                        value={sFrase}
                        onChange={(e) => setSFrase(e.target.value)}
                        onCopy={(event) => event.preventDefault()}
                        onCut={(event) => event.preventDefault()}
                        onPaste={(event) => event.preventDefault()}
                        onContextMenu={(event) => event.preventDefault()}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-[10px] text-slate-200 outline-none focus:border-cyan-500 transition-all"
                      />
                    </div>

                    {((!shieldActive && doubleCredential) || (shieldActive && bootStatus.credential_mode === "double")) && (
                      <div className="border-t border-slate-900 pt-3 space-y-3">
                        <div>
                          <label className="text-[8px] font-bold block mb-1 text-slate-400 uppercase">{t("settings.secondaryBoxes")}</label>
                          <div className="grid grid-cols-5 gap-1.5">
                            {[s2c1, s2c2, s2c3, s2c4, s2c5].map((val, idx) => (
                              <input
                                key={idx}
                                type="text"
                                inputMode="text"
                                placeholder={t("boot.secondaryBoxPlaceholder", { index: idx + 1 })}
                                value={val}
                                onChange={(e) => [setS2c1, setS2c2, setS2c3, setS2c4, setS2c5][idx](e.target.value)}
                                onCopy={(event) => event.preventDefault()}
                                onCut={(event) => event.preventDefault()}
                                onPaste={(event) => event.preventDefault()}
                                onContextMenu={(event) => event.preventDefault()}
                                className="bg-slate-950 border border-slate-800 rounded text-center py-1 text-[10px] text-slate-200 outline-none focus:border-cyan-500 transition-all"
                              />
                            ))}
                          </div>
                        </div>

                        <div>
                          <label className="text-[8px] font-bold block mb-1 text-slate-400 uppercase">{t("settings.secondaryPhrase")}</label>
                          <input
                            type="password"
                            placeholder={t("settings.secondaryPhrasePlaceholder")}
                            value={sFrase2}
                            onChange={(e) => setSFrase2(e.target.value)}
                            onCopy={(event) => event.preventDefault()}
                            onCut={(event) => event.preventDefault()}
                            onPaste={(event) => event.preventDefault()}
                            onContextMenu={(event) => event.preventDefault()}
                            className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-[10px] text-slate-200 outline-none focus:border-cyan-500 transition-all"
                          />
                        </div>
                      </div>
                    )}

                    <button
                      onClick={() => void handleApplyShield()}
                      disabled={shieldProcessing}
                      className={`w-full py-1.5 border font-bold uppercase text-[9px] rounded transition-all cursor-pointer hover:scale-[1.01] disabled:cursor-wait disabled:opacity-60 ${
                        shieldActive
                          ? "bg-red-950/30 hover:bg-red-900/30 border-red-500/40 text-red-400"
                          : "bg-cyan-950/30 hover:bg-cyan-900/30 border-cyan-500/40 text-cyan-400"
                      }`}
                    >
                      {shieldProcessing
                        ? t("settings.processingVault")
                        : shieldActive
                          ? t("settings.disableBootShield")
                          : t("settings.createVault")}
                    </button>
                  </div>
                )}
              </div>
            </div>

            <div className="mb-4">
              <span className="text-[10px] font-black text-red-500 tracking-wider uppercase block mb-3">{t("settings.panicSection")}</span>
              <div className="border border-red-900/50 rounded-lg p-3 bg-red-950/10 space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-[9px] font-bold text-red-200 uppercase">{t("settings.destructivePanicMode")}</span>
                  <button
                    type="button"
                    onClick={() => setDestructivePanicEnabled((value) => !value)}
                    className={`px-2 py-1 rounded border text-[8px] font-black uppercase transition-all cursor-pointer ${
                      destructivePanicEnabled
                        ? "border-red-500/50 bg-red-950/30 text-red-300 hover:bg-red-900/40"
                        : "border-slate-700 bg-slate-900 text-slate-400 hover:bg-slate-800"
                    }`}
                  >
                    {destructivePanicEnabled ? t("settings.deactivate") : t("settings.activate")}
                  </button>
                </div>
                <p className="text-[8px] text-red-300 leading-4 uppercase">
                  {t("settings.destructivePanicDescription")}
                </p>
              </div>
            </div>

            <div className="mb-4">
              <span className="text-[10px] font-black text-amber-500 tracking-wider uppercase block mb-3">{t("settings.inactivitySection")}</span>
              <div className="border border-slate-800 rounded-lg p-3 bg-slate-950/40 space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-[9px] font-bold text-slate-300 uppercase">{t("settings.inactivityCloseMode")}</span>
                  <button
                    type="button"
                    onClick={() => setInactivityCloseEnabled(!inactivityCloseEnabled)}
                    className={`px-2 py-1 rounded border text-[8px] font-black uppercase transition-all cursor-pointer ${
                      inactivityCloseEnabled
                        ? "border-amber-500/50 bg-amber-950/30 text-amber-300 hover:bg-amber-900/40"
                        : "border-slate-700 bg-slate-900 text-slate-400 hover:bg-slate-800"
                    }`}
                  >
                    {inactivityCloseEnabled ? t("settings.deactivate") : t("settings.activate")}
                  </button>
                </div>
                <label className="block space-y-1">
                  <span className="text-[8px] font-bold text-slate-400 uppercase">{t("settings.inactivitySeconds")}</span>
                  <input
                    type="number"
                    min={10}
                    max={86400}
                    value={inactivityCloseSeconds}
                    onChange={(event) => setInactivityCloseSeconds(Number(event.target.value) || 10)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-[10px] text-slate-200 outline-none focus:border-amber-500"
                  />
                </label>
                <p className="text-[8px] text-slate-500 leading-4 uppercase">
                  {t("settings.inactivityDescription")}
                </p>
              </div>
            </div>

            <div className="mb-2">
              <span className="text-[10px] font-black text-amber-500 tracking-wider uppercase block mb-3">{t("settings.networkSection")}</span>
              <div className="border border-slate-800 rounded-lg p-3 bg-slate-950/40 space-y-3">
                <label className="text-[8px] font-bold block text-slate-400 uppercase">{t("settings.networkProfile")}</label>
                <select
                  value={networkProfile}
                  onChange={(event) => setNetworkProfile(event.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-[10px] text-slate-200 outline-none focus:border-cyan-500"
                  style={{
                    colorScheme: "dark",
                    backgroundColor: "#020617",
                    color: "#e2e8f0",
                  }}
                >
                  <option className="bg-slate-950 text-slate-200" value="mock">{t("settings.networkMock")}</option>
                  <option className="bg-slate-950 text-slate-200" value="manual">{t("settings.networkManual")}</option>
                  <option className="bg-slate-950 text-slate-200" value="drop-default-route">{t("settings.networkDropRoute")}</option>
                  <option className="bg-slate-950 text-slate-200" value="nmcli-off">{t("settings.networkNmcliOff")}</option>
                </select>
                {(networkProfile === "drop-default-route" || networkProfile === "nmcli-off") && (
                  <input
                    type="text"
                    value={networkConfirmation}
                    onChange={(event) => setNetworkConfirmation(event.target.value)}
                    placeholder="ENTENDIDO"
                    className="w-full bg-slate-950 border border-red-900/60 rounded px-2.5 py-1.5 text-[10px] text-slate-200 outline-none focus:border-red-500"
                  />
                )}
                <button
                  type="button"
                  onClick={() => void handleSaveNetworkProfile()}
                  className="w-full py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 font-bold uppercase text-[9px] rounded transition-all cursor-pointer"
                >
                  {t("settings.networkSave")}
                </button>
                <p className="text-[8px] text-slate-500 leading-4 uppercase">
                  {t("settings.networkHelp")}
                </p>
              </div>
            </div>

            <div className="mt-4">
              <span className="text-[10px] font-black text-amber-500 tracking-wider uppercase block mb-3">{t("settings.hardeningSection")}</span>
              <div className="border border-slate-800 rounded-lg p-3 bg-slate-950/40 space-y-2">
                {hardeningStatus ? (
                  <>
                    <div className="grid grid-cols-2 gap-2 text-[8px] uppercase">
                      <span className={hardeningStatus.core_dumps_disabled ? "text-emerald-400" : "text-red-400"}>{t("hardening.coreDumps")}: {hardeningStatus.core_dumps_disabled ? t("hardening.blocked") : t("hardening.no")}</span>
                      <span className={hardeningStatus.dumpable_disabled ? "text-emerald-400" : "text-red-400"}>{t("hardening.dumpable")}: {hardeningStatus.dumpable_disabled ? t("hardening.off") : t("hardening.failed")}</span>
                      <span className={hardeningStatus.mlockall_applied ? "text-emerald-400" : "text-red-400"}>{t("hardening.mlockall")}: {hardeningStatus.mlockall_applied ? "OK" : t("hardening.failed")}</span>
                      <span className={hardeningStatus.binary_integrity_ok === false ? "text-red-400" : "text-slate-400"}>{t("hardening.integrity")}: {hardeningStatus.binary_integrity_ok === null ? t("hardening.noExpectedHash") : hardeningStatus.binary_integrity_ok ? "OK" : t("hardening.failed")}</span>
                    </div>
                    <div className="break-all text-[7px] leading-3 text-slate-600">
                      {t("hardening.binarySha256")}: {hardeningStatus.binary_sha256}
                    </div>
                    <p className="text-[8px] leading-4 text-slate-500 uppercase">
                      {t("hardening.note")}
                    </p>
                    {hardeningStatus.warnings.length > 0 ? (
                      <div className="space-y-1">
                        {hardeningStatus.warnings.map((warning) => (
                          <div key={warning} className="text-[8px] leading-3 text-amber-300 uppercase">
                            {warning}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-[8px] text-emerald-400 uppercase">{t("hardening.noWarnings")}</div>
                    )}
                  </>
                ) : (
                  <div className="text-[8px] text-slate-500 uppercase">{t("hardening.unavailable")}</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
      {closeNoticeOpen && (
        <div className="fixed inset-0 z-[80] grid place-items-center bg-black/80 px-4">
          <div className="w-full max-w-md rounded-lg border border-cyan-500/40 bg-slate-950 p-5 shadow-2xl shadow-cyan-950/40">
            <div className="mb-3 text-[11px] font-black uppercase tracking-[0.2em] text-cyan-300">
              {t("settings.bootEnabled")}
            </div>
            <p className="mb-4 text-[10px] font-bold uppercase leading-5 text-slate-300">
              {t("settings.bootEnabledCloseText")}
            </p>
            <button
              type="button"
              disabled={closeNoticeLoading}
              onClick={() => void handleConfirmedClose()}
              className="w-full rounded border border-cyan-500/50 bg-cyan-950/30 px-4 py-2 text-[10px] font-black uppercase text-cyan-200 transition-all hover:bg-cyan-900/40 disabled:cursor-wait disabled:opacity-60"
            >
              {closeNoticeLoading ? t("settings.closing") : t("settings.closeLivencrypt")}
            </button>
          </div>
        </div>
      )}
    </main>
  );
}

function Root() {
  const { t } = useTranslation();
  const hash = useHashRoute();
  const [bootStatus, setBootStatus] = useState<BootShieldStatus | null>(null);
  const [bootError, setBootError] = useState("");
  const [sessionUnlocked, setSessionUnlocked] = useState(false);
  const [hardeningStatus, setHardeningStatus] = useState<ProcessHardeningStatus | null>(null);
  const [inactivityCloseEnabled, setInactivityCloseEnabledState] = useState(() =>
    readBooleanSetting(INACTIVITY_CLOSE_ENABLED_KEY),
  );
  const [inactivityCloseSeconds, setInactivityCloseSecondsState] = useState(() =>
    readNumberSetting(INACTIVITY_CLOSE_SECONDS_KEY, 300, 10, 86400),
  );
  const bootState = bootStatus?.state ?? "loading";
  const { templates, selectedTemplate, error } = useTemplates(bootState);
  const darkMode = true;

  const setInactivityCloseEnabled = (value: boolean) => {
    setInactivityCloseEnabledState(value);
    writeBooleanSetting(INACTIVITY_CLOSE_ENABLED_KEY, value);
  };

  const setInactivityCloseSeconds = (value: number) => {
    const normalized = writeNumberSetting(INACTIVITY_CLOSE_SECONDS_KEY, value, 10, 86400);
    setInactivityCloseSecondsState(normalized);
  };

  const refreshBootStatus = async () => {
    if (!invoke) {
      setBootStatus({ state: "not_configured", network_profile: "mock", credential_mode: "single" });
      return;
    }

    try {
      const status = (await invoke("boot_shield_status")) as BootShieldStatus;
      setBootStatus(status);
      setBootError("");
      if (status.state !== "unlocked") {
        setSessionUnlocked(false);
      }
    } catch (cause) {
      setBootError(String(cause));
      setBootStatus({ state: "not_configured", network_profile: "mock", credential_mode: "single" });
    }
  };

  useEffect(() => {
    void refreshBootStatus();
    if (invoke) {
      invoke("process_hardening_status")
        .then((status: unknown) => setHardeningStatus(status as ProcessHardeningStatus))
        .catch(() => setHardeningStatus(null));
    }
  }, []);

  useEffect(() => {
    const refreshSecuritySettings = () => {
      setInactivityCloseEnabledState(readBooleanSetting(INACTIVITY_CLOSE_ENABLED_KEY));
      setInactivityCloseSecondsState(readNumberSetting(INACTIVITY_CLOSE_SECONDS_KEY, 300, 10, 86400));
    };
    window.addEventListener("storage", refreshSecuritySettings);
    window.addEventListener(SECURITY_SETTINGS_CHANGED_EVENT, refreshSecuritySettings);
    return () => {
      window.removeEventListener("storage", refreshSecuritySettings);
      window.removeEventListener(SECURITY_SETTINGS_CHANGED_EVENT, refreshSecuritySettings);
    };
  }, []);

  useEffect(() => {
    if (!invoke || !inactivityCloseEnabled) return;

    let timer: number | undefined;
    const closeForInactivity = () => {
      void invoke("panic_wipe_and_exit").catch(() => undefined);
    };
    const resetTimer = () => {
      if (timer !== undefined) window.clearTimeout(timer);
      timer = window.setTimeout(closeForInactivity, inactivityCloseSeconds * 1000);
    };
    const events = ["mousedown", "mousemove", "pointerdown", "keydown", "scroll", "touchstart", "click", "input", "focus"];
    events.forEach((eventName) => window.addEventListener(eventName, resetTimer, { passive: true }));
    resetTimer();

    return () => {
      if (timer !== undefined) window.clearTimeout(timer);
      events.forEach((eventName) => window.removeEventListener(eventName, resetTimer));
    };
  }, [inactivityCloseEnabled, inactivityCloseSeconds]);

  useEffect(() => {
    if (!invoke || bootStatus?.state !== "unlocked" || !sessionUnlocked) return;

    let timer: number | undefined;
    const lockForInactivity = () => {
      void invoke("boot_shield_lock")
        .catch(() => undefined)
        .finally(() => {
          setSessionUnlocked(false);
          void refreshBootStatus();
        });
    };
    const resetTimer = () => {
      if (timer !== undefined) window.clearTimeout(timer);
      timer = window.setTimeout(lockForInactivity, 10 * 60 * 1000);
    };
    const events = ["mousedown", "mousemove", "keydown", "scroll", "touchstart"];
    events.forEach((eventName) => window.addEventListener(eventName, resetTimer, { passive: true }));
    resetTimer();

    return () => {
      if (timer !== undefined) window.clearTimeout(timer);
      events.forEach((eventName) => window.removeEventListener(eventName, resetTimer));
    };
  }, [bootStatus?.state, sessionUnlocked]);

  useEffect(() => {
    if (!invoke || bootStatus?.state !== "unlocked" || !sessionUnlocked) return;

    let hiddenTimer: number | undefined;
    const lockAfterHidden = () => {
      hiddenTimer = window.setTimeout(() => {
        void invoke("boot_shield_lock")
          .catch(() => undefined)
          .finally(() => {
            setSessionUnlocked(false);
            void refreshBootStatus();
          });
      }, 30 * 1000);
    };
    const handleVisibility = () => {
      if (hiddenTimer !== undefined) {
        window.clearTimeout(hiddenTimer);
        hiddenTimer = undefined;
      }
      if (document.visibilityState !== "visible") {
        lockAfterHidden();
      }
    };
    document.addEventListener("visibilitychange", handleVisibility);
    return () => {
      if (hiddenTimer !== undefined) window.clearTimeout(hiddenTimer);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [bootStatus?.state, sessionUnlocked]);

  useEffect(() => {
    if (!invoke) return;
    const lockOnUnload = () => {
      void invoke("boot_shield_lock").catch(() => undefined);
    };
    window.addEventListener("beforeunload", lockOnUnload);
    return () => window.removeEventListener("beforeunload", lockOnUnload);
  }, []);

  if (!bootStatus) {
    return (
      <main className="min-h-screen bg-[#020617] text-cyan-300 font-mono grid place-items-center">
        <div className="text-[10px] font-black tracking-[0.2em] uppercase">{t("dashboard.initializingBootShield")}</div>
      </main>
    );
  }

  if (bootStatus.state === "locked" && !sessionUnlocked) {
    return (
      <LockScreen
        credentialMode={bootStatus.credential_mode}
        onUnlock={async (status: BootShieldStatus) => {
          setSessionUnlocked(true);
          setBootStatus(status);
          window.location.hash = "";
          await refreshBootStatus();
        }}
      />
    );
  }

  if (hash === "text-cipher") {
    return <TextCipherWindow darkMode={darkMode} selectedTemplate={selectedTemplate} templates={templates} />;
  }

  if (hash === "file-cipher") {
    return <FileCipherWindow darkMode={darkMode} />;
  }

  if (hash === "template-editor") {
    return <TemplateEditorWindow darkMode={darkMode} />;
  }

  return (
    <>
      <Launcher
        bootStatus={bootStatus}
        refreshBootStatus={refreshBootStatus}
        templates={templates}
        hardeningStatus={hardeningStatus}
        inactivityCloseEnabled={inactivityCloseEnabled}
        setInactivityCloseEnabled={setInactivityCloseEnabled}
        inactivityCloseSeconds={inactivityCloseSeconds}
        setInactivityCloseSeconds={setInactivityCloseSeconds}
      />
      {error || bootError ? (
        <div className="fixed bottom-4 left-1/2 z-50 -translate-x-1/2 rounded border border-amber-500/30 bg-amber-950 px-4 py-2 font-mono text-[10px] font-bold text-amber-300">
          {error || bootError}
        </div>
      ) : null}
    </>
  );
}

const rootEl = document.getElementById("root");

if (!rootEl) {
  throw new Error("Root element #root not found");
}

ReactDOM.createRoot(rootEl).render(
  <LanguageProvider>
    <Root />
  </LanguageProvider>
);
