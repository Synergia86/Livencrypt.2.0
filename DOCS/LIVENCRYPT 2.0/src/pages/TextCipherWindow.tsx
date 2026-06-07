// SPDX-License-Identifier: GPL-3.0-or-later

import { useEffect, useState } from "react";
import PasswordDialog from "../components/hud/PasswordDialog";
import PasswordSetupDialog from "../components/hud/PasswordSetupDialog";
import WindowSecurityActions from "../components/hud/WindowSecurityActions";
import type { TemplateData } from "../components/dashboard/TemplateSelector";
import invoke from "../invoke";
import { useTranslation } from "../context/LanguageContext";
import { formatLocalizedInteger, formatLocalizedTime, parseBootCajas, parseLocalizedInteger } from "../i18n/numerals";

const DEFAULT_CONTROL_SYMBOLS = "¢|@#~½¶←↓→ˀ|¢ª─¬";
const DEFAULT_TEXT_CAJAS = [5, 7, 2, 3, 0];

type PasswordDirection = "after" | "before";

interface TextPasswordSettings {
  enabled: boolean;
  passwordLength: number;
  passwordDirection: PasswordDirection;
  controlSymbols: string;
}

interface Props {
  darkMode: boolean;
  selectedTemplate: { name: string; data: TemplateData } | null;
  templates: Array<{ name: string; data: TemplateData }>;
}

export default function TextCipherWindow({ darkMode, selectedTemplate, templates }: Props) {
  const { language, t } = useTranslation();
  const [mode, setMode] = useState<"cifrar" | "descifrar">("cifrar");
  const [text, setText] = useState("");
  const [result, setResult] = useState("");
  const [cajas, setCajas] = useState(() => DEFAULT_TEXT_CAJAS.map((value) => formatLocalizedInteger(value, language)));
  const [templateName, setTemplateName] = useState(selectedTemplate?.name ?? templates[0]?.name ?? "");
  const [consoleLog, setConsoleLog] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  // F2: Password dialog state
  const [passwordDialog, setPasswordDialog] = useState<{
    expectedPassword: string;
    resolve: (v: boolean) => void;
  } | null>(null);
  const [passwordSecurityEnabled, setPasswordSecurityEnabled] = useState(false);
  const [passwordLength, setPasswordLength] = useState(8);
  const [passwordDirection, setPasswordDirection] = useState<PasswordDirection>("before");
  const [controlSymbols, setControlSymbols] = useState(DEFAULT_CONTROL_SYMBOLS);
  const [passwordSetupOpen, setPasswordSetupOpen] = useState(false);
  const [securityError, setSecurityError] = useState("");

  useEffect(() => {
    if (!templateName && templates.length > 0) {
      setTemplateName(selectedTemplate?.name ?? templates[0].name);
    }
  }, [selectedTemplate, templateName, templates]);

  const log = (msg: string) => setConsoleLog((p) => [...p.slice(-19), `[${formatLocalizedTime(new Date(), language)}] ${msg}`]);

  useEffect(() => {
    const parsed = cajas.map(parseLocalizedInteger);
    const isDefault = parsed.every((value, index) => value === DEFAULT_TEXT_CAJAS[index]);
    if (isDefault) {
      setCajas(DEFAULT_TEXT_CAJAS.map((value) => formatLocalizedInteger(value, language)));
    }
  }, [language]);

  useEffect(() => {
    if (!invoke) return;
    invoke("get_text_password_settings")
      .then((settings: any) => {
        const loaded = normalizePasswordSettings(settings);
        setPasswordSecurityEnabled(loaded.enabled);
        setPasswordLength(loaded.passwordLength);
        setPasswordDirection(loaded.passwordDirection);
        setControlSymbols(loaded.controlSymbols);
      })
      .catch((error: unknown) => log(`Configuración de contraseña no cargada: ${error}`));
  }, []);

  const normalizePasswordSettings = (settings: Partial<TextPasswordSettings>): TextPasswordSettings => {
    const symbols = normalizeControlSymbols(settings.controlSymbols ?? controlSymbols);
    return {
      enabled: Boolean(settings.enabled),
      passwordLength: Math.max(2, Math.min(25, Number(settings.passwordLength) || 8)),
      passwordDirection: settings.passwordDirection === "after" ? "after" : "before",
      controlSymbols: symbols || DEFAULT_CONTROL_SYMBOLS,
    };
  };

  const normalizeControlSymbols = (value: string): string => {
    let normalized = "";
    for (const symbol of Array.from(value).filter((symbol) => !/\s/u.test(symbol))) {
      if (!normalized.includes(symbol)) normalized += symbol;
    }
    return normalized || DEFAULT_CONTROL_SYMBOLS;
  };

  const persistPasswordSettings = async (settings: TextPasswordSettings) => {
    if (!invoke) return settings;
    const normalized = normalizePasswordSettings(settings);
    try {
      const saved: any = await invoke("save_text_password_settings", { settings: normalized });
      return normalizePasswordSettings(saved);
    } catch (error) {
      log(`Configuración de contraseña no guardada: ${error}`);
      return normalized;
    }
  };

  const applyPasswordSettingsState = (settings: TextPasswordSettings) => {
    setPasswordSecurityEnabled(settings.enabled);
    setPasswordLength(settings.passwordLength);
    setPasswordDirection(settings.passwordDirection);
    setControlSymbols(settings.controlSymbols);
  };

  const handleTogglePasswordDirection = () => {
    const nextDirection = passwordDirection === "after" ? "before" : "after";
    const nextSettings = normalizePasswordSettings({
      enabled: passwordSecurityEnabled,
      passwordLength,
      passwordDirection: nextDirection,
      controlSymbols,
    });
    applyPasswordSettingsState(nextSettings);
    void persistPasswordSettings(nextSettings).then(applyPasswordSettingsState);
  };

  const parseCajasForCipher = (): number[] | null => {
    try {
      return parseBootCajas(cajas, {
        missing: t("boot.missingBoxes"),
        numeric: t("boot.numericBoxes"),
        range: t("boot.boxRange"),
      });
    } catch (error) {
      log(String(error));
      return null;
    }
  };

  const handleCipher = async () => {
    if (!invoke) return;
    if (!text.trim()) return log(t("textCipher.emptyText"));
    if (!templateName) return log(t("textCipher.selectTemplate"));
    const parsedCajas = parseCajasForCipher();
    if (!parsedCajas) return;
    setLoading(true);
    try {
      const cmd = mode === "cifrar" ? "cipher_text" : "decipher_text";
      const res: any = await invoke(cmd, {
        text,
        templateName,
        caja1: parsedCajas[0], caja2: parsedCajas[1],
        caja3: parsedCajas[2], caja4: parsedCajas[3],
        caja5: parsedCajas[4],
        passwordLength: passwordSecurityEnabled ? passwordLength : 0,
        passwordDirection,
        controlSymbols,
      });

      if (passwordSecurityEnabled && res.detected_password) {
        log(t("textCipher.passwordDetected"));
        const verified = await new Promise<boolean>((resolve) => {
          setPasswordDialog({ expectedPassword: res.detected_password, resolve });
        });
        if (!verified) {
          log(t("textCipher.passwordRejected"));
          setResult("");
          return;
        }
        log(t("textCipher.passwordVerified"));
      }

      setResult(res.result || "");
      log(t("textCipher.operationOk", {
        operation: mode === "cifrar" ? t("textCipher.encrypt") : t("textCipher.decrypt"),
        count: formatLocalizedInteger(res.result?.length ?? 0, language),
      }));
    } catch (e: any) {
      log(`ERROR: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (result) { navigator.clipboard.writeText(result).then(() => log(t("textCipher.copied"))); }
  };

  const handleClear = () => {
    setText("");
    setResult("");
    log(t("textCipher.cleared"));
  };

  const palette = darkMode
    ? { bg: "bg-[#0B1120]", border: "border-cyan-900/30", input: "bg-slate-950 border-cyan-900/40 text-slate-200" }
    : { bg: "bg-white", border: "border-slate-200", input: "bg-white border-slate-300 text-slate-800" };

  const hasErrors = cajas.some((v) => {
    const parsed = parseLocalizedInteger(v);
    return parsed === null || parsed < 0 || parsed > 1000;
  });

  return (
    <div className={`h-screen w-screen flex flex-col font-mono ${darkMode ? "bg-[#020617] text-slate-200" : "bg-slate-50 text-slate-800"}`}>
      <header className={`flex items-center gap-4 px-6 py-2.5 border-b ${palette.border} ${palette.bg}`}>
        <button
          onClick={() => { window.location.hash = ""; }}
          className={`px-3 py-1 rounded text-[9px] font-bold border transition-all hover:scale-105 ${
            darkMode ? "border-slate-700 text-slate-400 hover:border-slate-600" : "border-slate-200 text-slate-500 hover:border-slate-400"
          }`}
        >
          ← {t("common.back")}
        </button>
        <span className={`text-[11px] font-black uppercase tracking-[0.15em] ${darkMode ? "text-cyan-400" : "text-cyan-600"}`}>
          {t("textCipher.title")}
        </span>
        <div className="flex-1" />
        <WindowSecurityActions onError={setSecurityError} />
      </header>
      {securityError ? (
        <div className="border-b border-red-500/30 bg-red-500/10 px-4 py-2 text-[9px] font-bold text-red-300">
          {securityError}
        </div>
      ) : null}

      <div className="flex flex-1 overflow-hidden">
        <div className="flex-1 flex flex-col p-4 gap-3 overflow-auto">
          {/* Template + cajas */}
          <div className="flex gap-3 flex-wrap items-end">
            <div>
              <label className={`text-[8px] uppercase font-bold block mb-1 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                {t("textCipher.template")}
              </label>
              <div className="relative">
              <select value={templateName} onChange={(e) => setTemplateName(e.target.value)}
                className={`appearance-none px-3 py-1.5 pr-7 rounded-lg text-[10px] font-bold border cursor-pointer outline-none ${palette.input}`}>
                {templates.map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
              </select>
              <span className={`pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-[7px] ${darkMode ? "text-slate-500" : "text-slate-400"}`}>▼</span>
              </div>
            </div>
            {cajas.map((v, i) => (
              <div key={i}>
                <label className={`text-[8px] uppercase font-bold block mb-1 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                  {t("common.box", { index: i + 1 })} {(() => {
                    const parsed = parseLocalizedInteger(v);
                    return parsed === null || parsed < 0 || parsed > 1000 ? t("common.boxRangeSuffix") : "";
                  })()}
                </label>
                <input
                  value={v}
                  onChange={(e) => { const n = [...cajas]; n[i] = e.target.value; setCajas(n); }}
                  className={`w-20 px-2 py-1.5 rounded-lg text-[10px] font-bold text-center border ${
                    (() => {
                      const parsed = parseLocalizedInteger(v);
                      return parsed === null || parsed < 0 || parsed > 1000;
                    })()
                      ? "border-red-500/50 bg-red-950/10"
                      : palette.input
                  }`}
                />
              </div>
            ))}
          </div>

          {/* Botones de acción */}
          <div className="flex gap-2">
            <button onClick={handleCipher} disabled={loading || hasErrors}
              className={`px-5 py-2 rounded-lg text-[10px] font-black uppercase border transition-all ${
                loading || hasErrors ? "opacity-50 cursor-not-allowed" : "hover:scale-105"
              } ${darkMode ? "bg-cyan-600/20 border-cyan-500/40 text-cyan-400" : "bg-cyan-50 border-cyan-500/50 text-cyan-700"}`}>
              {loading ? t("common.processing") : t("common.execute")}
            </button>
            <button onClick={handleClear}
              className={`px-5 py-2 rounded-lg text-[10px] font-black uppercase border transition-all hover:scale-105 ${
                darkMode ? "bg-slate-900 border-slate-700 text-slate-400" : "bg-slate-100 border-slate-300 text-slate-500"
              }`}>
              {t("common.clean")}
            </button>

            {/* Password config button (Matrix lock) */}
            <button
              onClick={() => setPasswordSetupOpen(true)}
              className={`relative px-3 py-2 rounded-lg text-[10px] font-black uppercase border transition-all hover:scale-105 group ${
                passwordSecurityEnabled
                  ? darkMode ? "bg-emerald-600/20 border-emerald-500/50 text-emerald-300" : "bg-emerald-100 border-emerald-400 text-emerald-700"
                  : darkMode ? "bg-emerald-950/20 border-emerald-900/40 text-emerald-400 hover:bg-emerald-950/40" : "bg-emerald-50 border-emerald-200 text-emerald-600 hover:bg-emerald-100"
              }`}
            >
              🔒
              {/* Tooltip on hover */}
              <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 rounded-lg border text-[8px] font-mono leading-relaxed opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity z-50 whitespace-nowrap bg-slate-950 border-cyan-900/40 text-slate-300 shadow-xl"
                style={{ minWidth: "280px" }}>
                <div className="text-[9px] font-black uppercase text-emerald-400 mb-1">{t("textCipher.insertPassword")}</div>
                <div className="text-emerald-300 tracking-[0.3em]">{Array.from(controlSymbols).join(" ")}</div>
              </div>
            </button>

            {/* Direction toggle */}
            <button
              onClick={handleTogglePasswordDirection}
              title={t("textCipher.passwordDirectionTitle", {
                position: passwordDirection === "after" ? t("textCipher.positionAfter") : t("textCipher.positionBefore"),
              })}
              className={`px-3 py-1.5 rounded-lg text-[40px] font-black leading-none border transition-all hover:scale-105 ${
                darkMode ? "bg-slate-900 border-cyan-800 text-cyan-400 hover:border-cyan-500" : "bg-slate-100 border-cyan-200 text-cyan-600 hover:border-cyan-400"
              }`}
            >
              {passwordDirection === "after" ? "←" : "→"}
            </button>

            <label className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border cursor-pointer transition-all text-[9px] font-bold ${
              mode === "cifrar"
                ? darkMode ? "bg-cyan-600/10 border-cyan-500/40 text-cyan-400" : "bg-cyan-50 border-cyan-400 text-cyan-700"
                : darkMode ? "border-slate-800 text-slate-500" : "border-slate-200 text-slate-400"
            }`}>
              <input type="radio" name="mode" checked={mode === "cifrar"} onChange={() => setMode("cifrar")} className="sr-only" />
              <span className={`w-3 h-3 rounded-full border-2 flex items-center justify-center ${
                mode === "cifrar" ? (darkMode ? "border-cyan-400" : "border-cyan-500") : (darkMode ? "border-slate-600" : "border-slate-300")
              }`}>
                {mode === "cifrar" && <span className={`w-1.5 h-1.5 rounded-full ${darkMode ? "bg-cyan-400" : "bg-cyan-500"}`} />}
              </span>
              {t("textCipher.encrypt")}
            </label>
            <label className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border cursor-pointer transition-all text-[9px] font-bold ${
              mode === "descifrar"
                ? darkMode ? "bg-cyan-600/10 border-cyan-500/40 text-cyan-400" : "bg-cyan-50 border-cyan-400 text-cyan-700"
                : darkMode ? "border-slate-800 text-slate-500" : "border-slate-200 text-slate-400"
            }`}>
              <input type="radio" name="mode" checked={mode === "descifrar"} onChange={() => setMode("descifrar")} className="sr-only" />
              <span className={`w-3 h-3 rounded-full border-2 flex items-center justify-center ${
                mode === "descifrar" ? (darkMode ? "border-cyan-400" : "border-cyan-500") : (darkMode ? "border-slate-600" : "border-slate-300")
              }`}>
                {mode === "descifrar" && <span className={`w-1.5 h-1.5 rounded-full ${darkMode ? "bg-cyan-400" : "bg-cyan-500"}`} />}
              </span>
              {t("textCipher.decrypt")}
            </label>
          </div>

          {/* Texto de entrada */}
          <label className={`text-[8px] uppercase font-bold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>{t("textCipher.text")}</label>
          <textarea value={text} onChange={(e) => setText(e.target.value)}
            className={`flex-1 min-h-[120px] p-3 rounded-xl text-[11px] border resize-none font-mono ${palette.input}`}
            placeholder={mode === "cifrar" ? t("textCipher.textEncryptPlaceholder") : t("textCipher.textDecryptPlaceholder")} />

          {/* Resultado */}
          <label className={`text-[8px] uppercase font-bold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>{t("textCipher.result")}</label>
          <div className="relative flex-1 min-h-[120px]">
            <textarea value={result} readOnly
              className={`w-full h-full p-3 rounded-xl text-[11px] border resize-none font-mono ${palette.input}`}
              placeholder={t("textCipher.resultPlaceholder")} />
            {result && (
              <button onClick={handleCopy}
                className={`absolute top-2 right-2 px-2 py-1 rounded text-[9px] font-bold border ${
                  darkMode ? "bg-slate-800 border-slate-700 text-slate-400" : "bg-slate-100 border-slate-300 text-slate-600"}`}>
                {t("common.copy")}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Console */}
      <div className={`h-[100px] border-t p-2 overflow-y-auto ${palette.border}`}>
        {consoleLog.map((l, i) => (
          <div key={i} className={`text-[9px] font-mono ${darkMode ? "text-slate-500" : "text-slate-400"}`}>{l}</div>
        ))}
      </div>

      {/* F2: Password Dialog (modal overlay) */}
      <PasswordDialog
        isOpen={passwordDialog !== null}
        mode={mode}
        maxAttempts={3}
        onVerify={(input) => {
          const match = input === passwordDialog?.expectedPassword;
          if (match) passwordDialog?.resolve(true);
          return match;
        }}
        onCancel={() => {
          passwordDialog?.resolve(false);
          setPasswordDialog(null);
        }}
        passwordLength={passwordLength}
        passwordDirection={passwordDirection}
        controlSymbols={controlSymbols}
        darkMode={darkMode}
      />
      <PasswordSetupDialog
        isOpen={passwordSetupOpen}
        passwordLength={passwordLength}
        passwordDirection={passwordDirection}
        controlSymbols={controlSymbols}
        onApply={(len, dir, symbols) => {
          const nextSettings = normalizePasswordSettings({
            enabled: true,
            passwordLength: len,
            passwordDirection: dir,
            controlSymbols: symbols,
          });
          applyPasswordSettingsState(nextSettings);
          setPasswordSetupOpen(false);
          void persistPasswordSettings(nextSettings).then(applyPasswordSettingsState);
        }}
        onCancel={() => setPasswordSetupOpen(false)}
        darkMode={darkMode}
      />
    </div>
  );
}
