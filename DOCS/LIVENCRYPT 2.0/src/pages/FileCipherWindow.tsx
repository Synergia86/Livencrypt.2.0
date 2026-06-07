// SPDX-License-Identifier: GPL-3.0-or-later

import { useState, useEffect } from "react";
import { open as tauriOpen, save as tauriSave } from "@tauri-apps/plugin-dialog";
import WindowSecurityActions from "../components/hud/WindowSecurityActions";
import invoke from "../invoke";
import { useTranslation } from "../context/LanguageContext";
import {
  formatLocalizedCompactNumber,
  formatLocalizedInteger,
  formatLocalizedMilliseconds,
  formatLocalizedTime,
  parseBootCajas,
  parseLocalizedInteger,
} from "../i18n/numerals";
import {
  FILE_AUTO_CLOSE_STORAGE_KEY,
  readBooleanSetting,
  writeBooleanSetting,
} from "../securitySettings";


interface FileInfo { name: string; size_bytes: number; hex_chars: number; is_compressed: boolean; }
interface TemplateInfo { name: string; rows: number; cols: number; chars: string[]; }
interface Props { darkMode: boolean; }
const DEFAULT_FILE_CAJAS = [1, 1, 1, 1, 1];

async function openFileDialog(title: string): Promise<string | null> {
  try {
    const result = await tauriOpen({ multiple: false, title });
    if (result) {
      if (typeof result === "string") return result;
      if (Array.isArray(result)) return result[0] ?? null;
    }
  } catch (e: any) { console.warn("FileCipherWindow: open dialog:", String(e)); }

  // Fallback: HTML input
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.onchange = () => {
      const file = input.files?.[0];
      resolve(file ? ((file as any).path && (file as any).path !== file.name ? (file as any).path : null) : null);
    };
    input.oncancel = () => resolve(null);
    input.click();
  });
}

async function saveFileDialog(defaultName: string, title: string, promptLabel: string): Promise<string | null> {
  try {
    const result = await tauriSave({ title, defaultPath: defaultName });
    return result || null;
  } catch (e: any) { console.warn("FileCipherWindow: open dialog:", String(e)); }
  return prompt(promptLabel, defaultName);
}

export default function FileCipherWindow({ darkMode }: Props) {
  const { language, t } = useTranslation();
  const [mode, setMode] = useState<"cifrar" | "descifrar">("cifrar");
  const [filePath, setFilePath] = useState("");
  const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);
  const [referencia, setReferencia] = useState("");
  const [cajas, setCajas] = useState(() => DEFAULT_FILE_CAJAS.map((value) => formatLocalizedInteger(value, language)));
  const [consoleLog, setConsoleLog] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingFile, setLoadingFile] = useState(false);
  const [fileTemplate, setFileTemplate] = useState("Livencrypt");
  const [templates, setTemplates] = useState<TemplateInfo[]>([]);
  const [securityError, setSecurityError] = useState("");
  const [autoCloseAfterAction, setAutoCloseAfterAction] = useState(() =>
    readBooleanSetting(FILE_AUTO_CLOSE_STORAGE_KEY),
  );

  const log = (msg: string) => setConsoleLog((p) => [...p.slice(-29), `[${formatLocalizedTime(new Date(), language)}] ${msg}`]);
  const bytesLabel = t("fileCipher.bytes").replace(/[:：]\s*$/, "");

  useEffect(() => {
    const parsed = cajas.map(parseLocalizedInteger);
    const isDefault = parsed.every((value, index) => value === DEFAULT_FILE_CAJAS[index]);
    if (isDefault) {
      setCajas(DEFAULT_FILE_CAJAS.map((value) => formatLocalizedInteger(value, language)));
    }
  }, [language]);

  useEffect(() => {
    if (!invoke) return;
    invoke("load_templates").then((tmpl: any) => {
      try {
        const list = Object.entries(tmpl as Record<string, any>).map(([name, data]: [string, any]) => ({
          name, rows: data.rows, cols: data.cols, chars: data.chars || []
        }));
        if (!list.some((template) => template.name === "Livencrypt")) {
          list.unshift({ name: "Livencrypt", rows: 5, cols: 23, chars: [] });
        }
        setTemplates(list);
      } catch (e: any) { console.warn("FileCipherWindow: load_templates:", String(e)); }
    }).catch((e: any) => console.warn("FileCipherWindow: load_templates:", String(e)));
  }, []);

  useEffect(() => {
    writeBooleanSetting(FILE_AUTO_CLOSE_STORAGE_KEY, autoCloseAfterAction);
  }, [autoCloseAfterAction]);

  const hexCoverage = (tmpl: TemplateInfo): number => {
    if (tmpl.name === "Livencrypt" || tmpl.name === "filelivencrypt") return 16;
    const hexSet = new Set('0123456789abcdef'.split(''));
    const tmplSet = new Set((tmpl.chars || []).map((c: string) => (c || '').toLowerCase()));
    let covered = 0;
    hexSet.forEach((h) => { if (tmplSet.has(h)) covered++; });
    return covered;
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

  const loadFile = async () => {
    if (!invoke) return log(t("fileCipher.missingTauri"));
    if (!filePath) return log(t("fileCipher.missingPath"));
    setLoadingFile(true);
    const t0 = performance.now();
    try {
      const info: any = await invoke("load_file_info", { path: filePath });
      const elapsed = Math.round(performance.now() - t0);
      setFileInfo(info);
      log(`✓ ${info.name} — ${formatLocalizedCompactNumber(info.size_bytes, language)} ${bytesLabel} (${formatLocalizedMilliseconds(elapsed, language)})`);
    } catch (e: any) {
      log(`✗ ${t("fileCipher.loadError", { error: String(e) })}`);
      setFileInfo(null);
    } finally {
      setLoadingFile(false);
    }
  };

  const handleFilePick = async () => {
    const path = await openFileDialog(t("fileCipher.selectFile"));
    if (path) {
      setFilePath(path);
      log(`📂 ${path}`);
      setLoadingFile(true);
      const t0 = performance.now();
      try {
        const info: any = await invoke("load_file_info", { path });
        const elapsed = Math.round(performance.now() - t0);
        setFileInfo(info);
        log(`  ${formatLocalizedCompactNumber(info.size_bytes, language)} ${bytesLabel} (${formatLocalizedMilliseconds(elapsed, language)})`);
      } catch (e: any) { log(`  ✗ ${e}`); setFileInfo(null); }
      finally { setLoadingFile(false); }
    } else {
      log(`⚠ ${t("fileCipher.pathUnavailable")}`);
    }
  };

  const execute = async () => {
    if (!invoke || !filePath || !referencia) return;
    const parsedCajas = parseCajasForCipher();
    if (!parsedCajas) return;

    // 1. Pedir al usuario dónde guardar el resultado
    const parentDir = filePath.replace(/\/[^/]*$/, "");
    const baseName = filePath.split("/").pop()?.replace(/\.[^.]+$/, "") || "resultado";
    const defaultOut = `${parentDir}/${baseName}_${mode === "cifrar" ? "cifrado.lvc" : "descifrado.txt"}`;
    const savePath = await saveFileDialog(defaultOut, t("fileCipher.saveResult"), t("fileCipher.savePathPrompt"));
    if (!savePath) return log(t("fileCipher.saveCancelled"));

    setLoading(true);
    const t0 = performance.now();
    try {
      const cmd = mode === "cifrar" ? "cipher_file" : "decipher_file";
      await invoke(cmd, {
        inputPath: filePath, outputPath: savePath, referencia,
        templateName: fileTemplate,
        caja1: parsedCajas[0], caja2: parsedCajas[1], caja3: parsedCajas[2],
        caja4: parsedCajas[3], caja5: parsedCajas[4],
        ...(mode === "descifrar" ? { isTxtOutput: true } : {}),
      });
      const elapsed = Math.round(performance.now() - t0);
      const action = mode === "cifrar" ? t("fileCipher.encryptedAction") : t("fileCipher.decryptedAction");
      log(`✓ ${action} → ${savePath} (${formatLocalizedMilliseconds(elapsed, language)})`);
      if (autoCloseAfterAction) {
        await invoke("panic_wipe_and_exit");
      }
    } catch (e: any) {
      log(`✗ ERROR: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setFilePath("");
    setFileInfo(null);
    setReferencia("");
    setConsoleLog([]);
    log(t("fileCipher.windowCleared"));
  };

  const palette = darkMode
    ? { bg: "bg-[#0B1120]", border: "border-cyan-900/30", input: "bg-slate-950 border-cyan-900/40 text-slate-200" }
    : { bg: "bg-white", border: "border-slate-200", input: "bg-white border-slate-300 text-slate-800" };

  const hasCajaErrors = cajas.some((v) => {
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
        <span className={`text-[11px] font-black uppercase tracking-[0.15em] ${darkMode ? "text-emerald-400" : "text-emerald-600"}`}>
          {t("fileCipher.title")}
        </span>
        <div className="flex-1" />
        <WindowSecurityActions onError={setSecurityError} />
      </header>
      {securityError ? (
        <div className="border-b border-red-500/30 bg-red-500/10 px-4 py-2 text-[9px] font-bold text-red-300">
          {securityError}
        </div>
      ) : null}

      <div className="flex-1 p-6 overflow-auto flex flex-col gap-4">
        {/* File selector */}
        <div className="flex gap-3 items-end">
          <div className="flex-1">
            <label className={`text-[9px] uppercase font-bold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>{t("fileCipher.path")}</label>
            <input value={filePath} onChange={(e) => setFilePath(e.target.value)}
              className={`w-full px-3 py-2 rounded-lg text-[11px] border font-mono ${palette.input}`}
              placeholder={t("fileCipher.pathPlaceholder")} />
          </div>
          <button onClick={handleFilePick}
            className={`px-3 py-2 rounded-lg text-[10px] font-bold border transition-all hover:scale-105 ${
              darkMode ? "border-slate-700 text-slate-500 hover:border-cyan-600" : "border-slate-200 text-slate-500 hover:border-cyan-400"
            }`}>
            📁
          </button>
          <button onClick={loadFile} disabled={loadingFile || !filePath}
            className={`px-4 py-2 rounded-lg text-[10px] font-black uppercase border transition-all ${
              loadingFile || !filePath ? "opacity-40 cursor-not-allowed" : "hover:scale-105"
            } ${darkMode ? "bg-slate-900 border-slate-700 text-slate-400" : "bg-slate-100 border-slate-300 text-slate-600"}`}>
            {loadingFile ? t("fileCipher.loading") : t("fileCipher.load")}
          </button>
        </div>

        {fileInfo && (
          <div className={`grid grid-cols-2 gap-3 p-3 rounded-xl border text-[10px] ${palette.border} ${palette.bg}`}>
            <div><span className={darkMode ? "text-slate-500" : "text-slate-400"}>{t("fileCipher.name")}</span> <span className="font-bold">{fileInfo.name}</span></div>
            <div><span className={darkMode ? "text-slate-500" : "text-slate-400"}>{t("fileCipher.bytes")}</span> <span className="font-bold">{formatLocalizedCompactNumber(fileInfo.size_bytes, language)}</span></div>
          </div>
        )}

        {/* Referencia + cajas */}
        <div className="flex gap-3 flex-wrap items-end">
          <div>
            <label className={`text-[9px] uppercase font-bold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>{t("fileCipher.reference")}</label>
            <input value={referencia} onChange={(e) => setReferencia(e.target.value)}
              className={`px-3 py-2 rounded-lg text-[11px] border font-mono ${palette.input}`}
              placeholder={t("fileCipher.referencePlaceholder")} />
          </div>
          {cajas.map((v, i) => (
            <div key={i}>
              <label className={`text-[8px] uppercase font-bold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                {t("common.box", { index: i + 1 })} {(() => {
                  const parsed = parseLocalizedInteger(v);
                  return parsed === null || parsed < 0 || parsed > 1000 ? t("common.boxRangeSuffix") : "";
                })()}
              </label>
              <input
                value={v}
                onChange={(e) => { const n = [...cajas]; n[i] = e.target.value; setCajas(n); }}
                className={`w-20 px-2 py-2 rounded-lg text-[11px] font-bold text-center border ${
                  (() => {
                    const parsed = parseLocalizedInteger(v);
                    return parsed === null || parsed < 0 || parsed > 1000;
                  })()
                    ? "border-red-500/50 bg-red-950/10"
                    : palette.input
                }`} />
            </div>
          ))}
        </div>

        {/* Execute / Limpiar */}
        <div className="flex gap-3 flex-wrap items-center">
          <label className={`flex items-center gap-1.5 px-3 py-3 rounded-xl border cursor-pointer transition-all text-[9px] font-bold ${
            mode === "cifrar"
              ? darkMode ? "bg-emerald-600/10 border-emerald-500/40 text-emerald-400" : "bg-emerald-50 border-emerald-400 text-emerald-700"
              : darkMode ? "border-slate-800 text-slate-500" : "border-slate-200 text-slate-400"
          }`}>
            <input type="radio" name="fmode" checked={mode === "cifrar"} onChange={() => setMode("cifrar")} className="sr-only" />
            <span className={`w-3 h-3 rounded-full border-2 flex items-center justify-center ${
              mode === "cifrar" ? (darkMode ? "border-emerald-400" : "border-emerald-500") : (darkMode ? "border-slate-600" : "border-slate-300")
            }`}>
              {mode === "cifrar" && <span className={`w-1.5 h-1.5 rounded-full ${darkMode ? "bg-emerald-400" : "bg-emerald-500"}`} />}
            </span>
            {t("textCipher.encrypt")}
          </label>
          <label className={`flex items-center gap-1.5 px-3 py-3 rounded-xl border cursor-pointer transition-all text-[9px] font-bold ${
            mode === "descifrar"
              ? darkMode ? "bg-emerald-600/10 border-emerald-500/40 text-emerald-400" : "bg-emerald-50 border-emerald-400 text-emerald-700"
              : darkMode ? "border-slate-800 text-slate-500" : "border-slate-200 text-slate-400"
          }`}>
            <input type="radio" name="fmode" checked={mode === "descifrar"} onChange={() => setMode("descifrar")} className="sr-only" />
            <span className={`w-3 h-3 rounded-full border-2 flex items-center justify-center ${
              mode === "descifrar" ? (darkMode ? "border-emerald-400" : "border-emerald-500") : (darkMode ? "border-slate-600" : "border-slate-300")
            }`}>
              {mode === "descifrar" && <span className={`w-1.5 h-1.5 rounded-full ${darkMode ? "bg-emerald-400" : "bg-emerald-500"}`} />}
            </span>
            {t("textCipher.decrypt")}
          </label>
          <div className="relative">
            <select
              value={fileTemplate}
              onChange={(e) => setFileTemplate(e.target.value)}
              className={`appearance-none px-3 py-3 pr-7 rounded-xl text-[8px] font-bold border cursor-pointer outline-none ${
                darkMode ? "bg-[#020617] border-cyan-900/40 text-cyan-300 hover:border-cyan-500/50" : "bg-white border-slate-300 text-cyan-700 hover:border-cyan-400"
              }`}
            >
            {templates.length > 0 && (
              <optgroup label={`── ${t("fileCipher.templatesGroup")} ──`}>
                {templates.map((template) => {
                  const cov = hexCoverage(template);
                  return (
                    <option key={template.name} value={template.name}>
                      {template.name} ({formatLocalizedInteger(template.rows, language)}×{formatLocalizedInteger(template.cols, language)}) {cov === 16 ? "✓" : `⚠${formatLocalizedInteger(cov, language)}/16`}
                    </option>
                  );
                })}
              </optgroup>
            )}
            </select>
            <span className={`pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-[7px] ${darkMode ? "text-cyan-400" : "text-cyan-600"}`}>
              ▼
            </span>
          </div>
          <button onClick={execute} disabled={loading || !filePath || !referencia || hasCajaErrors}
            className={`px-6 py-3 rounded-xl text-[11px] font-black uppercase border transition-all ${
              loading || !filePath || !referencia || hasCajaErrors ? "opacity-30 cursor-not-allowed" : "hover:scale-105"
            } ${darkMode ? "bg-emerald-600/20 border-emerald-500/40 text-emerald-400" : "bg-emerald-50 border-emerald-500/50 text-emerald-700"}`}>
            {loading ? t("common.processing") : t("fileCipher.executeSave")}
          </button>
          <button onClick={handleClear}
            className={`px-6 py-3 rounded-xl text-[11px] font-black uppercase border transition-all hover:scale-105 ${
              darkMode ? "bg-slate-900 border-slate-700 text-slate-400" : "bg-slate-100 border-slate-300 text-slate-500"
            }`}>
            {t("common.clean")}
          </button>
          <button
            type="button"
            onClick={() => setAutoCloseAfterAction((value) => !value)}
            className={`px-4 py-3 rounded-xl text-[10px] font-black uppercase border transition-all hover:scale-105 ${
              autoCloseAfterAction
                ? darkMode ? "bg-rose-600/20 border-rose-500/40 text-rose-300" : "bg-rose-50 border-rose-400 text-rose-700"
                : darkMode ? "bg-slate-900 border-slate-700 text-slate-400" : "bg-slate-100 border-slate-300 text-slate-500"
            }`}
            title={t("fileCipher.autoCloseAfterActionHelp")}
          >
            {autoCloseAfterAction ? t("settings.deactivate") : t("settings.activate")} · {t("fileCipher.autoCloseAfterAction")}
          </button>
        </div>
      </div>

      <div className={`flex-1 min-h-[120px] border-t p-2 overflow-y-auto ${palette.border}`}>
        {consoleLog.map((l, i) => (
          <div key={i} className="text-[10px] font-mono leading-relaxed">
            <ClickableLog text={l} darkMode={darkMode} openFolderTitle={(path) => t("fileCipher.openFolderTitle", { path })} />
          </div>
        ))}
      </div>
    </div>
  );
}

function ClickableLog({ text, darkMode, openFolderTitle }: { text: string; darkMode: boolean; openFolderTitle: (path: string) => string }) {
  // Render paths (starting with /) as clickable links that open the folder
  const parts = text.split(/(\/[^\s,;]*)/g);
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith("/") && part.length > 1) {
          const dir = part.replace(/\/[^/]*$/, "") || "/";
          return (
            <button
              key={i}
              onClick={async () => {
                try {
                  await invoke("open_folder", { path: dir });
                } catch (e: any) { console.warn("FileCipherWindow: clipboard:", String(e));
                  navigator.clipboard.writeText(part).catch((e: any) => console.warn("FileCipherWindow: clipboard:", String(e)));
                }
              }}
              className={`underline decoration-dotted cursor-pointer hover:brightness-150 ${
                darkMode ? "text-cyan-400/80" : "text-cyan-600"
              }`}
              title={openFolderTitle(dir)}
            >
              {part}
            </button>
          );
        }
        return <span key={i} className={darkMode ? "text-slate-500" : "text-slate-400"}>{part}</span>;
      })}
    </>
  );
}
