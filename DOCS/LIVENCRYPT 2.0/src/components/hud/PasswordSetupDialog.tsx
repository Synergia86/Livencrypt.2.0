// SPDX-License-Identifier: GPL-3.0-or-later

import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Lock, ArrowRight, ArrowLeft } from "lucide-react";
import { useTranslation } from "../../context/LanguageContext";
import { formatLocalizedInteger, parseLocalizedInteger } from "../../i18n/numerals";

interface PasswordSetupDialogProps {
  isOpen: boolean;
  passwordLength: number;
  passwordDirection: "after" | "before";
  controlSymbols: string;
  onApply: (length: number, direction: "after" | "before", controlSymbols: string) => void;
  onCancel: () => void;
  darkMode: boolean;
}

const CONTROL_SYMBOLS = "¢|@#~½¶←↓→ˀ|¢ª─¬";

export default function PasswordSetupDialog({
  isOpen, passwordLength, passwordDirection, controlSymbols, onApply, onCancel, darkMode,
}: PasswordSetupDialogProps) {
  const { language, t } = useTranslation();
  const [length, setLength] = useState(passwordLength);
  const [direction, setDirection] = useState<"after" | "before">(passwordDirection);
  const [symbols, setSymbols] = useState(controlSymbols || CONTROL_SYMBOLS);

  useEffect(() => {
    if (!isOpen) return;
    setLength(passwordLength);
    setDirection(passwordDirection);
    setSymbols(controlSymbols || CONTROL_SYMBOLS);
  }, [controlSymbols, isOpen, passwordDirection, passwordLength]);

  const normalizeSymbols = (value: string) => {
    let normalized = "";
    for (const symbol of Array.from(value).filter((symbol) => !/\s/u.test(symbol))) {
      if (!normalized.includes(symbol)) normalized += symbol;
    }
    return normalized || CONTROL_SYMBOLS;
  };

  const handleApply = () => {
    const len = Math.max(2, Math.min(length, 25));
    onApply(len, direction, normalizeSymbols(symbols));
  };

  const samplePassword = t("password.samplePassword");

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: "rgba(2, 6, 23, 0.85)" }}
        >
          <motion.div
            initial={{ scale: 0.95, opacity: 0, y: 10 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.95, opacity: 0, y: 10 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            className={`w-[440px] rounded-2xl border backdrop-blur-xl shadow-2xl overflow-hidden ${
              darkMode ? "bg-slate-950/95 border-emerald-900/30" : "bg-white/95 border-emerald-200"
            }`}
          >
            {/* Header */}
            <div className={`flex items-center gap-3 px-5 py-4 border-b ${
              darkMode ? "border-emerald-900/20" : "border-emerald-100"
            }`}>
              <div className={`p-1.5 rounded-lg ${darkMode ? "bg-emerald-500/10" : "bg-emerald-50"}`}>
                <Lock size={18} className={darkMode ? "text-emerald-400" : "text-emerald-600"} />
              </div>
              <div>
                <h2 className={`text-[11px] font-black uppercase tracking-widest ${darkMode ? "text-slate-200" : "text-slate-800"}`}>
                  {t("password.setupTitle")}
                </h2>
                <p className={`text-[8px] font-bold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                  {t("password.setupSubtitle")}
                </p>
              </div>
              <div className="flex-1" />
              <button onClick={onCancel}
                className={`p-1.5 rounded-lg transition-all hover:scale-110 ${darkMode ? "text-slate-600 hover:text-slate-400" : "text-slate-400 hover:text-slate-600"}`}>
                ✕
              </button>
            </div>

            {/* Body */}
            <div className="p-5 space-y-4">
              {/* Password length */}
              <div>
                <label className={`text-[9px] uppercase font-black tracking-widest block mb-2 ${darkMode ? "text-slate-400" : "text-slate-600"}`}>
                  {t("password.lengthLimit")}
                </label>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setLength((l) => Math.max(2, l - 1))}
                    className={`px-2 py-1.5 rounded-lg text-[10px] font-bold border ${
                      darkMode ? "bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600" : "bg-slate-50 border-slate-200 text-slate-500"
                    }`}>−</button>
                  <input
                    type="text"
                    inputMode="text"
                    value={formatLocalizedInteger(length, language)}
                    onChange={(e) => {
                      const parsed = parseLocalizedInteger(e.target.value);
                      setLength(Math.max(2, Math.min(25, parsed ?? 2)));
                    }}
                    className={`w-20 px-3 py-1.5 rounded-lg text-[12px] font-bold text-center border outline-none ${
                      darkMode ? "bg-slate-950 border-emerald-900/40 text-emerald-400" : "bg-white border-emerald-200 text-emerald-600"
                    }`}
                  />
                  <button
                    onClick={() => setLength((l) => Math.min(25, l + 1))}
                    className={`px-2 py-1.5 rounded-lg text-[10px] font-bold border ${
                      darkMode ? "bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600" : "bg-slate-50 border-slate-200 text-slate-500"
                    }`}>+</button>
                  <span className={`text-[8px] font-bold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                    {t("password.lengthRangeLocalized", {
                      min: formatLocalizedInteger(2, language),
                      max: formatLocalizedInteger(25, language),
                    })}
                  </span>
                </div>
              </div>

              {/* Direction */}
              <div>
                <label className={`text-[9px] uppercase font-black tracking-widest block mb-2 ${darkMode ? "text-slate-400" : "text-slate-600"}`}>
                  {t("password.position")}
                </label>
                <div className="flex gap-3">
                  <label className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border cursor-pointer transition-all ${
                    direction === "after"
                      ? darkMode ? "bg-emerald-600/10 border-emerald-500/40 text-emerald-400" : "bg-emerald-50 border-emerald-400 text-emerald-700"
                      : darkMode ? "border-slate-800 text-slate-500" : "border-slate-200 text-slate-400"
                  }`}>
                    <input type="radio" name="pwdir" checked={direction === "after"} onChange={() => setDirection("after")} className="sr-only" />
                    <ArrowLeft size={18} />
                    <div>
                      <div className="text-[9px] font-black uppercase">{t("password.afterSymbol")}</div>
                      <div className={`text-[7px] ${darkMode ? "text-emerald-500" : "text-emerald-700"}`}>{samplePassword}~</div>
                    </div>
                  </label>
                  <label className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border cursor-pointer transition-all ${
                    direction === "before"
                      ? darkMode ? "bg-emerald-600/10 border-emerald-500/40 text-emerald-400" : "bg-emerald-50 border-emerald-400 text-emerald-700"
                      : darkMode ? "border-slate-800 text-slate-500" : "border-slate-200 text-slate-400"
                  }`}>
                    <input type="radio" name="pwdir" checked={direction === "before"} onChange={() => setDirection("before")} className="sr-only" />
                    <ArrowRight size={18} />
                    <div>
                      <div className="text-[9px] font-black uppercase">{t("password.beforeSymbol")}</div>
                      <div className={`text-[7px] ${darkMode ? "text-emerald-500" : "text-emerald-700"}`}>~{samplePassword}</div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Control symbols */}
              <div className={`p-3 rounded-lg border text-[9px] leading-relaxed ${
                darkMode ? "bg-slate-900/60 border-slate-800" : "bg-slate-50 border-slate-200"
              }`}>
                <span className={`font-bold ${darkMode ? "text-slate-300" : "text-slate-600"}`}>{t("password.controlSymbols")}</span>
                <br />
                <code className={`text-[10px] mt-1 block font-mono tracking-wider ${darkMode ? "text-emerald-400" : "text-emerald-600"}`}>
                  {Array.from(normalizeSymbols(symbols)).join("  ")}
                </code>
                <input
                  value={symbols}
                  onChange={(event) => setSymbols(event.target.value)}
                  className={`mt-2 w-full px-3 py-2 rounded-lg text-[11px] font-mono border outline-none ${
                    darkMode ? "bg-slate-950 border-emerald-900/40 text-emerald-300 focus:border-emerald-500/50" : "bg-white border-emerald-200 text-emerald-700 focus:border-emerald-400"
                  }`}
                  placeholder={CONTROL_SYMBOLS}
                />
                <p className={`mt-2 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                  {t("password.controlSymbolsHelp")}
                </p>
              </div>
            </div>

            {/* Footer */}
            <div className={`flex gap-3 px-5 py-4 border-t ${darkMode ? "border-emerald-900/20" : "border-emerald-100"}`}>
              <button onClick={onCancel}
                className={`flex-1 py-2.5 rounded-lg text-[10px] font-black uppercase border transition-all hover:scale-105 ${
                  darkMode ? "border-slate-700 text-slate-400 hover:bg-slate-900" : "border-slate-200 text-slate-500 hover:bg-slate-50"
                }`}>
                {t("common.cancel")}
              </button>
              <button onClick={handleApply}
                className={`flex-1 py-2.5 rounded-lg text-[10px] font-black uppercase border transition-all hover:scale-105 ${
                  darkMode ? "bg-emerald-600/20 border-emerald-500/40 text-emerald-400 hover:bg-emerald-600/30" : "bg-emerald-50 border-emerald-400 text-emerald-700 hover:bg-emerald-100"
                }`}>
                {t("common.apply")}
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
