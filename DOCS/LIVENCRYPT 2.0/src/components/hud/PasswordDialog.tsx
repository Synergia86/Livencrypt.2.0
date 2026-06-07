// SPDX-License-Identifier: GPL-3.0-or-later

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Lock, Eye, EyeOff, ShieldAlert } from "lucide-react";
import { useTranslation } from "../../context/LanguageContext";

interface PasswordDialogProps {
  isOpen: boolean;
  mode: "cifrar" | "descifrar";
  maxAttempts: number;
  onVerify: (input: string) => boolean;
  onCancel: () => void;
  passwordLength: number;
  passwordDirection: "after" | "before";
  controlSymbols: string;
  darkMode: boolean;
}

const CONTROL_SYMBOLS = "¢|@#~½¶←↓→ˀ|¢ª─¬";

export default function PasswordDialog({
  isOpen, mode, maxAttempts, onVerify, onCancel, passwordLength, passwordDirection, controlSymbols, darkMode,
}: PasswordDialogProps) {
  const { t } = useTranslation();
  const [input, setInput] = useState("");
  const [attempts, setAttempts] = useState(0);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setInput("");
      setAttempts(0);
      setError(null);
      setLocked(false);
      setShowPassword(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [isOpen]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
      if (e.key === "Enter" && isOpen && !locked) handleVerify();
    };
    if (isOpen) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isOpen, input, attempts, locked]);

  const handleVerify = () => {
    if (!input.trim() || locked) return;
    const correct = onVerify(input);
    if (correct) {
      setError(null);
      onCancel();
    } else {
      const remaining = attempts + 1;
      setAttempts(remaining);
      if (remaining >= maxAttempts) {
        setLocked(true);
        setError(t("password.blocked", { count: maxAttempts }));
      } else {
        setError(t("password.incorrect", { count: maxAttempts - remaining }));
      }
      setInput("");
      inputRef.current?.focus();
    }
  };

  const isCifrar = mode === "cifrar";
  const activeSymbols = controlSymbols || CONTROL_SYMBOLS;
  const exampleSymbol = Array.from(activeSymbols)[0] || "¢";
  const examplePassword = "x".repeat(Math.max(1, passwordLength - 1));
  const example = passwordDirection === "after"
    ? `${examplePassword}${exampleSymbol}`
    : `${exampleSymbol}${examplePassword}`;

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: "rgba(2, 6, 23, 0.85)" }}
        >
          <motion.div
            initial={{ scale: 0.95, opacity: 0, y: 10 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.95, opacity: 0, y: 10 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            className={`w-[420px] rounded-2xl border backdrop-blur-xl shadow-2xl overflow-hidden ${
              darkMode ? "bg-slate-950/95 border-cyan-900/30" : "bg-white/95 border-slate-200"
            }`}
          >
            {/* Header */}
            <div className={`flex items-center gap-3 px-5 py-4 border-b ${
              darkMode ? "border-cyan-900/20" : "border-slate-100"
            }`}>
              <div className={`p-1.5 rounded-lg ${locked
                ? darkMode ? "bg-red-500/10" : "bg-red-50"
                : darkMode ? "bg-amber-500/10" : "bg-amber-50"
              }`}>
                {locked
                  ? <ShieldAlert size={18} className={darkMode ? "text-red-400" : "text-red-600"} />
                  : <Lock size={18} className={darkMode ? "text-amber-400" : "text-amber-600"} />
                }
              </div>
              <div>
                <h2 className={`text-[11px] font-black uppercase tracking-widest ${
                  darkMode ? "text-slate-200" : "text-slate-800"
                }`}>
                  {isCifrar ? t("password.detectedTitle") : t("password.verifyTitle")}
                </h2>
                <p className={`text-[8px] font-bold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                  {isCifrar ? t("password.detectedSubtitle") : t("password.protectedSubtitle")}
                </p>
              </div>
              <div className="flex-1" />
              {!locked && (
                <button onClick={onCancel}
                  className={`p-1.5 rounded-lg transition-all hover:scale-110 ${
                    darkMode ? "text-slate-600 hover:text-slate-400" : "text-slate-400 hover:text-slate-600"
                  }`}>
                  ✕
                </button>
              )}
            </div>

            {/* Body */}
            <div className="p-5 space-y-4">
              {/* Info */}
              <div className={`p-3 rounded-lg border text-[9px] leading-relaxed ${
                darkMode ? "bg-slate-900/60 border-slate-800 text-slate-400" : "bg-slate-50 border-slate-200 text-slate-600"
              }`}>
                <span className="font-bold text-slate-300">
                  {isCifrar ? t("password.controlSymbolsDetected") : t("password.specialDetected")}
                </span>
                <br />
                <code className={`text-[10px] mt-1 block font-mono ${darkMode ? "text-amber-400" : "text-amber-600"}`}>
                  {Array.from(activeSymbols).join(" ")}
                </code>
                <p className="mt-2">
                  {isCifrar
                    ? t("password.detectedInfo", { length: passwordLength, example })
                    : t("password.verifyInfo")}
                </p>
              </div>

              {/* Input */}
              <div>
                <label className={`text-[8px] uppercase font-black tracking-widest block mb-1.5 ${
                  darkMode ? "text-slate-500" : "text-slate-400"
                }`}>
                  {t("password.passwordLabel")}
                </label>
                <div className="relative">
                  <input
                    ref={inputRef}
                    type={showPassword ? "text" : "password"}
                    value={input}
                    onChange={(e) => { setInput(e.target.value); setError(null); }}
                    disabled={locked}
                    className={`w-full px-3 py-2.5 rounded-lg text-[12px] font-mono border outline-none transition-all ${
                      locked ? "opacity-40 cursor-not-allowed" : ""
                    } ${
                      darkMode
                        ? "bg-slate-950 border-slate-700 text-slate-200 focus:border-amber-500/50"
                        : "bg-white border-slate-300 text-slate-800 focus:border-amber-400"
                    }`}
                    placeholder={isCifrar ? t("password.examplePlaceholder", { example }) : t("password.originalPlaceholder")}
                  />
                  <button
                    onClick={() => setShowPassword(!showPassword)}
                    className={`absolute right-2.5 top-1/2 -translate-y-1/2 p-1 rounded transition-all ${
                      darkMode ? "text-slate-600 hover:text-slate-400" : "text-slate-400 hover:text-slate-600"
                    }`}
                    tabIndex={-1}
                  >
                    {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>

              {/* Attempts */}
              <div className="flex items-center gap-2">
                <span className={`text-[8px] uppercase font-bold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                  {t("password.attempts")}
                </span>
                {[...Array(maxAttempts)].map((_, i) => (
                  <span
                    key={i}
                    className={`w-2.5 h-2.5 rounded-full transition-all duration-200 ${
                      i < attempts
                        ? darkMode ? "bg-red-500/60" : "bg-red-400"
                        : darkMode ? "bg-slate-700" : "bg-slate-200"
                    }`}
                  />
                ))}
                <span className={`text-[8px] font-bold ml-1 ${attempts >= maxAttempts - 1 ? "text-red-400" : darkMode ? "text-slate-500" : "text-slate-400"}`}>
                  {t("password.remaining", { count: maxAttempts - attempts })}
                </span>
              </div>

              {/* Error */}
              {error && (
                <div className={`p-2.5 rounded-lg border text-[9px] font-bold ${
                  locked
                    ? darkMode ? "bg-red-950/20 border-red-900/40 text-red-400" : "bg-red-50 border-red-200 text-red-600"
                    : darkMode ? "bg-amber-950/10 border-amber-900/30 text-amber-400" : "bg-amber-50 border-amber-200 text-amber-700"
                }`}>
                  {error}
                </div>
              )}
            </div>

            {/* Footer */}
            <div className={`flex gap-3 px-5 py-4 border-t ${
              darkMode ? "border-cyan-900/20" : "border-slate-100"
            }`}>
              {locked ? (
                <button
                  onClick={onCancel}
                  className={`flex-1 py-2.5 rounded-lg text-[10px] font-black uppercase border transition-all hover:scale-105 ${
                    darkMode ? "bg-red-600/20 border-red-500/40 text-red-400" : "bg-red-50 border-red-400 text-red-600"
                  }`}
                >
                  {t("common.close")}
                </button>
              ) : (
                <>
                  <button
                    onClick={onCancel}
                    className={`flex-1 py-2.5 rounded-lg text-[10px] font-black uppercase border transition-all hover:scale-105 ${
                      darkMode ? "border-slate-700 text-slate-400 hover:bg-slate-900" : "border-slate-200 text-slate-500 hover:bg-slate-50"
                    }`}
                  >
                    {t("common.cancel")}
                  </button>
                  <button
                    onClick={handleVerify}
                    disabled={!input.trim()}
                    className={`flex-1 py-2.5 rounded-lg text-[10px] font-black uppercase border transition-all ${
                      !input.trim() ? "opacity-40 cursor-not-allowed" : "hover:scale-105"
                    } ${
                      darkMode ? "bg-amber-600/20 border-amber-500/40 text-amber-400 hover:bg-amber-600/30" : "bg-amber-50 border-amber-400 text-amber-700 hover:bg-amber-100"
                    }`}
                  >
                    {t("common.verify")}
                  </button>
                </>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
