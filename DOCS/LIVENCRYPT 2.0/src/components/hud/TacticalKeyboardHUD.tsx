// SPDX-License-Identifier: GPL-3.0-or-later

import { motion } from "framer-motion";
import { Delete, CornerDownLeft, Space } from "lucide-react";
import type { TemplateData } from "../dashboard/TemplateSelector";

interface TacticalKeyboardHUDProps {
  template: TemplateData | null;
  onKeyPress: (char: string) => void;
  onBackspace: () => void;
  onSpace: () => void;
  darkMode: boolean;
}

export default function TacticalKeyboardHUD({ template, onKeyPress, onBackspace, onSpace, darkMode }: TacticalKeyboardHUDProps) {
  if (!template) {
    return (
      <div className={`p-3 rounded-xl border border-dashed text-center text-[8px] uppercase font-black ${darkMode ? "bg-slate-900/20 border-slate-800 text-slate-600" : "bg-slate-50 border-slate-200 text-slate-300"}`}>
        Seleccione plantilla
      </div>
    );
  }

  const rows: string[][] = [];
  for (let i = 0; i < template.rows; i++) {
    rows.push(template.chars.slice(i * template.cols, (i + 1) * template.cols));
  }

  return (
    <div className={`p-2 rounded-xl border ${darkMode ? "bg-slate-950/50 border-slate-800" : "bg-slate-50 border-slate-200"}`}>
      <div className="flex flex-col gap-1">
        {rows.map((row, ri) => (
          <div key={ri} className="flex gap-1 justify-center flex-wrap">
            {row.map((ch, ci) => (
              <motion.button
                key={`${ri}-${ci}`}
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.9 }}
                onClick={() => ch === "␣" ? onSpace() : onKeyPress(ch)}
                className={`w-7 h-7 rounded-md border text-[10px] font-sans font-bold flex items-center justify-center transition-all ${
                  darkMode
                    ? "bg-slate-900 border-slate-700 text-slate-300 hover:border-cyan-500 hover:text-cyan-400"
                    : "bg-white border-slate-300 text-slate-700 hover:border-cyan-600 hover:text-cyan-600"
                }`}
              >
                {ch === "␣" ? <Space size={10} /> : ch}
              </motion.button>
            ))}
          </div>
        ))}

        <div className="flex gap-1 justify-center mt-1">
          <motion.button whileTap={{ scale: 0.9 }} onClick={onBackspace}
            className={`px-3 h-7 rounded-md border text-[8px] font-black uppercase flex items-center gap-1 ${
              darkMode ? "bg-red-950/20 border-red-900/50 text-red-500 hover:bg-red-900/30" : "bg-red-50 border-red-200 text-red-600 hover:bg-red-100"
            }`}>
            <Delete size={10} /> Borrar
          </motion.button>
          <motion.button whileTap={{ scale: 0.9 }} onClick={onSpace}
            className={`px-5 h-7 rounded-md border text-[8px] font-black uppercase flex items-center gap-1 ${
              darkMode ? "bg-slate-900 border-slate-700 text-slate-400" : "bg-white border-slate-300 text-slate-600"
            }`}>
            <Space size={10} /> Espacio
          </motion.button>
          <motion.button whileTap={{ scale: 0.9 }} onClick={() => onKeyPress("\n")}
            className={`px-3 h-7 rounded-md border text-[8px] font-black uppercase flex items-center gap-1 ${
              darkMode ? "bg-cyan-600 border-cyan-500 text-white hover:bg-cyan-500" : "bg-cyan-700 border-cyan-600 text-white"
            }`}>
            Enter <CornerDownLeft size={10} />
          </motion.button>
        </div>
      </div>
    </div>
  );
}
