// SPDX-License-Identifier: GPL-3.0-or-later

import { useEffect, useState } from "react";
import invoke from "../../invoke";

export interface TemplateData {
  rows: number;
  cols: number;
  chars: string[];
}

interface TemplateSelectorProps {
  onSelect: (name: string, data: TemplateData) => void;
  darkMode: boolean;
}

export default function TemplateSelector({ onSelect, darkMode }: TemplateSelectorProps) {
  const [templates, setTemplates] = useState<Record<string, TemplateData>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    invoke("list_templates").then((tmpl: unknown) => {
      const list = tmpl as Record<string, TemplateData>;
      if (list) setTemplates(list);
    }).catch((e: any) => { console.warn('TemplateSelector: list_templates:', String(e)); }).finally(() => setLoading(false));
  }, []);

  const names = Object.keys(templates);

  if (loading) {
    return (
      <div className={`px-4 py-3 text-xs ${darkMode ? "text-emerald-400" : "text-emerald-700"}`}>
        Cargando plantillas...
      </div>
    );
  }

  if (names.length === 0) {
    return (
      <div className={`px-4 py-3 text-xs ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
        No hay plantillas disponibles
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {names.map(name => (
        <button
          key={name}
          onClick={() => templates[name] && onSelect(name, templates[name])}
          className={`w-full text-left px-3 py-2 text-xs rounded-lg transition-colors ${
            darkMode
              ? "bg-slate-800/60 hover:bg-emerald-900/40 text-slate-300 hover:text-emerald-300 border border-slate-700/50"
              : "bg-slate-50 hover:bg-emerald-50 text-slate-700 hover:text-emerald-700 border border-slate-200"
          }`}
        >
          {name}
        </button>
      ))}
    </div>
  );
}
