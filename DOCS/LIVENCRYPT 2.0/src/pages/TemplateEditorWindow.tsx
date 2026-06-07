// SPDX-License-Identifier: GPL-3.0-or-later

import { useState, useEffect, useMemo } from "react";
import type { TemplateData } from "../components/dashboard/TemplateSelector";
import WindowSecurityActions from "../components/hud/WindowSecurityActions";
import invoke from "../invoke";
import { useTranslation } from "../context/LanguageContext";
import type { Language } from "../i18n";
import { formatLocalizedInteger, formatLocalizedTime, parseLocalizedInteger } from "../i18n/numerals";


interface Props { darkMode: boolean; }

const UNICODE_ESCAPE_PATTERN = /\\+u\{([0-9a-fA-F]+)\}|\\+u([0-9a-fA-F]{4})/g;

const decodeEscapedUnicode = (value: string) => value.replace(
  UNICODE_ESCAPE_PATTERN,
  (match, braced: string | undefined, short: string | undefined) => {
    const hex = braced ?? short;
    if (!hex) return match;
    const codePoint = Number.parseInt(hex, 16);
    return Number.isFinite(codePoint) ? String.fromCodePoint(codePoint) : match;
  },
);

const normalizeTemplateData = (data: TemplateData): TemplateData => ({
  ...data,
  chars: (data.chars ?? []).map((char) => decodeEscapedUnicode(String(char))),
});

const normalizeTemplates = (rawTemplates: Record<string, TemplateData> | null | undefined) => {
  if (!rawTemplates) return {};

  return Object.fromEntries(
    Object.entries(rawTemplates).map(([name, data]) => [
      name,
      normalizeTemplateData(data),
    ]),
  );
};

const fallbackLabelCollator = new Intl.Collator("es", {
  numeric: true,
  sensitivity: "base",
});

const normalizeLanguageMap = (map: Record<string, string[]>) => Object.fromEntries(
  Object.entries(map)
    .sort(([left], [right]) => fallbackLabelCollator.compare(left, right))
    .map(([language, chars]) => [
      language,
      chars.map(decodeEscapedUnicode),
    ]),
);

const LANGUAGE_LABEL_CODES: Record<string, string> = {
  "Alemán": "de",
  "Amhárico": "am",
  "Árabe clásico": "ar",
  "Armenio": "hy",
  "Bengalí": "bn",
  "Birmano": "my",
  "Checo": "cs",
  "Cherokee": "chr",
  "Chino": "zh",
  "Coreano": "ko",
  "Devanágari": "hi",
  "Español": "es",
  "Francés": "fr",
  "Gales": "cy",
  "Georgiano": "ka",
  "Griego": "el",
  "Hindi": "hi",
  "Húngaro": "hu",
  "Inglés": "en",
  "Islandés": "is",
  "Japonés": "ja",
  "Kannada": "kn",
  "Katakana": "ja",
  "Khmer": "km",
  "Latín": "la",
  "Letón": "lv",
  "Lituano": "lt",
  "Polaco": "pl",
  "Portugués": "pt",
  "Rumano": "ro",
  "Ruso": "ru",
  "Tailandés": "th",
  "Tibetano": "bo",
  "Turco": "tr",
  "Vietnamita": "vi",
};

const CATALOG_LABEL_TRANSLATIONS: Record<string, Record<Language, string>> = {
  "Escandinavo": {
    es: "Escandinavo",
    en: "Scandinavian",
    zh: "斯堪的纳维亚语",
    ru: "Скандинавские",
    pt: "Escandinavo",
    de: "Skandinavisch",
    fr: "Scandinave",
    hi: "स्कैंडिनेवियाई",
    ja: "スカンジナビア語",
    ko: "스칸디나비아어",
    id: "Skandinavia",
  },
  "Etíope": {
    es: "Etíope",
    en: "Ethiopic",
    zh: "埃塞俄比亚文",
    ru: "Эфиопское письмо",
    pt: "Etíope",
    de: "Äthiopisch",
    fr: "Éthiopien",
    hi: "इथियोपिक",
    ja: "エチオピア文字",
    ko: "에티오피아 문자",
    id: "Etiopia",
  },
};

export default function TemplateEditorWindow({ darkMode }: Props) {
  const { language, t } = useTranslation();
  const [templates, setTemplates] = useState<Record<string, TemplateData>>({});
  const [langChars, setLangChars] = useState<Record<string, string[]>>({});
  const [numSigns, setNumSigns] = useState<Record<string, string[]>>({});
  const [presets, setPresets] = useState<[number, number][]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [name, setName] = useState("");
  const [rows, setRows] = useState(3);
  const [cols, setCols] = useState(56);
  const [consoleLog, setConsoleLog] = useState<string[]>([]);
  const [securityError, setSecurityError] = useState("");
  // F1: Editar plantilla existente
  const [editingTemplate, setEditingTemplate] = useState<string | null>(null);
  // F1 fix: Caracteres del editor (separados de selected para edición)
  const [editorChars, setEditorChars] = useState<string[]>([]);
  const labelCollator = useMemo(() => new Intl.Collator(language, {
    numeric: true,
    sensitivity: "base",
  }), [language]);
  const displayNames = useMemo(() => new Intl.DisplayNames([language], { type: "language" }), [language]);

  const log = (msg: string) => setConsoleLog((p) => [...p.slice(-29), `[${formatLocalizedTime(new Date(), language)}] ${msg}`]);
  const displayCatalogLabel = (label: string) => {
    if (label === "Signos") return t("templateEditor.signs");
    if (label === "Arábigos") return t("templateEditor.arabicDigits");
    const translated = CATALOG_LABEL_TRANSLATIONS[label]?.[language];
    if (translated) return translated;
    const code = LANGUAGE_LABEL_CODES[label];
    return code ? displayNames.of(code) ?? label : label;
  };
  const sortCatalogLabels = (labels: string[]) => [...labels].sort((left, right) =>
    labelCollator.compare(displayCatalogLabel(left), displayCatalogLabel(right)),
  );

  const reloadTemplates = async () => {
    if (!invoke) return;
    try { const tmpl: any = await invoke("load_templates"); setTemplates(normalizeTemplates(tmpl)); } catch (e: any) { console.warn("TemplateEditor: load_templates:", String(e)); }
  };

  const allSelectedChars = () => {
    // Siempre devuelve los caracteres acumulados en el editor
    if (editingTemplate) {
      // En modo edición: caracteres cargados de la plantilla + añadidos de la paleta
      const set = new Set(editorChars);
      selected.forEach((lang) => {
        (langChars[lang] || []).forEach((c) => set.add(c));
        (numSigns[lang] || []).forEach((c) => set.add(c));
      });
      return [...set];
    }
    // En modo creación: caracteres acumulados al hacer clic en la paleta
    return [...editorChars];
  };

  useEffect(() => {
    if (!invoke) return;
    (async () => {
      try {
        const [tmpl, lc, ns, ps]: any = await Promise.all([
          invoke("load_templates"),
          invoke("get_language_characters"),
          invoke("get_language_numbers_signs"),
          invoke("get_template_presets"),
        ]);
        const normalizedTemplates = normalizeTemplates(tmpl);
        setTemplates(normalizedTemplates);
        setLangChars(normalizeLanguageMap(lc));
        setNumSigns(normalizeLanguageMap(ns));
        setPresets(ps);
        log(t("templateEditor.loadedLog", {
          templates: formatLocalizedInteger(Object.keys(normalizedTemplates).length, language),
          languages: formatLocalizedInteger(Object.keys(lc).length, language),
        }));
      } catch (e: any) { log(`ERROR: ${e}`); }
    })();
  }, []);

  const toggleLang = (lang: string) => {
    const next = new Set(selected);
    if (next.has(lang)) next.delete(lang); else next.add(lang);
    setSelected(next);
  };

  const handleDelete = async (name: string) => {
    if (!invoke) return;
    if (!confirm(t("templateEditor.deleteConfirm", { name }))) return;
    try {
      await invoke("delete_template", { name });
      log(t("templateEditor.deletedLog", { name }));
      await reloadTemplates();
      // Si estábamos editando esta plantilla, cancelar edición
      if (editingTemplate === name) handleCancelEdit();
    } catch (e: any) { log(`ERROR: ${e}`); }
  };

  // F1: Cargar plantilla en el editor
  const handleEdit = (tmplName: string) => {
    const tmpl = templates[tmplName];
    if (!tmpl) return;
    setEditingTemplate(tmplName);
    setName(tmplName);
    setRows(tmpl.rows);
    setCols(tmpl.cols);
    // Cargar caracteres de la plantilla en el editor
    setEditorChars([...tmpl.chars]);
    // Limpiar selecciones de idioma (el usuario puede añadir más)
    setSelected(new Set());
      log(t("templateEditor.editingLog", {
      name: tmplName,
      rows: formatLocalizedInteger(tmpl.rows, language),
      cols: formatLocalizedInteger(tmpl.cols, language),
      count: formatLocalizedInteger(tmpl.chars.length, language),
    }));
  };

  // F1: Cancelar edición — volver a modo creación
  const handleCancelEdit = () => {
    setEditingTemplate(null);
    setName("");
    setSelected(new Set());
    setEditorChars([]);
    setRows(3);
    setCols(56);
    log(t("templateEditor.editCancelled"));
  };

  // F1: Guardar cambios (creación o edición)
  const handleSave = async () => {
    if (!invoke || !name.trim()) return log(t("templateEditor.needName"));
    const chars = allSelectedChars();
    if (chars.length === 0) return log(t("templateEditor.needChars"));
    try {
      await invoke("save_template", {
        name: name.trim(),
        data: { rows, cols, chars },
      });
      if (editingTemplate && name.trim() !== editingTemplate) {
        await invoke("delete_template", { name: editingTemplate });
        log(t("templateEditor.renamedLog", { oldName: editingTemplate, newName: name.trim() }));
      } else {
        log(t("templateEditor.savedLog", {
          name: name.trim(),
          rows: formatLocalizedInteger(rows, language),
          cols: formatLocalizedInteger(cols, language),
          count: formatLocalizedInteger(chars.length, language),
        }));
      }
      await reloadTemplates();
      window.dispatchEvent(new CustomEvent("templates:updated", { detail: { name: name.trim() } }));
      handleCancelEdit();
    } catch (e: any) { log(`ERROR: ${e}`); }
  };

  // F1 fix: Quitar un carácter del editor (en modo edición) o de la selección (en modo creación)
  const removeChar = (c: string) => {
    if (editingTemplate) {
      setEditorChars((prev) => prev.filter((x) => x !== c));
    } else {
      setEditorChars((prev) => prev.filter((x) => x !== c));
    }
  };

  // Límite de caracteres permitidos
  const cellLimit = rows * cols;

  // Añadir todos los caracteres de un idioma/números — respetando límite de celdas
  const addAllFromLang = (lang: string) => {
    const allFromLang: string[] = [];
    (langChars[lang] || []).forEach((c) => { if (!allFromLang.includes(c)) allFromLang.push(c); });
    (numSigns[lang] || []).forEach((c) => { if (!allFromLang.includes(c)) allFromLang.push(c); });

    const current = allSelectedChars();
    const remaining = cellLimit - current.length;
    if (remaining <= 0) {
      log(`⚠ ${t("templateEditor.limitReached", { count: formatLocalizedInteger(cellLimit, language), language: displayCatalogLabel(lang) })}`);
      return;
    }

    const chars = new Set(current);
    let inserted = 0;
    for (const c of allFromLang) {
      if (inserted >= remaining) break;
      if (!chars.has(c)) { chars.add(c); inserted++; }
    }
    setEditorChars([...chars]);

    if (inserted < allFromLang.length) {
      log(`⚠ ${t("templateEditor.insertedPartial", {
        inserted: formatLocalizedInteger(inserted, language),
        total: formatLocalizedInteger(allFromLang.length, language),
        language: displayCatalogLabel(lang),
        limit: formatLocalizedInteger(cellLimit, language),
      })}`);
    } else {
      log(`✓ ${t("templateEditor.insertedAll", { language: displayCatalogLabel(lang), count: formatLocalizedInteger(inserted, language) })}`);
    }
  };

  // Mezclar aleatoriamente (Fisher-Yates)
  const handleShuffle = () => {
    const chars = allSelectedChars();
    if (chars.length < 2) return log(t("templateEditor.needShuffle"));
    const arr = [...chars];
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    if (editingTemplate) {
      setEditorChars(arr);
    } else {
      setEditorChars(arr);
    }
    log(t("templateEditor.shuffled", { count: formatLocalizedInteger(arr.length, language) }));
  };

  // Verificar cobertura HEX
  const hexCheck = () => {
    const hexSet = new Set('0123456789abcdef'.split(''));
    const current = new Set(allSelectedChars().map((c) => c.toLowerCase()));
    const present: string[] = []; const missing: string[] = [];
    hexSet.forEach((h) => { if (current.has(h)) present.push(h); else missing.push(h); });
    return { present, missing, complete: missing.length === 0 };
  };

  const addMissingHexMinimum = () => {
    const { missing } = hexCheck();
    if (missing.length === 0) return log(t("templateEditor.hexAlreadyComplete"));
    const current = allSelectedChars();
    const remaining = cellLimit - current.length;
    if (remaining < missing.length) {
      return log(t("templateEditor.hexNoSpace", { count: formatLocalizedInteger(missing.length, language) }));
    }
    const next = [...new Set([...current, ...missing])];
    setEditorChars(next);
    log(t("templateEditor.hexAdded", { chars: missing.join(" ") }));
  };

  const palette = darkMode
    ? { bg: "bg-[#0B1120]", border: "border-cyan-900/30", input: "bg-slate-950 border-cyan-900/40 text-slate-200" }
    : { bg: "bg-white", border: "border-slate-200", input: "bg-white border-slate-300 text-slate-800" };

  const selectedChars = allSelectedChars();

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
        <span className={`text-[11px] font-black uppercase tracking-[0.15em] ${darkMode ? "text-amber-400" : "text-amber-600"}`}>
          {t("templateEditor.title")}
          {editingTemplate && (
            <span className={`ml-2 text-[9px] font-bold ${darkMode ? "text-cyan-400" : "text-cyan-600"}`}>
              · {t("common.editing")}: {editingTemplate}
            </span>
          )}
        </span>
        <div className="flex-1" />
        <span className={`text-[9px] font-bold ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
          {t("templateEditor.loaded", { count: formatLocalizedInteger(Object.keys(templates).length, language) })} | {t("templateEditor.selected", { count: formatLocalizedInteger(selectedChars.length, language) })}
        </span>
        <WindowSecurityActions onError={setSecurityError} />
      </header>
      {securityError ? (
        <div className="border-b border-red-500/30 bg-red-500/10 px-4 py-2 text-[9px] font-bold text-red-300">
          {securityError}
        </div>
      ) : null}

      <div className="flex-1 flex overflow-hidden">
        {/* Panel izquierdo: Idiomas */}
        <div className={`w-[340px] border-r p-4 overflow-y-auto ${palette.border}`}>
          <h3 className={`text-[10px] font-black uppercase tracking-widest mb-3 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
            {t("templateEditor.selectLanguages")}
          </h3>
          <div className="grid grid-cols-4 gap-1">
            {sortCatalogLabels(Object.keys(langChars)).map((lang) => (
              <button key={lang} onClick={() => toggleLang(lang)}
                className={`px-1.5 py-1 rounded text-[8px] font-bold transition-all border ${
                  selected.has(lang)
                    ? darkMode ? "bg-cyan-600/20 border-cyan-500/50 text-cyan-400" : "bg-cyan-50 border-cyan-400 text-cyan-700"
                    : darkMode ? "bg-slate-900/40 border-slate-800 text-slate-500" : "bg-slate-50 border-slate-200 text-slate-400"
                }`}>
                {displayCatalogLabel(lang)}
              </button>
            ))}
          </div>

          {/* Números/Signos */}
          <h3 className={`text-[10px] font-black uppercase tracking-widest mt-4 mb-2 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
            {t("templateEditor.numbersSigns")}
          </h3>
          <div className="grid grid-cols-4 gap-1">
            {sortCatalogLabels(Object.keys(numSigns)).map((ns) => (
              <button key={ns} onClick={() => toggleLang(ns)}
                className={`px-1.5 py-1 rounded text-[7px] font-bold transition-all border ${
                  selected.has(ns)
                    ? darkMode ? "bg-amber-600/20 border-amber-500/50 text-amber-400" : "bg-amber-50 border-amber-400 text-amber-700"
                    : darkMode ? "bg-slate-900/40 border-slate-800 text-slate-500" : "bg-slate-50 border-slate-200 text-slate-400"
                }`}>
                {displayCatalogLabel(ns)}
              </button>
            ))}
          </div>
        </div>

        {/* Panel central: Editor de caracteres */}
        <div className="flex-1 p-4 overflow-y-auto flex flex-col gap-3">
          {/* Cabecera: Tamaño y nombre */}
          <div className="flex gap-3 items-center flex-wrap flex-shrink-0">
            <h3 className={`text-[10px] font-black uppercase tracking-widest ${darkMode ? "text-cyan-400" : "text-cyan-600"}`}>
              {editingTemplate ? `${t("common.editing")}: ${editingTemplate}` : t("templateEditor.newTemplate")}
            </h3>
            <div className="relative">
            <select
              value={`${rows},${cols}`}
              onChange={(e) => { const [r, c] = e.target.value.split(",").map(Number); setRows(r); setCols(c); }}
              className={`appearance-none px-2 py-1 pr-6 rounded text-[9px] font-bold border cursor-pointer outline-none ${palette.input}`}>
              <option value="">{t("templateEditor.customSize")}</option>
              {presets.map(([r, c]) => (
                <option key={`${r},${c}`} value={`${r},${c}`}>{formatLocalizedInteger(r, language)}×{formatLocalizedInteger(c, language)}</option>
              ))}
            </select>
            <span className={`pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-[6px] ${darkMode ? "text-slate-500" : "text-slate-400"}`}>▼</span>
            </div>
            <div className="flex items-center">
              <button onClick={() => setRows((r) => Math.max(1, r - 1))}
                className={`px-0.5 rounded-l text-[7px] border-r-0 ${palette.input}`}>◀</button>
              <input type="text" inputMode="text" value={formatLocalizedInteger(rows, language)} onChange={(e) => setRows(parseLocalizedInteger(e.target.value) || 1)}
                className={`w-10 px-1 py-1 rounded-none text-[9px] font-bold text-center border-x-0 outline-none ${palette.input}`} placeholder="F" />
              <button onClick={() => setRows((r) => r + 1)}
                className={`px-0.5 rounded-r text-[7px] border-l-0 ${palette.input}`}>▶</button>
            </div>
            <div className="flex items-center">
              <button onClick={() => setCols((c) => Math.max(1, c - 1))}
                className={`px-0.5 rounded-l text-[7px] border-r-0 ${palette.input}`}>◀</button>
              <input type="text" inputMode="text" value={formatLocalizedInteger(cols, language)} onChange={(e) => setCols(parseLocalizedInteger(e.target.value) || 1)}
                className={`w-10 px-1 py-1 rounded-none text-[9px] font-bold text-center border-x-0 outline-none ${palette.input}`} placeholder="C" />
              <button onClick={() => setCols((c) => c + 1)}
                className={`px-0.5 rounded-r text-[7px] border-l-0 ${palette.input}`}>▶</button>
            </div>
            <span className="text-[9px] font-bold">{t("templateEditor.cells", { count: formatLocalizedInteger(rows * cols, language) })}</span>
            <span className={`text-[8px] ${
              rows * cols < selectedChars.length ? "text-red-400" : rows * cols > selectedChars.length ? "text-emerald-400" : "text-cyan-400"
            }`}>
                {rows * cols < selectedChars.length
                  ? `⚠ ${t("templateEditor.excess", { count: formatLocalizedInteger(selectedChars.length - rows * cols, language) })}`
                  : rows * cols > selectedChars.length
                    ? t("templateEditor.free", { count: formatLocalizedInteger(rows * cols - selectedChars.length, language) })
                    : `✓ ${t("templateEditor.exact")}`}
            </span>
            <div className="flex-1" />
            {/* HEX indicator */}
            <div
              className={`px-3 py-1.5 rounded text-[9px] font-black uppercase border cursor-help ${
                hexCheck().complete
                  ? "bg-emerald-600/20 border-emerald-500/40 text-emerald-400"
                  : "bg-red-600/20 border-red-500/40 text-red-400"
              }`}
              title={(() => {
                const h = hexCheck();
                return `${t("templateEditor.hexLabel")} ${h.complete ? `${t("templateEditor.hexComplete")} ✓` : `${t("templateEditor.hexIncomplete")} ⚠ (${formatLocalizedInteger(h.missing.length, language)})`}\n\n${t("templateEditor.present")}: ${h.present.join(" ")}\n${t("templateEditor.missing")}: ${h.missing.join(" ")}`;
              })()}
            >
              {t("templateEditor.hexLabel")} {formatLocalizedInteger(hexCheck().present.length, language)}/{formatLocalizedInteger(16, language)}
            </div>
            <button onClick={addMissingHexMinimum}
              className={`px-3 py-1.5 rounded text-[9px] font-black uppercase border transition-all hover:scale-105 ${
                darkMode ? "bg-emerald-600/15 border-emerald-500/40 text-emerald-400" : "bg-emerald-50 border-emerald-400 text-emerald-700"
              }`}
              title={t("templateEditor.addHexTitle")}>
              {t("templateEditor.addHexMinimum")}
            </button>
            {/* ALEATORIO */}
            <button onClick={handleShuffle}
              className={`px-3 py-1.5 rounded text-[9px] font-black uppercase border transition-all hover:scale-105 ${
                darkMode ? "bg-purple-600/20 border-purple-500/40 text-purple-400" : "bg-purple-50 border-purple-400 text-purple-600"
              }`}
              title={t("templateEditor.shuffleTitle")}>
              🎲 {t("templateEditor.shuffle")}
            </button>
            <input value={name} onChange={(e) => setName(e.target.value)}
              className={`w-48 px-3 py-1.5 rounded text-[9px] font-bold border ${palette.input}`}
              placeholder={t("templateEditor.templateNamePlaceholder")} />
            <button onClick={handleSave}
              className={`px-4 py-1.5 rounded text-[10px] font-black uppercase border transition-all hover:scale-105 ${
                darkMode ? "bg-amber-600/20 border-amber-500/40 text-amber-400" : "bg-amber-50 border-amber-500/50 text-amber-700"}`}>
              {editingTemplate ? t("common.save") : t("common.create")}
            </button>
            {editingTemplate && (
              <button onClick={handleCancelEdit}
                className={`px-4 py-1.5 rounded text-[10px] font-black uppercase border transition-all hover:scale-105 ${
                  darkMode ? "bg-slate-900 border-slate-700 text-slate-400" : "bg-slate-100 border-slate-300 text-slate-500"
                }`}>
                {t("common.cancel")}
              </button>
            )}
          </div>

          {/* PALETA: Caracteres disponibles de los idiomas seleccionados */}
          <div className={`flex-shrink-0 p-3 rounded-xl border ${darkMode ? "bg-slate-950/40 border-slate-800" : "bg-slate-50 border-slate-200"}`}>
            <div className="flex items-center justify-between mb-2">
              <h4 className={`text-[9px] font-black uppercase tracking-widest ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
                {t("templateEditor.palette")}
              </h4>
              <div className="flex items-center gap-2">
                <span className="text-[7px] text-slate-600">
                  {t("templateEditor.selectedLanguagesHint", { count: formatLocalizedInteger(selected.size, language) })}
                </span>
                {selected.size > 0 && (
                  <button
                    onClick={() => {
                      selected.forEach((lang) => addAllFromLang(lang));
                    }}
                    className={`px-2 py-0.5 rounded text-[7px] font-black uppercase border transition-all hover:scale-105 ${
                      darkMode ? "bg-cyan-600/10 border-cyan-500/30 text-cyan-400 hover:bg-cyan-600/20" : "bg-cyan-50 border-cyan-300 text-cyan-600 hover:bg-cyan-100"
                    }`}>
                    {t("templateEditor.all")}
                  </button>
                )}
              </div>
            </div>
            <div className="flex flex-wrap gap-1 max-h-[140px] overflow-y-auto">
              {selected.size === 0 ? (
                <span className={`text-[9px] ${darkMode ? "text-slate-600" : "text-slate-400"}`}>
                  {t("templateEditor.emptyPalette")}
                </span>
              ) : (
                (() => {
                  const paletteChars = new Set<string>();
                  selected.forEach((lang) => {
                    (langChars[lang] || []).forEach((c) => paletteChars.add(c));
                    (numSigns[lang] || []).forEach((c) => paletteChars.add(c));
                  });
                  return [...paletteChars].map((c, i) => {
                    const alreadyAdded = editorChars.includes(c) || (editingTemplate ? false : editorChars.includes(c));
                    const atLimit = allSelectedChars().length >= cellLimit && !alreadyAdded;
                    return (
                    <button key={i}
                      onClick={() => {
                        if (allSelectedChars().length >= cellLimit && !editorChars.includes(c)) {
                          log(`⚠ ${t("templateEditor.charNotInserted", { char: c, count: formatLocalizedInteger(cellLimit, language) })}`);
                          return;
                        }
                        if (editingTemplate) {
                          if (!editorChars.includes(c)) setEditorChars((p) => [...p, c]);
                        } else {
                          setEditorChars((p) => p.includes(c) ? p : [...p, c]);
                        }
                      }}
                      className={`w-8 h-8 rounded flex items-center justify-center text-[13px] font-mono font-bold border transition-all ${
                        atLimit
                          ? "opacity-30 cursor-not-allowed border-red-800"
                          : alreadyAdded
                            ? darkMode ? "bg-cyan-900/30 border-cyan-700 text-cyan-400" : "bg-cyan-50 border-cyan-300 text-cyan-600"
                            : darkMode ? "bg-slate-900/60 border-slate-800 text-slate-400 hover:scale-110 hover:border-cyan-500 hover:text-cyan-400" : "bg-white border-slate-300 text-slate-600 hover:scale-110 hover:text-cyan-600"
                      }`}
                      title={atLimit ? t("templateEditor.charLimitReached", { count: formatLocalizedInteger(cellLimit, language) }) : alreadyAdded ? t("templateEditor.alreadyAdded") : t("templateEditor.addChar", { char: c })}>
                      {c}
                    </button>
                    );
                  });
                })()
              )}
            </div>
          </div>

          {/* CAJA: Caracteres para la plantilla (acumulados) */}
          <div className={`flex-1 min-h-[120px] p-3 rounded-xl border ${
            darkMode ? "bg-slate-950/80 border-amber-900/20" : "bg-amber-50/30 border-amber-200"
          }`}>
            <div className="flex items-center justify-between mb-2">
              <h4 className={`text-[9px] font-black uppercase tracking-widest ${darkMode ? "text-amber-400" : "text-amber-600"}`}>
                {t("templateEditor.templateChars", { count: formatLocalizedInteger(selectedChars.length, language) })}
              </h4>
              {selectedChars.length > 0 && (
                <button
                  onClick={() => {
                    if (editingTemplate) setEditorChars([]);
                    else { setEditorChars([]); setSelected(new Set()); }
                  }}
                  className={`px-2 py-0.5 rounded text-[7px] font-bold border transition-all hover:scale-105 ${
                    darkMode ? "bg-red-950/20 border-red-900/40 text-red-400 hover:bg-red-900/30" : "bg-red-50 border-red-200 text-red-500 hover:bg-red-100"
                  }`}
                >
                  {t("templateEditor.clearAll")}
                </button>
              )}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {selectedChars.length === 0 ? (
                <span className={`text-[9px] ${darkMode ? "text-slate-600" : "text-slate-400"}`}>
                  {t("templateEditor.emptyTemplateChars")}
                </span>
              ) : (
                selectedChars.map((c, i) => (
                  <button key={i}
                    onClick={() => removeChar(c)}
                    className={`w-8 h-8 rounded flex items-center justify-center text-[13px] font-mono font-bold border transition-all hover:scale-110 hover:border-red-500 ${
                      darkMode ? "bg-slate-900 border-amber-900/30 text-slate-200 hover:text-red-400" : "bg-white border-amber-200 text-slate-700 hover:text-red-500"
                    }`}>
                    {c}
                  </button>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Panel derecho: Plantillas existentes */}
        <div className={`w-[260px] border-l p-4 overflow-y-auto ${palette.border}`}>
          <h3 className={`text-[10px] font-black uppercase tracking-widest mb-3 ${darkMode ? "text-slate-500" : "text-slate-400"}`}>
            {t("templateEditor.templates", { count: formatLocalizedInteger(Object.keys(templates).length, language) })}
          </h3>
          {Object.entries(templates).map(([key, tmpl]) => {
            const isDefault = false;
            const isEditing = editingTemplate === key;
            return (
            <div key={key}
              onClick={() => { if (!isEditing) handleEdit(key); }}
              className={`mb-2 p-2 rounded-lg border text-[9px] transition-all ${
                isEditing
                  ? darkMode ? "border-cyan-500/50 bg-cyan-500/5" : "border-cyan-300 bg-cyan-50"
                  : darkMode ? `${palette.border} ${palette.bg} hover:border-cyan-800 hover:bg-slate-900/80 cursor-pointer` : `${palette.border} ${palette.bg} hover:border-cyan-200 hover:bg-cyan-50/30 cursor-pointer`
              }`}>
              <div className="flex items-center justify-between">
                <div className={`font-bold ${isEditing ? (darkMode ? "text-cyan-400" : "text-cyan-600") : ""}`}>{key}</div>
                <div className="flex gap-1">
                  {!isEditing && (
                    <button
                      onClick={(e) => { e.stopPropagation(); handleEdit(key); }}
                      className={`px-1.5 py-0.5 rounded text-[7px] font-bold border transition-all hover:scale-105 ${
                        darkMode ? "bg-cyan-950/20 border-cyan-900/40 text-cyan-400 hover:bg-cyan-900/30" : "bg-cyan-50 border-cyan-200 text-cyan-600 hover:bg-cyan-100"
                      }`}
                    >
                      {t("common.edit")}
                    </button>
                  )}
                  {!isDefault && !isEditing && (
                    <button
                      onClick={(e) => { e.stopPropagation(); handleDelete(key); }}
                      className={`px-1.5 py-0.5 rounded text-[7px] font-bold border transition-all hover:scale-105 ${
                        darkMode ? "bg-red-950/20 border-red-900/40 text-red-400 hover:bg-red-900/30" : "bg-red-50 border-red-200 text-red-600 hover:bg-red-100"
                      }`}
                    >
                      {t("common.delete")}
                    </button>
                  )}
                  {isEditing && (
                    <span className="text-[7px] font-bold text-cyan-400 uppercase px-1 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
                      {t("common.editing")}
                    </span>
                  )}
                </div>
              </div>
              <div className={darkMode ? "text-slate-500" : "text-slate-400"}>
                {t("templateEditor.templateItemMeta", {
                  rows: formatLocalizedInteger(tmpl.rows, language),
                  cols: formatLocalizedInteger(tmpl.cols, language),
                  count: formatLocalizedInteger(tmpl.chars.length, language),
                })}
              </div>
            </div>
            );
          })}
        </div>
      </div>

      <div className={`h-[60px] border-t p-2 overflow-y-auto ${palette.border}`}>
        {consoleLog.map((l, i) => (
          <div key={i} className={`text-[9px] font-mono ${darkMode ? "text-slate-500" : "text-slate-400"}`}>{l}</div>
        ))}
      </div>
    </div>
  );
}
