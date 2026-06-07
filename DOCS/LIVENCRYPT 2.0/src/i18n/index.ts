import es from "./locales/es.json";
import en from "./locales/en.json";
import zh from "./locales/zh.json";
import { de, fr, hi, id, ja, ko, pt, ru } from "./locales/extended";

export type Language = "es" | "en" | "zh" | "ru" | "pt" | "de" | "fr" | "hi" | "ja" | "ko" | "id";
export type TranslationParams = Record<string, string | number>;

const catalogs = {
  es,
  en,
  zh,
  ru,
  pt,
  de,
  fr,
  hi,
  ja,
  ko,
  id,
} as const;

export const SUPPORTED_LANGUAGES: Language[] = ["es", "en", "zh", "ru", "pt", "de", "fr", "hi", "ja", "ko", "id"];
export const FALLBACK_LANGUAGE: Language = "es";

export function normalizeLanguage(value: unknown): Language {
  return SUPPORTED_LANGUAGES.includes(value as Language)
    ? (value as Language)
    : FALLBACK_LANGUAGE;
}

function resolvePath(source: unknown, path: string): string | null {
  let current: unknown = source;
  for (const part of path.split(".")) {
    if (!current || typeof current !== "object" || !(part in current)) {
      return null;
    }
    current = (current as Record<string, unknown>)[part];
  }
  return typeof current === "string" ? current : null;
}

export function translate(language: Language, path: string, params: TranslationParams = {}): string {
  const template =
    resolvePath(catalogs[language], path) ??
    resolvePath(catalogs[FALLBACK_LANGUAGE], path) ??
    path;

  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) =>
    params[key] === undefined ? `{{${key}}}` : String(params[key]),
  );
}
