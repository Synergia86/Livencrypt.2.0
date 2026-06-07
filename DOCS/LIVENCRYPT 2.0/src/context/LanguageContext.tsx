import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import invoke from "../invoke";
import { FALLBACK_LANGUAGE, type Language, normalizeLanguage, translate, type TranslationParams } from "../i18n";

const LANGUAGE_STORAGE_KEY = "livencrypt_language";
const LANGUAGE_CHANNEL_NAME = "livencrypt_language_sync";
const LANGUAGE_EVENT_NAME = "livencrypt-language-sync";

interface LanguageContextValue {
  language: Language;
  setLanguage: (language: Language) => void;
  t: (path: string, params?: TranslationParams) => string;
}

const LanguageContext = createContext<LanguageContextValue | null>(null);

const readStoredLanguage = () => {
  try {
    return normalizeLanguage(window.localStorage.getItem(LANGUAGE_STORAGE_KEY));
  } catch {
    return FALLBACK_LANGUAGE;
  }
};

const persistLanguageLocally = (language: Language) => {
  try {
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
    window.dispatchEvent(new CustomEvent(LANGUAGE_EVENT_NAME, { detail: language }));
  } catch {
    // El idioma tambien se guarda en Rust; localStorage solo sincroniza ventanas abiertas.
  }
};

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<Language>(() => readStoredLanguage());

  useEffect(() => {
    if (!invoke) return;
    invoke("get_language_settings")
      .then((settings: any) => {
        const normalized = normalizeLanguage(settings?.language);
        setLanguageState(normalized);
        persistLanguageLocally(normalized);
      })
      .catch(() => setLanguageState(FALLBACK_LANGUAGE));
  }, []);

  useEffect(() => {
    const applySyncedLanguage = (value: unknown) => {
      const normalized = normalizeLanguage(value);
      setLanguageState(normalized);
    };

    const onStorage = (event: StorageEvent) => {
      if (event.key === LANGUAGE_STORAGE_KEY) applySyncedLanguage(event.newValue);
    };

    const onCustomEvent = (event: Event) => {
      applySyncedLanguage((event as CustomEvent).detail);
    };

    const channel = "BroadcastChannel" in window
      ? new BroadcastChannel(LANGUAGE_CHANNEL_NAME)
      : null;

    channel?.addEventListener("message", (event) => applySyncedLanguage(event.data));
    window.addEventListener("storage", onStorage);
    window.addEventListener(LANGUAGE_EVENT_NAME, onCustomEvent);

    return () => {
      channel?.close();
      window.removeEventListener("storage", onStorage);
      window.removeEventListener(LANGUAGE_EVENT_NAME, onCustomEvent);
    };
  }, []);

  const setLanguage = (nextLanguage: Language) => {
    const normalized = normalizeLanguage(nextLanguage);
    setLanguageState(normalized);
    persistLanguageLocally(normalized);
    if ("BroadcastChannel" in window) {
      const channel = new BroadcastChannel(LANGUAGE_CHANNEL_NAME);
      channel.postMessage(normalized);
      channel.close();
    }
    if (!invoke) return;
    void invoke("save_language_settings", {
      settings: {
        language: normalized,
        fallbackLanguage: FALLBACK_LANGUAGE,
      },
    });
  };

  const value = useMemo<LanguageContextValue>(() => ({
    language,
    setLanguage,
    t: (path, params) => translate(language, path, params),
  }), [language]);

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

export function useTranslation() {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error("useTranslation must be used inside LanguageProvider");
  }
  return context;
}
