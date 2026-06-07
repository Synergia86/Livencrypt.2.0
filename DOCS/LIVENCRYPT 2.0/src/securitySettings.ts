export const DESTRUCTIVE_PANIC_STORAGE_KEY = "livencrypt_destructive_panic_enabled";
export const INACTIVITY_CLOSE_ENABLED_KEY = "livencrypt_inactivity_close_enabled";
export const INACTIVITY_CLOSE_SECONDS_KEY = "livencrypt_inactivity_close_seconds";
export const FILE_AUTO_CLOSE_STORAGE_KEY = "livencrypt_file_auto_close_after_action";
export const SECURITY_SETTINGS_CHANGED_EVENT = "livencrypt:security-settings-changed";

export function readBooleanSetting(key: string, fallback = false) {
  try {
    return window.localStorage.getItem(key) === "1";
  } catch {
    return fallback;
  }
}

export function writeBooleanSetting(key: string, value: boolean) {
  try {
    window.localStorage.setItem(key, value ? "1" : "0");
    window.dispatchEvent(new CustomEvent(SECURITY_SETTINGS_CHANGED_EVENT));
  } catch {
    // Ajuste no secreto; si localStorage no esta disponible, queda limitado a memoria.
  }
}

export function readNumberSetting(key: string, fallback: number, min: number, max: number) {
  try {
    const value = Number(window.localStorage.getItem(key));
    if (Number.isFinite(value)) return Math.max(min, Math.min(max, value));
  } catch {
    // Mantener fallback.
  }
  return fallback;
}

export function writeNumberSetting(key: string, value: number, min: number, max: number) {
  const normalized = Math.max(min, Math.min(max, Math.floor(value)));
  try {
    window.localStorage.setItem(key, String(normalized));
    window.dispatchEvent(new CustomEvent(SECURITY_SETTINGS_CHANGED_EVENT));
  } catch {
    // Ajuste no secreto; si localStorage no esta disponible, queda limitado a memoria.
  }
  return normalized;
}
