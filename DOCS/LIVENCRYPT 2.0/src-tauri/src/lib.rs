// SPDX-License-Identifier: GPL-3.0-or-later
#![deny(unsafe_code)]

pub mod crypto;
pub mod security;
pub mod templates;

use crate::crypto::file_cipher::{FileCipher, FileInfo};
use crate::crypto::positional::{
    normalize_control_symbols, normalize_password_direction, CipherResult, PositionalCipher,
    DEFAULT_CONTROL_SYMBOLS, PASSWORD_DIRECTION_BEFORE,
};
use crate::templates::{
    delete_template, get_language_characters, get_language_numbers_signs, get_template_presets,
    get_templates_dir, initialize_defaults, load_templates, save_template,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tauri::Manager;

pub(crate) fn livencrypt_base_dir() -> PathBuf {
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(data_home).join("livencrypt");
    }

    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("livencrypt");
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

const TEXT_PASSWORD_ENABLED_KEY: &str = "text_password.enabled";
const TEXT_PASSWORD_LENGTH_KEY: &str = "text_password.length";
const TEXT_PASSWORD_DIRECTION_KEY: &str = "text_password.direction";
const TEXT_PASSWORD_CONTROL_SYMBOLS_KEY: &str = "text_password.control_symbols";
const I18N_LANGUAGE_KEY: &str = "i18n.language";
const I18N_FALLBACK_LANGUAGE_KEY: &str = "i18n.fallback_language";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TextPasswordSettings {
    enabled: bool,
    password_length: usize,
    password_direction: String,
    control_symbols: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LanguageSettings {
    language: String,
    fallback_language: String,
}

impl Default for LanguageSettings {
    fn default() -> Self {
        Self {
            language: "es".to_string(),
            fallback_language: "es".to_string(),
        }
    }
}

impl Default for TextPasswordSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            password_length: 8,
            password_direction: PASSWORD_DIRECTION_BEFORE.to_string(),
            control_symbols: DEFAULT_CONTROL_SYMBOLS.to_string(),
        }
    }
}

fn text_password_settings_path() -> PathBuf {
    livencrypt_base_dir()
        .join(".livencrypt")
        .join("settings")
        .join("text_password.msgpack")
}

fn language_settings_path() -> PathBuf {
    livencrypt_base_dir()
        .join(".livencrypt")
        .join("settings")
        .join("i18n.msgpack")
}

fn normalize_text_password_settings(settings: TextPasswordSettings) -> TextPasswordSettings {
    TextPasswordSettings {
        enabled: settings.enabled,
        password_length: settings.password_length.clamp(2, 25),
        password_direction: normalize_password_direction(&settings.password_direction),
        control_symbols: normalize_control_symbols(&settings.control_symbols),
    }
}

fn normalize_language(value: &str) -> String {
    match value {
        "en" | "zh" | "ru" | "pt" | "de" | "fr" | "hi" | "ja" | "ko" | "id" => value.to_string(),
        _ => "es".to_string(),
    }
}

fn normalize_language_settings(settings: LanguageSettings) -> LanguageSettings {
    LanguageSettings {
        language: normalize_language(&settings.language),
        fallback_language: normalize_language(&settings.fallback_language),
    }
}

fn settings_from_map(settings: &HashMap<String, String>) -> TextPasswordSettings {
    let defaults = TextPasswordSettings::default();
    normalize_text_password_settings(TextPasswordSettings {
        enabled: settings
            .get(TEXT_PASSWORD_ENABLED_KEY)
            .map(|value| value == "1")
            .unwrap_or(defaults.enabled),
        password_length: settings
            .get(TEXT_PASSWORD_LENGTH_KEY)
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(defaults.password_length),
        password_direction: settings
            .get(TEXT_PASSWORD_DIRECTION_KEY)
            .cloned()
            .unwrap_or(defaults.password_direction),
        control_symbols: settings
            .get(TEXT_PASSWORD_CONTROL_SYMBOLS_KEY)
            .cloned()
            .unwrap_or(defaults.control_symbols),
    })
}

fn language_settings_from_map(settings: &HashMap<String, String>) -> LanguageSettings {
    let defaults = LanguageSettings::default();
    normalize_language_settings(LanguageSettings {
        language: settings
            .get(I18N_LANGUAGE_KEY)
            .cloned()
            .unwrap_or(defaults.language),
        fallback_language: settings
            .get(I18N_FALLBACK_LANGUAGE_KEY)
            .cloned()
            .unwrap_or(defaults.fallback_language),
    })
}

fn settings_to_map(settings: &TextPasswordSettings) -> HashMap<String, String> {
    HashMap::from([
        (
            TEXT_PASSWORD_ENABLED_KEY.to_string(),
            if settings.enabled { "1" } else { "0" }.to_string(),
        ),
        (
            TEXT_PASSWORD_LENGTH_KEY.to_string(),
            settings.password_length.to_string(),
        ),
        (
            TEXT_PASSWORD_DIRECTION_KEY.to_string(),
            settings.password_direction.clone(),
        ),
        (
            TEXT_PASSWORD_CONTROL_SYMBOLS_KEY.to_string(),
            settings.control_symbols.clone(),
        ),
    ])
}

fn language_settings_to_map(settings: &LanguageSettings) -> HashMap<String, String> {
    HashMap::from([
        (I18N_LANGUAGE_KEY.to_string(), settings.language.clone()),
        (
            I18N_FALLBACK_LANGUAGE_KEY.to_string(),
            settings.fallback_language.clone(),
        ),
    ])
}

fn read_local_text_password_settings() -> Result<TextPasswordSettings, String> {
    let path = text_password_settings_path();
    if !path.exists() {
        return Ok(TextPasswordSettings::default());
    }

    let bytes = std::fs::read(&path)
        .map_err(|error| format!("No se pudo leer configuracion: {}", error))?;
    let settings = rmp_serde::from_slice::<TextPasswordSettings>(&bytes)
        .map_err(|error| format!("Configuracion de contrasena invalida: {}", error))?;
    Ok(normalize_text_password_settings(settings))
}

fn read_local_language_settings() -> Result<LanguageSettings, String> {
    let path = language_settings_path();
    if !path.exists() {
        return Ok(LanguageSettings::default());
    }

    let bytes = std::fs::read(&path)
        .map_err(|error| format!("No se pudo leer configuracion i18n: {}", error))?;
    let settings = rmp_serde::from_slice::<LanguageSettings>(&bytes)
        .map_err(|error| format!("Configuracion i18n invalida: {}", error))?;
    Ok(normalize_language_settings(settings))
}

fn write_local_text_password_settings(settings: &TextPasswordSettings) -> Result<(), String> {
    let path = text_password_settings_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("No se pudo crear directorio de configuracion: {}", error))?;
    }

    let bytes = rmp_serde::to_vec(settings)
        .map_err(|error| format!("No se pudo serializar configuracion: {}", error))?;
    std::fs::write(&path, bytes)
        .map_err(|error| format!("No se pudo guardar configuracion: {}", error))
}

fn write_local_language_settings(settings: &LanguageSettings) -> Result<(), String> {
    let path = language_settings_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("No se pudo crear directorio de configuracion: {}", error))?;
    }

    let bytes = rmp_serde::to_vec(settings)
        .map_err(|error| format!("No se pudo serializar configuracion i18n: {}", error))?;
    std::fs::write(&path, bytes)
        .map_err(|error| format!("No se pudo guardar configuracion i18n: {}", error))
}

#[tauri::command]
fn get_text_password_settings() -> Result<TextPasswordSettings, String> {
    if let Some(settings) = crate::security::vault::read_unlocked_settings()? {
        return Ok(settings_from_map(&settings));
    }

    read_local_text_password_settings()
}

#[tauri::command]
fn save_text_password_settings(
    settings: TextPasswordSettings,
) -> Result<TextPasswordSettings, String> {
    let settings = normalize_text_password_settings(settings);
    let stored_in_vault =
        crate::security::vault::update_unlocked_settings(settings_to_map(&settings))?;
    if !stored_in_vault {
        write_local_text_password_settings(&settings)?;
    }
    Ok(settings)
}

#[tauri::command]
fn get_language_settings() -> Result<LanguageSettings, String> {
    if let Ok(Some(settings)) = crate::security::vault::read_unlocked_settings() {
        return Ok(language_settings_from_map(&settings));
    }

    read_local_language_settings()
}

#[tauri::command]
fn save_language_settings(settings: LanguageSettings) -> Result<LanguageSettings, String> {
    let settings = normalize_language_settings(settings);
    write_local_language_settings(&settings)?;

    if let Ok(Some(_)) = crate::security::vault::read_unlocked_settings() {
        crate::security::vault::update_unlocked_settings(language_settings_to_map(&settings))?;
    }

    Ok(settings)
}

#[tauri::command]
fn list_templates(
    app: tauri::AppHandle,
) -> Result<std::collections::HashMap<String, crate::templates::TemplateData>, String> {
    crate::templates::load_templates(app)
}

#[tauri::command]
async fn cipher_text(
    text: String,
    template_name: String,
    caja1: i64,
    caja2: i64,
    caja3: i64,
    caja4: i64,
    caja5: i64,
    password_length: usize,
    password_direction: String,
    control_symbols: String,
    app: tauri::AppHandle,
) -> Result<CipherResult, String> {
    let templates = crate::templates::load_templates(app)?;
    let template = templates
        .get(&template_name)
        .ok_or_else(|| format!("Plantilla no encontrada: {}", template_name))?;
    let cipher = PositionalCipher::new(template.clone());
    Ok(cipher.cifrar_with_password_config(
        &text,
        caja1,
        caja2,
        caja3,
        caja4,
        caja5,
        password_length,
        &password_direction,
        &control_symbols,
    ))
}

#[tauri::command]
async fn decipher_text(
    text: String,
    template_name: String,
    caja1: i64,
    caja2: i64,
    caja3: i64,
    caja4: i64,
    caja5: i64,
    password_length: usize,
    password_direction: String,
    control_symbols: String,
    app: tauri::AppHandle,
) -> Result<CipherResult, String> {
    let templates = crate::templates::load_templates(app)?;
    let template = templates
        .get(&template_name)
        .ok_or_else(|| format!("Plantilla no encontrada: {}", template_name))?;
    let cipher = PositionalCipher::new(template.clone());
    Ok(cipher.descifrar_with_password_config(
        &text,
        caja1,
        caja2,
        caja3,
        caja4,
        caja5,
        password_length,
        &password_direction,
        &control_symbols,
    ))
}

#[tauri::command]
async fn load_file_info(path: String) -> Result<FileInfo, String> {
    FileCipher::load_file_info(Path::new(&path))
}

#[tauri::command]
async fn cipher_file(
    input_path: String,
    output_path: String,
    referencia: String,
    template_name: String,
    caja1: i64,
    caja2: i64,
    caja3: i64,
    caja4: i64,
    caja5: i64,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let template = resolve_file_template(&app, &template_name)?;
    FileCipher::encrypt_file(
        Path::new(&input_path),
        Path::new(&output_path),
        &referencia,
        &template,
        caja1,
        caja2,
        caja3,
        caja4,
        caja5,
        &[0u8; 32],
    )?;
    Ok(output_path)
}

#[tauri::command]
async fn decipher_file(
    input_path: String,
    output_path: String,
    referencia: String,
    is_txt_output: bool,
    template_name: String,
    caja1: i64,
    caja2: i64,
    caja3: i64,
    caja4: i64,
    caja5: i64,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let template = resolve_file_template(&app, &template_name)?;
    FileCipher::decrypt_file(
        Path::new(&input_path),
        Path::new(&output_path),
        &referencia,
        is_txt_output,
        &template,
        caja1,
        caja2,
        caja3,
        caja4,
        caja5,
        &[0u8; 32],
    )?;
    Ok(output_path)
}

fn resolve_file_template(
    app: &tauri::AppHandle,
    name: &str,
) -> Result<crate::templates::TemplateData, String> {
    if name == "filelivencrypt" || name == "Livencrypt" {
        return Ok(crate::templates::filelivencrypt_template());
    }

    let templates = crate::templates::load_templates(app.clone())?;
    templates
        .get(name)
        .cloned()
        .ok_or_else(|| format!("Plantilla no encontrada: {}", name))
}

#[tauri::command]
async fn save_cipher_result(temp_path: String, save_path: String) -> Result<(), String> {
    FileCipher::save_result(Path::new(&temp_path), Path::new(&save_path))
}

#[tauri::command]
fn open_folder(path: String) -> Result<(), String> {
    let path = Path::new(&path);
    let folder = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    };

    opener::open(folder).map_err(|error| format!("No se pudo abrir la carpeta: {}", error))
}

#[derive(Clone, Copy)]
struct ToolWindowConfig {
    label: &'static str,
    route: &'static str,
    title: &'static str,
    width: f64,
    height: f64,
}

fn tool_window_config(label: &str) -> Result<ToolWindowConfig, String> {
    match label {
        "text-cipher" => Ok(ToolWindowConfig {
            label: "text-cipher",
            route: "/#/text-cipher",
            title: "Livencrypt 2.0 - Transmutador de Texto",
            width: 980.0,
            height: 760.0,
        }),
        "file-cipher" => Ok(ToolWindowConfig {
            label: "file-cipher",
            route: "/#/file-cipher",
            title: "Livencrypt 2.0 - Transmutador de Archivo",
            width: 1040.0,
            height: 780.0,
        }),
        "template-editor" => Ok(ToolWindowConfig {
            label: "template-editor",
            route: "/#/template-editor",
            title: "Livencrypt 2.0 - Plantillas",
            width: 1180.0,
            height: 820.0,
        }),
        _ => Err(format!("Herramienta no permitida: {}", label)),
    }
}

#[tauri::command]
async fn open_tool_window(app: tauri::AppHandle, label: String) -> Result<(), String> {
    use tauri::WebviewWindowBuilder;

    let config = tool_window_config(&label)?;
    if let Some(window) = app.get_webview_window(config.label) {
        window.maximize().map_err(|error| error.to_string())?;
        window.set_focus().map_err(|error| error.to_string())?;
        return Ok(());
    }

    #[cfg(debug_assertions)]
    let webview_url = {
        let full_url = format!("http://localhost:1420{}", config.route);
        tauri::WebviewUrl::External(
            full_url
                .parse()
                .map_err(|error: url::ParseError| error.to_string())?,
        )
    };

    #[cfg(not(debug_assertions))]
    let webview_url = tauri::WebviewUrl::App(
        config
            .route
            .parse()
            .map_err(|_| "URL invalida".to_string())?,
    );

    WebviewWindowBuilder::new(&app, config.label, webview_url)
        .title(config.title)
        .inner_size(config.width, config.height)
        .maximized(true)
        .content_protected(true)
        .resizable(true)
        .min_inner_size(600.0, 400.0)
        .build()
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[tauri::command]
fn toggle_network(disable: bool) -> Result<bool, String> {
    crate::security::toggle_network_safely(disable)
}

#[tauri::command]
fn panic_wipe_and_exit() {
    let _ = crate::security::boot_shield_hardened_lock();
    std::process::exit(0);
}

#[tauri::command]
fn destructive_wipe_and_exit(confirmation: String) -> Result<(), String> {
    crate::security::boot_shield_destructive_panic(confirmation)?;
    std::process::exit(0);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let hardening_status = crate::security::initialize_process_hardening();
    for warning in &hardening_status.warnings {
        eprintln!("[SECURITY] {}", warning);
    }
    crate::crypto::file_cipher::configure_chunk_tasks();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if let Err(error) = initialize_defaults(app.handle().clone()) {
                eprintln!("[INIT] Error inicializando plantillas: {}", error);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_templates_dir,
            get_text_password_settings,
            save_text_password_settings,
            get_language_settings,
            save_language_settings,
            load_templates,
            list_templates,
            save_template,
            initialize_defaults,
            cipher_text,
            decipher_text,
            load_file_info,
            cipher_file,
            decipher_file,
            save_cipher_result,
            get_language_characters,
            get_language_numbers_signs,
            get_template_presets,
            open_tool_window,
            delete_template,
            open_folder,
            toggle_network,
            crate::security::vault::boot_shield_status,
            crate::security::vault::boot_shield_enable,
            crate::security::vault::boot_shield_unlock,
            crate::security::vault::boot_shield_lock,
            crate::security::vault::boot_shield_disable,
            crate::security::vault::boot_shield_factory_reset,
            crate::security::network_profile::get_network_profile,
            crate::security::network_profile::set_network_profile,
            crate::security::process_hardening::process_hardening_status,
            panic_wipe_and_exit,
            destructive_wipe_and_exit,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_window_config_allows_only_allowed_tools() {
        assert!(tool_window_config("text-cipher").is_ok());
        assert!(tool_window_config("file-cipher").is_ok());
        assert!(tool_window_config("template-editor").is_ok());
        assert!(tool_window_config("dashboard").is_err());
        assert!(tool_window_config("node").is_err());
    }
}
