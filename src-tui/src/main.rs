// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Punto de entrada principal de la TUI y bucle de renderizado interactivo */

use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use livencrypt_lib::crypto::blockchain::breaker::GatewaySecurityState;
use livencrypt_lib::crypto::blockchain::firewall::{FirewallRules, LiveFirewall};
use livencrypt_lib::crypto::blockchain::multi_curve::UniversalKeymaster;
use livencrypt_lib::crypto::blockchain::nodes::{self, NodeRegistry};
use livencrypt_lib::crypto::blockchain::supervisor::GatewaySupervisor;
use livencrypt_lib::crypto::blockchain::worker::{
    Web3BackgroundWorker, Web3WorkerCmd, Web3WorkerEvent,
};
use livencrypt_lib::crypto::positional::{DEFAULT_CONTROL_SYMBOLS, PASSWORD_DIRECTION_BEFORE};
use livencrypt_lib::security;
use livencrypt_lib::templates::TemplateData;
use rand::seq::SliceRandom;
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use rust_decimal::Decimal;
use std::error::Error;
use std::fs;
use std::io;
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const INVALID_ACCESS: &str = "CREDENCIALES INVALIDAS O VAULT MANIPULADO";
const DEFAULT_TEMPLATE: &str = "Livencrypt";
const DEFAULT_FILE_REFERENCE: &str = "LIVENCRYPT-FILE";
const DEFAULT_FILE_SECRET: &str = "LIVENCRYPT-FILE-SECRET";
const TEMPLATE_ROWS: u32 = 5;
const TEMPLATE_COLS: u32 = 23;
const TEMPLATE_GRID_CELL_WIDTH: usize = 4;
const TEMPLATE_PREVIEW_CELL_WIDTH: usize = 6;
const TEMPLATE_LIST_ROWS: usize = 10;
const MIN_TERMINAL_WIDTH: u16 = 100;
const MIN_TERMINAL_HEIGHT: u16 = 30;

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args
        .iter()
        .any(|arg| arg == "--network-self-test-container-only")
    {
        return run_container_network_self_test().map_err(Into::into);
    }

    if args.iter().any(|arg| arg == "--self-test-safe") {
        return run_safe_self_test().map_err(Into::into);
    }

    if args.iter().any(|arg| arg == "--hardening-check") {
        let hardening_status = security::initialize_process_hardening();
        for warning in &hardening_status.warnings {
            eprintln!("[SECURITY] {}", warning);
        }
        livencrypt_lib::crypto::file_cipher::configure_chunk_tasks();
        print_hardening_check();
        return Ok(());
    }

    livencrypt_lib::initialize_core();
    run_terminal_ui()
}

fn run_container_network_self_test() -> Result<(), String> {
    ensure_container_network_test_guard()?;

    let temp_root = std::env::temp_dir().join(format!(
        "livencrypt-container-network-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&temp_root)
        .map_err(|error| format!("No se pudo crear directorio temporal: {}", error))?;
    std::env::set_var("XDG_DATA_HOME", &temp_root);

    println!("LIVENCRYPT NETWORK SELF-TEST CONTAINER-ONLY");
    println!("Datos temporales: {}", temp_root.display());
    println!("Guard: contenedor Docker detectado y LIVENCRYPT_CONTAINER_NETWORK_TEST=1.");
    println!("Prohibido: --network host, --privileged, montajes del host.");

    livencrypt_lib::initialize_core_without_process_hardening()?;

    security::set_network_profile("mock".to_string(), None)?;
    let mock_state = security::toggle_network_safely(true)?;
    if mock_state {
        return Err("Perfil mock devolvio estado inesperado.".into());
    }
    println!("OK red mock: no modifica rutas.");

    security::set_network_profile(
        "drop-default-route".to_string(),
        Some("ENTENDIDO".to_string()),
    )?;
    let disabled = security::toggle_network_safely(true)?;
    if disabled {
        return Err("drop-default-route no informo corte de conectividad.".into());
    }
    println!("OK red drop-default-route: rutas por defecto eliminadas dentro del contenedor.");

    let restored = security::toggle_network_safely(false)?;
    if !restored {
        return Err("drop-default-route no restauro conectividad.".into());
    }
    println!("OK red drop-default-route: rutas restauradas dentro del contenedor.");

    security::set_network_profile("nmcli-off".to_string(), Some("ENTENDIDO".to_string()))?;
    let nmcli_disabled = security::toggle_network_safely(true)?;
    if nmcli_disabled {
        return Err("nmcli-off no informo corte de conectividad.".into());
    }
    let nmcli_restored = security::toggle_network_safely(false)?;
    if !nmcli_restored {
        return Err("nmcli-off no informo restauracion de conectividad.".into());
    }
    println!("OK red nmcli-off: ejecutado contra shim aislado dentro del contenedor.");

    let _ = fs::remove_dir_all(&temp_root);
    println!("NETWORK SELF-TEST CONTAINER-ONLY OK");
    Ok(())
}

fn ensure_container_network_test_guard() -> Result<(), String> {
    if std::env::var("LIVENCRYPT_CONTAINER_NETWORK_TEST").as_deref() != Ok("1") {
        return Err(
            "Test de red bloqueado: falta LIVENCRYPT_CONTAINER_NETWORK_TEST=1.".to_string(),
        );
    }

    let docker_marker = Path::new("/.dockerenv").exists()
        || fs::read_to_string("/proc/1/cgroup")
            .map(|content| content.contains("docker") || content.contains("containerd"))
            .unwrap_or(false);

    if !docker_marker {
        return Err("Test de red bloqueado: no se detecta contenedor Docker.".into());
    }

    Ok(())
}

fn run_safe_self_test() -> Result<(), String> {
    let temp_root = std::env::temp_dir().join(format!(
        "livencrypt-safe-self-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&temp_root)
        .map_err(|error| format!("No se pudo crear directorio temporal: {}", error))?;
    std::env::set_var("XDG_DATA_HOME", &temp_root);

    println!("LIVENCRYPT SELF-TEST SEGURO");
    println!("Datos temporales: {}", temp_root.display());
    println!("Excluido: red, nmcli, ip route, AppArmor, mlockall, prctl, setrlimit, kernel/SO.");

    livencrypt_lib::initialize_core_without_process_hardening()?;
    safe_test_templates()?;
    safe_test_text_cipher()?;
    safe_test_file_cipher(&temp_root)?;
    safe_test_boot_shield()?;

    let _ =
        security::vault::boot_shield_destructive_panic("DESTRUIR VAULT Y PLANTILLAS".to_string());
    let _ = fs::remove_dir_all(&temp_root);

    println!("SELF-TEST OK");
    Ok(())
}

fn safe_test_templates() -> Result<(), String> {
    let templates = livencrypt_lib::load_templates()?;
    if !templates.contains_key(DEFAULT_TEMPLATE) {
        return Err("No se cargo la plantilla Livencrypt por defecto.".into());
    }

    let name = "SelfTestTemplate".to_string();
    let data = livencrypt_lib::templates::filelivencrypt_template();
    livencrypt_lib::save_template(name.clone(), data)?;
    let templates = livencrypt_lib::load_templates()?;
    if !templates.contains_key(&name) {
        return Err("No se pudo guardar/cargar plantilla de self-test.".into());
    }
    livencrypt_lib::delete_template(name)?;
    println!("OK plantillas: cargar/guardar/eliminar.");
    Ok(())
}

fn safe_test_text_cipher() -> Result<(), String> {
    let plain = "abc123 prueba livencrypt";
    let secret = "clave de texto segura 2026";
    let encrypted = livencrypt_lib::cipher_text_secure(plain, secret)?;
    let decrypted = livencrypt_lib::decipher_text_secure(&encrypted, secret)?;
    if decrypted != plain {
        return Err(format!(
            "Roundtrip texto fallo: esperado '{}', obtenido '{}'.",
            plain, decrypted
        ));
    }
    println!("OK texto: cifrar/descifrar.");
    Ok(())
}

fn safe_test_file_cipher(temp_root: &Path) -> Result<(), String> {
    let input = temp_root.join("archivo_selftest.txt");
    let encrypted = temp_root.join("archivo_selftest_cifrado.lvc");
    let decrypted = temp_root.join("archivo_selftest_descifrado.txt");
    let plain = b"abc123 archivo livencrypt self-test";
    fs::write(&input, plain).map_err(|error| error.to_string())?;

    let info = livencrypt_lib::load_file_info(&input)?;
    if info.size_bytes != plain.len() as u64 {
        return Err("load_file_info devolvio tamano incorrecto.".into());
    }

    let cajas = [1, 2, 3, 4, 5];
    livencrypt_lib::cipher_file_with_secret(
        &input,
        &encrypted,
        DEFAULT_FILE_REFERENCE,
        DEFAULT_TEMPLATE,
        cajas,
        DEFAULT_FILE_SECRET,
    )?;
    livencrypt_lib::decipher_file_with_secret(
        &encrypted,
        &decrypted,
        DEFAULT_FILE_REFERENCE,
        true,
        DEFAULT_TEMPLATE,
        cajas,
        DEFAULT_FILE_SECRET,
    )?;
    let recovered = fs::read(&decrypted).map_err(|error| error.to_string())?;
    if recovered != plain {
        return Err("Roundtrip archivo fallo: bytes recuperados no coinciden.".into());
    }
    println!("OK archivo: info/cifrar/descifrar.");
    Ok(())
}

fn safe_test_boot_shield() -> Result<(), String> {
    let cajas = [10, 20, 30, 40, 50];
    let frase = "frase self test livencrypt";
    security::boot_shield_enable(
        cajas,
        frase.to_string(),
        Some(DEFAULT_TEMPLATE.to_string()),
        None,
        None,
    )?;
    security::boot_shield_hardened_lock()?;
    security::boot_shield_unlock(cajas, frase.to_string(), None, None)?;

    let mut settings = std::collections::HashMap::new();
    settings.insert("self_test".to_string(), "ok".to_string());
    security::vault::update_unlocked_settings(settings)?;
    let settings = security::vault::read_unlocked_settings()?
        .ok_or_else(|| "Settings cifrados no disponibles tras desbloqueo.".to_string())?;
    if settings.get("self_test").map(String::as_str) != Some("ok") {
        return Err("Settings cifrados no persistieron en vault.".into());
    }

    println!("OK Boot Shield: crear/bloquear/desbloquear/settings.");
    Ok(())
}

fn print_hardening_check() {
    let status = security::process_hardening::process_hardening_status();
    println!(
        "CORE DUMPS: {}",
        if status.core_dumps_disabled {
            "OFF"
        } else {
            "ON"
        }
    );
    println!(
        "DUMPABLE: {}",
        if status.dumpable_disabled {
            "OFF"
        } else {
            "ON"
        }
    );
    println!(
        "MLOCKALL: {}",
        if status.mlockall_applied {
            "OK"
        } else {
            "FALLO"
        }
    );
    println!(
        "INTEGRIDAD: {}",
        match status.binary_integrity_ok {
            Some(true) => "OK",
            Some(false) => "FALLO",
            None => "SIN HASH ESPERADO",
        }
    );
    println!("SHA-256 binario: {}", status.binary_sha256);
    if status.warnings.is_empty() {
        println!("SIN AVISOS DE HARDENING.");
    } else {
        for warning in status.warnings {
            println!("AVISO: {}", warning);
        }
    }
}

fn run_terminal_ui() -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    )?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_app(&mut terminal);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    if let Err(error) = result {
        eprintln!("{}", error);
    }

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Unlock,
    Dashboard,
    TextCipher,
    FileCipher,
    TemplateEditor,
    Settings,
    SystemMonitor,
    AuditMonitor,
    FirmwareStaging,
    SandboxManager,
    RecoveryMode,
    InstallProfile,
    WalletGateway,
    NodesManager,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileMode {
    Encrypt,
    Decrypt,
}

impl FileMode {
    fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "cifrar",
            Self::Decrypt => "descifrar",
        }
    }

    fn forensic_label(self) -> &'static str {
        match self {
            Self::Encrypt => "CIFRADO",
            Self::Decrypt => "DESCIFRADO",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileBrowserTarget {
    Input,
    Output,
    TextExport,
}

struct FileBrowser {
    current_dir: PathBuf,
    all_items: Vec<PathBuf>,
    filtered_items: Vec<PathBuf>,
    selected_index: usize,
    vertical_offset: usize,
    horizontal_offset: usize,
    search_query: String,
    name_mode: bool,
    name_input: String,
}

impl FileBrowser {
    fn new() -> Self {
        let mut browser = Self {
            current_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            all_items: Vec::new(),
            filtered_items: Vec::new(),
            selected_index: 0,
            vertical_offset: 0,
            horizontal_offset: 0,
            search_query: String::new(),
            name_mode: false,
            name_input: String::new(),
        };
        browser.refresh();
        browser
    }

    fn refresh(&mut self) {
        self.all_items = fs::read_dir(&self.current_dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        self.apply_filter();
    }

    fn apply_filter(&mut self) {
        let query = self.search_query.to_lowercase();
        self.filtered_items = self
            .all_items
            .iter()
            .filter(|path| {
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase();
                name.contains(&query)
            })
            .cloned()
            .collect();
        self.filtered_items
            .sort_by(|a, b| b.is_dir().cmp(&a.is_dir()).then_with(|| a.cmp(b)));
        if self.selected_index >= self.filtered_items.len() {
            self.selected_index = self.filtered_items.len().saturating_sub(1);
        }
        self.vertical_offset = self.vertical_offset.min(self.selected_index / 3);
    }

    fn selected(&self) -> Option<PathBuf> {
        self.filtered_items.get(self.selected_index).cloned()
    }

    fn move_up(&mut self) {
        self.selected_index = self.selected_index.saturating_sub(3);
        self.ensure_selected_visible(1);
    }

    fn move_down(&mut self) {
        if self.selected_index + 3 < self.filtered_items.len() {
            self.selected_index += 3;
        } else if !self.filtered_items.is_empty() {
            self.selected_index = self.filtered_items.len() - 1;
        }
        self.ensure_selected_visible(1);
    }

    fn move_left(&mut self) {
        self.selected_index = self.selected_index.saturating_sub(1);
        self.ensure_selected_visible(1);
    }

    fn move_right(&mut self) {
        if self.selected_index + 1 < self.filtered_items.len() {
            self.selected_index += 1;
        }
        self.ensure_selected_visible(1);
    }

    fn scroll_name_left(&mut self) {
        self.horizontal_offset = self.horizontal_offset.saturating_sub(4);
    }

    fn scroll_name_right(&mut self) {
        self.horizontal_offset = self.horizontal_offset.saturating_add(4).min(240);
    }

    fn ensure_selected_visible(&mut self, visible_rows: usize) {
        let selected_row = self.selected_index / 3;
        if selected_row < self.vertical_offset {
            self.vertical_offset = selected_row;
        } else if selected_row >= self.vertical_offset.saturating_add(visible_rows) {
            self.vertical_offset = selected_row.saturating_sub(visible_rows.saturating_sub(1));
        }
    }

    fn navigate_out(&mut self) {
        if let Some(parent) = self.current_dir.parent() {
            self.current_dir = parent.to_path_buf();
            self.search_query.clear();
            self.selected_index = 0;
            self.vertical_offset = 0;
            self.refresh();
        }
    }

    fn enter_selected(&mut self) -> Option<PathBuf> {
        let selected = self.selected()?;
        if selected.is_dir() {
            self.current_dir = selected;
            self.search_query.clear();
            self.selected_index = 0;
            self.vertical_offset = 0;
            self.refresh();
            None
        } else {
            Some(selected)
        }
    }

    fn clear(&mut self) {
        self.search_query.zeroize();
        self.search_query.clear();
        self.name_input.zeroize();
        self.name_input.clear();
        self.name_mode = false;
        self.all_items.clear();
        self.filtered_items.clear();
    }
}

struct FileJobResult {
    mode: FileMode,
    output: PathBuf,
    duration_ms: u128,
    result: Result<Option<security::forensics::ForensicReport>, String>,
}

struct TuiState {
    screen: Screen,
    cajas: [String; 5],
    frase: String,
    focus: usize,
    status: String,
    operation_log: Vec<String>,
    templates_count: usize,
    templates: Vec<String>,
    integrity: security::vault::IntegrityStatus,
    teclado_shuffled: Vec<char>,
    cursor_teclado: usize,
    recovery_path: String,
    recovery_error: String,
    should_quit: bool,

    text_input: String,
    text_output: String,
    text_cajas: [String; 5],
    text_template: String,
    text_password_length: String,
    text_password_direction: String,
    text_control_symbols: String,
    text_output_file: String,
    show_matrix_config: bool,
    matrix_focus: usize,
    text_keyboard_chars: Vec<String>,
    text_keyboard_cursor: usize,
    show_text_password_prompt: bool,
    text_password_prompt_input: String,
    text_password_expected: String,
    text_password_pending_encrypt: bool,
    text_password_attempts: u8,
    text_internal_clipboard: String,
    nodes: NodeRegistry,
    nodes_chains: Vec<String>,
    nodes_selected: usize,
    nodes_editing: bool,
    nodes_edit_buffer: String,

    file_input_path: String,
    file_output_path: String,
    file_cajas: [String; 5],
    file_template: String,
    file_reference_phrase: String,
    file_key_phrase: String,
    file_mode: FileMode,
    file_close_after_operation: bool,
    show_file_browser: bool,
    file_browser_target: FileBrowserTarget,
    file_browser: FileBrowser,
    processing_progress: Arc<AtomicU64>,
    is_processing: bool,
    file_job_rx: Option<mpsc::Receiver<FileJobResult>>,
    last_forensic_report: Option<security::forensics::ForensicReport>,
    last_forensic_report_path: Option<PathBuf>,

    template_name: String,
    template_chars: Vec<String>,
    template_rows: String,
    template_cols: String,
    template_selected_index: usize,
    template_cell_index: usize,
    template_focus: usize,
    template_preview_cursor: usize,
    template_preview_click_ready: bool,
    language_names: Vec<String>,
    number_names: Vec<String>,
    language_index: usize,
    number_index: usize,
    language_click_ready: bool,
    number_click_ready: bool,

    settings_boot_cajas: [String; 5],
    settings_boot_frase: String,
    settings_boot_template: String,
    settings_network_profile: String,
    settings_network_confirmation: String,
    inactivity_enabled: bool,
    inactivity_timeout_seconds: u64,
    settings_focus: usize,

    web3_cmd_tx: Option<mpsc::Sender<Web3WorkerCmd>>,
    web3_event_rx: Option<mpsc::Receiver<Web3WorkerEvent>>,
    cached_gateway_state: GatewaySecurityState,
    cached_tx_count: u32,
    cached_volume_units: Decimal,
    allowed_dex_contracts: Vec<String>,
    allowed_cex_destinations: Vec<String>,
    system_notification: String,
    gateway_focused_field: usize,
    input_max_tx: String,
    input_max_volume: String,
    input_new_dex_id: String,
    input_new_cex_id: String,
    show_breaker_reset: bool,
    reset_cajas: [String; 5],
    reset_phrase: String,
    reset_focus_index: usize,
}

impl TuiState {
    fn new() -> Self {
        let vault_configured = security::vault_is_configured();
        let templates = template_names();
        let mut state = Self {
            screen: if vault_configured {
                Screen::Unlock
            } else {
                Screen::Dashboard
            },
            cajas: empty_boxes(),
            frase: String::new(),
            focus: 0,
            status: if vault_configured {
                "Boot Shield bloqueado. Introduzca 5 cajas + frase.".to_string()
            } else {
                "Boot Shield no configurado. Nucleo TUI cargado.".to_string()
            },
            operation_log: Vec::new(),
            templates_count: 0,
            templates,
            integrity: security::vault::current_integrity_status(),
            teclado_shuffled: shuffled_keyboard(),
            cursor_teclado: 0,
            recovery_path: String::new(),
            recovery_error: String::new(),
            should_quit: false,
            text_input: String::new(),
            text_output: String::new(),
            text_cajas: default_boxes(),
            text_template: DEFAULT_TEMPLATE.to_string(),
            text_password_length: "8".to_string(),
            text_password_direction: PASSWORD_DIRECTION_BEFORE.to_string(),
            text_control_symbols: DEFAULT_CONTROL_SYMBOLS.to_string(),
            text_output_file: String::new(),
            show_matrix_config: false,
            matrix_focus: 0,
            text_keyboard_chars: shuffled_template_keyboard(DEFAULT_TEMPLATE),
            text_keyboard_cursor: 0,
            show_text_password_prompt: false,
            text_password_prompt_input: String::new(),
            text_password_expected: String::new(),
            text_password_pending_encrypt: true,
            text_password_attempts: 0,
            text_internal_clipboard: String::new(),
            nodes: NodeRegistry::default(),
            nodes_chains: Vec::new(),
            nodes_selected: 0,
            nodes_editing: false,
            nodes_edit_buffer: String::new(),
            file_input_path: String::new(),
            file_output_path: String::new(),
            file_cajas: default_boxes(),
            file_template: DEFAULT_TEMPLATE.to_string(),
            file_reference_phrase: DEFAULT_FILE_REFERENCE.to_string(),
            file_key_phrase: String::new(),
            file_mode: FileMode::Encrypt,
            file_close_after_operation: false,
            show_file_browser: false,
            file_browser_target: FileBrowserTarget::Input,
            file_browser: FileBrowser::new(),
            processing_progress: Arc::new(AtomicU64::new(0)),
            is_processing: false,
            file_job_rx: None,
            last_forensic_report: None,
            last_forensic_report_path: None,
            template_name: DEFAULT_TEMPLATE.to_string(),
            template_chars: livencrypt_lib::resolve_template(DEFAULT_TEMPLATE)
                .map(|template| compact_template_chars(&template.chars))
                .unwrap_or_else(|_| default_template_chars()),
            template_rows: TEMPLATE_ROWS.to_string(),
            template_cols: TEMPLATE_COLS.to_string(),
            template_selected_index: 0,
            template_cell_index: 0,
            template_focus: 0,
            template_preview_cursor: 0,
            template_preview_click_ready: false,
            language_names: sorted_keys(livencrypt_lib::language_characters()),
            number_names: sorted_keys(livencrypt_lib::language_numbers_signs()),
            language_index: 0,
            number_index: 0,
            language_click_ready: false,
            number_click_ready: false,
            settings_boot_cajas: default_boxes(),
            settings_boot_frase: String::new(),
            settings_boot_template: DEFAULT_TEMPLATE.to_string(),
            settings_network_profile: security::get_network_profile()
                .unwrap_or_else(|_| "mock".to_string()),
            settings_network_confirmation: String::new(),
            inactivity_enabled: false,
            inactivity_timeout_seconds: 300,
            settings_focus: 0,
            web3_cmd_tx: None,
            web3_event_rx: None,
            cached_gateway_state: GatewaySecurityState::Frozen {
                reason: "Pasarela Web3 no inicializada".to_string(),
                timestamp: 0,
            },
            cached_tx_count: 0,
            cached_volume_units: Decimal::ZERO,
            allowed_dex_contracts: Vec::new(),
            allowed_cex_destinations: Vec::new(),
            system_notification: "Pasarela Web3 pendiente de desbloqueo Boot Shield.".to_string(),
            gateway_focused_field: 0,
            input_max_tx: "10".to_string(),
            input_max_volume: "5000".to_string(),
            input_new_dex_id: String::new(),
            input_new_cex_id: String::new(),
            show_breaker_reset: false,
            reset_cajas: empty_boxes(),
            reset_phrase: String::new(),
            reset_focus_index: 0,
        };
        state.refresh_templates_count();
        state.add_log("TUI inicializada.");
        state
    }

    fn clear_secret_fields(&mut self) {
        zeroize_boxes(&mut self.cajas);
        self.frase.zeroize();
        self.frase.clear();
        self.focus = 0;
    }

    fn clear_text_fields(&mut self) {
        self.text_input.zeroize();
        self.text_input.clear();
        self.text_output.zeroize();
        self.text_output.clear();
        self.text_output_file.zeroize();
        self.text_output_file.clear();
        self.text_password_prompt_input.zeroize();
        self.text_password_prompt_input.clear();
        self.text_password_expected.zeroize();
        self.text_password_expected.clear();
        self.text_internal_clipboard.zeroize();
        self.text_internal_clipboard.clear();
        self.show_text_password_prompt = false;
        self.text_password_attempts = 0;
        self.show_matrix_config = false;
    }

    fn refresh_text_keyboard(&mut self) {
        self.text_keyboard_chars = shuffled_template_keyboard(&self.text_template);
        if self.text_keyboard_cursor >= self.text_keyboard_chars.len() {
            self.text_keyboard_cursor = self.text_keyboard_chars.len().saturating_sub(1);
        }
    }

    fn clear_file_fields(&mut self) {
        self.file_input_path.zeroize();
        self.file_input_path.clear();
        self.file_output_path.zeroize();
        self.file_output_path.clear();
        self.file_reference_phrase.zeroize();
        self.file_reference_phrase = DEFAULT_FILE_REFERENCE.to_string();
        self.file_key_phrase.zeroize();
        self.file_key_phrase.clear();
        self.last_forensic_report = None;
        self.last_forensic_report_path = None;
    }

    fn refresh_integrity(&mut self) {
        self.integrity = security::vault::current_integrity_status();
    }

    fn refresh_templates_count(&mut self) {
        self.templates = template_names();
        self.templates_count = self.templates.len();
        self.refresh_integrity();
    }

    fn add_log(&mut self, message: impl Into<String>) {
        self.operation_log
            .push(format!("[{}] {}", timestamp_label(), message.into()));
        if self.operation_log.len() > 8 {
            let overflow = self.operation_log.len() - 8;
            self.operation_log.drain(0..overflow);
        }
    }

    fn parse_unlock_cajas(&self) -> Result<[i64; 5], String> {
        parse_boxes(&self.cajas)
    }

    fn unlock(&mut self) {
        let cajas = self.parse_unlock_cajas();
        let mut frase = String::new();
        std::mem::swap(&mut frase, &mut self.frase);

        let result = match cajas {
            Ok(cajas) if !frase.trim().is_empty() => {
                let mut frase_for_gateway = frase.clone();
                let unlock_result = security::vault::boot_shield_unlock(cajas, frase, None, None)
                    .map(|_| ())
                    .map_err(|_| INVALID_ACCESS.to_string());
                if unlock_result.is_ok() {
                    if let Err(error) = self.initialize_wallet_gateway(cajas, &frase_for_gateway) {
                        self.system_notification = format!("Web3 no inicializado: {}", error);
                    }
                }
                frase_for_gateway.zeroize();
                unlock_result
            }
            Ok(_) | Err(_) => {
                frase.zeroize();
                Err(INVALID_ACCESS.to_string())
            }
        };

        self.clear_secret_fields();
        match result {
            Ok(()) => {
                self.screen = Screen::Dashboard;
                self.status = "Vault desbloqueado. Dashboard TUI activo.".to_string();
                self.refresh_templates_count();
                self.add_log("Boot Shield desbloqueado.");
            }
            Err(error) => {
                self.status = error;
                self.add_log("Intento de acceso rechazado.");
            }
        }
    }

    fn lock(&mut self) {
        self.shutdown_wallet_gateway();
        let _ = security::vault::boot_shield_hardened_lock();
        self.clear_secret_fields();
        self.clear_text_fields();
        self.clear_file_fields();
        self.settings_boot_frase.zeroize();
        self.settings_boot_frase.clear();
        self.screen = if security::vault_is_configured() {
            Screen::Unlock
        } else {
            Screen::Dashboard
        };
        self.status = "Sesion bloqueada.".to_string();
        self.refresh_templates_count();
    }

    fn initialize_wallet_gateway(
        &mut self,
        cajas: [i64; 5],
        master_phrase: &str,
    ) -> Result<(), String> {
        if self.web3_cmd_tx.is_some() {
            return Ok(());
        }

        let keymaster = UniversalKeymaster::new(cajas, master_phrase)?;
        let default_rules = FirewallRules::default();
        let firewall = LiveFirewall::new(default_rules);
        let mut supervisor = GatewaySupervisor::new(keymaster, firewall);
        // Vincula la combinación EXACTA (5 cajas + frase maestra) requerida para
        // descongelar el disyuntor. Sin esto el rearme aceptaba cualquier credencial.
        supervisor
            .breaker
            .set_rearm_credentials(cajas, master_phrase)?;

        self.input_max_tx = supervisor.firewall.rules.max_daily_tx.to_string();
        self.input_max_volume = supervisor.firewall.rules.max_daily_volume_units.to_string();
        self.allowed_dex_contracts = supervisor.firewall.rules.allowed_dex_contracts.clone();
        self.allowed_cex_destinations = supervisor.firewall.rules.allowed_cex_destinations.clone();
        self.cached_gateway_state = supervisor.breaker.state.clone();
        self.cached_tx_count = supervisor.firewall.tx_count_today;
        self.cached_volume_units = supervisor.firewall.volume_today_units;

        let (tx, rx) = Web3BackgroundWorker::spawn(supervisor);
        self.web3_cmd_tx = Some(tx);
        self.web3_event_rx = Some(rx);
        self.system_notification = "Pasarela Web3 inicializada.".to_string();
        Ok(())
    }

    fn shutdown_wallet_gateway(&mut self) {
        if let Some(tx) = self.web3_cmd_tx.take() {
            let _ = tx.send(Web3WorkerCmd::Shutdown);
        }
        self.web3_event_rx = None;
        self.cached_gateway_state = GatewaySecurityState::Frozen {
            reason: "Pasarela Web3 no inicializada".to_string(),
            timestamp: 0,
        };
        self.cached_tx_count = 0;
        self.cached_volume_units = Decimal::ZERO;
        self.system_notification = "Pasarela Web3 detenida.".to_string();
        self.show_breaker_reset = false;
        self.clear_gateway_secret_fields();
    }

    fn clear_gateway_secret_fields(&mut self) {
        zeroize_boxes(&mut self.reset_cajas);
        self.reset_phrase.zeroize();
        self.reset_phrase.clear();
    }

    fn insert_virtual_char(&mut self) {
        let Some(value) = self.teclado_shuffled.get(self.cursor_teclado).copied() else {
            return;
        };
        if self.focus < 5 {
            if value.is_ascii_digit() || (value == '-' && self.cajas[self.focus].is_empty()) {
                self.cajas[self.focus].push(value);
            }
        } else {
            self.frase.push(value);
        }
    }

    fn selected_template_name(&self) -> String {
        self.templates
            .get(self.template_selected_index)
            .cloned()
            .unwrap_or_else(|| DEFAULT_TEMPLATE.to_string())
    }

    fn load_selected_template(&mut self) {
        let name = self.selected_template_name();
        match livencrypt_lib::resolve_template(&name) {
            Ok(template) => {
                self.template_name = name;
                self.template_rows = template.rows.max(1).to_string();
                self.template_cols = template.cols.max(1).to_string();
                self.template_chars = compact_template_chars(&template.chars);
                normalize_template_cell_index(self);
                self.status = "Plantilla cargada en editor.".to_string();
            }
            Err(error) => self.status = format!("No se pudo cargar plantilla: {}", error),
        }
    }
}

impl Drop for TuiState {
    fn drop(&mut self) {
        self.clear_secret_fields();
        self.clear_text_fields();
        self.clear_file_fields();
        zeroize_boxes(&mut self.text_cajas);
        zeroize_boxes(&mut self.file_cajas);
        zeroize_boxes(&mut self.settings_boot_cajas);
        self.file_browser.clear();
        self.status.zeroize();
        self.recovery_path.zeroize();
        self.recovery_error.zeroize();
        self.settings_boot_frase.zeroize();
        self.settings_network_confirmation.zeroize();
        self.text_output_file.zeroize();
        self.shutdown_wallet_gateway();
        self.input_new_dex_id.zeroize();
        self.input_new_cex_id.zeroize();
        self.system_notification.zeroize();
    }
}

fn empty_boxes() -> [String; 5] {
    Default::default()
}

fn default_boxes() -> [String; 5] {
    [
        "1".to_string(),
        "2".to_string(),
        "3".to_string(),
        "4".to_string(),
        "5".to_string(),
    ]
}

fn zeroize_boxes(boxes: &mut [String; 5]) {
    for value in boxes {
        value.zeroize();
        value.clear();
    }
}

fn sorted_keys(map: std::collections::HashMap<String, Vec<String>>) -> Vec<String> {
    let mut keys = map.into_keys().collect::<Vec<_>>();
    keys.sort_by_key(|value| value.to_lowercase());
    keys
}

fn template_names() -> Vec<String> {
    let mut names = livencrypt_lib::load_templates()
        .map(|templates| templates.into_keys().collect::<Vec<_>>())
        .unwrap_or_else(|_| vec![DEFAULT_TEMPLATE.to_string()]);
    if !names.iter().any(|name| name == DEFAULT_TEMPLATE) {
        names.push(DEFAULT_TEMPLATE.to_string());
    }
    names.sort_by_key(|value| value.to_lowercase());
    names
}

fn default_template_chars() -> Vec<String> {
    livencrypt_lib::templates::filelivencrypt_template().chars
}

fn template_rows(state: &TuiState) -> u32 {
    state
        .template_rows
        .trim()
        .parse::<u32>()
        .unwrap_or(TEMPLATE_ROWS)
        .clamp(1, 99)
}

fn template_cols(state: &TuiState) -> u32 {
    state
        .template_cols
        .trim()
        .parse::<u32>()
        .unwrap_or(TEMPLATE_COLS)
        .clamp(1, 99)
}

fn template_cell_limit(state: &TuiState) -> usize {
    template_rows(state) as usize * template_cols(state) as usize
}

fn template_char_count(chars: &[String]) -> usize {
    chars.iter().filter(|value| !value.is_empty()).count()
}

fn compact_template_chars(chars: &[String]) -> Vec<String> {
    chars
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect()
}

fn normalize_template_cell_index(state: &mut TuiState) {
    let limit = template_cell_limit(state).max(1);
    if state.template_cell_index >= limit {
        state.template_cell_index = limit - 1;
    }
}

fn parse_boxes(values: &[String; 5]) -> Result<[i64; 5], String> {
    let parsed = values
        .iter()
        .map(|value| {
            value
                .trim()
                .parse::<i64>()
                .map_err(|_| INVALID_ACCESS.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    parsed.try_into().map_err(|_| INVALID_ACCESS.to_string())
}

fn push_box_char(value: &mut String, c: char) -> bool {
    if !(c.is_ascii_digit() || (c == '-' && value.is_empty())) {
        return false;
    }
    let max_len = if value.starts_with('-') || c == '-' {
        4
    } else {
        3
    };
    if value.len() >= max_len {
        return false;
    }

    let mut candidate = value.clone();
    candidate.push(c);
    if candidate == "-" {
        value.push(c);
        return true;
    }
    if candidate
        .parse::<i64>()
        .map(|number| (-999..=999).contains(&number))
        .unwrap_or(false)
    {
        value.push(c);
        return true;
    }
    false
}

fn box_value_valid(value: &str) -> bool {
    if value.is_empty() || value == "-" {
        return true;
    }
    value
        .parse::<i64>()
        .map(|number| (-999..=999).contains(&number))
        .unwrap_or(false)
}

fn timestamp_label() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() % 86_400)
        .unwrap_or_default();
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

fn gateway_state_label(state: &GatewaySecurityState) -> &'static str {
    match state {
        GatewaySecurityState::Operational => "OPERATIVA",
        GatewaySecurityState::Frozen { .. } => "CONGELADA",
        GatewaySecurityState::HardLocked => "BLOQUEADA",
    }
}

fn shuffled_keyboard() -> Vec<char> {
    let mut chars: Vec<char> = "0123456789ABCDEFabcdef!@#$%^&*()-_=+[]{};:,.?/"
        .chars()
        .collect();
    chars.shuffle(&mut rand::thread_rng());
    chars
}

fn shuffled_template_keyboard(template_name: &str) -> Vec<String> {
    let mut values = livencrypt_lib::resolve_template(template_name)
        .map(|template| template.chars)
        .unwrap_or_else(|_| default_template_chars());
    for value in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-", "␣"] {
        if !values.iter().any(|existing| existing == value) {
            values.push(value.to_string());
        }
    }
    values.retain(|value| !value.is_empty());
    values.sort();
    values.dedup();
    values.shuffle(&mut rand::thread_rng());
    values.truncate(80);
    values
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>) -> io::Result<()> {
    let mut state = TuiState::new();
    let mut last_interaction = Instant::now();

    loop {
        poll_file_job(&mut state);
        process_background_web3_events(&mut state);
        if state.inactivity_enabled
            && last_interaction.elapsed()
                >= Duration::from_secs(state.inactivity_timeout_seconds.max(30))
        {
            state.lock();
            state.status = "Sesion bloqueada por inactividad.".to_string();
            last_interaction = Instant::now();
        }
        terminal.draw(|frame| draw_ui(frame, &state))?;

        if event::poll(Duration::from_millis(200))? {
            last_interaction = Instant::now();
            match event::read()? {
                Event::Key(key) => {
                    if key.kind == KeyEventKind::Release {
                        continue;
                    }
                    handle_key(&mut state, key);
                }
                Event::Mouse(mouse) => handle_mouse_event(&mut state, mouse),
                Event::Paste(text) => handle_paste_event(&mut state, text),
                _ => {}
            }
        }

        if state.should_quit {
            break;
        }
    }

    Ok(())
}

fn poll_file_job(state: &mut TuiState) {
    let Some(rx) = state.file_job_rx.take() else {
        return;
    };
    match rx.try_recv() {
        Ok(job) => {
            state.is_processing = false;
            state.processing_progress.store(100, Ordering::Relaxed);
            match job.result {
                Ok(report) => {
                    state.file_output_path = job.output.display().to_string();
                    if let Some(report) = report {
                        state.last_forensic_report = Some(report);
                        state.last_forensic_report_path = None;
                    }
                    state.status = format!(
                        "Archivo {} completado. Resultado actualizado en destino.",
                        job.mode.label()
                    );
                    state.add_log(format!(
                        "Archivo {} -> {} ({}ms)",
                        job.mode.label(),
                        state.file_output_path,
                        job.duration_ms
                    ));
                    if state.file_close_after_operation {
                        state.lock();
                        state.should_quit = true;
                    }
                }
                Err(error) => {
                    state.status = format!("Error de archivo: {}", error);
                }
            }
        }
        Err(mpsc::TryRecvError::Empty) => {
            state.file_job_rx = Some(rx);
            let current = state.processing_progress.load(Ordering::Relaxed);
            if current < 95 {
                state
                    .processing_progress
                    .store(current.saturating_add(1), Ordering::Relaxed);
            }
        }
        Err(mpsc::TryRecvError::Disconnected) => {
            state.is_processing = false;
            state.status = "Proceso de archivo interrumpido.".to_string();
        }
    }
}

fn process_background_web3_events(state: &mut TuiState) {
    let Some(rx) = state.web3_event_rx.take() else {
        return;
    };

    let mut disconnected = false;
    loop {
        match rx.try_recv() {
            Ok(Web3WorkerEvent::StatusChanged(new_state)) => {
                state.cached_gateway_state = new_state;
                if matches!(
                    state.cached_gateway_state,
                    GatewaySecurityState::Operational
                ) {
                    state.show_breaker_reset = false;
                    state.clear_gateway_secret_fields();
                }
            }
            Ok(Web3WorkerEvent::MetricsUpdated {
                tx_count,
                volume_units,
            }) => {
                state.cached_tx_count = tx_count;
                state.cached_volume_units = volume_units;
            }
            Ok(Web3WorkerEvent::SyncRules(rules)) => {
                state.allowed_dex_contracts = rules.allowed_dex_contracts;
                state.allowed_cex_destinations = rules.allowed_cex_destinations;
                if state.gateway_focused_field != 0 {
                    state.input_max_tx = rules.max_daily_tx.to_string();
                }
                if state.gateway_focused_field != 1 {
                    state.input_max_volume = rules.max_daily_volume_units.to_string();
                }
            }
            Ok(Web3WorkerEvent::Notification(message)) => {
                state.system_notification = message;
            }
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => {
                state.cached_gateway_state = GatewaySecurityState::Frozen {
                    reason: "CRASH CRITICO: SUBSISTEMA WEB3 DETENIDO".to_string(),
                    timestamp: 0,
                };
                disconnected = true;
                break;
            }
        }
    }

    if !disconnected {
        state.web3_event_rx = Some(rx);
    }
}

fn close_forensic_report(state: &mut TuiState) {
    state.last_forensic_report = None;
    state.last_forensic_report_path = None;
    state.status = "Reporte cerrado. Permanece en Cifrar archivo.".to_string();
}

fn handle_key(state: &mut TuiState, key: KeyEvent) {
    if state.show_file_browser {
        handle_file_browser_key(state, key);
        return;
    }
    if state.show_matrix_config {
        handle_matrix_config_key(state, key);
        return;
    }
    if state.is_processing {
        return;
    }
    if state.screen == Screen::FileCipher && state.last_forensic_report.is_some() {
        match key.code {
            KeyCode::Esc | KeyCode::Char('X') | KeyCode::Char('x') => {
                close_forensic_report(state);
                return;
            }
            _ => {}
        }
    }
    match state.screen {
        Screen::Unlock => handle_unlock_key(state, key),
        Screen::Dashboard => handle_dashboard_key(state, key),
        Screen::TextCipher => handle_text_cipher_key(state, key),
        Screen::FileCipher => handle_file_cipher_key(state, key),
        Screen::TemplateEditor => handle_template_editor_key(state, key),
        Screen::Settings => handle_settings_key(state, key),
        Screen::SystemMonitor => handle_system_monitor_key(state, key),
        Screen::AuditMonitor => handle_back_to_dashboard_key(state, key),
        Screen::FirmwareStaging => handle_firmware_staging_key(state, key),
        Screen::SandboxManager => handle_back_to_dashboard_key(state, key),
        Screen::RecoveryMode => handle_recovery_key(state, key),
        Screen::InstallProfile => handle_back_to_dashboard_key(state, key),
        Screen::WalletGateway => handle_wallet_gateway_key(state, key),
        Screen::NodesManager => handle_nodes_manager_key(state, key),
    }
}

fn handle_paste_event(state: &mut TuiState, text: String) {
    if state.screen != Screen::TextCipher
        || state.show_file_browser
        || state.show_matrix_config
        || state.is_processing
    {
        return;
    }
    paste_text_into_text_cipher(state, &text);
}

fn handle_mouse_event(state: &mut TuiState, mouse: MouseEvent) {
    match mouse.kind {
        MouseEventKind::ScrollUp => handle_mouse_scroll(state, true),
        MouseEventKind::ScrollDown => handle_mouse_scroll(state, false),
        MouseEventKind::Down(MouseButton::Left) => handle_mouse(state, mouse),
        _ => {}
    }
}

fn handle_mouse_scroll(state: &mut TuiState, up: bool) {
    if state.show_file_browser {
        if up {
            state.file_browser.move_up();
        } else {
            state.file_browser.move_down();
        }
        return;
    }

    match state.screen {
        Screen::TemplateEditor => {
            let limit = template_cell_limit(state);
            if state.template_focus == 0 {
                if up {
                    state.template_selected_index = state.template_selected_index.saturating_sub(1);
                } else if state.template_selected_index + 1 < state.templates.len() {
                    state.template_selected_index += 1;
                }
            } else if state.template_focus == 3 && up {
                state.template_cell_index = state.template_cell_index.saturating_sub(1);
            } else if state.template_focus == 3 && state.template_cell_index + 1 < limit {
                state.template_cell_index += 1;
            } else if state.template_focus == 4 && up {
                state.template_preview_cursor = state.template_preview_cursor.saturating_sub(1);
            } else if state.template_focus == 4 {
                let preview_len = template_preview_values(state).len();
                if state.template_preview_cursor + 1 < preview_len {
                    state.template_preview_cursor += 1;
                }
            }
            if state.template_focus == 0 {
                if up {
                    state.language_index = state.language_index.saturating_sub(1);
                    state.number_index = state.number_index.saturating_sub(1);
                } else {
                    if state.language_index + 1 < state.language_names.len() {
                        state.language_index += 1;
                    }
                    if state.number_index + 1 < state.number_names.len() {
                        state.number_index += 1;
                    }
                }
            }
        }
        Screen::FileCipher => {
            if up {
                state.focus = state.focus.saturating_sub(1);
            } else {
                state.focus = (state.focus + 1).min(9);
            }
        }
        Screen::TextCipher => {
            if up {
                if state.focus == 8 {
                    toggle_text_password_direction(state);
                } else {
                    state.focus = state.focus.saturating_sub(1);
                }
            } else {
                if state.focus == 8 {
                    toggle_text_password_direction(state);
                } else {
                    state.focus = (state.focus + 1).min(10);
                }
            }
        }
        _ => {}
    }
}

fn handle_mouse(state: &mut TuiState, mouse: MouseEvent) {
    let area = terminal_area();
    let inner = centered_area(area, 94, 88);
    if state.show_file_browser {
        handle_file_browser_mouse(state, mouse, inner);
        return;
    }
    if state.is_processing {
        return;
    }
    if state.screen == Screen::FileCipher && state.last_forensic_report.is_some() {
        close_forensic_report(state);
        return;
    }
    if !point_in_rect(mouse.column, mouse.row, inner) {
        return;
    }

    match state.screen {
        Screen::Unlock => handle_unlock_mouse(state, mouse, inner),
        Screen::Dashboard => handle_dashboard_mouse(state, mouse, inner),
        Screen::TextCipher => handle_text_cipher_mouse(state, mouse, inner),
        Screen::FileCipher => handle_file_cipher_mouse(state, mouse, inner),
        Screen::TemplateEditor => handle_template_editor_mouse(state, mouse, inner),
        Screen::Settings => handle_settings_mouse(state, mouse, inner),
        Screen::SystemMonitor
        | Screen::AuditMonitor
        | Screen::FirmwareStaging
        | Screen::SandboxManager
        | Screen::RecoveryMode
        | Screen::InstallProfile
        | Screen::NodesManager => {
            if mouse.row <= inner.y + 1 {
                state.screen = Screen::Dashboard;
            }
        }
        Screen::WalletGateway => handle_wallet_gateway_mouse(state, mouse, inner),
    }
}

fn terminal_area() -> Rect {
    let (width, height) = crossterm::terminal::size().unwrap_or((100, 36));
    Rect {
        x: 0,
        y: 0,
        width,
        height,
    }
}

fn point_in_rect(x: u16, y: u16, rect: Rect) -> bool {
    x >= rect.x
        && y >= rect.y
        && x < rect.x.saturating_add(rect.width)
        && y < rect.y.saturating_add(rect.height)
}

fn handle_unlock_mouse(state: &mut TuiState, mouse: MouseEvent, area: Rect) {
    let hardening = security::process_hardening::process_hardening_status();
    let constraints = if hardening.warnings.is_empty() {
        vec![
            Constraint::Length(4),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(4),
        ]
    } else {
        vec![
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(4),
        ]
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);
    let form_index = if hardening.warnings.is_empty() { 1 } else { 2 };
    let keyboard_index = form_index + 1;

    let form = chunks[form_index];
    if point_in_rect(mouse.column, mouse.row, form) {
        let offset = mouse.row.saturating_sub(form.y + 1);
        if offset < 6 {
            state.focus = offset as usize;
        }
        return;
    }

    let keyboard = chunks[keyboard_index];
    if point_in_rect(mouse.column, mouse.row, keyboard) {
        let row = mouse.row.saturating_sub(keyboard.y + 2) as usize;
        let col = mouse.column.saturating_sub(keyboard.x + 2) as usize / 3;
        let index = row.saturating_mul(10).saturating_add(col);
        if index < state.teclado_shuffled.len() {
            state.cursor_teclado = index;
            state.insert_virtual_char();
        }
    }
}

fn handle_dashboard_mouse(state: &mut TuiState, mouse: MouseEvent, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(16),
            Constraint::Min(4),
        ])
        .split(area);
    let list = chunks[1];
    if !point_in_rect(mouse.column, mouse.row, list) {
        return;
    }
    match mouse.row.saturating_sub(list.y + 1) {
        3 => state.screen = Screen::WalletGateway,
        4 => state.screen = Screen::TextCipher,
        5 => state.screen = Screen::FileCipher,
        6 => state.screen = Screen::TemplateEditor,
        7 => state.screen = Screen::Settings,
        8 => {
            state.refresh_integrity();
            state.screen = Screen::SystemMonitor;
        }
        9 => state.screen = Screen::AuditMonitor,
        10 => state.screen = Screen::FirmwareStaging,
        11 => state.screen = Screen::SandboxManager,
        12 => state.screen = Screen::RecoveryMode,
        13 => state.screen = Screen::InstallProfile,
        14 => state.lock(),
        15 => {
            let _ = security::vault::boot_shield_hardened_lock();
            state.should_quit = true;
        }
        _ => {}
    }
}

fn handle_wallet_gateway_mouse(state: &mut TuiState, mouse: MouseEvent, area: Rect) {
    if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
        return;
    }

    if state.show_breaker_reset {
        let modal = centered_area(area, 72, 44);
        if !point_in_rect(mouse.column, mouse.row, modal) {
            return;
        }
        let relative = mouse.row.saturating_sub(modal.y + 4);
        if relative <= 1 {
            let col = mouse.column.saturating_sub(modal.x + 2) as usize;
            state.reset_focus_index = (col / 12).min(4);
        } else if relative >= 3 {
            state.reset_focus_index = 5;
        }
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

    if point_in_rect(mouse.column, mouse.row, chunks[2]) {
        state.screen = Screen::Dashboard;
        return;
    }

    let body = chunks[1];
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(body);
    if !point_in_rect(mouse.column, mouse.row, body_chunks[0]) {
        return;
    }

    match mouse.row.saturating_sub(body_chunks[0].y + 5) {
        0 => state.gateway_focused_field = 0,
        1 => state.gateway_focused_field = 1,
        2 => state.gateway_focused_field = 2,
        3 => state.gateway_focused_field = 3,
        _ => {}
    }
}

fn handle_text_cipher_mouse(state: &mut TuiState, mouse: MouseEvent, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(13),
            Constraint::Min(8),
            Constraint::Length(10),
        ])
        .split(area);
    if point_in_rect(mouse.column, mouse.row, chunks[0]) {
        let line = mouse.row.saturating_sub(chunks[0].y + 1);
        match line {
            0 => {
                if mouse.column < chunks[0].x + 20 {
                    run_text_cipher(state, true);
                } else {
                    state.focus = 1;
                    cycle_text_template(state, true);
                }
            }
            1..=5 => state.focus = line as usize + 1,
            6 => state.focus = 7,
            7 => {
                if state.focus == 8 {
                    toggle_text_password_direction(state);
                }
                state.focus = 8;
            }
            8 => state.focus = 9,
            9 => state.focus = 10,
            _ => {}
        }
        return;
    }
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);
    if point_in_rect(mouse.column, mouse.row, columns[0]) {
        state.focus = 0;
        if !state.text_internal_clipboard.is_empty() {
            let text = state.text_internal_clipboard.clone();
            paste_text_into_text_cipher(state, &text);
            state.status = "Texto copiado desde Resultado pegado en Entrada.".to_string();
        }
    } else if point_in_rect(mouse.column, mouse.row, columns[1]) {
        copy_text_output_to_clipboard(state);
    }
    let keyboard_area = chunks[2];
    if text_keyboard_visible(state) && point_in_rect(mouse.column, mouse.row, keyboard_area) {
        let row = mouse.row.saturating_sub(keyboard_area.y + 2) as usize;
        let col = mouse.column.saturating_sub(keyboard_area.x + 2) as usize / 4;
        let index = row.saturating_mul(16).saturating_add(col);
        if index < state.text_keyboard_chars.len() {
            state.text_keyboard_cursor = index;
            insert_text_keyboard_value(state);
        }
    }
}

fn handle_file_cipher_mouse(state: &mut TuiState, mouse: MouseEvent, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(14),
            Constraint::Min(5),
            Constraint::Length(6),
        ])
        .split(area);
    if !point_in_rect(mouse.column, mouse.row, chunks[0]) {
        return;
    }
    match mouse.row.saturating_sub(chunks[0].y + 1) {
        0 => {
            if mouse.column < chunks[0].x + 24 {
                open_file_browser(state);
            } else if mouse.column < chunks[0].x + 38 {
                start_file_cipher_task(state);
            }
        }
        1 => {
            toggle_file_mode(state);
        }
        2 => state.file_close_after_operation = !state.file_close_after_operation,
        3 => state.focus = 0,
        4 => state.focus = 1,
        5 => {
            state.focus = 2;
            cycle_file_template(state, true);
        }
        6..=10 => state.focus = mouse.row.saturating_sub(chunks[0].y + 3) as usize,
        11 => state.focus = 8,
        _ => {}
    }
}

fn handle_template_editor_mouse(state: &mut TuiState, mouse: MouseEvent, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(8)])
        .split(area);
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(chunks[0]);
    if point_in_rect(mouse.column, mouse.row, columns[0]) {
        let left = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(35),
                Constraint::Percentage(30),
                Constraint::Percentage(35),
            ])
            .split(columns[0]);
        if point_in_rect(mouse.column, mouse.row, left[0]) {
            let index = template_grid_index_at(
                left[0],
                mouse.column,
                mouse.row,
                state.language_index,
                state.language_names.len(),
            );
            if index < state.language_names.len() {
                if index == state.language_index && state.language_click_ready {
                    add_selected_language(state);
                    state.language_click_ready = false;
                } else {
                    state.language_index = index;
                    state.language_click_ready = true;
                    state.status = format!(
                        "Idioma seleccionado: {}. Segundo clic inserta caracteres hasta completar tabla.",
                        state.language_names[index]
                    );
                }
            }
        } else if point_in_rect(mouse.column, mouse.row, left[1]) {
            let index = template_grid_index_at(
                left[1],
                mouse.column,
                mouse.row,
                state.number_index,
                state.number_names.len(),
            );
            if index < state.number_names.len() {
                if index == state.number_index && state.number_click_ready {
                    add_selected_numbers(state);
                    state.number_click_ready = false;
                } else {
                    state.number_index = index;
                    state.number_click_ready = true;
                    state.status = format!(
                        "Numeros/signos seleccionados: {}. Segundo clic inserta hasta completar tabla.",
                        state.number_names[index]
                    );
                }
            }
        } else if point_in_rect(mouse.column, mouse.row, left[2]) {
            let visible = left[2].height.saturating_sub(2).max(1) as usize;
            let start = list_window_start(
                state.template_selected_index,
                state.templates.len(),
                visible,
            );
            let index = start + mouse.row.saturating_sub(left[2].y + 1) as usize;
            if index < state.templates.len() {
                state.template_selected_index = index;
                state.load_selected_template();
            }
        }
    } else if point_in_rect(mouse.column, mouse.row, columns[1]) {
        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),
                Constraint::Min(8),
                Constraint::Length(5),
                Constraint::Length(4),
                Constraint::Length(5),
            ])
            .split(columns[1]);
        if point_in_rect(mouse.column, mouse.row, right[0]) {
            state.template_focus = 0;
            let relative_x = mouse.column.saturating_sub(right[0].x);
            let insert_start = (state.template_name.chars().count() as u16).saturating_add(16);
            if mouse.row == right[0].y + 1
                && (relative_x >= insert_start || relative_x > right[0].width / 2)
            {
                insert_new_template_from_state(state);
            } else if mouse.row >= right[0].y + 2 {
                if relative_x < right[0].width / 3 {
                    state.template_focus = 1;
                    state.template_rows.zeroize();
                    state.template_rows.clear();
                } else if relative_x < right[0].width * 2 / 3 {
                    state.template_focus = 2;
                    state.template_cols.zeroize();
                    state.template_cols.clear();
                }
            }
        } else if point_in_rect(mouse.column, mouse.row, right[1]) {
            state.template_focus = 3;
            let visible_rows = right[1].height.saturating_sub(2).max(1) as usize;
            let start_row = table_window_start(state, visible_rows);
            let row = mouse.row.saturating_sub(right[1].y + 1) as usize;
            let col = mouse.column.saturating_sub(right[1].x + 1) as usize
                / TEMPLATE_GRID_CELL_WIDTH.max(1);
            let index = start_row
                .saturating_add(row)
                .saturating_mul(template_cols(state) as usize)
                .saturating_add(col);
            if index < template_cell_limit(state) {
                state.template_cell_index = index;
            }
        } else if point_in_rect(mouse.column, mouse.row, right[2]) {
            state.template_focus = 4;
            let visible_rows = right[2].height.saturating_sub(2).max(1) as usize;
            let start_row = preview_window_start(state, visible_rows);
            let row = mouse.row.saturating_sub(right[2].y + 1) as usize;
            let col = mouse.column.saturating_sub(right[2].x + 1) as usize
                / TEMPLATE_PREVIEW_CELL_WIDTH.max(1);
            let index = start_row
                .saturating_add(row)
                .saturating_mul(16)
                .saturating_add(col);
            if let Some(value) = template_preview_values(state).get(index).cloned() {
                if state.template_preview_cursor == index && state.template_preview_click_ready {
                    insert_template_value(state, value);
                    state.template_preview_click_ready = false;
                } else {
                    state.template_preview_cursor = index;
                    state.template_preview_click_ready = true;
                    state.status = format!(
                        "Caracter seleccionado en vista previa: {}. Segundo clic lo inserta.",
                        value
                    );
                }
            }
        } else if point_in_rect(mouse.column, mouse.row, right[4]) {
            let offset = mouse.column.saturating_sub(right[4].x);
            if offset < right[4].width / 4 {
                save_template_from_state(state);
            } else if offset < right[4].width / 2 {
                delete_template_from_state(state);
            } else if offset < right[4].width * 3 / 4 {
                fill_missing_hex_chars(state);
            } else {
                state.template_chars.clear();
                state.status = "Caracteres de plantilla limpiados.".to_string();
            }
        }
    }
}

fn handle_settings_mouse(state: &mut TuiState, mouse: MouseEvent, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(14), Constraint::Length(6)])
        .split(area);
    if !point_in_rect(mouse.column, mouse.row, chunks[0]) {
        return;
    }
    match mouse.row.saturating_sub(chunks[0].y + 1) {
        3..=7 => state.settings_focus = mouse.row.saturating_sub(chunks[0].y + 4) as usize,
        8 => state.settings_focus = 5,
        9 => state.settings_focus = 6,
        10 => state.settings_focus = 9,
        13 => state.settings_focus = 7,
        14 => state.settings_focus = 8,
        0 => {}
        row if row >= 22 => {
            if mouse.column < chunks[0].x + chunks[0].width / 2 {
                enable_apparmor_from_settings(state);
            } else {
                disable_apparmor_from_settings(state);
            }
        }
        _ => {}
    }
}

fn handle_unlock_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            state.clear_secret_fields();
            state.should_quit = true;
        }
        KeyCode::Tab => state.focus = (state.focus + 1) % 6,
        KeyCode::BackTab => state.focus = if state.focus == 0 { 5 } else { state.focus - 1 },
        KeyCode::Backspace => {
            if state.focus < 5 {
                state.cajas[state.focus].pop();
            } else {
                state.frase.pop();
            }
        }
        KeyCode::Left => state.cursor_teclado = state.cursor_teclado.saturating_sub(1),
        KeyCode::Right => {
            if state.cursor_teclado + 1 < state.teclado_shuffled.len() {
                state.cursor_teclado += 1;
            }
        }
        KeyCode::Up => {
            if state.cursor_teclado >= 10 {
                state.cursor_teclado -= 10;
            }
        }
        KeyCode::Down => {
            if state.cursor_teclado + 10 < state.teclado_shuffled.len() {
                state.cursor_teclado += 10;
            }
        }
        KeyCode::Char(' ') => state.insert_virtual_char(),
        KeyCode::Enter => {
            if state.focus < 5 {
                state.focus += 1;
            } else {
                state.unlock();
            }
        }
        KeyCode::F(10) => state.unlock(),
        KeyCode::Char(value) => {
            if state.focus < 5 {
                if !push_box_char(&mut state.cajas[state.focus], value) {
                    state.status = "Caja fuera de rango permitido (-999..999).".to_string();
                }
            } else {
                state.frase.push(value);
            }
        }
        _ => {}
    }
}

fn handle_dashboard_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            let _ = security::vault::boot_shield_hardened_lock();
            state.should_quit = true;
        }
        KeyCode::Char('t') => {
            state.focus = 0;
            state.screen = Screen::TextCipher;
        }
        KeyCode::Char('f') => {
            state.focus = 0;
            state.screen = Screen::FileCipher;
        }
        KeyCode::Char('e') => {
            state.template_focus = 0;
            state.screen = Screen::TemplateEditor;
        }
        KeyCode::Char('c') => {
            state.settings_focus = 0;
            state.screen = Screen::Settings;
        }
        KeyCode::Char('m') => {
            state.refresh_integrity();
            state.screen = Screen::SystemMonitor;
        }
        KeyCode::Char('a') => state.screen = Screen::AuditMonitor,
        KeyCode::Char('u') => state.screen = Screen::FirmwareStaging,
        KeyCode::Char('s') => state.screen = Screen::SandboxManager,
        KeyCode::Char('r') => {
            state.recovery_error.clear();
            state.screen = Screen::RecoveryMode;
        }
        KeyCode::Char('p') => state.screen = Screen::InstallProfile,
        KeyCode::Char('w') | KeyCode::Char('W') => state.screen = Screen::WalletGateway,
        KeyCode::Char('l') => state.lock(),
        KeyCode::Char('R') => {
            state.refresh_templates_count();
            state.status = "Estado actualizado.".to_string();
        }
        _ => {}
    }
}

fn handle_back_to_dashboard_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::Dashboard,
        _ => {}
    }
}

fn reload_nodes_manager(state: &mut TuiState) {
    state.nodes = NodeRegistry::load_from_path(&nodes::default_nodes_path());
    state.nodes_chains = state.nodes.chain_names();
    if state.nodes_chains.is_empty() {
        state.nodes_selected = 0;
    } else if state.nodes_selected >= state.nodes_chains.len() {
        state.nodes_selected = state.nodes_chains.len() - 1;
    }
}

fn handle_nodes_manager_key(state: &mut TuiState, key: KeyEvent) {
    if state.nodes_editing {
        match key.code {
            KeyCode::Esc => {
                state.nodes_edit_buffer.zeroize();
                state.nodes_edit_buffer.clear();
                state.nodes_editing = false;
                state.status = "Edicion cancelada.".to_string();
            }
            KeyCode::Backspace => {
                state.nodes_edit_buffer.pop();
            }
            KeyCode::Enter => {
                if let Some(chain) = state.nodes_chains.get(state.nodes_selected).cloned() {
                    let url = state.nodes_edit_buffer.clone();
                    state.nodes.set_primary(&chain, &url);
                    state.status = format!("Endpoint principal actualizado para {}.", chain);
                }
                state.nodes_edit_buffer.zeroize();
                state.nodes_edit_buffer.clear();
                state.nodes_editing = false;
            }
            KeyCode::Char(value) => state.nodes_edit_buffer.push(value),
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Esc => {
            state.nodes_edit_buffer.zeroize();
            state.nodes_edit_buffer.clear();
            state.screen = Screen::Dashboard;
        }
        KeyCode::Up => {
            state.nodes_selected = state.nodes_selected.saturating_sub(1);
        }
        KeyCode::Down => {
            if state.nodes_selected + 1 < state.nodes_chains.len() {
                state.nodes_selected += 1;
            }
        }
        KeyCode::Char(' ') => {
            if let Some(chain) = state.nodes_chains.get(state.nodes_selected).cloned() {
                match state.nodes.switch_to_fallback(&chain) {
                    Some(endpoint) => {
                        state.status = format!("{} ahora enruta por {}.", chain, endpoint)
                    }
                    None => {
                        state.status =
                            "Sin nodo de respaldo registrado para esta cadena.".to_string()
                    }
                }
            }
        }
        KeyCode::Char('E') | KeyCode::Char('e') => {
            if let Some(chain) = state.nodes_chains.get(state.nodes_selected).cloned() {
                let current = state
                    .nodes
                    .current_endpoint(&chain)
                    .unwrap_or_default()
                    .to_string();
                state.nodes_edit_buffer = current;
                state.nodes_editing = true;
                state.status =
                    "Editando endpoint principal. Enter guarda, Esc cancela.".to_string();
            }
        }
        KeyCode::Char('R') | KeyCode::Char('r') => {
            reload_nodes_manager(state);
            state.status = "Catalogo de nodos recargado desde disco.".to_string();
        }
        KeyCode::Char('G') | KeyCode::Char('g') => {
            match state.nodes.save_to_path(&nodes::default_nodes_path()) {
                Ok(()) => state.status = "nodes.toml guardado en disco.".to_string(),
                Err(error) => state.status = format!("Error guardando nodes.toml: {}", error),
            }
        }
        KeyCode::Char('c') | KeyCode::Char('C')
            if key.modifiers.contains(KeyModifiers::CONTROL) =>
        {
            if let Some(chain) = state.nodes_chains.get(state.nodes_selected).cloned() {
                if let Some(endpoint) = state.nodes.current_endpoint(&chain) {
                    let endpoint = endpoint.to_string();
                    let _ = write_system_clipboard(&endpoint);
                    state.status = "Endpoint copiado al portapapeles.".to_string();
                }
            }
        }
        _ => {}
    }
}

fn handle_wallet_gateway_key(state: &mut TuiState, key: KeyEvent) {
    if state.show_breaker_reset {
        handle_wallet_gateway_reset_key(state, key);
        return;
    }

    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::Dashboard,
        KeyCode::Tab => state.gateway_focused_field = (state.gateway_focused_field + 1) % 4,
        KeyCode::BackTab => {
            state.gateway_focused_field = state.gateway_focused_field.saturating_sub(1);
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            state.show_breaker_reset = true;
            state.reset_focus_index = 0;
        }
        KeyCode::Backspace => match state.gateway_focused_field {
            0 => {
                state.input_max_tx.pop();
            }
            1 => {
                state.input_max_volume.pop();
            }
            2 => {
                state.input_new_dex_id.pop();
            }
            3 => {
                state.input_new_cex_id.pop();
            }
            _ => {}
        },
        KeyCode::Enter => submit_wallet_gateway_field(state),
        KeyCode::Char(value) => match state.gateway_focused_field {
            0 => {
                if value.is_ascii_digit() && state.input_max_tx.len() < 5 {
                    state.input_max_tx.push(value);
                }
            }
            1 => {
                if (value.is_ascii_digit() || value == '.') && state.input_max_volume.len() < 12 {
                    state.input_max_volume.push(value);
                }
            }
            2 => {
                if state.input_new_dex_id.len() < 96 {
                    state.input_new_dex_id.push(value);
                }
            }
            3 => {
                if state.input_new_cex_id.len() < 96 {
                    state.input_new_cex_id.push(value);
                }
            }
            _ => {}
        },
        _ => {}
    }
}

fn submit_wallet_gateway_field(state: &mut TuiState) {
    match state.gateway_focused_field {
        0 | 1 => {
            let max_tx = state.input_max_tx.trim().parse::<u32>().ok();
            let max_vol = state.input_max_volume.trim().parse::<Decimal>().ok();
            if max_tx.is_none() && max_vol.is_none() {
                state.system_notification = "Error: formato numerico invalido.".to_string();
                return;
            }
            if let Some(tx) = &state.web3_cmd_tx {
                let _ = tx.send(Web3WorkerCmd::UpdateRules { max_tx, max_vol });
            } else {
                state.system_notification = "Web3 no inicializado.".to_string();
            }
        }
        2 => {
            let value = state.input_new_dex_id.trim().to_string();
            if value.is_empty() {
                return;
            }
            if let Some(tx) = &state.web3_cmd_tx {
                let _ = tx.send(Web3WorkerCmd::AddDexContract(value));
                state.input_new_dex_id.zeroize();
                state.input_new_dex_id.clear();
            } else {
                state.system_notification = "Web3 no inicializado.".to_string();
            }
        }
        3 => {
            let value = state.input_new_cex_id.trim().to_string();
            if value.is_empty() {
                return;
            }
            if let Some(tx) = &state.web3_cmd_tx {
                let _ = tx.send(Web3WorkerCmd::AddCexDestination(value));
                state.input_new_cex_id.zeroize();
                state.input_new_cex_id.clear();
            } else {
                state.system_notification = "Web3 no inicializado.".to_string();
            }
        }
        _ => {}
    }
}

fn handle_wallet_gateway_reset_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            state.show_breaker_reset = false;
            state.clear_gateway_secret_fields();
        }
        KeyCode::Tab => state.reset_focus_index = (state.reset_focus_index + 1) % 6,
        KeyCode::BackTab => state.reset_focus_index = state.reset_focus_index.saturating_sub(1),
        KeyCode::Backspace => {
            if state.reset_focus_index < 5 {
                state.reset_cajas[state.reset_focus_index].pop();
            } else {
                state.reset_phrase.pop();
            }
        }
        KeyCode::Enter => submit_wallet_gateway_reset(state),
        KeyCode::Char(value) => {
            if state.reset_focus_index < 5 {
                let target = &mut state.reset_cajas[state.reset_focus_index];
                let _ = push_box_char(target, value);
            } else if state.reset_phrase.len() < 120 {
                state.reset_phrase.push(value);
            }
        }
        _ => {}
    }
}

fn submit_wallet_gateway_reset(state: &mut TuiState) {
    let Ok(cajas) = parse_boxes(&state.reset_cajas) else {
        state.system_notification = "Error: cajas de rearme invalidas.".to_string();
        return;
    };
    if state.reset_phrase.trim().is_empty() {
        state.system_notification = "Error: frase de rearme vacia.".to_string();
        return;
    }

    let mut phrase_bytes = state.reset_phrase.as_bytes().to_vec();
    state.reset_phrase.zeroize();
    state.reset_phrase.clear();

    if let Some(tx) = &state.web3_cmd_tx {
        if let Err(mpsc::SendError(Web3WorkerCmd::ResetBreaker(_, mut bytes))) =
            tx.send(Web3WorkerCmd::ResetBreaker(cajas, phrase_bytes))
        {
            bytes.zeroize();
        }
        zeroize_boxes(&mut state.reset_cajas);
    } else {
        phrase_bytes.zeroize();
        state.system_notification = "Web3 no inicializado.".to_string();
    }
}

fn handle_text_cipher_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => state.screen = Screen::Dashboard,
        KeyCode::Left => {
            if state.focus == 1 {
                cycle_text_template(state, false);
            } else if text_keyboard_visible(state) {
                state.text_keyboard_cursor = state.text_keyboard_cursor.saturating_sub(1);
            }
        }
        KeyCode::Right => {
            if state.focus == 1 {
                cycle_text_template(state, true);
            } else if text_keyboard_visible(state)
                && state.text_keyboard_cursor + 1 < state.text_keyboard_chars.len()
            {
                state.text_keyboard_cursor += 1;
            }
        }
        KeyCode::Up => {
            if state.focus == 1 {
                cycle_text_template(state, false);
            } else if text_keyboard_visible(state) {
                state.text_keyboard_cursor = state.text_keyboard_cursor.saturating_sub(16);
            }
        }
        KeyCode::Down => {
            if state.focus == 1 {
                cycle_text_template(state, true);
            } else if text_keyboard_visible(state)
                && state.text_keyboard_cursor + 16 < state.text_keyboard_chars.len()
            {
                state.text_keyboard_cursor += 16;
            }
        }
        KeyCode::Enter | KeyCode::Char(' ') if text_keyboard_visible(state) => {
            insert_text_keyboard_value(state);
        }
        KeyCode::F(2) => {
            state.show_matrix_config = true;
            state.matrix_focus = 0;
        }
        KeyCode::F(6) => export_text_to_file(state),
        KeyCode::Char('B') => open_file_browser(state),
        KeyCode::Tab => state.focus = (state.focus + 1) % 11,
        KeyCode::BackTab => {
            state.focus = if state.focus == 0 {
                10
            } else {
                state.focus - 1
            }
        }
        KeyCode::Backspace => active_text_field_mut(state).pop().map(|_| ()).unwrap_or(()),
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            copy_text_output_to_clipboard(state)
        }
        KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            paste_clipboard_into_text_cipher(state)
        }
        KeyCode::Char('V') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            paste_clipboard_into_text_cipher(state)
        }
        KeyCode::Char('C') => run_text_cipher(state, true),
        KeyCode::Char('D') => run_text_cipher(state, false),
        KeyCode::Char('R') => {
            state.refresh_text_keyboard();
            state.status = "Teclado contextual regenerado desde plantilla.".to_string();
        }
        KeyCode::Char('X') => {
            state.clear_text_fields();
            state.status = "Texto limpiado.".to_string();
        }
        KeyCode::Char(value) => {
            if (2..=6).contains(&state.focus) {
                let index = state.focus - 2;
                if !push_box_char(&mut state.text_cajas[index], value) {
                    state.status = "Caja fuera de rango permitido (-999..999).".to_string();
                }
            } else if state.focus == 1 {
                state.status =
                    "Use flechas o clic para seleccionar una plantilla existente.".to_string();
            } else {
                active_text_field_mut(state).push(value);
            }
        }
        _ => {}
    }
}

fn open_file_browser(state: &mut TuiState) {
    state.file_browser_target = if state.screen == Screen::TextCipher {
        FileBrowserTarget::TextExport
    } else if state.focus == 1 {
        FileBrowserTarget::Output
    } else {
        FileBrowserTarget::Input
    };
    if state.file_browser.all_items.is_empty() {
        state.file_browser.refresh();
    }
    state.file_browser.name_mode = false;
    state.file_browser.name_input.clear();
    state.show_file_browser = true;
    state.status = "Explorador interno abierto.".to_string();
}

fn select_browser_path(state: &mut TuiState, path: PathBuf) {
    match state.file_browser_target {
        FileBrowserTarget::Input => {
            state.file_input_path = path.display().to_string();
            state.file_output_path = derive_output_path(&path, state.file_mode)
                .display()
                .to_string();
        }
        FileBrowserTarget::Output => {
            state.file_output_path = path.display().to_string();
        }
        FileBrowserTarget::TextExport => {
            state.text_output_file = path.display().to_string();
        }
    }
    state.show_file_browser = false;
    state.file_browser.search_query.zeroize();
    state.file_browser.search_query.clear();
    state.file_browser.name_input.zeroize();
    state.file_browser.name_input.clear();
    state.file_browser.name_mode = false;
    state.status = "Ruta seleccionada desde explorador interno.".to_string();
}

fn handle_file_browser_key(state: &mut TuiState, key: KeyEvent) {
    if matches!(state.file_browser_target, FileBrowserTarget::TextExport)
        && state.file_browser.name_mode
    {
        match key.code {
            KeyCode::Esc => {
                state.show_file_browser = false;
                state.file_browser.clear();
            }
            KeyCode::Tab => state.file_browser.name_mode = false,
            KeyCode::Backspace => {
                state.file_browser.name_input.pop();
            }
            KeyCode::Enter => {
                let name = state.file_browser.name_input.trim();
                if name.is_empty() {
                    state.status = "Nombre de exportacion vacio.".to_string();
                    return;
                }
                let path = state.file_browser.current_dir.join(name);
                state.text_output_file = path.display().to_string();
                state.show_file_browser = false;
                state.file_browser.clear();
                export_text_to_file(state);
            }
            KeyCode::Char(value) => state.file_browser.name_input.push(value),
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Esc => {
            state.show_file_browser = false;
            state.file_browser.clear();
        }
        KeyCode::Tab if matches!(state.file_browser_target, FileBrowserTarget::TextExport) => {
            state.file_browser.name_mode = true;
            if state.file_browser.name_input.is_empty() {
                state.file_browser.name_input = "livencrypt_export.txt".to_string();
            }
        }
        KeyCode::Up => state.file_browser.move_up(),
        KeyCode::Down => state.file_browser.move_down(),
        KeyCode::Left => state.file_browser.move_left(),
        KeyCode::Right => state.file_browser.move_right(),
        KeyCode::Char('<') => state.file_browser.scroll_name_left(),
        KeyCode::Char('>') => state.file_browser.scroll_name_right(),
        KeyCode::Backspace => {
            if state.file_browser.search_query.is_empty() {
                state.file_browser.navigate_out();
            } else {
                state.file_browser.search_query.pop();
                state.file_browser.apply_filter();
            }
        }
        KeyCode::Enter => {
            if let Some(path) = state.file_browser.enter_selected() {
                select_browser_path(state, path);
            }
        }
        KeyCode::Char('/') => {
            state.file_browser.search_query.clear();
            state.file_browser.apply_filter();
        }
        KeyCode::Char(value) => {
            state.file_browser.search_query.push(value);
            state.file_browser.apply_filter();
        }
        _ => {}
    }
}

fn handle_file_browser_mouse(state: &mut TuiState, mouse: MouseEvent, area: Rect) {
    let popup = centered_area(area, 82, 72);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(3),
        ])
        .split(popup);
    if point_in_rect(mouse.column, mouse.row, chunks[1]) {
        let rows = chunks[1].height.saturating_sub(2).max(1) as usize;
        let col_width = chunks[1].width.saturating_sub(2).max(3) as usize / 3;
        let row = mouse.row.saturating_sub(chunks[1].y + 1) as usize;
        let col = mouse.column.saturating_sub(chunks[1].x + 1) as usize / col_width.max(1);
        let index = state
            .file_browser
            .vertical_offset
            .saturating_mul(3)
            .saturating_add(row.min(rows.saturating_sub(1)).saturating_mul(3))
            .saturating_add(col.min(2));
        if index < state.file_browser.filtered_items.len() {
            state.file_browser.selected_index = index;
            if let Some(path) = state.file_browser.enter_selected() {
                select_browser_path(state, path);
            }
        }
    } else if point_in_rect(mouse.column, mouse.row, chunks[0])
        && matches!(state.file_browser_target, FileBrowserTarget::TextExport)
    {
        state.file_browser.name_mode = !state.file_browser.name_mode;
        if state.file_browser.name_mode && state.file_browser.name_input.is_empty() {
            state.file_browser.name_input = "livencrypt_export.txt".to_string();
        }
    } else if point_in_rect(mouse.column, mouse.row, chunks[2]) {
        state.show_file_browser = false;
    }
}

fn active_text_field_mut(state: &mut TuiState) -> &mut String {
    match state.focus {
        0 => &mut state.text_input,
        1 => &mut state.text_template,
        2..=6 => &mut state.text_cajas[state.focus - 2],
        7 => &mut state.text_password_length,
        8 => &mut state.text_password_direction,
        9 => &mut state.text_control_symbols,
        _ => &mut state.text_output_file,
    }
}

fn text_keyboard_visible(state: &TuiState) -> bool {
    state.screen == Screen::TextCipher && (state.focus == 0 || (2..=6).contains(&state.focus))
}

fn toggle_text_password_direction(state: &mut TuiState) {
    state.text_password_direction = if state.text_password_direction == PASSWORD_DIRECTION_BEFORE {
        "after".to_string()
    } else {
        PASSWORD_DIRECTION_BEFORE.to_string()
    };
    state.status = format!(
        "Posicion de contrasena: {}",
        password_direction_label(&state.text_password_direction)
    );
}

fn password_direction_label(direction: &str) -> &'static str {
    if direction == "after" {
        "detras del caracter"
    } else {
        "delante del caracter"
    }
}

fn insert_text_keyboard_value(state: &mut TuiState) {
    let Some(value) = state
        .text_keyboard_chars
        .get(state.text_keyboard_cursor)
        .cloned()
    else {
        return;
    };
    let value = if value == "␣" {
        " ".to_string()
    } else {
        value
    };
    if (2..=6).contains(&state.focus) {
        let index = state.focus - 2;
        for ch in value.chars() {
            if !push_box_char(&mut state.text_cajas[index], ch) {
                state.status = "Caja fuera de rango permitido (-999..999).".to_string();
                break;
            }
        }
    } else if state.focus == 0 {
        state.text_input.push_str(&value);
    }
}

fn cycle_text_template(state: &mut TuiState, forward: bool) {
    state.refresh_templates_count();
    if let Some(next) = cycle_template_name(&state.templates, &state.text_template, forward) {
        state.text_template = next;
        state.refresh_text_keyboard();
        state.status = format!("Plantilla de texto: {}", state.text_template);
    }
}

fn cycle_file_template(state: &mut TuiState, forward: bool) {
    state.refresh_templates_count();
    if let Some(next) = cycle_template_name(&state.templates, &state.file_template, forward) {
        state.file_template = next;
        state.status = format!("Plantilla de archivo: {}", state.file_template);
    }
}

fn cycle_template_name(templates: &[String], current: &str, forward: bool) -> Option<String> {
    if templates.is_empty() {
        return None;
    }
    let current_index = templates
        .iter()
        .position(|name| name == current)
        .unwrap_or_default();
    let next_index = if forward {
        (current_index + 1) % templates.len()
    } else if current_index == 0 {
        templates.len() - 1
    } else {
        current_index - 1
    };
    templates.get(next_index).cloned()
}

fn handle_matrix_config_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Enter => state.show_matrix_config = false,
        KeyCode::Tab => state.matrix_focus = (state.matrix_focus + 1) % 3,
        KeyCode::BackTab => {
            state.matrix_focus = if state.matrix_focus == 0 {
                2
            } else {
                state.matrix_focus - 1
            };
        }
        KeyCode::Up | KeyCode::Right => match state.matrix_focus {
            0 => {
                let current = state
                    .text_password_length
                    .parse::<usize>()
                    .unwrap_or(8)
                    .saturating_add(1)
                    .clamp(2, 25);
                state.text_password_length = current.to_string();
            }
            1 => state.text_password_direction = "before".to_string(),
            2 => {
                if state.text_control_symbols.is_empty() {
                    state.text_control_symbols = DEFAULT_CONTROL_SYMBOLS.to_string();
                }
            }
            _ => {}
        },
        KeyCode::Down | KeyCode::Left => match state.matrix_focus {
            0 => {
                let current = state
                    .text_password_length
                    .parse::<usize>()
                    .unwrap_or(8)
                    .saturating_sub(1)
                    .clamp(2, 25);
                state.text_password_length = current.to_string();
            }
            1 => state.text_password_direction = "after".to_string(),
            2 => {
                state.text_control_symbols.zeroize();
                state.text_control_symbols.clear();
            }
            _ => {}
        },
        _ => {}
    }
}

fn export_text_to_file(state: &mut TuiState) {
    if state.text_output.is_empty() {
        state.status = "No hay resultado de texto para exportar.".to_string();
        return;
    }
    let path = PathBuf::from(state.text_output_file.trim());
    if path.as_os_str().is_empty() {
        state.status = "Indique ruta de exportacion en Cifrar texto.".to_string();
        return;
    }

    let mut content = state.text_output.clone();
    let result = (|| -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|error| error.to_string())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
        }

        file.write_all(content.as_bytes())
            .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();
    content.zeroize();

    match result {
        Ok(()) => {
            state.status = format!("Texto exportado: {}", path.display());
            state.add_log(format!(
                "Texto exportado a archivo seguro: {}",
                path.display()
            ));
        }
        Err(error) => state.status = format!("No se pudo exportar texto: {}", error),
    }
}

fn terminal_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(b0 >> 2) as usize] as char);
        output.push(TABLE[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(b2 & 0b0011_1111) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

fn copy_text_output_to_clipboard(state: &mut TuiState) {
    if state.text_output.is_empty() {
        state.status = "No hay resultado de texto para copiar.".to_string();
        return;
    }
    state.text_internal_clipboard.zeroize();
    state.text_internal_clipboard = state.text_output.clone();
    let system_status = match write_system_clipboard(&state.text_output) {
        Ok(()) => "Portapapeles del sistema actualizado.",
        Err(_) => "Portapapeles interno actualizado; OSC52 enviado si la terminal lo permite.",
    };
    let encoded = terminal_base64(state.text_output.as_bytes());
    print!("\x1b]52;c;{}\x07", encoded);
    let _ = io::stdout().flush();
    state.status = format!(
        "{} Clic en Entrada pega el resultado completo.",
        system_status
    );
}

fn paste_clipboard_into_text_cipher(state: &mut TuiState) {
    match read_system_clipboard() {
        Ok(text) if !text.is_empty() => {
            paste_text_into_text_cipher(state, &text);
            state.status = "Texto pegado desde portapapeles.".to_string();
        }
        Ok(_) => {
            state.status = "Portapapeles vacio.".to_string();
        }
        Err(error) => {
            state.status = format!("No se pudo pegar desde portapapeles: {}", error);
        }
    }
}

fn read_system_clipboard() -> Result<String, String> {
    let candidates: &[(&str, &[&str])] = &[
        ("wl-paste", &["-n"]),
        ("xclip", &["-selection", "clipboard", "-o"]),
        ("xsel", &["--clipboard", "--output"]),
    ];
    for (program, args) in candidates {
        let Ok(output) = Command::new(program).args(*args).output() else {
            continue;
        };
        if output.status.success() {
            return String::from_utf8(output.stdout)
                .map(|value| value.trim_end_matches(['\r', '\n']).to_string())
                .map_err(|error| error.to_string());
        }
    }
    Err("no se encontro wl-paste, xclip ni xsel".to_string())
}

fn write_system_clipboard(text: &str) -> Result<(), String> {
    let candidates: &[(&str, &[&str])] = &[
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ];
    for (program, args) in candidates {
        let Ok(mut child) = Command::new(program)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        if let Some(stdin) = child.stdin.as_mut() {
            if stdin.write_all(text.as_bytes()).is_err() {
                continue;
            }
        }
        if child.wait().map(|status| status.success()).unwrap_or(false) {
            return Ok(());
        }
    }
    Err("no se encontro wl-copy, xclip ni xsel".to_string())
}

fn paste_text_into_text_cipher(state: &mut TuiState, text: &str) {
    if (2..=6).contains(&state.focus) {
        let index = state.focus - 2;
        for ch in text.chars() {
            let _ = push_box_char(&mut state.text_cajas[index], ch);
        }
    } else {
        active_text_field_mut(state).push_str(text);
        if state.focus == 1 {
            state.refresh_text_keyboard();
        }
    }
    state.status = "Texto pegado.".to_string();
}

fn run_text_cipher(state: &mut TuiState, encrypt: bool) {
    execute_text_cipher(state, encrypt);
}

fn text_secret_material(cajas: &[i64; 5], passphrase: &str) -> String {
    let mut secret = String::from("LVC-TEXT-V1|");
    for caja in cajas {
        secret.push_str(&caja.to_string());
        secret.push('|');
    }
    secret.push_str(passphrase);
    secret
}

fn execute_text_cipher(state: &mut TuiState, encrypt: bool) {
    let started = Instant::now();
    let cajas = match parse_boxes(&state.text_cajas) {
        Ok(cajas) => cajas,
        Err(error) => {
            state.status = error;
            return;
        }
    };
    let mut secret = text_secret_material(&cajas, &state.text_control_symbols);
    let result = if encrypt {
        livencrypt_lib::cipher_text_secure(&state.text_input, &secret)
    } else {
        livencrypt_lib::decipher_text_secure(&state.text_input, &secret)
    };
    secret.zeroize();

    match result {
        Ok(output) => {
            state.text_output = output;
            state.status = if encrypt {
                "Texto cifrado con cifrado fuerte (Argon2id + XChaCha20Poly1305).".to_string()
            } else {
                "Texto descifrado con cifrado fuerte (Argon2id + XChaCha20Poly1305).".to_string()
            };
            state.add_log(format!(
                "{} texto completado ({}ms)",
                if encrypt { "Cifrado" } else { "Descifrado" },
                started.elapsed().as_millis()
            ));
        }
        Err(error) => state.status = format!("Error de texto: {}", error),
    }
}

fn handle_file_cipher_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => state.screen = Screen::Dashboard,
        KeyCode::Up | KeyCode::Left if state.focus == 2 => cycle_file_template(state, false),
        KeyCode::Down | KeyCode::Right if state.focus == 2 => cycle_file_template(state, true),
        KeyCode::Tab => state.focus = (state.focus + 1) % 10,
        KeyCode::BackTab => state.focus = if state.focus == 0 { 9 } else { state.focus - 1 },
        KeyCode::Backspace => active_file_field_mut(state).pop().map(|_| ()).unwrap_or(()),
        KeyCode::Char('M') => {
            toggle_file_mode(state);
        }
        KeyCode::Char('A') => {
            state.file_close_after_operation = !state.file_close_after_operation;
            state.status = format!(
                "Cierre automatico tras archivo: {}",
                if state.file_close_after_operation {
                    "ON"
                } else {
                    "OFF"
                }
            );
        }
        KeyCode::Char('B') => open_file_browser(state),
        KeyCode::Char('E') => start_file_cipher_task(state),
        KeyCode::Char('I') => show_file_info(state),
        KeyCode::Char('X') => {
            state.clear_file_fields();
            state.status = "Rutas limpiadas.".to_string();
        }
        KeyCode::Char(value) => {
            if (3..=7).contains(&state.focus) {
                let index = state.focus - 3;
                if !push_box_char(&mut state.file_cajas[index], value) {
                    state.status = "Caja fuera de rango permitido (-999..999).".to_string();
                }
            } else if state.focus == 2 {
                state.status =
                    "Use flechas o clic para seleccionar una plantilla existente.".to_string();
            } else {
                active_file_field_mut(state).push(value);
            }
        }
        _ => {}
    }
}

fn active_file_field_mut(state: &mut TuiState) -> &mut String {
    match state.focus {
        0 => &mut state.file_input_path,
        1 => &mut state.file_output_path,
        2 => &mut state.file_template,
        3..=7 => &mut state.file_cajas[state.focus - 3],
        8 => &mut state.file_reference_phrase,
        9 => &mut state.file_key_phrase,
        _ => &mut state.file_output_path,
    }
}

fn show_file_info(state: &mut TuiState) {
    let path = Path::new(state.file_input_path.trim());
    match livencrypt_lib::load_file_info(path) {
        Ok(info) => {
            state.status = format!(
                "{} | {} bytes | {} hex chars | comprimido: {}",
                info.name, info.size_bytes, info.hex_chars, info.is_compressed
            );
        }
        Err(error) => state.status = format!("No se pudo leer archivo: {}", error),
    }
}

fn toggle_file_mode(state: &mut TuiState) {
    state.file_mode = match state.file_mode {
        FileMode::Encrypt => FileMode::Decrypt,
        FileMode::Decrypt => FileMode::Encrypt,
    };
    refresh_file_output_from_input(state);
    state.status = format!("Modo archivo: {}", state.file_mode.label());
}

fn refresh_file_output_from_input(state: &mut TuiState) {
    let input = PathBuf::from(state.file_input_path.trim());
    if input.as_os_str().is_empty() {
        return;
    }
    state.file_output_path = derive_output_path(&input, state.file_mode)
        .display()
        .to_string();
}

fn start_file_cipher_task(state: &mut TuiState) {
    if state.is_processing {
        state.status = "Ya hay una operacion de archivo en curso.".to_string();
        return;
    }
    let cajas = match parse_boxes(&state.file_cajas) {
        Ok(cajas) => cajas,
        Err(error) => {
            state.status = error;
            return;
        }
    };
    let input = PathBuf::from(state.file_input_path.trim());
    if input.as_os_str().is_empty() {
        state.status = "Indique archivo origen.".to_string();
        return;
    }
    let output = if state.file_output_path.trim().is_empty() {
        derive_output_path(&input, state.file_mode)
    } else {
        PathBuf::from(state.file_output_path.trim())
    };

    let template = state.file_template.clone();
    let reference = if state.file_reference_phrase.trim().is_empty() {
        DEFAULT_FILE_REFERENCE.to_string()
    } else {
        state.file_reference_phrase.clone()
    };
    if reference.trim().chars().count() < 12 {
        state.status = "La referencia de archivo debe tener al menos 12 caracteres.".to_string();
        return;
    }
    let file_secret = state.file_key_phrase.clone();
    if file_secret.trim().chars().count() < 12 {
        state.status = "La clave de archivo debe tener al menos 12 caracteres.".to_string();
        return;
    }
    if file_secret.trim() == reference.trim() {
        state.status =
            "La clave de archivo debe ser distinta de la referencia visible.".to_string();
        return;
    }
    let mode = state.file_mode;
    let progress = Arc::clone(&state.processing_progress);
    let (tx, rx) = mpsc::channel();

    state.processing_progress.store(1, Ordering::Relaxed);
    state.is_processing = true;
    state.file_job_rx = Some(rx);
    state.last_forensic_report = None;
    state.last_forensic_report_path = None;
    state.status = format!("Procesando archivo en modo {}.", mode.label());

    thread::spawn(move || {
        let started = Instant::now();
        progress.store(5, Ordering::Relaxed);
        let operation_result = run_file_operation_quietly(|| match mode {
            FileMode::Encrypt => livencrypt_lib::cipher_file_with_secret(
                &input,
                &output,
                &reference,
                &template,
                cajas,
                &file_secret,
            ),
            FileMode::Decrypt => livencrypt_lib::decipher_file_with_secret(
                &input,
                &output,
                &reference,
                output
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case("txt")),
                &template,
                cajas,
                &file_secret,
            ),
        });
        progress.store(90, Ordering::Relaxed);
        let duration_ms = started.elapsed().as_millis();
        let result = operation_result.and_then(|_| {
            let report = security::forensics::generate_file_report(
                mode.forensic_label(),
                &input,
                &output,
                duration_ms,
            )?;
            Ok(Some(report))
        });
        progress.store(100, Ordering::Relaxed);
        let _ = tx.send(FileJobResult {
            mode,
            output,
            duration_ms,
            result,
        });
    });
}

#[cfg(unix)]
fn run_file_operation_quietly<F>(operation: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    let devnull = fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|error| error.to_string())?;
    let stdout_fd = io::stdout().as_raw_fd();
    let saved_fd = unsafe { libc::dup(stdout_fd) };
    if saved_fd < 0 {
        return operation();
    }
    unsafe {
        libc::dup2(devnull.as_raw_fd(), stdout_fd);
    }
    let result = operation();
    unsafe {
        libc::dup2(saved_fd, stdout_fd);
        libc::close(saved_fd);
    }
    result
}

#[cfg(not(unix))]
fn run_file_operation_quietly<F>(operation: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    operation()
}

fn derive_output_path(input: &Path, mode: FileMode) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let file_name = input
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("archivo");
    match mode {
        FileMode::Encrypt => {
            let stem = input
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("archivo");
            parent.join(format!("{}_cifrado.lvc", stem))
        }
        FileMode::Decrypt => {
            if let Some(base) = file_name.strip_suffix("_cifrado.lvc") {
                parent.join(format!("{}_descifrado.lvc", base))
            } else {
                let stem = input
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .unwrap_or("archivo");
                parent.join(format!("{}_descifrado.txt", stem))
            }
        }
    }
}

fn handle_template_editor_key(state: &mut TuiState, key: KeyEvent) {
    let limit = template_cell_limit(state);
    let cols = template_cols(state) as usize;
    match key.code {
        KeyCode::Esc => state.screen = Screen::Dashboard,
        KeyCode::Tab => state.template_focus = (state.template_focus + 1) % 5,
        KeyCode::BackTab => {
            state.template_focus = if state.template_focus == 0 {
                4
            } else {
                state.template_focus - 1
            }
        }
        KeyCode::Up => {
            if state.template_focus == 0 {
                state.template_selected_index = state.template_selected_index.saturating_sub(1);
                state.load_selected_template();
            } else if state.template_focus == 3 && state.template_cell_index >= cols {
                state.template_cell_index -= cols;
            } else if state.template_focus == 4 {
                state.template_preview_cursor = state.template_preview_cursor.saturating_sub(16);
            }
        }
        KeyCode::Down => {
            if state.template_focus == 0 {
                if state.template_selected_index + 1 < state.templates.len() {
                    state.template_selected_index += 1;
                    state.load_selected_template();
                }
            } else if state.template_focus == 3 && state.template_cell_index + cols < limit {
                state.template_cell_index += cols;
            } else if state.template_focus == 4 {
                let preview_len = template_preview_values(state).len();
                if state.template_preview_cursor + 16 < preview_len {
                    state.template_preview_cursor += 16;
                }
            }
        }
        KeyCode::Left => {
            if state.template_focus == 0 {
                state.language_index = state.language_index.saturating_sub(1);
                state.number_index = state.number_index.saturating_sub(1);
            } else if state.template_focus == 3 {
                state.template_cell_index = state.template_cell_index.saturating_sub(1);
            } else if state.template_focus == 4 {
                state.template_preview_cursor = state.template_preview_cursor.saturating_sub(1);
            }
        }
        KeyCode::Right => {
            if state.template_focus == 0 {
                if state.language_index + 1 < state.language_names.len() {
                    state.language_index += 1;
                }
                if state.number_index + 1 < state.number_names.len() {
                    state.number_index += 1;
                }
            } else if state.template_focus == 3 && state.template_cell_index + 1 < limit {
                state.template_cell_index += 1;
            } else if state.template_focus == 4 {
                let preview_len = template_preview_values(state).len();
                if state.template_preview_cursor + 1 < preview_len {
                    state.template_preview_cursor += 1;
                }
            }
        }
        KeyCode::Enter => {
            if state.template_focus == 0
                && state.template_selected_index + 1 < state.templates.len()
            {
                state.template_selected_index += 1;
                state.load_selected_template();
            } else if state.template_focus == 4 {
                if let Some(value) = template_preview_values(state)
                    .get(state.template_preview_cursor)
                    .cloned()
                {
                    insert_template_value(state, value);
                }
            }
        }
        KeyCode::Backspace => {
            if state.template_focus == 0 {
                state.template_name.pop();
            } else if state.template_focus == 1 {
                state.template_rows.pop();
                normalize_template_cell_index(state);
            } else if state.template_focus == 2 {
                state.template_cols.pop();
                normalize_template_cell_index(state);
            } else {
                remove_template_cell(state);
            }
        }
        KeyCode::Delete => {
            if state.template_focus == 1 {
                state.template_rows.zeroize();
                state.template_rows.clear();
            } else if state.template_focus == 2 {
                state.template_cols.zeroize();
                state.template_cols.clear();
            } else {
                remove_template_cell(state);
            }
        }
        KeyCode::Char('G') => save_template_from_state(state),
        KeyCode::Char('I') => insert_new_template_from_state(state),
        KeyCode::Char('D') => delete_template_from_state(state),
        KeyCode::Char('L') => add_selected_language(state),
        KeyCode::Char('N') => add_selected_numbers(state),
        KeyCode::Char('A') => add_selected_language(state),
        KeyCode::Char('E') => remove_template_cell(state),
        KeyCode::Char('H') => fill_missing_hex_chars(state),
        KeyCode::Char('X') => {
            state.template_chars.clear();
            state.status = "Caracteres de plantilla limpiados.".to_string();
        }
        KeyCode::Char(value) => {
            if state.template_focus == 0 {
                state.template_name.push(value);
            } else if state.template_focus == 1 {
                if value.is_ascii_digit() && state.template_rows.len() < 2 {
                    state.template_rows.push(value);
                    normalize_template_cell_index(state);
                }
            } else if state.template_focus == 2 {
                if value.is_ascii_digit() && state.template_cols.len() < 2 {
                    state.template_cols.push(value);
                    normalize_template_cell_index(state);
                }
            } else if state.template_focus == 3 && !value.is_control() {
                insert_template_value(state, value.to_string());
            }
        }
        _ => {}
    }
}

fn save_template_from_state(state: &mut TuiState) {
    save_template_from_state_inner(state, false);
}

fn insert_new_template_from_state(state: &mut TuiState) {
    save_template_from_state_inner(state, true);
}

fn save_template_from_state_inner(state: &mut TuiState, reject_existing: bool) {
    let name = state.template_name.trim().to_string();
    if name.is_empty() {
        state.status = "Nombre de plantilla vacio.".to_string();
        return;
    }
    if reject_existing && state.templates.iter().any(|existing| existing == &name) {
        state.status = format!(
            "La plantilla '{}' ya existe. Cambie el nombre antes de insertarla.",
            name
        );
        return;
    }
    let rows = template_rows(state);
    let cols = template_cols(state);
    let limit = template_cell_limit(state);
    let count = template_char_count(&state.template_chars);
    if count > limit {
        state.status = format!(
            "Plantilla no guardada. Caracteres {}/{} supera la tabla.",
            count, limit
        );
        return;
    }
    let (_, missing) = check_hex_coverage(&state.template_chars);
    if !missing.is_empty() {
        state.status = format!(
            "Plantilla no guardada. Faltan HEX: {}. Use H para rellenar esenciales.",
            missing.into_iter().collect::<String>()
        );
        return;
    }
    let mut chars = state
        .template_chars
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<Vec<_>>();
    while chars.len() < limit {
        chars.push(String::new());
    }

    let data = TemplateData { rows, cols, chars };
    match livencrypt_lib::save_template(name.clone(), data) {
        Ok(()) => {
            state.status = if reject_existing {
                format!("Plantilla '{}' insertada.", name)
            } else {
                format!("Plantilla '{}' guardada.", name)
            };
            state.refresh_templates_count();
            if let Some(index) = state.templates.iter().position(|value| value == &name) {
                state.template_selected_index = index;
            }
            state.add_log("Plantilla guardada.");
        }
        Err(error) => state.status = format!("No se pudo guardar plantilla: {}", error),
    }
}

fn check_hex_coverage(chars: &[String]) -> (usize, Vec<char>) {
    let required = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let mut missing = Vec::new();
    let mut count = 0;
    for value in required {
        if chars.iter().any(|item| item == &value.to_string()) {
            count += 1;
        } else {
            missing.push(value);
        }
    }
    (count, missing)
}

fn list_window_start(selected: usize, total: usize, visible: usize) -> usize {
    if total <= visible {
        return 0;
    }
    let half = visible / 2;
    selected
        .saturating_sub(half)
        .min(total.saturating_sub(visible))
}

fn table_window_start(state: &TuiState, visible_rows: usize) -> usize {
    let cols = template_cols(state).max(1) as usize;
    let selected_row = state.template_cell_index / cols;
    let total_rows = template_cell_limit(state).div_ceil(cols);
    list_window_start(selected_row, total_rows, visible_rows)
}

fn preview_window_start(state: &TuiState, visible_rows: usize) -> usize {
    let selected_row = state.template_preview_cursor / 16;
    let total_rows = template_preview_values(state).len().div_ceil(16);
    list_window_start(selected_row, total_rows, visible_rows)
}

fn delete_template_from_state(state: &mut TuiState) {
    let name = state.template_name.trim().to_string();
    if name.is_empty() {
        state.status = "Nombre de plantilla vacio.".to_string();
        return;
    }
    match livencrypt_lib::delete_template(name.clone()) {
        Ok(()) => {
            state.status = format!("Plantilla '{}' eliminada.", name);
            state.refresh_templates_count();
            state.template_selected_index = 0;
            state.load_selected_template();
        }
        Err(error) => state.status = format!("No se pudo eliminar plantilla: {}", error),
    }
}

fn remove_template_cell(state: &mut TuiState) {
    if state.template_cell_index < state.template_chars.len() {
        let mut value = state.template_chars.remove(state.template_cell_index);
        value.zeroize();
        normalize_template_cell_index(state);
        state.status = format!("Celda {} limpiada.", state.template_cell_index + 1);
    }
}

fn fill_missing_hex_chars(state: &mut TuiState) {
    let (_, missing) = check_hex_coverage(&state.template_chars);
    if missing.is_empty() {
        state.status = "HEX esencial ya completo.".to_string();
        return;
    }
    let limit = template_cell_limit(state);
    if template_char_count(&state.template_chars) >= limit {
        let message = "Tabla ya completada; no se ha rellenado HEX esencial.".to_string();
        state.status = message.clone();
        state.add_log(message);
        return;
    }
    let added = append_unique_until_limit(
        &mut state.template_chars,
        missing.into_iter().map(|value| value.to_string()).collect(),
        limit,
    );
    state.status = format!("HEX esencial rellenado: {} caracteres insertados.", added);
}

fn insert_template_value(state: &mut TuiState, value: String) {
    let limit = template_cell_limit(state);
    if template_char_count(&state.template_chars) >= limit {
        let message = format!(
            "Tabla ya completada; no se ha insertado el caracter [{}].",
            value
        );
        state.status = message.clone();
        state.add_log(message);
        return;
    }
    if state
        .template_chars
        .iter()
        .any(|existing| existing == &value)
    {
        state.status = format!("Caracter ya insertado en la tabla: {}", value);
        return;
    }
    if state.template_focus == 3 {
        if state.template_cell_index < state.template_chars.len() {
            state.template_chars[state.template_cell_index] = value;
        } else {
            state.template_chars.push(value);
        }
        if state.template_cell_index + 1 < limit {
            state.template_cell_index += 1;
        }
    } else {
        append_template_value(state, value);
    }
}

fn append_template_value(state: &mut TuiState, value: String) {
    if !state
        .template_chars
        .iter()
        .any(|existing| existing == &value)
    {
        state.template_chars.push(value);
    }
}

fn template_preview_values(state: &TuiState) -> Vec<String> {
    let language_name = state
        .language_names
        .get(state.language_index)
        .cloned()
        .unwrap_or_default();
    let number_name = state
        .number_names
        .get(state.number_index)
        .cloned()
        .unwrap_or_default();
    let mut values = livencrypt_lib::language_characters()
        .remove(&language_name)
        .unwrap_or_default();
    append_unique_values(
        &mut values,
        livencrypt_lib::language_numbers_signs()
            .remove(&number_name)
            .unwrap_or_default(),
    );
    values
}

fn add_selected_language(state: &mut TuiState) {
    let Some(name) = state.language_names.get(state.language_index).cloned() else {
        return;
    };
    if let Some(chars) = livencrypt_lib::language_characters().remove(&name) {
        let limit = template_cell_limit(state);
        let added = append_unique_until_limit(&mut state.template_chars, chars, limit);
        state.status = if added == 0 {
            if template_char_count(&state.template_chars) >= limit {
                let message = format!(
                    "Tabla completa. No se añaden mas caracteres del idioma '{}'.",
                    name
                );
                state.add_log(message.clone());
                message
            } else {
                format!(
                    "Idioma '{}' ya estaba insertado. No se repiten caracteres.",
                    name
                )
            }
        } else {
            format!("Idioma '{}' agregado: {} caracteres nuevos.", name, added)
        };
    }
}

fn add_selected_numbers(state: &mut TuiState) {
    let Some(name) = state.number_names.get(state.number_index).cloned() else {
        return;
    };
    if let Some(chars) = livencrypt_lib::language_numbers_signs().remove(&name) {
        let limit = template_cell_limit(state);
        let added = append_unique_until_limit(&mut state.template_chars, chars, limit);
        state.status = if added == 0 {
            if template_char_count(&state.template_chars) >= limit {
                let message = format!(
                    "Tabla completa. No se añaden mas numeros/signos '{}'.",
                    name
                );
                state.add_log(message.clone());
                message
            } else {
                format!(
                    "Numeros/signos '{}' ya estaban insertados. No se repiten caracteres.",
                    name
                )
            }
        } else {
            format!("Numeros/signos '{}' agregados: {} nuevos.", name, added)
        };
    }
}

fn append_unique_values(target: &mut Vec<String>, values: Vec<String>) -> usize {
    let mut added = 0;
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
            added += 1;
        }
    }
    added
}

fn append_unique_until_limit(target: &mut Vec<String>, values: Vec<String>, limit: usize) -> usize {
    let mut added = 0;
    for value in values {
        if template_char_count(target) >= limit {
            break;
        }
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
            added += 1;
        }
    }
    added
}

fn handle_settings_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => state.screen = Screen::Dashboard,
        KeyCode::Char('N') => {
            state.screen = Screen::NodesManager;
            reload_nodes_manager(state);
        }
        KeyCode::Tab => state.settings_focus = (state.settings_focus + 1) % 10,
        KeyCode::BackTab => {
            state.settings_focus = if state.settings_focus == 0 {
                9
            } else {
                state.settings_focus - 1
            };
        }
        KeyCode::Backspace => active_settings_field_mut(state)
            .pop()
            .map(|_| ())
            .unwrap_or(()),
        KeyCode::Char('T') => {
            state.inactivity_enabled = !state.inactivity_enabled;
            state.status = format!(
                "Bloqueo por inactividad: {}",
                if state.inactivity_enabled {
                    "ON"
                } else {
                    "OFF"
                }
            );
        }
        KeyCode::Char('+') => {
            state.inactivity_timeout_seconds =
                (state.inactivity_timeout_seconds + 30).clamp(30, 3600);
        }
        KeyCode::Char('-') => {
            state.inactivity_timeout_seconds = state
                .inactivity_timeout_seconds
                .saturating_sub(30)
                .clamp(30, 3600);
        }
        KeyCode::Char('S') => save_network_profile_setting(state),
        KeyCode::Char('B') => enable_boot_shield_from_settings(state),
        KeyCode::Char('O') => disable_boot_shield_from_settings(state),
        KeyCode::Char('P') => enable_apparmor_from_settings(state),
        KeyCode::Char('U') => disable_apparmor_from_settings(state),
        KeyCode::Char(value) => {
            if state.settings_focus <= 4 {
                if !push_box_char(&mut state.settings_boot_cajas[state.settings_focus], value) {
                    state.status = "Caja fuera de rango permitido (-999..999).".to_string();
                }
            } else {
                active_settings_field_mut(state).push(value);
            }
        }
        _ => {}
    }
}

fn active_settings_field_mut(state: &mut TuiState) -> &mut String {
    match state.settings_focus {
        0..=4 => &mut state.settings_boot_cajas[state.settings_focus],
        5 => &mut state.settings_boot_frase,
        6 => &mut state.settings_boot_template,
        7 => &mut state.settings_network_profile,
        8 => &mut state.settings_network_confirmation,
        _ => &mut state.settings_network_confirmation,
    }
}

fn save_network_profile_setting(state: &mut TuiState) {
    let confirmation = if state.settings_network_confirmation.trim().is_empty() {
        None
    } else {
        Some(state.settings_network_confirmation.clone())
    };
    match security::set_network_profile(state.settings_network_profile.clone(), confirmation) {
        Ok(profile) => {
            state.settings_network_profile = profile;
            state.status =
                "Perfil de red guardado. No se ha ejecutado ninguna funcion de red.".to_string();
        }
        Err(error) => state.status = format!("No se pudo guardar perfil de red: {}", error),
    }
}

fn enable_apparmor_from_settings(state: &mut TuiState) {
    match security::apparmor::enable_apparmor_profile() {
        Ok(status) => {
            state.status = format!(
                "AppArmor activado: {} ({})",
                status.profile_path, status.message
            );
            state.add_log("Perfil AppArmor activado desde Configuracion.");
        }
        Err(error) => state.status = format!("No se pudo activar AppArmor: {}", error),
    }
}

fn disable_apparmor_from_settings(state: &mut TuiState) {
    match security::apparmor::disable_apparmor_profile() {
        Ok(status) => {
            state.status = format!("AppArmor desactivado: {}", status.message);
            state.add_log("Perfil AppArmor desactivado desde Configuracion.");
        }
        Err(error) => state.status = format!("No se pudo desactivar AppArmor: {}", error),
    }
}

fn enable_boot_shield_from_settings(state: &mut TuiState) {
    let cajas = match parse_boxes(&state.settings_boot_cajas) {
        Ok(cajas) => cajas,
        Err(error) => {
            state.status = error;
            return;
        }
    };
    let mut frase = String::new();
    std::mem::swap(&mut frase, &mut state.settings_boot_frase);
    if frase.trim().is_empty() {
        state.status = "La frase Boot Shield no puede estar vacia.".to_string();
        return;
    }
    match security::boot_shield_enable(
        cajas,
        frase,
        Some(state.settings_boot_template.clone()),
        None,
        None,
    ) {
        Ok(_) => {
            state.status = "Boot Shield creado. Cierre y reinicie Livencrypt.".to_string();
            state.add_log("Boot Shield activado desde TUI.");
            state.refresh_templates_count();
        }
        Err(error) => state.status = format!("No se pudo activar Boot Shield: {}", error),
    }
}

fn disable_boot_shield_from_settings(state: &mut TuiState) {
    let cajas = match parse_boxes(&state.settings_boot_cajas) {
        Ok(cajas) => cajas,
        Err(error) => {
            state.status = error;
            return;
        }
    };
    let mut frase = String::new();
    std::mem::swap(&mut frase, &mut state.settings_boot_frase);
    match security::boot_shield_disable(cajas, frase, None, None) {
        Ok(_) => {
            state.status = "Boot Shield desactivado y plantillas exportadas.".to_string();
            state.refresh_templates_count();
        }
        Err(error) => state.status = format!("No se pudo desactivar Boot Shield: {}", error),
    }
}

fn handle_system_monitor_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::Dashboard,
        KeyCode::Char('r') => {
            state.refresh_templates_count();
            state.status = "Monitor actualizado.".to_string();
        }
        _ => {}
    }
}

fn handle_firmware_staging_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::Dashboard,
        KeyCode::Char('v') => match security::updates::verify_pending_update() {
            Ok(Some(true)) => state.status = "Update staging verificado correctamente.".to_string(),
            Ok(Some(false)) => state.status = "Update staging no verifica firma/hash.".to_string(),
            Ok(None) => state.status = "No hay update staging pendiente.".to_string(),
            Err(error) => state.status = format!("Error verificando update: {}", error),
        },
        KeyCode::Char('h') => match security::vault::finalize_update_handover() {
            Ok(()) => {
                state.status = "Handover de update aplicado en vault.".to_string();
                state.refresh_templates_count();
            }
            Err(error) => state.status = format!("Handover no aplicado: {}", error),
        },
        KeyCode::Char('c') => match security::updates::clear_staging() {
            Ok(()) => state.status = "Staging limpiado con borrado seguro.".to_string(),
            Err(error) => state.status = format!("No se pudo limpiar staging: {}", error),
        },
        _ => {}
    }
}

fn handle_recovery_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            state.recovery_error.clear();
            state.screen = Screen::Dashboard;
        }
        KeyCode::Backspace => {
            state.recovery_path.pop();
        }
        KeyCode::Enter => {
            let path = Path::new(&state.recovery_path);
            match security::recovery::apply_recovery_file(path) {
                Ok(()) => {
                    state.recovery_error.clear();
                    state.status = "Recovery Ed25519 aplicado al anclaje del vault.".to_string();
                    state.refresh_integrity();
                    state.screen = Screen::Dashboard;
                }
                Err(error) => state.recovery_error = error,
            }
        }
        KeyCode::Char(value) => {
            state.recovery_path.push(value);
        }
        _ => {}
    }
}

fn draw_ui(frame: &mut Frame<'_>, state: &TuiState) {
    let area = frame.size();
    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        draw_terminal_size_warning(frame, area);
        return;
    }
    let glyph = match state.integrity {
        security::vault::IntegrityStatus::Valid => ".",
        _ => "·",
    };
    let block = Block::default()
        .title(format!(" Livencrypt 2.0 TUI{} ", glyph))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    frame.render_widget(block, area);

    let inner = centered_area(area, 94, 88);
    frame.render_widget(Clear, inner);

    match state.screen {
        Screen::Unlock => draw_unlock(frame, inner, state),
        Screen::Dashboard => draw_dashboard(frame, inner, state),
        Screen::TextCipher => draw_text_cipher(frame, inner, state),
        Screen::FileCipher => draw_file_cipher(frame, inner, state),
        Screen::TemplateEditor => draw_template_editor(frame, inner, state),
        Screen::Settings => draw_settings(frame, inner, state),
        Screen::SystemMonitor => draw_system_monitor(frame, inner, state),
        Screen::AuditMonitor => draw_audit_monitor(frame, inner),
        Screen::FirmwareStaging => draw_firmware_staging(frame, inner, state),
        Screen::SandboxManager => draw_sandbox_manager(frame, inner),
        Screen::RecoveryMode => draw_recovery_mode(frame, inner, state),
        Screen::InstallProfile => draw_install_profile(frame, inner),
        Screen::WalletGateway => draw_wallet_gateway(frame, inner, state),
        Screen::NodesManager => draw_nodes_manager(frame, inner, state),
    }

    if state.show_file_browser {
        draw_file_browser(frame, inner, state);
    }
    if state.show_matrix_config {
        draw_matrix_config_modal(frame, inner, state);
    }
    if state.is_processing {
        draw_progress_modal(frame, inner, state);
    } else if state.screen == Screen::FileCipher {
        if let Some(report) = &state.last_forensic_report {
            draw_forensic_summary(
                frame,
                inner,
                report,
                state.last_forensic_report_path.as_ref(),
            );
        }
    }
}

fn draw_terminal_size_warning(frame: &mut Frame<'_>, area: Rect) {
    let popup = centered_area(area, 70, 34);
    frame.render_widget(Clear, popup);
    let warning = Paragraph::new(vec![
        Line::from(Span::styled(
            "ERROR DE DIMENSIONES",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "Minimo: {}x{}",
            MIN_TERMINAL_WIDTH, MIN_TERMINAL_HEIGHT
        )),
        Line::from(format!("Actual: {}x{}", area.width, area.height)),
        Line::from(""),
        Line::from("Expanda la ventana de terminal para operar."),
    ])
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .title(" Livencrypt 2.0 TUI ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red)),
    );
    frame.render_widget(warning, popup);
}

fn draw_file_browser(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let popup = centered_area(area, 82, 72);
    frame.render_widget(Clear, popup);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(3),
        ])
        .split(popup);

    let target = match state.file_browser_target {
        FileBrowserTarget::Input => "origen",
        FileBrowserTarget::Output => "destino",
        FileBrowserTarget::TextExport => "exportacion texto",
    };
    let prompt = if matches!(state.file_browser_target, FileBrowserTarget::TextExport)
        && state.file_browser.name_mode
    {
        format!(
            "Nombre: {}_ | destino: {} | Enter exporta en directorio actual",
            state.file_browser.name_input, target
        )
    } else if matches!(state.file_browser_target, FileBrowserTarget::TextExport) {
        format!(
            "Buscar: {}_ | destino: {} | Tab cambia a Nombre",
            state.file_browser.search_query, target
        )
    } else {
        format!(
            "Buscar: {}_ | destino: {} | Backspace sube si busqueda vacia",
            state.file_browser.search_query, target
        )
    };
    let search = Paragraph::new(prompt)
        .block(
            Block::default()
                .title(" Explorador interno ")
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(search, chunks[0]);

    let rows = chunks[1].height.saturating_sub(2).max(1) as usize;
    let col_width = (chunks[1].width.saturating_sub(2).max(6) as usize / 3).max(6);
    let mut lines = Vec::new();
    for row in 0..rows {
        let mut spans = Vec::new();
        for col in 0..3 {
            let index = state
                .file_browser
                .vertical_offset
                .saturating_mul(3)
                .saturating_add(row.saturating_mul(3))
                .saturating_add(col);
            let Some(path) = state.file_browser.filtered_items.get(index) else {
                spans.push(Span::raw(" ".repeat(col_width)));
                continue;
            };
            let icon = if path.is_dir() { "D" } else { "F" };
            let mut name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .chars()
                .skip(state.file_browser.horizontal_offset)
                .collect::<String>();
            let max_name = col_width.saturating_sub(5).max(1);
            if name.chars().count() > max_name {
                name = name.chars().take(max_name).collect::<String>();
            }
            let text = format!("[{}] {:width$}", icon, name, width = max_name);
            let style = if index == state.file_browser.selected_index {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if path.is_dir() {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            spans.push(Span::styled(text, style));
        }
        lines.push(Line::from(spans));
    }
    let list = Paragraph::new(lines)
        .block(
            Block::default()
                .title(format!(
                    " Directorio: {} | < > desplazan texto | offset {} ",
                    state.file_browser.current_dir.display(),
                    state.file_browser.horizontal_offset
                ))
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(list, chunks[1]);

    let footer_text = if matches!(state.file_browser_target, FileBrowserTarget::TextExport) {
        "Flechas/clic seleccionan | Tab Buscar/Nombre | Enter abre/elige o exporta | < > scroll | Esc cancelar"
    } else {
        "Flechas/clic seleccionan | Enter abre/elige | < > scroll horizontal | Esc cancelar"
    };
    let footer = Paragraph::new(footer_text)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, chunks[2]);
}

fn draw_progress_modal(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let pct = state.processing_progress.load(Ordering::Relaxed).min(100) as u16;
    let popup = centered_area(area, 62, 14);
    frame.render_widget(Clear, popup);
    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(" Procesando criptografia posicional ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .gauge_style(
            Style::default()
                .fg(Color::Magenta)
                .bg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .percent(pct);
    frame.render_widget(gauge, popup);
}

fn draw_matrix_config_modal(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let popup = centered_area(area, 56, 32);
    frame.render_widget(Clear, popup);
    let length_style = if state.matrix_focus == 0 {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    let direction_style = if state.matrix_focus == 1 {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    let symbols_style = if state.matrix_focus == 2 {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    let symbols = if state.text_control_symbols.is_empty() {
        "INACTIVOS"
    } else {
        "ACTIVOS"
    };
    let body = vec![
        Line::from(Span::styled(
            "CONFIGURACION MATRIX LOCK F2",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Longitud clave: ", length_style),
            Span::raw(format!("{} (2-25)", state.text_password_length)),
        ]),
        Line::from(vec![
            Span::styled("Direccion: ", direction_style),
            Span::raw(if state.text_password_direction == "after" {
                "DESPUES"
            } else {
                "ANTES"
            }),
        ]),
        Line::from(vec![
            Span::styled("Clave secreta: ", symbols_style),
            Span::raw(symbols),
        ]),
        Line::from(""),
        Line::from("Tab cambia campo | Flechas ajustan | Enter/Esc confirma"),
    ];
    let panel = Paragraph::new(body).alignment(Alignment::Center).block(
        Block::default()
            .title(" Matrix Lock ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta)),
    );
    frame.render_widget(panel, popup);
}

fn short_hash(value: &str) -> String {
    value.chars().take(16).collect::<String>()
}

fn draw_forensic_summary(
    frame: &mut Frame<'_>,
    area: Rect,
    report: &security::forensics::ForensicReport,
    report_path: Option<&PathBuf>,
) {
    let popup = centered_area(area, 74, 44);
    frame.render_widget(Clear, popup);
    let report_path = report_path
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "temporal en memoria; no se crea archivo _report".to_string());
    let info = vec![
        Line::from(vec![
            Span::styled("OPERACION: ", Style::default().fg(Color::Cyan)),
            Span::raw(report.operation.clone()),
        ]),
        Line::from(format!("TIMESTAMP UNIX: {}", report.timestamp_unix)),
        Line::from(format!("DURACION: {} ms", report.duration_ms)),
        Line::from(""),
        Line::from(format!(
            "ORIGEN SHA256: {}...",
            short_hash(&report.source_hash)
        )),
        Line::from(format!(
            "RESULT SHA256: {}...",
            short_hash(&report.result_hash)
        )),
        Line::from(format!("REPORTE: {}", report_path)),
        Line::from(""),
        Line::from("Firma Ed25519 local generada y auditoria encadenada actualizada."),
        Line::from("Esc/X cierra solo este reporte"),
    ];
    let panel = Paragraph::new(info)
        .block(
            Block::default()
                .title(" Reporte forense generado ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(panel, popup);
}

fn draw_unlock(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let hardening = security::process_hardening::process_hardening_status();
    let has_warnings = !hardening.warnings.is_empty();
    let constraints = if has_warnings {
        vec![
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(4),
        ]
    } else {
        vec![
            Constraint::Length(4),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(4),
        ]
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let header = Paragraph::new(vec![
        Line::from(Span::styled(
            "LIVENCRYPT BOOT SHIELD",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("Acceso por descifrado: 5 cajas + frase exacta."),
        Line::from("Tab/clic cambia campo. Enter/F10 desbloquea. Esc sale limpiando campos."),
    ])
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let mut chunk_index = 1;
    if has_warnings {
        let warning = Paragraph::new(format!(
            "SEGURIDAD DEGRADADA: {} aviso(s). Revise Monitor con 'm' tras desbloquear.",
            hardening.warnings.len()
        ))
        .alignment(Alignment::Center)
        .style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
        frame.render_widget(warning, chunks[chunk_index]);
        chunk_index += 1;
    }

    let mut fields = Vec::new();
    for index in 0..5 {
        let marker = if state.focus == index { ">" } else { " " };
        fields.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(
                format!(" CAJA {}: ", index + 1),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(&state.cajas[index]),
        ]));
    }
    let phrase_marker = if state.focus == 5 { ">" } else { " " };
    fields.push(Line::from(vec![
        Span::raw(phrase_marker),
        Span::styled(" FRASE: ", Style::default().fg(Color::Cyan)),
        Span::raw("*".repeat(state.frase.chars().count())),
    ]));

    let form = Paragraph::new(fields)
        .block(
            Block::default()
                .title(" Credenciales ")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(form, chunks[chunk_index]);
    chunk_index += 1;

    draw_secure_keyboard(frame, chunks[chunk_index], state);
    chunk_index += 1;

    let status = Paragraph::new(state.status.as_str())
        .style(Style::default().fg(Color::White))
        .block(Block::default().title(" Estado ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(status, chunks[chunk_index]);
}

fn draw_secure_keyboard(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    let help = Paragraph::new(
        "Clic inserta caracter | Flechas navegan | Espacio inserta | Enter/F10 desbloquea",
    )
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(help, chunks[0]);

    let rows: Vec<Line> = state
        .teclado_shuffled
        .chunks(10)
        .enumerate()
        .map(|(row, chunk)| {
            let spans = chunk
                .iter()
                .enumerate()
                .map(|(col, value)| {
                    let index = row * 10 + col;
                    let style = if index == state.cursor_teclado {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Cyan)
                    };
                    Span::styled(format!(" {} ", value), style)
                })
                .collect::<Vec<_>>();
            Line::from(spans)
        })
        .collect();

    let keyboard = Paragraph::new(rows).alignment(Alignment::Center).block(
        Block::default()
            .title(" Teclado blindado barajado ")
            .borders(Borders::ALL),
    );
    frame.render_widget(keyboard, chunks[1]);
}

fn draw_dashboard(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(14),
            Constraint::Min(4),
        ])
        .split(area);

    let status = security::process_hardening::process_hardening_status();
    let hardening = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("CORE DUMPS: ", Style::default().fg(Color::Cyan)),
            Span::raw(if status.core_dumps_disabled {
                "OFF"
            } else {
                "ON"
            }),
        ]),
        Line::from(vec![
            Span::styled("DUMPABLE: ", Style::default().fg(Color::Cyan)),
            Span::raw(if status.dumpable_disabled {
                "OFF"
            } else {
                "ON"
            }),
        ]),
        Line::from(vec![
            Span::styled("MLOCKALL: ", Style::default().fg(Color::Cyan)),
            Span::raw(if status.mlockall_applied {
                "OK"
            } else {
                "FALLO"
            }),
        ]),
        Line::from(vec![
            Span::styled("INTEGRIDAD: ", Style::default().fg(Color::Cyan)),
            Span::raw(match status.binary_integrity_ok {
                Some(true) => "OK",
                Some(false) => "FALLO",
                None => "SIN HASH ESPERADO",
            }),
        ]),
    ])
    .block(Block::default().title(" Hardening ").borders(Borders::ALL));
    frame.render_widget(hardening, chunks[0]);

    let items = vec![
        ListItem::new(format!("Plantillas cargadas: {}", state.templates_count)),
        ListItem::new(format!(
            "Boot Shield: {}",
            security::vault::boot_shield_status()
                .map(|value| value.state)
                .unwrap_or_else(|_| "desconocido".to_string())
        )),
        ListItem::new(format!(
            "Pasarela Web3: {} | firmas hoy: {} | volumen: {:.8} unidades",
            gateway_state_label(&state.cached_gateway_state),
            state.cached_tx_count,
            state.cached_volume_units
        )),
        ListItem::new("w = pasarela Web3 / custodia"),
        ListItem::new("t = cifrar texto"),
        ListItem::new("f = cifrar archivo"),
        ListItem::new("e = editor de plantillas"),
        ListItem::new("c = configuracion del sistema"),
        ListItem::new("m = monitor de sistema"),
        ListItem::new("a = auditoria detallada"),
        ListItem::new("u = staging/updates firmados"),
        ListItem::new("s = sandbox expu"),
        ListItem::new("r = recovery Ed25519"),
        ListItem::new("p = perfil instalado"),
        ListItem::new("l = bloquear sesion"),
        ListItem::new("q / Esc = cerrar limpiando sesion"),
    ];
    let list = List::new(items).block(Block::default().title(" Dashboard ").borders(Borders::ALL));
    frame.render_widget(list, chunks[1]);

    draw_log_box(frame, chunks[2], state);
}

fn qr_lines(data: &str) -> Vec<Line<'static>> {
    let code = match qrcode::QrCode::new(data.as_bytes()) {
        Ok(code) => code,
        Err(_) => return vec![Line::from("QR no disponible para este endpoint")],
    };
    let image = code
        .render::<char>()
        .quiet_zone(false)
        .dark_color('#')
        .light_color(' ')
        .build();

    let rows: Vec<&str> = image.lines().collect();
    let mut lines = Vec::new();
    let mut y = 0;
    while y < rows.len() {
        let top = rows[y];
        let bottom = if y + 1 < rows.len() {
            Some(rows[y + 1])
        } else {
            None
        };
        let mut text = String::new();
        for (x, top_char) in top.chars().enumerate() {
            let bottom_char = bottom
                .and_then(|row| row.chars().nth(x))
                .unwrap_or(' ');
            let block = match (top_char == '#', bottom_char == '#') {
                (true, true) => '\u{2588}',
                (true, false) => '\u{2580}',
                (false, true) => '\u{2584}',
                (false, false) => ' ',
            };
            text.push(block);
        }
        lines.push(Line::from(text));
        y += 2;
    }
    lines
}

fn draw_nodes_manager(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

    let header = Paragraph::new("GESTION DE INFRAESTRUCTURA DE NODOS")
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
    frame.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[1]);

    let items: Vec<ListItem> = if state.nodes_chains.is_empty() {
        vec![ListItem::new("Sin cadenas registradas en nodes.toml")]
    } else {
        state
            .nodes_chains
            .iter()
            .enumerate()
            .map(|(idx, name)| {
                let marker = if idx == state.nodes_selected { ">" } else { " " };
                ListItem::new(format!("{} {}", marker, name))
            })
            .collect()
    };
    let list = List::new(items).block(
        Block::default()
            .title(" Cadenas registradas ")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, body[0]);

    let mut detail: Vec<Line> = Vec::new();
    if let Some(chain) = state.nodes_chains.get(state.nodes_selected) {
        let endpoints = state.nodes.endpoints(chain);
        let active = state.nodes.active_index(chain);
        detail.push(Line::from(Span::styled(
            format!("Cadena: {}", chain),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        detail.push(Line::from(""));
        for (idx, endpoint) in endpoints.iter().enumerate() {
            let marker = if idx == active { "[x]" } else { "[ ]" };
            let role = if idx == 0 { "principal" } else { "respaldo" };
            detail.push(Line::from(format!("{} {} ({})", marker, endpoint, role)));
        }
        detail.push(Line::from(""));
        if state.nodes_editing {
            detail.push(Line::from(Span::styled(
                format!("Editando endpoint: {}", state.nodes_edit_buffer),
                Style::default().fg(Color::Green),
            )));
        } else if let Some(active_endpoint) = state.nodes.current_endpoint(chain) {
            detail.push(Line::from("QR del endpoint activo (escanear offline):"));
            detail.extend(qr_lines(active_endpoint));
        }
    } else {
        detail.push(Line::from("Pulse N en Ajustes para gestionar los nodos."));
    }

    let detail_panel = Paragraph::new(detail)
        .block(
            Block::default()
                .title(" Detalle del nodo ")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(detail_panel, body[1]);

    let footer = Paragraph::new(
        "Flechas navegan | Espacio cambia nodo activo | E edita | G guarda | R recarga | Ctrl+C copia | Esc vuelve",
    )
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(footer, chunks[2]);
}

fn draw_wallet_gateway(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

    let (status_text, status_style) = match &state.cached_gateway_state {
        GatewaySecurityState::Operational => (
            "OPERATIVA - CANAL SEGURO ACTIVO".to_string(),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        GatewaySecurityState::Frozen { reason, .. } => (
            format!("CONGELADA - {}", reason),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        GatewaySecurityState::HardLocked => (
            "BLOQUEO PERIMETRAL - REINICIO LOCAL REQUERIDO".to_string(),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    };

    let header = Paragraph::new(Line::from(vec![
        Span::raw(" PASARELA WEB3 SECURE GATEWAY [ "),
        Span::styled(status_text, status_style),
        Span::raw(" ]"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(header, chunks[0]);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(chunks[1]);

    let field_style = |idx: usize| {
        if state.gateway_focused_field == idx {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        }
    };

    let left = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("Transacciones hoy: "),
            Span::styled(
                state.cached_tx_count.to_string(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("Volumen diario consumido: "),
            Span::styled(
                format!("{:.8} unidades", state.cached_volume_units),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Configuracion de limites",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(vec![
            Span::styled("[1] Limite diario Tx: ", field_style(0)),
            Span::raw(&state.input_max_tx),
        ]),
        Line::from(vec![
            Span::styled("[2] Techo diario unidades: ", field_style(1)),
            Span::raw(&state.input_max_volume),
        ]),
        Line::from(vec![
            Span::styled("[3] Nuevo DEX ID: ", field_style(2)),
            Span::raw(&state.input_new_dex_id),
        ]),
        Line::from(vec![
            Span::styled("[4] Nuevo CEX ID: ", field_style(3)),
            Span::raw(&state.input_new_cex_id),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            format!("Estado: {}", state.system_notification),
            Style::default().fg(Color::Magenta),
        )),
    ])
    .block(
        Block::default()
            .title(" Parametros de Firewall ")
            .borders(Borders::ALL),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(left, body_chunks[0]);

    let list_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body_chunks[1]);

    let dex_items = gateway_list_items(&state.allowed_dex_contracts, "Sin contratos DEX.");
    let dex_list = List::new(dex_items).block(
        Block::default()
            .title(" Contratos DEX en lista blanca ")
            .borders(Borders::ALL),
    );
    frame.render_widget(dex_list, list_chunks[0]);

    let cex_items = gateway_list_items(&state.allowed_cex_destinations, "Sin destinos CEX.");
    let cex_list = List::new(cex_items).block(
        Block::default()
            .title(" Destinos CEX en lista blanca ")
            .borders(Borders::ALL),
    );
    frame.render_widget(cex_list, list_chunks[1]);

    let footer = Paragraph::new(
        "Tab/clic navega | Enter confirma | R rearma disyuntor | Esc vuelve al dashboard",
    )
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(footer, chunks[2]);

    if state.show_breaker_reset {
        draw_wallet_gateway_reset_modal(frame, area, state);
    }
}

fn gateway_list_items<'a>(items: &'a [String], empty: &'a str) -> Vec<ListItem<'a>> {
    if items.is_empty() {
        return vec![ListItem::new(empty)];
    }
    items
        .iter()
        .map(|id| ListItem::new(format!("  - {}", id)))
        .collect()
}

fn draw_wallet_gateway_reset_modal(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let modal = centered_area(area, 72, 44);
    frame.render_widget(Clear, modal);

    let block = Block::default()
        .title(" REARME DE CIRCUITO WEB3 ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    frame.render_widget(block, modal);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(modal);

    let warning = Paragraph::new(
        "Introduzca la secuencia local de 5 cajas + frase para rearmar la pasarela.",
    )
    .style(Style::default().fg(Color::Yellow))
    .wrap(Wrap { trim: false });
    frame.render_widget(warning, chunks[0]);

    let mut cajas_line = Vec::new();
    for i in 0..5 {
        let style = if state.reset_focus_index == i {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        cajas_line.push(Span::styled(format!(" Caja {}: ", i + 1), style));
        cajas_line.push(Span::raw(format!("{:<4}", state.reset_cajas[i])));
    }
    frame.render_widget(
        Paragraph::new(Line::from(cajas_line))
            .block(Block::default().title(" Cajas ").borders(Borders::ALL)),
        chunks[1],
    );

    let phrase_style = if state.reset_focus_index == 5 {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    let hidden_phrase = "*".repeat(state.reset_phrase.len());
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" Frase: ", phrase_style),
            Span::raw(hidden_phrase),
        ]))
        .block(Block::default().borders(Borders::ALL)),
        chunks[2],
    );

    frame.render_widget(
        Paragraph::new("Enter envia | Tab cambia campo | Esc cancela")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray)),
        chunks[3],
    );
}

fn draw_text_cipher(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(13),
            Constraint::Min(8),
            Constraint::Length(10),
        ])
        .split(area);
    let config = text_config_lines(state);
    frame.render_widget(
        Paragraph::new(config)
            .block(Block::default().title(" Cifrar texto - clic/Tab | B explorador | C cifrar | D descifrar | F2 Matrix | F6 exportar | Ctrl+C copiar | Ctrl+V pegar | X limpiar | Esc ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);
    frame.render_widget(
        Paragraph::new(state.text_input.as_str())
            .block(
                Block::default()
                    .title(focus_title(" Entrada ", state.focus == 0))
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        columns[0],
    );
    frame.render_widget(
        Paragraph::new(state.text_output.as_str())
            .block(Block::default().title(" Resultado ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        columns[1],
    );
    if text_keyboard_visible(state) {
        draw_text_keyboard(frame, chunks[2], state);
    } else {
        draw_log_box(frame, chunks[2], state);
    }
}

fn draw_text_keyboard(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let rows = state
        .text_keyboard_chars
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let spans = chunk
                .iter()
                .enumerate()
                .map(|(col, value)| {
                    let index = row * 16 + col;
                    let label = if value == " " { "␣" } else { value };
                    let style = if index == state.text_keyboard_cursor {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Cyan)
                    };
                    Span::styled(format!(" {:^2} ", label), style)
                })
                .collect::<Vec<_>>();
            Line::from(spans)
        })
        .collect::<Vec<_>>();
    let title = if state.focus == 0 {
        " Teclado plantilla para entrada "
    } else {
        " Teclado numerico/plantilla para cajas "
    };
    let keyboard = Paragraph::new(rows)
        .block(
            Block::default()
                .title(format!(
                    "{}| Flechas navegan | Espacio/Enter inserta | R regenerar ",
                    title
                ))
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(keyboard, area);
}

fn text_config_lines(state: &TuiState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(format!(
        "{} Plantilla ({}): [{}]",
        marker(state.focus == 1),
        state.templates.len(),
        state.text_template
    ))];
    for index in 0..5 {
        let valid = box_value_valid(&state.text_cajas[index]);
        let style = if valid {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        };
        lines.push(Line::from(vec![
            Span::raw(format!(
                "{} caja {}: ",
                marker(state.focus == index + 2),
                index + 1
            )),
            Span::styled(state.text_cajas[index].clone(), style),
        ]));
    }
    lines.push(Line::from(format!(
        "{} limite caracteres contrasena: {}",
        marker(state.focus == 7),
        state.text_password_length
    )));
    lines.push(Line::from(format!(
        "{} posicion: {}",
        marker(state.focus == 8),
        password_direction_label(&state.text_password_direction)
    )));
    lines.push(Line::from(format!(
        "{} simbolos control: {}",
        marker(state.focus == 9),
        state.text_control_symbols
    )));
    lines.push(Line::from(format!(
        "{} ruta exportacion: {}",
        marker(state.focus == 10),
        state.text_output_file
    )));
    lines
}

fn draw_file_cipher(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(14),
            Constraint::Min(5),
            Constraint::Length(6),
        ])
        .split(area);
    let mut lines = vec![
        Line::from("clic/Tab campos | B explorador | E ejecutar | M modo | I info | A autocierre | X limpiar | Esc"),
        Line::from(format!("modo: {}", state.file_mode.label())),
        Line::from(format!(
            "cierre automatico: {}",
            if state.file_close_after_operation { "ON" } else { "OFF" }
        )),
        Line::from(format!("{} origen: {}", marker(state.focus == 0), state.file_input_path)),
        Line::from(format!("{} destino: {}", marker(state.focus == 1), state.file_output_path)),
        Line::from(format!(
            "{} Plantilla ({}): [{}]",
            marker(state.focus == 2),
            state.templates.len(),
            state.file_template
        )),
    ];
    for index in 0..5 {
        let valid = box_value_valid(&state.file_cajas[index]);
        let style = if valid {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        };
        lines.push(Line::from(vec![
            Span::raw(format!(
                "{} caja {}: ",
                marker(state.focus == index + 3),
                index + 1
            )),
            Span::styled(state.file_cajas[index].clone(), style),
        ]));
    }
    lines.push(Line::from(format!(
        "{} referencia: {}",
        marker(state.focus == 8),
        state.file_reference_phrase
    )));
    lines.push(Line::from(format!(
        "{} clave archivo: {}",
        marker(state.focus == 9),
        secret_placeholder(&state.file_key_phrase)
    )));
    if let Some(path) = &state.last_forensic_report_path {
        lines.push(Line::from(format!("reporte forense: {}", path.display())));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" Cifrar archivo ")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(state.status.as_str())
            .block(Block::default().title(" Estado ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
    draw_log_box(frame, chunks[2], state);
}

fn draw_template_editor(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(8)])
        .split(area);
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(chunks[0]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Percentage(30),
            Constraint::Percentage(35),
        ])
        .split(columns[0]);

    draw_template_name_grid(
        frame,
        left[0],
        " Idiomas - clic añade todos ",
        &state.language_names,
        state.language_index,
    );
    draw_template_name_grid(
        frame,
        left[1],
        " Numeros / signos - clic añade ",
        &state.number_names,
        state.number_index,
    );
    draw_template_name_list(
        frame,
        left[2],
        " Plantillas ",
        &state.templates,
        state.template_selected_index,
    );

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(8),
            Constraint::Length(5),
            Constraint::Length(4),
            Constraint::Length(5),
        ])
        .split(columns[1]);

    let (hex_count, missing_hex) = check_hex_coverage(&state.template_chars);
    let hex_status = if missing_hex.is_empty() {
        "VALIDA".to_string()
    } else {
        format!("FALTAN {}", missing_hex.iter().collect::<String>())
    };
    let cols = template_cols(state);
    let limit = template_cell_limit(state);
    let count = template_char_count(&state.template_chars);
    let count_style = if count == limit {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    };

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::raw(format!(
                "{}Nombre: {}",
                marker(state.template_focus == 0),
                state.template_name
            )),
            Span::raw(" | "),
            Span::styled(
                "[Insertar nueva plantilla]",
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::raw("Caracteres: "),
            Span::styled(format!("{}/{}", count, limit), count_style),
            Span::raw(" | Tabla: "),
            Span::raw(format!(
                "{}Fila [{}]",
                marker(state.template_focus == 1),
                state.template_rows
            )),
            Span::raw(" x "),
            Span::raw(format!(
                "{}Columna [{}]",
                marker(state.template_focus == 2),
                state.template_cols
            )),
        ]),
        Line::from(vec![
            Span::raw("HEX: "),
            Span::styled(
                format!("{}/16", hex_count),
                if hex_count == 16 {
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                },
            ),
            Span::raw(format!(" [{}] | H rellena esenciales", hex_status)),
        ]),
    ])
    .block(Block::default().title(" Plantilla ").borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    frame.render_widget(header, right[0]);

    let compact_chars = compact_template_chars(&state.template_chars);
    let table_visible_rows = right[1].height.saturating_sub(2).max(1) as usize;
    let table_start_row = table_window_start(state, table_visible_rows);
    let table_total_rows = limit.div_ceil(cols as usize);
    let table_has_more = table_total_rows > table_visible_rows;
    let grid_preview = (0..limit)
        .collect::<Vec<_>>()
        .chunks(cols as usize)
        .skip(table_start_row)
        .take(table_visible_rows)
        .map(|row| {
            row.iter()
                .map(|index| {
                    let value = if let Some(value) = compact_chars.get(*index) {
                        value.clone()
                    } else if count < limit {
                        "·".to_string()
                    } else {
                        " ".to_string()
                    };
                    if state.template_focus == 3 && *index == state.template_cell_index {
                        fixed_cell(&format!("[{}]", value), TEMPLATE_GRID_CELL_WIDTH)
                    } else {
                        fixed_cell(&format!(" {}", value), TEMPLATE_GRID_CELL_WIDTH)
                    }
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let editor = Paragraph::new(grid_preview)
        .block(
            Block::default()
                .title(focus_title(
                    if table_has_more {
                        " Tabla editable ↕ "
                    } else {
                        " Tabla editable "
                    },
                    state.template_focus == 3,
                ))
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(editor, right[1]);

    let language_name = state
        .language_names
        .get(state.language_index)
        .cloned()
        .unwrap_or_default();
    let number_name = state
        .number_names
        .get(state.number_index)
        .cloned()
        .unwrap_or_default();
    let preview_values = template_preview_values(state);
    let preview_visible_rows = right[2].height.saturating_sub(2).max(1) as usize;
    let preview_start_row = preview_window_start(state, preview_visible_rows);
    let preview_total_rows = preview_values.len().div_ceil(16);
    let preview_has_more = preview_total_rows > preview_visible_rows;
    let preview_lines = preview_values
        .chunks(16)
        .enumerate()
        .skip(preview_start_row)
        .take(right[2].height.saturating_sub(2).max(1) as usize)
        .map(|(row, chunk)| {
            let spans = chunk
                .iter()
                .enumerate()
                .map(|(col, value)| {
                    let index = row * 16 + col;
                    let style =
                        if state.template_focus == 4 && index == state.template_preview_cursor {
                            Style::default()
                                .fg(Color::Black)
                                .bg(Color::Yellow)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Cyan)
                        };
                    Span::styled(
                        fixed_cell(&format!(" {}", value), TEMPLATE_PREVIEW_CELL_WIDTH),
                        style,
                    )
                })
                .collect::<Vec<_>>();
            Line::from(spans)
        })
        .collect::<Vec<_>>();
    let preview = Paragraph::new(preview_lines)
        .block(
            Block::default()
                .title(format!(
                    " Vista previa seleccionable{}: {} + {} ",
                    if preview_has_more { " ↕" } else { "" },
                    language_name,
                    number_name
                ))
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(preview, right[2]);

    let selected_chars = state
        .template_chars
        .iter()
        .filter(|value| !value.is_empty())
        .take(96)
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    let result = Paragraph::new(selected_chars)
        .block(
            Block::default()
                .title(" Resultado caracteres seleccionados ")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(result, right[3]);

    let functions = Paragraph::new(vec![
        Line::from("G guardar | I insertar nueva | H rellenar HEX | D eliminar plantilla | E/Delete celda | X limpiar"),
        Line::from("L idioma | N numeros | Enter inserta vista previa | Tab cambia nombre/fila/columna/tabla/vista"),
    ])
    .block(Block::default().title(" Panel de funciones ").borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    frame.render_widget(functions, right[4]);

    draw_log_box(frame, chunks[1], state);
}

fn draw_template_name_list(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    values: &[String],
    selected_index: usize,
) {
    let visible = area.height.saturating_sub(2).max(1) as usize;
    let start = list_window_start(selected_index, values.len(), visible);
    let title = if values.len() > visible {
        format!("{}↕ ", title)
    } else {
        title.to_string()
    };
    let items = values
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(index, name)| {
            let style = if index == selected_index {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Span::styled(name.clone(), style))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(Block::default().title(title).borders(Borders::ALL)),
        area,
    );
}

fn draw_template_name_grid(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    values: &[String],
    selected_index: usize,
) {
    let rows = TEMPLATE_LIST_ROWS.min(area.height.saturating_sub(2).max(1) as usize);
    let col_width = 18usize.min(area.width.saturating_sub(2).max(8) as usize);
    let visible_cols = (area.width.saturating_sub(2).max(1) as usize / col_width).max(1);
    let visible = rows.saturating_mul(visible_cols).max(1);
    let start = list_window_start(selected_index, values.len(), visible);
    let title = if values.len() > visible {
        format!("{}↕ ", title)
    } else {
        title.to_string()
    };
    let lines = (0..rows)
        .map(|row| {
            let spans = (0..visible_cols)
                .map(|col| {
                    let index = start + col * rows + row;
                    let name = values.get(index).cloned().unwrap_or_default();
                    let label = truncate_chars(&name, col_width.saturating_sub(2).max(1));
                    let style = if index == selected_index {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    Span::styled(format!("{:<width$}", label, width = col_width), style)
                })
                .collect::<Vec<_>>();
            Line::from(spans)
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn template_grid_index_at(
    area: Rect,
    x: u16,
    y: u16,
    selected_index: usize,
    total: usize,
) -> usize {
    let rows = TEMPLATE_LIST_ROWS.min(area.height.saturating_sub(2).max(1) as usize);
    let col_width = 18usize.min(area.width.saturating_sub(2).max(8) as usize);
    let visible_cols = (area.width.saturating_sub(2).max(1) as usize / col_width).max(1);
    let visible = rows.saturating_mul(visible_cols).max(1);
    let start = list_window_start(selected_index, total, visible);
    let row = y.saturating_sub(area.y + 1) as usize;
    let col = x.saturating_sub(area.x + 1) as usize / col_width.max(1);
    start + col.saturating_mul(rows) + row
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn fixed_cell(value: &str, width: usize) -> String {
    let mut text = truncate_chars(value, width.saturating_sub(2).max(1));
    let len = text.chars().count();
    if len < width {
        text.push_str(&" ".repeat(width - len));
    }
    text
}

fn settings_box_line(state: &TuiState, index: usize) -> Line<'static> {
    let valid = box_value_valid(&state.settings_boot_cajas[index]);
    let style = if valid {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    };
    Line::from(vec![
        Span::raw(format!(
            "{} caja {}: ",
            marker(state.settings_focus == index),
            index + 1
        )),
        Span::styled(state.settings_boot_cajas[index].clone(), style),
    ])
}

fn draw_settings(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(14), Constraint::Length(6)])
        .split(area);
    let hardening = security::process_hardening::process_hardening_status();
    let apparmor = security::apparmor::apparmor_status();
    let lines = vec![
        Line::from("clic/Tab campos | B Boot Shield ON | O OFF | S red | T inactividad | +/- segundos | P AppArmor ON | U OFF | Esc"),
        Line::from(""),
        Line::from("SECCION: ACCESO"),
        settings_box_line(state, 0),
        settings_box_line(state, 1),
        settings_box_line(state, 2),
        settings_box_line(state, 3),
        settings_box_line(state, 4),
        Line::from(format!("{} frase: {}", marker(state.settings_focus == 5), "*".repeat(state.settings_boot_frase.chars().count()))),
        Line::from(format!("{} plantilla arranque: {}", marker(state.settings_focus == 6), state.settings_boot_template)),
        Line::from(format!(
            "{} bloqueo inactividad: {} ({}s)",
            marker(state.settings_focus == 9),
            if state.inactivity_enabled { "ON" } else { "OFF" },
            state.inactivity_timeout_seconds
        )),
        Line::from(""),
        Line::from("SECCION: RED (solo configuracion, no se ejecutan pruebas de red)"),
        Line::from(format!("{} perfil: {}", marker(state.settings_focus == 7), state.settings_network_profile)),
        Line::from(format!("{} confirmacion: {}", marker(state.settings_focus == 8), state.settings_network_confirmation)),
        Line::from(""),
        Line::from("SECCION: HARDENING"),
        Line::from(format!("CORE DUMPS: {}", if hardening.core_dumps_disabled { "OFF" } else { "ON" })),
        Line::from(format!("DUMPABLE: {}", if hardening.dumpable_disabled { "OFF" } else { "ON" })),
        Line::from(format!("MLOCKALL: {}", if hardening.mlockall_applied { "OK" } else { "FALLO" })),
        Line::from(""),
        Line::from("SECCION: APPARMOR"),
        Line::from(format!("SO detectado: {}", apparmor.os_id)),
        Line::from(format!("Soportado: {}", if apparmor.supported { "SI" } else { "NO" })),
        Line::from(format!("Kernel AppArmor: {}", if apparmor.kernel_enabled { "OK" } else { "NO" })),
        Line::from(format!("apparmor_parser: {}", if apparmor.parser_available { "OK" } else { "NO" })),
        Line::from(format!("Perfil instalado: {}", if apparmor.profile_installed { "SI" } else { "NO" })),
        Line::from(format!("Estado: {}", apparmor.message)),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" Configuracion del sistema ")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    draw_log_box(frame, chunks[1], state);
}

fn draw_system_monitor(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Min(8),
            Constraint::Length(5),
        ])
        .split(area);

    let hardening = security::process_hardening::process_hardening_status();
    let integrity = match state.integrity {
        security::vault::IntegrityStatus::Valid => "VALIDA",
        security::vault::IntegrityStatus::Truncated => "TRUNCADA",
        security::vault::IntegrityStatus::Deleted => "LOG BORRADO",
    };
    let summary = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Integridad auditoria: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                integrity,
                Style::default().fg(
                    if matches!(state.integrity, security::vault::IntegrityStatus::Valid) {
                        Color::Green
                    } else {
                        Color::Yellow
                    },
                ),
            ),
        ]),
        Line::from(format!(
            "Tombstones pendientes: {}",
            security::audit::tombstone_count()
        )),
        Line::from(format!("Hardening warnings: {}", hardening.warnings.len())),
        Line::from("Esc/q vuelve al dashboard | r refresca"),
    ])
    .block(
        Block::default()
            .title(" Monitor de sistema ")
            .borders(Borders::ALL),
    );
    frame.render_widget(summary, chunks[0]);

    let entries = security::audit::read_recent_entries(12).unwrap_or_default();
    let audit_items = if entries.is_empty() {
        vec![ListItem::new("Sin eventos de auditoria registrados.")]
    } else {
        entries
            .iter()
            .map(|entry| {
                ListItem::new(format!(
                    "#{:04} | {} | {} | {}...",
                    entry.index,
                    entry.timestamp_unix,
                    entry.event_type,
                    hex::encode(&entry.prev_hash)
                        .chars()
                        .take(10)
                        .collect::<String>()
                ))
            })
            .collect::<Vec<_>>()
    };
    let audit = List::new(audit_items).block(
        Block::default()
            .title(" Auditoria encadenada ")
            .borders(Borders::ALL),
    );
    frame.render_widget(audit, chunks[1]);

    let warnings = if hardening.warnings.is_empty() {
        "Sin avisos de hardening.".to_string()
    } else {
        hardening.warnings.join("\n")
    };
    let warning_box = Paragraph::new(warnings)
        .block(Block::default().title(" Avisos ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(warning_box, chunks[2]);
}

fn draw_audit_monitor(frame: &mut Frame<'_>, area: Rect) {
    let entries = security::audit::read_recent_entries(20).unwrap_or_default();
    let items = if entries.is_empty() {
        vec![ListItem::new("Sin eventos de auditoria.")]
    } else {
        entries
            .iter()
            .map(|entry| {
                let hash = hex::encode(entry.calculate_hash())
                    .chars()
                    .take(12)
                    .collect::<String>();
                ListItem::new(format!(
                    "#{:04} | {} | {} | {} | anchor {}...",
                    entry.index,
                    entry.timestamp_unix,
                    entry.event_type,
                    entry.signature_scheme,
                    hash
                ))
            })
            .collect()
    };

    let list = List::new(items).block(
        Block::default()
            .title(" Auditoria avanzada - Esc vuelve ")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, area);
}

fn draw_firmware_staging(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(5)])
        .split(area);

    let body = match security::updates::inspect_pending_update() {
        Ok(Some(manifest)) => vec![
            Line::from(vec![
                Span::styled("Version: ", Style::default().fg(Color::Cyan)),
                Span::raw(manifest.version),
            ]),
            Line::from(vec![
                Span::styled("Creado: ", Style::default().fg(Color::Cyan)),
                Span::raw(manifest.created_at_unix.to_string()),
            ]),
            Line::from(vec![
                Span::styled("Payload SHA-256: ", Style::default().fg(Color::Cyan)),
                Span::raw(manifest.payload_sha256),
            ]),
            Line::from(""),
            Line::from(manifest.changelog),
            Line::from(""),
            Line::from("v = verificar firma/hash | h = handover al vault | c = limpiar staging | Esc = volver"),
        ],
        Ok(None) => vec![
            Line::from("No hay update en staging."),
            Line::from("Ruta esperada: ~/.local/share/livencrypt/.livencrypt/staging/"),
            Line::from("Esc = volver"),
        ],
        Err(error) => vec![
            Line::from(format!("Error inspeccionando staging: {}", error)),
            Line::from("Esc = volver"),
        ],
    };

    let panel = Paragraph::new(body)
        .block(
            Block::default()
                .title(" Staging VFS / Updates firmados ")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(panel, chunks[0]);

    let status = Paragraph::new(state.status.as_str())
        .block(Block::default().title(" Estado ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(status, chunks[1]);
}

fn draw_sandbox_manager(frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(6)])
        .split(area);

    let summary = security::sandbox::sandbox_capability_summary()
        .into_iter()
        .map(Line::from)
        .collect::<Vec<_>>();
    let panel = Paragraph::new(summary)
        .block(
            Block::default()
                .title(" Sandbox expu ")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(panel, chunks[0]);

    let risk = security::ai_monitor::expu_baseline_risk();
    let body = Paragraph::new(vec![
        Line::from(format!("Riesgo heuristico base: {:.0}%", risk * 100.0)),
        Line::from("Loader memfd integrado como API Linux-gated."),
        Line::from("No se ejecuta automaticamente ningun binario desde esta pantalla."),
        Line::from("Esc = volver"),
    ])
    .block(
        Block::default()
            .title(" IA/heuristica local ")
            .borders(Borders::ALL),
    );
    frame.render_widget(body, chunks[1]);
}

fn draw_recovery_mode(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Min(4),
        ])
        .split(area);

    let title = Paragraph::new("MODO RECOVERY ED25519")
        .alignment(Alignment::Center)
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let input = Paragraph::new(format!("Ruta .lvc_recovery: {}", state.recovery_path))
        .block(
            Block::default()
                .title(" Archivo firmado ")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(input, chunks[1]);

    let message = if state.recovery_error.is_empty() {
        "Enter aplica recovery | Backspace edita | Esc vuelve".to_string()
    } else {
        format!("ERROR: {}", state.recovery_error)
    };
    let output = Paragraph::new(message)
        .style(Style::default().fg(if state.recovery_error.is_empty() {
            Color::White
        } else {
            Color::Red
        }))
        .block(Block::default().title(" Estado ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(output, chunks[2]);
}

fn draw_install_profile(frame: &mut Frame<'_>, area: Rect) {
    let profile = security::install_profile::read_install_profile();
    let body = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Perfil instalado: ", Style::default().fg(Color::Cyan)),
            Span::raw(profile.as_str()),
        ]),
        Line::from(""),
        Line::from("standard: hardening + vault + auditoria"),
        Line::from("isolated: standard + politica de equipo aislado"),
        Line::from("expu: recovery + staging + sandbox"),
        Line::from("pba: expu + initramfs manual"),
        Line::from(""),
        Line::from("Esc = volver"),
    ])
    .block(
        Block::default()
            .title(" Perfil de instalacion ")
            .borders(Borders::ALL),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(body, area);
}

fn draw_log_box(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let content = if state.operation_log.is_empty() {
        state.status.clone()
    } else {
        format!("{}\n{}", state.status, state.operation_log.join("\n"))
    };
    frame.render_widget(
        Paragraph::new(content)
            .block(Block::default().title(" Registro ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn marker(active: bool) -> &'static str {
    if active {
        ">"
    } else {
        " "
    }
}

fn secret_placeholder(value: &str) -> String {
    let count = value.chars().count();
    if count == 0 {
        "<vacia>".to_string()
    } else {
        format!("<{} caracteres ocultos>", count)
    }
}

fn focus_title(title: &'static str, active: bool) -> String {
    if active {
        format!("{}*", title)
    } else {
        title.to_string()
    }
}

fn centered_area(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}
