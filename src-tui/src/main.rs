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
use livencrypt_lib::crypto::blockchain::address::{self, Network};
use livencrypt_lib::crypto::blockchain::breaker::GatewaySecurityState;
use livencrypt_lib::crypto::blockchain::firewall::{FirewallRules, LiveFirewall};
use livencrypt_lib::crypto::blockchain::multi_curve::UniversalKeymaster;
use livencrypt_lib::crypto::blockchain::nodes::{self, NodeRegistry};
use livencrypt_lib::crypto::blockchain::rpc_manager;
use livencrypt_lib::crypto::blockchain::supervisor::GatewaySupervisor;
use livencrypt_lib::crypto::blockchain::types::{
    AccountPolicy, BroadcastRequestPreview, ChainType, PolicyWindow, PriceQuote, ScheduledPolicy,
    SigningRequestPreview, Web3ConnectivityProfile,
};
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
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
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
const CREDENTIAL_MODE_DOUBLE: &str = "double";
const UNLOCK_SINGLE_FIELD_COUNT: usize = 6;
const UNLOCK_DOUBLE_FIELD_COUNT: usize = 12;
const SETTINGS_FIELD_COUNT: usize = 22;

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

    if args.iter().any(|arg| arg == "--web3-real-check") {
        return run_web3_real_check().map_err(Into::into);
    }

    livencrypt_lib::initialize_core();
    run_terminal_ui()
}

fn run_web3_real_check() -> Result<(), String> {
    println!("LIVENCRYPT WEB3 REAL CHECK");
    println!("Alcance: nodos blockchain publicos de lectura, derivacion local y QR publico.");
    println!("Excluido: nmcli, firewall del SO, AppArmor operativo, broadcast y firma real.");
    println!();

    let keymaster = UniversalKeymaster::new(
        [101, 202, 303, 404, 505],
        "LIVENCRYPT-WEB3-REAL-CHECK-NO-USAR-EN-PRODUCCION",
    )?;
    for chain in [ChainType::Bitcoin, ChainType::Ethereum, ChainType::Solana] {
        for index in 0..2 {
            let started = Instant::now();
            match keymaster.get_public_key(&chain, Network::Mainnet, 0, index) {
                Ok(public_key) => {
                    let address = public_key_address_label(&chain, &public_key, Network::Mainnet);
                    let payload =
                        wallet_link_payload_for_check(&chain, 0, index, &address, &public_key);
                    println!(
                        "WALLET {:?} cuenta=0 indice={} generada en {}ms",
                        chain,
                        index,
                        started.elapsed().as_millis()
                    );
                    println!("direccion: {}", address);
                    println!("payload-extension: {}", payload);
                    println!("QR ASCII: {}", qr_ascii_summary(&payload));
                    println!();
                }
                Err(error) => {
                    println!(
                        "WALLET {:?} cuenta=0 indice={} ERROR: {}",
                        chain, index, error
                    );
                }
            }
        }
    }

    let mut registry = NodeRegistry::default();
    registry.set_profile(Web3ConnectivityProfile::RpcReadOnly);
    registry.set_primary("ethereum", "https://ethereum-rpc.publicnode.com");
    registry.set_primary("solana", "https://api.mainnet-beta.solana.com");
    registry.set_primary("bitcoin", "https://bitcoin-rpc.publicnode.com");

    println!("RPC PROFILE: {}", registry.profile().label());
    println!("{}", registry.connectivity_summary());
    println!();

    run_rpc_probe(
        &registry,
        "ethereum",
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "ETH",
        Some("0x0000000000000000000000000000000000000000000000000000000000000000"),
    );
    run_rpc_probe(
        &registry,
        "solana",
        "11111111111111111111111111111111",
        "SOL",
        None,
    );
    run_rpc_probe(
        &registry,
        "bitcoin",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "BTC",
        None,
    );

    match rpc_manager::verified_clock_from_nodes(&registry, &["ethereum", "solana", "bitcoin"]) {
        Ok(clock) => println!(
            "RELOJ VERIFICADO: local={} consenso={:?} drift={:?}s estado={}",
            clock.local_unix, clock.consensus_unix, clock.drift_seconds, clock.status
        ),
        Err(error) => println!("RELOJ VERIFICADO ERROR: {}", error),
    }

    println!();
    println!("DEX/EXTENSION CHECK:");
    println!("OK: se genera payload publico livencrypt-wallet-link por wallet.");
    println!("OK: el bridge nativo puede exponer clave publica/direccion sin secreto.");
    println!("LIMITACION: MetaMask no acepta este payload directamente; requiere extension Livencrypt o adaptador EIP-1193 propio.");
    println!(
        "OK: Bitcoin genera direccion publica P2PKH valida desde la clave publica comprimida."
    );
    println!(
        "LIMITACION: Monero/ZCash/Starknet no tienen adaptador de derivacion/RPC en este binario."
    );

    Ok(())
}

fn wallet_link_payload_for_check(
    chain: &ChainType,
    account: u32,
    index: u32,
    address: &str,
    public_key: &[u8],
) -> String {
    serde_json::json!({
        "type": "livencrypt-wallet-link",
        "version": 1,
        "chain": format!("{:?}", chain),
        "account": account,
        "address_index": index,
        "derivation_path": derivation_path_label(chain, account, index),
        "address": address,
        "public_key_hex": hex::encode(public_key),
        "scope": "public-address-only",
        "warning": "No contiene clave privada ni frase secreta"
    })
    .to_string()
}

fn qr_ascii_summary(payload: &str) -> String {
    let qr = render_ascii_qr(payload);
    let lines = qr.lines().count();
    let chars = qr.chars().count();
    let digest = Sha256::digest(qr.as_bytes());
    format!(
        "OK lineas={} chars={} sha256={}",
        lines,
        chars,
        hex::encode(&digest[..8])
    )
}

fn render_ascii_qr(payload: &str) -> String {
    match qrcode::QrCode::new(payload.as_bytes()) {
        Ok(code) => code
            .render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .dark_color('█')
            .light_color(' ')
            .build(),
        Err(error) => format!("QR ERROR: {}", error),
    }
}

fn run_rpc_probe(
    registry: &NodeRegistry,
    chain: &str,
    address: &str,
    asset: &str,
    txid: Option<&str>,
) {
    println!("RPC {}", chain);
    let adapter = match rpc_manager::adapter_for_chain(registry, chain) {
        Ok(adapter) => adapter,
        Err(error) => {
            println!("  ADAPTADOR ERROR: {}", error);
            println!();
            return;
        }
    };

    match adapter.health() {
        Ok(health) => println!(
            "  HEALTH OK endpoint={} network={} altura={:?} latencia={}ms",
            health.endpoint, health.network_id, health.block_height_or_slot, health.latency_ms
        ),
        Err(error) => println!("  HEALTH ERROR: {}", error),
    }
    match adapter.read_chain_clock() {
        Ok(clock) => println!(
            "  CLOCK OK altura={:?} chain_unix={:?} drift={:?}",
            clock.block_height_or_slot, clock.chain_unix, clock.drift_seconds
        ),
        Err(error) => println!("  CLOCK ERROR: {}", error),
    }
    match adapter.read_balance(address, asset) {
        Ok(balance) => println!(
            "  BALANCE OK {} {} raw={} endpoint={}",
            balance.amount, balance.asset, balance.raw_amount, balance.endpoint
        ),
        Err(error) => println!("  BALANCE ERROR: {}", error),
    }
    match adapter.read_nonce(address) {
        Ok(nonce) => println!("  NONCE OK {}", nonce.nonce),
        Err(error) => println!("  NONCE ERROR: {}", error),
    }
    match adapter.estimate_fee(&[]) {
        Ok(fee) => println!(
            "  FEE OK {} {} raw={} source={}",
            fee.fee_amount, fee.asset, fee.raw_fee, fee.source
        ),
        Err(error) => println!("  FEE ERROR: {}", error),
    }
    if let Some(txid) = txid {
        match adapter.read_transaction_status(txid) {
            Ok(status) => println!(
                "  TX OK confirmado={} bloque={:?} success={:?}",
                status.confirmed, status.block_height_or_slot, status.success
            ),
            Err(error) => println!("  TX ERROR: {}", error),
        }
    }
    println!();
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
    WalletAuditor,
    NodesManager,
    Web3AccountPolicies,
    Web3ScheduledRules,
    Web3PriceOracle,
    Web3RpcInspector,
    Web3AccountEditor,
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
    SandboxPayload,
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

/// Accion del auditor en espera de re-confirmacion Boot Shield (gate C.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingAction {
    AuditorDerive,
    AuditorVerify,
    AuditorCopy,
}

struct TuiState {
    screen: Screen,
    cajas: [String; 5],
    frase: String,
    secondary_cajas: [String; 5],
    secondary_frase: String,
    boot_credential_mode: String,
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
    last_click_millis: u128,
    last_click_col: u16,
    last_click_row: u16,
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
    settings_boot_secondary_cajas: [String; 5],
    settings_boot_secondary_frase: String,
    settings_duress_cajas: [String; 5],
    settings_duress_frase: String,
    settings_boot_template: String,
    settings_network_profile: String,
    settings_network_confirmation: String,
    settings_destructive_auditor_reauth: bool,
    inactivity_enabled: bool,
    inactivity_timeout_seconds: u64,
    settings_focus: usize,
    settings_scroll: u16,

    web3_cmd_tx: Option<mpsc::Sender<Web3WorkerCmd>>,
    web3_event_rx: Option<mpsc::Receiver<Web3WorkerEvent>>,
    cached_gateway_state: GatewaySecurityState,
    cached_tx_count: u32,
    cached_volume_units: Decimal,
    cached_fiat_value: Decimal,
    allowed_dex_contracts: Vec<String>,
    allowed_cex_destinations: Vec<String>,
    account_policies: Vec<AccountPolicy>,
    price_quotes: Vec<PriceQuote>,
    system_notification: String,
    pending_signing_preview: Option<SigningRequestPreview>,
    pending_broadcast_preview: Option<BroadcastRequestPreview>,
    last_identity_confirmation_unix: u64,
    show_reauth_modal: bool,
    pending_action_after_reauth: Option<PendingAction>,
    reauth_cajas: [String; 5],
    reauth_phrase: String,
    reauth_secondary_cajas: [String; 5],
    reauth_secondary_phrase: String,
    reauth_focus: usize,
    gateway_focused_field: usize,
    gateway_network: Network,
    input_max_tx: String,
    input_max_volume: String,
    input_max_fiat_value: String,
    input_fiat_currency: String,
    input_price_asset: String,
    input_price_value: String,
    input_new_dex_id: String,
    input_new_cex_id: String,
    show_breaker_reset: bool,
    reset_cajas: [String; 5],
    reset_phrase: String,
    reset_focus_index: usize,
    auditor_chain_index: usize,
    auditor_network: Network,
    auditor_account_index: String,
    auditor_address_index: String,
    auditor_focus: usize,
    auditor_public_key_hex: String,
    auditor_address: String,
    auditor_segwit_address: String,
    auditor_expected_input: String,
    auditor_match_status: String,
    auditor_status: String,
    web3_policy_selected: usize,
    web3_policy_focus: usize,
    web3_policy_chain_index: usize,
    web3_policy_account_index: String,
    web3_policy_address_index: String,
    web3_policy_label: String,
    web3_policy_max_tx: String,
    web3_policy_max_crypto: String,
    web3_policy_max_fiat: String,
    web3_policy_fiat_currency: String,
    web3_policy_require_confirmation: bool,
    web3_policy_destination_input: String,
    web3_policy_contract_input: String,
    web3_policy_asset_input: String,
    web3_policy_asset_limit_input: String,
    web3_schedule_selected: usize,
    web3_schedule_focus: usize,
    web3_schedule_name: String,
    web3_schedule_asset: String,
    web3_schedule_destination: String,
    web3_schedule_max_tx: String,
    web3_schedule_max_asset: String,
    web3_schedule_max_fiat: String,
    web3_schedule_currency: String,
    web3_schedule_window: String,
    web3_schedule_expires_unix: String,
    web3_price_focus: usize,
    web3_price_selected: usize,
    web3_price_asset: String,
    web3_price_fiat: String,
    web3_price_value: String,
    web3_price_source: String,
    web3_price_max_age_seconds: String,
    web3_price_import_path: String,
    web3_rpc_focus: usize,
    web3_rpc_chain_index: usize,
    web3_rpc_address: String,
    web3_rpc_asset: String,
    web3_rpc_status: String,
    web3_rpc_balance: String,
    web3_rpc_nonce: String,
    web3_rpc_fee: String,
    web3_rpc_tx_status: String,
    sandbox_payload_path: String,
    sandbox_memory_mib: String,
    sandbox_cpu_seconds: String,
    sandbox_file_size_mib: String,
    sandbox_focus: usize,
    sandbox_active_pids: Vec<i32>,
    sandbox_selected_pid: usize,
    sandbox_status: String,
}

impl TuiState {
    fn new() -> Self {
        let vault_configured = security::vault_is_configured();
        let boot_credential_mode = current_boot_credential_mode();
        let templates = template_names();
        let mut state = Self {
            screen: if vault_configured {
                Screen::Unlock
            } else {
                Screen::Dashboard
            },
            cajas: empty_boxes(),
            frase: String::new(),
            secondary_cajas: empty_boxes(),
            secondary_frase: String::new(),
            boot_credential_mode,
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
            text_password_attempts: 0,
            text_internal_clipboard: String::new(),
            nodes: NodeRegistry::load_from_path(&nodes::default_nodes_path()),
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
            last_click_millis: 0,
            last_click_col: 0,
            last_click_row: 0,
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
            settings_boot_secondary_cajas: empty_boxes(),
            settings_boot_secondary_frase: String::new(),
            settings_duress_cajas: empty_boxes(),
            settings_duress_frase: String::new(),
            settings_boot_template: DEFAULT_TEMPLATE.to_string(),
            settings_network_profile: security::get_network_profile()
                .unwrap_or_else(|_| "mock".to_string()),
            settings_network_confirmation: String::new(),
            settings_destructive_auditor_reauth: false,
            inactivity_enabled: false,
            inactivity_timeout_seconds: 300,
            settings_focus: 0,
            settings_scroll: 0,
            web3_cmd_tx: None,
            web3_event_rx: None,
            cached_gateway_state: GatewaySecurityState::Frozen {
                reason: "Pasarela Web3 no inicializada".to_string(),
                timestamp: 0,
            },
            cached_tx_count: 0,
            cached_volume_units: Decimal::ZERO,
            cached_fiat_value: Decimal::ZERO,
            allowed_dex_contracts: Vec::new(),
            allowed_cex_destinations: Vec::new(),
            account_policies: Vec::new(),
            price_quotes: Vec::new(),
            system_notification: "Pasarela Web3 pendiente de desbloqueo Boot Shield.".to_string(),
            pending_signing_preview: None,
            pending_broadcast_preview: None,
            last_identity_confirmation_unix: 0,
            show_reauth_modal: false,
            pending_action_after_reauth: None,
            reauth_cajas: empty_boxes(),
            reauth_phrase: String::new(),
            reauth_secondary_cajas: empty_boxes(),
            reauth_secondary_phrase: String::new(),
            reauth_focus: 0,
            gateway_focused_field: 0,
            gateway_network: Network::Mainnet,
            input_max_tx: "10".to_string(),
            input_max_volume: "5000".to_string(),
            input_max_fiat_value: "5000".to_string(),
            input_fiat_currency: "USD".to_string(),
            input_price_asset: "BTC".to_string(),
            input_price_value: String::new(),
            input_new_dex_id: String::new(),
            input_new_cex_id: String::new(),
            show_breaker_reset: false,
            reset_cajas: empty_boxes(),
            reset_phrase: String::new(),
            reset_focus_index: 0,
            auditor_chain_index: 0,
            auditor_network: Network::Mainnet,
            auditor_account_index: "0".to_string(),
            auditor_address_index: "0".to_string(),
            auditor_focus: 0,
            auditor_public_key_hex: String::new(),
            auditor_address: String::new(),
            auditor_segwit_address: String::new(),
            auditor_expected_input: String::new(),
            auditor_match_status: String::new(),
            auditor_status: "Seleccione red y pulse Enter para derivar.".to_string(),
            web3_policy_selected: 0,
            web3_policy_focus: 0,
            web3_policy_chain_index: 1,
            web3_policy_account_index: "0".to_string(),
            web3_policy_address_index: String::new(),
            web3_policy_label: "Operativa".to_string(),
            web3_policy_max_tx: "10".to_string(),
            web3_policy_max_crypto: String::new(),
            web3_policy_max_fiat: "5000".to_string(),
            web3_policy_fiat_currency: "USD".to_string(),
            web3_policy_require_confirmation: true,
            web3_policy_destination_input: String::new(),
            web3_policy_contract_input: String::new(),
            web3_policy_asset_input: String::new(),
            web3_policy_asset_limit_input: String::new(),
            web3_schedule_selected: 0,
            web3_schedule_focus: 0,
            web3_schedule_name: String::new(),
            web3_schedule_asset: "USDT".to_string(),
            web3_schedule_destination: String::new(),
            web3_schedule_max_tx: "4".to_string(),
            web3_schedule_max_asset: String::new(),
            web3_schedule_max_fiat: String::new(),
            web3_schedule_currency: "USD".to_string(),
            web3_schedule_window: "diario".to_string(),
            web3_schedule_expires_unix: String::new(),
            web3_price_focus: 0,
            web3_price_selected: 0,
            web3_price_asset: "BTC".to_string(),
            web3_price_fiat: "USD".to_string(),
            web3_price_value: String::new(),
            web3_price_source: "manual-local".to_string(),
            web3_price_max_age_seconds: "86400".to_string(),
            web3_price_import_path: String::new(),
            web3_rpc_focus: 0,
            web3_rpc_chain_index: 1,
            web3_rpc_address: String::new(),
            web3_rpc_asset: "native".to_string(),
            web3_rpc_status: "RPC no consultado.".to_string(),
            web3_rpc_balance: String::new(),
            web3_rpc_nonce: String::new(),
            web3_rpc_fee: String::new(),
            web3_rpc_tx_status: String::new(),
            sandbox_payload_path: String::new(),
            sandbox_memory_mib: "512".to_string(),
            sandbox_cpu_seconds: "120".to_string(),
            sandbox_file_size_mib: "64".to_string(),
            sandbox_focus: 0,
            sandbox_active_pids: Vec::new(),
            sandbox_selected_pid: 0,
            sandbox_status: "Seleccione binario y pulse Enter para ejecutar en memfd.".to_string(),
        };
        state.nodes_chains = state.nodes.chain_names();
        state.refresh_templates_count();
        state.add_log("TUI inicializada.");
        state
    }

    fn clear_secret_fields(&mut self) {
        zeroize_boxes(&mut self.cajas);
        self.frase.zeroize();
        self.frase.clear();
        zeroize_boxes(&mut self.secondary_cajas);
        self.secondary_frase.zeroize();
        self.secondary_frase.clear();
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
        self.boot_credential_mode = current_boot_credential_mode();
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

    fn unlock_requires_secondary(&self) -> bool {
        self.boot_credential_mode == CREDENTIAL_MODE_DOUBLE
    }

    fn unlock(&mut self) {
        let cajas = self.parse_unlock_cajas();
        let mut frase = String::new();
        std::mem::swap(&mut frase, &mut self.frase);
        let secondary_required = self.unlock_requires_secondary();
        let secondary_cajas = if secondary_required {
            Some(match parse_boxes(&self.secondary_cajas) {
                Ok(cajas) => cajas,
                Err(error) => {
                    frase.zeroize();
                    self.clear_secret_fields();
                    self.status = error;
                    self.add_log("Intento de acceso rechazado.");
                    return;
                }
            })
        } else {
            None
        };
        let mut secondary_frase = if secondary_required {
            let mut value = String::new();
            std::mem::swap(&mut value, &mut self.secondary_frase);
            Some(value)
        } else {
            None
        };

        let result = match cajas {
            Ok(cajas) if !frase.trim().is_empty() => {
                if secondary_required
                    && secondary_frase
                        .as_ref()
                        .is_none_or(|value| value.trim().is_empty())
                {
                    frase.zeroize();
                    if let Some(value) = secondary_frase.as_mut() {
                        value.zeroize();
                    }
                    Err(INVALID_ACCESS.to_string())
                } else {
                    let mut frase_for_gateway = frase.clone();
                    let unlock_result = security::vault::boot_shield_unlock(
                        cajas,
                        frase,
                        secondary_cajas,
                        secondary_frase.take(),
                    )
                    .map(|_| ())
                    .map_err(|_| INVALID_ACCESS.to_string());
                    if unlock_result.is_ok() {
                        if let Err(error) =
                            self.initialize_wallet_gateway(cajas, &frase_for_gateway)
                        {
                            self.system_notification = format!("Web3 no inicializado: {}", error);
                        }
                    }
                    frase_for_gateway.zeroize();
                    unlock_result
                }
            }
            Ok(_) | Err(_) => {
                frase.zeroize();
                if let Some(value) = secondary_frase.as_mut() {
                    value.zeroize();
                }
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
        zeroize_boxes(&mut self.settings_boot_secondary_cajas);
        self.settings_boot_secondary_frase.zeroize();
        self.settings_boot_secondary_frase.clear();
        zeroize_boxes(&mut self.settings_duress_cajas);
        self.settings_duress_frase.zeroize();
        self.settings_duress_frase.clear();
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
        self.input_max_volume = supervisor
            .firewall
            .rules
            .max_daily_crypto_amount
            .to_string();
        self.input_max_fiat_value = supervisor.firewall.rules.max_daily_fiat_value.to_string();
        self.input_fiat_currency = supervisor.firewall.rules.fiat_currency.clone();
        self.allowed_dex_contracts = supervisor.firewall.rules.allowed_dex_contracts.clone();
        self.allowed_cex_destinations = supervisor.firewall.rules.allowed_cex_destinations.clone();
        self.account_policies = supervisor.firewall.rules.account_policies.clone();
        self.price_quotes = supervisor.firewall.rules.price_book.quotes.clone();
        self.cached_gateway_state = supervisor.breaker.state.clone();
        self.cached_tx_count = supervisor.firewall.tx_count_today;
        self.cached_volume_units = supervisor.firewall.volume_today_units;
        self.cached_fiat_value = supervisor.firewall.fiat_value_today;

        let (tx, rx) = Web3BackgroundWorker::spawn(supervisor, self.nodes.clone());
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
        self.cached_fiat_value = Decimal::ZERO;
        self.system_notification = "Pasarela Web3 detenida.".to_string();
        self.pending_signing_preview = None;
        self.pending_broadcast_preview = None;
        self.show_breaker_reset = false;
        self.show_reauth_modal = false;
        self.pending_action_after_reauth = None;
        self.clear_gateway_secret_fields();
        self.clear_reauth_secret_fields();
    }

    fn clear_gateway_secret_fields(&mut self) {
        zeroize_boxes(&mut self.reset_cajas);
        self.reset_phrase.zeroize();
        self.reset_phrase.clear();
    }

    fn clear_reauth_secret_fields(&mut self) {
        zeroize_boxes(&mut self.reauth_cajas);
        self.reauth_phrase.zeroize();
        self.reauth_phrase.clear();
        zeroize_boxes(&mut self.reauth_secondary_cajas);
        self.reauth_secondary_phrase.zeroize();
        self.reauth_secondary_phrase.clear();
        self.reauth_focus = 0;
    }

    fn insert_virtual_char(&mut self) {
        let Some(value) = self.teclado_shuffled.get(self.cursor_teclado).copied() else {
            return;
        };
        if matches!(self.focus, 0..=4 | 6..=10) {
            let _ = push_unlock_box_char(self, value);
        } else {
            push_unlock_phrase_char(self, value);
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
        zeroize_boxes(&mut self.settings_boot_secondary_cajas);
        zeroize_boxes(&mut self.settings_duress_cajas);
        self.file_browser.clear();
        self.status.zeroize();
        self.recovery_path.zeroize();
        self.recovery_error.zeroize();
        self.settings_boot_frase.zeroize();
        self.settings_boot_secondary_frase.zeroize();
        self.settings_duress_frase.zeroize();
        self.settings_network_confirmation.zeroize();
        self.text_output_file.zeroize();
        self.shutdown_wallet_gateway();
        self.input_new_dex_id.zeroize();
        self.input_new_cex_id.zeroize();
        self.system_notification.zeroize();
        self.auditor_public_key_hex.zeroize();
        self.auditor_address.zeroize();
        self.auditor_segwit_address.zeroize();
        self.auditor_expected_input.zeroize();
        self.auditor_match_status.zeroize();
        self.auditor_status.zeroize();
        self.sandbox_payload_path.zeroize();
        self.sandbox_status.zeroize();
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

fn current_boot_credential_mode() -> String {
    security::vault::boot_shield_status()
        .map(|status| status.credential_mode)
        .unwrap_or_else(|_| "single".to_string())
}

fn unlock_field_count(state: &TuiState) -> usize {
    if state.unlock_requires_secondary() {
        UNLOCK_DOUBLE_FIELD_COUNT
    } else {
        UNLOCK_SINGLE_FIELD_COUNT
    }
}

fn push_unlock_box_char(state: &mut TuiState, value: char) -> bool {
    match state.focus {
        0..=4 => push_box_char(&mut state.cajas[state.focus], value),
        6..=10 => push_box_char(&mut state.secondary_cajas[state.focus - 6], value),
        _ => false,
    }
}

fn push_unlock_phrase_char(state: &mut TuiState, value: char) {
    match state.focus {
        5 => state.frase.push(value),
        11 => state.secondary_frase.push(value),
        _ => {}
    }
}

fn pop_unlock_field(state: &mut TuiState) {
    match state.focus {
        0..=4 => {
            state.cajas[state.focus].pop();
        }
        5 => {
            state.frase.pop();
        }
        6..=10 => {
            state.secondary_cajas[state.focus - 6].pop();
        }
        11 => {
            state.secondary_frase.pop();
        }
        _ => {}
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

fn auditor_chains() -> [ChainType; 3] {
    [ChainType::Bitcoin, ChainType::Ethereum, ChainType::Solana]
}

fn selected_auditor_chain(state: &TuiState) -> ChainType {
    auditor_chains()
        .get(state.auditor_chain_index)
        .cloned()
        .unwrap_or(ChainType::Bitcoin)
}

fn parse_auditor_index(value: &str) -> Result<u32, String> {
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| "Indice de auditor invalido.".to_string())
}

fn increment_numeric_string(value: &mut String) {
    let current = value.trim().parse::<u32>().unwrap_or(0);
    *value = current.saturating_add(1).to_string();
}

fn decrement_numeric_string(value: &mut String) {
    let current = value.trim().parse::<u32>().unwrap_or(0);
    *value = current.saturating_sub(1).to_string();
}

fn public_key_address_label(chain: &ChainType, public_key: &[u8], network: Network) -> String {
    match address::public_address_for_network(chain, public_key, network) {
        Ok(address) => address,
        Err(_) => match chain {
            ChainType::Bitcoin => format!(
                "btc-pubkey:{}",
                truncate_chars(&hex::encode(public_key), 72)
            ),
            ChainType::Ethereum => format!(
                "eth-pubkey:{}",
                truncate_chars(&hex::encode(public_key), 72)
            ),
            ChainType::Solana => format!(
                "sol-pubkey:{}",
                truncate_chars(&hex::encode(public_key), 72)
            ),
            ChainType::Monero => "Monero no soportado en auditor TUI.".to_string(),
            ChainType::Zcash => "Zcash no soportado en auditor TUI.".to_string(),
            ChainType::Starknet => "Starknet no soportado en auditor TUI.".to_string(),
        },
    }
}

fn chain_support_status(chain: &ChainType) -> &'static str {
    match chain {
        ChainType::Bitcoin => "firma soportada parcial: parser BTC raw + firma secp256k1",
        ChainType::Ethereum => "firma soportada parcial: EVM basico + ERC-20 transfer",
        ChainType::Solana => "firma soportada parcial: transferencia nativa",
        ChainType::Monero => "solo auditoria/no soportada: requiere adaptador Monero separado",
        ChainType::Zcash => "solo auditoria/no soportada: requiere adaptador Zcash separado",
        ChainType::Starknet => "solo auditoria/no soportada: requiere adaptador Starknet separado",
    }
}

fn derivation_path_label(chain: &ChainType, account: u32, index: u32) -> String {
    address::derivation_path(chain, account, index)
}

fn selected_auditor_indexes(state: &TuiState) -> (u32, u32) {
    let account_index = state
        .auditor_account_index
        .trim()
        .parse::<u32>()
        .unwrap_or(0);
    let address_index = state
        .auditor_address_index
        .trim()
        .parse::<u32>()
        .unwrap_or(0);
    (account_index, address_index)
}

fn wallet_qr_payload(state: &TuiState) -> Option<String> {
    if state.auditor_address.is_empty() {
        return None;
    }
    let chain = selected_auditor_chain(state);
    let (account_index, address_index) = selected_auditor_indexes(state);
    let derivation_path = derivation_path_label(&chain, account_index, address_index);
    Some(
        serde_json::json!({
            "type": "livencrypt-wallet",
            "v": 1,
            "chain": format!("{:?}", chain),
            "account": account_index,
            "index": address_index,
            "path": derivation_path,
            "address": state.auditor_address,
        })
        .to_string(),
    )
}

fn wallet_clipboard_payload(state: &TuiState) -> Option<String> {
    if state.auditor_address.is_empty() {
        return None;
    }
    let chain = selected_auditor_chain(state);
    let (account_index, address_index) = selected_auditor_indexes(state);
    let derivation_path = derivation_path_label(&chain, account_index, address_index);
    Some(
        serde_json::json!({
            "type": "livencrypt-wallet-link",
            "version": 1,
            "chain": format!("{:?}", chain),
            "account": account_index,
            "address_index": address_index,
            "derivation_path": derivation_path,
            "address": state.auditor_address,
            "public_key_hex": state.auditor_public_key_hex,
            "scope": "public-address-only",
            "warning": "No contiene clave privada ni frase secreta",
        })
        .to_string(),
    )
}

fn copy_wallet_link_payload(state: &mut TuiState) {
    if !require_boot_shield_confirmation_for_auditor(state, PendingAction::AuditorCopy) {
        return;
    }
    let Some(payload) = wallet_clipboard_payload(state) else {
        state.auditor_status = "Primero derive una direccion para copiar el vinculo.".to_string();
        return;
    };
    match write_system_clipboard(&payload) {
        Ok(()) => {
            state.auditor_status =
                "Vinculo publico de wallet copiado para extension/aplicacion.".to_string();
        }
        Err(error) => {
            state.auditor_status = format!(
                "Vinculo generado, pero no se pudo copiar al portapapeles: {}",
                error
            );
        }
    }
}

fn account_policy_label(
    policies: &[AccountPolicy],
    chain: &ChainType,
    account: u32,
    index: u32,
    global_tx: &str,
    global_fiat: &str,
    global_currency: &str,
) -> Vec<Line<'static>> {
    if let Some(policy) = policies
        .iter()
        .find(|policy| policy.applies_to(chain, account, index))
    {
        return vec![
            Line::from(format!("Politica: {}", policy.label)),
            Line::from(format!("Max TX ventana: {}", policy.max_tx_per_window)),
            Line::from(format!(
                "Max fiat: {} {}",
                policy
                    .max_fiat_value
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "sin limite especifico".to_string()),
                policy.fiat_currency
            )),
            Line::from(format!(
                "Destinos permitidos: {} | Contratos: {}",
                policy.allowed_destinations.len(),
                policy.allowed_contracts.len()
            )),
            Line::from(format!(
                "Reglas programadas: {}",
                policy
                    .scheduled_rules
                    .iter()
                    .filter(|rule| rule.enabled)
                    .count()
            )),
        ];
    }

    vec![
        Line::from("Politica: global"),
        Line::from(format!("Max TX diario: {}", global_tx)),
        Line::from(format!(
            "Max fiat diario: {} {}",
            global_fiat, global_currency
        )),
        Line::from("Sin reglas especificas por cuenta/direccion."),
    ]
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

fn run_app<B>(terminal: &mut Terminal<B>) -> io::Result<()>
where
    B: Backend,
    io::Error: From<B::Error>,
{
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
                fiat_value,
                fiat_currency,
            }) => {
                state.cached_tx_count = tx_count;
                state.cached_volume_units = volume_units;
                state.cached_fiat_value = fiat_value;
                state.input_fiat_currency = fiat_currency;
            }
            Ok(Web3WorkerEvent::SyncRules(rules)) => {
                state.allowed_dex_contracts = rules.allowed_dex_contracts;
                state.allowed_cex_destinations = rules.allowed_cex_destinations;
                state.account_policies = rules.account_policies;
                state.price_quotes = rules.price_book.quotes;
                if state.gateway_focused_field != 0 {
                    state.input_max_tx = rules.max_daily_tx.to_string();
                }
                if state.gateway_focused_field != 1 {
                    state.input_max_volume = rules.max_daily_crypto_amount.to_string();
                }
                if state.gateway_focused_field != 2 {
                    state.input_max_fiat_value = rules.max_daily_fiat_value.to_string();
                }
                if state.gateway_focused_field != 3 {
                    state.input_fiat_currency = rules.fiat_currency;
                }
            }
            Ok(Web3WorkerEvent::AccountPoliciesUpdated(policies)) => {
                state.account_policies = policies;
                if state.web3_policy_selected >= state.account_policies.len() {
                    state.web3_policy_selected = state.account_policies.len().saturating_sub(1);
                }
            }
            Ok(Web3WorkerEvent::PriceBookUpdated(price_book)) => {
                state.price_quotes = price_book.quotes;
            }
            Ok(Web3WorkerEvent::RpcInspectorResult { label, result }) => match result {
                Ok(value) => {
                    match label.as_str() {
                        "balance" => state.web3_rpc_balance = value.clone(),
                        "nonce" => state.web3_rpc_nonce = value.clone(),
                        "fee" => state.web3_rpc_fee = value.clone(),
                        "tx_status" => state.web3_rpc_tx_status = value.clone(),
                        _ => {}
                    }
                    state.web3_rpc_status = format!("{} OK: {}", label, value);
                }
                Err(error) => {
                    state.web3_rpc_status = format!("{}: {}", label, error);
                }
            },
            Ok(Web3WorkerEvent::SigningRequest(preview)) => {
                state.pending_signing_preview = Some(preview);
                state.screen = Screen::WalletGateway;
                state.status = "Firma Web3 pendiente de autorizacion local.".to_string();
            }
            Ok(Web3WorkerEvent::BroadcastRequest(preview)) => {
                state.pending_broadcast_preview = Some(preview);
                state.screen = Screen::WalletGateway;
                state.status = "Broadcast Web3 pendiente de autorizacion local.".to_string();
            }
            Ok(Web3WorkerEvent::PublicKeyDerived {
                chain,
                account_index,
                address_index,
                result,
            }) => match result {
                Ok(public_key) => {
                    state.auditor_public_key_hex = hex::encode(&public_key);
                    state.auditor_address =
                        public_key_address_label(&chain, &public_key, state.auditor_network);
                    state.auditor_segwit_address = match chain {
                        ChainType::Bitcoin => {
                            address::bitcoin_p2wpkh_address(&public_key, state.auditor_network)
                                .unwrap_or_else(|error| format!("segwit no disponible: {}", error))
                        }
                        _ => String::new(),
                    };
                    recompute_auditor_match(state);
                    state.auditor_status = format!(
                        "Derivacion OK: {:?} cuenta {} indice {}.",
                        chain, account_index, address_index
                    );
                    state.add_log(format!(
                        "Auditor Web3: {:?} cuenta {} indice {} derivado.",
                        chain, account_index, address_index
                    ));
                }
                Err(error) => {
                    state.auditor_public_key_hex.zeroize();
                    state.auditor_public_key_hex.clear();
                    state.auditor_address.zeroize();
                    state.auditor_address.clear();
                    state.auditor_segwit_address.clear();
                    state.auditor_match_status.clear();
                    state.auditor_status = format!("Error derivando clave publica: {}", error);
                }
            },
            Ok(Web3WorkerEvent::DerivationVerified {
                chain,
                account_index,
                address_index,
                matches,
                address,
            }) => {
                if matches {
                    state.auditor_status = format!(
                        "Verificacion OK ✔: {:?} cuenta {} indice {} reproducible ({}).",
                        chain, account_index, address_index, address
                    );
                } else {
                    state.auditor_status = format!(
                        "Verificacion FALLIDA ✘: {:?} cuenta {} indice {} NO reproducible.",
                        chain, account_index, address_index
                    );
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
    // Pegado explícito Ctrl+V en cualquier campo de datos (validado por tipo).
    // El editor de texto (TextCipher) mantiene su propio manejo de Ctrl+V.
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('v') | KeyCode::Char('V'))
        && state.screen != Screen::TextCipher
        && !state.is_processing
    {
        paste_clipboard_into_focused(state);
        return;
    }
    if state.show_reauth_modal {
        handle_reauth_modal_key(state, key);
        return;
    }
    if state.pending_signing_preview.is_some() {
        handle_signing_authorization_key(state, key);
        return;
    }
    if state.pending_broadcast_preview.is_some() {
        handle_broadcast_authorization_key(state, key);
        return;
    }
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
        Screen::AuditMonitor => handle_audit_monitor_key(state, key),
        Screen::FirmwareStaging => handle_firmware_staging_key(state, key),
        Screen::SandboxManager => handle_sandbox_manager_key(state, key),
        Screen::RecoveryMode => handle_recovery_key(state, key),
        Screen::InstallProfile => handle_back_to_dashboard_key(state, key),
        Screen::WalletGateway => handle_wallet_gateway_key(state, key),
        Screen::WalletAuditor => handle_wallet_auditor_key(state, key),
        Screen::NodesManager => handle_nodes_manager_key(state, key),
        Screen::Web3AccountPolicies => handle_web3_account_policies_key(state, key),
        Screen::Web3ScheduledRules => handle_web3_scheduled_rules_key(state, key),
        Screen::Web3PriceOracle => handle_web3_price_oracle_key(state, key),
        Screen::Web3RpcInspector => handle_web3_rpc_inspector_key(state, key),
        Screen::Web3AccountEditor => handle_web3_account_policies_key(state, key),
    }
}

fn gateway_field_mut(state: &mut TuiState) -> Option<&mut String> {
    match state.gateway_focused_field {
        0 => Some(&mut state.input_max_tx),
        1 => Some(&mut state.input_max_volume),
        2 => Some(&mut state.input_max_fiat_value),
        3 => Some(&mut state.input_fiat_currency),
        4 => Some(&mut state.input_price_asset),
        5 => Some(&mut state.input_price_value),
        6 => Some(&mut state.input_new_dex_id),
        7 => Some(&mut state.input_new_cex_id),
        _ => None,
    }
}

fn auditor_field_mut(state: &mut TuiState) -> Option<&mut String> {
    match state.auditor_focus {
        1 => Some(&mut state.auditor_account_index),
        2 => Some(&mut state.auditor_address_index),
        3 => Some(&mut state.auditor_expected_input),
        _ => None,
    }
}

fn reauth_field_mut(state: &mut TuiState) -> Option<&mut String> {
    match state.reauth_focus {
        0..=4 => Some(&mut state.reauth_cajas[state.reauth_focus]),
        5 => Some(&mut state.reauth_phrase),
        6..=10 => Some(&mut state.reauth_secondary_cajas[state.reauth_focus - 6]),
        _ => Some(&mut state.reauth_secondary_phrase),
    }
}

/// Campo de entrada enfocado en la pantalla/modal activos (destino del pegado de portapapeles).
fn focused_paste_target(state: &mut TuiState) -> Option<&mut String> {
    if state.show_reauth_modal {
        return reauth_field_mut(state);
    }
    if state.show_breaker_reset {
        return if state.reset_focus_index < 5 {
            Some(&mut state.reset_cajas[state.reset_focus_index])
        } else {
            Some(&mut state.reset_phrase)
        };
    }
    match state.screen {
        Screen::WalletGateway => gateway_field_mut(state),
        Screen::WalletAuditor => auditor_field_mut(state),
        Screen::Web3AccountPolicies | Screen::Web3AccountEditor => policy_field_mut(state),
        Screen::Web3ScheduledRules => schedule_field_mut(state),
        Screen::Web3PriceOracle => price_field_mut(state),
        Screen::Web3RpcInspector => rpc_field_mut(state),
        Screen::Settings => Some(active_settings_field_mut(state)),
        Screen::FileCipher => Some(active_file_field_mut(state)),
        _ => None,
    }
}

/// Tipo de dato aceptado por un campo de entrada.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldKind {
    /// Entero sin signo (índices, contadores): solo dígitos.
    Integer,
    /// Entero con signo (cajas -999..999): dígitos y un '-' inicial.
    SignedInteger,
    /// Decimal (USD/BTC/ETH y montos): dígitos y un único separador decimal.
    Decimal,
    /// Texto libre (direcciones, IDs, etiquetas, rutas, frases): texto+números+especiales.
    Text,
}

/// Tipo del campo enfocado en la pantalla/modal activos.
fn focused_field_kind(state: &TuiState) -> FieldKind {
    if state.show_reauth_modal {
        return match state.reauth_focus {
            0..=4 | 6..=10 => FieldKind::SignedInteger,
            _ => FieldKind::Text,
        };
    }
    if state.show_breaker_reset {
        return if state.reset_focus_index < 5 {
            FieldKind::SignedInteger
        } else {
            FieldKind::Text
        };
    }
    match state.screen {
        Screen::WalletGateway => match state.gateway_focused_field {
            0 => FieldKind::Integer,
            1 | 2 | 5 => FieldKind::Decimal,
            _ => FieldKind::Text,
        },
        Screen::WalletAuditor => match state.auditor_focus {
            1 | 2 => FieldKind::Integer,
            _ => FieldKind::Text,
        },
        Screen::Web3AccountPolicies | Screen::Web3AccountEditor => match state.web3_policy_focus {
            1 | 2 | 4 => FieldKind::Integer,
            5 | 6 | 12 => FieldKind::Decimal,
            _ => FieldKind::Text,
        },
        Screen::Web3ScheduledRules => match state.web3_schedule_focus {
            3 | 8 => FieldKind::Integer,
            4 | 5 => FieldKind::Decimal,
            _ => FieldKind::Text,
        },
        Screen::Web3PriceOracle => match state.web3_price_focus {
            2 => FieldKind::Decimal,
            3 => FieldKind::Integer,
            _ => FieldKind::Text,
        },
        Screen::Settings => match state.settings_focus {
            0..=4 | 7..=11 | 13..=17 => FieldKind::SignedInteger,
            _ => FieldKind::Text,
        },
        _ => FieldKind::Text,
    }
}

/// Inserta `input` en `field` aceptando solo los caracteres válidos para el tipo de campo.
fn sanitize_into_field(kind: FieldKind, field: &mut String, input: &str, max_len: usize) {
    for raw in input.chars() {
        if field.chars().count() >= max_len {
            break;
        }
        match kind {
            FieldKind::Integer => {
                if raw.is_ascii_digit() {
                    field.push(raw);
                }
            }
            FieldKind::SignedInteger => {
                if raw.is_ascii_digit() || (raw == '-' && field.is_empty()) {
                    field.push(raw);
                }
            }
            FieldKind::Decimal => {
                let character = if raw == ',' { '.' } else { raw };
                if character.is_ascii_digit() {
                    field.push(character);
                } else if character == '.' && !field.contains('.') {
                    field.push('.');
                }
            }
            FieldKind::Text => {
                if !raw.is_control() {
                    field.push(raw);
                }
            }
        }
    }
}

/// Inserta texto (de teclado o portapapeles) en el campo enfocado, validado por su tipo.
fn insert_text_into_focused(state: &mut TuiState, text: &str) {
    let kind = focused_field_kind(state);
    let recompute = state.screen == Screen::WalletAuditor && state.auditor_focus == 3;
    if let Some(field) = focused_paste_target(state) {
        sanitize_into_field(kind, field, text, 512);
    }
    if recompute {
        recompute_auditor_match(state);
    }
}

/// Lee el portapapeles del sistema y lo pega (validado por tipo) en el campo enfocado.
fn paste_clipboard_into_focused(state: &mut TuiState) {
    match read_system_clipboard() {
        Ok(text) => {
            if focused_paste_target(state).is_none() {
                state.system_notification =
                    "No hay campo de entrada enfocado para pegar.".to_string();
                return;
            }
            insert_text_into_focused(state, &text);
            state.system_notification = "Datos pegados desde el portapapeles.".to_string();
        }
        Err(error) => {
            state.system_notification = format!("No se pudo leer el portapapeles: {}", error);
        }
    }
}

fn handle_paste_event(state: &mut TuiState, text: String) {
    if state.is_processing {
        return;
    }
    // El editor de texto mantiene su pegado multilinea propio.
    if state.screen == Screen::TextCipher
        && !state.show_file_browser
        && !state.show_matrix_config
        && !state.show_reauth_modal
        && !state.show_breaker_reset
    {
        paste_text_into_text_cipher(state, &text);
        return;
    }
    if state.show_file_browser || state.show_matrix_config {
        return;
    }
    insert_text_into_focused(state, &text);
}

fn handle_mouse_event(state: &mut TuiState, mouse: MouseEvent) {
    if state.show_reauth_modal {
        return;
    }
    if state.pending_signing_preview.is_some() {
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            let area = terminal_area();
            let inner = centered_area(area, 94, 88);
            let popup = centered_area(inner, 78, 56);
            if point_in_rect(mouse.column, mouse.row, popup) {
                let approve = mouse.column < popup.x + popup.width / 2;
                submit_signing_authorization(state, approve);
            }
        }
        return;
    }
    if state.pending_broadcast_preview.is_some() {
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            let area = terminal_area();
            let inner = centered_area(area, 94, 88);
            let popup = centered_area(inner, 78, 56);
            if point_in_rect(mouse.column, mouse.row, popup) {
                let approve = mouse.column < popup.x + popup.width / 2;
                submit_broadcast_authorization(state, approve);
            }
        }
        return;
    }
    match mouse.kind {
        MouseEventKind::ScrollUp => handle_mouse_scroll(state, true),
        MouseEventKind::ScrollDown => handle_mouse_scroll(state, false),
        MouseEventKind::Down(MouseButton::Left) => {
            // Detección de doble clic (≤400 ms y misma celda ±1): el primer clic enfoca el
            // campo; el segundo pega del portapapeles (validado por tipo) en ese campo.
            let now = current_unix_millis();
            let is_double = now.saturating_sub(state.last_click_millis) <= 400
                && state.last_click_col.abs_diff(mouse.column) <= 1
                && state.last_click_row.abs_diff(mouse.row) <= 1;
            state.last_click_millis = now;
            state.last_click_col = mouse.column;
            state.last_click_row = mouse.row;
            handle_mouse(state, mouse);
            if is_double && !state.is_processing && focused_paste_target(state).is_some() {
                paste_clipboard_into_focused(state);
            }
        }
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
        Screen::Settings => {
            if up {
                state.settings_scroll = state.settings_scroll.saturating_sub(1);
            } else {
                state.settings_scroll = state.settings_scroll.saturating_add(1).min(24);
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
        | Screen::RecoveryMode
        | Screen::InstallProfile
        | Screen::NodesManager
        | Screen::Web3AccountPolicies
        | Screen::Web3ScheduledRules
        | Screen::Web3PriceOracle
        | Screen::Web3RpcInspector
        | Screen::Web3AccountEditor => {
            if mouse.row <= inner.y + 1 {
                state.screen = Screen::Dashboard;
            }
        }
        Screen::SandboxManager => handle_sandbox_manager_mouse(state, mouse, inner),
        Screen::WalletGateway => handle_wallet_gateway_mouse(state, mouse, inner),
        Screen::WalletAuditor => handle_wallet_auditor_mouse(state, mouse, inner),
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
    let form_height = if state.unlock_requires_secondary() {
        15
    } else {
        10
    };
    let constraints = if hardening.warnings.is_empty() {
        vec![
            Constraint::Length(4),
            Constraint::Length(form_height),
            Constraint::Length(8),
            Constraint::Min(4),
        ]
    } else {
        vec![
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Length(form_height),
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
        let selected = match offset {
            1..=5 => Some((offset - 1) as usize),
            6 => Some(5),
            9..=13 if state.unlock_requires_secondary() => Some((offset - 3) as usize),
            14 if state.unlock_requires_secondary() => Some(11),
            _ => None,
        };
        if let Some(selected) = selected {
            state.focus = selected.min(unlock_field_count(state).saturating_sub(1));
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
            Constraint::Length(17),
            Constraint::Min(4),
        ])
        .split(area);
    let list = chunks[1];
    if !point_in_rect(mouse.column, mouse.row, list) {
        return;
    }
    match mouse.row.saturating_sub(list.y + 1) {
        3 => state.screen = Screen::WalletGateway,
        4 => state.screen = Screen::WalletAuditor,
        5 => state.screen = Screen::TextCipher,
        6 => state.screen = Screen::FileCipher,
        7 => state.screen = Screen::TemplateEditor,
        8 => {
            state.settings_destructive_auditor_reauth = load_destructive_reauth_flag();
            state.screen = Screen::Settings;
        }
        9 => {
            state.refresh_integrity();
            state.screen = Screen::SystemMonitor;
        }
        10 => state.screen = Screen::AuditMonitor,
        11 => state.screen = Screen::FirmwareStaging,
        12 => state.screen = Screen::SandboxManager,
        13 => state.screen = Screen::RecoveryMode,
        14 => state.screen = Screen::InstallProfile,
        15 => state.lock(),
        16 => {
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
    let row = mouse
        .row
        .saturating_sub(chunks[0].y + 1)
        .saturating_add(state.settings_scroll);
    match row {
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
        11..=15 => state.settings_focus = mouse.row.saturating_sub(chunks[0].y + 5) as usize,
        16 => state.settings_focus = 12,
        20..=24 => state.settings_focus = mouse.row.saturating_sub(chunks[0].y + 7) as usize,
        25 => state.settings_focus = 18,
        27 => state.settings_focus = 21,
        30 => state.settings_focus = 19,
        31 => state.settings_focus = 20,
        0 => {}
        row if row >= 38 => {
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
    let field_count = unlock_field_count(state);
    match key.code {
        KeyCode::Esc => {
            state.clear_secret_fields();
            state.should_quit = true;
        }
        KeyCode::Tab => state.focus = (state.focus + 1) % field_count,
        KeyCode::BackTab => {
            state.focus = if state.focus == 0 {
                field_count - 1
            } else {
                state.focus - 1
            }
        }
        KeyCode::Backspace => pop_unlock_field(state),
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
            if state.focus + 1 < field_count {
                state.focus += 1;
            } else {
                state.unlock();
            }
        }
        KeyCode::F(10) => state.unlock(),
        KeyCode::Char(value) => {
            if matches!(state.focus, 0..=4 | 6..=10) {
                if !push_unlock_box_char(state, value) {
                    state.status = "Caja fuera de rango permitido (-999..999).".to_string();
                }
            } else {
                push_unlock_phrase_char(state, value);
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
            state.settings_destructive_auditor_reauth = load_destructive_reauth_flag();
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
        KeyCode::Char('k') | KeyCode::Char('K') => state.screen = Screen::WalletAuditor,
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

fn handle_audit_monitor_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::Dashboard,
        KeyCode::Char('v') | KeyCode::Char('V') => verify_web3_audit_chain_ui(state),
        _ => {}
    }
}

/// C.4: verifica la integridad + firma del log de auditoria Web3 y muestra el resultado.
fn verify_web3_audit_chain_ui(state: &mut TuiState) {
    match livencrypt_lib::crypto::blockchain::web3_audit::verify_local_audit_chain() {
        Ok(()) => {
            state.system_notification =
                "Cadena de auditoria Web3 integra y firmada correctamente.".to_string();
        }
        Err(error) => {
            state.system_notification = format!("AUDITORIA WEB3: {}", error);
        }
    }
}

fn submit_wallet_auditor_derivation(state: &mut TuiState) {
    if !require_boot_shield_confirmation_for_auditor(state, PendingAction::AuditorDerive) {
        return;
    }
    let Ok(account_index) = parse_auditor_index(&state.auditor_account_index) else {
        state.auditor_status = "Cuenta invalida: use un entero sin signo.".to_string();
        return;
    };
    let Ok(address_index) = parse_auditor_index(&state.auditor_address_index) else {
        state.auditor_status = "Indice invalido: use un entero sin signo.".to_string();
        return;
    };
    let chain = selected_auditor_chain(state);

    if let Some(tx) = &state.web3_cmd_tx {
        let result = tx.send(Web3WorkerCmd::DerivePublicKey {
            chain: chain.clone(),
            network: state.auditor_network,
            account_index,
            address_index,
        });
        if result.is_ok() {
            state.auditor_status = format!(
                "Solicitada derivacion {:?} cuenta {} indice {}.",
                chain, account_index, address_index
            );
        } else {
            state.auditor_status = "Web3 no acepta solicitudes en este momento.".to_string();
        }
    } else {
        state.auditor_status =
            "Web3 no inicializado: desbloquee Boot Shield o configure el vault.".to_string();
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn current_unix_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

const DESTRUCTIVE_REAUTH_KEY: &str = "auditor_destructive_reauth";

/// Lee en vivo del vault si la re-confirmacion del auditor debe usar el verificador
/// DESTRUCTIVO (boot_shield_unlock: un fallo cuenta intento y puede destruir el vault).
fn load_destructive_reauth_flag() -> bool {
    security::vault::read_unlocked_settings()
        .ok()
        .flatten()
        .and_then(|map| map.get(DESTRUCTIVE_REAUTH_KEY).cloned())
        .map(|value| value == "true")
        .unwrap_or(false)
}

fn persist_destructive_reauth_flag(enabled: bool) -> Result<(), String> {
    let mut entries = std::collections::HashMap::new();
    entries.insert(
        DESTRUCTIVE_REAUTH_KEY.to_string(),
        if enabled { "true" } else { "false" }.to_string(),
    );
    security::vault::update_unlocked_settings(entries).map(|_| ())
}

fn toggle_destructive_auditor_reauth(state: &mut TuiState) {
    let new_value = !state.settings_destructive_auditor_reauth;
    match persist_destructive_reauth_flag(new_value) {
        Ok(()) => {
            state.settings_destructive_auditor_reauth = new_value;
            state.status = if new_value {
                "Re-auth destructiva auditor: ON. Un fallo DESTRUYE el vault (tenga backup externo)."
                    .to_string()
            } else {
                "Re-auth destructiva auditor: OFF (verificacion read-only segura).".to_string()
            };
        }
        Err(error) => {
            state.status = format!("No se pudo guardar el ajuste (vault bloqueado?): {}", error);
        }
    }
}

/// Gate C.4: exige re-confirmacion Boot Shield reciente antes de derivar/verificar/exportar
/// en el auditor. Devuelve true si la sesion re-valido dentro de la ventana; si no, arma el
/// modal de re-autenticacion y devuelve false para abortar la accion en curso.
fn require_boot_shield_confirmation_for_auditor(
    state: &mut TuiState,
    action: PendingAction,
) -> bool {
    const AUDITOR_REAUTH_WINDOW_SECS: u64 = 120;
    let now = current_unix_secs();
    if state.last_identity_confirmation_unix != 0
        && now.saturating_sub(state.last_identity_confirmation_unix) <= AUDITOR_REAUTH_WINDOW_SECS
    {
        return true;
    }
    state.pending_action_after_reauth = Some(action);
    state.reauth_focus = 0;
    zeroize_boxes(&mut state.reauth_cajas);
    state.reauth_phrase.zeroize();
    state.reauth_phrase.clear();
    state.show_reauth_modal = true;
    state.auditor_status = "Re-confirmacion Boot Shield requerida para el auditor.".to_string();
    false
}

/// Número de campos del modal de re-auth: 6 (primaria) o 12 (con doble credencial).
fn reauth_field_count(state: &TuiState) -> usize {
    if state.unlock_requires_secondary() {
        12
    } else {
        6
    }
}

fn handle_reauth_modal_key(state: &mut TuiState, key: KeyEvent) {
    let count = reauth_field_count(state);
    match key.code {
        KeyCode::Esc => cancel_reauth(state),
        KeyCode::Tab => state.reauth_focus = (state.reauth_focus + 1) % count,
        KeyCode::BackTab => {
            state.reauth_focus = if state.reauth_focus == 0 {
                count - 1
            } else {
                state.reauth_focus - 1
            };
        }
        KeyCode::Backspace => match state.reauth_focus {
            0..=4 => {
                state.reauth_cajas[state.reauth_focus].pop();
            }
            5 => {
                state.reauth_phrase.pop();
            }
            6..=10 => {
                state.reauth_secondary_cajas[state.reauth_focus - 6].pop();
            }
            _ => {
                state.reauth_secondary_phrase.pop();
            }
        },
        KeyCode::Enter => submit_reauth(state),
        KeyCode::Char(value) => match state.reauth_focus {
            0..=4 => {
                let target = &mut state.reauth_cajas[state.reauth_focus];
                if target.len() < 32 {
                    target.push(value);
                }
            }
            5 => {
                if state.reauth_phrase.len() < 120 {
                    state.reauth_phrase.push(value);
                }
            }
            6..=10 => {
                let target = &mut state.reauth_secondary_cajas[state.reauth_focus - 6];
                if target.len() < 32 {
                    target.push(value);
                }
            }
            _ => {
                if state.reauth_secondary_phrase.len() < 120 {
                    state.reauth_secondary_phrase.push(value);
                }
            }
        },
        _ => {}
    }
}

fn cancel_reauth(state: &mut TuiState) {
    state.clear_reauth_secret_fields();
    state.show_reauth_modal = false;
    state.pending_action_after_reauth = None;
    state.auditor_status = "Re-confirmacion cancelada.".to_string();
}

fn submit_reauth(state: &mut TuiState) {
    let Ok(cajas) = parse_boxes(&state.reauth_cajas) else {
        state.auditor_status = "Cajas invalidas: use enteros con signo.".to_string();
        return;
    };
    if state.reauth_phrase.trim().is_empty() {
        state.auditor_status = "Frase maestra requerida.".to_string();
        return;
    }
    let requires_secondary = state.unlock_requires_secondary();
    let (secondary_cajas, secondary_frase): (Option<[i64; 5]>, Option<String>) = if requires_secondary
    {
        let Ok(sc) = parse_boxes(&state.reauth_secondary_cajas) else {
            state.auditor_status = "Cajas secundarias invalidas: use enteros con signo.".to_string();
            return;
        };
        if state.reauth_secondary_phrase.trim().is_empty() {
            state.auditor_status = "Frase secundaria requerida.".to_string();
            return;
        }
        (Some(sc), Some(state.reauth_secondary_phrase.clone()))
    } else {
        (None, None)
    };
    let destructive = load_destructive_reauth_flag();
    let verified = if destructive {
        // Verificador DESTRUCTIVO opcional: un fallo incrementa el contador de intentos
        // y puede destruir el vault / disparar la clave de coaccion. Solo si el usuario lo
        // activo a proposito en Configuraciones (debe tener backup externo).
        security::vault::boot_shield_unlock(
            cajas,
            state.reauth_phrase.clone(),
            secondary_cajas,
            secondary_frase.clone(),
        )
        .is_ok()
    } else {
        security::vault::verify_credentials_readonly_dual(
            cajas,
            &state.reauth_phrase,
            secondary_cajas,
            secondary_frase.as_deref(),
        )
    };
    state.clear_reauth_secret_fields();
    state.show_reauth_modal = false;
    if !verified {
        state.pending_action_after_reauth = None;
        state.auditor_status = if destructive {
            "Re-confirmacion fallida: credenciales invalidas (modo destructivo activo).".to_string()
        } else {
            "Re-confirmacion fallida: credenciales invalidas.".to_string()
        };
        return;
    }
    state.last_identity_confirmation_unix = current_unix_secs();
    let action = state.pending_action_after_reauth.take();
    state.auditor_status = "Identidad re-confirmada; ejecutando accion del auditor.".to_string();
    match action {
        Some(PendingAction::AuditorDerive) => submit_wallet_auditor_derivation(state),
        Some(PendingAction::AuditorVerify) => submit_wallet_auditor_verification(state),
        Some(PendingAction::AuditorCopy) => copy_wallet_link_payload(state),
        None => {}
    }
}

fn submit_wallet_auditor_verification(state: &mut TuiState) {
    if !require_boot_shield_confirmation_for_auditor(state, PendingAction::AuditorVerify) {
        return;
    }
    let Ok(account_index) = parse_auditor_index(&state.auditor_account_index) else {
        state.auditor_status = "Cuenta invalida: use un entero sin signo.".to_string();
        return;
    };
    let Ok(address_index) = parse_auditor_index(&state.auditor_address_index) else {
        state.auditor_status = "Indice invalido: use un entero sin signo.".to_string();
        return;
    };
    let chain = selected_auditor_chain(state);

    if let Some(tx) = &state.web3_cmd_tx {
        let result = tx.send(Web3WorkerCmd::VerifyDerivation {
            chain: chain.clone(),
            network: state.auditor_network,
            account_index,
            address_index,
        });
        if result.is_ok() {
            state.auditor_status = format!(
                "Solicitada verificacion (doble derivacion) {:?} cuenta {} indice {}.",
                chain, account_index, address_index
            );
        } else {
            state.auditor_status = "Web3 no acepta solicitudes en este momento.".to_string();
        }
    } else {
        state.auditor_status =
            "Web3 no inicializado: desbloquee Boot Shield o configure el vault.".to_string();
    }
}

fn toggle_auditor_network(state: &mut TuiState) {
    state.auditor_network = match state.auditor_network {
        Network::Mainnet => Network::Testnet,
        Network::Testnet => Network::Mainnet,
    };
    // La red cambia la derivacion/direccion: invalidar la vista actual.
    state.auditor_address.clear();
    state.auditor_segwit_address.clear();
    state.auditor_match_status.clear();
    state.auditor_status = format!(
        "Red: {:?}. Pulse Enter para derivar de nuevo.",
        state.auditor_network
    );
}

/// C.3: valida el checksum de la direccion introducida y la compara con la derivada.
fn recompute_auditor_match(state: &mut TuiState) {
    let expected = state.auditor_expected_input.trim().to_string();
    if expected.is_empty() {
        state.auditor_match_status.clear();
        return;
    }
    if state.auditor_address.is_empty() {
        state.auditor_match_status = "Primero derive una direccion.".to_string();
        return;
    }
    let chain = selected_auditor_chain(state);
    let checksum_ok = match chain {
        ChainType::Ethereum => address::validate_ethereum_address_checksum(&expected),
        ChainType::Bitcoin => address::validate_bitcoin_address_checksum(&expected).is_ok(),
        ChainType::Solana => address::validate_solana_address(&expected).is_ok(),
        _ => true,
    };
    if !checksum_ok {
        state.auditor_match_status =
            "X Checksum de la direccion introducida invalido.".to_string();
        return;
    }
    let matches = if matches!(chain, ChainType::Ethereum) {
        state.auditor_address.eq_ignore_ascii_case(&expected)
    } else {
        state.auditor_address == expected || state.auditor_segwit_address == expected
    };
    state.auditor_match_status = if matches {
        "OK Coincide con la direccion derivada.".to_string()
    } else {
        "X NO coincide con la direccion derivada.".to_string()
    };
}

fn cycle_wallet_auditor_chain(state: &mut TuiState, forward: bool) {
    let count = auditor_chains().len();
    if forward {
        state.auditor_chain_index = (state.auditor_chain_index + 1) % count;
    } else if state.auditor_chain_index == 0 {
        state.auditor_chain_index = count - 1;
    } else {
        state.auditor_chain_index -= 1;
    }
    state.auditor_status = format!("Red seleccionada: {:?}.", selected_auditor_chain(state));
}

fn edit_wallet_auditor_number(target: &mut String, value: char) {
    if value.is_ascii_digit() && target.len() < 10 {
        target.push(value);
    }
}

fn handle_wallet_auditor_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::Dashboard,
        KeyCode::Tab => state.auditor_focus = (state.auditor_focus + 1) % 4,
        KeyCode::BackTab => {
            state.auditor_focus = if state.auditor_focus == 0 {
                3
            } else {
                state.auditor_focus - 1
            };
        }
        KeyCode::Left => {
            if state.auditor_focus == 0 {
                cycle_wallet_auditor_chain(state, false);
            }
        }
        KeyCode::Right => {
            if state.auditor_focus == 0 {
                cycle_wallet_auditor_chain(state, true);
            }
        }
        KeyCode::Char('-') => match state.auditor_focus {
            1 => decrement_numeric_string(&mut state.auditor_account_index),
            2 => decrement_numeric_string(&mut state.auditor_address_index),
            _ => {}
        },
        KeyCode::Char('+') => match state.auditor_focus {
            1 => increment_numeric_string(&mut state.auditor_account_index),
            2 => increment_numeric_string(&mut state.auditor_address_index),
            _ => {}
        },
        KeyCode::Backspace => match state.auditor_focus {
            1 => {
                state.auditor_account_index.pop();
            }
            2 => {
                state.auditor_address_index.pop();
            }
            3 => {
                state.auditor_expected_input.pop();
                recompute_auditor_match(state);
            }
            _ => {}
        },
        KeyCode::Char('C') | KeyCode::Char('c')
            if key.modifiers.contains(KeyModifiers::CONTROL) =>
        {
            copy_wallet_link_payload(state);
        }
        KeyCode::Char('C') | KeyCode::Char('c') if state.auditor_focus != 3 => {
            copy_wallet_link_payload(state);
        }
        KeyCode::Enter => submit_wallet_auditor_derivation(state),
        KeyCode::Char('V') | KeyCode::Char('v') if state.auditor_focus != 3 => {
            submit_wallet_auditor_verification(state)
        }
        KeyCode::Char(value) => match state.auditor_focus {
            0 => match value {
                '[' => cycle_wallet_auditor_chain(state, false),
                ']' => cycle_wallet_auditor_chain(state, true),
                'n' | 'N' => toggle_auditor_network(state),
                _ => {}
            },
            1 => edit_wallet_auditor_number(&mut state.auditor_account_index, value),
            2 => edit_wallet_auditor_number(&mut state.auditor_address_index, value),
            3 => {
                if state.auditor_expected_input.len() < 128 {
                    state.auditor_expected_input.push(value);
                    recompute_auditor_match(state);
                }
            }
            _ => {}
        },
        _ => {}
    }
}

fn handle_wallet_auditor_mouse(state: &mut TuiState, mouse: MouseEvent, area: Rect) {
    if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    if point_in_rect(mouse.column, mouse.row, chunks[3]) {
        let third = chunks[3].width / 3;
        if mouse.column < chunks[3].x + third {
            submit_wallet_auditor_derivation(state);
        } else if mouse.column < chunks[3].x + third.saturating_mul(2) {
            copy_wallet_link_payload(state);
        } else {
            state.screen = Screen::Dashboard;
        }
        return;
    }
    if point_in_rect(mouse.column, mouse.row, chunks[1]) {
        match mouse.row.saturating_sub(chunks[1].y + 1) {
            0 => {
                state.auditor_focus = 0;
                cycle_wallet_auditor_chain(state, true);
            }
            1 => state.auditor_focus = 1,
            2 => state.auditor_focus = 2,
            _ => {}
        }
    }
}

fn parse_sandbox_limits(state: &TuiState) -> Result<security::sandbox::SandboxLimits, String> {
    let memory_mib = state
        .sandbox_memory_mib
        .trim()
        .parse::<u64>()
        .map_err(|_| "Memoria sandbox invalida.".to_string())?
        .clamp(16, 8192);
    let cpu_seconds = state
        .sandbox_cpu_seconds
        .trim()
        .parse::<u64>()
        .map_err(|_| "CPU sandbox invalida.".to_string())?
        .clamp(1, 3600);
    let file_size_mib = state
        .sandbox_file_size_mib
        .trim()
        .parse::<u64>()
        .map_err(|_| "Limite de archivo sandbox invalido.".to_string())?
        .clamp(1, 4096);
    Ok(security::sandbox::SandboxLimits {
        memory_mib,
        cpu_seconds,
        file_size_mib,
    })
}

fn launch_sandbox_payload(state: &mut TuiState) {
    let path = PathBuf::from(state.sandbox_payload_path.trim());
    if path.as_os_str().is_empty() {
        state.sandbox_status = "Seleccione un binario para el sandbox.".to_string();
        return;
    }
    let limits = match parse_sandbox_limits(state) {
        Ok(limits) => limits,
        Err(error) => {
            state.sandbox_status = error;
            return;
        }
    };
    let mut binary_data = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            state.sandbox_status = format!("No se pudo leer payload: {}", error);
            return;
        }
    };
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("livencrypt-sandbox");
    match security::loader::load_and_execute_in_ram_with_limits(name, &mut binary_data, limits) {
        Ok(pid) => {
            state.sandbox_active_pids.push(pid);
            state.sandbox_selected_pid = state.sandbox_active_pids.len().saturating_sub(1);
            state.sandbox_status = format!("Payload lanzado en memfd con PID {}.", pid);
            state.add_log(format!("Sandbox memfd lanzado: PID {}", pid));
        }
        Err(error) => {
            binary_data.zeroize();
            state.sandbox_status = format!("No se pudo lanzar sandbox: {}", error);
        }
    }
}

fn terminate_selected_sandbox(state: &mut TuiState) {
    let Some(pid) = state
        .sandbox_active_pids
        .get(state.sandbox_selected_pid)
        .copied()
    else {
        state.sandbox_status = "No hay PID sandbox seleccionado.".to_string();
        return;
    };
    security::sandbox::terminate_sandbox(pid, "operador_tui");
    state.sandbox_active_pids.remove(state.sandbox_selected_pid);
    state.sandbox_selected_pid = state
        .sandbox_selected_pid
        .min(state.sandbox_active_pids.len().saturating_sub(1));
    state.sandbox_status = format!("SIGKILL enviado al PID {}.", pid);
}

fn active_sandbox_field_mut(state: &mut TuiState) -> &mut String {
    match state.sandbox_focus {
        0 => &mut state.sandbox_payload_path,
        1 => &mut state.sandbox_memory_mib,
        2 => &mut state.sandbox_cpu_seconds,
        3 => &mut state.sandbox_file_size_mib,
        _ => &mut state.sandbox_payload_path,
    }
}

fn handle_sandbox_manager_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::Dashboard,
        KeyCode::Tab => state.sandbox_focus = (state.sandbox_focus + 1) % 4,
        KeyCode::BackTab => {
            state.sandbox_focus = if state.sandbox_focus == 0 {
                3
            } else {
                state.sandbox_focus - 1
            };
        }
        KeyCode::Char('B') | KeyCode::Char('b') => open_file_browser(state),
        KeyCode::Enter => launch_sandbox_payload(state),
        KeyCode::Char('K') | KeyCode::Char('k') => terminate_selected_sandbox(state),
        KeyCode::Up => {
            state.sandbox_selected_pid = state.sandbox_selected_pid.saturating_sub(1);
        }
        KeyCode::Down => {
            if state.sandbox_selected_pid + 1 < state.sandbox_active_pids.len() {
                state.sandbox_selected_pid += 1;
            }
        }
        KeyCode::Backspace => {
            active_sandbox_field_mut(state).pop();
        }
        KeyCode::Char(value) => {
            if state.sandbox_focus == 0 {
                state.sandbox_payload_path.push(value);
            } else if value.is_ascii_digit() {
                active_sandbox_field_mut(state).push(value);
            }
        }
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
        KeyCode::Char('M') | KeyCode::Char('m') => {
            let profile = state.nodes.cycle_profile();
            state.status = format!(
                "Perfil Web3 activo: {}. Pulse G para guardar nodes.toml.",
                profile.label()
            );
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

fn handle_sandbox_manager_mouse(state: &mut TuiState, mouse: MouseEvent, area: Rect) {
    if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(7)])
        .split(area);
    if point_in_rect(mouse.column, mouse.row, chunks[0]) {
        let row = mouse.row.saturating_sub(chunks[0].y + 1);
        match row {
            1 => state.sandbox_focus = 0,
            2 => state.sandbox_focus = 1,
            3 => state.sandbox_focus = 2,
            4 => state.sandbox_focus = 3,
            6 => launch_sandbox_payload(state),
            7 => open_file_browser(state),
            _ => {}
        }
    } else if point_in_rect(mouse.column, mouse.row, chunks[1]) {
        let index = mouse.row.saturating_sub(chunks[1].y + 1) as usize;
        if index < state.sandbox_active_pids.len() {
            state.sandbox_selected_pid = index;
        }
    }
}

fn handle_signing_authorization_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::F(10) | KeyCode::Char('A') | KeyCode::Char('a') => {
            submit_signing_authorization(state, true);
        }
        KeyCode::Esc | KeyCode::Char('D') | KeyCode::Char('d') => {
            submit_signing_authorization(state, false);
        }
        _ => {
            state.status = "Firma pendiente: F10/A autoriza, Esc/D rechaza.".to_string();
        }
    }
}

fn submit_signing_authorization(state: &mut TuiState, approve: bool) {
    let Some(preview) = state.pending_signing_preview.take() else {
        return;
    };
    if let Some(tx) = &state.web3_cmd_tx {
        let _ = tx.send(Web3WorkerCmd::AuthorizeSigning {
            request_id: preview.request_id,
            approve,
        });
    }
    state.status = if approve {
        "Firma Web3 autorizada; procesando en backend.".to_string()
    } else {
        "Firma Web3 rechazada por operador.".to_string()
    };
}

fn handle_broadcast_authorization_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::F(10) | KeyCode::Char('A') | KeyCode::Char('a') => {
            submit_broadcast_authorization(state, true);
        }
        KeyCode::Esc | KeyCode::Char('D') | KeyCode::Char('d') => {
            submit_broadcast_authorization(state, false);
        }
        _ => {
            state.status = "Broadcast pendiente: F10/A autoriza, Esc/D rechaza.".to_string();
        }
    }
}

fn submit_broadcast_authorization(state: &mut TuiState, approve: bool) {
    let Some(preview) = state.pending_broadcast_preview.take() else {
        return;
    };
    if let Some(tx) = &state.web3_cmd_tx {
        let _ = tx.send(Web3WorkerCmd::AuthorizeBroadcast {
            request_id: preview.request_id,
            approve,
        });
    }
    state.status = if approve {
        "Broadcast Web3 autorizado; enviando a la red blockchain.".to_string()
    } else {
        "Broadcast Web3 rechazado por operador.".to_string()
    };
}

fn handle_wallet_gateway_key(state: &mut TuiState, key: KeyEvent) {
    if state.show_breaker_reset {
        handle_wallet_gateway_reset_key(state, key);
        return;
    }

    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::Dashboard,
        KeyCode::Tab => state.gateway_focused_field = (state.gateway_focused_field + 1) % 8,
        KeyCode::BackTab => {
            state.gateway_focused_field = state.gateway_focused_field.saturating_sub(1);
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            state.show_breaker_reset = true;
            state.reset_focus_index = 0;
        }
        KeyCode::Char('p') | KeyCode::Char('P') => {
            state.screen = Screen::Web3AccountPolicies;
            load_selected_policy_into_form(state);
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            state.screen = Screen::Web3ScheduledRules;
        }
        KeyCode::Char('$') => {
            state.screen = Screen::Web3PriceOracle;
        }
        KeyCode::Char('i') | KeyCode::Char('I') => {
            state.screen = Screen::Web3RpcInspector;
        }
        KeyCode::Char('n') | KeyCode::Char('N') => {
            state.screen = Screen::NodesManager;
            reload_nodes_manager(state);
        }
        KeyCode::Char('e') | KeyCode::Char('E') => {
            state.screen = Screen::Web3AccountEditor;
            load_selected_policy_into_form(state);
        }
        KeyCode::Char('m') | KeyCode::Char('M') => {
            let profile = state.nodes.cycle_profile();
            state.system_notification = format!(
                "Perfil Web3 cambiado a {}. Pulse G en Nodos para persistir.",
                profile.label()
            );
        }
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            state.gateway_network = match state.gateway_network {
                Network::Mainnet => Network::Testnet,
                Network::Testnet => Network::Mainnet,
            };
            state.system_notification = format!("Red gateway: {:?}", state.gateway_network);
        }
        KeyCode::Backspace => match state.gateway_focused_field {
            0 => {
                state.input_max_tx.pop();
            }
            1 => {
                state.input_max_volume.pop();
            }
            2 => {
                state.input_max_fiat_value.pop();
            }
            3 => {
                state.input_fiat_currency.pop();
            }
            4 => {
                state.input_price_asset.pop();
            }
            5 => {
                state.input_price_value.pop();
            }
            6 => {
                state.input_new_dex_id.pop();
            }
            7 => {
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
                if (value.is_ascii_digit() || value == '.') && state.input_max_fiat_value.len() < 12
                {
                    state.input_max_fiat_value.push(value);
                }
            }
            3 => {
                if value.is_ascii_alphabetic() && state.input_fiat_currency.len() < 8 {
                    state.input_fiat_currency.push(value.to_ascii_uppercase());
                }
            }
            4 => {
                if value.is_ascii_alphanumeric() && state.input_price_asset.len() < 32 {
                    state.input_price_asset.push(value.to_ascii_uppercase());
                }
            }
            5 => {
                if (value.is_ascii_digit() || value == '.') && state.input_price_value.len() < 16 {
                    state.input_price_value.push(value);
                }
            }
            6 => {
                if state.input_new_dex_id.len() < 96 {
                    state.input_new_dex_id.push(value);
                }
            }
            7 => {
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
        0 | 1 | 2 | 3 => {
            let max_tx = state.input_max_tx.trim().parse::<u32>().ok();
            let max_vol = state.input_max_volume.trim().parse::<Decimal>().ok();
            let max_fiat = state.input_max_fiat_value.trim().parse::<Decimal>().ok();
            let fiat_currency = state.input_fiat_currency.trim().to_uppercase();
            if max_tx.is_none()
                && max_vol.is_none()
                && max_fiat.is_none()
                && fiat_currency.is_empty()
            {
                state.system_notification = "Error: formato numerico invalido.".to_string();
                return;
            }
            if let Some(tx) = &state.web3_cmd_tx {
                let _ = tx.send(Web3WorkerCmd::UpdateRules {
                    max_tx,
                    max_vol,
                    max_fiat,
                    fiat_currency: if fiat_currency.is_empty() {
                        None
                    } else {
                        Some(fiat_currency)
                    },
                });
            } else {
                state.system_notification = "Web3 no inicializado.".to_string();
            }
        }
        4 | 5 => {
            let asset = state.input_price_asset.trim().to_uppercase();
            let fiat = state.input_fiat_currency.trim().to_uppercase();
            let value = state.input_price_value.trim().parse::<Decimal>().ok();
            let Some(value) = value else {
                state.system_notification = "Error: precio manual invalido.".to_string();
                return;
            };
            if let Some(tx) = &state.web3_cmd_tx {
                let _ = tx.send(Web3WorkerCmd::SetManualPrice { asset, fiat, value });
            } else {
                state.system_notification = "Web3 no inicializado.".to_string();
            }
        }
        6 => {
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
        7 => {
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

fn parse_optional_u32(value: &str) -> Result<Option<u32>, String> {
    let value = value.trim();
    if value.is_empty() || value == "*" {
        return Ok(None);
    }
    value
        .parse::<u32>()
        .map(Some)
        .map_err(|_| "valor numerico opcional invalido".to_string())
}

fn parse_optional_decimal(value: &str) -> Result<Option<Decimal>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<Decimal>()
        .map(Some)
        .map_err(|_| "decimal opcional invalido".to_string())
}

fn parse_optional_u64(value: &str) -> Result<Option<u64>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| "entero opcional invalido".to_string())
}

fn parse_policy_window(value: &str) -> PolicyWindow {
    match value.trim().to_lowercase().as_str() {
        "semanal" | "weekly" => PolicyWindow::Weekly,
        "mensual" | "monthly" => PolicyWindow::Monthly,
        other if other.starts_with("custom:") => other
            .trim_start_matches("custom:")
            .parse::<u64>()
            .map(PolicyWindow::CustomSeconds)
            .unwrap_or_default(),
        _ => PolicyWindow::Daily,
    }
}

fn policy_chain_options() -> [ChainType; 6] {
    [
        ChainType::Bitcoin,
        ChainType::Ethereum,
        ChainType::Solana,
        ChainType::Monero,
        ChainType::Zcash,
        ChainType::Starknet,
    ]
}

fn selected_policy_chain(state: &TuiState) -> ChainType {
    policy_chain_options()
        .get(state.web3_policy_chain_index)
        .cloned()
        .unwrap_or(ChainType::Ethereum)
}

fn selected_rpc_chain_name(state: &TuiState) -> String {
    format!(
        "{:?}",
        policy_chain_options()
            .get(state.web3_rpc_chain_index)
            .cloned()
            .unwrap_or(ChainType::Ethereum)
    )
}

fn comma_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn load_selected_policy_into_form(state: &mut TuiState) {
    let Some(policy) = state
        .account_policies
        .get(state.web3_policy_selected)
        .cloned()
    else {
        return;
    };
    state.web3_policy_chain_index = policy_chain_options()
        .iter()
        .position(|chain| *chain == policy.chain)
        .unwrap_or(1);
    state.web3_policy_account_index = policy.account_index.to_string();
    state.web3_policy_address_index = policy
        .address_index
        .map(|value| value.to_string())
        .unwrap_or_default();
    state.web3_policy_label = policy.label;
    state.web3_policy_max_tx = policy.max_tx_per_window.to_string();
    state.web3_policy_max_crypto = policy
        .max_native_amount
        .map(|value| value.to_string())
        .unwrap_or_default();
    state.web3_policy_max_fiat = policy
        .max_fiat_value
        .map(|value| value.to_string())
        .unwrap_or_default();
    state.web3_policy_fiat_currency = policy.fiat_currency;
    state.web3_policy_require_confirmation = policy.require_local_confirmation;
    state.web3_policy_destination_input = policy.allowed_destinations.join(", ");
    state.web3_policy_contract_input = policy.allowed_contracts.join(", ");
    if let Some((asset, limit)) = policy.max_asset_amounts.iter().next() {
        state.web3_policy_asset_input = asset.clone();
        state.web3_policy_asset_limit_input = limit.to_string();
    }
}

fn build_account_policy_from_state(state: &TuiState) -> Result<AccountPolicy, String> {
    let chain = selected_policy_chain(state);
    let account_index = state
        .web3_policy_account_index
        .trim()
        .parse::<u32>()
        .map_err(|_| "cuenta invalida".to_string())?;
    let address_index = parse_optional_u32(&state.web3_policy_address_index)?;
    let max_tx = state
        .web3_policy_max_tx
        .trim()
        .parse::<u32>()
        .map_err(|_| "max TX invalido".to_string())?;
    let mut max_asset_amounts = HashMap::new();
    if let Some(asset_limit) = parse_optional_decimal(&state.web3_policy_asset_limit_input)? {
        let asset = state.web3_policy_asset_input.trim().to_uppercase();
        if !asset.is_empty() {
            max_asset_amounts.insert(asset, asset_limit);
        }
    }
    Ok(AccountPolicy {
        chain,
        account_index,
        address_index,
        label: state.web3_policy_label.trim().to_string(),
        max_tx_per_window: max_tx,
        max_native_amount: parse_optional_decimal(&state.web3_policy_max_crypto)?,
        max_asset_amounts,
        max_fiat_value: parse_optional_decimal(&state.web3_policy_max_fiat)?,
        max_fiat_value_per_tx: None,
        max_fee_native: state
            .account_policies
            .iter()
            .find(|policy| {
                policy.chain == selected_policy_chain(state)
                    && policy.account_index == account_index
                    && policy.address_index == address_index
            })
            .and_then(|policy| policy.max_fee_native),
        fiat_currency: state.web3_policy_fiat_currency.trim().to_uppercase(),
        allowed_destinations: comma_list(&state.web3_policy_destination_input),
        allowed_contracts: comma_list(&state.web3_policy_contract_input),
        scheduled_rules: state
            .account_policies
            .iter()
            .find(|policy| {
                policy.chain == selected_policy_chain(state)
                    && policy.account_index
                        == state
                            .web3_policy_account_index
                            .trim()
                            .parse::<u32>()
                            .unwrap_or(u32::MAX)
                    && policy.address_index == address_index
            })
            .map(|policy| policy.scheduled_rules.clone())
            .unwrap_or_default(),
        require_local_confirmation: state.web3_policy_require_confirmation,
    })
}

fn submit_web3_account_policy(state: &mut TuiState) {
    match build_account_policy_from_state(state) {
        Ok(policy) => {
            if let Some(tx) = &state.web3_cmd_tx {
                let _ = tx.send(Web3WorkerCmd::UpsertAccountPolicy(policy));
            } else {
                state.system_notification = "Web3 no inicializado.".to_string();
            }
        }
        Err(error) => state.system_notification = error,
    }
}

fn remove_selected_web3_account_policy(state: &mut TuiState) {
    let Some(policy) = state
        .account_policies
        .get(state.web3_policy_selected)
        .cloned()
    else {
        state.system_notification = "No hay politica seleccionada.".to_string();
        return;
    };
    if let Some(tx) = &state.web3_cmd_tx {
        let _ = tx.send(Web3WorkerCmd::RemoveAccountPolicy {
            chain: policy.chain,
            account_index: policy.account_index,
            address_index: policy.address_index,
        });
    }
}

fn policy_field_mut(state: &mut TuiState) -> Option<&mut String> {
    match state.web3_policy_focus {
        1 => Some(&mut state.web3_policy_account_index),
        2 => Some(&mut state.web3_policy_address_index),
        3 => Some(&mut state.web3_policy_label),
        4 => Some(&mut state.web3_policy_max_tx),
        5 => Some(&mut state.web3_policy_max_crypto),
        6 => Some(&mut state.web3_policy_max_fiat),
        7 => Some(&mut state.web3_policy_fiat_currency),
        9 => Some(&mut state.web3_policy_destination_input),
        10 => Some(&mut state.web3_policy_contract_input),
        11 => Some(&mut state.web3_policy_asset_input),
        12 => Some(&mut state.web3_policy_asset_limit_input),
        _ => None,
    }
}

fn edit_policy_field_char(state: &mut TuiState, value: char) {
    if state.web3_policy_focus == 0 {
        let count = policy_chain_options().len();
        if value == '[' {
            state.web3_policy_chain_index = state.web3_policy_chain_index.saturating_sub(1);
        } else if value == ']' {
            state.web3_policy_chain_index = (state.web3_policy_chain_index + 1) % count;
        }
        return;
    }
    if state.web3_policy_focus == 8 {
        if value == ' ' {
            state.web3_policy_require_confirmation = !state.web3_policy_require_confirmation;
        }
        return;
    }
    let kind = focused_field_kind(state);
    if let Some(field) = policy_field_mut(state) {
        sanitize_into_field(kind, field, &value.to_string(), 160);
    }
}

fn handle_web3_account_policies_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::WalletGateway,
        KeyCode::Tab => state.web3_policy_focus = (state.web3_policy_focus + 1) % 13,
        KeyCode::BackTab => {
            state.web3_policy_focus = state.web3_policy_focus.saturating_sub(1);
        }
        KeyCode::Up => {
            state.web3_policy_selected = state.web3_policy_selected.saturating_sub(1);
            load_selected_policy_into_form(state);
        }
        KeyCode::Down => {
            if state.web3_policy_selected + 1 < state.account_policies.len() {
                state.web3_policy_selected += 1;
                load_selected_policy_into_form(state);
            }
        }
        KeyCode::Left => {
            if state.web3_policy_focus == 0 {
                state.web3_policy_chain_index = state.web3_policy_chain_index.saturating_sub(1);
            }
        }
        KeyCode::Right => {
            if state.web3_policy_focus == 0 {
                state.web3_policy_chain_index =
                    (state.web3_policy_chain_index + 1) % policy_chain_options().len();
            }
        }
        KeyCode::Enter => submit_web3_account_policy(state),
        KeyCode::Delete => remove_selected_web3_account_policy(state),
        KeyCode::Char('s') | KeyCode::Char('S') => state.screen = Screen::Web3ScheduledRules,
        KeyCode::Char(' ') if state.web3_policy_focus == 8 => {
            state.web3_policy_require_confirmation = !state.web3_policy_require_confirmation;
        }
        KeyCode::Backspace => {
            if let Some(field) = policy_field_mut(state) {
                field.pop();
            }
        }
        KeyCode::Char(value) => edit_policy_field_char(state, value),
        _ => {}
    }
}

fn selected_policy_identity(state: &TuiState) -> Result<(ChainType, u32, Option<u32>), String> {
    let chain = selected_policy_chain(state);
    let account_index = state
        .web3_policy_account_index
        .trim()
        .parse::<u32>()
        .map_err(|_| "cuenta invalida".to_string())?;
    let address_index = parse_optional_u32(&state.web3_policy_address_index)?;
    Ok((chain, account_index, address_index))
}

fn build_scheduled_policy_from_state(state: &TuiState) -> Result<ScheduledPolicy, String> {
    let (chain, account_index, address_index) = selected_policy_identity(state)?;
    let max_tx = state
        .web3_schedule_max_tx
        .trim()
        .parse::<u32>()
        .unwrap_or(1);
    Ok(ScheduledPolicy {
        name: state.web3_schedule_name.trim().to_string(),
        enabled: true,
        chain,
        account_index,
        address_index,
        asset: state.web3_schedule_asset.trim().to_uppercase(),
        destination: state.web3_schedule_destination.trim().to_string(),
        max_tx,
        max_asset_amount: parse_optional_decimal(&state.web3_schedule_max_asset)?,
        max_fiat_value: parse_optional_decimal(&state.web3_schedule_max_fiat)?,
        fiat_currency: state.web3_schedule_currency.trim().to_uppercase(),
        window: parse_policy_window(&state.web3_schedule_window),
        expires_unix: parse_optional_u64(&state.web3_schedule_expires_unix)?,
        require_local_confirmation: true,
    })
}

fn schedule_field_mut(state: &mut TuiState) -> Option<&mut String> {
    match state.web3_schedule_focus {
        0 => Some(&mut state.web3_schedule_name),
        1 => Some(&mut state.web3_schedule_asset),
        2 => Some(&mut state.web3_schedule_destination),
        3 => Some(&mut state.web3_schedule_max_tx),
        4 => Some(&mut state.web3_schedule_max_asset),
        5 => Some(&mut state.web3_schedule_max_fiat),
        6 => Some(&mut state.web3_schedule_currency),
        7 => Some(&mut state.web3_schedule_window),
        8 => Some(&mut state.web3_schedule_expires_unix),
        _ => None,
    }
}

fn submit_web3_scheduled_rule(state: &mut TuiState) {
    let Ok((chain, account_index, address_index)) = selected_policy_identity(state) else {
        state.system_notification = "Seleccione primero una politica valida.".to_string();
        return;
    };
    match build_scheduled_policy_from_state(state) {
        Ok(rule) => {
            if let Some(tx) = &state.web3_cmd_tx {
                let _ = tx.send(Web3WorkerCmd::AddScheduledPolicy {
                    chain,
                    account_index,
                    address_index,
                    rule,
                });
            }
        }
        Err(error) => state.system_notification = error,
    }
}

fn remove_web3_scheduled_rule(state: &mut TuiState) {
    let Ok((chain, account_index, address_index)) = selected_policy_identity(state) else {
        return;
    };
    let name = state.web3_schedule_name.trim().to_string();
    if name.is_empty() {
        state.system_notification = "Indique el nombre de la regla a eliminar.".to_string();
        return;
    }
    if let Some(tx) = &state.web3_cmd_tx {
        let _ = tx.send(Web3WorkerCmd::RemoveScheduledPolicy {
            chain,
            account_index,
            address_index,
            name,
        });
    }
}

fn handle_web3_scheduled_rules_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::Web3AccountPolicies,
        KeyCode::Tab => state.web3_schedule_focus = (state.web3_schedule_focus + 1) % 9,
        KeyCode::BackTab => {
            state.web3_schedule_focus = state.web3_schedule_focus.saturating_sub(1);
        }
        KeyCode::Enter => submit_web3_scheduled_rule(state),
        KeyCode::Delete => remove_web3_scheduled_rule(state),
        KeyCode::Backspace => {
            if let Some(field) = schedule_field_mut(state) {
                field.pop();
            }
        }
        KeyCode::Char(value) => {
            let kind = focused_field_kind(state);
            if let Some(field) = schedule_field_mut(state) {
                sanitize_into_field(kind, field, &value.to_string(), 160);
            }
        }
        _ => {}
    }
}

fn price_field_mut(state: &mut TuiState) -> Option<&mut String> {
    match state.web3_price_focus {
        0 => Some(&mut state.web3_price_asset),
        1 => Some(&mut state.web3_price_fiat),
        2 => Some(&mut state.web3_price_value),
        3 => Some(&mut state.web3_price_max_age_seconds),
        4 => Some(&mut state.web3_price_import_path),
        _ => None,
    }
}

fn submit_web3_manual_price(state: &mut TuiState) {
    let Ok(value) = state.web3_price_value.trim().parse::<Decimal>() else {
        state.system_notification = "Precio invalido.".to_string();
        return;
    };
    if let Some(tx) = &state.web3_cmd_tx {
        let _ = tx.send(Web3WorkerCmd::SetManualPrice {
            asset: state.web3_price_asset.trim().to_uppercase(),
            fiat: state.web3_price_fiat.trim().to_uppercase(),
            value,
        });
    }
}

fn handle_web3_price_oracle_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::WalletGateway,
        KeyCode::Tab => state.web3_price_focus = (state.web3_price_focus + 1) % 5,
        KeyCode::BackTab => state.web3_price_focus = state.web3_price_focus.saturating_sub(1),
        KeyCode::Up => state.web3_price_selected = state.web3_price_selected.saturating_sub(1),
        KeyCode::Down => {
            if state.web3_price_selected + 1 < state.price_quotes.len() {
                state.web3_price_selected += 1;
            }
        }
        KeyCode::Enter => submit_web3_manual_price(state),
        KeyCode::Char('i') | KeyCode::Char('I') => {
            let path = state.web3_price_import_path.clone();
            submit_lvcprices_import(state, &path);
        }
        KeyCode::Backspace => {
            if let Some(field) = price_field_mut(state) {
                field.pop();
            }
        }
        KeyCode::Char(value) => {
            let kind = focused_field_kind(state);
            if kind == FieldKind::Text {
                // Activo/FIAT en mayúsculas; ruta de import conserva mayúsculas/minúsculas.
                let preserve_case = state.web3_price_focus == 4;
                if let Some(field) = price_field_mut(state) {
                    if field.chars().count() < 256 {
                        field.push(if preserve_case {
                            value
                        } else {
                            value.to_ascii_uppercase()
                        });
                    }
                }
            } else if let Some(field) = price_field_mut(state) {
                sanitize_into_field(kind, field, &value.to_string(), 256);
            }
        }
        _ => {}
    }
}

/// Envia el fichero de precios firmado al worker (verificacion Ed25519 + antiguedad en backend).
fn submit_lvcprices_import(state: &mut TuiState, path_text: &str) {
    let trimmed = path_text.trim();
    if trimmed.is_empty() {
        state.system_notification =
            "Indique la ruta del fichero .lvcprices (campo Ruta import).".to_string();
        return;
    }
    let path = std::path::PathBuf::from(trimmed);
    if !path.is_file() {
        state.system_notification = "Ruta .lvcprices no encontrada.".to_string();
        return;
    }
    match &state.web3_cmd_tx {
        Some(tx) => {
            let _ = tx.send(Web3WorkerCmd::ImportSignedPriceFile { path });
            state.system_notification =
                "Importacion .lvcprices enviada; verificando firma Ed25519 en backend.".to_string();
        }
        None => {
            state.system_notification =
                "Web3 no inicializado: no se puede importar precios.".to_string();
        }
    }
}

fn rpc_field_mut(state: &mut TuiState) -> Option<&mut String> {
    match state.web3_rpc_focus {
        1 => Some(&mut state.web3_rpc_address),
        2 => Some(&mut state.web3_rpc_asset),
        3 => Some(&mut state.web3_rpc_tx_status),
        _ => None,
    }
}

fn request_rpc_balance(state: &mut TuiState) {
    if !state.nodes.profile().allows_rpc_read() {
        state.web3_rpc_status = "Perfil OFFLINE: lectura RPC bloqueada.".to_string();
        return;
    }
    if let Some(tx) = &state.web3_cmd_tx {
        let _ = tx.send(Web3WorkerCmd::RpcReadBalance {
            chain: selected_rpc_chain_name(state),
            address: state.web3_rpc_address.clone(),
            asset: state.web3_rpc_asset.clone(),
        });
    }
}

fn request_rpc_nonce(state: &mut TuiState) {
    if !state.nodes.profile().allows_rpc_read() {
        state.web3_rpc_status = "Perfil OFFLINE: lectura RPC bloqueada.".to_string();
        return;
    }
    if let Some(tx) = &state.web3_cmd_tx {
        let _ = tx.send(Web3WorkerCmd::RpcReadNonce {
            chain: selected_rpc_chain_name(state),
            address: state.web3_rpc_address.clone(),
        });
    }
}

fn request_rpc_fee(state: &mut TuiState) {
    if !state.nodes.profile().allows_rpc_read() {
        state.web3_rpc_status = "Perfil OFFLINE: lectura RPC bloqueada.".to_string();
        return;
    }
    if let Some(tx) = &state.web3_cmd_tx {
        let _ = tx.send(Web3WorkerCmd::RpcEstimateFee {
            chain: selected_rpc_chain_name(state),
            raw_payload: Vec::new(),
        });
    }
}

fn request_rpc_tx_status(state: &mut TuiState) {
    if !state.nodes.profile().allows_rpc_read() {
        state.web3_rpc_status = "Perfil OFFLINE: lectura RPC bloqueada.".to_string();
        return;
    }
    if let Some(tx) = &state.web3_cmd_tx {
        let _ = tx.send(Web3WorkerCmd::RpcReadTxStatus {
            chain: selected_rpc_chain_name(state),
            txid: state.web3_rpc_tx_status.clone(),
        });
    }
}

fn handle_web3_rpc_inspector_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.screen = Screen::WalletGateway,
        KeyCode::Tab => state.web3_rpc_focus = (state.web3_rpc_focus + 1) % 4,
        KeyCode::BackTab => state.web3_rpc_focus = state.web3_rpc_focus.saturating_sub(1),
        KeyCode::Left if state.web3_rpc_focus == 0 => {
            state.web3_rpc_chain_index = state.web3_rpc_chain_index.saturating_sub(1);
        }
        KeyCode::Right if state.web3_rpc_focus == 0 => {
            state.web3_rpc_chain_index =
                (state.web3_rpc_chain_index + 1) % policy_chain_options().len();
        }
        KeyCode::Char('b') | KeyCode::Char('B') => request_rpc_balance(state),
        KeyCode::Char('n') | KeyCode::Char('N') => request_rpc_nonce(state),
        KeyCode::Char('f') | KeyCode::Char('F') => request_rpc_fee(state),
        KeyCode::Char('t') | KeyCode::Char('T') => request_rpc_tx_status(state),
        KeyCode::Backspace => {
            if let Some(field) = rpc_field_mut(state) {
                field.pop();
            }
        }
        KeyCode::Char(value) => {
            if let Some(field) = rpc_field_mut(state) {
                if field.len() < 160 {
                    field.push(value);
                }
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
    } else if state.screen == Screen::SandboxManager {
        FileBrowserTarget::SandboxPayload
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
        FileBrowserTarget::SandboxPayload => {
            state.sandbox_payload_path = path.display().to_string();
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
        KeyCode::Tab => state.settings_focus = (state.settings_focus + 1) % SETTINGS_FIELD_COUNT,
        KeyCode::BackTab => {
            state.settings_focus = if state.settings_focus == 0 {
                SETTINGS_FIELD_COUNT - 1
            } else {
                state.settings_focus - 1
            };
        }
        KeyCode::PageUp => state.settings_scroll = state.settings_scroll.saturating_sub(4),
        KeyCode::PageDown => {
            state.settings_scroll = state.settings_scroll.saturating_add(4).min(24);
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
        KeyCode::Char('D') => set_duress_key_from_settings(state),
        KeyCode::Char('P') => enable_apparmor_from_settings(state),
        KeyCode::Char('U') => disable_apparmor_from_settings(state),
        KeyCode::Char('Z') => toggle_destructive_auditor_reauth(state),
        KeyCode::Char(value) => {
            if matches!(state.settings_focus, 0..=4 | 7..=11 | 13..=17) {
                let target = match state.settings_focus {
                    0..=4 => &mut state.settings_boot_cajas[state.settings_focus],
                    7..=11 => &mut state.settings_boot_secondary_cajas[state.settings_focus - 7],
                    13..=17 => &mut state.settings_duress_cajas[state.settings_focus - 13],
                    _ => unreachable!(),
                };
                if !push_box_char(target, value) {
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
        7..=11 => &mut state.settings_boot_secondary_cajas[state.settings_focus - 7],
        12 => &mut state.settings_boot_secondary_frase,
        13..=17 => &mut state.settings_duress_cajas[state.settings_focus - 13],
        18 => &mut state.settings_duress_frase,
        19 => &mut state.settings_network_profile,
        20 => &mut state.settings_network_confirmation,
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

fn secondary_settings_credentials(
    state: &mut TuiState,
) -> Result<(Option<[i64; 5]>, Option<String>), String> {
    let boxes_empty = state
        .settings_boot_secondary_cajas
        .iter()
        .all(|value| value.trim().is_empty());
    let phrase_empty = state.settings_boot_secondary_frase.trim().is_empty();

    if boxes_empty && phrase_empty {
        return Ok((None, None));
    }
    if boxes_empty || phrase_empty {
        return Err("La credencial secundaria requiere 5 cajas y frase B.".to_string());
    }

    let cajas = parse_boxes(&state.settings_boot_secondary_cajas)?;
    let mut frase = String::new();
    std::mem::swap(&mut frase, &mut state.settings_boot_secondary_frase);
    Ok((Some(cajas), Some(frase)))
}

fn duress_settings_credentials(state: &mut TuiState) -> Result<([i64; 5], String), String> {
    let cajas = parse_boxes(&state.settings_duress_cajas)?;
    let mut frase = String::new();
    std::mem::swap(&mut frase, &mut state.settings_duress_frase);
    if frase.trim().is_empty() {
        frase.zeroize();
        return Err("La frase de coaccion no puede estar vacia.".to_string());
    }
    Ok((cajas, frase))
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

fn set_duress_key_from_settings(state: &mut TuiState) {
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
        frase.zeroize();
        state.status = "La frase principal es obligatoria para validar el vault.".to_string();
        return;
    }

    let (secondary_cajas, secondary_frase) = match secondary_settings_credentials(state) {
        Ok(credentials) => credentials,
        Err(error) => {
            frase.zeroize();
            state.status = error;
            return;
        }
    };
    let (duress_cajas, duress_frase) = match duress_settings_credentials(state) {
        Ok(credentials) => credentials,
        Err(error) => {
            frase.zeroize();
            if let Some(mut value) = secondary_frase {
                value.zeroize();
            }
            state.status = error;
            return;
        }
    };

    match security::boot_shield_set_duress_key(
        cajas,
        frase,
        secondary_cajas,
        secondary_frase,
        duress_cajas,
        duress_frase,
    ) {
        Ok(_) => {
            zeroize_boxes(&mut state.settings_duress_cajas);
            state.settings_duress_frase.zeroize();
            state.settings_duress_frase.clear();
            state.status =
                "Clave de coaccion configurada. Un uso real ejecutara borrado silencioso."
                    .to_string();
            state.add_log("Clave de coaccion Boot Shield configurada.");
        }
        Err(error) => {
            state.status = format!("No se pudo configurar clave de coaccion: {}", error);
        }
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
    let (secondary_cajas, secondary_frase) = match secondary_settings_credentials(state) {
        Ok(credentials) => credentials,
        Err(error) => {
            frase.zeroize();
            state.status = error;
            return;
        }
    };
    match security::boot_shield_enable(
        cajas,
        frase,
        Some(state.settings_boot_template.clone()),
        secondary_cajas,
        secondary_frase,
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
    let (secondary_cajas, secondary_frase) = match secondary_settings_credentials(state) {
        Ok(credentials) => credentials,
        Err(error) => {
            frase.zeroize();
            state.status = error;
            return;
        }
    };
    match security::boot_shield_disable(cajas, frase, secondary_cajas, secondary_frase) {
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
    let area = frame.area();
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
        Screen::SandboxManager => draw_sandbox_manager(frame, inner, state),
        Screen::RecoveryMode => draw_recovery_mode(frame, inner, state),
        Screen::InstallProfile => draw_install_profile(frame, inner),
        Screen::WalletGateway => draw_wallet_gateway(frame, inner, state),
        Screen::WalletAuditor => draw_wallet_auditor(frame, inner, state),
        Screen::NodesManager => draw_nodes_manager(frame, inner, state),
        Screen::Web3AccountPolicies | Screen::Web3AccountEditor => {
            draw_web3_account_policies(frame, inner, state)
        }
        Screen::Web3ScheduledRules => draw_web3_scheduled_rules(frame, inner, state),
        Screen::Web3PriceOracle => draw_web3_price_oracle(frame, inner, state),
        Screen::Web3RpcInspector => draw_web3_rpc_inspector(frame, inner, state),
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
    if let Some(preview) = &state.pending_signing_preview {
        draw_signing_authorization_modal(frame, inner, preview);
    }
    if let Some(preview) = &state.pending_broadcast_preview {
        draw_broadcast_authorization_modal(frame, inner, preview);
    }
    if state.show_reauth_modal {
        draw_reauth_modal(frame, inner, state);
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

fn draw_signing_authorization_modal(
    frame: &mut Frame<'_>,
    area: Rect,
    preview: &SigningRequestPreview,
) {
    let popup = centered_area(area, 78, 56);
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::from(Span::styled(
            "AUTORIZACION REQUERIDA - PASARELA WEB3",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "ID solicitud: {} | Red: {:?} | chain_id: {}",
            preview.request_id, preview.chain, preview.chain_id
        )),
        Line::from(format!(
            "Ruta: m/44'/{}/{}'/0/{}",
            preview.chain_id, preview.account_index, preview.address_index
        )),
        Line::from(format!("Metodo: {:?}", preview.method)),
        Line::from(format!(
            "Destino declarado: {}",
            preview
                .target_dex_cex_id
                .as_deref()
                .unwrap_or("sin destino declarado")
        )),
        Line::from(format!("Valor externo USD: {}", preview.value_usd)),
        Line::from(format!(
            "Volumen efectivo parseado: {}",
            preview.effective_volume_units
        )),
        Line::from(format!(
            "Comision estimada: {}",
            preview
                .fee_estimate
                .as_deref()
                .unwrap_or("no disponible (OFFLINE o sin nodo)")
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Resumen parseado por backend:",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(preview.summary.clone()),
        Line::from(""),
        Line::from(Span::styled(
            "F10/A autoriza la firma | Esc/D rechaza y responde error al socket",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
    ];
    let modal = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Confirmacion fisica de firma ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(modal, popup);
}

fn draw_broadcast_authorization_modal(
    frame: &mut Frame<'_>,
    area: Rect,
    preview: &BroadcastRequestPreview,
) {
    let popup = centered_area(area, 78, 44);
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::from(Span::styled(
            "AUTORIZACION DE BROADCAST - PASARELA WEB3",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "ID solicitud: {} | Red: {:?}",
            preview.request_id, preview.chain
        )),
        Line::from(format!(
            "Tamano payload firmado: {} bytes",
            preview.payload_len
        )),
        Line::from(format!("SHA-256 payload: {}", preview.payload_sha256)),
        Line::from(""),
        Line::from(Span::styled(
            "El envio a la red blockchain es IRREVERSIBLE.",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "F10/A autoriza y difunde | Esc/D rechaza y responde error al socket",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
    ];
    let modal = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Confirmacion fisica de broadcast ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(modal, popup);
}

fn draw_reauth_modal(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let popup = centered_area(area, 72, 56);
    frame.render_widget(Clear, popup);
    let focus = |idx: usize| {
        if state.reauth_focus == idx {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        }
    };
    let mut lines = vec![
        Line::from(Span::styled(
            "RE-CONFIRMACION BOOT SHIELD",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Introduzca cajas y frase maestra para autorizar la accion del auditor."),
        Line::from(Span::styled(
            "Verificacion read-only por defecto (modo destructivo configurable en Ajustes, tecla Z).",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(""),
    ];
    for (idx, caja) in state.reauth_cajas.iter().enumerate() {
        let masked: String = "*".repeat(caja.chars().count());
        lines.push(Line::from(vec![
            Span::styled(format!("Caja {}: ", idx + 1), focus(idx)),
            Span::raw(masked),
        ]));
    }
    let masked_phrase: String = "*".repeat(state.reauth_phrase.chars().count());
    lines.push(Line::from(vec![
        Span::styled("Frase: ", focus(5)),
        Span::raw(masked_phrase),
    ]));
    if state.unlock_requires_secondary() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "DOBLE CREDENCIAL (secundaria):",
            Style::default().fg(Color::Cyan),
        )));
        for (idx, caja) in state.reauth_secondary_cajas.iter().enumerate() {
            let masked: String = "*".repeat(caja.chars().count());
            lines.push(Line::from(vec![
                Span::styled(format!("Caja B{}: ", idx + 1), focus(6 + idx)),
                Span::raw(masked),
            ]));
        }
        let masked_secondary: String = "*".repeat(state.reauth_secondary_phrase.chars().count());
        lines.push(Line::from(vec![
            Span::styled("Frase B: ", focus(11)),
            Span::raw(masked_secondary),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Tab cambia campo | Enter confirma | Esc cancela",
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    )));
    let modal = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Verificacion de identidad ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(modal, popup);
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
        FileBrowserTarget::SandboxPayload => "payload sandbox",
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
    let double_mode = state.unlock_requires_secondary();
    let form_height = if double_mode { 15 } else { 10 };
    let constraints = if has_warnings {
        vec![
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Length(form_height),
            Constraint::Length(8),
            Constraint::Min(4),
        ]
    } else {
        vec![
            Constraint::Length(4),
            Constraint::Length(form_height),
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
        Line::from(format!(
            "Acceso por descifrado: {}.",
            if double_mode {
                "2 credenciales: A+B, cada una con 5 cajas + frase exacta"
            } else {
                "5 cajas + frase exacta"
            }
        )),
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
    fields.push(Line::from(Span::styled(
        "Custodio A / credencial principal",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
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
    if double_mode {
        fields.push(Line::from(""));
        fields.push(Line::from(Span::styled(
            "Custodio B / credencial secundaria",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        for index in 0..5 {
            let focus_index = 6 + index;
            let marker = if state.focus == focus_index { ">" } else { " " };
            fields.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(
                    format!(" CAJA B{}: ", index + 1),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(&state.secondary_cajas[index]),
            ]));
        }
        let phrase_marker = if state.focus == 11 { ">" } else { " " };
        fields.push(Line::from(vec![
            Span::raw(phrase_marker),
            Span::styled(" FRASE B: ", Style::default().fg(Color::Cyan)),
            Span::raw("*".repeat(state.secondary_frase.chars().count())),
        ]));
    }

    let form = Paragraph::new(fields)
        .block(
            Block::default()
                .title(if double_mode {
                    " Credenciales Boot Shield doble "
                } else {
                    " Credenciales "
                })
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
            Constraint::Length(17),
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
            "Pasarela Web3: {} | TX hoy: {} | cripto/token: {:.8} | fiat: {:.2} {}",
            gateway_state_label(&state.cached_gateway_state),
            state.cached_tx_count,
            state.cached_volume_units,
            state.cached_fiat_value,
            state.input_fiat_currency
        )),
        ListItem::new(format!(
            "Politicas cuenta: {} | reglas programadas activas: {} | perfil: {}",
            state.account_policies.len(),
            state
                .account_policies
                .iter()
                .flat_map(|policy| policy.scheduled_rules.iter())
                .filter(|rule| rule.enabled)
                .count(),
            state.nodes.profile().label()
        )),
        ListItem::new("w = pasarela Web3 / custodia"),
        ListItem::new("k = auditor visual de direcciones publicas"),
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
            let bottom_char = bottom.and_then(|row| row.chars().nth(x)).unwrap_or(' ');
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

    let header = Paragraph::new(format!(
        "GESTION DE INFRAESTRUCTURA DE NODOS | PERFIL WEB3: {}",
        state.nodes.profile().label()
    ))
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
                let marker = if idx == state.nodes_selected {
                    ">"
                } else {
                    " "
                };
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
        let clock_status = state.nodes.offline_verified_clock();
        detail.push(Line::from(Span::styled(
            format!("Cadena: {}", chain),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        detail.push(Line::from(format!(
            "Perfil: {} | timeout RPC: {} ms | drift max: {} s",
            state.nodes.profile().label(),
            state.nodes.timeout_ms(),
            state.nodes.max_clock_drift_seconds()
        )));
        detail.push(Line::from(format!("Estado reloj: {}", clock_status.status)));
        detail.push(Line::from(""));
        for (idx, endpoint) in endpoints.iter().enumerate() {
            let marker = if idx == active { "[x]" } else { "[ ]" };
            let role = if idx == 0 { "principal" } else { "respaldo" };
            detail.push(Line::from(format!("{} {} ({})", marker, endpoint, role)));
        }
        if let Some(policy) = state.nodes.endpoint_policy(chain) {
            detail.push(Line::from(""));
            detail.push(Line::from(format!(
                "Politica endpoint: broadcast={} | chain_id requerido='{}'",
                if policy.allow_broadcast { "si" } else { "no" },
                if policy.require_chain_id.is_empty() {
                    "pendiente"
                } else {
                    &policy.require_chain_id
                }
            )));
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
        "Flechas navegan | Espacio cambia nodo activo | M perfil | E edita | G guarda | R recarga | Ctrl+C copia | Esc",
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

    let clock_status = state.nodes.offline_verified_clock();
    let left = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("Perfil Web3: "),
            Span::styled(
                state.nodes.profile().label(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("   M cambia perfil"),
        ]),
        Line::from(vec![
            Span::raw(format!("Red: {:?}", state.gateway_network)),
            Span::raw(format!(
                "   chain_id ETH: {}   Y cambia red",
                address::chain_id_label_for(&ChainType::Ethereum, state.gateway_network)
            )),
        ]),
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
            Span::raw("Cantidad cripto/token hoy: "),
            Span::styled(
                format!("{:.8}", state.cached_volume_units),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("Valor fiat estimado hoy: "),
            Span::styled(
                format!(
                    "{:.2} {}",
                    state.cached_fiat_value, state.input_fiat_currency
                ),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("Reloj verificado: "),
            Span::styled(clock_status.status, Style::default().fg(Color::Gray)),
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
            Span::styled("[2] Max cripto/token diario: ", field_style(1)),
            Span::raw(&state.input_max_volume),
        ]),
        Line::from(vec![
            Span::styled("[3] Max valor fiat diario: ", field_style(2)),
            Span::raw(&state.input_max_fiat_value),
        ]),
        Line::from(vec![
            Span::styled("[4] Moneda fiat: ", field_style(3)),
            Span::raw(&state.input_fiat_currency),
        ]),
        Line::from(vec![
            Span::styled("[5] Activo precio manual: ", field_style(4)),
            Span::raw(&state.input_price_asset),
        ]),
        Line::from(vec![
            Span::styled("[6] Precio manual activo/FIAT: ", field_style(5)),
            Span::raw(&state.input_price_value),
        ]),
        Line::from(vec![
            Span::styled("[7] Nuevo DEX ID: ", field_style(6)),
            Span::raw(&state.input_new_dex_id),
        ]),
        Line::from(vec![
            Span::styled("[8] Nuevo CEX ID: ", field_style(7)),
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
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
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

    let price_list = List::new(gateway_price_items(&state.price_quotes)).block(
        Block::default()
            .title(" Precios manuales/offline ")
            .borders(Borders::ALL),
    );
    frame.render_widget(price_list, list_chunks[2]);

    let footer = Paragraph::new(
        "P politicas | S reglas | $ precios | I inspector | N nodos | M perfil | Y red | R rearme | Ctrl+V/doble-clic pega | Esc",
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

fn gateway_price_items<'a>(items: &'a [PriceQuote]) -> Vec<ListItem<'a>> {
    if items.is_empty() {
        return vec![ListItem::new(
            "Sin precios manuales. Configure activo y precio.",
        )];
    }
    items
        .iter()
        .rev()
        .take(8)
        .map(|quote| {
            ListItem::new(format!(
                "  - {}/{} = {} ({})",
                quote.asset, quote.fiat, quote.value, quote.source
            ))
        })
        .collect()
}

fn draw_web3_account_policies(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

    let header = Paragraph::new("POLITICAS WEB3 POR CUENTA")
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
    frame.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Percentage(40),
            Constraint::Percentage(30),
        ])
        .split(chunks[1]);

    let items = if state.account_policies.is_empty() {
        vec![ListItem::new("Sin politicas por cuenta.")]
    } else {
        state
            .account_policies
            .iter()
            .enumerate()
            .map(|(idx, policy)| {
                let marker = if idx == state.web3_policy_selected {
                    ">"
                } else {
                    " "
                };
                ListItem::new(format!(
                    "{} {:?} cuenta {} indice {:?} - {}",
                    marker, policy.chain, policy.account_index, policy.address_index, policy.label
                ))
            })
            .collect()
    };
    frame.render_widget(
        List::new(items).block(Block::default().title(" Politicas ").borders(Borders::ALL)),
        body[0],
    );

    let focus = |idx: usize| {
        if state.web3_policy_focus == idx {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        }
    };
    let form = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("[0] Red: ", focus(0)),
            Span::raw(format!("{:?}", selected_policy_chain(state))),
            Span::raw("  [ / ] cambia"),
        ]),
        Line::from(vec![
            Span::styled("[1] Cuenta: ", focus(1)),
            Span::raw(&state.web3_policy_account_index),
        ]),
        Line::from(vec![
            Span::styled("[2] Indice: ", focus(2)),
            Span::raw(if state.web3_policy_address_index.is_empty() {
                "*"
            } else {
                &state.web3_policy_address_index
            }),
        ]),
        Line::from(vec![
            Span::styled("[3] Etiqueta: ", focus(3)),
            Span::raw(&state.web3_policy_label),
        ]),
        Line::from(vec![
            Span::styled("[4] Max TX: ", focus(4)),
            Span::raw(&state.web3_policy_max_tx),
        ]),
        Line::from(vec![
            Span::styled("[5] Max cripto/token: ", focus(5)),
            Span::raw(&state.web3_policy_max_crypto),
        ]),
        Line::from(vec![
            Span::styled("[6] Max FIAT: ", focus(6)),
            Span::raw(&state.web3_policy_max_fiat),
        ]),
        Line::from(vec![
            Span::styled("[7] Moneda: ", focus(7)),
            Span::raw(&state.web3_policy_fiat_currency),
        ]),
        Line::from(vec![
            Span::styled("[8] Confirmacion local: ", focus(8)),
            Span::raw(if state.web3_policy_require_confirmation {
                "si"
            } else {
                "no"
            }),
        ]),
    ])
    .block(Block::default().title(" Editor ").borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    frame.render_widget(form, body[1]);

    let side = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("[9] Destinos: ", focus(9)),
            Span::raw(&state.web3_policy_destination_input),
        ]),
        Line::from(vec![
            Span::styled("[10] Contratos: ", focus(10)),
            Span::raw(&state.web3_policy_contract_input),
        ]),
        Line::from(vec![
            Span::styled("[11] Activo: ", focus(11)),
            Span::raw(&state.web3_policy_asset_input),
        ]),
        Line::from(vec![
            Span::styled("[12] Limite activo: ", focus(12)),
            Span::raw(&state.web3_policy_asset_limit_input),
        ]),
        Line::from(""),
        Line::from("Destinos/contratos separados por coma."),
        Line::from("S abre reglas programadas."),
    ])
    .block(Block::default().title(" Listas ").borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    frame.render_widget(side, body[2]);

    let footer = Paragraph::new(
        "Enter guarda | Delete elimina | Tab campo | Flechas seleccionan | S reglas | Esc pasarela",
    )
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, chunks[2]);
}

fn draw_web3_scheduled_rules(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);
    let header = Paragraph::new("REGLAS PROGRAMADAS WEB3")
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let focus = |idx: usize| {
        if state.web3_schedule_focus == idx {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        }
    };
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(chunks[1]);
    let current_rules = state
        .account_policies
        .get(state.web3_policy_selected)
        .map(|policy| policy.scheduled_rules.clone())
        .unwrap_or_default();
    let list_items = if current_rules.is_empty() {
        vec![ListItem::new("Sin reglas para la politica seleccionada.")]
    } else {
        current_rules
            .iter()
            .enumerate()
            .map(|(idx, rule)| {
                let marker = if idx == state.web3_schedule_selected {
                    ">"
                } else {
                    " "
                };
                ListItem::new(format!(
                    "{} {} {} -> {}",
                    marker, rule.name, rule.asset, rule.destination
                ))
            })
            .collect()
    };
    frame.render_widget(
        List::new(list_items).block(Block::default().title(" Reglas ").borders(Borders::ALL)),
        body[0],
    );

    let form = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("[0] Nombre: ", focus(0)),
            Span::raw(&state.web3_schedule_name),
        ]),
        Line::from(vec![
            Span::styled("[1] Activo: ", focus(1)),
            Span::raw(&state.web3_schedule_asset),
        ]),
        Line::from(vec![
            Span::styled("[2] Destino: ", focus(2)),
            Span::raw(&state.web3_schedule_destination),
        ]),
        Line::from(vec![
            Span::styled("[3] Max TX: ", focus(3)),
            Span::raw(&state.web3_schedule_max_tx),
        ]),
        Line::from(vec![
            Span::styled("[4] Max activo: ", focus(4)),
            Span::raw(&state.web3_schedule_max_asset),
        ]),
        Line::from(vec![
            Span::styled("[5] Max FIAT: ", focus(5)),
            Span::raw(&state.web3_schedule_max_fiat),
        ]),
        Line::from(vec![
            Span::styled("[6] Moneda: ", focus(6)),
            Span::raw(&state.web3_schedule_currency),
        ]),
        Line::from(vec![
            Span::styled("[7] Ventana: ", focus(7)),
            Span::raw(&state.web3_schedule_window),
        ]),
        Line::from(vec![
            Span::styled("[8] Caduca UNIX: ", focus(8)),
            Span::raw(&state.web3_schedule_expires_unix),
        ]),
    ])
    .block(Block::default().title(" Editor ").borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    frame.render_widget(form, body[1]);

    let footer =
        Paragraph::new("Enter guarda | Delete elimina por nombre | Tab campo | Esc politicas")
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, chunks[2]);
}

fn draw_web3_price_oracle(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);
    let header = Paragraph::new("ORACULO DE PRECIOS WEB3")
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);
    let prices = gateway_price_items(&state.price_quotes);
    frame.render_widget(
        List::new(prices).block(Block::default().title(" Precios ").borders(Borders::ALL)),
        body[0],
    );
    let focus = |idx: usize| {
        if state.web3_price_focus == idx {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        }
    };
    let form = Paragraph::new(vec![
        Line::from("Modo actual: OFFLINE MANUAL"),
        Line::from(vec![
            Span::styled("[0] Activo: ", focus(0)),
            Span::raw(&state.web3_price_asset),
        ]),
        Line::from(vec![
            Span::styled("[1] Fiat: ", focus(1)),
            Span::raw(&state.web3_price_fiat),
        ]),
        Line::from(vec![
            Span::styled("[2] Valor: ", focus(2)),
            Span::raw(&state.web3_price_value),
        ]),
        Line::from(vec![
            Span::styled("[3] Max edad s: ", focus(3)),
            Span::raw(&state.web3_price_max_age_seconds),
        ]),
        Line::from(vec![
            Span::styled("[4] Ruta import: ", focus(4)),
            Span::raw(&state.web3_price_import_path),
        ]),
        Line::from(""),
        Line::from(format!("Fuente: {}", state.web3_price_source)),
        Line::from("I: importar .lvcprices firmado (verificacion Ed25519 en backend)."),
    ])
    .block(Block::default().title(" Editor ").borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    frame.render_widget(form, body[1]);
    frame.render_widget(
        Paragraph::new(
            "Enter guarda precio manual | I importar firmado | Tab campo | Esc pasarela",
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL)),
        chunks[2],
    );
}

fn draw_web3_rpc_inspector(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);
    let header = Paragraph::new(format!(
        "INSPECTOR RPC | PERFIL {}",
        state.nodes.profile().label()
    ))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);
    let focus = |idx: usize| {
        if state.web3_rpc_focus == idx {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        }
    };
    let body = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("[0] Red: ", focus(0)),
            Span::raw(selected_rpc_chain_name(state)),
            Span::raw("  ←/→ cambia"),
        ]),
        Line::from(vec![
            Span::styled("[1] Direccion: ", focus(1)),
            Span::raw(&state.web3_rpc_address),
        ]),
        Line::from(vec![
            Span::styled("[2] Activo: ", focus(2)),
            Span::raw(&state.web3_rpc_asset),
        ]),
        Line::from(vec![
            Span::styled("[3] TXID/estado: ", focus(3)),
            Span::raw(&state.web3_rpc_tx_status),
        ]),
        Line::from(""),
        Line::from(format!("Balance: {}", state.web3_rpc_balance)),
        Line::from(format!("Nonce: {}", state.web3_rpc_nonce)),
        Line::from(format!("Fee: {}", state.web3_rpc_fee)),
        Line::from(""),
        Line::from(Span::styled(
            &state.web3_rpc_status,
            Style::default().fg(Color::Magenta),
        )),
    ])
    .block(
        Block::default()
            .title(" Lectura controlada ")
            .borders(Borders::ALL),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(body, chunks[1]);
    frame.render_widget(
        Paragraph::new("B balance | N nonce | F fee | T estado TX | Tab campo | Esc pasarela")
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL)),
        chunks[2],
    );
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

fn draw_wallet_auditor(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " AUDITOR VISUAL DE DIRECCIONES PUBLICAS ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("solo deriva claves publicas; no firma transacciones"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(header, chunks[0]);

    let focused = |index: usize| {
        if state.auditor_focus == index {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        }
    };
    let controls = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("[Red] ", focused(0)),
            Span::raw(format!("{:?}", selected_auditor_chain(state))),
            Span::raw(format!("  red:{:?}  ", state.auditor_network)),
            Span::raw("←/→ cadena · n red"),
        ]),
        Line::from(vec![
            Span::styled("[Cuenta] ", focused(1)),
            Span::raw(&state.auditor_account_index),
            Span::raw("   +/- ajusta"),
        ]),
        Line::from(vec![
            Span::styled("[Indice] ", focused(2)),
            Span::raw(&state.auditor_address_index),
            Span::raw("   Enter deriva · V verifica"),
        ]),
        Line::from(vec![
            Span::styled("[Verificar] ", focused(3)),
            Span::raw(if state.auditor_expected_input.is_empty() {
                "(teclee la direccion esperada)"
            } else {
                &state.auditor_expected_input
            }),
        ]),
        Line::from(Span::styled(
            &state.auditor_status,
            Style::default().fg(Color::Magenta),
        )),
    ])
    .block(
        Block::default()
            .title(" Selector local ")
            .borders(Borders::ALL),
    );
    frame.render_widget(controls, chunks[1]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(chunks[2]);

    let selected_chain = selected_auditor_chain(state);
    let account_index = state
        .auditor_account_index
        .trim()
        .parse::<u32>()
        .unwrap_or(0);
    let address_index = state
        .auditor_address_index
        .trim()
        .parse::<u32>()
        .unwrap_or(0);
    let derivation_path = derivation_path_label(&selected_chain, account_index, address_index);
    let mut details = vec![
        Line::from(vec![
            Span::styled("Red: ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{:?}", selected_chain)),
        ]),
        Line::from(vec![
            Span::styled("Cuenta: ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{} - cuenta logica HD", account_index)),
        ]),
        Line::from(vec![
            Span::styled("Indice direccion: ", Style::default().fg(Color::Cyan)),
            Span::raw(address_index.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Ruta: ", Style::default().fg(Color::Cyan)),
            Span::raw(derivation_path),
        ]),
        Line::from(vec![
            Span::styled("Soporte: ", Style::default().fg(Color::Cyan)),
            Span::raw(chain_support_status(&selected_chain)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("chain_id: ", Style::default().fg(Color::Cyan)),
            Span::raw(address::chain_id_label_for(&selected_chain, state.auditor_network)),
        ]),
        Line::from(vec![
            Span::styled("Direccion / etiqueta: ", Style::default().fg(Color::Cyan)),
            Span::raw(if state.auditor_address.is_empty() {
                "pendiente de derivacion"
            } else {
                &state.auditor_address
            }),
        ]),
    ];
    if !state.auditor_segwit_address.is_empty() {
        details.push(Line::from(vec![
            Span::styled("SegWit (bech32): ", Style::default().fg(Color::Cyan)),
            Span::raw(&state.auditor_segwit_address),
        ]));
    }
    if !state.auditor_match_status.is_empty() {
        let color = if state.auditor_match_status.starts_with("OK") {
            Color::Green
        } else {
            Color::Red
        };
        details.push(Line::from(vec![
            Span::styled("Verificacion: ", Style::default().fg(Color::Cyan)),
            Span::styled(&state.auditor_match_status, Style::default().fg(color)),
        ]));
    }
    details.push(Line::from(""));
    details.push(Line::from(Span::styled(
        "Clave publica hexadecimal:",
        Style::default().fg(Color::Cyan),
    )));
    if state.auditor_public_key_hex.is_empty() {
        details.push(Line::from("pendiente"));
    } else {
        for line in chunk_string(&state.auditor_public_key_hex, 72)
            .into_iter()
            .take(8)
        {
            details.push(Line::from(line));
        }
    }
    details.push(Line::from(""));
    details.extend(account_policy_label(
        &state.account_policies,
        &selected_chain,
        account_index,
        address_index,
        &state.input_max_tx,
        &state.input_max_fiat_value,
        &state.input_fiat_currency,
    ));
    let details_box = Paragraph::new(details)
        .block(
            Block::default()
                .title(" Resultado criptografico y politica ")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(details_box, body[0]);

    let right_panel = if let Some(payload) = wallet_qr_payload(state) {
        let mut lines = vec![
            Line::from(Span::styled(
                "QR ASCII individual",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(format!(
                "{:?} cuenta {} indice {}",
                selected_chain, account_index, address_index
            )),
            Line::from(""),
        ];
        lines.extend(qr_lines(&payload));
        lines.push(Line::from(""));
        lines.push(Line::from("C / Ctrl+C copia el vinculo publico completo."));
        Paragraph::new(lines).alignment(Alignment::Center).block(
            Block::default()
                .title(" QR wallet / vinculo publico ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
    } else {
        Paragraph::new(address_fingerprint_lines("LIVENCRYPT-AUDITOR-PENDING"))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .title(" Huella visual ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
    };
    frame.render_widget(right_panel, body[1]);

    let footer = Paragraph::new(
        "Enter deriva | V verifica | C copia | n red | Tab campo | +/- indices | [Verificar] Ctrl+V/doble-clic pega direccion | Esc",
    )
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(footer, chunks[3]);
}

fn chunk_string(value: &str, chunk_chars: usize) -> Vec<String> {
    if value.is_empty() {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    for ch in value.chars() {
        current.push(ch);
        if current.chars().count() >= chunk_chars {
            chunks.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn address_fingerprint_lines(value: &str) -> Vec<Line<'static>> {
    let digest = Keccak256::digest(value.as_bytes());
    let mut lines = Vec::new();
    lines.push(Line::from("Comparacion visual local"));
    lines.push(Line::from(""));
    for row in 0..9 {
        let mut text = String::with_capacity(19);
        text.push(' ');
        for col in 0..17 {
            let byte = digest[(row * 17 + col) % digest.len()];
            let bit = (byte >> (col % 8)) & 1;
            text.push(if bit == 1 { '#' } else { '.' });
        }
        lines.push(Line::from(text));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(truncate_chars(value, 32)));
    lines
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

fn settings_secondary_box_line(state: &TuiState, index: usize) -> Line<'static> {
    let focus_index = 7 + index;
    let valid = box_value_valid(&state.settings_boot_secondary_cajas[index]);
    let style = if valid {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    };
    Line::from(vec![
        Span::raw(format!(
            "{} caja B{}: ",
            marker(state.settings_focus == focus_index),
            index + 1
        )),
        Span::styled(state.settings_boot_secondary_cajas[index].clone(), style),
    ])
}

fn settings_duress_box_line(state: &TuiState, index: usize) -> Line<'static> {
    let focus_index = 13 + index;
    let valid = box_value_valid(&state.settings_duress_cajas[index]);
    let style = if valid {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    };
    Line::from(vec![
        Span::raw(format!(
            "{} caja D{}: ",
            marker(state.settings_focus == focus_index),
            index + 1
        )),
        Span::styled(state.settings_duress_cajas[index].clone(), style),
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
        Line::from("clic/Tab campos | PgUp/PgDown scroll | B Boot ON | O OFF | D coaccion | S red | T inactividad | P AppArmor ON | U OFF | Z reauth destructiva | Esc"),
        Line::from(""),
        Line::from(format!(
            "SECCION: ACCESO | modo vault actual: {}",
            state.boot_credential_mode
        )),
        settings_box_line(state, 0),
        settings_box_line(state, 1),
        settings_box_line(state, 2),
        settings_box_line(state, 3),
        settings_box_line(state, 4),
        Line::from(format!("{} frase: {}", marker(state.settings_focus == 5), "*".repeat(state.settings_boot_frase.chars().count()))),
        Line::from(format!("{} plantilla arranque: {}", marker(state.settings_focus == 6), state.settings_boot_template)),
        Line::from(""),
        Line::from("SECCION: DOBLE CREDENCIAL OPCIONAL"),
        settings_secondary_box_line(state, 0),
        settings_secondary_box_line(state, 1),
        settings_secondary_box_line(state, 2),
        settings_secondary_box_line(state, 3),
        settings_secondary_box_line(state, 4),
        Line::from(format!("{} frase B: {}", marker(state.settings_focus == 12), "*".repeat(state.settings_boot_secondary_frase.chars().count()))),
        Line::from(""),
        Line::from("SECCION: CLAVE DE COACCION"),
        settings_duress_box_line(state, 0),
        settings_duress_box_line(state, 1),
        settings_duress_box_line(state, 2),
        settings_duress_box_line(state, 3),
        settings_duress_box_line(state, 4),
        Line::from(format!("{} frase D: {}", marker(state.settings_focus == 18), "*".repeat(state.settings_duress_frase.chars().count()))),
        Line::from("Al introducirla en el arranque se muestra fallo fisico simulado y se destruye el vault."),
        Line::from(format!(
            "{} bloqueo inactividad: {} ({}s)",
            marker(state.settings_focus == 21),
            if state.inactivity_enabled { "ON" } else { "OFF" },
            state.inactivity_timeout_seconds
        )),
        Line::from(""),
        Line::from("SECCION: PROTECCION WALLETS (AUDITOR)"),
        Line::from(format!(
            "Re-auth destructiva auditor (tecla Z): {}",
            if state.settings_destructive_auditor_reauth {
                "ON"
            } else {
                "OFF"
            }
        )),
        Line::from(
            "Si ON, un fallo en la re-confirmacion del auditor DESTRUYE el vault (exige backup externo).",
        ),
        Line::from(""),
        Line::from("SECCION: RED (solo configuracion, no se ejecutan pruebas de red)"),
        Line::from(format!("{} perfil: {}", marker(state.settings_focus == 19), state.settings_network_profile)),
        Line::from(format!("{} confirmacion: {}", marker(state.settings_focus == 20), state.settings_network_confirmation)),
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
                    .title(format!(
                        " Configuracion del sistema | scroll {} ",
                        state.settings_scroll
                    ))
                    .borders(Borders::ALL),
            )
            .scroll((state.settings_scroll, 0))
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
            .title(" Auditoria avanzada - V verifica cadena Web3 firmada | Esc vuelve ")
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

fn draw_sandbox_manager(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(7)])
        .split(area);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(chunks[0]);

    let field_style = |index: usize| {
        if state.sandbox_focus == index {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        }
    };
    let launcher = Paragraph::new(vec![
        Line::from(Span::styled(
            "Lanzador de procesos en RAM",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("[Ruta binario] ", field_style(0)),
            Span::raw(truncate_chars(&state.sandbox_payload_path, 76)),
        ]),
        Line::from(vec![
            Span::styled("[Memoria MiB] ", field_style(1)),
            Span::raw(&state.sandbox_memory_mib),
        ]),
        Line::from(vec![
            Span::styled("[CPU segundos] ", field_style(2)),
            Span::raw(&state.sandbox_cpu_seconds),
        ]),
        Line::from(vec![
            Span::styled("[Archivo MiB] ", field_style(3)),
            Span::raw(&state.sandbox_file_size_mib),
        ]),
        Line::from(""),
        Line::from("Enter lanza memfd | B explorador | K mata PID seleccionado | Esc vuelve"),
        Line::from(Span::styled(
            &state.sandbox_status,
            Style::default().fg(Color::Magenta),
        )),
    ])
    .block(
        Block::default()
            .title(" Sandbox expu - lanzador ")
            .borders(Borders::ALL),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(launcher, body[0]);

    let active = if state.sandbox_active_pids.is_empty() {
        vec![ListItem::new("Sin procesos sandbox activos.")]
    } else {
        state
            .sandbox_active_pids
            .iter()
            .enumerate()
            .map(|(index, pid)| {
                let prefix = if index == state.sandbox_selected_pid {
                    ">"
                } else {
                    " "
                };
                ListItem::new(format!(
                    "{} PID {} | memfd | NEWNET/NEWNS/NEWIPC",
                    prefix, pid
                ))
            })
            .collect::<Vec<_>>()
    };
    let monitor = List::new(active).block(
        Block::default()
            .title(" Procesos sandbox ")
            .borders(Borders::ALL),
    );
    frame.render_widget(monitor, body[1]);

    let risk = security::ai_monitor::expu_baseline_risk();
    let mut footer_lines = security::sandbox::sandbox_capability_summary()
        .into_iter()
        .map(Line::from)
        .collect::<Vec<_>>();
    footer_lines.insert(
        0,
        Line::from(format!("Riesgo heuristico base: {:.0}%", risk * 100.0)),
    );
    footer_lines.push(Line::from(
        "Esta pantalla no ejecuta nada automaticamente; Enter lanza el payload seleccionado.",
    ));
    let footer = Paragraph::new(footer_lines)
        .block(
            Block::default()
                .title(" Capacidades y control ")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(footer, chunks[1]);
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

#[cfg(test)]
mod field_input_tests {
    use super::{sanitize_into_field, FieldKind};

    fn apply(kind: FieldKind, current: &str, input: &str) -> String {
        let mut field = current.to_string();
        sanitize_into_field(kind, &mut field, input, 64);
        field
    }

    #[test]
    fn integer_field_accepts_only_digits() {
        assert_eq!(apply(FieldKind::Integer, "", "12ab3"), "123");
        assert_eq!(apply(FieldKind::Integer, "", "-5"), "5");
        assert_eq!(apply(FieldKind::Integer, "", "1.5"), "15");
    }

    #[test]
    fn signed_integer_allows_leading_minus_only() {
        assert_eq!(apply(FieldKind::SignedInteger, "", "-42"), "-42");
        assert_eq!(apply(FieldKind::SignedInteger, "1", "-2"), "12");
        assert_eq!(apply(FieldKind::SignedInteger, "", "9-9"), "99");
    }

    #[test]
    fn decimal_field_accepts_digits_and_single_separator() {
        assert_eq!(apply(FieldKind::Decimal, "", "12.34"), "12.34");
        assert_eq!(apply(FieldKind::Decimal, "", "1,5"), "1.5");
        assert_eq!(apply(FieldKind::Decimal, "", "1.2.3"), "1.23");
        assert_eq!(apply(FieldKind::Decimal, "", "0xBTC9"), "09");
    }

    #[test]
    fn text_field_accepts_text_numbers_and_special_chars() {
        assert_eq!(
            apply(FieldKind::Text, "", "0xAbC_123-!@#"),
            "0xAbC_123-!@#"
        );
        // Los caracteres de control (saltos de línea) se descartan.
        assert_eq!(apply(FieldKind::Text, "", "a\nb\tc"), "abc");
    }

    #[test]
    fn respects_max_len() {
        assert_eq!(apply(FieldKind::Text, "abcd", &"x".repeat(100)).len(), 64);
    }
}
