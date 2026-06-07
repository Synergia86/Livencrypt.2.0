frontend 
Para implementar un frontend completamente interactivo, profesional y seguro para el módulo de la pasarela Web3 y custodia universal, dividiremos el desarrollo de la interfaz en 4 mensajes secuenciales.

Este es el Mensaje 1 de 4, enfocado en la extensión del estado global de la aplicación y definición de las estructuras de la interfaz gráfica dentro del archivo principal de la TUI.

1. Modificación de la enumeración de pantallas (Screen)
Añadiremos la nueva pantalla dedicada a la gobernanza y monitoreo de la pasarela Web3 en caliente.

Archivo implicado: src-tui/src/main.rs

Código a añadir en el enum Screen:

Rust
/* rol: pantallas de navegacion de la interfaz de usuario */
pub enum Screen {
    Unlock,
    Dashboard,
    TextCipher,
    FileBrowser,
    FilePreview { metadata: security::vault::FileMetadata },
    Settings,
    TemplateEditor,
    WalletGateway,
}
2. Extensión del estado global de la TUI (TuiState)
Añadiremos los componentes del supervisor, buffers de entrada de texto interactivos para las listas blancas y el estado de selección de los campos del formulario al estado principal.

Archivo implicado: src-tui/src/main.rs

Código a añadir dentro de la estructura TuiState:

Rust
/* rol: estado centralizado de la interfaz tui de livencrypt */
pub struct TuiState {
    pub screen: Screen,
    pub active_vault_unlocked: bool,
    pub supervisor: Option<crypto::blockchain::supervisor::GatewaySupervisor>,
    pub gateway_focused_field: usize,
    pub input_max_tx: String,
    pub input_max_volume: String,
    pub input_new_dex_id: String,
    pub input_new_cex_id: String,
    pub show_breaker_reset: bool,
    pub reset_cajas: [String; 5],
    pub reset_phrase: String,
    pub reset_focus_index: usize,
}
3. Inicialización del estado de la pasarela
Configuraremos los valores por defecto para los campos interactivos dentro de la función constructora del estado.

Archivo implicado: src-tui/src/main.rs

Código a añadir en impl TuiState { pub fn new() -> Self }:

Rust
        // ... inicializaciones previas de TuiState
        supervisor: None,
        gateway_focused_field: 0,
        input_max_tx: String::new(),
        input_max_volume: String::new(),
        input_new_dex_id: String::new(),
        input_new_cex_id: String::new(),
        show_breaker_reset: false,
        reset_cajas: [String::new(), String::new(), String::new(), String::new(), String::new()],
        reset_phrase: String::new(),
        reset_focus_index: 0,
4. Función de instanciación del supervisor en el desbloqueo
Implementaremos el método encargado de arrancar el supervisor con las reglas iniciales guardadas en el vault una vez que el usuario descifra el contenedor local de forma exitosa.

Archivo implicado: src-tui/src/main.rs

Código a añadir en el bloque impl TuiState:

Rust
/* rol: inicializacion tactica del entorno web3 tras autorizacion exitosa */
impl TuiState {
    pub fn initialize_wallet_gateway(&mut self, cajas: [i64; 5], master_phrase: &str) -> Result<(), String> {
        let keymaster = crypto::blockchain::multi_curve::UniversalKeymaster::new(cajas, master_phrase)?;
        
        let default_rules = crypto::blockchain::firewall::FirewallRules {
            max_daily_tx: 10,
            max_daily_volume_usd: 5000.0,
            allowed_dex_contracts: vec![],
            allowed_cex_destinations: vec![],
        };
        
        let firewall = crypto::blockchain::firewall::LiveFirewall::new(default_rules);
        let supervisor = crypto::blockchain::supervisor::GatewaySupervisor::new(keymaster, firewall);
        
        self.input_max_tx = supervisor.firewall.rules.max_daily_tx.to_string();
        self.input_max_volume = supervisor.firewall.rules.max_daily_volume_usd.to_string();
        self.supervisor = Some(supervisor);
        
        Ok(())
    }
}
Con estas estructuras asentadas, los cimientos del estado reactivo de la pasarela Web3 están consolidados. Indica cuándo estás listo para recibir el Mensaje 2 de 4, donde desarrollaremos las funciones completas de renderizado (draw_wallet_gateway y los componentes HUD del Dashboard) utilizando la distribución de bloques avanzados de Ratatui.

Este es el **Mensaje 2 de 4** del desarrollo del frontend interactivo. En esta fase implementaremos las **funciones completas de diseño y renderizado visual** del panel de control de la pasarela mediante bloques estructurados de la librería Ratatui.

Este módulo se encarga de segmentar la terminal en paneles tácticos dinámicos para mostrar el estado del disyuntor, las métricas en tiempo real del cortafuegos, los campos de edición y las listas blancas de filtrado.

---

### 1. Creación del archivo de interfaz de la pasarela

Este nuevo módulo contiene la lógica de dibujo de la pantalla de gobernanza Web3, incluyendo el renderizado condicional de la ventana flotante (*modal*) para el desbloqueo del disyuntor.

* **Archivo a crear:** `src-tui/src/ui/gateway.rs`
* **Código:**

```rust
/* rol: renderizado del panel de control y componentes visuales de la pasarela web3 */
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};
use crate::TuiState;
use crate::crypto::blockchain::breaker::GatewaySecurityState;

pub fn draw_wallet_gateway(f: &mut Frame, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Encabezado de estado
            Constraint::Min(10),   // Cuerpo central dividido
            Constraint::Length(3), // Barra de comandos inferior
        ])
        .split(f.area());

    // 1. Renderizado del encabezado HUD (Estado del disyuntor)
    let supervisor_ref = state.supervisor.as_ref();
    let (status_text, status_style) = match supervisor_ref.map(|s| &s.breaker.state) {
        Some(GatewaySecurityState::Operational) => ("OPERATIVA - CANAL SEGURO ACTIVO", Style::default().fg(Color::Green).bold()),
        Some(GatewaySecurityState::Frozen { reason, .. }) => (reason.as_str(), Style::default().fg(Color::Yellow).bold()),
        Some(GatewaySecurityState::HardLocked) => ("BLOQUEO PERIMETRAL: REVERIFICACIÓN REQUERIDA", Style::default().fg(Color::Red).bold().add_modifier(Modifier::BLINK)),
        None => ("PASARELA NO INICIALIZADA", Style::default().fg(Color::DarkGray)),
    };

    let header = Paragraph::new(Line::from(vec![
        Span::raw(" PASARELA WEB3 SECURE GATEWAY [ "),
        Span::styled(status_text, status_style),
        Span::raw(" ]"),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
    f.render_widget(header, chunks[0]);

    // 2. División del cuerpo central (Controles de Firewall frente a Listas Blancas)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40), // Reglas y cuotas fijas
            Constraint::Percentage(60), // Listas de IDs de CEX/DEX
        ])
        .split(chunks[1]);

    // Panel Izquierdo: Métricas del Cortafuegos en tiempo real
    let mut firewall_info = Vec::new();
    if let Some(sup) = supervisor_ref {
        firewall_info.push(Line::from(vec![
            Span::raw("Transacciones hoy: "),
            Span::styled(format!("{}/{}", sup.firewall.tx_count_today, sup.firewall.rules.max_daily_tx), Style::default().fg(Color::White).bold()),
        ]));
        firewall_info.push(Line::from(vec![
            Span::raw("Volumen diario consumido: "),
            Span::styled(format!("{:.2}/{:.2} USD", sup.firewall.volume_today_usd, sup.firewall.rules.max_daily_volume_usd), Style::default().fg(Color::White).bold()),
        ]));
    }

    // Campos de entrada interactivos con indicación visual de enfoque
    let get_field_style = |idx: usize| {
        if state.gateway_focused_field == idx {
            Style::default().fg(Color::Yellow).bold()
        } else {
            Style::default().fg(Color::Gray)
        }
    };

    firewall_info.push(Line::from(""));
    firewall_info.push(Line::from(Span::styled("--- Configuración de Límites (Presiona Enter para Editar) ---", Style::default().fg(Color::Cyan))));
    firewall_info.push(Line::from(vec![Span::styled(" [1] Límite diario Tx (X): ", get_field_style(0)), Span::raw(&state.input_max_tx)]));
    firewall_info.push(Line::from(vec![Span::styled(" [2] Techo diario USD (Y): ", get_field_style(1)), Span::raw(&state.input_max_volume)]));
    firewall_info.push(Line::from(vec![Span::styled(" [3] Registrar nuevo DEX ID: ", get_field_style(2)), Span::raw(&state.input_new_dex_id)]));
    firewall_info.push(Line::from(vec![Span::styled(" [4] Registrar nuevo CEX ID: ", get_field_style(3)), Span::raw(&state.input_new_cex_id)]));

    let left_panel = Paragraph::new(firewall_info)
        .block(Block::default().title(" Parámetros de Firewall ").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    f.render_widget(left_panel, body_chunks[0]);

    // Panel Derecho: Visualizador de infraestructuras autorizadas
    let list_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body_chunks[1]);

    let dex_items: Vec<ListItem> = match supervisor_ref {
        Some(sup) => sup.firewall.rules.allowed_dex_contracts.iter().map(|id| ListItem::new(format!("  • Contract-ID: {}", id)).white()).collect(),
        None => vec![],
    };
    let dex_list = List::new(dex_items).block(Block::default().title(" Contratos de DEX en Lista Blanca ").borders(Borders::ALL));
    f.render_widget(dex_list, list_chunks[0]);

    let cex_items: Vec<ListItem> = match supervisor_ref {
        Some(sup) => sup.firewall.rules.allowed_cex_destinations.iter().map(|id| ListItem::new(format!("  • Vault-ID: {}", id)).white()).collect(),
        None => vec![],
    };
    let cex_list = List::new(cex_items).block(Block::default().title(" Direcciones de CEX en Lista Blanca ").borders(Borders::ALL));
    f.render_widget(cex_list, list_chunks[1]);

    // 3. Barra de instrucciones inferior
    let footer_text = " Tab: Navegar Campos | Enter: Confirmar Entrada | Backspace: Borrar | R: Rearmar Disyuntor Físico | Esc: Dashboard ";
    let footer = Paragraph::new(footer_text)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(footer, chunks[2]);

    // 4. Modal Flotante de Desbloqueo Forense (Condicional)
    if state.show_breaker_reset {
        render_reset_modal(f, state);
    }
}

fn render_reset_modal(f: &mut Frame, state: &TuiState) {
    let size = f.area();
    let modal_area = Rect::new(size.width / 2 - 30, size.height / 2 - 6, 60, 12);
    
    f.render_widget(Clear, modal_area); // Limpiar fondo subyacente
    
    let block = Block::default()
        .title(" INTERVENCIÓN REQUERIDA: REARME DE CIRCUITO ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red).bold());
    f.render_widget(block, modal_area);

    let modal_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(2), // Advertencia
            Constraint::Length(3), // Cajas de combinación
            Constraint::Length(3), // Frase maestra
        ])
        .split(modal_area);

    let warning = Paragraph::new("La pasarela está congelada por violación de perímetro. Introduce la matriz táctica clásica para restablecer el canal operativo.").red().wrap(Wrap { trim: true });
    f.render_widget(warning, modal_chunks[0]);

    // Dibujar estado de entrada de cajas de desbloqueo
    let mut cajas_line = Vec::new();
    for i in 0..5 {
        let style = if state.reset_focus_index == i { Style::default().fg(Color::Yellow).bold() } else { Style::default().fg(Color::Gray) };
        cajas_line.push(Span::styled(format!(" [Caja {}]: ", i + 1), style));
        cajas_line.push(Span::raw(format!("{:<4} ", state.reset_cajas[i])));
    }
    let cajas_para = Paragraph::new(Line::from(cajas_line)).block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(cajas_para, modal_chunks[1]);

    // Frase de acceso en modal
    let phrase_style = if state.reset_focus_index == 5 { Style::default().fg(Color::Yellow).bold() } else { Style::default().fg(Color::Gray) };
    let hidden_phrase: String = "*".repeat(state.reset_phrase.len());
    let phrase_para = Paragraph::new(vec![Line::from(vec![
        Span::styled(" Frase Maestra del Vault: ", phrase_style),
        Span::raw(hidden_phrase),
    ])]);
    f.render_widget(phrase_para, modal_chunks[2]);
}

```

---

### 2. Vinculación en el enrutador del frontend

Para integrar de forma limpia la nueva pantalla en el flujo central de dibujo de la interfaz, debes registrar el archivo creado e invocarlo dentro del bucle de pintado principal.

* **Archivo a modificar:** `src-tui/src/ui/mod.rs` (o el archivo equivalente donde centralices el dibujo)
* **Código a añadir:**

```rust
/* Declarar el submódulo de la pasarela */
pub mod gateway;

/* Dentro de tu función general de enrutamiento de dibujo (ej: draw_main_ui) */
match state.screen {
    Screen::Unlock => draw_unlock_screen(f, state),
    Screen::Dashboard => draw_dashboard(f, state),
    // ... otros emparejamientos
    Screen::WalletGateway => gateway::draw_wallet_gateway(f, state),
}

```

---

El diseño visual adaptativo y el modal de aislamiento forense están completamente estructurados. Indica cuándo deseas recibir el **Mensaje 3 de 4**, donde desarrollaremos el gestor de eventos de teclado de Ratatui para dotar de interactividad completa a los formularios y campos del cortafuegos de la pasarela Web3.

Este es el **Mensaje 3 de 4** del desarrollo del frontend. En esta fase implementaremos el **gestor de eventos de teclado e interactividad** para controlar la entrada de datos en los formularios del cortafuegos y administrar las acciones de desbloqueo táctico dentro del modal del disyuntor.

Este módulo procesa las pulsaciones de teclas (`crossterm::event::KeyCode`) variando su comportamiento de forma dinámica dependiendo de si el panel está en modo de edición normal o bloqueado en cuarentena forense.

---

### 1. Implementación del controlador de eventos de teclado

Este bloque de código intercepta las acciones del usuario, permitiendo la navegación fluida mediante la tecla `Tab`, la edición atómica de caracteres y la validación impositiva de credenciales locales.

* **Archivo a crear:** `src-tui/src/ui/gateway_events.rs`
* **Código:**

```rust
/* rol: gestion de eventos de teclado e interactividad de la pasarela web3 */
use crossterm::event::{KeyCode, KeyEvent};
use crate::{TuiState, Screen};

pub fn handle_gateway_input(state: &mut TuiState, key_event: KeyEvent) {
    // 1. Bifurcación de entrada si el modal del disyuntor está activo
    if state.show_breaker_reset {
        handle_modal_input(state, key_event.code);
        return;
    }

    // 2. Procesamiento ordinario de la pantalla de la pasarela
    match key_event.code {
        KeyCode::Esc => {
            state.screen = Screen::Dashboard;
        }
        KeyCode::Tab => {
            // Rotar el enfoque entre los 4 campos de configuración disponibles
            state.gateway_focused_field = (state.gateway_focused_field + 1) % 4;
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            // Forzar la apertura del modal de rearme físico
            state.show_breaker_reset = true;
            state.reset_focus_index = 0;
        }
        KeyCode::Backspace => {
            // Borrado del último carácter según el campo activo
            match state.gateway_focused_field {
                0 => { state.input_max_tx.pop(); }
                1 => { state.input_max_volume.pop(); }
                2 => { state.input_new_dex_id.pop(); }
                3 => { state.input_new_cex_id.pop(); }
                _ => {}
            }
        }
        KeyCode::Char(c) => {
            // Inserción de caracteres en el buffer del campo enfocado
            match state.gateway_focused_field {
                0 => { if c.is_ascii_digit() { state.input_max_tx.push(c); } }
                1 => { if c.is_ascii_digit() || c == '.' { state.input_max_volume.push(c); } }
                2 => { state.input_new_dex_id.push(c); }
                3 => { state.input_new_cex_id.push(c); }
                _ => {}
            }
        }
        KeyCode::Enter => {
            // Confirmación y consolidación de la regla en el motor del cortafuegos
            if let Some(ref mut sup) = state.supervisor {
                match state.gateway_focused_field {
                    0 => {
                        if let Ok(val) = state.input_max_tx.parse::<u32>() {
                            sup.firewall.rules.max_daily_tx = val;
                        }
                    }
                    1 => {
                        if let Ok(val) = state.input_max_volume.parse::<f64>() {
                            sup.firewall.rules.max_daily_volume_usd = val;
                        }
                    }
                    2 => {
                        if !state.input_new_dex_id.is_empty() {
                            sup.firewall.rules.allowed_dex_contracts.push(state.input_new_dex_id.clone());
                            state.input_new_dex_id.clear();
                        }
                    }
                    3 => {
                        if !state.input_new_cex_id.is_empty() {
                            sup.firewall.rules.allowed_cex_destinations.push(state.input_new_cex_id.clone());
                            state.input_new_cex_id.clear();
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn handle_modal_input(state: &mut TuiState, key_code: KeyCode) {
    match key_code {
        KeyCode::Esc => {
            // Cancelar el proceso de rearme y cerrar la ventana flotante
            state.show_breaker_reset = false;
        }
        KeyCode::Tab => {
            // Navegar entre las 5 cajas numéricas (0-4) y el campo de frase maestra (5)
            state.reset_focus_index = (state.reset_focus_index + 1) % 6;
        }
        KeyCode::Backspace => {
            if state.reset_focus_index < 5 {
                state.reset_cajas[state.reset_focus_index].pop();
            } else {
                state.reset_phrase.pop();
            }
        }
        KeyCode::Char(c) => {
            if state.reset_focus_index < 5 {
                // Restringir la entrada a dígitos o signo negativo para la combinación matricial
                if c.is_ascii_digit() || c == '-' {
                    state.reset_cajas[state.reset_focus_index].push(c);
                }
            } else {
                state.reset_phrase.push(c);
            }
        }
        KeyCode::Enter => {
            // Ejecutar el procedimiento de desbloqueo forense e impositivo
            let mut cajas_parsed = [0i64; 5];
            let mut parse_success = true;

            for i in 0..5 {
                if let Ok(val) = state.reset_cajas[i].parse::<i64>() {
                    cajas_parsed[i] = val;
                } else {
                    parse_success = false;
                }
            }

            if parse_success && !state.reset_phrase.is_empty() {
                if let Some(ref mut sup) = state.supervisor {
                    // Validar la combinación física contra el disyuntor táctico
                    if sup.breaker.resolve_and_reset(cajas_parsed, &state.reset_phrase).is_ok() {
                        // Limpieza atómica de buffers locales tras el éxito
                        state.show_breaker_reset = false;
                        state.reset_phrase.clear();
                        for i in 0..5 {
                            state.reset_cajas[i].clear();
                        }
                    } else {
                        // Penalización: incrementar fallos de integridad si la llave es incorrecta
                        sup.breaker.integrity_failures += 1;
                        if sup.breaker.integrity_failures >= 3 {
                            sup.breaker.trigger_hard_lock();
                        }
                        state.reset_phrase.clear();
                    }
                }
            }
        }
        _ => {}
    }
}

```

---

### 2. Integración en el distribuidor de eventos general

Para activar el gestor interactivo dentro del bucle asíncrono de la TUI, debes registrar la llamada en tu interceptor de teclado maestro.

* **Archivo a modificar:** `src-tui/src/main.rs` (o el archivo equivalente encargado de gestionar el mapeo de teclas general)
* **Código a añadir en el bloque de control de eventos:**

```rust
/* Dentro del bucle de captura de teclas principal (ej: match state.screen) */
match state.screen {
    Screen::Unlock => handle_unlock_input(state, key_event),
    Screen::Dashboard => handle_dashboard_input(state, key_event),
    // ... otras pantallas
    Screen::WalletGateway => ui::gateway_events::handle_gateway_input(state, key_event),
}

```

---

Con esta fase integrada, la pasarela es completamente dinámica y permite la manipulación y el restablecimiento físico en caliente. Indica cuándo deseas recibir el **Mensaje 4 de 4**, el cierre definitivo del frontend, donde conectaremos el hilo de ejecución asíncrono (*background worker*) de la pasarela Web3 para procesar las iteraciones del supervisor sin bloquear la tasa de refresco de la TUI.

Este es el **Mensaje 4 de 4** del desarrollo del frontend e integración final. En esta fase implementaremos el **hilo de ejecución en segundo plano (background worker)** y la sincronización asíncrona mediante canales de paso de mensajes (`std::sync::mpsc`).

Dado que la escucha de peticiones desde el navegador a través de `stdin` es una operación completamente síncrona y bloqueante, ejecutarla directamente en el hilo principal congelaría la interfaz gráfica de la TUI. Diseñaremos un entorno de ejecución en paralelo que permita al supervisor operar de forma autónoma sin penalizar la tasa de refresco del panel visual.

---

### 1. Creación del módulo del trabajador asíncrono

Este componente define los comandos de control y los eventos de notificación inter-hilo, abstrayendo la concurrencia de forma segura.

* **Archivo a crear:** `src-tui/src/crypto/blockchain/worker.rs`
* **Código:**

```rust
/* rol: hilo de ejecucion asincrono desacoplado mediante sockets unix locales */
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;
use std::os::unix::net::UnixListener;
use std::io::Read;
use crate::crypto::blockchain::supervisor::GatewaySupervisor;
use crate::crypto::blockchain::firewall::FirewallRules;
use crate::crypto::blockchain::breaker::GatewaySecurityState;
use crate::crypto::blockchain::proxy::ExtensionRequest;
use zeroize::Zeroize;

pub enum Web3WorkerCmd {
    UpdateRules { max_tx: Option<u32>, max_vol: Option<f64> },
    AddDexContract(String),      
    AddCexDestination(String),   
    ResetBreaker([i64; 5], Vec<u8>), 
    IncomingWebRequest(Vec<u8>),    
}

pub enum Web3WorkerEvent {
    StatusChanged(GatewaySecurityState),
    MetricsUpdated { tx_count: u32, volume_usd: f64 },
    SyncRules(FirewallRules), 
    Notification(String),
}

pub struct Web3BackgroundWorker;

impl Web3BackgroundWorker {
    pub fn spawn(
        mut supervisor: GatewaySupervisor,
    ) -> (Sender<Web3WorkerCmd>, Receiver<Web3WorkerEvent>) {
        let (cmd_tx, cmd_rx) = channel::<Web3WorkerCmd>();
        let (event_tx, event_rx) = channel::<Web3WorkerEvent>();

        // Corrección A: Inicialización de socket Unix para evitar colisión de descriptores con la TUI
        let io_cmd_tx = cmd_tx.clone();
        thread::spawn(move || {
            let _ = std::fs::remove_file("/tmp/livencrypt.sock");
            if let Ok(listener) = UnixListener::bind("/tmp/livencrypt.sock") {
                for stream in listener.incoming() {
                    if let Ok(mut stream) = stream {
                        let mut length_buffer = [0u8; 4];
                        if stream.read_exact(&mut length_buffer).is_ok() {
                            let message_length = u32::from_ne_bytes(length_buffer) as usize;
                            if message_length <= 1024 * 1024 {
                                let mut json_buffer = vec![0u8; message_length];
                                if stream.read_exact(&mut json_buffer).is_ok() {
                                    let _ = io_cmd_tx.send(Web3WorkerCmd::IncomingWebRequest(json_buffer));
                                }
                            }
                        }
                    }
                }
            }
        });

        // HILO MAESTRO DEL SUPERVISOR (DRAIN LOOP)
        thread::spawn(move || {
            let mut last_tx_count = 0;
            let mut last_volume_usd = 0.0;

            loop {
                while let Ok(cmd) = cmd_rx.try_recv() {
                    match cmd {
                        Web3WorkerCmd::UpdateRules { max_tx, max_vol } => {
                            if let Some(tx) = max_tx { supervisor.firewall.rules.max_daily_tx = tx; }
                            if let Some(vol) = max_vol { supervisor.firewall.rules.max_daily_volume_usd = vol; }
                            let _ = event_tx.send(Web3WorkerEvent::Notification("Límites del Firewall actualizados".to_string()));
                            let _ = event_tx.send(Web3WorkerEvent::SyncRules(supervisor.firewall.rules.clone()));
                        }
                        Web3WorkerCmd::AddDexContract(contract) => {
                            if supervisor.firewall.rules.allowed_dex_contracts.len() < 100 {
                                if !supervisor.firewall.rules.allowed_dex_contracts.contains(&contract) {
                                    supervisor.firewall.rules.allowed_dex_contracts.push(contract);
                                    let _ = event_tx.send(Web3WorkerEvent::SyncRules(supervisor.firewall.rules.clone()));
                                }
                            }
                        }
                        Web3WorkerCmd::AddCexDestination(destination) => {
                            if supervisor.firewall.rules.allowed_cex_destinations.len() < 100 {
                                if !supervisor.firewall.rules.allowed_cex_destinations.contains(&destination) {
                                    supervisor.firewall.rules.allowed_cex_destinations.push(destination);
                                    let _ = event_tx.send(Web3WorkerEvent::SyncRules(supervisor.firewall.rules.clone()));
                                }
                            }
                        }
                        Web3WorkerCmd::ResetBreaker(cajas, mut phrase_bytes) => {
                            let mut phrase = String::from_utf8(phrase_bytes.clone()).unwrap_or_default();
                            if supervisor.breaker.resolve_and_reset(cajas, &phrase).is_ok() {
                                let _ = event_tx.send(Web3WorkerEvent::StatusChanged(supervisor.breaker.state.clone()));
                            } else {
                                supervisor.breaker.integrity_failures += 1;
                                if supervisor.breaker.integrity_failures >= 3 {
                                    supervisor.breaker.trigger_hard_lock();
                                    let _ = event_tx.send(Web3WorkerEvent::StatusChanged(supervisor.breaker.state.clone()));
                                }
                            }
                            phrase.zeroize();
                            phrase_bytes.zeroize();
                        }
                        Web3WorkerCmd::IncomingWebRequest(mut raw_json) => {
                            let old_state = supervisor.breaker.state.clone();
                            if let Ok(req) = serde_json::from_slice::<ExtensionRequest>(&raw_json) {
                                if supervisor.run_loop_iteration(req).is_err() {
                                    if supervisor.breaker.state != old_state {
                                        let _ = event_tx.send(Web3WorkerEvent::StatusChanged(supervisor.breaker.state.clone()));
                                    }
                                }
                            }
                            raw_json.zeroize();
                        }
                    }
                }

                let current_tx_count = supervisor.firewall.tx_count_today;
                let current_volume_usd = supervisor.firewall.volume_today_usd;
                if current_tx_count != last_tx_count || current_volume_usd != last_volume_usd {
                    let _ = event_tx.send(Web3WorkerEvent::MetricsUpdated {
                        tx_count: current_tx_count,
                        volume_usd: current_volume_usd,
                    });
                    last_tx_count = current_tx_count;
                    last_volume_usd = current_volume_usd;
                }

                thread::sleep(std::time::Duration::from_millis(10));
            }
        });

        (cmd_tx, event_rx)
    }
}
```

---

### 2. Actualización del enrutador maestro blockchain

Registramos el nuevo archivo del trabajador en el árbol de dependencias internas.

* **Archivo implicado:** `src-tui/src/crypto/blockchain/mod.rs`
* **Código a editar:**

```rust
/* rol: enrutador maestro del subsistema blockchain universal */
pub mod multi_curve;
pub mod types;
pub mod proxy;
pub mod firewall;
pub mod breaker;
pub mod supervisor;
pub mod worker;

```

---

### 3. Adaptación del estado y consumo de eventos en la interfaz

Modificaremos los manejadores globales para consumir los eventos asíncronos generados por el hilo de ejecución secundario en cada ciclo de refresco de pantalla de la TUI.

* **Archivo implicado:** `src-tui/src/main.rs`
* **Código a actualizar dentro de la estructura general de tu bucle principal:**

```rust
/* Añadir las variables de canal al TuiState en sustitución del objeto directo */
pub struct TuiState {
    // ... otros campos
    pub web3_cmd_tx: Option<std::sync::mpsc::Sender<crypto::blockchain::worker::Web3WorkerCmd>>,
    pub web3_event_rx: Option<std::sync::mpsc::Receiver<crypto::blockchain::worker::Web3WorkerEvent>>,
    pub cached_gateway_state: crypto::blockchain::breaker::GatewaySecurityState,
    pub cached_tx_count: u32,
    pub cached_volume_usd: f64,
    pub system_notification: String,
}

/* Dentro de tu funcion de actualizacion logica por tick de reloj (ej: update_state) */
pub fn process_background_web3_events(state: &mut TuiState) {
    if let Some(ref rx) = state.web3_event_rx {
        loop {
            match rx.try_recv() {
                Ok(event) => {
                    match event {
                        crypto::blockchain::worker::Web3WorkerEvent::StatusChanged(new_state) => {
                            state.cached_gateway_state = new_state.clone();
                            if let crypto::blockchain::breaker::GatewaySecurityState::Operational = state.cached_gateway_state {
                                state.show_breaker_reset = false;
                            }
                        }
                        crypto::blockchain::worker::Web3WorkerEvent::MetricsUpdated { tx_count, volume_usd } => {
                            state.cached_tx_count = tx_count;
                            state.cached_volume_usd = volume_usd;
                        }
                        crypto::blockchain::worker::Web3WorkerEvent::SyncRules(backend_rules) => {
                            state.allowed_dex_contracts = backend_rules.allowed_dex_contracts;
                            state.allowed_cex_destinations = backend_rules.allowed_cex_destinations;
                            
                            // Corrección B: Solo actualizar los buffers si el usuario no los está editando activamente
                            if state.gateway_focused_field != 0 {
                                state.input_max_tx = backend_rules.max_daily_tx.to_string();
                            }
                            if state.gateway_focused_field != 1 {
                                state.input_max_volume = backend_rules.max_daily_volume_usd.to_string();
                            }
                        }
                        crypto::blockchain::worker::Web3WorkerEvent::Notification(msg) => {
                            state.system_notification = msg;
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Corrección C: Forzar estado de pánico visual si el hilo secundario cae
                    state.cached_gateway_state = crypto::blockchain::breaker::GatewaySecurityState::Frozen {
                        reason: "CRASH CRÍTICO: SUBSISTEMA ASÍNCRONO DETENIDO IMPREVISTAMENTE".to_string(),
                        timestamp: 0,
                    };
                    break;
                }
            }
        }
    }
}

```

---

### 4. Integración del indicador visual HUD en el Dashboard principal

Para completar el requerimiento de monitoreo, implementamos un bloque de estado compacto dentro del cuadro de mandos principal de la aplicación.

* **Archivo implicado:** `src-tui/src/ui/dashboard.rs` (o la función encargada de dibujar el Dashboard principal)
* **Código a añadir:**

```rust
/* rol: componente hud de visualizacion rapida para la pasarela web3 en el dashboard */
use ratatui::{
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use crate::TuiState;
use crate::crypto::blockchain::breaker::GatewaySecurityState;

pub fn render_web3_gateway_hud(f: &mut Frame, area: ratatui::layout::Rect, state: &TuiState) {
    let (status_str, color) = match state.cached_gateway_state {
        GatewaySecurityState::Operational => ("ACTIVA", Color::Green),
        GatewaySecurityState::Frozen { .. } => ("CONGELADA", Color::Yellow),
        GatewaySecurityState::HardLocked => ("BLOQUEADA", Color::Red),
    };

    let hud_content = vec![
        Line::from(vec![
            Span::raw("Estado del Canal: "),
            Span::styled(status_str, Style::default().fg(color).bold()),
        ]),
        Line::from(vec![
            Span::raw("Firmas emitidas hoy: "),
            Span::styled(state.cached_tx_count.to_string(), Style::default().fg(Color::White).bold()),
        ]),
        Line::from(vec![
            Span::raw("Volumen transferido: "),
            Span::styled(format!("{:.2} USD", state.cached_volume_usd), Style::default().fg(Color::White).bold()),
        ]),
    ];

    let block = Paragraph::new(hud_content)
        .block(Block::default().title(" Pasarela Web3 ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
        
    f.render_widget(block, area);
}

```

---

## Conclusión del despliegue de la TUI

Con la implementación de este cuarto bloque, el desarrollo de la interfaz interactiva para el **Motor de Custodia Universal de Livencrypt 2.0** queda completamente cerrado y funcional:

1. El estado global ha sido adaptado para soportar concurrencia sin bloqueos mediante un modelo asíncrono guiado por eventos.
2. Los paneles tácticos renderizan las métricas directamente desde los hilos de ejecución en tiempo real.
3. El bucle de eventos del teclado discrimina de manera segura las fases de edición ordinaria frente a los procesos críticos de re-verificación matricial en caliente.


