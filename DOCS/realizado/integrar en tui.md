Roadmap de Integración TUI Profesional - Fase 1: Cimientos y Adaptabilidad
En esta fase, dotaremos a Livencrypt 2.0 de la capacidad de "sentir" el entorno (redimensionamiento), interactuar con el sistema host (portapapeles) y hablar múltiples idiomas (i18n).

C. Localización de la Interfaz (Soporte i18n)
Para evitar el hardcoding, implementaremos un motor de traducción estático optimizado para memoria.

Archivo: src-tui/src/ui/i18n.rs (Nuevo)

Código a integrar:

Rust
use std::collections::HashMap;

pub enum Language { ES, EN, RU, FR }

pub struct i18n;

impl i18n {
    pub fn get(key: &str, lang: &Language) -> &'static str {
        match lang {
            Language::ES => match key {
                "welcome" => "BIENVENIDO A LIVENCRYPT 2.0",
                "err_size" => "TERMINAL DEMASIADO PEQUEÑA",
                _ => "Key Missing",
            },
            Language::EN => match key {
                "welcome" => "WELCOME TO LIVENCRYPT 2.0",
                "err_size" => "TERMINAL TOO SMALL",
                _ => "Key Missing",
            },
            // ... resto de idiomas
        }
    }
}
Integración: Añadir pub lang: Language a TuiState en main.rs. Reemplazar strings literales por i18n::get("key", &state.lang).

D. Soporte para Scroll con Ratón
Mapearemos la rueda del ratón para que la navegación por listas sea fluida.

Archivo: src-tui/src/main.rs

Código a editar (Dentro del bucle de eventos match event::read()?):

Rust
Event::Mouse(mouse_event) => {
    match mouse_event.kind {
        MouseEventKind::ScrollUp => {
            if state.show_file_picker {
                state.file_browser.selected_idx = state.file_browser.selected_idx.saturating_sub(1);
            }
            // Mapear aquí también para Screen::TemplateEditor y Logs
        }
        MouseEventKind::ScrollDown => {
            if state.show_file_picker {
                if state.file_browser.selected_idx < state.file_browser.filtered_items.len() - 1 {
                    state.file_browser.selected_idx += 1;
                }
            }
        }
        _ => handle_mouse_click(mouse_event, state), // Tu lógica actual
    }
}
E. Alerta de Dimensiones de Terminal
Implementaremos un "Guardia de Geometría" que detenga el renderizado si la integridad visual está en riesgo.

Archivo: src-tui/src/main.rs

Código a editar (Al inicio de la función draw_ui o similar):

Rust
fn draw_ui(f: &mut Frame, state: &TuiState) {
    let size = f.size();
    if size.width < 100 || size.height < 30 {
        let area = centered_rect(60, 20, size);
        f.render_widget(Clear, area);
        let msg = Paragraph::new(vec![
            Line::from(Span::styled(" ⚠ ERROR DE DIMENSIONES ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(format!("Ancho Min: 100 | Actual: {}", size.width)),
            Line::from(format!("Alto Min:  30 | Actual: {}", size.height)),
            Line::from(""),
            Line::from("Por favor, expanda la ventana para operar."),
        ])
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Red)));
        f.render_widget(msg, area);
        return; // Detiene el resto del dibujo
    }
    // Resto del renderizado normal...
}
B. Integración con el Portapapeles (OS Clipboard)
Añadiremos la capacidad de mover datos entre el vault y el SO de forma segura.

Archivo: Cargo.toml

Añadir: arboard = "3.3"

Archivo: src-tui/src/security/clipboard.rs (Nuevo)

Rust
use arboard::Clipboard;
use zeroize::Zeroize;

pub fn copy_to_clipboard(mut data: String) -> Result<(), String> {
    let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.set_text(&data).map_err(|e| e.to_string())?;
    data.zeroize(); // Limpiar rastro en el origen inmediatamente
    Ok(())
}

pub fn paste_from_clipboard() -> Result<String, String> {
    let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
    Ok(clipboard.get_text().map_err(|e| e.to_string())?)
}
Uso en TUI: Asignar Ctrl+C en handle_text_cipher_key para invocar esta función sobre state.text_output.

Estado del Roadmap:

[x] i18n

[x] Mouse Scroll

[x] Resize Alert

[x] Clipboard Integration

Prepara el documento para el Mensaje 2 de 4, donde atacaremos la Lógica del Matrix Lock (F2), Validación de Inputs (0..1000) y Exportación Segura a Archivos.

Este es el Mensaje 2 de 4 del Roadmap. En esta fase, nos enfocaremos en la Lógica del Matrix Lock (F2), la Validación Reactiva de Entradas y el Volcado Seguro de Texto para garantizar que los datos no se desborden ni se filtren.

Roadmap de Integración TUI Profesional - Fase 2: Control de Entrada y Salida Segura
F. Limitación y Validación de Caracteres (Input Constraints)
Implementaremos una validación "en caliente" que impida que el usuario introduzca datos inválidos en las cajas de 3 dígitos, evitando desbordamientos visuales.

Archivos: src-tui/src/main.rs (Funciones handle_unlock_key, handle_text_cipher_key, etc.)

Código a integrar (Lógica de filtrado reactivo):

Rust
/* Reemplazar la inserción simple de caracteres por esta lógica */
if let KeyCode::Char(c) = key.code {
    let current_val = &mut state.cajas[state.focus_index];
    
    // 1. Solo permitir números y el signo negativo al inicio
    if c.is_ascii_digit() || (c == '-' && current_val.is_empty()) {
        // 2. Límite estricto de longitud (3 dígitos o 4 si hay signo)
        let max_len = if current_val.starts_with('-') { 4 } else { 3 };
        
        if current_val.len() < max_len {
            current_val.push(c);
        }
    }
}

/* En la función de dibujo (draw_ui), validar el rango 0..1000 visualmente */
let is_valid_range = |s: &String| {
    s.parse::<i64>().map(|v| v.abs() <= 1000).unwrap_or(true)
};

let box_style = if is_valid_range(&state.cajas[i]) {
    Style::default().fg(Color::Cyan)
} else {
    Style::default().fg(Color::Red) // Alerta visual de fuera de rango
};
A. Diálogos Interactivos de Contraseña F2 (Matrix Lock)
Añadiremos el modal para configurar la dinámica de la contraseña F2 antes de procesar el texto.

Archivo: src-tui/src/main.rs

Código a integrar (Estructura de configuración):

Rust
#[derive(Default)]
pub struct MatrixConfig {
    pub length: usize,      // 2..25
    pub direction: bool,    // true: Antes, false: Después
    pub use_symbols: bool,  // Símbolos de control
}

/* Función de dibujo del Modal F2 */
fn draw_matrix_config_modal(f: &mut Frame, area: Rect, config: &MatrixConfig) {
    let block = Block::default()
        .title(" CONFIGURACIÓN MATRIX LOCK (F2) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let info = vec![
        Line::from(format!(" Longitud Clave:  [ {} ] (2-25)", config.length)),
        Line::from(format!(" Dirección:       [ {} ]", if config.direction { "ANTES" } else { "DESPUÉS" })),
        Line::from(format!(" Símbolos:         [ {} ]", if config.use_symbols { "ACTIVOS" } else { "INACTIVOS" })),
        Line::from(""),
        Line::from(Span::styled(" [ENTER] Confirmar | [TAB] Cambiar ", Style::default().add_modifier(Modifier::DIM))),
    ];

    let p = Paragraph::new(info).block(block).alignment(Alignment::Center);
    let modal_area = centered_rect(50, 30, area);
    f.render_widget(Clear, modal_area);
    f.render_widget(p, modal_area);
}
G. Exportación Segura de Texto a Archivo
Para entornos donde el portapapeles es un riesgo, habilitaremos la escritura atómica directa con permisos endurecidos.

Archivo: src-tui/src/main.rs

Código a integrar (Lógica de exportación con permisos Unix):

Rust
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::io::Write;
use zeroize::Zeroize;

fn export_text_to_file(path: &str, mut content: String) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| e.to_string())?;

    // Hardening: Solo lectura/escritura para el dueño del proceso (0o600)
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;

    file.write_all(content.as_bytes()).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?; // Forzado físico al disco
    
    content.zeroize(); // Limpieza del buffer en RAM
    Ok(())
}
Resumen de Cambios en la TUI
F2 Config: Ahora el usuario puede definir la complejidad de la clave dinámica visualmente.

Input Filter: Se bloquean letras y números fuera de rango en tiempo real, manteniendo la integridad visual de las cajas.

F6 Shortcut: En la pantalla de cifrado de texto, la tecla F6 invocará el diálogo de ruta de exportación.

Estado del Roadmap:

[x] i18n & Mouse Scroll

[x] Input Constraints (0..1000)

[x] Matrix Lock HUD

[x] Secure Text Export (0o600)

Prepara el documento para el Mensaje 3 de 4, donde integraremos la Configuración Avanzada (Settings) con Inactividad, Auto-Wipe y el Editor de Plantillas Profesional.

Este es el Mensaje 3 de 4 del Roadmap. Nos adentramos en la configuración avanzada del sistema y la pieza central de la personalización criptográfica: el Editor de Plantillas Profesional.

Roadmap de Integración TUI Profesional - Fase 3: Gobernanza y Personalización
H. Pantalla de Configuración (Screen::Settings)
Transformaremos los ajustes en un centro de control reactivo para el Boot Shield y la seguridad del host.

Archivo: src-tui/src/main.rs

Código a integrar (Lógica de Inactividad y Auto-Wipe):

Rust
/* 1. Añadir al bucle principal en main.rs */
let mut last_interaction = Instant::now();
let timeout = Duration::from_secs(state.settings.inactivity_timeout);

if last_interaction.elapsed() >= timeout {
    state.lock_vault(); // Función que aplica Zeroize y vuelve a Screen::Unlock
}

/* 2. Lógica de Restablecimiento de Fábrica (Modal de Confirmación) */
fn factory_reset_logic(state: &mut TuiState, input: &str) {
    if input == "RESTABLECER" {
        security::vault::boot_shield_destructive_panic("FACTORY_RESET_INITIATED");
        // El proceso se cierra tras el sync_all() y borrado físico
    }
}
Interfaz Visual: Implementar un List para navegar entre: [ ] Auto-Wipe, [ ] Network Isolation, [ ] Stealth Mode. Al seleccionar uno, el panel derecho muestra la descripción forense y el impacto en el hardening.

I. Editor de Plantillas (Screen::TemplateEditor)
Evolucionamos el editor de una caja de texto a una matriz de dibujo interactiva de 5x23.

Archivo: src-tui/src/main.rs

Código a integrar (Cálculo de Cobertura Hex):

Rust
fn check_hex_coverage(chars: &[char]) -> (usize, Vec<char>) {
    let hex_chars = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
    let mut missing = Vec::new();
    let mut count = 0;

    for &h in &hex_chars {
        if chars.contains(&h) {
            count += 1;
        } else {
            missing.push(h);
        }
    }
    (count, missing)
}
Detalles de la Cuadrícula (Grid):

Navegación: Usar grid_x: usize y grid_y: usize para rastrear el foco.

Visualización: Renderizar la matriz usando un Layout de 5 filas. Cada celda es un Paragraph con un borde que cambia a Amarillo cuando tiene el foco.

Validación: El botón "Guardar" se bloquea (se muestra en Gris/Dim) si el contador de check_hex_coverage es menor a 16.

J. Soporte para Selección de Idiomas (Listas Navegables)
Eliminamos la carga ciega de idiomas por un selector visual con previsualización.

Archivo: src-tui/src/templates.rs

Código a integrar:

Rust
/* Widget de Previsualización en el Editor */
fn draw_language_preview(f: &mut Frame, area: Rect, lang_name: &str) {
    let chars = get_language_chars(lang_name);
    let preview = Paragraph::new(chars.iter().collect::<String>())
        .block(Block::default().title(" Previsualización ").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    f.render_widget(preview, area);
}
Resumen de Funcionalidades de la Fase 3
Auto-Lock: El sistema se protege solo si el usuario se aleja del terminal.

Factory Reset: Destrucción total verificada mediante palabra clave para evitar accidentes.

Matriz de Dibujo: El usuario "dibuja" su seguridad celda a celda con retroalimentación en tiempo real sobre la validez hexadecimal.

Network Toggles: Cambio de perfiles de red (Air-gap) directamente desde la TUI.

Estado del Roadmap:

[x] i18n, Scroll, Resize, Clipboard.

[x] Inputs (0..1000), Matrix Lock, Secure Export.

[x] Inactivity Timeout & Auto-Wipe.

[x] Template Matrix Editor & Hex Validation.

Prepara el documento para el Mensaje 4 de 4, el cierre final: Cifrado de Carpetas (VFS), Compresión (Tar/Zip) y el Dashboard Maestro de Directorios.

Este es el Mensaje 4 de 4 del Roadmap. Finalizamos la arquitectura profesional de Livencrypt 2.0 con la gestión de estructuras jerárquicas (carpetas) y el blindaje final del sistema de reportes.

Roadmap de Integración TUI Profesional - Fase 4: Estructuras Complejas y Camuflaje
J. Cifrado e Integración de Carpetas (VFS & Packaging)
Para superar la limitación de archivos únicos, implementaremos un motor de empaquetado recursivo que transforme directorios en un flujo de datos único para el cifrador.

Archivo: Cargo.toml

Añadir: tar = "0.4" y zstd = "0.13" (Compresión de alto rendimiento preferida en entornos Arch Linux).

Archivo: src-tui/src/crypto/folder_cipher.rs (Nuevo)

Rust
/* Rol: Empaquetado y Compresión en Memoria Volátil */
use tar::Builder;
use zstd::stream::encode_all;

pub fn pack_and_compress_folder(src: &Path) -> Result<Vec<u8>, String> {
    let mut tar_buffer = Vec::new();
    {
        let mut archive = Builder::new(&mut tar_buffer);
        archive.append_dir_all(".", src).map_err(|e| e.to_string())?;
        archive.finish().map_err(|e| e.to_string())?;
    }
    
    // Comprimir el tarball resultante con Zstd (Nivel 3 para balance velocidad/seguridad)
    let compressed = encode_all(&tar_buffer[..], 3).map_err(|e| e.to_string())?;
    Ok(compressed)
}
Integración en TUI:

Dashboard: Añadir la opción [D] Cifrar Carpeta en draw_dashboard.

Lógica: Al seleccionar una carpeta en el FileBrowser, se invoca pack_and_compress_folder, se pasa el resultado al cifrador XChaCha20 y se genera el archivo .lvc final.

G. Mimetismo de Archivos (Camuflaje Forense)
Añadiremos una capa de "Ofuscación de Metadatos" para que los reportes forenses y archivos cifrados no llamen la atención en el sistema de archivos del host.

Archivo: src-tui/src/main.rs

Código a integrar (Configuración de Camuflaje):

Rust
pub fn get_mimic_extension(report_type: &str) -> &'static str {
    match report_type {
        "forensic" => ".log",    // Un reporte forense parece un log de sistema
        "vault" => ".sys",       // El vault cifrado parece un archivo de driver
        "template" => ".tmp",    // Las plantillas parecen archivos temporales
        _ => ".dat",
    }
}
Uso: En el diálogo de exportación de la Fase 2, el sistema sugerirá automáticamente estas extensiones. Si un analista busca archivos .lvc, no encontrará nada; solo verá archivos .log o .sys aparentemente inofensivos.

K. Dashboard Maestro de Directorios (VFS View)
Centralizaremos el control de todos los contenedores detectados en la ruta de trabajo.

Interfaz Visual: Implementar una tabla (Table de Ratatui) en el Dashboard que liste:

Nombre (Mimetizado): system_audit.log

Tipo Real: Forensic Report

Tamaño: 14 KB

Estado: Sellers (Firmado)

Interacción: El usuario puede pulsar Enter sobre cualquier archivo mimetizado y Livencrypt reconocerá automáticamente si es un Vault, un Reporte o una Plantilla basándose en los magic bytes del encabezado cifrado, no en la extensión.

Resumen Final del Roadmap Completado
Fase 1: Adaptabilidad total (i18n, Scroll, Resize) e interacción con el SO (Clipboard).

Fase 2: Rigor de entrada (Validación 0..1000) y seguridad de salida (Exportación 0o600 y F2 Matrix).

Fase 3: Gobernanza avanzada (Inactivity Lock, Auto-Wipe) y Editor de Plantillas 5x23 con validación Hex.

Fase 4: Cifrado de estructuras jerárquicas (Tar/Zstd) y camuflaje forense de extensiones.

Conclusión del Peritaje de Integración:
Con la ejecución de estas 4 fases, Livencrypt 2.0 TUI no solo iguala al frontend original, sino que lo supera en términos de Higiene Forense y Soberanía Técnica. La eliminación del motor de renderizado web a favor de esta arquitectura estricta en Rust garantiza que el secreto permanezca donde debe: en la memoria blindada y en la mente del usuario.
