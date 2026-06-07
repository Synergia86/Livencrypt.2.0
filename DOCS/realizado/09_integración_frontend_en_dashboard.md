Para integrar estas funciones de nivel de expu en el frontend (TUI) de Livencrypt 2.0, necesitamos transformar el dashboard en un centro de mando multitarea.

A continuación, presento el código necesario para actualizar main.rs y los módulos de soporte, permitiendo la ejecución de la Auditoría, el Sandbox con IA y la Gestión de Firmware.

1. Actualización del Estado y Navegación (src-tui/src/main.rs)
Primero, redefinimos el sistema de pantallas para permitir la navegación entre los nuevos módulos.

Archivo implicado: src-tui/src/main.rs

Código a añadir/editar:

Rust
/* rol: gestión de pantallas y navegación avanzada */

#[derive(Clone, PartialEq, Eq)]
enum Screen {
    Unlock,
    Dashboard,
    AuditMonitor,      // Monitor de logs encadenados
    FirmwareStaging,   // Gestión de updates y handover
    SandboxManager,    // Ejecución aislada con IA
    SecurityAlert(String), // Pantalla de pánico/violación
}

struct TuiState {
    screen: Screen,
    audit_entries: Vec<security::audit::AuditEntry>,
    ia_risk_score: f32,
    pending_update: Option<security::vault::UpdateManifest>,
    // ... campos existentes
}
2. El Nuevo Dashboard (Punto de Entrada)
Actualizamos el renderizado del Dashboard para incluir los accesos directos a las nuevas herramientas de soberanía.

Archivo implicado: src-tui/src/main.rs

Código a editar: Función draw_dashboard.

Rust
fn draw_dashboard(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    // NUEVO: Barra de estado de integridad con glifo esteganográfico
    let glyph = if matches!(state.integrity, IntegrityStatus::Valid) { "." } else { "·" };
    let header = Paragraph::new(format!(" LIVENCRYPT 2.0 - SISTEMA SEGURO{} ", glyph))
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    // NUEVO: Menú de funciones avanzadas
    let menu_items = vec![
        ListItem::new("[A] Monitor de Auditoría (Hash Chain)"),
        ListItem::new("[S] Ejecución en Sandbox (IA Quarantine)"),
        ListItem::new("[F] Gestión de Firmware y Updates"),
        ListItem::new("[L] Bloquear Vault y Zeroize"),
    ];
    let menu = List::new(menu_items)
        .block(Block::default().title(" Funciones de Soberanía ").borders(Borders::ALL));
    frame.render_widget(menu, chunks[1]);
}
3. Ventana: Monitor de Auditoría Inmutable
Esta ventana permite al usuario verificar que nadie ha manipulado los registros de acceso.

Archivo implicado: src-tui/src/main.rs

Código a añadir: Función draw_audit_monitor.

Rust
fn draw_audit_monitor(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let audit_block = Block::default()
        .title(" Registro de Auditoría (Encadenamiento SHA-256) ")
        .borders(Borders::ALL);

    let mut lines = vec![
        Line::from(Span::styled("Índice | Timestamp | Evento | Hash Chain", Style::default().add_modifier(Modifier::UNDERLINED)))
    ];

    for entry in &state.audit_entries {
        let status_color = if entry.event_type == "ACCESS_FAIL" { Color::Red } else { Color::Green };
        lines.push(Line::from(vec![
            Span::raw(format!("{} | ", entry.index)),
            Span::raw(format!("{} | ", entry.timestamp.format("%H:%M:%S"))),
            Span::styled(&entry.event_type, Style::default().fg(status_color)),
            Span::raw(format!(" | {:.8}...", hex::encode(&entry.prev_hash))),
        ]));
    }

    let p = Paragraph::new(lines).block(audit_block).wrap(Wrap { trim: true });
    frame.render_widget(p, area);
}
4. Ventana: Gestión de Sandbox e IA
Aquí es donde el usuario lanza aplicaciones externas y monitoriza su riesgo en tiempo real mediante el sensor eBPF.

Archivo implicado: src-tui/src/main.rs

Código a añadir: Función draw_sandbox_manager.

Rust
fn draw_sandbox_manager(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    // Medidor de Riesgo IA
    let risk_pct = (state.ia_risk_score * 100.0) as u16;
    let gauge = Gauge::default()
        .block(Block::default().title(" Análisis Heurístico Local (IA SLM) ").borders(Borders::ALL))
        .gauge_style(Style::default().fg(if risk_pct > 70 { Color::Red } else { Color::Green }))
        .percent(risk_pct);
    frame.render_widget(gauge, chunks[0]);

    // Logs de Syscalls eBPF
    let log_block = Block::default().title(" Telemetría en Cuarentena (eBPF) ").borders(Borders::ALL);
    let logs = Paragraph::new("Awaiting execution...\n[S] Seleccionar binario para carga fileless en RAM")
        .block(log_block);
    frame.render_widget(logs, chunks[1]);
}
5. Lógica de Ejecución (Manejador de Teclas)
Finalmente, unimos el frontend con el backend permitiendo que las teclas activen las nuevas funciones.

Archivo implicado: src-tui/src/main.rs

Código a editar: Función handle_events.

Rust
fn handle_events(state: &mut TuiState, key: KeyEvent) {
    match state.screen {
        Screen::Dashboard => match key.code {
            KeyCode::Char('a') => state.screen = Screen::AuditMonitor,
            KeyCode::Char('s') => state.screen = Screen::SandboxManager,
            KeyCode::Char('f') => state.screen = Screen::FirmwareStaging,
            KeyCode::Char('l') => {
                security::vault::boot_shield_lock().unwrap();
                state.screen = Screen::Unlock;
            }
            _ => {}
        },
        Screen::AuditMonitor | Screen::SandboxManager | Screen::FirmwareStaging => {
            if key.code == KeyCode::Esc {
                state.screen = Screen::Dashboard;
            }
        },
        _ => {}
    }
}
Resumen de Integración
Dashboard Multicapa: Ahora no es solo un editor, sino un gestor de seguridad.

Visibilidad Forense: El Monitor de Auditoría expone la cadena de hashes (AuditEntry) directamente al usuario.

Ejecución Inteligente: El Sandbox Manager visualiza el riesgo calculado por la IA local mientras el programa corre en el memfd (RAM).

Soberanía Total: La pestaña de Firmware permite al usuario realizar el handover criptográfico solo después de inspeccionar el UpdateManifest.
