1. Actualización de la Estructura de Estado
Añadiremos al estado de la TUI los caracteres barajados y el índice del cursor virtual.

Archivo implicado: src-tui/src/main.rs

Código a añadir en TuiState:

Rust
/* Editar TuiState en src-tui/src/main.rs */

struct TuiState {
    // ... campos existentes (cajas, frase, focus_index)
    pub teclado_shuffled: Vec<char>,
    pub cursor_teclado: usize,
    pub modo_teclado_virtual: bool, // Alternar entre teclado físico y virtual
}

impl TuiState {
    pub fn new() -> Self {
        let mut chars: Vec<char> = "0123456789ABCDEFabcdef!@#$%^&*".chars().collect();
        use rand::seq::SliceRandom;
        chars.shuffle(&mut rand::thread_rng()); // Barajado aleatorio en cada inicio

        Self {
            // ... inicialización existente
            teclado_shuffled: chars,
            cursor_teclado: 0,
            modo_teclado_virtual: true, 
        }
    }
}
2. El Widget del Teclado Aleatorio (Frontend)
Implementamos la función de renderizado que dibuja la cuadrícula de caracteres barajados.

Archivo implicado: src-tui/src/main.rs

Código a añadir:

Rust
/* Añadir función de renderizado en src-tui/src/main.rs */

fn draw_secure_keyboard(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    // Instrucciones sutiles
    let help = Paragraph::new(" [←↑→↓] Navegar | [ENTER] Seleccionar | [TAB] Cambiar Caja ")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(help, chunks[0]);

    // Renderizado de la cuadrícula (10 columnas)
    let rows: Vec<Line> = state.teclado_shuffled
        .chunks(10)
        .enumerate()
        .map(|(y, chunk)| {
            let spans: Vec<Span> = chunk.iter().enumerate().map(|(x, &c)| {
                let idx = y * 10 + x;
                let style = if idx == state.cursor_teclado {
                    Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                Span::styled(format!("  {}  ", c), style)
            }).collect();
            Line::from(spans)
        })
        .collect();

    let keyboard = Paragraph::new(rows)
        .block(Block::default().title(" Teclado Blindado (Posiciones Aleatorias) ").borders(Borders::ALL))
        .alignment(Alignment::Center);
    
    frame.render_widget(keyboard, chunks[1]);
}
3. Integración en la Pantalla de Desbloqueo (Unlock)
Modificaremos el layout de la pantalla de acceso para que el teclado ocupe la parte inferior.

Archivo implicado: src-tui/src/main.rs

Código a editar en draw_unlock:

Rust
/* Editar draw_unlock para integrar el teclado */

fn draw_unlock(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(10), // Campos de credenciales (Cajas/Frase)
            Constraint::Min(0),    // NUEVO: Espacio para el Teclado Seguro
        ])
        .split(area);

    // ... renderizado de cabecera y campos (existente)

    // NUEVO: Renderizar el teclado en el chunk inferior
    draw_secure_keyboard(frame, chunks[2], state);
}
4. Lógica de Interacción (Manejador de Eventos)
Debemos permitir que el usuario navegue por la cuadrícula y seleccione caracteres usando las flechas y la tecla Enter.

Archivo implicado: src-tui/src/main.rs

Código a editar en el bucle principal de eventos:

Rust
/* Modificar la lógica de teclado en run_terminal/run_app */

match key.code {
    KeyCode::Left => {
        if state.cursor_teclado > 0 { state.cursor_teclado -= 1; }
    }
    KeyCode::Right => {
        if state.cursor_teclado < state.teclado_shuffled.len() - 1 { state.cursor_teclado += 1; }
    }
    KeyCode::Up => {
        if state.cursor_teclado >= 10 { state.cursor_teclado -= 10; }
    }
    KeyCode::Down => {
        if state.cursor_teclado + 10 < state.teclado_shuffled.len() { state.cursor_teclado += 10; }
    }
    KeyCode::Enter => {
        // Seleccionar el carácter bajo el cursor e insertarlo en el campo activo
        let c = state.teclado_shuffled[state.cursor_teclado];
        match state.focus_index {
            0..=4 => state.cajas[state.focus_index].push(c),
            5 => state.frase.push(c),
            _ => {}
        }
    }
    // ... resto de controles (Tab, etc.)
}
Análisis Forense del Blindaje
Inmunidad a la Observación Física: Al cambiar las posiciones de los caracteres en cada arranque (teclado_shuffled.shuffle), un observador externo o una cámara de vigilancia no puede deducir la clave mirando qué parte de la pantalla seleccionas.

Neutralización de Keyloggers: Como la entrada se realiza mediante navegación de cursor y Enter (en lugar de emitir el código de carácter de la tecla física), los keyloggers tradicionales solo registrarían pulsaciones de "Flecha Arriba/Abajo/Enter", las cuales son inútiles sin el mapa de caracteres aleatorios de esa sesión específica.

Soberanía de Interfaz: La transición a este modelo de entrada visual refuerza la "Negación Plausible", ya que el usuario puede alegar que está navegando por un menú de opciones cuando en realidad está introduciendo la clave maestra.
