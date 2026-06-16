# Pre-Boot Authentication (PBA) y Teclado Aleatorio

Este módulo aborda la estrategia para mitigar amenazas físicas y lógicas extremas (como troyanos a nivel de firmware, keyloggers de kernel o ataques de arranque) mediante la integración de la TUI de Livencrypt en la fase previa a la carga del sistema operativo y la aleatorización visual de las interfaces de entrada.

---

## 1. Diseño y Principios Técnicos

### A. Root vs. Criptografía: La necesidad de PBA
En un sistema operativo ya iniciado, un atacante con privilegios de **Root** (superusuario) tiene capacidad para interceptar la memoria, instalar keyloggers por software, o realizar volcados de RAM (*Cold Boot Attacks*). Para neutralizar esto:
1. **Autenticación Pre-Arranque (Pre-Boot Authentication - PBA)**: Livencrypt 2.0 se empaqueta para ejecutarse en la fase de **Initramfs** (sistema de archivos inicial en RAM) o como un cargador previo al kernel.
2. **Flujo de Encendido**:
   * El hardware arranca y la BIOS/UEFI carga el gestor de arranque (GRUB o systemd-boot).
   * Antes de montar la partición raíz `/` del disco y antes de iniciar cualquier servicio del sistema operativo (redes, daemon de depuración, etc.), se lanza la TUI de Livencrypt en modo texto puro directo.
   * El sistema está temporalmente congelado y blindado contra redes. Solo se presenta la solicitud de las 5 cajas y la frase.
   * Una vez introducida y validada la secuencia exacta, Livencrypt descifra en RAM la clave maestra, abre la partición cifrada principal y transfiere el control al kernel normal de Linux para completar el arranque.
3. **Seguridad Forense**: Sin la secuencia, el disco es 100% ruido binario incomprensible. No se puede realizar ingeniería inversa del sistema operativo del disco duro porque este aún no ha sido descifrado para el hardware.

### B. Cajas Aleatorias y Teclado Virtual Aleatorio
Para contrarrestar keyloggers por hardware, capturadores de pantalla o técnicas de espionaje visual directo (*shoulder surfing*):
* **Carga Aleatoria de Cajas**: En lugar de presentar las cajas de entrada en el orden secuencial estático de izquierda a derecha (1 a 5), la TUI las distribuye en la pantalla o solicita su entrada en una secuencia desordenada generada aleatoriamente en cada arranque.
* **Teclado Virtual Aleatorio**: La TUI de Ratatui dibuja una matriz con letras y números en pantalla. El usuario utiliza las teclas de dirección (flechas) o un puntero de consola para seleccionar los caracteres.
* **Mutación de Layout**: La disposición de los caracteres en este teclado virtual muta (se baraja aleatoriamente) en cada sesión de inicio (respetando los caracteres especiales del idioma seleccionado). Así, registrar las pulsaciones físicas de las teclas de dirección del teclado real no revela qué caracteres se están seleccionando.

---

## 2. Archivos Implicados en el Proyecto

* **[main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs)**: Debe actualizarse para implementar el widget de teclado virtual renderizado en la terminal y la lógica de aleatorización del layout de las cajas.
* **`scripts/build-deb.sh` / `scripts/initramfs-setup.sh`** *(Scripts de despliegue)*: Deberán compilar el binario de Rust-TUI de forma estática (usando la arquitectura de destino `x86_64-unknown-linux-musl`) y configurar las directivas del Initramfs de la distribución Linux host para inyectar el binario en la fase de arranque.

---

## 3. Estado de la Integración

### ¿Qué está YA integrado?
* [x] **Captura de Entrada Básica**: `main.rs` renderiza un formulario básico con 5 cajas secuenciales y una caja oculta con asteriscos para la frase de paso, procesando eventos de teclado a través de `crossterm`.
* [x] **Arquitectura sin Dependencias Gráficas**: El paso a una TUI Ratatui facilita enormemente la compilación estática y reduce el tamaño del ejecutable a pocos megabytes, lo que permite incrustarlo fácilmente en un Initramfs ligero.

### ¿Qué falta por integrar?
* [ ] **Aleatorización de Caja**: Modificar la estructura `AppState` en `main.rs` para que determine dinámicamente un orden aleatorio de enfoque de las cajas, o cambie su orden físico en la pantalla al renderizarse.
* [ ] **Widget de Teclado Virtual**: Programar el renderizador del teclado virtual de consola y el algoritmo de barajado de caracteres (*shuffling*).
* [ ] **Compilación y Configuración Estática para Initramfs**: No se cuenta con scripts o directivas de configuración para acoplar el ejecutable en el arranque seguro de Linux.

---

## Enlaces Relacionados
* Volver al [[00_indice|Índice General]].
* Ver la protección del proceso de descifrado en RAM: [[01_proteccion_ingenieria_inversa_y_hardening_memoria|Protección contra Ingeniería Inversa y Hardening de Memoria]].

## Código a integrar
1. Aleatorización de Cajas y Teclado Virtual (main.rs)
Modificaremos la estructura de estado para que las cajas no se sigan de forma lineal (1, 2, 3...) y añadiremos un teclado virtual barajado (shuffled) que se renderice en pantalla. Esto mitiga ataques de keyloggers físicos y observación visual.

Archivo implicado: src-tui/src/main.rs

Código a editar: Actualizar AppState y las funciones de renderizado.

Rust
/* Editar src-tui/src/main.rs */

use rand::seq::SliceRandom; // Añadir a las importaciones

struct AppState {
    cajas: [String; 5],
    frase: String,
    focus_index: usize,
    // NUEVO: Orden aleatorio de navegación (mapa de índices)
    navegacion_map: Vec<usize>,
    // NUEVO: Caracteres del teclado virtual barajados
    teclado_shuffled: Vec<char>,
    cursor_teclado: usize,
}

impl AppState {
    pub fn new() -> Self {
        let mut indices = vec![0, 1, 2, 3, 4, 5];
        indices.shuffle(&mut rand::thread_rng()); // Aleatorizar orden de Tab

        let mut chars: Vec<char> = "0123456789ABCDEFabcdef!@#$%^&*".chars().collect();
        chars.shuffle(&mut rand::thread_rng()); // Barajado inicial del teclado virtual

        Self {
            cajas: Default::default(),
            frase: String::new(),
            focus_index: 0,
            navegacion_map: indices,
            teclado_shuffled: chars,
            cursor_teclado: 0,
        }
    }
}

/* Modificar lógica de Tabulación en run_app */
// ... dentro de match key.code
KeyCode::Tab => {
    state.focus_index = (state.focus_index + 1) % 6;
    // El índice real a editar se obtiene de: state.navegacion_map[state.focus_index]
}
2. Widget de Teclado Virtual (Renderizado TUI)
Implementaremos el dibujo del teclado virtual que cambia en cada sesión para evitar que un atacante deduzca la clave por la posición del cursor en pantalla.

Archivo implicado: src-tui/src/main.rs

Código a añadir:

Rust
/* Añadir función de renderizado en src-tui/src/main.rs */

fn draw_virtual_keyboard(f: &mut Frame, area: ratatui::layout::Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    let rows: Vec<Line> = state.teclado_shuffled
        .chunks(10) // 10 caracteres por fila
        .enumerate()
        .map(|(y, chunk)| {
            let spans: Vec<Span> = chunk.iter().enumerate().map(|(x, &c)| {
                let style = if (y * 10 + x) == state.cursor_teclado {
                    Style::default().fg(Color::Black).bg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                Span::styled(format!(" {} ", c), style)
            }).collect();
            Line::from(spans)
        })
        .collect();

    let keyboard = Paragraph::new(rows)
        .block(Block::default().title(" Teclado Seguro (Shuffled) ").borders(Borders::ALL))
        .alignment(Alignment::Center);
    
    f.render_widget(keyboard, chunks[1]);
}
3. Compilación Estática para Initramfs
Para que Livencrypt funcione en el arranque, antes de que el sistema de archivos principal esté montado, el ejecutable debe ser estático (sin dependencias de librerías .so).

Archivo implicado: src-tui/scripts/initramfs-build.sh (NUEVO)

Código:

Bash
#!/bin/bash
# Rol: Compilación estática y preparación para el arranque seguro (PBA)

set -e

# 1. Instalar el target de compilación estática si no existe
rustup target add x86_64-unknown-linux-musl

# 2. Compilar binario estático
echo "Compilando Livencrypt-Core estático (MUSL)..."
cargo build --release --target x86_64-unknown-linux-musl

# 3. Preparar Hook para el arranque (initramfs-tools)
cat <<EOF > livencrypt_hook
#!/bin/sh
PREREQ=""
prereqs() { echo "\$PREREQ"; }
case \$1 in prereqs) prereqs; exit 0;; esac

. /usr/share/initramfs-tools/hook-functions
copy_exec $(pwd)/target/x86_64-unknown-linux-musl/release/livencrypt-core /bin/livencrypt
EOF

echo "Binario estático generado. Mueva 'livencrypt_hook' a /etc/initramfs-tools/hooks/"
Impacto en la Seguridad
Anti-Keylogging Visual: Al barajar el teclado virtual (teclado_shuffled.shuffle), un atacante que vea tu pantalla no podrá saber qué carácter estás seleccionando basándose en la posición del cursor .

Entropía de Navegación: El navegacion_map hace que el cursor salte de la Caja 3 a la 5 y luego a la 1, por ejemplo. Esto confunde a cualquiera que intente memorizar el patrón rítmico de entrada.

Pre-Boot Authentication (PBA): La compilación estática con musl asegura que Livencrypt pueda ejecutarse en el entorno minimalista del arranque de Linux, bloqueando el acceso al Kernel hasta que se resuelva la barrera matemática.
