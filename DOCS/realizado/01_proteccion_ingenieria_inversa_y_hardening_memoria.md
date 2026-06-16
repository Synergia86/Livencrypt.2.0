# Protección contra Ingeniería Inversa y Hardening de Memoria

Este módulo detalla las contramedidas lógicas y físicas de Livencrypt 2.0 destinadas a dificultar la ingeniería inversa en desensambladores/decompiladores (como Ghidra) y bloquear ataques físicos o lógicos de volcado de memoria.

---

## 1. Diseño y Principios Técnicos

### A. Resistencia a Ingeniería Inversa Lógica
Aunque un analista decompile el binario de Livencrypt 2.0 (por ejemplo, usando Ghidra MCP Server), no podrá obtener los datos protegidos debido a:
* **Principio de Conocimiento Cero (Zero Knowledge)**: Las credenciales de acceso (la combinación de las 5 cajas de la cuadrícula y la frase de paso) nunca se almacenan en el binario, ni en archivos de configuración planos, ni en el código fuente.
* **Indivisibilidad Criptográfica**: Livencrypt utiliza la función de derivación de claves **Argon2id** (para resistir ataques ASIC/GPU en hardware) y el cifrado de datos **XChaCha20-Poly1305**. Sin las credenciales exactas proporcionadas por el usuario, el contenido del vault es indistinguible del ruido aleatorio.

### B. Endurecimiento de Memoria (RAM Hardening)
Evita que las claves criptográficas o fragmentos de datos sensibles terminen en el almacenamiento persistente (disco duro/swap) mediante:
* **Anclaje de Páginas de Memoria (`mlockall`)**: Llama a `libc::mlockall` con las banderas `MCL_CURRENT` y `MCL_FUTURE` para indicarle al kernel que no envíe ninguna página del proceso al Swap (espacio de intercambio), mitigando análisis forenses posteriores al apagado.
* **Deshabilitación de Core Dumps**: Deshabilita los volcados de memoria automáticos si el proceso sufre un pánico, estableciendo el límite `RLIMIT_CORE` a 0.
* **Control de Dumpability (`PR_SET_DUMPABLE = 0`)**: Impide que otros procesos sin privilegios depuren (mediante `ptrace`) u obtengan volcados de memoria en caliente del proceso de Livencrypt.

### C. Zeroize de Secretos
* **Limpieza Inmediata de RAM**: Todos los secretos del usuario (la frase y los índices de las cajas) y los materiales de clave derivada (`AccessSecret`, `BootMaterial`) implementan el trait `Drop` de Rust para sobrescribir su espacio de memoria con ceros criptográficos en el milisegundo exacto en que dejan de ser necesarios.

### D. Eliminación del Puente IPC (Pureza TUI)
* **La Gran Amputación**: El paso de Tauri (HTML/JS/WebView) a una interfaz de terminal pura basada en Rust (**Ratatui**) elimina el motor V8 y el recolector de basura, donde las copias de los secretos podían quedar "flotando" en la memoria de manera incontrolable. También se elimina el puente de comunicación IPC (Inter-Process Communication) entre el frontend y el backend, cerrando un vector de intercepción crucial.

### E. Defensas Activas
* **Clave de Coacción (Duress Key)**: Si se introduce una clave especial preconfigurada para coacción, el sistema simula un fallo físico catastrófico de lectura (Mimetismo Técnico) mientras inicia una destrucción silenciosa del vault y las plantillas.
* **Auto-Wipe**: Tras alcanzar un límite máximo de intentos de acceso fallidos, el vault se autodestruye físicamente mediante sobrescritura con ruido aleatorio y sync de bajo nivel (`sync_all`).

---

## 2. Archivos Implicados en el Proyecto

* **[process_hardening.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/process_hardening.rs)**: Contiene la lógica para invocar `mlockall`, configurar `RLIMIT_CORE`, deshabilitar `PR_SET_DUMPABLE`, y comprobar la integridad SHA-256 del binario.
* **[vault.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs)**: Gestiona la derivación de claves (`derive_key`), el ciclo de vida de los secretos en memoria mediante el uso de `zeroize`, la lógica de autodestrucción y detección de la clave de coacción.
* **[main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs)**: Punto de entrada de la TUI Ratatui que llama a la inicialización del hardening en el arranque.

---

## 3. Estado de la Integración

### ¿Qué está YA integrado?
* [x] **Migración Rust-TUI**: La interfaz Ratatui está completamente operativa en `main.rs`, eliminando Tauri/JS.
* [x] **Hardening Unix**: `mlockall` (con elevación del límite blando de `RLIMIT_MEMLOCK`), `PR_SET_DUMPABLE=0` y la desactivación de core dumps (`RLIMIT_CORE=0`) están implementados en `process_hardening.rs`.
* [x] **Detección de LD_PRELOAD e Integridad**: Se detecta si hay librerías inyectadas mediante `LD_PRELOAD` y se valida el hash SHA-256 del binario ejecutable contra `/etc/livencrypt/expected.sha256`.
* [x] **Zeroize en Estructuras**: Las estructuras `AccessSecret`, `BootMaterial` y `BootShieldRuntime` implementan de forma explícita `Drop` llamando a `zeroize()` para limpiar claves y secuencias en RAM.
* [x] **Clave de Coacción (Duress Key)**: `vault.rs` incluye `is_duress_key` para verificar la clave de coacción mediante un hash `duress_check` en el estado de defensa y activar `boot_shield_destructive_panic`.
* [x] **Límite de Intentos y Auto-Wipe**: Se incrementan los intentos fallidos en `VaultDefenseState` y se llama a `boot_shield_destructive_panic` al llegar a 5 intentos fallidos (`MAX_FAILED_ATTEMPTS`).

### ¿Qué falta por integrar?
* [ ] **Alertas Visuales en TUI**: El estado de degradación del hardening (ej. si falla `mlockall` porque no se tiene la capacidad `CAP_IPC_LOCK`) devuelve advertencias detalladas en Rust, pero no se muestran de forma destacada o configurable en la interfaz de usuario de Ratatui.
* [ ] **Control de Swap Avanzado en Instalación**: Asegurar que la distribución del paquete asigne la capacidad necesaria al binario para que no requiera root para ejecutar `mlockall` (mediante scripts como `postinstall.sh` ejecutando `setcap cap_ipc_lock=+ep`).
* [ ] **Limpieza de RAM de buffers de lectura/escritura**: Asegurar que en todas las operaciones de cifrado de archivos, los búferes internos intermedios también sean sobrescritos de forma proactiva con `zeroize()`.

---

## Enlaces Relacionados
* Volver al [[00_indice|Índice General]].
* Ver la hoja de ruta para el arranque seguro: [[08_pre_boot_authentication_y_teclado_aleatorio|Pre-Boot Authentication (PBA) y Teclado Aleatorio]].

## Código a integrar
1. Alertas Visuales en TUI (Hardening Degradado)Actualmente, el sistema detecta fallos en mlockall o integridad, pero solo los imprime en la consola al inicio o los muestra de forma pasiva en el Dashboard . Vamos a modificar la interfaz de desbloqueo para que muestre un aviso crítico si el Hardening no es óptimo.  Archivo implicado: src-tui/src/main.rsCódigo a editar: Modificar la función draw_unlock para incluir un banner de advertencia.Rust/* Editar función draw_unlock en src-tui/src/main.rs */

fn draw_unlock(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &TuiState) {
    let hardening = security::process_hardening::process_hardening_status(); // [cite: 773]
    let has_warnings = !hardening.warnings.is_empty(); // [cite: 764]

    let constraints = if has_warnings {
        vec![Constraint::Length(4), Constraint::Length(3), Constraint::Length(10), Constraint::Min(4)]
    } else {
        vec![Constraint::Length(4), Constraint::Length(10), Constraint::Min(4)]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    // Header existente... [cite: 61]
    
    let mut next_chunk_idx = 1;

    // NUEVO: Banner de advertencia de Hardening
    if has_warnings {
        let warn_text = format!("⚠ ADVERTENCIA: SEGURIDAD DEGRADADA ({})", hardening.warnings.len());
        let warning = Paragraph::new(warn_text)
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Black).bg(Color::Red).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(warning, chunks[next_chunk_idx]);
        next_chunk_idx += 1;
    }

    // Renderizar campos de Credenciales en el chunk correspondiente
    let mut fields = Vec::new();
    // ... (resto del bucle de campos de cajas y frase igual) [cite: 64-67]
    
    let form = Paragraph::new(fields)
        .block(Block::default().title(" Credenciales ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(form, chunks[next_chunk_idx]);
    
    // El resto de la función usa chunks[next_chunk_idx + 1] para el estado [cite: 69]
}
2. Control de Swap Avanzado en InstalaciónPara que mlockall funcione sin privilegios de root, el binario debe poseer la capacidad CAP_IPC_LOCK. El script actual ya intenta aplicarlo, pero vamos a asegurar que la verificación sea implacable y que informe al usuario si el sistema de archivos (como particiones montadas con nosuid) bloquea esta capacidad.  Archivo implicado: src-tui/scripts/postinstall.shCódigo a editar: Reforzar la lógica de aplicación de capacidades.Bash#!/bin/sh
# Editar lógica en src-tui/scripts/postinstall.sh [cite: 1174]

setcap cap_ipc_lock=ep "$binary_path" || {
    echo "ERROR: No se pudieron asignar capacidades al binario." >&2
    echo "Verifique que el sistema de archivos permita 'setcap' (no montado con nosuid)." >&2
    exit 1
}

# Verificación proactiva [cite: 1178]
if ! getcap "$binary_path" | grep -q "cap_ipc_lock"; then
    echo "CRÍTICO: CAP_IPC_LOCK no detectado. El blindaje de memoria (mlockall) fallará." >&2
    exit 1
fi

# NUEVO: Comprobar límites de usuario (memlock)
echo "Verificando límites de memoria bloqueada (memlock)..."
if ! [ "$(ulimit -l)" = "unlimited" ] && [ "$(ulimit -l)" -lt 65536 ]; then
    echo "AVISO: El límite de 'memlock' es bajo ($(ulimit -l) KB). Considere aumentarlo en /etc/security/limits.conf" >&2
fi
3. Limpieza de RAM de buffers de lectura/escrituraDebemos garantizar que cualquier fragmento de datos que pase por la RAM sea sobrescrito. Aunque ya existe Zeroize en el búfer principal de streaming, debemos extenderlo a los procesos de descompresión y manipulación de fragmentos (nibbles).  Archivo implicado: src-tui/src/crypto/file_cipher.rsCódigo a editar: Asegurar limpieza en decrypt_file_streaming.Rust/* Editar lógica en src-tui/src/crypto/file_cipher.rs */

fn decrypt_file_streaming(...) -> Result<(), String> {
    // ... inicialización de rutas y buffers [cite: 485]

    let write_result = (|| -> Result<(), String> {
        // ... configuración de escritores y nibbles [cite: 486]

        process_clean_encrypted_chars(input_path, referencia, |encrypted| {
            let mut hex_char = transform_file_char(...)?; // [cite: 486]
            
            let nibble = hex_char
                .to_digit(16)
                .ok_or_else(|| format!("Hex invalido: {}", hex_char))? as u8;
            
            // LIMPIEZA: El carácter hex transformado ya no se necesita
            hex_char.zeroize(); 

            if let Some(high) = high_nibble.take() {
                let mut byte = (high << 4) | nibble;
                if use_seed {
                    byte ^= seed[byte_index % 32]; // [cite: 491]
                }
                decoded_writer.write_all(&[byte]).map_err(|e| e.to_string())?;
                
                // NUEVO: Limpieza explícita del byte procesado
                byte.zeroize();
                byte_index += 1;
            } else {
                high_nibble = Some(nibble);
            }
            Ok(())
        })?;

        // ... lógica de fin de archivo [cite: 497]
    })();
    
    // ... limpieza de archivos temporales [cite: 504-506]
}

Impacto en la SeguridadVisibilidad: El usuario no puede ignorar un fallo de Hardening; el banner rojo en la pantalla de desbloqueo actúa como un "semáforo forense".Soberanía de Permisos: Al usar setcap correctamente, el programa mantiene su blindaje sin comprometer la seguridad general del sistema al no requerir ejecución como root.  Remanencia Cero: La limpieza de hex_char y byte individuales en el bucle de descifrado cierra la ventana de exposición a ataques de búsqueda de patrones en la RAM.
