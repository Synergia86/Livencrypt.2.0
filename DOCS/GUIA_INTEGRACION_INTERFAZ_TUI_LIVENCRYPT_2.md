# Guia de integracion de interfaz TUI para Livencrypt 2.0

## 1. Objetivo

Este documento define como integrar la interfaz TUI completa de Livencrypt 2.0 sobre el nucleo Rust actual.

La TUI debe reemplazar la antigua interfaz grafica/web y permitir operar Livencrypt desde terminal con menor superficie de ataque:

```text
sin WebView
sin navegador embebido
sin frontend JavaScript
sin localStorage
sin dependencias de escritorio
```

La interfaz debe cubrir:

```text
1. inicio seguro Boot Shield
2. dashboard principal
3. cifrado/descifrado de texto
4. cifrado/descifrado de archivo
5. editor de plantillas
6. configuracion del sistema
7. monitor de hardening
8. auditoria
9. staging/updates firmados
10. recovery Ed25519
11. sandbox de expu
12. perfil de instalacion
```

## 2. Archivos implicados

```text
src-tui/src/main.rs
  interfaz TUI principal
  estado de pantalla
  eventos de teclado
  renderizado Ratatui

src-tui/src/lib.rs
  API publica del nucleo Livencrypt
  cifrado de texto
  cifrado de archivo
  carga de plantillas

src-tui/src/crypto/positional.rs
  algoritmo Livencrypt para texto

src-tui/src/crypto/file_cipher.rs
  cifrado/descifrado de archivos

src-tui/src/templates.rs
  plantillas
  editor
  validacion

src-tui/src/security/vault.rs
  Boot Shield
  vault cifrado
  estado bloqueado/desbloqueado
  settings cifrados

src-tui/src/security/audit.rs
  auditoria encadenada
  eventos HMAC si Boot Shield esta desbloqueado

src-tui/src/security/process_hardening.rs
  CORE DUMPS
  DUMPABLE
  MLOCKALL
  integridad SHA-256 del binario

src-tui/src/security/network_profile.rs
  perfiles de red
  no ejecutar pruebas de red desde la TUI

src-tui/src/security/updates.rs
  staging VFS
  updates firmados

src-tui/src/security/recovery.rs
  recovery Ed25519

src-tui/src/security/sandbox.rs
  resumen de sandbox de expu
```

## 3. Dependencias TUI

El `Cargo.toml` debe incluir:

```toml
ratatui = "0.26"
crossterm = "0.27"
zeroize = "1"
rand = "0.8"
```

La TUI debe ejecutarse con:

```rust
enable_raw_mode()
EnterAlternateScreen
Terminal<CrosstermBackend>
loop de eventos
LeaveAlternateScreen
disable_raw_mode()
```

Regla obligatoria:

```text
al salir de cualquier pantalla que contenga secretos, limpiar campos con zeroize
```

## 4. Estructura de pantallas

El enum `Screen` debe crecer hasta cubrir todas las funciones:

```rust
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
    ConfirmExit,
    ConfirmDestructivePanic,
}
```

Estado minimo:

```rust
struct TuiState {
    screen: Screen,
    previous_screen: Screen,

    status: String,
    should_quit: bool,

    boot_cajas: [String; 5],
    boot_frase: String,

    text_input: String,
    text_output: String,
    text_cajas: [String; 5],
    text_template: String,
    password_length: usize,
    password_direction: String,
    control_symbols: String,

    file_path: String,
    file_output_path: String,
    file_cajas: [String; 5],
    file_template: String,
    close_after_file_operation: bool,

    template_name: String,
    template_grid: Vec<char>,
    template_selected_languages: Vec<String>,
    template_selected_numbers: Vec<String>,

    recovery_path: String,
}
```

Limpieza:

```rust
impl Drop for TuiState {
    fn drop(&mut self) {
        self.boot_frase.zeroize();
        self.text_input.zeroize();
        self.text_output.zeroize();
        self.file_path.zeroize();
        self.file_output_path.zeroize();
        self.recovery_path.zeroize();
        self.status.zeroize();
    }
}
```

## 5. Navegacion principal

El dashboard debe mostrar accesos claros:

```text
t = cifrar texto
f = cifrar archivo
e = editor de plantillas
c = configuracion del sistema
m = monitor de sistema
a = auditoria
u = staging/updates firmados
s = sandbox de expu
r = recovery Ed25519
p = perfil instalado
l = bloquear sesion
q / Esc = cerrar limpiando sesion
```

Render recomendado del dashboard:

```text
LIVENCRYPT 2.0 TUI

Estado:
  Boot Shield: bloqueado/desbloqueado/no configurado
  Plantillas cargadas: N
  Integridad auditoria: valida/truncada/borrada
  Hardening: OK/degradado

Funciones:
  [t] Cifrar texto
  [f] Cifrar archivo
  [e] Editor de plantillas
  [c] Configuracion del sistema
  [m] Monitor
  [a] Auditoria
  [u] Updates
  [s] Sandbox
  [r] Recovery
  [p] Perfil
```

## 6. Pantalla Boot Shield

Contenido:

```text
titulo: LIVENCRYPT BOOT SHIELD
mensaje: Acceso por descifrado: 5 cajas + frase exacta
campos:
  CAJA 1
  CAJA 2
  CAJA 3
  CAJA 4
  CAJA 5
  FRASE
teclado blindado barajado
estado/error
```

Atajos:

```text
Tab        siguiente campo
Shift+Tab  campo anterior
Enter      avanzar/desbloquear
F10        desbloquear
Esc        salir limpiando campos
Flechas    navegar teclado virtual
Espacio    insertar caracter seleccionado
```

Funcion a llamar:

```rust
security::vault::boot_shield_unlock(cajas, frase, None, None)
```

Error unico:

```text
CREDENCIALES INVALIDAS O VAULT MANIPULADO
```

No mostrar:

```text
que caja fallo
si fallo la frase
si fallo la primera o segunda credencial
si el vault fue manipulado
```

## 7. Pantalla Cifrar Texto

Contenido:

```text
panel izquierdo:
  texto de entrada

panel derecho:
  resultado cifrado/descifrado

barra de configuracion:
  plantilla
  caja 1
  caja 2
  caja 3
  caja 4
  caja 5
  limite caracteres contrasena
  posicion contrasena: delante/detras
  simbolos de control activos

botones/atajos:
  c = cifrar
  d = descifrar
  p = configurar contrasena
  x = limpiar entrada/salida
  Esc = dashboard
```

Llamadas al nucleo:

```rust
livencrypt_lib::cipher_text(
    &state.text_input,
    &state.text_template,
    cajas,
    state.password_length,
    &state.password_direction,
    &state.control_symbols,
)
```

```rust
livencrypt_lib::decipher_text(
    &state.text_input,
    &state.text_template,
    cajas,
    state.password_length,
    &state.password_direction,
    &state.control_symbols,
)
```

Reglas:

```text
1. parsear cajas como i64
2. validar plantilla existente
3. no registrar texto claro
4. no registrar frase ni cajas
5. al cambiar de plantilla, recalcular solo si el usuario ejecuta accion
6. limpiar entrada/salida al bloquear sesion
7. si Boot Shield esta activo, guardar configuracion en settings cifrados
```

Registro permitido:

```text
[HH:MM:SS] texto cifrado correctamente
[HH:MM:SS] texto descifrado correctamente
[HH:MM:SS] error generico de operacion
```

Registro prohibido:

```text
texto original
texto cifrado completo
cajas
frase
simbolos usados como secreto
```

## 8. Pantalla Cifrar Archivo

Contenido:

```text
archivo origen
archivo destino
plantilla
cajas 1..5
modo:
  cifrar
  descifrar
opcion:
  cerrar Livencrypt al finalizar operacion
registro de operacion
```

Atajos:

```text
o = seleccionar/escribir ruta origen
s = escribir ruta destino
t = cambiar plantilla
c = cifrar archivo
d = descifrar archivo
a = activar/desactivar cierre automatico al finalizar
x = limpiar rutas
Esc = dashboard
```

Llamadas al nucleo:

```rust
livencrypt_lib::cipher_file(
    input_path,
    output_path,
    &state.file_template,
    cajas,
)
```

```rust
livencrypt_lib::decipher_file(
    input_path,
    output_path,
    &state.file_template,
    cajas,
)
```

Reglas:

```text
1. no cargar archivos completos en la TUI
2. usar rutas y dejar el nucleo gestionar streams/chunks
3. mostrar bytes procesados solo como metadato
4. no mostrar contenido del archivo
5. no ejecutar cierre automatico hasta recibir Ok de la operacion
6. si close_after_file_operation esta activo:
   - limpiar estado
   - boot_shield_hardened_lock()
   - salir de la TUI
```

Registro permitido:

```text
[HH:MM:SS] archivo cargado: /ruta/nombre.ext
[HH:MM:SS] 350196 bytes
[HH:MM:SS] cifrado completado -> /ruta/nombre_cifrado.lvc
[HH:MM:SS] descifrado completado -> /ruta/nombre_descifrado.ext
```

No ejecutar:

```text
ninguna funcion de red
ningun nmcli
ningun ip route
```

## 9. Pantalla Editor de Plantillas

Contenido:

```text
lista de plantillas
nombre plantilla activa
grid de caracteres
idiomas disponibles
numeros/signos disponibles
contador:
  filas
  columnas
  total caracteres
estado:
  exacto
  incompleto
  sobredimensionado
```

Atajos:

```text
n = nueva plantilla
g = guardar plantilla
e = editar nombre
d = eliminar plantilla
i = seleccionar idiomas
u = seleccionar numeros/signos
flechas = mover celda
Enter = editar celda
Backspace = borrar caracter
Esc = dashboard
```

Funciones del nucleo:

```rust
livencrypt_lib::load_templates()
livencrypt_lib::save_template(name, template)
livencrypt_lib::delete_template(name)
livencrypt_lib::resolve_template(name)
```

Reglas:

```text
1. mantener plantilla por defecto Livencrypt
2. permitir eliminar plantillas de usuario
3. no permitir dejar el sistema sin plantilla valida
4. ordenar idiomas alfabeticamente segun idioma activo
5. ordenar numeros/signos alfabeticamente segun idioma activo
6. validar duplicados antes de guardar
7. validar que filas * columnas coincide con caracteres
8. si Boot Shield esta activo, persistir dentro del vault cifrado
```

Estado visual recomendado:

```text
Livencrypt editando 5x23 - 115 chars
Idiomas seleccionados: 3
Numeros/signos seleccionados: 2
Estado: exacto
```

## 10. Pantalla Configuracion del Sistema

Contenido:

```text
Boot Shield:
  activar/desactivar
  plantilla de arranque
  modo credencial:
    simple
    doble

Red:
  perfil de control:
    mock
    drop-default-route
    nmcli-off
    isolated

Panico:
  cierre rapido
  panico destructivo activar/desactivar

Inactividad:
  activar/desactivar autocierre
  segundos de inactividad

Hardening:
  core dumps
  dumpable
  mlockall
  integridad binario

Idioma:
  idioma activo
  numerales localizados
  simbolos de control
```

Reglas de red:

```text
1. desde la TUI no ejecutar pruebas automaticas de red
2. mostrar estado del perfil
3. exigir confirmacion fuerte para perfiles destructivos
4. mantener mock por defecto si no hay configuracion de expu
```

Funciones:

```rust
security::vault::boot_shield_enable(...)
security::vault::boot_shield_disable(...)
security::vault::boot_shield_hardened_lock()
security::network_profile::read_network_profile()
security::network_profile::write_network_profile(...)
security::process_hardening::process_hardening_status()
```

## 11. Pantalla Monitor de Sistema

Contenido actual recomendado:

```text
integridad auditoria:
  valida
  truncada
  log borrado

tombstones pendientes
avisos hardening
eventos recientes
```

Atajos:

```text
r = refrescar
Esc/q = dashboard
```

Funciones:

```rust
security::vault::current_integrity_status()
security::audit::tombstone_count()
security::audit::read_recent_entries(limit)
security::process_hardening::process_hardening_status()
```

## 12. Pantalla Auditoria

Contenido:

```text
eventos recientes
indice
timestamp
tipo evento
anchor/hash corto
esquema firma:
  local-sha256-v1
  hmac-sha256-v1
```

Funciones:

```rust
security::audit::read_recent_entries(20)
entry.calculate_hash()
```

Eventos esperados:

```text
BOOT_SHIELD_ENABLE
VAULT_OPEN
TOMBSTONE
RECOVERY_APPLIED
UPDATE_HANDOVER
LOADER_MEMFD_EXEC
SANDBOX_TERMINATED
MIRAGE_WRITE_DISCARDED
MIRAGE_DELETE_DISCARDED
```

## 13. Pantalla Staging / Updates Firmados

Contenido:

```text
version
fecha creacion
sha256 payload
changelog
estado firma/hash
```

Atajos:

```text
v = verificar firma/hash
h = handover al vault
c = limpiar staging con borrado seguro
Esc/q = dashboard
```

Funciones:

```rust
security::updates::inspect_pending_update()
security::updates::verify_pending_update()
security::vault::finalize_update_handover()
security::updates::clear_staging()
```

Ruta staging:

```text
~/.local/share/livencrypt/.livencrypt/staging/update.manifest
~/.local/share/livencrypt/.livencrypt/staging/shadow_payload.bin
```

Claves publicas:

```text
/etc/livencrypt/update_public.key
```

## 14. Pantalla Recovery Ed25519

Contenido:

```text
ruta del archivo .lvc_recovery
estado de verificacion
resultado de aplicacion
```

Atajos:

```text
escribir ruta
Backspace = corregir
Enter = aplicar recovery
Esc = dashboard
```

Funcion:

```rust
security::recovery::apply_recovery_file(Path::new(&state.recovery_path))
```

Clave publica:

```text
/etc/livencrypt/recovery_public.key
```

Regla:

```text
Recovery solo actualiza el anclaje de auditoria si la firma Ed25519 es valida.
```

## 15. Pantalla Sandbox de Expu

Contenido:

```text
SO Linux: true/false
NO_NEW_PRIVS
namespaces
RLIMIT_AS
RLIMIT_CPU
RLIMIT_FSIZE
riesgo heuristico local
```

Funcion:

```rust
security::sandbox::sandbox_capability_summary()
security::ai_monitor::expu_baseline_risk()
```

Regla:

```text
esta pantalla no debe ejecutar binarios ni activar red
solo muestra capacidades disponibles
```

## 16. Pantalla Perfil de Instalacion

Contenido:

```text
perfil instalado:
  standard
  isolated
  expu
  pba

descripcion de cada perfil
```

Funcion:

```rust
security::install_profile::read_install_profile()
```

Origen:

```text
/etc/livencrypt/install_profile.conf
```

Fallback:

```text
~/.local/share/livencrypt/.livencrypt/secure/install_profile.msgpack
```

## 17. Confirmaciones

### 17.1. Cierre normal

Pantalla opcional:

```text
Cerrar Livencrypt

Se bloqueara Boot Shield, se limpiaran campos sensibles y se cerrara la TUI.

Enter = cerrar
Esc = cancelar
```

Accion:

```rust
security::vault::boot_shield_hardened_lock();
state.clear_secret_fields();
state.should_quit = true;
```

### 17.2. Panico destructivo

Pantalla obligatoria antes de destruir:

```text
PANICO DESTRUCTIVO

Esta accion puede hacer irrecuperables vault, plantillas, backups y datos locales Livencrypt.

Escriba: DESTRUIR LIVENCRYPT
```

Accion:

```rust
security::vault::boot_shield_destructive_panic("DESTRUIR LIVENCRYPT".to_string())
```

Reglas:

```text
1. no ejecutar desde atajo accidental
2. no mostrar si no esta habilitado por configuracion
3. limpiar pantalla y cerrar proceso tras ejecucion
```

## 18. Integracion de idioma en TUI

La TUI debe usar un modulo `i18n` Rust, no textos dispersos.

Estructura recomendada:

```text
src-tui/src/i18n/mod.rs
src-tui/src/i18n/catalog.rs
src-tui/src/i18n/numerals.rs
src-tui/src/i18n/languages.rs
```

Funciones:

```rust
fn tr(key: &str, lang: Language) -> &'static str
fn format_number(value: i64, lang: Language) -> String
fn parse_localized_number(value: &str, lang: Language) -> Result<i64, String>
fn language_name(language: Language, active: Language) -> &'static str
```

Regla para Boot Shield:

```text
los valores visuales pueden mostrarse con numerales localizados,
pero antes de derivar la clave deben canonicalizarse a i64 estable.
```

Esto permite:

```text
chino: 一 二 三
arabe: ١ ٢ ٣
hindi: १ २ ३
japones/coreano: caracteres propios o numeracion configurada
```

## 19. Bucle de eventos recomendado

```rust
fn run_app<B: Backend>(terminal: &mut Terminal<B>) -> io::Result<()> {
    let mut state = TuiState::new();

    loop {
        terminal.draw(|frame| draw_ui(frame, &state))?;

        if event::poll(Duration::from_millis(200))? {
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind == KeyEventKind::Release {
                continue;
            }
            handle_key(&mut state, key);
        }

        if state.should_quit {
            break;
        }
    }

    Ok(())
}
```

## 20. Render general recomendado

```rust
fn draw_ui(frame: &mut Frame<'_>, state: &TuiState) {
    let area = frame.size();
    let block = Block::default()
        .title(" Livencrypt 2.0 TUI ")
        .borders(Borders::ALL);
    frame.render_widget(block, area);

    let inner = centered_area(area, 92, 86);
    frame.render_widget(Clear, inner);

    match state.screen {
        Screen::Unlock => draw_unlock(frame, inner, state),
        Screen::Dashboard => draw_dashboard(frame, inner, state),
        Screen::TextCipher => draw_text_cipher(frame, inner, state),
        Screen::FileCipher => draw_file_cipher(frame, inner, state),
        Screen::TemplateEditor => draw_template_editor(frame, inner, state),
        Screen::Settings => draw_settings(frame, inner, state),
        Screen::SystemMonitor => draw_system_monitor(frame, inner, state),
        Screen::AuditMonitor => draw_audit_monitor(frame, inner, state),
        Screen::FirmwareStaging => draw_firmware_staging(frame, inner, state),
        Screen::SandboxManager => draw_sandbox_manager(frame, inner, state),
        Screen::RecoveryMode => draw_recovery_mode(frame, inner, state),
        Screen::InstallProfile => draw_install_profile(frame, inner, state),
        Screen::ConfirmExit => draw_confirm_exit(frame, inner, state),
        Screen::ConfirmDestructivePanic => draw_confirm_destructive_panic(frame, inner, state),
    }
}
```

## 21. Orden de integracion recomendado

### Pasada 1: navegacion

```text
1. ampliar enum Screen
2. ampliar TuiState
3. ampliar dashboard con accesos t/f/e/c
4. crear draw_* vacios para nuevas pantallas
5. crear handle_* de cada pantalla
```

### Pasada 2: Cifrar Texto

```text
1. panel entrada/salida
2. cajas
3. plantilla
4. configuracion de contrasena
5. llamada cipher_text/decipher_text
6. limpieza zeroize
```

### Pasada 3: Cifrar Archivo

```text
1. rutas
2. modo cifrar/descifrar
3. plantilla
4. cierre automatico al finalizar
5. llamada cipher_file/decipher_file
6. registro sin contenido sensible
```

### Pasada 4: Editor de Plantillas

```text
1. lista plantillas
2. grid caracteres
3. selector idiomas
4. selector numeros/signos
5. guardar/eliminar
6. persistencia vault si Boot Shield activo
```

### Pasada 5: Configuracion

```text
1. Boot Shield
2. red solo configuracion, no pruebas
3. panico destructivo
4. inactividad
5. idioma
6. settings cifrados
```

### Pasada 6: i18n

```text
1. catalogo de textos
2. numerales localizados
3. nombres de idiomas traducidos
4. parseo Boot Shield localizado
5. traduccion de logs visibles
```

## 22. Criterios de aceptacion

La interfaz TUI se considera integrada cuando:

```text
1. Boot Shield desbloquea y carga dashboard
2. Dashboard permite acceder a todas las funciones
3. Cifrar Texto cifra y descifra desde TUI
4. Cifrar Archivo cifra y descifra desde TUI
5. Editor de Plantillas crea, edita, guarda y elimina plantillas
6. Configuracion permite cambiar opciones sin WebView
7. Auditoria muestra eventos recientes
8. Monitor muestra hardening e integridad
9. Staging verifica firma/hash sin ejecutar contenido
10. Recovery aplica archivo firmado
11. Sandbox solo muestra capacidades salvo accion explicita futura
12. Salida limpia campos y bloquea runtime
13. No existe dependencia de localStorage
14. No se ejecutan pruebas de red automaticamente
```

## 23. Reglas de seguridad

```text
1. Ningun secreto debe escribirse en logs.
2. Ningun secreto debe permanecer en estado tras bloqueo o cierre.
3. La TUI no debe ejecutar red automaticamente.
4. La TUI no debe ejecutar PBA/initramfs.
5. Las operaciones destructivas requieren confirmacion fuerte.
6. Las operaciones de staging requieren firma/hash validos.
7. Las plantillas deben persistirse cifradas si Boot Shield esta activo.
8. La auditoria debe registrar eventos, no contenido sensible.
9. Cualquier error de Boot Shield debe ser generico.
10. El modo espejismo no debe revelarse al atacante.
```

## 24. Resultado esperado

La TUI final debe permitir usar Livencrypt 2.0 de forma completa desde terminal:

```text
livencrypt-core
  -> Boot Shield si existe vault
  -> dashboard
  -> cifrar texto
  -> cifrar archivo
  -> editar plantillas
  -> configurar sistema
  -> monitorizar seguridad
  -> cerrar limpiando sesion
```

El modo diagnostico debe mantenerse separado:

```bash
livencrypt-core --hardening-check
```

Este modo no abre la TUI y solo informa:

```text
CORE DUMPS
DUMPABLE
MLOCKALL
INTEGRIDAD
SHA-256 binario
avisos de hardening
```
