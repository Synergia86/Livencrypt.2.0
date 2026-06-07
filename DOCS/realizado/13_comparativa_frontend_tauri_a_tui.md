# Comparativa de Frontend: Migración de Tauri (React/TS) a TUI (Rust/Ratatui)

Este documento detalla la comparativa técnica y forense del paso de la interfaz gráfica híbrida basada en **Tauri (React/TypeScript)** de la versión anterior a la interfaz de terminal interactiva pura **TUI (Rust/Ratatui/Crossterm)** de la versión actual.

---

## 1. Resumen de la Transición de Arquitectura

El objetivo fundamental de la migración de la interfaz gráfica a TUI fue alcanzar la **Soberanía Criptográfica y de Memoria**. 

| Métrica / Dimensión | Versión Anterior (Tauri) | Versión Actual (TUI) |
| --- | --- | --- |
| **Tecnologías de Frontend** | HTML5, CSS3 (Tailwind), React, TypeScript | Rust, Ratatui, Crossterm |
| **Entorno de Ejecución** | WebView del Sistema (webkit2gtk/Chromium) + Motor V8 | Consola / Terminal nativa (directo sobre TTY) |
| **Seguridad de Memoria** | Coexistencia con GC (Garbage Collector) y Heap compartido | Control determinista de Heap/Stack con `Zeroize` |
| **Comunicación de Datos** | Puente IPC serializado JSON (Tauri `invoke`) | Llamadas de función directas en el mismo hilo de ejecución |
| **Selección de Archivos** | Diálogo nativo del S.O. (paquete `@tauri-apps/plugin-dialog`) | Explorador de archivos nativo integrado en terminal (`FileBrowser`) |
| **Ingeniería Inversa** | Código JS extraíble del empaquetado web | Binario único compilado nativo y stripping |

---

## 2. Análisis del Frontend en la Versión Anterior (Tauri/React)

El frontend de la versión anterior estaba ubicado en la raíz del proyecto antiguo, bajo la carpeta `src/`.

### A. Estructura de Componentes y Páginas
* **[main.tsx](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/DOCS/pendiente/LIVENCRYPT%202.0/src/main.tsx)**: Archivo principal y punto de arranque del Dashboard. Contiene:
  * El enrutador basado en hashes (`useHashRoute`).
  * El selector visual de idiomas (`LanguageFlagSelector`) que muestra banderas Unicode (ej: 🇪🇸, 🇬🇧, 🇨🇳) y gestiona traducciones.
  * El cargador de estados del proceso de desbloqueo (`LockScreen`) y del centro de aplicaciones (`Launcher`).
* **[FileCipherWindow.tsx](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/DOCS/pendiente/LIVENCRYPT%202.0/src/pages/FileCipherWindow.tsx)**: Ventana de cifrado de archivos. Características:
  * Selección de archivos mediante el selector nativo de Tauri (`openFileDialog`).
  * Visualización rápida del tamaño en bytes localizado y velocidad en milisegundos.
  * Selector de plantillas con indicación visual de cobertura hexadecimal (ej: `Livencrypt (5×23) ✓` o `⚠12/16`).
  * Consola de salida de texto con enlaces interactivos a carpetas del sistema.
* **[TextCipherWindow.tsx](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/DOCS/pendiente/LIVENCRYPT%202.0/src/pages/TextCipherWindow.tsx)**: Ventana para procesar texto plano. Características:
  * Cajas de texto de entrada y salida redimensionables en CSS.
  * Integración con `PasswordSetupDialog` y `PasswordDialog` (cierre de cifrado de matriz F2).
  * Control del sentido del vector de cifrado de contraseña mediante un botón conmutador (`←` / `→`).
* **[TemplateEditorWindow.tsx](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/DOCS/pendiente/LIVENCRYPT%202.0/src/pages/TemplateEditorWindow.tsx)**: Editor de matrices de caracteres para la generación de plantillas de cifrado posicional de idiomas y alfabetos extendidos.
* **[i18n](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/DOCS/pendiente/LIVENCRYPT%202.0/src/i18n)**: Soporte de traducción dinámico para múltiples idiomas (`es.json`, `en.json`, `zh.json`) y localización matemática de números en el script [numerals.ts](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/DOCS/pendiente/LIVENCRYPT%202.0/src/i18n/numerals.ts).

### B. Puente de Comunicación (IPC API)
El frontend web interactuaba con el núcleo criptográfico en Rust a través del intermediario [invoke.ts](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/DOCS/pendiente/LIVENCRYPT%202.0/src/invoke.ts) que llamaba a las siguientes funciones del backend:
* `boot_shield_status`, `boot_shield_unlock`, `boot_shield_lock`, `boot_shield_enable`, `boot_shield_disable`, `boot_shield_factory_reset`.
* `cipher_text`, `decipher_text`, `cipher_file`, `decipher_file`, `load_file_info`.
* `get_text_password_settings`, `save_text_password_settings`.
* `load_templates`, `save_template`, `delete_template`.
* `panic_wipe_and_exit`.

---

## 3. Análisis del Frontend en la Versión Actual (Rust-TUI)

La versión TUI ha unificado el frontend y el backend en un único binario escrito en Rust localizado en [src-tui](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui). El frontend gráfico ha sido reemplazado por la lógica de dibujo directa en consola mediante la biblioteca **Ratatui**.

### A. Estructura de Control de Pantallas
Toda la interfaz y el enrutador se controlan en el bucle principal de [main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs) a través de la enumeración `Screen`:

```rust
enum Screen {
    Unlock,              // Pantalla de acceso de Boot Shield
    Dashboard,           // Centro principal de aplicaciones y VFS
    TextCipher,          // Cifrado y descifrado de texto en TUI
    FileCipher,          // Cifrado y descifrado de archivos
    TemplateEditor,      // Editor de matrices de caracteres
    Settings,            // Opciones de configuración y red
    SystemMonitor,       // Diagnósticos generales
    AuditMonitor,        // NUEVO: Verificación de logs encadenados SHA-256
    FirmwareStaging,     // NUEVO: Manifiesto de Updates y Handover
    SandboxManager,      // NUEVO: Lanzamiento fileless en RAM con telemetría eBPF/IA
    RecoveryMode,        // NUEVO: Carga de .lvc_recovery y verificación Ed25519
    InstallProfile,      // Instalación de perfiles de endurecimiento
}
```

### B. Mapeo de Funciones y Pantallas de la Interfaz

#### 1. Pantalla de Desbloqueo (`Screen::Unlock`)
* **React**: Formulario HTML clásico con 5 inputs para cajas, un input de contraseña y botones para restablecer. Los datos introducidos dependían de eventos reactivos `onChange` expuestos en el DOM.
* **TUI**: Renderiza 5 bloques individuales (`Paragraph` con bordes redondeados) enfocables con la tecla `Tab` o clic de ratón. Incorpora el **Teclado Seguro** de posiciones dinámicas aleatorias (`draw_secure_keyboard` en `10_teclado.md`) para evitar captura física de pulsaciones.

#### 2. Dashboard General (`Screen::Dashboard`)
* **React**: Un lanzador de aplicaciones tradicional con tarjetas (*Cards*) CSS que abren ventanas independientes del WebView.
* **TUI**: Renderiza una interfaz de paneles distribuidos en columnas utilizando `Layout` de Ratatui. En la zona de plantillas, si el sistema pierde la integridad, el dashboard cambia de forma invisible para listar contenedores señuelo en lugar de los reales (Honeypot de *Modo Espejismo*).

#### 3. Cifrador de Texto (`Screen::TextCipher`)
* **React**: Contaba con selectores visuales complejos y textareas HTML. Guardaba la configuración de bloqueo F2 en almacenamiento local del navegador (`localStorage`).
* **TUI**: Utiliza `TuiState` en Rust. Captura texto en un búfer que implementa `Zeroize`. La contraseña de matriz F2 se visualiza de forma dinámica en la parte inferior y permite configurar longitud, dirección y caracteres de control mediante menús interactivos de consola.

#### 4. Cifrador de Archivos (`Screen::FileCipher`)
* **React**: Invocaba el selector de archivos nativo de Tauri. Si fallaba, recurría a un elemento `<input type="file">` HTML.
* **TUI**: Implementa un componente de explorador de archivos nativo dentro de la consola (`FileBrowser` en `main.rs`), permitiendo navegar recursivamente por el disco del host, filtrar por extensiones permitidas (`txt`, `lvc`, `msgpack`, etc.) y seleccionar archivos de entrada/salida directamente sin dependencias externas.

#### 5. Editor de Plantillas (`Screen::TemplateEditor`)
* **React**: Una tabla HTML editable celda a celda donde el usuario tecleaba las matrices de caracteres.
* **TUI**: Renderiza una cuadrícula de caracteres en consola usando filas de texto estructurado. Se navega con el teclado o ratón y permite configurar idiomas predefinidos y conjuntos de signos especiales.

---

## 4. Comparativa de Implementación de Componentes de UI

| Componente de UI | Anterior (React/Tauri) | Actual (Rust/Ratatui) |
| --- | --- | --- |
| **Consola de Logs** | Array de strings renderizado en un `div` con scroll automático CSS. | Lista de `Line` y `Span` con marcas de tiempo en un panel `Paragraph` con scroll dinámico de Crossterm. |
| **Explorador de Archivos** | Diálogo nativo lanzado por plugin de Tauri. | Widget interno de Rust `FileBrowser` que lee directorios del sistema de archivos con `fs::read_dir`. |
| **Entrada de Texto** | Elementos `<input>` y `<textarea>` reactivos de React. | Búferes `String` capturados mediante intercepción de eventos `KeyCode::Char` de Crossterm. |
| **Firma/Verificación de Integridad** | Indicador de texto plano sobre estado de la firma. | Glifo de estado esteganográfico en el header (`.` para integridad válida, `·` para alteración/Modo Espejismo). |

---

## 5. Valoración Forense de la Migración

La migración del frontend ha cerrado vectores de ataque clave desde el punto de vista pericial:
1. **Remanencia en RAM**: React y JavaScript clonan constantemente cadenas de texto en memoria (Heap del motor V8). Al destruirse un componente en React, las cadenas con contraseñas o datos cifrados persistían en el Heap hasta que el recolector de basura las limpiaba de forma no controlada. La versión actual en TUI garantiza la destrucción inmediata de buffers usando `Zeroize` en el momento en que se cierra la sesión o cambia de pantalla.
2. **Intercepción de Mensajes IPC**: En Tauri, la comunicación del frontend al backend viaja a través de llamadas de sistema serializadas en JSON. Un malware en el host podría interceptar los sockets de comunicación locales para capturar los secretos de Livencrypt en tránsito. Al integrar el frontend directamente en el proceso binario de Rust-TUI, no existe canal IPC que pueda ser monitorizado.
3. **Dependencia de Entorno Gráfico**: Al ser una TUI pura, Livencrypt puede ejecutarse en consolas TTY virtuales (ej: `Ctrl+Alt+F3`), servidores SSH aislados, o en las primeras fases del arranque del kernel (Initramfs), proporcionando autenticación e inmutabilidad antes de que se inicie el entorno gráfico del sistema.

---

## 6. Interacciones y Funcionalidades Pendientes en la Versión TUI

Para que la versión TUI esté completamente madura y alcance una paridad de características real con el frontend anterior en React/Tauri, se requiere implementar las siguientes interacciones y funcionalidades en la interfaz de consola:

### A. Diálogos Interactivos de Contraseña F2 (Matrix Lock)
* **El Faltante**: El frontend anterior integraba dos ventanas emergentes críticas: `PasswordSetupDialog` (para configurar dinámicamente la longitud de contraseña de 2 a 25, la dirección antes/después y los símbolos de control) y `PasswordDialog` (HUD visual que solicitaba la contraseña mediante un teclado en pantalla durante el descifrado si se detectaba una clave cifrada).
* **Solución Necesaria**: En la TUI, aunque se soportan las variables en el estado (`text_password_length`, etc.), no existe un modal emergente interactivo que le pida al usuario teclear la contraseña en la matriz al descifrar o que dibuje la configuración gráfica del F2 Lock.

### B. Integración con el Portapapeles del Sistema (OS Clipboard)
* **El Faltante**: En React, copiar el texto cifrado resultante era instantáneo gracias al botón "Copiar" apoyado en la API del portapapeles del navegador. En la versión TUI actual no hay enlace con el portapapeles del sistema operativo. El usuario debe recurrir a las funciones de copia nativas de su emulador de terminal (las cuales a veces están bloqueadas por el hardening de la terminal).
* **Solución Necesaria**: Integrar una dependencia en `Cargo.toml` como `arboard` (o llamadas CLI seguras a utilidades como `xclip`/`xsel` en Linux) para permitir copiar resultados y pegar textos de entrada de manera fluida y segura directamente con atajos del teclado en la TUI.

### C. Localización de la Interfaz TUI (Soporte i18n)
* **El Faltante**: El frontend en React tenía una capa robusta de traducción dinámica (`i18n`) para 11 idiomas con selectores visuales de banderas y numerals localizados. En el TUI actual, todos los textos, títulos, advertencias y mensajes de error están codificados de forma rígida (*hardcoded*) en español.
* **Solución Necesaria**: Crear un sistema de traducción para el terminal mediante archivos YAML/JSON o diccionarios estáticos mapeados en Rust para reintroducir el cambio de idioma de la interfaz del usuario en la pantalla de ajustes (`Screen::Settings`).

### D. Soporte para Scroll con la Rueda del Ratón
* **El Faltante**: El motor de eventos de la TUI en `main.rs` captura clicks izquierdos para interactuar con botones y el movimiento del cursor, pero ignora por completo los eventos de rueda del ratón (`MouseEventKind::ScrollUp` y `MouseEventKind::ScrollDown`). Esto hace que navegar por el explorador de archivos, la consola de logs o tablas largas de plantillas solo sea posible con el teclado.
* **Solución Necesaria**: Mapear los eventos de scroll del ratón de Crossterm en el bucle principal de Ratatui para desplazar verticalmente las listas activas y la tabla de caracteres.

### E. Control de Redimensionamiento y Alerta de Dimensiones de Terminal
* **El Faltante**: El WebView de Tauri adaptaba la interfaz de manera fluida gracias a CSS responsivo. En la TUI, si la terminal se redimensiona por debajo de un tamaño mínimo (ej: 80x24 caracteres), la aplicación continúa renderizándose, provocando que los widgets se superpongan y las cajas de entrada queden ilegibles o corruptas visualmente.
* **Solución Necesaria**: Implementar una comprobación de tamaño del área del frame (`f.size()`). Si las dimensiones caen por debajo de un límite seguro, el renderizador debe pausar la interfaz principal y mostrar una pantalla de aviso centrada solicitando al usuario expandir su ventana de terminal (*"Terminal demasiado pequeña para operar"*).

### F. Limitación y Validación de Caracteres en las Cajas de Entrada (Input Constraints)
* **Archivos e Hilos Implicados**: [main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs) (campos `cajas`, `text_cajas`, `file_cajas`, y `settings_boot_cajas` del estado `TuiState`, gestores de eventos `handle_unlock_key`, `handle_text_cipher_key`, `handle_file_cipher_key`, `handle_settings_key`, y la función de validación `parse_boxes`).
* **El Faltante**: En la versión anterior de React, los inputs de las cajas de inicio estaban restringidos por expresiones regulares y formateadores numéricos en [numerals.ts](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/DOCS/pendiente/LIVENCRYPT%202.0/src/i18n/numerals.ts) (impidiendo pegar letras, caracteres no válidos o superar los 3 dígitos o el rango 0..1000). En la versión TUI actual de `main.rs`, las entradas de texto en las cajas permiten escribir temporalmente cadenas de cualquier longitud y tipo antes de su validación, lo que causa desbordamientos visuales o errores de parsing.
* **Detalles de Integración (Diseño Técnico)**:
  * **Restricción en Caliente de Entrada**: Modificar los event handlers de teclado (`handle_unlock_key`, `handle_text_cipher_key`, etc.) para filtrar reactivamente los caracteres. Al recibir un evento `KeyCode::Char(value)`, solo se debe permitir la inserción si el carácter es un dígito (`'0'..='9'`) o un signo negativo (`'-'`) en el primer índice de la cadena.
  * **Límite de Longitud**: Imponer un límite de tamaño de caracteres estricto (máximo 3 para números positivos, máximo 4 para números negativos con `-`) en cada caja de entrada antes de permitir añadir el carácter al buffer de la cadena.
  * **Comprobación de Rango Activa**: Comprobar de forma dinámica que el valor numérico absoluto se encuentre estrictamente entre `0` y `1000` (o `-999` a `999` si se permiten offsets negativos).
  * **Indicador de Estado de Error Visual**: Modificar la lógica de dibujo de bordes en Ratatui para que las cajas de entrada cambien de color a rojo (ej: `Style::default().fg(Color::Red)`) en el momento en que se ingrese un valor fuera de rango o mal formateado, alertando al usuario antes de ejecutar operaciones de validación criptográfica en `parse_boxes`.

### G. Exportación de Texto Cifrado de Forma Segura a un Archivo (Text Cipher)
* **Archivos e Hilos Implicados**: [main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs) (interfaz `Screen::TextCipher`, estructura `TuiState` con atajos en `handle_text_cipher_key`, `handle_text_cipher_mouse` y dibujo en `draw_text_cipher`).
* **El Faltante**: En el cifrador de texto de la versión React (`TextCipherWindow.tsx`), la alternativa a la falta de portapapeles era un botón de guardado. Dado que en terminales restringidas o entornos aislados de alta seguridad el portapapeles del sistema operativo puede estar deshabilitado por completo por políticas de seguridad, la falta de una opción para volcar directamente el texto cifrado/descifrado a un archivo físico en la TUI representa un cuello de botella crítico para la usabilidad.
* **Detalles de Integración (Diseño Técnico)**:
  * **Estructura de Datos**: Añadir el campo `text_output_file: String` a la estructura `TuiState` en `main.rs` para almacenar de forma persistente y editable la ruta del archivo del host donde se desea guardar el resultado.
  * **Interfaz Visual**: Renderizar un nuevo cuadro de entrada de texto en la vista de `Screen::TextCipher` utilizando un bloque de Ratatui titulado `" Ruta de Exportación "`, permitiendo enfocarlo mediante la navegación con la tecla `Tab` o clics de ratón.
  * **Atajo de Teclado y Confirmación**: Asignar un atajo de teclado dedicado (ej: `Ctrl+S` o tecla de función `F6`) y un botón interactivo `[E] Exportar a Archivo` para invocar el proceso de exportación del buffer `state.text_output`.
  * **Escritura Segura de Archivos**: Implementar una función `export_text_to_file` en `main.rs` que utilice `std::fs::OpenOptions` para crear/abrir el archivo. En plataformas Unix, forzar permisos ultra-restrictivos de lectura/escritura (`0o600` / propietario exclusivo) para evitar fugas de información.
  * **Garantías Criptográficas e Integridad**: Realizar la escritura a través de un búfer efímero que aplique `Zeroize` tras vaciarse, y ejecutar `.sync_all()` sobre el manejador de archivo para obligar al kernel a vaciar físicamente los datos al disco, previniendo su persistencia residual en memoria swap o caché de disco. En caso de que el archivo destino ya exista, se debe mostrar un aviso emergente solicitando confirmación explícita (ej: pulsar `Enter` nuevamente) para evitar sobrescrituras accidentales.

### H. Pantalla de Configuración (`Screen::Settings`): Funcionalidades Incompletas
* **Archivos e Hilos Implicados**: [main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs) (`Screen::Settings`, `handle_settings_key`, `draw_settings`), [vault.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs) (función `boot_shield_destructive_panic`/`boot_shield_factory_reset`) y [network_profile.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/network_profile.rs).
* **El Faltante**: La pantalla de ajustes en la versión Tauri (`Launcher`) permitía gestionar de manera granular parámetros de seguridad del daemon del Boot Shield. En la TUI actual, la pantalla `Screen::Settings` solo contiene buffers estáticos para cajas de boot y perfiles de red simplificados, careciendo de menús de configuración interactivos en caliente.
* **Detalles de Integración (Diseño Técnico)**:
  * **Control de Apagado por Inactividad (Inactivity Timeout)**: Añadir la variable `inactivity_timeout_seconds` (tipo `u64`, rango 30s-3600s) editable en la TUI. En el bucle principal de la aplicación en `main.rs`, comparar de forma continua el tiempo transcurrido desde la última interacción de Crossterm. Si se supera el límite de inactividad, invocar `state.lock()` inmediatamente y aplicar `Zeroize` sobre las claves en RAM.
  * **Borrado Destructivo Automático (Auto-Wipe)**: Añadir un interruptor lógico de activación/desactivación en la interfaz de configuración. Al estar activo, si el contador de intentos de acceso en el encabezado del vault alcanza el límite de 5 (`MAX_FAILED_ATTEMPTS`), se dispara automáticamente una destrucción silenciosa del volumen y las plantillas.
  * **Conmutador de Perfiles de Red Tácticos**: Implementar el cambio interactivo de perfiles de red en caliente (ej: `Drop Default Route` / `Decoy Network Traffic` / `Air-Gapped Isolation`). Al seleccionar un perfil y escribir la palabra de confirmación en `settings_network_confirmation`, invocar las utilidades del sistema (`nmcli`, `ip route` o subprocesos eBPF) para forzar el estado de conectividad deseado.
  * **Menú de Restablecimiento de Fábrica Segura**: Añadir un diálogo interactivo en `Screen::Settings`. El sistema debe congelar la UI y pedir al usuario que teclee textualmente la palabra `"RESTABLECER"`. Al confirmarse, invocar `boot_shield_destructive_panic("DESTRUIR VAULT Y PLANTILLAS")` para sobrescribir el archivo del vault con ruido criptográfico aleatorio, ejecutar `.sync_all()`, y borrar todos los datos físicos y backups del disco.
  * **Visor del Reporte Forense y Hardening**: Añadir una subventana interactiva con scroll vertical dentro del panel de configuración para renderizar la salida detallada en caliente de `process_hardening_status()` (ej: confirmación de `mlockall` exitoso, desactivación de core dumps y políticas de AppArmor).

### I. Editor de Plantillas (`Screen::TemplateEditor`): El Módulo con Mayor Carencia de Interacción
* **Archivos e Hilos Implicados**: [main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs) (`Screen::TemplateEditor`, `handle_template_editor_key`, `handle_template_editor_mouse`, `draw_template_editor`, `add_selected_language`, `add_selected_numbers`), [templates.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/templates.rs) (funciones `get_language_chars`, `get_numbers_signs`, `missing_hex_chars`, `save_template`, `delete_template`).
* **El Faltante**: Este es el componente más incompleto de la interfaz TUI en comparación con el editor en React (`TemplateEditorWindow.tsx`). Las carencias más críticas que deben resolverse para completar el módulo son: la selección estructurada de idiomas/signos de la lista, la navegación celda a celda con el ratón o flechas en la cuadrícula, el cálculo en vivo de cobertura hex, y la persistencia segura dentro del vault en caliente.
* **Detalles de Integración (Diseño Técnico)**:
  * **Selección Interactiva de Idiomas y Números (Listas Navegables)**: Dividir la columna derecha de `Screen::TemplateEditor` en dos widgets de lista interactiva (`List` de Ratatui y `ListState` en `main.rs`). El usuario debe poder navegar de forma independiente (usando las flechas del teclado `Up`/`Down` o scroll del ratón) por la lista completa de idiomas y tablas de caracteres de `templates.rs` (ej: Español, Ruso, Armenio, Amhárico) y la lista de signos/números, visualizando una previsualización de su contenido y cargándolos en la matriz activa al pulsar `Enter` o hacer clic.
  * **Navegación e Interacción Celda a Celda en la Cuadrícula**: Reemplazar la caja de texto plana del editor de caracteres por una rejilla de dibujo interactiva basada en una matriz de 5 filas por 23 columnas. La celda actualmente enfocada debe mostrarse con un borde resaltado. El usuario podrá navegar por la matriz usando las flechas de dirección (`Left`/`Right`/`Up`/`Down`) o haciendo clic directamente con el ratón sobre cualquier celda para reescribir/modificar el carácter correspondiente de forma individual.
  * **Validación de Cobertura Hexadecimal en Tiempo Real (Hex Coverage)**: Implementar una rutina que compare el buffer de la plantilla editada (`state.template_chars`) contra el conjunto requerido de 16 caracteres hexadecimales (`[0-9a-f]`). Renderizar un medidor dinámico en el panel del editor que indique visualmente el nivel de cobertura (ej: `Cobertura Hex: 16/16 [VÁLIDA]` en color verde, o `Cobertura Hex: 14/16 [⚠ INVÁLIDA - Faltan: e, f]` en color amarillo). Bloquear el botón de guardado si la cobertura hexadecimal no es del 100%.
  * **Persistencia Atómica e Integridad en el Vault**: Integrar los atajos y botones de interacción para salvar y borrar las plantillas de forma interactiva invocando directamente `save_template` y `delete_template` de `templates.rs`. Asegurar que estas operaciones escriban en caliente sobre el volumen seguro del vault ya desbloqueado, forzando `.sync_all()` sobre la escritura de archivos en disco y refrescando automáticamente la lista de plantillas disponibles en la TUI en tiempo de ejecución.

### J. Cifrado e Integración de Carpetas/Directorios (VFS de Carpetas Cifradas)
* **Archivos e Hilos Implicados**: [file_cipher.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/file_cipher.rs) (donde solo se procesan archivos individuales), [main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs) (enumeración `Screen`, bucle de eventos `handle_dashboard_key`/`handle_dashboard_mouse`, y función de dibujo `draw_dashboard`), y [lib.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/lib.rs).
* **El Faltante**:
  1. **En el Backend**: La lógica de `FileCipher` está restringida a archivos únicos. No existe en el backend actual código para empaquetar o recorrer de forma recursiva una estructura de carpetas (ej. comprimiéndolas en un contenedor intermedio `tar` o `zip` antes de cifrar el stream resultante), ni soporte para montar directorios cifrados mediante FUSE o sistemas de archivos virtuales (VFS).
  2. **En el Dashboard**: No existe ninguna entrada ni lógica mapeada en la TUI para iniciar operaciones sobre carpetas.
* **Detalles de Integración (Diseño Técnico)**:
  * **Empaquetado Criptográfico**: Integrar en `Cargo.toml` soporte para compresión de archivos jerárquicos (ej: crates `tar` o `zip`). En el cifrado de carpetas, empaquetar recursivamente el directorio seleccionado en un stream de memoria volátil protegido, y pasarlo directamente al cifrador por flujo para generar el archivo final `.lvc`. En el descifrado, expandir el stream descifrado directamente en la ruta de destino.
  * **Habilitación en el Dashboard TUI**:
    * Agregar una nueva opción visual en `draw_dashboard`: `d = cifrar/descifrar carpeta`.
    * Registrar el estado `Screen::FolderCipher` en la enumeración `Screen` y en los event handlers.
    * Mapear la tecla `d` en `handle_dashboard_key` y la fila correspondiente en `handle_dashboard_mouse`.
  * **Selector de Directorios**: Reutilizar el componente `FileBrowser` permitiendo al usuario seleccionar carpetas (`path.is_dir()`) como origen y destino.

---

## Enlaces Relacionados
* Volver al [[00_indice|Índice General]].
* Ver detalles de la interfaz de consola: [[09_integración_frontend_en_dashboard|Integración Frontend en Dashboard]].
* Ver detalles del Teclado Seguro: [[10_teclado|Teclado Blindado (Posiciones Aleatorias)]].
