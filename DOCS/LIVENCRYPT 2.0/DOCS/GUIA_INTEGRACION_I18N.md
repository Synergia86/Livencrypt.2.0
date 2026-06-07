# Guía de Integración Multiidioma i18n en Livencrypt 2.0

> [!info] Objetivo
> Integrar soporte multiidioma real en Livencrypt 2.0 para frontend React, backend Rust/Tauri, títulos de ventanas, errores, estados de seguridad y configuración de caracteres usados como contraseña.

Esta guía usa enlaces estilo Obsidian solo para citar archivos fuente del proyecto: [[main.tsx]], [[TextCipherWindow.tsx]], [[FileCipherWindow.tsx]], [[TemplateEditorWindow.tsx]], [[PasswordSetupDialog.tsx]], [[PasswordDialog.tsx]], [[lib.rs]], [[vault.rs]], [[positional.rs]], [[templates.rs]], [[process_hardening.rs]], [[network_profile.rs]], [[file_cipher.rs]] y [[TemplateSelector.tsx]].

---

## 1. Diagnóstico del Documento Actual

El documento anterior era útil como punto de partida, pero faltaban detalles críticos:

- No contemplaba i18n en Rust/Tauri.
- No cubría errores devueltos por comandos Rust.
- No cubría títulos de ventanas secundarias.
- No cubría textos de consola/log internos.
- No cubría estados de Boot Shield, red, hardening y pánico destructivo.
- Persistía idioma únicamente en `localStorage`, insuficiente si Boot Shield está activo y se quiere que la configuración de sesión quede dentro del vault.
- No contemplaba los símbolos de control editables para contraseña.
- No definía cómo insertar caracteres de otros idiomas como símbolos de contraseña.
- No definía claves tipadas, fallback, interpolación, pluralización ni auditoría de strings no traducidos.

> [!warning] Corrección de alcance
> i18n no debe limitarse a React. Livencrypt tiene mensajes de seguridad y validación generados en Rust. Esos mensajes deben salir como claves traducibles o como estructuras `error_code + params`, no como frases fijas en castellano.

---

## 2. Estado Actual Observado en Código

Según los archivos actuales:

- [[TextCipherWindow.tsx]] ya carga y guarda configuración de contraseña mediante `get_text_password_settings` y `save_text_password_settings`.
- [[PasswordSetupDialog.tsx]] ya permite editar manualmente `controlSymbols`.
- [[PasswordDialog.tsx]] ya muestra los símbolos configurados y el patrón según `passwordDirection`.
- [[positional.rs]] ya recibe `password_direction` y `control_symbols` en las funciones de cifrado/descifrado con contraseña.
- [[lib.rs]] ya contiene `TextPasswordSettings`, persistencia local en `text_password.msgpack` y comandos Tauri para leer/guardar configuración.
- [[vault.rs]] ya expone lectura/escritura de `VaultPayload.settings` cuando Boot Shield está desbloqueado.
- [[TemplateEditorWindow.tsx]] ya carga `get_language_characters`, `get_language_numbers_signs` y ordena idiomas/signos alfabéticamente.
- [[templates.rs]] ya contiene mapas de caracteres por idioma y signos/números.
- [[main.tsx]] ya importa paquetes `@fontsource` para CJK, árabe, armenio, bengalí, birmano, cherokee, devanágari, etíope, georgiano, japonés, kannada, khmer, coreano, chino simplificado, sinhala, símbolos, tailandés y tibetano.
- [[index.css]] ya declara una cadena de fallback con `Noto Sans SC`, `Noto Sans JP`, `Noto Sans KR`, `Noto Sans Arabic`, `Noto Sans Devanagari`, `Noto Sans Symbols` y otros perfiles.
- Aún no existe una estructura `src/i18n/` frontend.
- Aún no existe una estructura `src-tauri/src/i18n/` backend.
- Los textos visibles siguen mayoritariamente escritos como literales en componentes React.
- Los errores Rust siguen mayoritariamente escritos como strings directos.
- Falta integrar en [[PasswordSetupDialog.tsx]] una paleta para insertar caracteres de otros idiomas en `controlSymbols`; ahora el campo es editable manualmente, pero no tiene selector de idioma.
- Falta integrar en [[main.tsx]] un parser de cajas Boot Shield para numerales localizados. Actualmente existen caracteres y fuentes, pero las cajas se convierten con `Number(value)`.

---

## 3. Principios de Diseño

1. El idioma seleccionado no es secreto, pero si Boot Shield está desbloqueado debe persistirse dentro del vault para mantener coherencia de configuración cifrada.
2. Las frases, cajas, contraseñas y valores sensibles nunca se traducen, registran ni interpolan en mensajes.
3. Rust no debe devolver textos finales al usuario cuando el frontend pueda resolver una clave i18n.
4. Los textos de UI deben vivir en catálogos JSON/MessagePack.
5. Los textos de backend deben vivir en un catálogo Rust o devolverse como códigos estables.
6. Las claves i18n deben ser estables y semánticas, no textos originales.
7. Los símbolos de control de contraseña deben ser configurables, normalizados y persistidos.
8. Los caracteres de idiomas deben poder añadirse a los símbolos de contraseña desde los mapas ya existentes de [[templates.rs]].

---

## 4. Estructura Recomendada Frontend

Crear:

```text
src/
├── i18n/
│   ├── index.ts
│   ├── keys.ts
│   ├── normalize.ts
│   └── locales/
│       ├── es.json
│       └── en.json
├── context/
│   └── LanguageContext.tsx
└── hooks/
    └── useI18n.ts
```

### 4.1. `src/i18n/locales/es.json`

Debe estructurarse por dominio funcional:

```json
{
  "common": {
    "back": "VOLVER",
    "cancel": "CANCELAR",
    "apply": "APLICAR",
    "save": "GUARDAR",
    "create": "CREAR",
    "edit": "EDITAR",
    "delete": "ELIMINAR",
    "activate": "ACTIVAR",
    "deactivate": "DESACTIVAR",
    "processing": "PROCESANDO...",
    "close": "CERRAR",
    "error": "ERROR",
    "warning": "AVISO",
    "ok": "OK"
  },
  "dashboard": {
    "title": "LIVENCRYPT 2.0",
    "network": "RED",
    "network_online": "ONLINE",
    "network_offline": "OFFLINE",
    "settings": "CONFIGURACIÓN",
    "panic": "PÁNICO",
    "help_access": "AYUDA",
    "help_access_title": "Ayuda para consultar el acceso",
    "initializing_boot_shield": "Inicializando Boot Shield..."
  },
  "boot": {
    "secure_unlock_title": "DESBLOQUEO DE ENTORNO SEGURO",
    "secure_unlock_subtitle": "Introduzca la secuencia autorizada para descifrar en memoria",
    "boxes_sequence": "Secuencia de las Cajas (Caja 1 a 5):",
    "access_phrase": "Frase de Acceso:",
    "access_phrase_placeholder": "Inserte frase para descifrar...",
    "secondary_boxes": "Secuencia secundaria de cajas:",
    "secondary_phrase": "Frase secundaria:",
    "secondary_phrase_placeholder": "Inserte segunda frase...",
    "unlock_dram": "[ Desbloquear y Descargar en DRAM ]",
    "reset_local_install": "Restablecer instalación local",
    "reset_warning": "Borra el vault Boot Shield y las plantillas locales de este usuario. Use esta opción solo si desea una instalación limpia o no conserva la frase anterior.",
    "reset_confirm_placeholder": "RESTABLECER",
    "reset_and_close": "[ Borrar Boot Shield local y cerrar ]"
  },
  "settings": {
    "title": "CONFIGURACIÓN DEL SISTEMA",
    "access_section": "Sección: Acceso",
    "panic_section": "Sección: Pánico destructivo",
    "network_section": "Sección: Red",
    "hardening_section": "Sección: Hardening",
    "language_section": "Sección: Idioma",
    "boot_auto_encrypt": "AUTO-CIFRADO DE ARRANQUE:",
    "boot_template": "Plantilla Boot Shield:",
    "double_credential_before_aead": "Doble credencial antes de AEAD",
    "boot_phrase": "Frase de cifrado:",
    "boot_phrase_placeholder": "Frase de auto-cifrado...",
    "boot_disable_phrase_placeholder": "Frase actual para desactivar...",
    "boot_secondary_phrase_placeholder": "Segunda frase de auto-cifrado...",
    "create_vault": "[ CREAR VAULT CIFRADO Y BLINDAR ]",
    "disable_boot_shield": "[ VERIFICAR Y DESACTIVAR BOOT SHIELD ]",
    "processing_vault": "[ PROCESANDO VAULT CIFRADO... ]",
    "destructive_panic_mode": "Modo pánico destructivo:",
    "network_profile": "Perfil de control de red:",
    "network_save_profile": "[ GUARDAR PERFIL DE RED ]",
    "network_confirm_placeholder": "ENTENDIDO",
    "language_select": "Seleccionar idioma:"
  },
  "text_cipher": {
    "title": "CIFRAR TEXTO",
    "template": "Plantilla",
    "box": "Caja",
    "execute": "EJECUTAR",
    "clear": "LIMPIAR",
    "encrypt": "CIFRAR",
    "decrypt": "DESCIFRAR",
    "text": "Texto",
    "result": "Resultado",
    "copy": "COPIAR",
    "password_insert": "INSERTAR CONTRASEÑA",
    "password_position_title": "Contraseña {{position}} del símbolo",
    "empty_text": "Texto vacío",
    "select_template": "Selecciona una plantilla"
  },
  "password": {
    "setup_title": "CONFIGURAR CONTRASEÑA",
    "setup_subtitle": "Configuración del modo contraseña",
    "length_limit": "Límite caracteres contraseña",
    "length_range": "(mínimo 2, máximo 25)",
    "position": "Posición de la contraseña",
    "after_symbol": "Detrás del símbolo",
    "before_symbol": "Delante del símbolo",
    "control_symbols": "Símbolos de control activos:",
    "control_symbols_help": "Edita los símbolos de control según el idioma o plantilla. Incluye uno de ellos en el texto junto con los caracteres de contraseña para activar la protección.",
    "add_language_chars": "Añadir caracteres por idioma",
    "detected_title": "CONTRASEÑA DETECTADA",
    "verify_title": "VERIFICACIÓN DE CONTRASEÑA",
    "protected_text": "Este texto está protegido",
    "password_label": "Contraseña",
    "attempts": "Intentos:",
    "remaining": "{{count}} restantes"
  },
  "file_cipher": {
    "title": "CIFRAR ARCHIVOS",
    "select_file": "Seleccionar archivo",
    "save_result": "Guardar resultado",
    "save_path_prompt": "Ruta para guardar:",
    "reference": "Referencia",
    "guard_cancelled": "Guardado cancelado",
    "window_cleared": "Ventana limpiada"
  },
  "templates": {
    "title": "EDITOR DE PLANTILLAS",
    "editing": "EDITANDO: {{name}}",
    "loaded": "Cargadas: {{count}}",
    "selected": "Seleccionados: {{count}} chars",
    "select_languages": "Seleccionar idiomas",
    "numbers_signs": "Números / Signos",
    "new_template": "Nueva plantilla",
    "custom_size": "Tamaño personalizado",
    "cells": "{{count}} celdas",
    "free": "{{count}} libres",
    "exact": "exacto",
    "add_hex_minimum": "AÑADIR HEX MÍNIMO",
    "shuffle": "ALEATORIO",
    "template_name_placeholder": "Nombre plantilla...",
    "palette": "Paleta de caracteres",
    "all": "TODOS",
    "empty_palette": "Selecciona idiomas del panel izquierdo para ver los caracteres disponibles",
    "template_chars": "Caracteres para la plantilla ({{count}})",
    "clear_all": "VACIAR TODO",
    "existing_templates": "Plantillas ({{count}})"
  },
  "hardening": {
    "core_dumps": "Core dumps",
    "dumpable": "Dumpable",
    "mlockall": "mlockall",
    "integrity": "Integridad",
    "blocked": "BLOQUEADO",
    "off": "OFF",
    "failed": "FALLÓ",
    "no": "NO",
    "no_expected_hash": "SIN HASH ESPERADO",
    "binary_sha256": "SHA-256 binario",
    "no_warnings": "Sin avisos de hardening.",
    "unavailable": "Estado de hardening no disponible."
  }
}
```

---

## 5. Estructura Correcta para i18n en Rust

Crear:

```text
src-tauri/src/
├── i18n/
│   ├── mod.rs
│   ├── catalog.rs
│   ├── error.rs
│   ├── keys.rs
│   └── locales/
│       ├── es.json
│       └── en.json
```

### 5.1. `src-tauri/src/i18n/keys.rs`

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum I18nKey {
    TemplateNotFound,
    InvalidUrl,
    ToolNotAllowed,
    FolderOpenFailed,
    BootShieldLocked,
    BootShieldNotConfigured,
    BootShieldInvalidCredentials,
    VaultInvalid,
    NetworkPermissionDenied,
    HardeningCoreDumpsFailed,
    HardeningDumpableFailed,
    HardeningMlockallFailed,
    BinaryIntegrityMismatch,
}
```

### 5.2. `src-tauri/src/i18n/error.rs`

```rust
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalizedError {
    pub key: String,
    pub params: HashMap<String, String>,
    pub fallback: String,
}

impl LocalizedError {
    pub fn new(key: &str, fallback: &str) -> Self {
        Self {
            key: key.to_string(),
            params: HashMap::new(),
            fallback: fallback.to_string(),
        }
    }

    pub fn with_param(mut self, key: &str, value: impl Into<String>) -> Self {
        self.params.insert(key.to_string(), value.into());
        self
    }
}
```

### 5.3. Patrón recomendado de retorno

En vez de devolver:

```rust
Err(format!("Plantilla no encontrada: {}", template_name))
```

devolver:

```rust
Err(LocalizedError::new(
    "errors.template_not_found",
    "Plantilla no encontrada: {{name}}",
).with_param("name", template_name))
```

> [!important] Recomendación
> Para no romper todas las firmas de golpe, migrar en dos fases:
>
> 1. Mantener `Result<T, String>`, pero los strings deben ser claves tipo `errors.template_not_found|name=Livencrypt`.
> 2. Pasar después a `Result<T, LocalizedError>` cuando el frontend ya procese errores estructurados.

### 5.4. Catálogo Rust

`src-tauri/src/i18n/locales/es.json`:

```json
{
  "errors": {
    "template_not_found": "Plantilla no encontrada: {{name}}",
    "tool_not_allowed": "Herramienta no permitida: {{label}}",
    "invalid_url": "URL inválida",
    "folder_open_failed": "No se pudo abrir la carpeta: {{error}}",
    "boot_shield_locked": "Boot Shield activo: vault bloqueado.",
    "boot_shield_not_configured": "Boot Shield no está configurado.",
    "boot_shield_invalid_credentials": "Credenciales inválidas o vault manipulado.",
    "vault_invalid": "Vault Boot Shield inválido: {{error}}",
    "network_permission_denied": "Permiso denegado para modificar la red.",
    "hardening_core_dumps_failed": "No se pudo deshabilitar RLIMIT_CORE.",
    "hardening_dumpable_failed": "No se pudo aplicar PR_SET_DUMPABLE=0.",
    "hardening_mlockall_failed": "MLOCKALL real no aplicado: revise RLIMIT_MEMLOCK, CAP_IPC_LOCK o límites del usuario.",
    "binary_integrity_mismatch": "El hash del binario no coincide con el hash esperado."
  },
  "windows": {
    "text_cipher": "Livencrypt 2.0 - Transmutador de Texto",
    "file_cipher": "Livencrypt 2.0 - Transmutador de Archivo",
    "template_editor": "Livencrypt 2.0 - Plantillas"
  }
}
```

### 5.5. Comandos Tauri para idioma

Añadir comandos:

```rust
#[tauri::command]
pub fn get_language_settings() -> Result<LanguageSettings, String>;

#[tauri::command]
pub fn save_language_settings(settings: LanguageSettings) -> Result<LanguageSettings, String>;

#[tauri::command]
pub fn get_rust_i18n_catalog(language: String) -> Result<HashMap<String, String>, String>;
```

Persistencia:

- Si Boot Shield está activo y desbloqueado: guardar en `VaultPayload.settings`.
- Si Boot Shield no está activo: guardar en `~/.local/share/livencrypt/.livencrypt/settings/i18n.msgpack`.
- Nunca usar `localStorage` como única fuente si hay vault desbloqueado.

---

## 6. Inserción de Caracteres de Otros Idiomas como Contraseña

Livencrypt ya tiene mapas de caracteres por idioma en [[templates.rs]]:

- `get_language_characters`
- `get_language_numbers_signs`
- `get_template_presets`

La configuración de contraseña en [[PasswordSetupDialog.tsx]] debe integrarse con esos mapas.

### 6.1. UI requerida

En `CONFIGURAR CONTRASEÑA`, dentro de `Símbolos de control activos`, añadir:

```text
Selector de idioma
Selector de números/signos
Paleta de caracteres del idioma
Botón: AÑADIR A SÍMBOLOS DE CONTROL
Botón: RESTAURAR SÍMBOLOS POR DEFECTO
Campo editable final
Vista previa:
  símbolo + contraseña
  contraseña + símbolo
```

### 6.2. Reglas

- El usuario puede escribir símbolos manualmente.
- El usuario puede insertar caracteres desde otro idioma.
- Se eliminan espacios.
- Se eliminan duplicados.
- Se preserva el orden elegido por el usuario.
- Si el campo queda vacío, se restauran símbolos por defecto.
- El backend debe recibir `controlSymbols` en `cipher_text` y `decipher_text`.
- Rust debe preservar esos símbolos durante cifrado/descifrado.

### 6.3. Persistencia

Claves en configuración:

```text
text_password.enabled
text_password.length
text_password.direction
text_password.control_symbols
text_password.language_source
text_password.signs_source
```

> [!security] Seguridad
> Los símbolos de control no son secretos, pero sí afectan a cómo se detecta la contraseña. Si Boot Shield está activo, deben persistirse en el vault para evitar divergencia entre sesión cifrada y configuración local.

---

## 7. Inventario de Textos a Traducir

Este inventario cita los textos visibles que deben migrarse a claves i18n. Las rutas se citan con sintaxis Obsidian.

### 7.1. [[main.tsx]] - Pantalla de bloqueo y dashboard

| Texto actual | Clave propuesta |
|---|---|
| `LIVENCRYPT 2.0` | `dashboard.title` |
| `Inicializando Boot Shield...` | `dashboard.initializing_boot_shield` |
| `DESBLOQUEO DE ENTORNO SEGURO` | `boot.secure_unlock_title` |
| `Introduzca la secuencia autorizada para descifrar en memoria` | `boot.secure_unlock_subtitle` |
| `Secuencia de las Cajas (Caja 1 a 5):` | `boot.boxes_sequence` |
| `Frase de Acceso:` | `boot.access_phrase` |
| `Inserte frase para descifrar...` | `boot.access_phrase_placeholder` |
| `Secuencia secundaria de cajas:` | `boot.secondary_boxes` |
| `Frase secundaria:` | `boot.secondary_phrase` |
| `Inserte segunda frase...` | `boot.secondary_phrase_placeholder` |
| `[ Desbloquear y Descargar en DRAM ]` | `boot.unlock_dram` |
| `Restablecer instalacion local` | `boot.reset_local_install` |
| `Borra el vault Boot Shield...` | `boot.reset_warning` |
| `RESTABLECER` | `boot.reset_confirm_placeholder` |
| `[ Borrar Boot Shield local y cerrar ]` | `boot.reset_and_close` |
| `RED` | `dashboard.network` |
| `ONLINE` | `dashboard.network_online` |
| `OFFLINE` | `dashboard.network_offline` |
| `CONFIGURACIÓN` | `dashboard.settings` |
| `PÁNICO` | `dashboard.panic` |
| `Ayuda para consultar el acceso` | `dashboard.help_access_title` |
| `CONFIGURACIÓN DEL SISTEMA` | `settings.title` |
| `Sección: Acceso` | `settings.access_section` |
| `AUTO-CIFRADO DE ARRANQUE:` | `settings.boot_auto_encrypt` |
| `ACTIVAR` | `common.activate` |
| `DESACTIVAR` | `common.deactivate` |
| `Plantilla Boot Shield:` | `settings.boot_template` |
| `Doble credencial antes de AEAD` | `settings.double_credential_before_aead` |
| `Frase de cifrado:` | `settings.boot_phrase` |
| `Frase de auto-cifrado...` | `settings.boot_phrase_placeholder` |
| `Frase actual para desactivar...` | `settings.boot_disable_phrase_placeholder` |
| `Segunda frase de auto-cifrado...` | `settings.boot_secondary_phrase_placeholder` |
| `[ CREAR VAULT CIFRADO Y BLINDAR ]` | `settings.create_vault` |
| `[ VERIFICAR Y DESACTIVAR BOOT SHIELD ]` | `settings.disable_boot_shield` |
| `[ PROCESANDO VAULT CIFRADO... ]` | `settings.processing_vault` |
| `Sección: Pánico destructivo` | `settings.panic_section` |
| `Modo pánico destructivo:` | `settings.destructive_panic_mode` |
| `Sección: Red` | `settings.network_section` |
| `Perfil de control de red:` | `settings.network_profile` |
| `Simulación segura` | `network.profile_mock` |
| `Manual externo` | `network.profile_manual` |
| `Cortar Internet sin apagar interfaces` | `network.profile_drop_default_route` |
| `Apagar red del sistema` | `network.profile_nmcli_off` |
| `ENTENDIDO` | `network.confirmation` |
| `[ GUARDAR PERFIL DE RED ]` | `settings.network_save_profile` |
| `Sección: Hardening` | `settings.hardening_section` |
| `Core dumps` | `hardening.core_dumps` |
| `Dumpable` | `hardening.dumpable` |
| `Integridad` | `hardening.integrity` |
| `BLOQUEADO` | `hardening.blocked` |
| `FALLÓ` | `hardening.failed` |
| `SIN HASH ESPERADO` | `hardening.no_expected_hash` |
| `Sin avisos de hardening.` | `hardening.no_warnings` |
| `Estado de hardening no disponible.` | `hardening.unavailable` |
| `Boot Shield activado` | `boot.enabled_title` |
| `[ CERRANDO LIVENCRYPT... ]` | `common.closing_livencrypt` |
| `[ CERRAR LIVENCRYPT ]` | `common.close_livencrypt` |

### 7.2. [[TextCipherWindow.tsx]]

| Texto actual | Clave propuesta |
|---|---|
| `CIFRAR TEXTO` | `text_cipher.title` |
| `Plantilla` | `text_cipher.template` |
| `Caja {{n}}` | `text_cipher.box_number` |
| `Texto vacío` | `text_cipher.empty_text` |
| `Selecciona una plantilla` | `text_cipher.select_template` |
| `EJECUTAR` | `text_cipher.execute` |
| `PROCESANDO...` | `common.processing` |
| `LIMPIAR` | `text_cipher.clear` |
| `INSERTAR CONTRASEÑA` | `text_cipher.password_insert` |
| `Contraseña detrás del símbolo` | `text_cipher.password_position_title` |
| `Contraseña delante del símbolo` | `text_cipher.password_position_title` |
| `CIFRAR` | `text_cipher.encrypt` |
| `DESCIFRAR` | `text_cipher.decrypt` |
| `Texto` | `text_cipher.text` |
| `Resultado` | `text_cipher.result` |
| `COPIAR` | `text_cipher.copy` |
| `Copiado al portapapeles` | `text_cipher.copied` |
| `Formulario limpiado` | `text_cipher.form_cleared` |
| `Contraseña detectada — verificación requerida` | `text_cipher.password_detected_verification_required` |
| `Contraseña rechazada — resultado oculto` | `text_cipher.password_rejected_result_hidden` |
| `Contraseña verificada correctamente` | `text_cipher.password_verified` |

### 7.3. [[PasswordSetupDialog.tsx]] y [[PasswordDialog.tsx]]

| Texto actual | Clave propuesta |
|---|---|
| `CONFIGURAR CONTRASEÑA` | `password.setup_title` |
| `Configuración del modo contraseña` | `password.setup_subtitle` |
| `Límite caracteres contraseña` | `password.length_limit` |
| `(mínimo 2, máximo 25)` | `password.length_range` |
| `Posición de la contraseña` | `password.position` |
| `Detrás del símbolo` | `password.after_symbol` |
| `Delante del símbolo` | `password.before_symbol` |
| `Símbolos de control activos:` | `password.control_symbols` |
| `Edita los símbolos de control...` | `password.control_symbols_help` |
| `CONTRASEÑA DETECTADA` | `password.detected_title` |
| `VERIFICACIÓN DE CONTRASEÑA` | `password.verify_title` |
| `El texto contiene protección por contraseña` | `password.text_contains_password_protection` |
| `Este texto está protegido` | `password.protected_text` |
| `Símbolos de control:` | `password.control_symbols_short` |
| `Carácter especial detectado:` | `password.special_character_detected` |
| `Introduce la contraseña original usada al cifrar.` | `password.enter_original_password` |
| `Contraseña` | `password.password_label` |
| `Intentos:` | `password.attempts` |
| `{{count}} restantes` | `password.remaining` |
| `Bloqueado — {{count}} intentos fallidos.` | `password.locked_after_attempts` |
| `Contraseña incorrecta — {{count}} intentos restantes` | `password.incorrect_remaining` |

### 7.4. [[FileCipherWindow.tsx]]

| Texto actual | Clave propuesta |
|---|---|
| `Seleccionar archivo` | `file_cipher.select_file` |
| `Guardar resultado` | `file_cipher.save_result` |
| `Ruta para guardar:` | `file_cipher.save_path_prompt` |
| `CIFRAR ARCHIVOS` | `file_cipher.title` |
| `CIFRAR` | `file_cipher.encrypt` |
| `DESCIFRAR` | `file_cipher.decrypt` |
| `Guardado cancelado` | `file_cipher.save_cancelled` |
| `Ventana limpiada` | `file_cipher.window_cleared` |
| `ERROR: Tauri no detectado` | `file_cipher.tauri_not_detected` |
| `Escribe la ruta del archivo o selecciona uno` | `file_cipher.path_required` |
| `No se pudo obtener la ruta. Escribe la ruta manualmente.` | `file_cipher.path_pick_failed` |

### 7.5. [[TemplateEditorWindow.tsx]] y [[TemplateSelector.tsx]]

| Texto actual | Clave propuesta |
|---|---|
| `EDITOR DE PLANTILLAS` | `templates.title` |
| `EDITANDO: {{name}}` | `templates.editing` |
| `Cargadas: {{count}}` | `templates.loaded` |
| `Seleccionados: {{count}} chars` | `templates.selected` |
| `Seleccionar idiomas` | `templates.select_languages` |
| `Números / Signos` | `templates.numbers_signs` |
| `Nueva plantilla` | `templates.new_template` |
| `Tamaño personalizado` | `templates.custom_size` |
| `{{count}} celdas` | `templates.cells` |
| `{{count}} libres` | `templates.free` |
| `exacto` | `templates.exact` |
| `AÑADIR HEX MÍNIMO` | `templates.add_hex_minimum` |
| `ALEATORIO` | `templates.shuffle` |
| `Nombre plantilla...` | `templates.template_name_placeholder` |
| `GUARDAR` | `common.save` |
| `CREAR` | `common.create` |
| `CANCELAR` | `common.cancel` |
| `Paleta de caracteres` | `templates.palette` |
| `TODOS` | `templates.all` |
| `Selecciona idiomas del panel izquierdo para ver los caracteres disponibles` | `templates.empty_palette` |
| `Caracteres para la plantilla ({{count}})` | `templates.template_chars` |
| `VACIAR TODO` | `templates.clear_all` |
| `Haz clic en los caracteres de la paleta superior para añadirlos aquí` | `templates.click_palette_chars` |
| `Plantillas ({{count}})` | `templates.existing_templates` |
| `EDITAR` | `common.edit` |
| `ELIMINAR` | `common.delete` |
| `EDITANDO` | `templates.editing_badge` |
| `Cargando plantillas...` | `templates.loading` |
| `No hay plantillas disponibles` | `templates.none_available` |

### 7.6. [[lib.rs]], [[vault.rs]], [[process_hardening.rs]], [[network_profile.rs]], [[file_cipher.rs]], [[templates.rs]]

| Texto Rust actual | Clave propuesta |
|---|---|
| `No se pudo leer configuracion` | `errors.config_read_failed` |
| `Configuracion de contrasena invalida` | `errors.password_config_invalid` |
| `No se pudo guardar configuracion` | `errors.config_save_failed` |
| `Plantilla no encontrada: {{name}}` | `errors.template_not_found` |
| `No se pudo abrir la carpeta` | `errors.folder_open_failed` |
| `Herramienta no permitida: {{label}}` | `errors.tool_not_allowed` |
| `URL invalida` | `errors.invalid_url` |
| `Boot Shield activo: vault bloqueado.` | `errors.boot_shield_locked` |
| `Boot Shield no esta configurado.` | `errors.boot_shield_not_configured` |
| `Credenciales invalidas o vault manipulado.` | `errors.boot_shield_invalid_credentials` |
| `Vault Boot Shield invalido` | `errors.vault_invalid` |
| `No se pudo cifrar el vault Boot Shield.` | `errors.vault_encrypt_failed` |
| `La frase de Boot Shield no puede estar vacia.` | `errors.boot_phrase_empty` |
| `No se pudo deshabilitar RLIMIT_CORE.` | `errors.hardening_core_dumps_failed` |
| `No se pudo aplicar PR_SET_DUMPABLE=0.` | `errors.hardening_dumpable_failed` |
| `MLOCKALL REAL NO APLICADO...` | `errors.hardening_mlockall_failed` |
| `Livencrypt se esta ejecutando como root...` | `errors.running_as_root_warning` |
| `LD_PRELOAD esta definido...` | `errors.ld_preload_warning` |
| `El hash del binario no coincide...` | `errors.binary_integrity_mismatch` |
| `Plantilla vacia o dimensiones invalidas` | `errors.template_empty_or_invalid_dimensions` |
| `Caracter duplicado en plantilla` | `errors.template_duplicate_char` |
| `Faltan caracteres hexadecimales` | `errors.template_missing_hex` |
| `Archivo demasiado grande para indexado hex` | `errors.file_too_large_hex_index` |
| `Datos cifrados corruptos` | `errors.encrypted_data_corrupt` |
| `Permiso denegado` | `errors.permission_denied` |

---

## 8. Idiomas, Nombres de Idiomas y Plantillas

Los nombres de idiomas actualmente están en castellano dentro de [[templates.rs]]:

```text
Alemán, Amhárico, Árabe clásico, Armenio, Bengalí, Birmano, Cherokee,
Checo, Coreano, Chino, Devanágari, Escandinavo, Español, Etíope,
Francés, Gales, Georgiano, Griego, Húngaro, Inglés, Islandés, Kannada,
Katakana, Khmer, Letón, Lituano, Polaco, Rumano, Ruso, Tailandés,
Tibetano, Turco, Vietnamita, Signos, Arábigos
```

Para i18n deben convertirse a identificadores estables:

```text
de, am, ar_classical, hy, bn, my, chr, cs, ko, zh, devanagari,
scandinavian, es, ethiopic, fr, cy, ka, el, hu, en, is, kn, katakana,
km, lv, lt, pl, ro, ru, th, bo, tr, vi, signs, arabic_digits
```

El frontend mostrará el nombre traducido:

```json
{
  "languages": {
    "de": "Alemán",
    "en": "Inglés",
    "es": "Español",
    "zh": "Chino"
  }
}
```

### 8.1. Verificación de numeración y signos ya incluidos

[[templates.rs]] incluye `get_numbers_signs()` con numeración y signos por sistema de escritura. Ejemplos ya presentes:

| Grupo | Caracteres existentes |
|---|---|
| `Signos` | `+ - × ÷ ¡ ! ¿ ? ？ ) ( . · « » ; : = < > ␣` |
| `Árabe clásico` | `٠ ١ ٢ ٣ ٤ ٥ ٦ ٧ ٨ ٩ ؟ ؛` |
| `Bengalí` | `০ ১ ২ ৩ ৪ ৫ ৬ ৭ ৮ ۹ ৳ ৺ ৻ ঽ । ॥` |
| `Birmano` | `၀ ၁ ၂ ၃ ၄ ၅ ၆ ၇ ၈ ၉ ၊ ။` |
| `Coreano` | `0 1 2 3 4 5 6 7 8 9 零 一 二 三 四 五 六 七 八 九 十 百 千 万 億 兆` |
| `Chino` | `0 1 2 3 4 5 6 7 8 9 零 一 二 三 四 五 六 七 八 九 十 百 千 万 億 兆 壹 贰 叁 肆 伍 陆 柒 捌 玖 拾 佰 仟` |
| `Devanágari` | `० १ २ ३ ४ ५ ६ ७ ८ ९ । ॥ ॐ ॰ ₹` |
| `Kannada` | `೦ ೧ ೨ ೩ ೪ ೫ ೬ ೭ ೮ ೯` |
| `Khmer` | `០ ១ ២ ៣ ៤ ៥ ៦ ៧ ៨ ៩` |
| `Tailandés` | `๐ ๑ ๒ ๓ ๔ ๕ ๖ ๗ ๘ ๙` |

Conclusión:

```text
Fuentes y caracteres: incluidos para visualización y plantillas.
Uso como cajas Boot Shield: pendiente de parser local.
Uso como símbolos de contraseña de texto: parcialmente integrado mediante controlSymbols editable.
```

> [!important] Punto técnico
> Tener los caracteres incluidos no implica que JavaScript o Rust sepan convertirlos automáticamente a enteros. `一`, `壹`, `١`, `०` o `๗` se pueden mostrar correctamente, pero Boot Shield necesita convertirlos a `1`, `1`, `1`, `0` o `7` antes de derivar la clave.

---

## 9. Persistencia Recomendada

### 9.1. Sin Boot Shield

Guardar en:

```text
~/.local/share/livencrypt/.livencrypt/settings/i18n.msgpack
~/.local/share/livencrypt/.livencrypt/settings/text_password.msgpack
```

### 9.2. Con Boot Shield desbloqueado

Guardar dentro de:

```rust
VaultPayload.settings
```

Claves:

```text
i18n.language
i18n.fallback_language
text_password.enabled
text_password.length
text_password.direction
text_password.control_symbols
text_password.language_source
text_password.signs_source
```

### 9.3. Con Boot Shield bloqueado

Solo debe estar disponible:

- idioma mínimo de pantalla de desbloqueo;
- fallback local no secreto;
- nunca acceso al payload del vault hasta desbloquear.

### 9.4. Caso crítico: idioma de desbloqueo antes de abrir el vault

Si el usuario activa Boot Shield usando un idioma distinto, por ejemplo chino, Livencrypt debe poder mostrar la pantalla de desbloqueo en chino antes de descifrar el vault.

Esto no puede depender únicamente de `VaultPayload.settings`, porque ese payload está cifrado y no existe hasta que las cajas + frase ya han validado.

Diseño obligatorio:

```text
1. guardar idioma público de pantalla bloqueada en cabecera pública del vault o sidecar local no secreto
2. autenticar ese valor como Associated Data del vault cuando esté en cabecera
3. cargar ese idioma antes de montar LockScreen
4. mostrar etiquetas, placeholders, errores genéricos y ayuda en ese idioma
5. tras desbloquear, cargar configuración completa desde VaultPayload.settings
6. si hay divergencia entre cabecera pública y payload cifrado, el payload cifrado gana y se reescribe la cabecera pública en el siguiente guardado seguro
```

Claves públicas permitidas antes de desbloquear:

```text
boot_public.unlock_language
boot_public.unlock_number_system
boot_public.unlock_text_direction
boot_public.ui_font_profile
```

Estas claves no son secretas. No deben contener frase, cajas, hashes de frase, plantilla interna ni ningún dato que ayude a validar credenciales.

> [!important] Diferencia crítica
> Traducir la interfaz no significa traducir la credencial. Si la frase elegida por el usuario está en chino, esa frase exacta en Unicode forma parte del material criptográfico. Si se introduce otra frase visualmente parecida pero con distinta normalización Unicode, no debe desbloquear salvo que se aplique la misma normalización en activación y desbloqueo.

### 9.5. Números localizados en cajas Boot Shield

El código actual de [[main.tsx]] usa:

```ts
Number(value)
```

Esto no es suficiente para independencia i18n. En la práctica solo debe considerarse compatible con dígitos ASCII `0-9` y algunos formatos aceptados por JavaScript. Para usar chino, árabe, devanágari u otros sistemas, se requiere normalización explícita.

Requisito:

```text
entrada del usuario -> normalización Unicode -> parseo de número local -> entero canónico i64 -> Rust
```

Ejemplos:

```text
ASCII:       123 -> 123
Fullwidth:   １２３ -> 123
Árabe-Indic: ١٢٣ -> 123
Devanágari:  १२३ -> 123
Chino simple:
  一 -> 1
  十 -> 10
  二十三 -> 23
  一百二十三 -> 123
  一千 -> 1000
```

Reglas:

- Las cajas siguen siendo enteros canónicos `0..1000`.
- La UI puede mostrar y aceptar números localizados.
- Rust debe recibir `[i64; 5]` ya normalizados.
- Rust también debe validar rango `0..1000` para defensa en profundidad.
- El parser debe rechazar mezclas ambiguas, por ejemplo `1二3`, salvo que se defina una política explícita.
- Los mensajes de error deben ser genéricos en pantalla bloqueada: `CREDENCIALES INVALIDAS O VAULT MANIPULADO`.

Funciones recomendadas en frontend:

```text
normalizeUnicodeCredentialText(value)
parseLocalizedInteger(value, locale, numberSystem)
parseBootCajas(values, locale, numberSystem)
```

Funciones recomendadas en Rust:

```text
normalize_credential_phrase(value: &str) -> String
validate_boot_cajas(cajas: [i64; 5]) -> Result<[i64; 5], LocalizedError>
```

### 9.6. Frases en chino u otros idiomas

La frase de Boot Shield puede contener chino, japonés, coreano, árabe, devanágari, símbolos o cualquier Unicode soportado por la plantilla/entrada. Para evitar falsos fallos:

```text
1. aplicar normalización Unicode estable en activación y desbloqueo
2. recomendar NFC para conservar escritura del usuario
3. evaluar NFKC solo si se acepta plegar variantes compatibles, por ejemplo fullwidth
4. no convertir mayúsculas/minúsculas en frases secretas
5. no recortar caracteres internos
6. solo aplicar trim exterior si ya se hace en activación y desbloqueo
7. no traducir nunca la frase
```

Ejemplo:

```text
Activación:
  idioma desbloqueo: zh
  cajas mostradas/introducidas: 一 二 三 四 五
  cajas canónicas: 1 2 3 4 5
  frase: 安全短语
  KDF usa: frase normalizada + cajas canónicas

Desbloqueo:
  UI carga zh desde cabecera pública/sidecar
  usuario introduce 一 二 三 四 五
  frontend normaliza a 1 2 3 4 5
  usuario introduce 安全短语
  frontend/Rust aplica misma normalización Unicode
  Rust deriva la misma clave y abre el vault
```

Si el usuario introduce la frase traducida a otro idioma, no debe funcionar. La frase no es un texto de interfaz; es un secreto exacto.

---

## 10. Checklist de Integración

- [ ] Crear `src/i18n/` y `src/context/`.
- [ ] Crear `src/i18n/locales/es.json`.
- [ ] Crear `src/i18n/locales/en.json`.
- [ ] Crear `LanguageProvider`.
- [ ] Añadir interpolación `{{param}}`.
- [ ] Añadir fallback `es`.
- [ ] Añadir auditoría de claves faltantes.
- [ ] Añadir selector de idioma en `CONFIGURACIÓN DEL SISTEMA`.
- [ ] Persistir idioma en vault si Boot Shield está desbloqueado.
- [ ] Persistir idioma en archivo local si Boot Shield no está activo.
- [ ] Persistir idioma público mínimo de LockScreen fuera del payload cifrado, como cabecera pública autenticada o sidecar no secreto.
- [ ] Cargar idioma de LockScreen antes de pedir cajas + frase.
- [ ] Implementar parser de números localizados para cajas Boot Shield.
- [ ] Validar cajas `0..1000` en frontend y Rust.
- [ ] Normalizar Unicode de frase de Boot Shield de forma idéntica en activación y desbloqueo.
- [ ] Crear `src-tauri/src/i18n/`.
- [ ] Migrar errores Rust a claves o `LocalizedError`.
- [ ] Traducir títulos de ventanas Tauri.
- [ ] Migrar [[main.tsx]].
- [ ] Migrar [[TextCipherWindow.tsx]].
- [ ] Migrar [[PasswordSetupDialog.tsx]].
- [ ] Migrar [[PasswordDialog.tsx]].
- [ ] Migrar [[FileCipherWindow.tsx]].
- [ ] Migrar [[TemplateEditorWindow.tsx]].
- [ ] Migrar [[TemplateSelector.tsx]].
- [ ] Añadir selector de caracteres por idioma en símbolos de contraseña.
- [ ] Verificar que caracteres CJK, árabe, devanágari, tibetano y símbolos se muestran con las fuentes empaquetadas.
- [ ] Verificar que los símbolos personalizados de contraseña se preservan en `cipher_text` y `decipher_text`.
- [ ] Verificar que no se traducen ni registran frases, cajas ni contraseñas.

---

## 11. Pruebas Recomendadas

No requieren tocar red.

```text
npm run build
cargo test --test positional_tests
cargo test --test integration_tests
cargo check
```

Casos funcionales:

1. Cambiar idioma en configuración y cerrar/abrir Livencrypt.
2. Activar Boot Shield, desbloquear, cambiar idioma y verificar persistencia dentro del vault.
3. Activar Boot Shield con idioma de desbloqueo chino y reiniciar.
4. Verificar que LockScreen aparece en chino antes de descifrar el vault.
5. Introducir cajas con numerales chinos y comprobar que normalizan al mismo entero canónico.
6. Introducir frase china exacta y comprobar acceso al dashboard.
7. Verificar que una frase traducida o normalizada de forma distinta no desbloquea.
8. Configurar símbolo de contraseña en árabe, chino, griego o devanágari.
9. Cifrar texto con contraseña delante del símbolo.
10. Cifrar texto con contraseña detrás del símbolo.
11. Descifrar y verificar que el diálogo muestra el patrón traducido.
12. Crear plantilla con caracteres de varios idiomas.
13. Verificar que ningún texto visible queda en castellano cuando el idioma activo es inglés.

---
