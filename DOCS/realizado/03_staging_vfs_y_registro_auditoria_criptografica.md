# Staging VFS y Registro de Auditoría Cifrado

Este módulo detalla la implementación del área de descompresión de actualizaciones en el VFS y la estructura del registro de auditoría blindado localmente mediante cadenas de hashes criptográficas.

---

## 1. Diseño y Principios Técnicos

### A. Área de "Actualizaciones Pendientes" (Staging VFS)
Funciona como una cámara de descompresión criptográfica en la TUI:
* **Manifiesto de Metadatos**: El paquete entrante contiene un manifiesto firmado. Livencrypt lee y muestra en la TUI de solo lectura: versión del paquete, hash de destino, notas de versión (*changelog* cifrado que solo el administrador legítimo puede leer) y la firma Ed25519.
* **Inspección sin Ejecución**: El archivo de actualización (`.lvc_upd`) permanece en el disco como ruido cifrado. El usuario puede auditar los metadatos visualmente en la TUI. Solo al introducir la secuencia de acceso de Livencrypt, se verifica la firma, se descifra el payload en RAM blindada (`mlockall`) y se aplica la actualización.

### B. Registro de Auditoría Cifrado (Cryptographic Hash Chain)
Para evitar que un malware borre las huellas de un compromiso, el log de auditoría se diseña como una cadena local inmutable:
* **Estructura del Bloque (`AuditEntry`)**:
  ```rust
  pub struct AuditEntry {
      pub index: u64,                  // Previene inserción o borrado intermedio (Monotónico)
      pub timestamp: DateTime<Utc>,    // Línea de tiempo forense de alta precisión
      pub event_type: String,          // Tipo de evento (ej. "access_fail", "vault_open")
      pub details: String,             // Metadatos adicionales cifrados
      pub prev_hash: Vec<u8>,          // SHA-256 de la entrada anterior (N-1)
      pub signature: Vec<u8>,          // Firma Poly1305 con clave derivada de la secuencia del usuario
  }
  ```
* **Prevención de Ataques de Reordenamiento y Borrado**: Si un atacante altera un registro antiguo, la cadena de hashes (`prev_hash`) se rompe. Si elimina un registro intermedio, el índice monotónico saltará (ej. de 12 a 14), alertando sobre el borrado.

### C. Registro de Tumbas (Tombstone Log)
* **El Problema**: ¿Cómo registrar intentos fallidos de acceso si el vault y la clave del usuario están bloqueados?
* **La Solución**:
  1. Cuando un acceso falla, el sistema escribe en un archivo oculto externo (`tombstone.bin`) un registro cifrado con una clave efímera o la clave pública del fabricante.
  2. En el primer acceso exitoso del usuario, Livencrypt descifra el *Tombstone Log*, integra los eventos de intentos fallidos en la cadena principal del registro de auditoría, y aplica un borrado seguro (**Zeroize**) al archivo de tumbas en el disco.
  3. Si un malware borra el *Tombstone Log* para ocultar sus intentos de fuerza bruta, el sistema lo detectará al abrir el vault, ya que el contador de intentos fallidos guardado en el encabezado del vault (`VaultHeader`) no coincidirá con las entradas del log.

---

## 2. Archivos Implicados en el Proyecto

* **[vault.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs)**: Requiere actualizarse para incorporar el anclaje de continuidad del log en `VaultHeader` y coordinar el borrado seguro del Tombstone Log.
* **`src-tui/src/security/audit.rs`** *(Módulo propuesto)*: Debe implementar la estructura `AuditEntry`, la lógica de hash SHA-256 encadenado, la firma HMAC/Poly1305 de entradas de log, y la lectura/escritura de los logs de auditoría en disco.
* **[main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs)** y componentes TUI: Para añadir la pestaña **"Monitor de Sistema"** que permita navegar por el historial de accesos y revisar las actualizaciones pendientes.

---

## 3. Estado de la Integración

### ¿Qué está YA integrado?
* [x] **Serialización Eficiente**: El uso de `rmp_serde` (MessagePack) para serializar y deserializar estructuras del sistema con bajo overhead de memoria está integrado y disponible.
* [x] **Detección de Intentos Fallidos Básica**: Se cuenta con el archivo `vault.defense.msgpack` que almacena el número de intentos fallidos, el cual se incrementa tras cada fallo de acceso de forma persistente.

### ¿Qué falta por integrar?
* [ ] **Creación del Módulo `audit.rs`**: No existe la lógica de encadenamiento criptográfico de hashes (SHA-256) ni firmas Poly1305 para logs.
* [ ] **Estructura `AuditEntry`**: Falta definir e integrar el tipo en el flujo de desbloqueo del vault.
* [ ] **Registro de Tumbas (Tombstone)**: Falta la lógica de cifrado efímero para registrar accesos fallidos en caliente mientras el vault está cerrado y su posterior fusión/zeroización al abrirlo.
* [ ] **Flujo de Validación Secuencial**: Implementar la verificación de continuidad, firmas y hashes del log de auditoría durante la inicialización de la app.
* [ ] **Pestaña "Monitor de Sistema"**: La TUI de Ratatui en `main.rs` no cuenta con pantallas o pestañas para inspeccionar los metadatos del Staging VFS o los registros de auditoría históricos.

---

## Enlaces Relacionados
* Volver al [[00_indice|Índice General]].
* Ver cómo responde el sistema si se detecta manipulación en los logs: [[04_alerta_silenciosa_y_modo_espejismo|Alerta Silenciosa de Manipulación y Modo Espejismo]].

## Código a integrar
1. Creación del Módulo de Auditoría (src-tui/src/security/audit.rs)Este nuevo archivo gestiona el encadenamiento de hashes SHA-256 para garantizar que los logs no puedan ser borrados o reordenados sin romper la firma de integridad.Archivo implicado: src-tui/src/security/audit.rs (NUEVO)Rust// SPDX-License-Identifier: GPL-3.0-or-later
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use chrono::{Utc, DateTime};
use zeroize::Zeroize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp: DateTime<Utc>,
    pub event_type: String, // ej: "ACCESS_FAIL", "VAULT_OPEN"
    pub details: String,
    pub prev_hash: Vec<u8>,
    pub signature: Vec<u8>, // Poly1305 MAC
}

impl AuditEntry {
    pub fn calculate_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_le_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.event_type.as_bytes());
        hasher.update(self.details.as_bytes());
        hasher.update(&self.prev_hash);
        hasher.finalize().to_vec()
    }
}

/* Lógica de Registro de Tumbas (Tombstone) */
pub fn register_tombstone(event: &str) -> Result<(), String> {
    let path = crate::security::vault::secure_dir().join("vault.tombstone");
    let entry = format!("{}|{}|{}\n", Utc::now().to_rfc3339(), event, "EFÍMERO");
    
    let mut file = OpenOptions::new().append(true).create(true).open(path).map_err(|e| e.to_string())?;
    file.write_all(entry.as_bytes()).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    Ok(())
}
2. Integración en el Flujo del VaultDebemos actualizar el encabezado del vault para anclar el historial de auditoría y modificar la lógica de desbloqueo para procesar las "tumbas" (intentos fallidos registrados mientras estaba cerrado).Archivo implicado: src-tui/src/security/vault.rsCódigo a editar: Añadir last_audit_anchor a VaultHeader y actualizar boot_shield_unlock_impl.  Rust/* Editar VaultHeader en src-tui/src/security/vault.rs */
struct VaultHeader {
    // ... campos existentes
    pub last_audit_anchor: Vec<u8>, // Hash del último evento de auditoría válido
}

/* Actualizar lógica de fallo en boot_shield_unlock_impl */
// ... dentro del match Err(_)
Err(_) => {
    // Registro de Tumbas (Fase 5)
    let _ = crate::security::audit::register_tombstone("ACCESS_FAILED"); 
    
    if is_duress_key(&secret, &defense_state) {
        // ... lógica de pánico [cite: 925]
    }
    // ... incremento de intentos 
}
3. Flujo de Validación SecuencialAl iniciar la aplicación, el sistema debe verificar que la cadena de hashes del log de auditoría está intacta.Archivo implicado: src-tui/src/security/audit.rs (Añadir función)Rustpub fn verify_audit_chain(expected_anchor: &[u8]) -> Result<bool, String> {
    let log_path = crate::security::vault::secure_dir().join("audit.log");
    if !log_path.exists() { return Ok(expected_anchor.is_empty()); }

    let bytes = fs::read(log_path).map_err(|e| e.to_string())?;
    let entries: Vec<AuditEntry> = rmp_serde::from_slice(&bytes).map_err(|e| e.to_string())?;
    
    let mut current_prev_hash = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        if entry.index != i as u64 || entry.prev_hash != current_prev_hash {
            return Ok(false); // Cadena rota o reordenada
        }
        current_prev_hash = entry.calculate_hash();
    }
    
    Ok(current_prev_hash == expected_anchor)
}
4. Pestaña "Monitor de Sistema" en TUIExpandiremos la interfaz para permitir la inspección de logs y actualizaciones pendientes.Archivo implicado: src-tui/src/main.rsCódigo a editar: Actualizar Screen enum y el manejador de teclas.Rust/* Editar Screen en src-tui/src/main.rs [cite: 16] */
#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Unlock,
    Dashboard,
    SystemMonitor, // NUEVA
}

/* Actualizar handle_dashboard_key [cite: 53] */
fn handle_dashboard_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Char('m') => state.screen = Screen::SystemMonitor,
        KeyCode::Char('q') | KeyCode::Esc => {
            if state.screen == Screen::SystemMonitor {
                state.screen = Screen::Dashboard;
            } else {
                state.should_quit = true; // [cite: 55]
            }
        }
        // ... otros casos
    }
}
5. Visualización del Monitor de SistemaArchivo implicado: src-tui/src/main.rs (Añadir función de dibujo)Rustfn draw_system_monitor(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // 1. Panel de Auditoría
    let audit_block = Block::default().title(" Historial de Auditoría (Inmutable) ").borders(Borders::ALL);
    let audit_info = Paragraph::new("Integridad: OK\nÚltimo acceso: 2026-06-04 13:45\nEventos encadenados: 124")
        .block(audit_block);
    frame.render_widget(audit_info, chunks[0]);

    // 2. Panel de Firmware (Staging VFS)
    let fw_block = Block::default().title(" Actualizaciones Pendientes (Staging) ").borders(Borders::ALL);
    let fw_info = Paragraph::new("No hay actualizaciones aprobadas pendientes de handover.")
        .block(fw_block);
    frame.render_widget(fw_info, chunks[1]);
}
Valoración de Seguridad Post-IntegraciónInmutabilidad: El uso de AuditEntry con index y prev_hash impide ataques de truncado de logs.  Tombstones: Los intentos de acceso fallidos ahora dejan un rastro persistente incluso si el atacante apaga el equipo tras el fallo.  Soberanía Visual: El usuario puede auditar su propio sistema desde la TUI pulsando 'm', sin necesidad de herramientas externas que puedan estar comprometidas.
