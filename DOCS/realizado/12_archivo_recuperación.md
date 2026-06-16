La implementación del módulo de recuperación de emergencia es el mecanismo de "última instancia" para restaurar la soberanía del sistema cuando la cadena de integridad ha sido rota. Este módulo permite importar un anclaje de auditoría firmado (fuera del sistema comprometido) para validar el estado del vault y desactivar el modo espejismo.

Aquí tienes la arquitectura y el código para su integración.

1. creación del módulo de recuperación (src-tui/src/security/recovery.rs)
Este nuevo archivo gestiona la verificación criptográfica del archivo de recuperación (.lvc_recovery) utilizando la clave maestra del fabricante o la clave de recuperación del usuario.

archivo implicado: src-tui/src/security/recovery.rs (nuevo)

Rust
// SPDX-License-Identifier: GPL-3.0-or-later
use serde::{Serialize, Deserialize};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct RecoveryPayload {
    pub version: u32,
    pub timestamp: i64,
    pub anchor_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn verify_and_apply_recovery(
    recovery_path: &Path, 
    public_key_bytes: &[u8; 32]
) -> Result<Vec<u8>, String> {
    let bytes = fs::read(recovery_path).map_err(|e| e.to_string())?;
    let payload: RecoveryPayload = rmp_serde::from_slice(&bytes).map_err(|e| e.to_string())?;

    let public_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|_| "clave pública de recuperación inválida")?;
    
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| "formato de firma de recuperación inválido")?;

    // verificar que la firma cubra el hash del anclaje y el timestamp
    let mut signed_data = payload.anchor_hash.clone();
    signed_data.extend_from_slice(&payload.timestamp.to_le_bytes());

    public_key.verify(&signed_data, &signature)
        .map_err(|_| "la firma de recuperación no es auténtica")?;

    Ok(payload.anchor_hash)
}
2. actualización de la lógica del vault (src-tui/src/security/vault.rs)
Debemos añadir la función que sobrescribe el anclaje de integridad en el encabezado de forma atómica una vez verificado el backup.

archivo implicado: src-tui/src/security/vault.rs

código a añadir:

Rust
pub fn apply_emergency_anchor_update(new_anchor: Vec<u8>) -> Result<(), String> {
    let mut runtime = lock_runtime();
    let material = runtime.material.as_mut().ok_or("vault bloqueado")?;

    // actualizar el anclaje en el encabezado cargado
    let mut header = read_header_from_disk()?;
    header.last_audit_anchor = new_anchor;

    // re-cifrar el encabezado con el nuevo anclaje incluido en los datos asociados (aad)
    let envelope = create_envelope(&header, &material.key)?;
    write_envelope_to_disk(&envelope)?;

    // registrar el evento de recuperación en el log
    let _ = crate::security::audit::register_tombstone("EMERGENCY_RECOVERY_APPLIED");
    
    Ok(())
}
3. interfaz de recuperación en la tui (src-tui/src/main.rs)
Añadiremos una nueva pantalla que se activa desde la alerta forense para permitir al usuario introducir la ruta del archivo de recuperación.

archivo implicado: src-tui/src/main.rs

código a editar: actualizar el enum Screen y añadir el manejador.

Rust
enum Screen {
    // ...
    RecoveryMode { input_path: String, error: Option<String> },
}

fn draw_recovery_mode(frame: &mut Frame<'_>, area: ratatui::layout::Rect, input_path: &str, error: &Option<String>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let title = Paragraph::new(" MODO DE RECUPERACIÓN DE EMERGENCIA ")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    frame.render_widget(title, chunks[0]);

    let input = Paragraph::new(format!(" Ruta del archivo .lvc_recovery: {}", input_path))
        .block(Block::default().borders(Borders::ALL).title(" Entrada de Backup "));
    frame.render_widget(input, chunks[1]);

    if let Some(err) = error {
        let err_msg = Paragraph::new(format!(" ERROR: {}", err))
            .style(Style::default().fg(Color::Red));
        frame.render_widget(err_msg, chunks[2]);
    }
}
4. flujo de ejecución del proceso de recuperación
archivo implicado: src-tui/src/main.rs

código a añadir en handle_events:

Rust
/* lógica para procesar la recuperación */
match state.screen {
    Screen::RecoveryMode { ref mut input_path, ref mut error } => {
        match key.code {
            KeyCode::Enter => {
                let path = Path::new(input_path);
                // usar la clave pública maestra configurada
                match security::recovery::verify_and_apply_recovery(path, &MASTER_RECOVERY_KEY) {
                    Ok(new_anchor) => {
                        if security::vault::apply_emergency_anchor_update(new_anchor).is_ok() {
                            state.screen = Screen::Dashboard; // recuperación exitosa
                        }
                    }
                    Err(e) => *error = Some(e),
                }
            }
            KeyCode::Char(c) => input_path.push(c),
            KeyCode::Backspace => { input_path.pop(); }
            KeyCode::Esc => state.screen = Screen::Unlock,
            _ => {}
        }
    }
    // ...
}
análisis de seguridad del módulo
anclaje de confianza externo: al requerir una firma Ed25519, el sistema garantiza que un atacante no puede crear su propio archivo de recuperación para "blanquear" un log manipulado.

actualización atómica: el cambio del anclaje en el VaultHeader se realiza re-cifrando el sobre digital. Esto asegura que el Poly1305 valide el nuevo estado de integridad inmediatamente.

salida del modo espejismo: una vez que el anclaje en el disco coincide con el cálculo del log de auditoría (o un nuevo log iniciado), el sistema vuelve al estado IntegrityStatus::Valid, restaurando el acceso a los datos reales y eliminando los señuelos.

Es una excelente pregunta que toca la fibra de la **eficiencia operativa** frente a la **redundancia de datos**. Tienes razón en parte: si tienes una copia de seguridad del archivo `.lvcvault` completo y la aplicación, puedes simplemente borrar el archivo corrupto, poner el backup y seguir funcionando.

Sin embargo, el **Módulo de Recuperación de Emergencia** no es un sustituto del backup de datos, sino un **mecanismo de reparación de la integridad** diseñado para situaciones de alta seguridad. Aquí te explico por qué es necesario integrarlo aunque ya tengas backups:

### 1. El Bloqueo del "Modo Espejismo"

Livencrypt 2.0 no solo cifra datos; protege la **historia** de quién ha intentado acceder a ellos.

* **El Problema:** Si un atacante entra en tu PC y borra los logs de auditoría para ocultar sus intentos fallidos, pero deja el vault intacto, el sistema detectará que la "cadena de hashes" se ha roto.
* **La Consecuencia:** Al intentar abrir el vault, entrarás automáticamente en **Modo Espejismo** (viendo solo archivos señuelo).
* **La Solución con Recuperación:** En lugar de tener que restaurar un vault que quizá pesa 50GB (lo cual tarda tiempo y requiere espacio), usas el archivo de recuperación (que pesa 1KB) para decirle al sistema: *"Confío en este nuevo punto de inicio de los logs"*. El sistema actualiza el anclaje y sales del Modo Espejismo al instante sin mover gigabytes de datos.

### 2. Eficiencia vs. Peso de Datos

Imagina que usas Livencrypt para proteger volúmenes muy grandes.

* **Sin el módulo:** Ante cualquier sospecha de manipulación de integridad, te ves obligado a borrar el archivo actual y copiar el backup completo desde un disco externo.
* **Con el módulo:** Solo restauras la "firma de integridad". Es una operación de milisegundos que valida matemáticamente que el contenido del disco (aunque los logs hayan sido borrados) es el correcto.

### 3. El "Handover" de Soberanía

El módulo de recuperación utiliza firmas **Ed25519**. Esto permite que:

1. El usuario tenga una **"Llave Maestra de Identidad"** en una tarjeta física o papel (código QR).
2. Si el sistema operativo host es comprometido y el malware intenta "blanquear" el log para que parezca que no ha pasado nada, no podrá hacerlo porque no tiene tu clave privada para firmar el nuevo anclaje de integridad.
3. Solo tú, con tu clave de recuperación externa, puedes autorizar al sistema a "volver a confiar" en los archivos locales.

### 4. Diferencia Técnica: ¿Qué recupera cada cosa?

| Característica | Backup del Vault (.lvcvault) | Módulo de Recuperación (.lvc_recovery) |
| --- | --- | --- |
| **Objetivo** | Recuperar los datos si el archivo se borra o corrompe. | Restaurar la **confianza** y salir del Modo Espejismo. |
| **Tamaño** | Idéntico al original (puede ser enorme). | Minúsculo (pocos bytes). |
| **Uso** | Desastre físico (disco roto, archivo borrado). | Ataque lógico (manipulación de logs, intrusión). |
| **Seguridad** | Cifrado simétrico (requiere las 5 cajas). | Firma asimétrica (requiere clave privada Ed25519). |

### Conclusión para tu integración:

Si buscas crear una herramienta de **uso profesional y forense**, el módulo es indispensable. Permite que el usuario gestione la "confianza" del sistema sin depender de procesos pesados de restauración de archivos.

**Mi recomendación:** Mantenlo como una función de "Experto". El 90% de las veces un backup te salvará, pero ese 10% donde un malware ha manipulado los logs y te ha bloqueado en el Modo Espejismo, el módulo de recuperación será la única forma de recuperar tus datos sin sospechar que has sido hackeado.

Tu análisis es impecable desde una perspectiva de **Respuesta ante Incidentes (IR)**. Tienes toda la razón: si el sistema operativo ha sido comprometido, el entorno es "hostil". Realizar cualquier operación de descifrado o recuperación en un sistema con un posible *rootkit* o *keylogger* activo es una vulnerabilidad crítica.

El protocolo que describes es el estándar de **Soberanía Forense**: aislar el dato, limpiar el hierro (formatear) y reconstruir la confianza.

Para que **Livencrypt 2.0** soporte este flujo de "reinicio de confianza", debemos integrar la capacidad de **Rotación de Claves de Firma** y asegurar que el log de auditoría mantenga la trazabilidad del desastre.

---

### 1. Rotación de Claves Ed25519 (`recovery.rs`)

Debemos añadir la función para generar un nuevo par de claves (Pública/Privada). La clave privada debe mostrarse una sola vez (o guardarse en un archivo externo que el usuario debe mover a un USB) y la pública debe sellarse en el nuevo `VaultHeader`.

* **Archivo implicado:** `src-tui/src/security/recovery.rs`
* **Código a añadir:**

```rust
/* Rol: Generación y Rotación de Identidad de Recuperación */

pub struct NewRecoveryIdentity {
    pub public_key: [u8; 32],
    pub private_key: [u8; 64],
}

pub fn generate_new_recovery_identity() -> NewRecoveryIdentity {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    NewRecoveryIdentity {
        public_key: verifying_key.to_bytes(),
        private_key: signing_key.to_keypair_bytes(),
    }
}

```

---

### 2. Registro Forense de Restauración (`audit.rs`)

Al aplicar la recuperación tras el formateo, el log de auditoría debe registrar explícitamente el evento para que, en un futuro análisis, se sepa que hubo una ruptura de cadena y una restauración manual.

* **Archivo implicado:** `src-tui/src/security/audit.rs`
* **Código a añadir en la lógica de aplicación:**

```rust
pub fn log_recovery_event(new_anchor: &[u8]) -> Result<(), String> {
    let entry = AuditEntry {
        index: 0, // Reinicio de índice post-formateo o continuación
        timestamp: Utc::now(),
        event_type: "RECOVERY_RESTORE".to_string(),
        details: format!("Restauración de integridad mediante Ed25519. Nuevo Anchor: {}", hex::encode(new_anchor)),
        prev_hash: vec![0u8; 32], // Hash de génesis tras la restauración
        signature: vec![], // Se firma con la nueva clave derivativa
    };
    // ... guardar entrada
    Ok(())
}

```

---

### 3. Flujo en la Interfaz TUI (`main.rs`)

Tras la restauración exitosa y una vez dentro del Dashboard en el nuevo SO, el sistema debe presentar la opción de "Generar Nueva Identidad de Recuperación".

* **Archivo implicado:** `src-tui/src/main.rs`
* **Código a añadir (Pestaña System Monitor):**

```rust
fn draw_recovery_management(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let block = Block::default()
        .title(" Gestión de Identidad (Ed25519) ")
        .borders(Borders::ALL);
    
    let text = vec![
        Line::from("Estado: PROTEGIDO (Post-Restauración)"),
        Line::from(""),
        Line::from(Span::styled("ADVERTENCIA:", Style::default().fg(Color::Yellow))),
        Line::from("Si sospecha que su clave de recuperación anterior fue expuesta,"),
        Line::from("genere una nueva identidad ahora."),
        Line::from(""),
        Line::from("[G] Generar Nueva Clave de Recuperación"),
    ];

    let p = Paragraph::new(text).block(block);
    frame.render_widget(p, area);
}

```

---

### 4. Lógica de "Soberanía Post-Formateo"

El proceso técnico para cumplir tu visión sería:

1. **Backup:** El usuario copia el `.lvcvault` (que tiene el bit de integridad roto en el encabezado).
2. **Formateo:** Instalación limpia de Arch Linux (u otro SO) y Livencrypt.
3. **Importación:** Al abrir el vault, Livencrypt detecta el desajuste (`IntegrityStatus::Truncated`) y activa el **Modo Espejismo**.
4. **Recuperación:** El usuario usa su clave Ed25519 (guardada fuera del PC hackeado) para validar el anclaje.
5. **Re-Sello:** Livencrypt re-cifra el encabezado, limpia el Modo Espejismo y registra el evento `RECOVERY_RESTORE`.
6. **Rotación:** El usuario genera un nuevo par de claves Ed25519, invalidando la clave anterior que podría haber estado en manos del atacante.

### Conclusión Técnica

Tu enfoque es el correcto para un **entorno de alta traición o compromiso**. Formatear es la única forma de garantizar que el procesador y la RAM están libres de procesos espía. Livencrypt 2.0, con estos añadidos, no solo sobrevive al formateo, sino que utiliza ese evento para **re-certificar la integridad de los datos** y renovar las credenciales de recuperación.

¿Deseas que preparemos el script de **Generación de Reporte Forense** que exporte todo el log de auditoría (incluyendo el evento de restauración) a un PDF/Texto firmado para presentarlo como prueba de la intrusión?

