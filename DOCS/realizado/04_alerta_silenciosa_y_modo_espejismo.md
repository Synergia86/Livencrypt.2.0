# Alerta Silenciosa de Manipulación y Modo Espejismo

Este módulo describe la arquitectura técnica para responder a intrusiones de forma pasiva y asimétrica. Si un malware altera el registro de auditoría, el sistema entra en un estado degradado controlado (*Modo Espejismo*) y emite una señal esteganográfica sutil en lugar de un error ruidoso.

---

## 1. Diseño y Principios Técnicos

### A. El Anclaje de Continuidad
Para detectar si el log ha sido manipulado (truncado o borrado en el disco duro por el malware para borrar su rastro):
1. **Registro**: Cada vez que Livencrypt se cierra de forma segura, escribe el hash del último evento registrado (`last_audit_anchor`) en el encabezado cifrado del vault (`VaultHeader`).
2. **Verificación en el Arranque**: Al abrir el vault, se descifra el encabezado en RAM protegida y se calcula recursivamente el hash del archivo de logs en el disco.
3. **Decisión**: Si los hashes no coinciden, o si el archivo de log ha desaparecido, se activa el estado de **"Sistema Comprometido"** (`IntegrityStatus::Truncated` o `Deleted`).

### B. Alerta Silenciosa (Esteganografía Visual)
Mostrar una alerta de error directa revelaría al malware que ha sido descubierto, haciendo que intente otros vectores destructivos en caliente. En su lugar:
* **Alteración de Glifos**: Un pequeño carácter de la TUI (por ejemplo, un punto `.` o un carácter Unicode sutil en una esquina) cambia de forma, estilo o color (de verde a un tono casi idéntico pero técnicamente distinto). Solo el administrador sabe qué buscar.
* **Micro-Retrasos Calculados**: El sistema introduce retrasos de milisegundos artificiales en ciertas operaciones de navegación o descifrado. Para el atacante parece lag o lentitud ordinaria del sistema; para el usuario, es la alerta confirmada.
* **Logs Señuelo**: La TUI muestra un historial de auditoría falso o señuelo que no contiene las entradas borradas, induciendo al atacante a creer que su manipulación no dejó huellas perceptibles.

### C. El "Modo Espejismo" (Mirage Mode)
Si el estado de integridad es comprometido, el sistema aplica la contención:
* **Aislamiento de Claves**: Las claves reales de descifrado nunca se exponen al espacio de memoria activa. Se cargan claves falsas o contenedores de solo lectura con datos de configuración inofensivos.
* **Registro Paralelo**: Livencrypt crea un nuevo log de auditoría oculto en una ruta temporal aleatoria para registrar la actividad del atacante (por ejemplo, qué archivos intenta abrir o qué comandos ejecuta).
* **Mantenimiento de Negación Plausible**: Permite al usuario simular ante coacción que la información se ha corrompido o es inaccesible debido a un fallo lógico.

---

## 2. Archivos Implicados en el Proyecto

* **[vault.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs)**: Debe almacenar el `last_audit_anchor` en el `VaultHeader`, e implementar la función `check_audit_integrity` en la RAM blindada tras el descifrado inicial.
* **[main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs)**: El motor de Ratatui debe integrar las directivas de esteganografía visual (renderizado del glifo modificado, inyección de retardos mediante `std::thread::sleep` o temporizadores, y carga de la vista señuelo).

---

## 3. Estado de la Integración

### ¿Qué está YA integrado?
* [x] **Nada**: No existen alertas silenciosas, esteganografía visual, inyección de retardos por seguridad ni Modo Espejismo en el código de la TUI actual de `main.rs` ni en la lógica de `vault.rs`.

### ¿Qué falta por integrar?
* [ ] **Modificación de `VaultHeader`**: Añadir el campo `last_audit_anchor: Vec<u8>` en la estructura serializada y en la firma de datos asociados.
* [ ] **Función de Comprobación**: Implementar `check_audit_integrity` en `vault.rs` para retornar el estado de integridad:
  ```rust
  pub fn check_audit_integrity(header: &VaultHeader, log_path: &Path) -> IntegrityStatus
  ```
* [ ] **Mapeo de Glifos en Ratatui**: Configurar en el renderizado de la UI de `main.rs` el widget que cambia según el estado de integridad.
* [ ] **Inyección de Latencia Artificial**: Implementar la lógica que añade retardos dinámicos en los accesos cuando la integridad es inválida.
* [ ] **Contenedores Decoy (Señuelo)**: Crear plantillas y configuraciones señuelo para presentarlas en el VFS del Modo Espejismo si el log ha sido truncado.

---

## Enlaces Relacionados
* Volver al [[00_indice|Índice General]].
* Ver la consecuencia extrema ante la manipulación del log: [[05_cargador_sobre_digital_y_bit_de_suicidio|Cargador (Crypter/Loader) y Bit de Suicidio]].

## Código a integrar
1. Modificación de VaultHeader y Datos AsociadosDebemos anclar criptográficamente el estado del log de auditoría al encabezado del vault para detectar truncamientos.  Archivo implicado: src-tui/src/security/vault.rsCódigo a editar: Actualizar las estructuras VaultHeader, VaultAssociatedDataV3 y la función associated_data.Rust/* Editar en src-tui/src/security/vault.rs */

#[derive(Clone, Serialize, Deserialize)]
pub enum IntegrityStatus {
    Valid,
    Truncated,
    Deleted,
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultHeader {
    // ... campos existentes [cite: 786-787]
    pub vault_counter: u64,
    pub object_names: Vec<String>,
    #[serde(default)]
    pub last_audit_anchor: Vec<u8>, // NUEVO: Anclaje de auditoría
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultAssociatedDataV3 {
    // ... campos existentes [cite: 788]
    pub vault_counter: u64,
    pub object_names: Vec<String>,
    pub last_audit_anchor: Vec<u8>, // NUEVO: Incluido en el AAD para integridad Poly1305
}

// Actualizar en la función associated_data para incluir el anchor [cite: 834-836]
fn associated_data(header: &VaultHeader) -> Result<Vec<u8>, String> {
    if header.format_version >= FORMAT_VERSION {
        return rmp_serde::to_vec(&VaultAssociatedDataV3 {
            // ... mapeo de campos existentes
            last_audit_anchor: header.last_audit_anchor.clone(),
        }).map_err(|e| e.to_string());
    }
    // ... [cite: 837]
}
2. Implementación de check_audit_integrityEsta función compara el estado físico del log con el registro inmutable del encabezado.  Archivo implicado: src-tui/src/security/vault.rsCódigo a añadir:Rust/* Añadir a src-tui/src/security/vault.rs */

pub fn check_audit_integrity(header: &VaultHeader) -> IntegrityStatus {
    let log_path = secure_dir().join("audit.log");
    if !log_path.exists() {
        return if header.last_audit_anchor.is_empty() { IntegrityStatus::Valid } else { IntegrityStatus::Deleted };
    }

    // Nota: verify_audit_chain devuelve el hash del último eslabón válido
    match crate::security::audit::verify_audit_chain_and_get_last_hash() {
        Ok(current_hash) => {
            if current_hash == header.last_audit_anchor {
                IntegrityStatus::Valid
            } else {
                IntegrityStatus::Truncated
            }
        },
        Err(_) => IntegrityStatus::Truncated,
    }
}
3. Mapeo de Glifos e Inyección de Latencia (TUI)Implementaremos la Esteganografía Visual y el retardo artificial en el proceso de desbloqueo.  Archivo implicado: src-tui/src/main.rsCódigo a editar/añadir:Rust/* Editar en src-tui/src/main.rs */

// 1. Añadir campo de integridad al estado [cite: 16-17]
struct TuiState {
    // ...
    pub integrity: security::vault::IntegrityStatus,
}

// 2. Inyectar latencia en la función unlock [cite: 26-33]
fn unlock(&mut self) {
    // ... lógica de parseo existente
    
    // NUEVO: Latencia artificial si el sistema está bajo sospecha
    if !matches!(self.integrity, security::vault::IntegrityStatus::Valid) {
        std::thread::sleep(std::time::Duration::from_millis(1500));
    }

    // ... lógica de desbloqueo existente [cite: 27-33]
}

// 3. Glifo Esteganográfico en el renderizado [cite: 56-58]
fn draw_ui(frame: &mut Frame<'_>, state: &TuiState) {
    let area = frame.size();
    
    // Glifo sutil: el punto final del título cambia según integridad
    let glyph = match state.integrity {
        security::vault::IntegrityStatus::Valid => ".",
        _ => "·", // Carácter Unicode 0xb7 (sutilmente distinto)
    };

    let title = format!(" Livencrypt 2.0 TUI{} ", glyph);
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    frame.render_widget(block, area);
    // ...
}
4. Contenedores Decoy (Modo Espejismo)Cuando la integridad es nula, el sistema carga plantillas falsas para que el atacante no sospeche del bloqueo.  Archivo implicado: src-tui/src/security/vault.rsCódigo a editar: Modificar decrypt_payload.Rust/* Editar en src-tui/src/security/vault.rs */

fn decrypt_payload(...) -> Result<(...) , String> {
    // ... descifrado AEAD exitoso [cite: 855-857]

    let mut result = // ... lógica de extracción de payload existente [cite: 861]
    
    // NUEVO: Modo Espejismo (Mirage Mode)
    if !matches!(check_audit_integrity(&result.2), IntegrityStatus::Valid) {
        // Cargar plantillas señuelo en lugar de las reales
        result.0.templates = HashMap::from([
            ("Señuelo_1".to_string(), filelivencrypt_template()),
            ("Config_Old".to_string(), filelivencrypt_template()),
        ]);
        result.0.settings.insert("alert_active".into(), "true".into());
    }

    Ok(result)
}
Impacto en la Seguridad ForenseImposibilidad de Truncado: Al incluir last_audit_anchor en los datos asociados (AAD), un atacante no puede modificar el valor en el encabezado para que coincida con un log borrado sin romper el sello Poly1305 del vault.  Guerra Psicológica: La latencia de 1.5s y el cambio de glifo (. vs ·) informan al usuario legítimo del compromiso sin que un atacante inexperto note que el sistema ha detectado su intrusión.  Neutralización de Malware: El Malware que borre el log para ocultar su actividad terminará viendo un sistema "vacío" o con datos falsos (Decoys), protegiendo la información real que permanece cifrada y oculta tras la lógica del Modo Espejismo.  

