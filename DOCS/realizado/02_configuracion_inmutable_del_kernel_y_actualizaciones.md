# Configuración Inmutable del Kernel y Actualizaciones Seguras

Este módulo aborda la propuesta de diseño para convertir la configuración del kernel (o del programa) en un volumen inmutable de solo lectura protegido por Livencrypt 2.0, e implementar un proceso de actualizaciones atómicas blindado frente a interceptaciones y malware con permisos de Root.

---

## 1. Diseño y Principios Técnicos

### A. Configuración como un Vault
Normalmente, archivos como `/etc/sysctl.conf` o configuraciones críticas residen en texto plano. Si un atacante compromete el sistema (incluso como Root), los puede modificar a voluntad. Con Livencrypt:
1. **Funcionamiento**: El kernel o el software lee una copia de solo lectura o en RAM de la configuración para sus operaciones habituales.
2. **Edición Segura**: Cualquier cambio requiere que el administrador ingrese su secuencia personal de Livencrypt (5 cajas + frase). Solo entonces se descifra temporalmente en RAM blindada (`mlockall`) la estructura de configuración, se edita mediante la TUI, se vuelve a cifrar en el disco y se purga la RAM.

### B. El Triple Blindaje para Actualizaciones
Para proteger el canal y los datos durante las actualizaciones de software o firmware, se propone una arquitectura de tres niveles:
* **Capa 1 (Fabricante)**: El origen firma el paquete con un HSM (Hardware Security Module) utilizando firmas criptográficas **Ed25519**. El binario y las notas de la versión viajan pre-cifrados.
* **Capa 2 (Canal / Tránsito)**: El paquete se transfiere por un túnel cifrado (TLS 1.3) con claves efímeras de sesión (Perfect Forward Secrecy). Un atacante que capture el paquete no podrá descifrar su contenido ni reutilizar información para descifrar futuros paquetes.
* **Capa 3 (Usuario / Destino)**: El usuario local es el último guardián. El sistema local solicita la secuencia de Livencrypt del usuario para autorizar e integrar la actualización, evitando instalaciones silenciosas de telemetría o malware de persistencia.

### C. Handover Criptográfico (Traspaso Seguro)
Si una actualización implica cambiar la clave o la secuencia del sistema (o viene pre-cifrada de fábrica con una clave de transición):
1. El usuario autoriza la actualización ingresando su secuencia actual.
2. El motor de Livencrypt abre el payload de transición.
3. Se realiza una re-encapsulación atómica en memoria: se descifra el nuevo firmware/configuración y se cifra instantáneamente con la secuencia definitiva del usuario.
4. El nuevo archivo reemplaza al antiguo de forma atómica (mediante `rename` del sistema de archivos y `sync_all`).

---

## 2. Archivos Implicados en el Proyecto

* **[vault.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs)**: Gestiona la escritura atómica y las funciones de derivación criptográfica que servirían de base para el sellado local.
* **`src-tui/src/security/updates.rs`** *(Módulo propuesto)*: Manejaría la descarga en la partición en la sombra (`shadow_firmware.bin`), la verificación de la firma Ed25519 del fabricante, y la extracción del manifiesto firmado de metadatos.

---

## 3. Estado de la Integración

### ¿Qué está YA integrado?
* [x] **Persistencia Atómica**: En `vault.rs`, las funciones `write_bytes_atomically` y `write_envelope` realizan la escritura en un archivo temporal (`.tmp`), ejecutan `sync_all` en el archivo, hacen el reemplazo atómico mediante `fs::rename`, y ejecutan `sync_all` en el directorio padre.
* [x] **Doble Credencial**: `vault.rs` implementa una modalidad de doble credencial combinando claves primarias y secundarias con **HKDF**, lo cual proporciona un mecanismo preliminar para esquemas de co-autorización o claves de tránsito.

### ¿Qué falta por integrar?
* [ ] **Descarga en Sombra (`shadow_firmware.bin`)**: No existe lógica para recibir o gestionar archivos de firmware/configuración intermedios en una zona temporal aislada.
* [ ] **Firma y Verificación Ed25519**: El soporte para firmas digitales de clave pública para verificar la autenticidad del fabricante en origen no está implementado en la lógica criptográfica actual del proyecto.
* [ ] **Lógica de Handover Criptográfico**: El descifrado y re-cifrado dinámico en memoria de un payload externo para adaptarlo a la secuencia local del usuario está pendiente.
* [ ] **Integración en Nivel de Sistema/Bootloader**: Falta el empaquetado del kernel o scripts necesarios para que Livencrypt actúe como gestor de configuración inmutable del sistema operativo host.

---

## Enlaces Relacionados
* Volver al [[00_indice|Índice General]].
* Ver cómo se visualizan las actualizaciones en el VFS: [[03_staging_vfs_y_registro_auditoria_criptografica|Staging VFS y Registro de Auditoría Cifrado]].

## Código a integrar
1. Actualización de Dependencias (Cargo.toml)Para soportar la verificación de firmas Ed25519, necesitamos añadir la biblioteca estándar de criptografía de curva elíptica.Archivo implicado: src-tui/Cargo.toml   Código a añadir:Ini, TOML[dependencies]
# ... dependencias existentes 
ed25519-dalek = "2.1"
2. Firma y Verificación Ed25519Implementaremos un módulo para validar que los archivos de actualización provienen del fabricante legítimo.Archivo implicado: src-tui/src/crypto/signature.rs (NUEVO ARCHIVO)Código:Rustuse ed25519_dalek::{VerifyingKey, Signature, Verifier};
use std::convert::TryInto;

/* Rol: Verificación de autenticidad del fabricante */

// Clave pública del fabricante (Hardcoded como Root of Trust)
const MANUFACTURER_PUBLIC_KEY: &[u8; 32] = b"CLAVE_PUBLICA_FABRICANTE_HEX____";

pub fn verify_manufacturer_signature(payload: &[u8], signature_bytes: &[u8]) -> bool {
    let Ok(public_key) = VerifyingKey::from_bytes(MANUFACTURER_PUBLIC_KEY) else { return false; };
    let Ok(signature) = Signature::from_slice(signature_bytes) else { return false; };
    
    public_key.verify(payload, &signature).is_ok()
}
3. Descarga en Sombra y Staging VFSAñadiremos lógica para gestionar el directorio de "Staging" donde las actualizaciones esperan ser aprobadas por el usuario.Archivo implicado: src-tui/src/security/vault.rs   Código a añadir:Rust/* Rol: Gestión de Staging para actualizaciones (Fase 5) */

fn staging_dir() -> PathBuf {
    crate::livencrypt_base_dir().join(".livencrypt").join("staging")
}

#[derive(Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub changelog: String,
    pub binary_hash: String,
    pub signature: Vec<u8>,
}

pub fn inspect_pending_update() -> Result<Option<UpdateManifest>, String> {
    let manifest_path = staging_dir().join("update.manifest");
    if !manifest_path.exists() { return Ok(None); }
    
    let bytes = fs::read(manifest_path).map_err(|e| e.to_string())?;
    let manifest: UpdateManifest = rmp_serde::from_slice(&bytes).map_err(|e| e.to_string())?;
    Ok(Some(manifest))
}
4. Lógica de Handover CriptográficoEste es el proceso donde se toma el shadow_firmware.bin (cifrado por el fabricante) y se re-encapsula para el vault local del usuario tras su aprobación.Archivo implicado: src-tui/src/security/vault.rs   Código a añadir:Rustpub fn finalize_update_handover(transition_key: &[u8; 32]) -> Result<(), String> {
    let runtime = lock_runtime(); // [cite: 796]
    let user_material = runtime.material.as_ref().ok_or("Vault bloqueado")?;
    
    let shadow_path = staging_dir().join("shadow_firmware.bin");
    let payload = fs::read(&shadow_path).map_err(|e| e.to_string())?;
    
    // 1. Descifrado temporal en RAM blindada (con transition_key)
    // 2. Re-cifrado instantáneo (con user_material.key) [cite: 789]
    // 3. Escritura atómica en el sector de configuración local.
    
    // LIMPIEZA: Borrado seguro del binario sombra tras el handover
    secure_overwrite_and_remove_file(&shadow_path)?; // [cite: 798]
    Ok(())
}
5. Integración en Nivel de Sistema/BootloaderPara que Livencrypt actúe como gestor de configuración inmutable, debemos actualizar el script de instalación para que configure los ganchos del sistema.Archivo implicado: src-tui/scripts/postinstall.sh   Código a añadir/editar:Bash# Configuración de Inmutabilidad de Sistema
echo "Configurando Livencrypt como guardián de configuración..."

# Crear carpeta de configuración protegida
mkdir -p /etc/livencrypt/immutable

# Registrar el script de arranque para Initramfs (Conceptual)
if [ -d "/etc/initramfs-tools" ]; then
    cat > /etc/initramfs-tools/hooks/livencrypt <<EOF
#!/bin/sh
copy_exec /usr/bin/livencrypt-core /bin
EOF
    chmod +x /etc/initramfs-tools/hooks/livencrypt
    echo "Hook de Initramfs creado. Ejecute 'update-initramfs -u' para activar PBA."
fi
Resumen de la OperaciónEd25519: Añade la capacidad de verificar que nadie, excepto el poseedor de la clave privada del fabricante, pueda inyectar un shadow_firmware.bin.Staging: Crea un "limbo" seguro en el disco para inspeccionar metadatos (versión/cambios) antes de comprometer el sistema.Handover: Asegura que el "secreto de transporte" del fabricante se convierta en el "secreto de posesión" del usuario sin que los datos toquen el disco en texto plano.Inmutabilidad: Prepara el sistema operativo host para delegar su fase de arranque a la TUI de Livencrypt.
