Prompt listo para pegar en Codex/OpenCode
Audita y corrige Livencrypt 2.0 en Rust con prioridad de seguridad. Trabaja sobre el árbol real del proyecto, no sobre los .txt concatenados. Aplica los cambios con parches pequeños, compilables y con tests.

OBJETIVOS OBLIGATORIOS:
1) El cifrado de archivos debe ser autenticado con AEAD.
2) Ningún cifrado de archivo puede usar &[0u8; 32] como semilla efectiva.
3) Las plantillas deben validar dimensiones, longitud, duplicados y nombre seguro antes de guardar, cargar o borrar.
4) La pasarela Web3/Native Messaging no puede usar /tmp/livencrypt.sock ni aceptar peers sin verificar.
5) loader.rs no puede ejecutar si falla el sandbox y debe manejar escrituras parciales.
6) postremove.sh no debe borrar datos de usuario/vaults por defecto.
7) Si el código Tauri legacy sigue incluido, no puede tener CSP null.

────────────────────────────────────────
PATCH 1 — src-tui/src/templates.rs
────────────────────────────────────────

Añade estas funciones y úsalas en save_template(), delete_template() y load_templates():

```rust
fn sanitize_template_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err("Nombre de plantilla vacío.".to_string());
    }

    if trimmed.len() > 64 {
        return Err("Nombre de plantilla demasiado largo; máximo 64 caracteres.".to_string());
    }

    if trimmed == "." || trimmed == ".." {
        return Err("Nombre de plantilla reservado.".to_string());
    }

    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err("Nombre de plantilla no puede contener separadores de ruta.".to_string());
    }

    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' '))
    {
        return Err(
            "Nombre de plantilla inválido; use letras, números, espacios, '_' o '-'.".to_string(),
        );
    }

    Ok(trimmed.to_string())
}

fn validate_template_strict(data: &TemplateData) -> Result<(), String> {
    if data.rows == 0 || data.cols == 0 {
        return Err("Plantilla inválida: rows y cols deben ser mayores que cero.".to_string());
    }

    let expected = data.rows as usize * data.cols as usize;
    if data.chars.len() != expected {
        return Err(format!(
            "Plantilla inválida: esperaba {} celdas y recibió {}.",
            expected,
            data.chars.len()
        ));
    }

    let mut seen = std::collections::HashSet::new();
    for value in &data.chars {
        let value = value.trim();
        if value.is_empty() {
            return Err("Plantilla inválida: contiene celdas vacías.".to_string());
        }
        if value.chars().count() > 2 {
            return Err(format!("Plantilla inválida: celda demasiado larga: {}", value));
        }
        if !seen.insert(value.to_string()) {
            return Err(format!("Plantilla inválida: símbolo duplicado: {}", value));
        }
    }

    Ok(())
}

Modifica save_template():

pub fn save_template(name: String, data: TemplateData) -> Result<(), String> {
    let safe_name = sanitize_template_name(&name)?;
    let data = normalize_template_data(data);
    validate_template_strict(&data)?;

    if crate::security::save_template_to_unlocked_vault(safe_name.clone(), data.clone())? {
        return Ok(());
    }

    let dir_path = templates_dir();
    fs::create_dir_all(&dir_path)
        .map_err(|e| format!("Error al crear directorio de plantillas: {}", e))?;

    let file_path = dir_path.join(format!("{}.msgpack", safe_name));
    let encoded_data = rmp_serde::to_vec(&data)
        .map_err(|e| format!("Error al serializar con MessagePack: {}", e))?;

    write_file_atomically_no_symlink(&file_path, &encoded_data)?;
    Ok(())
}

Añade helper atómico:

fn write_file_atomically_no_symlink(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Ruta sin padre: {:?}", path))?;

    fs::create_dir_all(parent).map_err(|e| e.to_string())?;

    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!("Destino rechazada por symlink: {:?}", path));
        }
    }

    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|v| v.to_str()).unwrap_or("template"),
        std::process::id()
    ));

    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| format!("No se pudo crear temporal {:?}: {}", tmp, e))?;

        use std::io::Write;
        file.write_all(bytes)
            .map_err(|e| format!("No se pudo escribir temporal {:?}: {}", tmp, e))?;
        file.sync_all()
            .map_err(|e| format!("No se pudo sincronizar temporal {:?}: {}", tmp, e))?;
    }

    fs::rename(&tmp, path)
        .map_err(|e| format!("No se pudo promover temporal {:?}: {}", tmp, e))?;

    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

Modifica delete_template():

pub fn delete_template(name: String) -> Result<(), String> {
    let safe_name = sanitize_template_name(&name)?;

    if crate::security::delete_template_from_unlocked_vault(&safe_name)? {
        return Ok(());
    }

    let file_path = templates_dir().join(format!("{}.msgpack", safe_name));

    if let Ok(meta) = fs::symlink_metadata(&file_path) {
        if meta.file_type().is_symlink() {
            return Err("No se elimina plantilla porque el destino es symlink.".to_string());
        }
    }

    if !file_path.exists() {
        return Err(format!("Plantilla '{}' no encontrada", safe_name));
    }

    fs::remove_file(&file_path).map_err(|e| format!("Error al eliminar: {}", e))?;
    Ok(())
}

En load_templates(), ignora cualquier fichero cuyo stem no pase sanitize_template_name() o cuyo contenido no pase validate_template_strict().

Añade tests:

rechaza "../evil"
rechaza "a/b"
rechaza rows=0
rechaza cols=0
rechaza símbolos duplicados
guarda y carga una plantilla válida

────────────────────────────────────────
PATCH 2 — src-tui/src/lib.rs
────────────────────────────────────────

Eliminar el uso efectivo de &[0u8; 32] como clave de archivo.

Cambia las funciones públicas antiguas para que no sean la ruta segura por defecto:

pub fn cipher_file(
    _input_path: &Path,
    _output_path: &Path,
    _referencia: &str,
    _template_name: &str,
    _cajas: [i64; 5],
) -> Result<(), String> {
    Err("cipher_file legacy bloqueado: use cipher_file_with_secret() con clave de archivo.".into())
}

pub fn decipher_file(
    _input_path: &Path,
    _output_path: &Path,
    _referencia: &str,
    _is_txt_output: bool,
    _template_name: &str,
    _cajas: [i64; 5],
) -> Result<(), String> {
    Err("decipher_file legacy bloqueado: use decipher_file_with_secret() con clave de archivo.".into())
}

Añade nuevas funciones:

pub fn cipher_file_with_secret(
    input_path: &Path,
    output_path: &Path,
    referencia: &str,
    template_name: &str,
    cajas: [i64; 5],
    file_secret: &str,
) -> Result<(), String> {
    let template = resolve_template(template_name)?;
    FileCipher::encrypt_file_authenticated(
        input_path,
        output_path,
        referencia,
        &template,
        cajas,
        file_secret,
    )
}

pub fn decipher_file_with_secret(
    input_path: &Path,
    output_path: &Path,
    referencia: &str,
    is_txt_output: bool,
    template_name: &str,
    cajas: [i64; 5],
    file_secret: &str,
) -> Result<(), String> {
    let template = resolve_template(template_name)?;
    FileCipher::decrypt_file_authenticated(
        input_path,
        output_path,
        referencia,
        is_txt_output,
        &template,
        cajas,
        file_secret,
    )
}

Actualizar la TUI para pedir clave/frase de archivo antes de cifrar/descifrar. No reutilizar silenciosamente la frase del vault salvo que el usuario lo confirme explícitamente.

────────────────────────────────────────
PATCH 3 — src-tui/src/crypto/file_cipher.rs
────────────────────────────────────────

Añade cifrado autenticado con Argon2id + XChaCha20Poly1305. Mantén el algoritmo posicional como codec interno si quieres conservar compatibilidad estética, pero el contenedor final debe estar autenticado.

Añade imports:

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

Añade estructuras:

const FILE_V2_MAGIC: [u8; 8] = *b"LVCF2\0\0\0";

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct FileKdfParams {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl Default for FileKdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id-v19".to_string(),
            memory_kib: 128 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct FileV2Header {
    magic: [u8; 8],
    version: u16,
    kdf: FileKdfParams,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    template_sha256: Vec<u8>,
    cajas_sha256: Vec<u8>,
    referencia_sha256: Vec<u8>,
    is_txt_output_hint: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FileV2Envelope {
    header: FileV2Header,
    ciphertext: Vec<u8>,
}

Añade helpers:

fn sha256_bytes(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn template_sha256(template: &crate::templates::TemplateData) -> Result<Vec<u8>, String> {
    let encoded = rmp_serde::to_vec(template)
        .map_err(|e| format!("No se pudo serializar plantilla para hash: {}", e))?;
    Ok(sha256_bytes(&encoded))
}

fn cajas_sha256(cajas: [i64; 5]) -> Vec<u8> {
    let mut material = Vec::new();
    for caja in cajas {
        material.extend_from_slice(&caja.to_le_bytes());
    }
    let out = sha256_bytes(&material);
    material.zeroize();
    out
}

fn derive_file_key(
    file_secret: &str,
    referencia: &str,
    cajas: [i64; 5],
    salt: &[u8],
    params: &FileKdfParams,
) -> Result<[u8; 32], String> {
    if file_secret.trim().chars().count() < 12 {
        return Err("La clave/frase de archivo debe tener al menos 12 caracteres.".to_string());
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| format!("Parámetros Argon2 inválidos: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut material = Vec::new();
    material.extend_from_slice(b"LIVENCRYPT-FILE-V2|");
    material.extend_from_slice(referencia.as_bytes());
    material.push(b'|');
    for caja in cajas {
        material.extend_from_slice(&caja.to_le_bytes());
    }
    material.push(b'|');
    material.extend_from_slice(file_secret.as_bytes());

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(&material, salt, &mut key)
        .map_err(|e| format!("No se pudo derivar clave de archivo: {}", e))?;

    material.zeroize();
    Ok(key)
}

fn seal_v2(
    plaintext: &[u8],
    header: FileV2Header,
    key: &[u8; 32],
) -> Result<FileV2Envelope, String> {
    let aad = rmp_serde::to_vec(&header)
        .map_err(|e| format!("No se pudo serializar AAD: {}", e))?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(&header.nonce);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "Fallo AEAD al cifrar archivo.".to_string())?;

    Ok(FileV2Envelope { header, ciphertext })
}

fn open_v2(envelope: &FileV2Envelope, key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if envelope.header.magic != FILE_V2_MAGIC || envelope.header.version != 2 {
        return Err("Formato Livencrypt de archivo no soportado.".to_string());
    }

    if envelope.header.nonce.len() != 24 {
        return Err("Nonce AEAD inválido.".to_string());
    }

    let aad = rmp_serde::to_vec(&envelope.header)
        .map_err(|e| format!("No se pudo serializar AAD: {}", e))?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(&envelope.header.nonce);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: envelope.ciphertext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| "Autenticación AEAD fallida: archivo manipulado o clave incorrecta.".to_string())
}

Implementa:

impl FileCipher {
    pub fn encrypt_file_authenticated(
        input_path: &Path,
        output_path: &Path,
        referencia: &str,
        template: &crate::templates::TemplateData,
        cajas: [i64; 5],
        file_secret: &str,
    ) -> Result<(), String> {
        let mut inner = Self::encode_file_inner_v1_compatible(
            input_path,
            referencia,
            template,
            cajas[0],
            cajas[1],
            cajas[2],
            cajas[3],
            cajas[4],
        )?;

        let kdf = FileKdfParams::default();
        let salt = random_bytes(32);
        let nonce = random_bytes(24);

        let mut key = derive_file_key(file_secret, referencia, cajas, &salt, &kdf)?;

        let header = FileV2Header {
            magic: FILE_V2_MAGIC,
            version: 2,
            kdf,
            salt,
            nonce,
            template_sha256: template_sha256(template)?,
            cajas_sha256: cajas_sha256(cajas),
            referencia_sha256: sha256_bytes(referencia.as_bytes()),
            is_txt_output_hint: false,
        };

        let envelope = seal_v2(&inner, header, &key)?;
        inner.zeroize();
        key.zeroize();

        let encoded = rmp_serde::to_vec(&envelope)
            .map_err(|e| format!("No se pudo serializar archivo LVC v2: {}", e))?;

        write_file_synced(output_path, &encoded)
    }

    pub fn decrypt_file_authenticated(
        input_path: &Path,
        output_path: &Path,
        referencia: &str,
        is_txt_output: bool,
        template: &crate::templates::TemplateData,
        cajas: [i64; 5],
        file_secret: &str,
    ) -> Result<(), String> {
        let bytes = std::fs::read(input_path)
            .map_err(|e| format!("No se pudo leer archivo cifrado: {}", e))?;

        let envelope: FileV2Envelope = rmp_serde::from_slice(&bytes)
            .map_err(|e| format!("Archivo LVC v2 inválido: {}", e))?;

        if envelope.header.template_sha256 != template_sha256(template)? {
            return Err("La plantilla no coincide con la usada al cifrar.".to_string());
        }

        if envelope.header.cajas_sha256 != cajas_sha256(cajas) {
            return Err("Las cajas no coinciden con las usadas al cifrar.".to_string());
        }

        if envelope.header.referencia_sha256 != sha256_bytes(referencia.as_bytes()) {
            return Err("La referencia no coincide con la usada al cifrar.".to_string());
        }

        let mut key = derive_file_key(
            file_secret,
            referencia,
            cajas,
            &envelope.header.salt,
            &envelope.header.kdf,
        )?;

        let mut inner = open_v2(&envelope, &key)?;
        key.zeroize();

        let result = Self::decode_file_inner_v1_compatible(
            &inner,
            output_path,
            referencia,
            is_txt_output,
            template,
            cajas[0],
            cajas[1],
            cajas[2],
            cajas[3],
            cajas[4],
        );

        inner.zeroize();
        result
    }
}

Refactoriza el código actual para extraer:

encode_file_inner_v1_compatible(...)
decode_file_inner_v1_compatible(...)

Estas funciones deben contener el algoritmo posicional actual, pero nunca deben escribir un archivo final sin pasar por AEAD.

Añade tests:

cifrar/descifrar correcto con clave válida
descifrado falla si se cambia 1 byte del ciphertext
descifrado falla con clave incorrecta
descifrado falla con plantilla incorrecta
descifrado falla con cajas incorrectas
descifrado falla con referencia incorrecta

────────────────────────────────────────
PATCH 4 — src-tui/src/crypto/blockchain/worker.rs
────────────────────────────────────────

Eliminar fallback a /tmp. El socket debe vivir sólo en XDG_RUNTIME_DIR/livencrypt/livencrypt.sock.

#[cfg(unix)]
fn resolve_socket_path() -> Result<PathBuf, String> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| "XDG_RUNTIME_DIR no está definido; no se abrirá socket inseguro en /tmp.".to_string())?;

    let dir = PathBuf::from(runtime_dir).join("livencrypt");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("No se pudo crear directorio IPC: {}", e))?;

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("No se pudo asegurar permisos IPC: {}", e))?;

    Ok(dir.join("livencrypt.sock"))
}

Antes de remove_file, comprobar que el path existente es socket, no symlink ni archivo normal:

use std::os::unix::fs::FileTypeExt;

if let Ok(meta) = std::fs::symlink_metadata(&socket_path) {
    if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
        return Err("Ruta IPC existente no es socket seguro; abortando.".to_string());
    }
    std::fs::remove_file(&socket_path)
        .map_err(|e| format!("No se pudo eliminar socket previo: {}", e))?;
}

Después de aceptar conexión, verificar peer UID:

#[cfg(target_os = "linux")]
fn ensure_peer_is_current_user(stream: &std::os::unix::net::UnixStream) -> Result<(), String> {
    use std::mem;
    use std::os::fd::AsRawFd;

    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;

    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if rc != 0 {
        return Err("No se pudo verificar credenciales del peer IPC.".to_string());
    }

    let current_uid = unsafe { libc::geteuid() };
    if cred.uid != current_uid {
        return Err("Conexión IPC rechazada: UID no autorizado.".to_string());
    }

    Ok(())
}

En el loop de accept:

let Ok((mut stream, _addr)) = listener.accept() else {
    thread::sleep(Duration::from_millis(50));
    continue;
};

#[cfg(target_os = "linux")]
if ensure_peer_is_current_user(&stream).is_err() {
    continue;
}

────────────────────────────────────────
PATCH 5 — src-tui/src/bin/livencrypt-bridge.rs
────────────────────────────────────────

Eliminar fallback a /tmp también aquí:

#[cfg(unix)]
fn resolve_socket_path() -> Result<std::path::PathBuf, String> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| "XDG_RUNTIME_DIR no definido; bridge no usará /tmp.".to_string())?;

    Ok(std::path::PathBuf::from(runtime_dir)
        .join("livencrypt")
        .join("livencrypt.sock"))
}

Y cambiar:

let mut socket = UnixStream::connect(resolve_socket_path()?)
    .map_err(|error| format!("pasarela local no disponible: {}", error))?;

────────────────────────────────────────
PATCH 6 — src-tui/src/security/loader.rs
────────────────────────────────────────

Corregir escritura parcial y no ejecutar si falla sandbox:

#[cfg(target_os = "linux")]
fn write_all_fd(fd: i32, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let written = unsafe {
            libc::write(
                fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
            )
        };

        if written < 0 {
            return Err("No se pudo escribir binario completo en memfd.".to_string());
        }

        if written == 0 {
            return Err("Escritura parcial en memfd.".to_string());
        }

        bytes = &bytes[written as usize..];
    }

    Ok(())
}

Reemplazar el write() único por write_all_fd(fd, binary_data)?.

En el hijo:

if pid == 0 {
    if crate::security::sandbox::enter_restricted_child().is_err() {
        unsafe { close(fd); }
        std::process::exit(126);
    }

    let path = CString::new(format!("/proc/self/fd/{}", fd)).unwrap();
    let argv: [*const c_char; 2] = [path.as_ptr(), ptr::null()];
    let envp: [*const c_char; 1] = [ptr::null()];

    unsafe {
        execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }

    std::process::exit(127);
}

Añadir test o prueba manual controlada que verifique que un fallo de sandbox no ejecuta el payload.

────────────────────────────────────────
PATCH 7 — src-tui/scripts/postremove.sh
────────────────────────────────────────

Eliminar por completo el borrado automático de datos de usuario.

Sustituir este bloque:

for home_dir in /home/* /root; do
  ...
  rm -rf "$data_dir"
done

por:

echo "Livencrypt: purge completado. Los datos de usuario/vaults no se eliminan automáticamente."
echo "Livencrypt: para borrar datos personales, elimine manualmente ~/.local/share/livencrypt tras hacer copia de seguridad."

No usar rm -rf sobre /home/* desde scripts de paquete.

────────────────────────────────────────
PATCH 8 — DOCS/LIVENCRYPT 2.0/src-tauri/tauri.conf.json
────────────────────────────────────────

Si esta app Tauri sigue formando parte del build, reemplazar:

"csp": null

por una política cerrada:

"csp": "default-src 'self'; img-src 'self' asset: data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' ipc: http://ipc.localhost"

Si Tauri ya es legado, mover DOCS/LIVENCRYPT 2.0 fuera del árbol compilable y documentarlo como código histórico no distribuido.

────────────────────────────────────────
PATCH 9 — Web3 signing/firewall
────────────────────────────────────────

No confiar en target_dex_cex_id ni estimated_value_usd si vienen de la extensión.

Antes de firmar:

Parsear raw_payload según ChainType.
Extraer destino real, chain_id, contrato, método, amount y nonce.
Comparar destino real con allowed_dex_contracts / allowed_cex_destinations.
Mostrar resumen humano de lo que se firma.
Rechazar payloads que no se puedan parsear.
No hacer commit_transaction hasta después de firma correcta.

Para Ethereum, añadir como mínimo:

chain_id obligatorio
to obligatorio
value/gas visibles
selector de método visible
contrato real extraído del payload, no del JSON externo

Para Bitcoin:

outputs visibles
amounts visibles
dirección destino visible
fee estimada visible

────────────────────────────────────────
PATCH 10 — Tests finales obligatorios
────────────────────────────────────────

Ejecutar y corregir hasta verde:

cd src-tui
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
./target/release/livencrypt-core --self-test-safe
./target/release/livencrypt-core --hardening-check

Añadir tests nuevos:

template_path_traversal_rejected
template_invalid_dimensions_rejected
template_duplicate_symbols_rejected
file_aead_tamper_rejected
file_aead_wrong_secret_rejected
file_aead_wrong_template_rejected
ipc_socket_never_uses_tmp
postremove_does_not_delete_user_data

No cerrar la tarea hasta que todo compile y los tests pasen.


La corrección más urgente es esta combinación: **bloquear seed nulo + añadir AEAD al cifrado de archivos + sanear nombres de plantillas + quitar `/tmp/livencrypt.sock` + impedir borrado de datos en `postremove.sh`**. Ahí están los vectores de ataque más serios.
