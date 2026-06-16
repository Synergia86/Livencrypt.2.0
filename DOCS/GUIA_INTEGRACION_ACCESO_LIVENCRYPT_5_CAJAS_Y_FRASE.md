# Guia de integracion: acceso Livencrypt con 5 cajas y frase

## 1. Objetivo

Esta guia define una integracion completa para proteger el acceso a una aplicacion, portal web, base de datos o modulo privado mediante una secuencia Livencrypt formada por:

```text
5 cajas numericas + frase exacta
```

La aplicacion no debe limitarse a mostrar una pantalla de acceso. El estado seguro es que los datos necesarios para ejecutar la aplicacion esten cifrados y solo se monten en memoria cuando la secuencia sea correcta.

Resultado esperado:

```text
secuencia correcta:
  se deriva clave Argon2id
  se valida el vault AEAD
  se revierte la capa Livencrypt
  se cargan plantillas/configuracion/secretos
  se habilita el dashboard o servicio protegido

secuencia incorrecta:
  no se obtiene clave valida
  no se autentica el vault
  no se monta el payload
  no se carga el dashboard
```

Mensaje unico recomendado para cualquier fallo:

```text
CREDENCIALES INVALIDAS O VAULT MANIPULADO
```

## 2. Dependencias Rust

Anadir al `Cargo.toml` del proyecto:

```toml
[dependencies]
argon2 = "0.5"
chacha20poly1305 = { version = "0.10", features = ["std"] }
hex = "0.4"
hkdf = "0.12"
itoa = "1.0"
rand = "0.8"
rmp-serde = "1.3"
secrecy = "0.8"
serde = { version = "1", features = ["derive"] }
sha2 = "0.10"
zeroize = { version = "1", features = ["derive"] }
```

Si el proyecto usa Tauri:

```toml
tauri = { version = "2", features = [] }
```

## 3. Modelo de vault

El vault contiene el payload protegido. Puede incluir:

```text
plantillas Livencrypt
configuracion privada
secretos de API
credenciales de base de datos
datos iniciales del dashboard
permisos de usuario
metadatos privados
```

Formato recomendado:

```text
VaultPayload serializado
  -> capa Livencrypt interna
  -> cuerpo MessagePack
  -> XChaCha20-Poly1305 con AAD
  -> VaultEnvelope MessagePack
```

El encabezado del vault puede estar en claro porque no contiene la frase ni la clave. El encabezado se autentica como Associated Data del AEAD.

## 4. Imports base

```rust
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use zeroize::{Zeroize, Zeroizing};
```

## 5. Constantes

```rust
const MAGIC: &str = "LVCVAULT";
const FORMAT_VERSION: u16 = 3;
const AEAD_ALGORITHM: &str = "xchacha20poly1305";
const KDF_ALGORITHM: &str = "argon2id";
const CREDENTIAL_MODE_SINGLE: &str = "single";
const CREDENTIAL_MODE_DOUBLE: &str = "double";
const DEFAULT_BOOT_TEMPLATE_NAME: &str = "Livencrypt";
```

## 6. Plantilla Livencrypt

La plantilla es la matriz de caracteres usada por el cifrado posicional.

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct TemplateData {
    pub rows: u32,
    pub cols: u32,
    pub chars: Vec<String>,
}
```

Validacion minima:

```rust
pub fn validate_template(template: &TemplateData) -> Result<(), String> {
    if template.rows == 0 || template.cols == 0 || template.chars.is_empty() {
        return Err("Plantilla vacia.".into());
    }

    let expected = template.rows as usize * template.cols as usize;
    if expected != template.chars.len() {
        return Err(format!(
            "Dimensiones invalidas: {}x{} requiere {} caracteres, contiene {}.",
            template.rows,
            template.cols,
            expected,
            template.chars.len()
        ));
    }

    let mut seen = std::collections::HashSet::new();
    for value in &template.chars {
        if value.is_empty() {
            return Err("La plantilla contiene caracteres vacios.".into());
        }
        if !seen.insert(value.clone()) {
            return Err(format!("Caracter duplicado en plantilla: {}", value));
        }
    }

    Ok(())
}
```

Para usar una plantilla como plantilla de arranque del vault, debe contener al menos los caracteres hexadecimales:

```rust
pub fn validate_boot_template(name: &str, template: &TemplateData) -> Result<(), String> {
    validate_template(template)?;

    let required = [
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "f",
    ];

    let missing = required
        .iter()
        .filter(|value| !template.chars.iter().any(|item| item == **value))
        .copied()
        .collect::<Vec<_>>();

    if !missing.is_empty() {
        return Err(format!(
            "La plantilla Boot Shield '{}' no contiene caracteres HEX requeridos: {}",
            name,
            missing.join(" ")
        ));
    }

    Ok(())
}
```

## 7. Secreto de acceso

La frase debe tratarse como secreto de memoria. Las cajas se limpian al liberar la estructura.

```rust
pub struct AccessSecret {
    pub cajas: [i64; 5],
    pub frase: SecretString,
}

impl Drop for AccessSecret {
    fn drop(&mut self) {
        self.cajas.zeroize();
    }
}
```

Normalizacion de la frase:

```rust
pub fn normalize_secret(cajas: [i64; 5], mut frase: String) -> Result<AccessSecret, String> {
    if frase.trim().is_empty() {
        frase.zeroize();
        return Err("La frase de acceso no puede estar vacia.".into());
    }

    let trimmed = frase.trim();
    let mut normalized_buffer = String::with_capacity(trimmed.len());
    normalized_buffer.push_str(trimmed);
    frase.zeroize();

    Ok(AccessSecret {
        cajas,
        frase: SecretString::new(normalized_buffer),
    })
}
```

Normalizacion de doble credencial:

```rust
pub fn normalize_secondary_secret(
    cajas: Option<[i64; 5]>,
    frase: Option<String>,
) -> Result<Option<AccessSecret>, String> {
    match (cajas, frase) {
        (None, None) => Ok(None),
        (Some(_), Some(mut frase)) if frase.trim().is_empty() => {
            frase.zeroize();
            Err("La segunda frase de acceso no puede estar vacia.".into())
        }
        (Some(cajas), Some(frase)) => normalize_secret(cajas, frase).map(Some),
        _ => Err("La doble credencial requiere segunda secuencia de cajas y segunda frase.".into()),
    }
}
```

## 8. Material canonico para Argon2id

La secuencia se serializa en un buffer secreto. Las cajas se formatean con `itoa` para evitar asignaciones dinamicas por numero.

```rust
pub fn canonical_secret(secret: &AccessSecret) -> SecretVec<u8> {
    let mut buffer = Vec::with_capacity(128);
    buffer.extend_from_slice(b"LIVENCRYPT-ACCESS-V1|");

    let mut num_buf = itoa::Buffer::new();
    for caja in &secret.cajas {
        buffer.extend_from_slice(num_buf.format(*caja).as_bytes());
        buffer.push(b'|');
    }

    buffer.extend_from_slice(secret.frase.expose_secret().as_bytes());
    SecretVec::new(buffer)
}
```

## 9. Derivacion Argon2id

Parametros KDF:

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: KDF_ALGORITHM.to_string(),
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        }
    }
}
```

Derivacion:

```rust
pub fn derive_key(
    secret: &AccessSecret,
    salt: &[u8],
    params: &KdfParams,
) -> Result<[u8; 32], String> {
    if params.algorithm != KDF_ALGORITHM {
        return Err(format!("KDF no soportado: {}", params.algorithm));
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|error| format!("Parametros Argon2id invalidos: {}", error))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = [0u8; 32];
    let material = canonical_secret(secret);

    argon
        .hash_password_into(material.expose_secret(), salt, &mut key)
        .map_err(|error| format!("No se pudo derivar la clave de acceso: {}", error))?;

    Ok(key)
}
```

## 10. Doble credencial con HKDF

Para doble secuencia:

```text
A = cajas A + frase A
B = cajas B + frase B
```

No debe verificarse A por separado. Se derivan ambas claves y se combinan con HKDF-SHA256.

```rust
pub fn combine_derived_keys(
    primary: &[u8; 32],
    secondary: &[u8; 32],
    final_salt: &[u8],
) -> Result<[u8; 32], String> {
    let mut material = Zeroizing::new([0u8; 64]);
    material[..32].copy_from_slice(primary);
    material[32..].copy_from_slice(secondary);

    let hk = Hkdf::<Sha256>::new(Some(final_salt), &*material);
    let mut key = [0u8; 32];
    hk.expand(b"LIVENCRYPT-BOOT-SHIELD-V3-DOUBLE", &mut key)
        .map_err(|_| "No se pudo combinar doble credencial con HKDF.".to_string())?;

    Ok(key)
}
```

## 11. Material de arranque

```rust
#[derive(Clone)]
pub struct BootMaterial {
    pub key: [u8; 32],
    pub cajas: [i64; 5],
    pub secondary_cajas: Option<[i64; 5]>,
}

impl Drop for BootMaterial {
    fn drop(&mut self) {
        self.key.zeroize();
        self.cajas.zeroize();
        if let Some(cajas) = self.secondary_cajas.as_mut() {
            cajas.zeroize();
        }
    }
}
```

Derivacion de material:

```rust
pub fn derive_material(
    primary: &AccessSecret,
    secondary: Option<&AccessSecret>,
    header: &VaultHeader,
) -> Result<BootMaterial, String> {
    if header.format_version < FORMAT_VERSION || header.credential_mode == CREDENTIAL_MODE_SINGLE {
        return Ok(BootMaterial {
            key: derive_key(primary, &header.salt, &header.kdf)?,
            cajas: primary.cajas,
            secondary_cajas: None,
        });
    }

    if header.credential_mode != CREDENTIAL_MODE_DOUBLE {
        return Err(format!(
            "Modo de credencial no soportado: {}",
            header.credential_mode
        ));
    }

    if header.secondary_salt.len() != 32 || header.final_salt.len() != 32 {
        return Err("Cabecera de doble credencial invalida.".into());
    }

    let secondary = secondary.ok_or_else(|| "Doble credencial requerida.".to_string())?;
    let primary_key = Zeroizing::new(derive_key(primary, &header.salt, &header.kdf)?);
    let secondary_key = Zeroizing::new(derive_key(secondary, &header.secondary_salt, &header.kdf)?);
    let key = combine_derived_keys(&*primary_key, &*secondary_key, &header.final_salt)?;

    Ok(BootMaterial {
        key,
        cajas: primary.cajas,
        secondary_cajas: Some(secondary.cajas),
    })
}
```

## 12. Estructuras del vault

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub magic: String,
    pub format_version: u16,
    pub kdf: KdfParams,
    pub salt: Vec<u8>,
    pub credential_mode: String,
    pub secondary_salt: Vec<u8>,
    pub final_salt: Vec<u8>,
    pub aead: String,
    pub nonce: Vec<u8>,
    pub created_at_unix: u64,
    pub vault_counter: u64,
    pub object_names: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VaultEnvelope {
    pub header: VaultHeader,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VaultCipherBody {
    pub boot_template_name: String,
    pub boot_template: TemplateData,
    pub livencrypt_payload: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    pub templates: HashMap<String, TemplateData>,
    pub settings: HashMap<String, String>,
    pub protected_objects: HashMap<String, Vec<u8>>,
    pub metadata_version: u16,
    pub vault_counter: u64,
}
```

Creacion de encabezado:

```rust
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

pub fn new_header(double_credential: bool) -> VaultHeader {
    VaultHeader {
        magic: MAGIC.to_string(),
        format_version: FORMAT_VERSION,
        kdf: KdfParams::default(),
        salt: random_bytes(32),
        credential_mode: if double_credential {
            CREDENTIAL_MODE_DOUBLE.to_string()
        } else {
            CREDENTIAL_MODE_SINGLE.to_string()
        },
        secondary_salt: if double_credential { random_bytes(32) } else { Vec::new() },
        final_salt: if double_credential { random_bytes(32) } else { Vec::new() },
        aead: AEAD_ALGORITHM.to_string(),
        nonce: Vec::new(),
        created_at_unix: unix_now(),
        vault_counter: 1,
        object_names: Vec::new(),
    }
}
```

Datos autenticados:

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultAssociatedData {
    pub magic: String,
    pub format_version: u16,
    pub kdf: KdfParams,
    pub salt: Vec<u8>,
    pub credential_mode: String,
    pub secondary_salt: Vec<u8>,
    pub final_salt: Vec<u8>,
    pub aead: String,
    pub nonce: Vec<u8>,
    pub vault_counter: u64,
    pub object_names: Vec<String>,
}

pub fn associated_data(header: &VaultHeader) -> Result<Vec<u8>, String> {
    rmp_serde::to_vec(&VaultAssociatedData {
        magic: header.magic.clone(),
        format_version: header.format_version,
        kdf: header.kdf.clone(),
        salt: header.salt.clone(),
        credential_mode: header.credential_mode.clone(),
        secondary_salt: header.secondary_salt.clone(),
        final_salt: header.final_salt.clone(),
        aead: header.aead.clone(),
        nonce: header.nonce.clone(),
        vault_counter: header.vault_counter,
        object_names: header.object_names.clone(),
    })
    .map_err(|error| format!("Error generando datos autenticados del vault: {}", error))
}
```

## 13. Adaptador Livencrypt

Cada proyecto debe conectar estas funciones con su motor Livencrypt real.

Interfaz recomendada:

```rust
pub trait LivencryptEngine {
    fn encrypt_text(
        &self,
        text: &str,
        c1: i64,
        c2: i64,
        c3: i64,
        c4: i64,
        c5: i64,
    ) -> String;

    fn decrypt_text(
        &self,
        text: &str,
        c1: i64,
        c2: i64,
        c3: i64,
        c4: i64,
        c5: i64,
    ) -> String;
}
```

Ejemplo de adaptador para un motor posicional:

```rust
pub struct TemplateCipher {
    pub template: TemplateData,
}

impl LivencryptEngine for TemplateCipher {
    fn encrypt_text(
        &self,
        text: &str,
        c1: i64,
        c2: i64,
        c3: i64,
        c4: i64,
        c5: i64,
    ) -> String {
        positional_encrypt(&self.template, text, c1, c2, c3, c4, c5)
    }

    fn decrypt_text(
        &self,
        text: &str,
        c1: i64,
        c2: i64,
        c3: i64,
        c4: i64,
        c5: i64,
    ) -> String {
        positional_decrypt(&self.template, text, c1, c2, c3, c4, c5)
    }
}
```

Las funciones `positional_encrypt` y `positional_decrypt` deben ser el cifrado Livencrypt real del proyecto.

## 14. Capa Livencrypt interna del vault

```rust
pub fn livencrypt_encode(
    payload_bytes: &[u8],
    cajas: [i64; 5],
    template: &TemplateData,
    engine_factory: impl Fn(&TemplateData) -> Box<dyn LivencryptEngine>,
) -> Vec<u8> {
    let hex_payload = hex::encode(payload_bytes);
    let engine = engine_factory(template);
    engine
        .encrypt_text(
            &hex_payload,
            cajas[0],
            cajas[1],
            cajas[2],
            cajas[3],
            cajas[4],
        )
        .into_bytes()
}

pub fn livencrypt_decode(
    encoded: &[u8],
    cajas: [i64; 5],
    template: &TemplateData,
    engine_factory: impl Fn(&TemplateData) -> Box<dyn LivencryptEngine>,
) -> Result<Vec<u8>, String> {
    let encoded_text = std::str::from_utf8(encoded)
        .map_err(|_| "La capa Livencrypt interna no es UTF-8 valido.".to_string())?;

    let engine = engine_factory(template);
    let decoded_hex = engine.decrypt_text(
        encoded_text,
        cajas[0],
        cajas[1],
        cajas[2],
        cajas[3],
        cajas[4],
    );

    hex::decode(decoded_hex)
        .map_err(|_| "La capa Livencrypt interna no produjo payload hexadecimal valido.".into())
}
```

Doble capa Livencrypt interna:

```rust
pub fn livencrypt_encode_material(
    payload_bytes: &[u8],
    material: &BootMaterial,
    template: &TemplateData,
    engine_factory: impl Copy + Fn(&TemplateData) -> Box<dyn LivencryptEngine>,
) -> Vec<u8> {
    let first_layer_cajas = material.secondary_cajas.unwrap_or(material.cajas);
    let first_layer = livencrypt_encode(payload_bytes, first_layer_cajas, template, engine_factory);

    if material.secondary_cajas.is_some() {
        livencrypt_encode(&first_layer, material.cajas, template, engine_factory)
    } else {
        first_layer
    }
}

pub fn livencrypt_decode_material(
    encoded: &[u8],
    material: &BootMaterial,
    template: &TemplateData,
    engine_factory: impl Copy + Fn(&TemplateData) -> Box<dyn LivencryptEngine>,
) -> Result<Vec<u8>, String> {
    if let Some(secondary_cajas) = material.secondary_cajas {
        let inner_layer = livencrypt_decode(encoded, material.cajas, template, engine_factory)?;
        livencrypt_decode(&inner_layer, secondary_cajas, template, engine_factory)
    } else {
        livencrypt_decode(encoded, material.cajas, template, engine_factory)
    }
}
```

## 15. Cifrar vault

```rust
pub fn encrypt_payload(
    payload: &VaultPayload,
    material: &BootMaterial,
    mut header: VaultHeader,
    boot_template_name: &str,
    boot_template: &TemplateData,
    engine_factory: impl Copy + Fn(&TemplateData) -> Box<dyn LivencryptEngine>,
) -> Result<VaultEnvelope, String> {
    if header.aead != AEAD_ALGORITHM {
        return Err(format!("AEAD no soportado: {}", header.aead));
    }

    header.object_names = payload.protected_objects.keys().cloned().collect::<Vec<_>>();
    header.object_names.sort();
    header.nonce = random_bytes(24);

    let payload_bytes = rmp_serde::to_vec(payload)
        .map_err(|error| format!("Error serializando payload: {}", error))?;

    let body = VaultCipherBody {
        boot_template_name: boot_template_name.to_string(),
        boot_template: boot_template.clone(),
        livencrypt_payload: livencrypt_encode_material(
            &payload_bytes,
            material,
            boot_template,
            engine_factory,
        ),
    };

    let body_bytes = rmp_serde::to_vec(&body)
        .map_err(|error| format!("Error serializando cuerpo cifrado del vault: {}", error))?;

    let aad = associated_data(&header)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&material.key));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&header.nonce),
            Payload {
                msg: &body_bytes,
                aad: &aad,
            },
        )
        .map_err(|_| "No se pudo cifrar el vault.".to_string())?;

    Ok(VaultEnvelope { header, ciphertext })
}
```

## 16. Descifrar vault

```rust
pub fn decrypt_payload(
    envelope: &VaultEnvelope,
    secret: &AccessSecret,
    secondary_secret: Option<&AccessSecret>,
    engine_factory: impl Copy + Fn(&TemplateData) -> Box<dyn LivencryptEngine>,
) -> Result<(VaultPayload, BootMaterial, VaultHeader, String, TemplateData), String> {
    if envelope.header.magic != MAGIC {
        return Err("CREDENCIALES INVALIDAS O VAULT MANIPULADO".into());
    }

    if envelope.header.format_version != FORMAT_VERSION {
        return Err("CREDENCIALES INVALIDAS O VAULT MANIPULADO".into());
    }

    if envelope.header.aead != AEAD_ALGORITHM || envelope.header.nonce.len() != 24 {
        return Err("CREDENCIALES INVALIDAS O VAULT MANIPULADO".into());
    }

    let material = derive_material(secret, secondary_secret, &envelope.header)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&material.key));

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&envelope.header.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &associated_data(&envelope.header)?,
            },
        )
        .map_err(|_| "CREDENCIALES INVALIDAS O VAULT MANIPULADO".to_string())?;

    let body = rmp_serde::from_slice::<VaultCipherBody>(&plaintext)
        .map_err(|_| "CREDENCIALES INVALIDAS O VAULT MANIPULADO".to_string())?;

    let payload_bytes = livencrypt_decode_material(
        &body.livencrypt_payload,
        &material,
        &body.boot_template,
        engine_factory,
    )
    .map_err(|_| "CREDENCIALES INVALIDAS O VAULT MANIPULADO".to_string())?;

    let payload = rmp_serde::from_slice::<VaultPayload>(&payload_bytes)
        .map_err(|_| "CREDENCIALES INVALIDAS O VAULT MANIPULADO".to_string())?;

    Ok((
        payload,
        material,
        envelope.header.clone(),
        body.boot_template_name,
        body.boot_template,
    ))
}
```

## 17. Escritura atomica del vault

```rust
pub fn write_vault_atomic(path: &Path, envelope: &VaultEnvelope) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Ruta de vault sin directorio padre.".to_string())?;

    fs::create_dir_all(parent)
        .map_err(|error| format!("No se pudo crear directorio del vault: {}", error))?;

    let tmp_path = parent.join(".vault.tmp");
    let backup_path = parent.join("vault.backup.lvcvault");

    if path.exists() {
        fs::copy(path, &backup_path)
            .map_err(|error| format!("No se pudo crear backup del vault: {}", error))?;
    }

    let bytes = rmp_serde::to_vec(envelope)
        .map_err(|error| format!("Error serializando vault: {}", error))?;

    fs::write(&tmp_path, bytes)
        .map_err(|error| format!("No se pudo escribir vault temporal: {}", error))?;

    fs::rename(&tmp_path, path)
        .map_err(|error| format!("No se pudo promover vault temporal: {}", error))?;

    Ok(())
}

pub fn read_vault(path: &Path) -> Result<VaultEnvelope, String> {
    let bytes = fs::read(path).map_err(|error| format!("No se pudo leer vault: {}", error))?;
    rmp_serde::from_slice::<VaultEnvelope>(&bytes)
        .map_err(|error| format!("Vault invalido: {}", error))
}
```

## 18. Runtime desbloqueado

```rust
#[derive(Default)]
pub struct AccessRuntime {
    pub payload: Option<VaultPayload>,
    pub material: Option<BootMaterial>,
    pub header: Option<VaultHeader>,
    pub boot_template_name: Option<String>,
    pub boot_template: Option<TemplateData>,
}

impl Drop for AccessRuntime {
    fn drop(&mut self) {
        self.payload = None;
        self.material = None;
        self.header = None;
        self.boot_template_name = None;
        self.boot_template = None;
    }
}

static RUNTIME: OnceLock<Mutex<AccessRuntime>> = OnceLock::new();

pub fn runtime() -> &'static Mutex<AccessRuntime> {
    RUNTIME.get_or_init(|| Mutex::new(AccessRuntime::default()))
}

pub fn lock_runtime() -> MutexGuard<'static, AccessRuntime> {
    match runtime().lock() {
        Ok(runtime) => runtime,
        Err(poisoned) => poisoned.into_inner(),
    }
}
```

Montaje en memoria:

```rust
pub fn mount_runtime(
    payload: VaultPayload,
    material: BootMaterial,
    header: VaultHeader,
    boot_template_name: String,
    boot_template: TemplateData,
) {
    let mut runtime = lock_runtime();
    runtime.payload = Some(payload);
    runtime.material = Some(material);
    runtime.header = Some(header);
    runtime.boot_template_name = Some(boot_template_name);
    runtime.boot_template = Some(boot_template);
}

pub fn lock_access_runtime() {
    let mut runtime = lock_runtime();
    runtime.payload = None;
    runtime.material = None;
    runtime.header = None;
    runtime.boot_template_name = None;
    runtime.boot_template = None;
}
```

## 19. Activar acceso cifrado

```rust
pub fn enable_access_vault(
    vault_path: &Path,
    cajas: [i64; 5],
    frase: String,
    secondary_cajas: Option<[i64; 5]>,
    secondary_frase: Option<String>,
    boot_template_name: String,
    boot_template: TemplateData,
    payload: VaultPayload,
    engine_factory: impl Copy + Fn(&TemplateData) -> Box<dyn LivencryptEngine>,
) -> Result<(), String> {
    validate_boot_template(&boot_template_name, &boot_template)?;

    let secret = normalize_secret(cajas, frase)?;
    let secondary_secret = normalize_secondary_secret(secondary_cajas, secondary_frase)?;
    let header = new_header(secondary_secret.is_some());
    let material = derive_material(&secret, secondary_secret.as_ref(), &header)?;

    let envelope = encrypt_payload(
        &payload,
        &material,
        header,
        &boot_template_name,
        &boot_template,
        engine_factory,
    )?;

    decrypt_payload(&envelope, &secret, secondary_secret.as_ref(), engine_factory)?;
    write_vault_atomic(vault_path, &envelope)?;
    decrypt_payload(&read_vault(vault_path)?, &secret, secondary_secret.as_ref(), engine_factory)?;

    Ok(())
}
```

Despues de activar el vault:

```text
1. cerrar la aplicacion
2. no mantener la sesion desbloqueada por defecto
3. borrar plantillas .msgpack residuales si se migraron al vault
4. exigir secuencia de 5 cajas + frase en el siguiente arranque
```

## 20. Desbloquear acceso

```rust
pub fn unlock_access_vault(
    vault_path: &Path,
    cajas: [i64; 5],
    frase: String,
    secondary_cajas: Option<[i64; 5]>,
    secondary_frase: Option<String>,
    engine_factory: impl Copy + Fn(&TemplateData) -> Box<dyn LivencryptEngine>,
) -> Result<(), String> {
    let envelope = read_vault(vault_path)?;
    let secret = normalize_secret(cajas, frase)?;
    let secondary_secret = normalize_secondary_secret(secondary_cajas, secondary_frase)?;

    let (payload, material, header, boot_template_name, boot_template) =
        decrypt_payload(&envelope, &secret, secondary_secret.as_ref(), engine_factory)?;

    mount_runtime(payload, material, header, boot_template_name, boot_template);
    Ok(())
}
```

## 21. Comandos Tauri

Estado:

```rust
#[derive(Clone, Serialize)]
pub struct AccessStatus {
    pub state: String,
    pub credential_mode: String,
}

#[tauri::command]
pub fn access_status(vault_path: String) -> Result<AccessStatus, String> {
    let unlocked = lock_runtime().payload.is_some();
    let configured = PathBuf::from(&vault_path).exists();

    Ok(AccessStatus {
        state: if !configured {
            "not_configured".to_string()
        } else if unlocked {
            "unlocked".to_string()
        } else {
            "locked".to_string()
        },
        credential_mode: "single_or_double".to_string(),
    })
}
```

Desbloqueo:

```rust
#[tauri::command]
pub async fn access_unlock(
    vault_path: String,
    cajas: [i64; 5],
    frase: String,
    secondary_cajas: Option<[i64; 5]>,
    secondary_frase: Option<String>,
) -> Result<AccessStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        unlock_access_vault(
            &PathBuf::from(vault_path.clone()),
            cajas,
            frase,
            secondary_cajas,
            secondary_frase,
            |template| Box::new(TemplateCipher { template: template.clone() }),
        )?;

        access_status(vault_path)
    })
    .await
    .map_err(|error| format!("Tarea de acceso interrumpida: {}", error))?
}
```

Bloqueo:

```rust
#[tauri::command]
pub fn access_lock() -> Result<AccessStatus, String> {
    lock_access_runtime();
    Ok(AccessStatus {
        state: "locked".to_string(),
        credential_mode: "single_or_double".to_string(),
    })
}
```

## 22. Frontend de acceso

El frontend solo recoge los valores y los envia al backend. No debe guardar frase ni cajas.

```tsx
type UnlockState = {
  cajas: string[];
  frase: string;
  secondaryCajas: string[];
  secondaryFrase: string;
};

function parseBoxes(values: string[]): [number, number, number, number, number] | null {
  if (values.length !== 5) return null;
  const parsed = values.map((value) => Number(value.trim()));
  if (parsed.some((value) => !Number.isInteger(value))) return null;
  return parsed as [number, number, number, number, number];
}

async function unlock(
  state: UnlockState,
  clearStateCallback: () => void,
): Promise<string> {
  const cajas = parseBoxes(state.cajas);
  if (!cajas || !state.frase.trim()) {
    clearStateCallback();
    return "CREDENCIALES INVALIDAS O VAULT MANIPULADO";
  }

  try {
    await invoke("access_unlock", {
      cajas,
      frase: state.frase,
      secondaryCajas: null,
      secondaryFrase: null,
    });
    clearStateCallback();
    return "";
  } catch {
    clearStateCallback();
    return "CREDENCIALES INVALIDAS O VAULT MANIPULADO";
  }
}
```

Reglas:

```text
no usar localStorage para frase
no usar localStorage para cajas
no registrar intentos con valores
limpiar campos tras cada intento
mostrar un unico error generico
montar dashboard solo tras access_unlock correcto
```

## 23. Editor de plantillas

El editor debe guardar plantillas dentro del vault si el acceso esta desbloqueado.

```rust
pub fn load_templates() -> Result<HashMap<String, TemplateData>, String> {
    let runtime = lock_runtime();
    let payload = runtime
        .payload
        .as_ref()
        .ok_or_else(|| "Vault bloqueado.".to_string())?;

    Ok(payload.templates.clone())
}

pub fn save_template(name: String, data: TemplateData) -> Result<(), String> {
    validate_template(&data)?;

    let mut runtime = lock_runtime();
    let payload = runtime
        .payload
        .as_mut()
        .ok_or_else(|| "Vault bloqueado.".to_string())?;

    payload.templates.insert(name, data);
    Ok(())
}

pub fn delete_template(name: &str) -> Result<(), String> {
    let mut runtime = lock_runtime();
    let payload = runtime
        .payload
        .as_mut()
        .ok_or_else(|| "Vault bloqueado.".to_string())?;

    payload
        .templates
        .remove(name)
        .ok_or_else(|| format!("Plantilla '{}' no encontrada.", name))?;

    Ok(())
}
```

Persistencia tras editar:

```rust
pub fn persist_unlocked_runtime(
    vault_path: &Path,
    engine_factory: impl Copy + Fn(&TemplateData) -> Box<dyn LivencryptEngine>,
) -> Result<(), String> {
    let mut runtime = lock_runtime();

    let payload = runtime
        .payload
        .as_ref()
        .ok_or_else(|| "Vault bloqueado.".to_string())?;
    let material = runtime
        .material
        .as_ref()
        .ok_or_else(|| "Material criptografico no disponible.".to_string())?;
    let header = runtime
        .header
        .as_ref()
        .ok_or_else(|| "Cabecera no disponible.".to_string())?;
    let boot_template_name = runtime
        .boot_template_name
        .as_ref()
        .ok_or_else(|| "Nombre de plantilla Boot no disponible.".to_string())?;
    let boot_template = runtime
        .boot_template
        .as_ref()
        .ok_or_else(|| "Plantilla Boot no disponible.".to_string())?;

    let mut payload = payload.clone();
    let mut header = header.clone();
    header.vault_counter = header.vault_counter.saturating_add(1);
    payload.vault_counter = header.vault_counter;

    let envelope = encrypt_payload(
        &payload,
        material,
        header,
        boot_template_name,
        boot_template,
        engine_factory,
    )?;

    write_vault_atomic(vault_path, &envelope)?;
    runtime.payload = Some(payload);
    runtime.header = Some(envelope.header);
    Ok(())
}
```

## 24. Integracion en portal web

En un portal web la validacion debe realizarse en backend.

Flujo:

```text
1. usuario introduce 5 cajas + frase
2. frontend envia los valores al backend por TLS
3. backend intenta descifrar el vault del usuario
4. si descifra, crea sesion temporal
5. si falla, devuelve error generico
```

Ejemplo de handler:

```rust
pub struct LoginRequest {
    pub user_id: String,
    pub cajas: [i64; 5],
    pub frase: String,
}

pub struct LoginResponse {
    pub session_id: String,
}

pub async fn login_livencrypt(request: LoginRequest) -> Result<LoginResponse, String> {
    let vault_path = user_vault_path(&request.user_id);

    unlock_access_vault(
        &vault_path,
        request.cajas,
        request.frase,
        None,
        None,
        |template| Box::new(TemplateCipher { template: template.clone() }),
    )?;

    let session_id = create_short_lived_session(&request.user_id)?;
    Ok(LoginResponse { session_id })
}
```

## 25. Integracion con base de datos

El vault puede guardar una clave de base de datos o token de acceso. Esa clave solo se entrega si el vault se descifra.

```rust
pub fn get_database_key() -> Result<Vec<u8>, String> {
    let runtime = lock_runtime();
    let payload = runtime
        .payload
        .as_ref()
        .ok_or_else(|| "Vault bloqueado.".to_string())?;

    payload
        .protected_objects
        .get("database-key")
        .cloned()
        .ok_or_else(|| "Clave de base de datos no disponible.".to_string())
}
```

Uso:

```rust
pub fn open_database_after_unlock() -> Result<DatabaseConnection, String> {
    let db_key = get_database_key()?;
    DatabaseConnection::open_with_key(db_key)
}
```

## 26. Cierre seguro

Al cerrar la aplicacion:

```rust
pub fn close_secure_session() {
    lock_access_runtime();
}
```

Secuencia recomendada:

```text
1. persistir cambios en vault cifrado
2. desmontar runtime
3. limpiar material criptografico
4. limpiar campos frontend
5. cerrar proceso
```

## 27. Borrado de plantillas en claro

Si se migran plantillas `.msgpack` a vault, deben borrarse del disco.

```rust
pub fn overwrite_and_remove_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }

    let len = fs::metadata(path)
        .map_err(|error| format!("No se pudo inspeccionar archivo: {}", error))?
        .len()
        .max(1);

    let mut random = vec![0u8; len as usize];
    rand::rngs::OsRng.fill_bytes(&mut random);

    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| format!("No se pudo abrir archivo para limpieza: {}", error))?;

    file.write_all(&random)
        .map_err(|error| format!("No se pudo sobrescribir archivo: {}", error))?;

    file.sync_all()
        .map_err(|error| format!("No se pudo sincronizar el borrado en disco: {}", error))?;

    drop(file);

    fs::remove_file(path)
        .map_err(|error| format!("No se pudo borrar archivo: {}", error))
}
```

## 28. Reglas obligatorias

```text
no guardar frase en localStorage
no guardar cajas en localStorage
no guardar clave derivada
no guardar payload descifrado en disco
no registrar valores introducidos
no mostrar que caja fallo
no validar solo en frontend
no montar dashboard antes de descifrar vault
no dejar plantillas .msgpack en claro si el vault esta activo
```

## 29. Resumen de integracion

Secuencia de activacion:

```text
1. cargar plantillas y configuracion privada
2. seleccionar plantilla Boot
3. introducir 5 cajas + frase
4. normalizar AccessSecret
5. derivar Argon2id
6. aplicar capa Livencrypt al payload
7. cifrar con XChaCha20-Poly1305
8. escribir vault atomico
9. verificar lectura y descifrado
10. cerrar aplicacion
```

Secuencia de desbloqueo:

```text
1. leer vault
2. introducir 5 cajas + frase
3. normalizar AccessSecret
4. derivar Argon2id
5. verificar AEAD
6. revertir capa Livencrypt
7. deserializar payload
8. montar runtime en memoria
9. cargar dashboard
```

Secuencia de cierre:

```text
1. persistir vault si hay cambios
2. desmontar runtime
3. limpiar claves y cajas
4. limpiar interfaz
5. cerrar proceso
```

## 30. Resultado final

Con esta arquitectura, el acceso no depende de un bloqueo visual. La aplicacion solo puede cargar su estado privado si el usuario introduce la secuencia completa y el vault se descifra correctamente.

Sin la secuencia correcta:

```text
el vault no autentica
la capa Livencrypt no se revierte
las plantillas no se cargan
los secretos no se montan
el dashboard no se ejecuta
```
