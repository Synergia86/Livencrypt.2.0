// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Almacenamiento seguro en RAM y encriptación de archivos locales mediante Argon2id */

#![allow(clippy::explicit_auto_deref)]

use crate::crypto::positional::PositionalCipher;
use crate::security::network_profile;
use crate::templates::{filelivencrypt_template, validate_template_for_scheduling, TemplateData};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &str = "LVCVAULT";
const FORMAT_VERSION: u16 = 4;
const CREDENTIAL_FORMAT_VERSION: u16 = 3;
const LEGACY_FORMAT_VERSION: u16 = 1;
const TEMPLATE_FORMAT_VERSION: u16 = 2;
const AEAD_ALGORITHM: &str = "xchacha20poly1305";
const KDF_ALGORITHM: &str = "argon2id";
const DEFAULT_BOOT_TEMPLATE_NAME: &str = "Livencrypt";
const CREDENTIAL_MODE_SINGLE: &str = "single";
const CREDENTIAL_MODE_DOUBLE: &str = "double";
const MAX_FAILED_ATTEMPTS: u32 = 5;
const WEB3_VAULT_KEY_SALT: &[u8] = b"LIVENCRYPT-WEB3-UNIVERSAL-VAULT-KEY-V1";
const FAKE_HW_ERROR: &str = "Error critico de integridad: la suma de comprobacion del encabezado no coincide. El volumen parece estar danado fisicamente (0x8004210B).";

#[derive(Clone, Serialize)]
pub struct BootShieldStatus {
    pub state: String,
    pub network_profile: String,
    pub credential_mode: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    Valid,
    Truncated,
    Deleted,
}

#[derive(Clone, Serialize, Deserialize)]
struct KdfParams {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
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

#[derive(Clone, Serialize, Deserialize)]
struct VaultHeader {
    magic: String,
    format_version: u16,
    kdf: KdfParams,
    salt: Vec<u8>,
    #[serde(default = "default_credential_mode")]
    credential_mode: String,
    #[serde(default)]
    secondary_salt: Vec<u8>,
    #[serde(default)]
    final_salt: Vec<u8>,
    aead: String,
    nonce: Vec<u8>,
    created_at_unix: u64,
    vault_counter: u64,
    object_names: Vec<String>,
    #[serde(default)]
    last_audit_anchor: Vec<u8>,
    #[serde(default)]
    suicide_bit: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultEnvelope {
    header: VaultHeader,
    ciphertext: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultDefenseState {
    failed_attempts: u32,
    duress_salt: Vec<u8>,
    duress_check: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultCipherBody {
    boot_template_name: String,
    boot_template: TemplateData,
    livencrypt_payload: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultAssociatedDataV1 {
    magic: String,
    format_version: u16,
    kdf: KdfParams,
    salt: Vec<u8>,
    aead: String,
    nonce: Vec<u8>,
    vault_counter: u64,
    object_names: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultAssociatedDataV3 {
    magic: String,
    format_version: u16,
    kdf: KdfParams,
    salt: Vec<u8>,
    credential_mode: String,
    secondary_salt: Vec<u8>,
    final_salt: Vec<u8>,
    aead: String,
    nonce: Vec<u8>,
    vault_counter: u64,
    object_names: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultAssociatedDataV4 {
    magic: String,
    format_version: u16,
    kdf: KdfParams,
    salt: Vec<u8>,
    credential_mode: String,
    secondary_salt: Vec<u8>,
    final_salt: Vec<u8>,
    aead: String,
    nonce: Vec<u8>,
    vault_counter: u64,
    object_names: Vec<String>,
    last_audit_anchor: Vec<u8>,
    suicide_bit: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    templates: HashMap<String, TemplateData>,
    settings: HashMap<String, String>,
    network_profile: String,
    metadata_version: u16,
    vault_counter: u64,
}

#[derive(Clone)]
struct BootMaterial {
    key: [u8; 32],
    cajas: [i64; 5],
    secondary_cajas: Option<[i64; 5]>,
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

impl BootMaterial {
    fn audit_key(&self) -> Result<[u8; 32], String> {
        let hk = Hkdf::<Sha256>::new(Some(b"LIVENCRYPT-AUDIT-SALT-V1"), &self.key);
        let mut key = [0u8; 32];
        hk.expand(b"LIVENCRYPT-AUDIT-HMAC-V1", &mut key)
            .map_err(|_| "No se pudo derivar clave de auditoria.".to_string())?;
        Ok(key)
    }
}

pub struct AccessSecret {
    cajas: [i64; 5],
    frase: SecretString,
}

impl Drop for AccessSecret {
    fn drop(&mut self) {
        self.cajas.zeroize();
    }
}

#[derive(Default)]
struct BootShieldRuntime {
    payload: Option<VaultPayload>,
    material: Option<BootMaterial>,
    header: Option<VaultHeader>,
    boot_template_name: Option<String>,
    boot_template: Option<TemplateData>,
}

impl Drop for BootShieldRuntime {
    fn drop(&mut self) {
        self.payload = None;
        self.material = None;
        self.header = None;
        self.boot_template_name = None;
        self.boot_template = None;
    }
}

static RUNTIME: OnceLock<Mutex<BootShieldRuntime>> = OnceLock::new();

fn runtime() -> &'static Mutex<BootShieldRuntime> {
    RUNTIME.get_or_init(|| Mutex::new(BootShieldRuntime::default()))
}

fn lock_runtime() -> MutexGuard<'static, BootShieldRuntime> {
    match runtime().lock() {
        Ok(runtime) => runtime,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn default_credential_mode() -> String {
    CREDENTIAL_MODE_SINGLE.to_string()
}

fn secure_dir() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("secure")
}

fn templates_dir() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("templates")
}

fn vault_path() -> PathBuf {
    secure_dir().join("vault.lvcvault")
}

fn vault_backup_path() -> PathBuf {
    secure_dir().join("vault.backup.lvcvault")
}

fn defense_state_path() -> PathBuf {
    secure_dir().join("vault.defense.msgpack")
}

pub fn vault_is_configured() -> bool {
    vault_path().exists()
}

fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

fn secure_overwrite_and_remove_file(path: &Path) -> Result<(), String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("No se pudo inspeccionar {:?}: {}", path, error)),
    };

    if !metadata.is_file() {
        return Ok(());
    }

    let target_path = if let Some(parent) = path.parent() {
        let random_name = format!(".livencrypt-wipe-{}", hex::encode(random_bytes(16)));
        let renamed = parent.join(random_name);
        match fs::rename(path, &renamed) {
            Ok(()) => renamed,
            Err(_) => path.to_path_buf(),
        }
    } else {
        path.to_path_buf()
    };

    let file_len = metadata.len();
    let mut file = OpenOptions::new()
        .write(true)
        .open(&target_path)
        .map_err(|error| {
            format!(
                "No se pudo abrir {:?} para limpieza: {}",
                target_path, error
            )
        })?;

    let mut remaining = file_len.max(1);
    while remaining > 0 {
        let chunk_len = remaining.min(64 * 1024) as usize;
        let chunk = random_bytes(chunk_len);
        file.write_all(&chunk)
            .map_err(|error| format!("No se pudo sobrescribir {:?}: {}", target_path, error))?;
        remaining = remaining.saturating_sub(chunk_len as u64);
    }
    file.sync_all()
        .map_err(|error| format!("No se pudo sincronizar {:?}: {}", target_path, error))?;
    drop(file);

    fs::remove_file(&target_path)
        .map_err(|error| format!("No se pudo borrar {:?}: {}", target_path, error))?;
    sync_parent_dir(&target_path);
    Ok(())
}

pub fn secure_delete_public_file(path: &Path) -> Result<(), String> {
    secure_overwrite_and_remove_file(path)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

fn default_defense_state() -> VaultDefenseState {
    VaultDefenseState {
        failed_attempts: 0,
        duress_salt: random_bytes(32),
        duress_check: random_bytes(32),
    }
}

fn normalize_secret(cajas: [i64; 5], mut frase: String) -> Result<AccessSecret, String> {
    if frase.trim().is_empty() {
        frase.zeroize();
        return Err("La frase de Boot Shield no puede estar vacia.".into());
    }

    let trimmed = frase.trim();
    let mut normalized_buffer = String::with_capacity(trimmed.len());
    normalized_buffer.push_str(trimmed);
    frase.zeroize();
    let normalized_frase = SecretString::new(normalized_buffer);

    Ok(AccessSecret {
        cajas,
        frase: normalized_frase,
    })
}

fn normalize_secondary_secret(
    cajas: Option<[i64; 5]>,
    frase: Option<String>,
) -> Result<Option<AccessSecret>, String> {
    match (cajas, frase) {
        (None, None) => Ok(None),
        (Some(_cajas), Some(frase)) if frase.trim().is_empty() => {
            let mut frase = frase;
            frase.zeroize();
            Err("La segunda frase de Boot Shield no puede estar vacia.".into())
        }
        (Some(cajas), Some(frase)) => normalize_secret(cajas, frase).map(Some),
        _ => Err("La doble credencial requiere segunda secuencia de cajas y segunda frase.".into()),
    }
}

fn canonical_secret(secret: &AccessSecret) -> SecretVec<u8> {
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

fn derive_key(secret: &AccessSecret, salt: &[u8], params: &KdfParams) -> Result<[u8; 32], String> {
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
    let result = argon.hash_password_into(material.expose_secret(), salt, &mut key);
    result.map_err(|error| format!("No se pudo derivar la clave Boot Shield: {}", error))?;
    Ok(key)
}

pub fn derive_vault_key(cajas: [i64; 5], master_phrase: &str) -> Result<[u8; 32], String> {
    let mut phrase = master_phrase.to_string();
    let secret = normalize_secret(cajas, phrase.clone())?;
    phrase.zeroize();
    derive_key(&secret, WEB3_VAULT_KEY_SALT, &KdfParams::default())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}

fn is_duress_key(secret: &AccessSecret, defense_state: &VaultDefenseState) -> bool {
    if defense_state.duress_salt.len() != 32 || defense_state.duress_check.len() != 32 {
        return false;
    }

    let params = KdfParams::default();
    let Ok(mut candidate) = derive_key(secret, &defense_state.duress_salt, &params) else {
        return false;
    };
    let matches = constant_time_eq(&candidate, &defense_state.duress_check);
    candidate.zeroize();
    matches
}

fn combine_derived_keys(
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

fn derive_material(
    primary: &AccessSecret,
    secondary: Option<&AccessSecret>,
    header: &VaultHeader,
) -> Result<BootMaterial, String> {
    if header.format_version < CREDENTIAL_FORMAT_VERSION
        || header.credential_mode == CREDENTIAL_MODE_SINGLE
    {
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

fn associated_data(header: &VaultHeader) -> Result<Vec<u8>, String> {
    if header.format_version >= FORMAT_VERSION {
        return rmp_serde::to_vec(&VaultAssociatedDataV4 {
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
            last_audit_anchor: header.last_audit_anchor.clone(),
            suicide_bit: header.suicide_bit,
        })
        .map_err(|error| format!("Error generando datos autenticados del vault: {}", error));
    }

    if header.format_version >= CREDENTIAL_FORMAT_VERSION {
        return rmp_serde::to_vec(&VaultAssociatedDataV3 {
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
        .map_err(|error| format!("Error generando datos autenticados del vault: {}", error));
    }

    rmp_serde::to_vec(&VaultAssociatedDataV1 {
        magic: header.magic.clone(),
        format_version: header.format_version,
        kdf: header.kdf.clone(),
        salt: header.salt.clone(),
        aead: header.aead.clone(),
        nonce: header.nonce.clone(),
        vault_counter: header.vault_counter,
        object_names: header.object_names.clone(),
    })
    .map_err(|error| format!("Error generando datos autenticados del vault: {}", error))
}

fn livencrypt_encode(payload_bytes: &[u8], cajas: [i64; 5], template: &TemplateData) -> Vec<u8> {
    let hex_payload = hex::encode(payload_bytes);
    let cipher = PositionalCipher::new(template.clone());
    cipher
        .cifrar_raw(
            &hex_payload,
            cajas[0],
            cajas[1],
            cajas[2],
            cajas[3],
            cajas[4],
        )
        .into_bytes()
}

fn livencrypt_decode(
    encoded: &[u8],
    cajas: [i64; 5],
    template: &TemplateData,
) -> Result<Vec<u8>, String> {
    let encoded_text = std::str::from_utf8(encoded)
        .map_err(|_| "La capa Livencrypt interna no es UTF-8 valido.".to_string())?;
    let cipher = PositionalCipher::new(template.clone());
    let decoded_hex = cipher.descifrar_raw(
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

fn livencrypt_encode_material(
    payload_bytes: &[u8],
    material: &BootMaterial,
    template: &TemplateData,
) -> Vec<u8> {
    let first_layer_cajas = material.secondary_cajas.unwrap_or(material.cajas);
    let first_layer = livencrypt_encode(payload_bytes, first_layer_cajas, template);
    if material.secondary_cajas.is_some() {
        livencrypt_encode(&first_layer, material.cajas, template)
    } else {
        first_layer
    }
}

fn livencrypt_decode_material(
    encoded: &[u8],
    material: &BootMaterial,
    template: &TemplateData,
) -> Result<Vec<u8>, String> {
    if let Some(secondary_cajas) = material.secondary_cajas {
        let inner_layer = livencrypt_decode(encoded, material.cajas, template)?;
        livencrypt_decode(&inner_layer, secondary_cajas, template)
    } else {
        livencrypt_decode(encoded, material.cajas, template)
    }
}

fn encrypt_payload(
    payload: &VaultPayload,
    material: &BootMaterial,
    mut header: VaultHeader,
    boot_template_name: &str,
    boot_template: &TemplateData,
) -> Result<VaultEnvelope, String> {
    if header.aead != AEAD_ALGORITHM {
        return Err(format!("AEAD no soportado: {}", header.aead));
    }

    header.object_names = payload.templates.keys().cloned().collect::<Vec<_>>();
    header.object_names.sort();
    header.nonce = random_bytes(24);
    let payload_bytes = rmp_serde::to_vec(payload)
        .map_err(|error| format!("Error serializando vault: {}", error))?;
    let body = VaultCipherBody {
        boot_template_name: boot_template_name.to_string(),
        boot_template: boot_template.clone(),
        livencrypt_payload: livencrypt_encode_material(&payload_bytes, material, boot_template),
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
        .map_err(|_| "No se pudo cifrar el vault Boot Shield.".to_string())?;

    Ok(VaultEnvelope { header, ciphertext })
}

fn decrypt_payload(
    envelope: &VaultEnvelope,
    secret: &AccessSecret,
    secondary_secret: Option<&AccessSecret>,
) -> Result<
    (
        VaultPayload,
        BootMaterial,
        VaultHeader,
        String,
        TemplateData,
    ),
    String,
> {
    if envelope.header.magic != MAGIC {
        return Err("Vault Boot Shield no reconocido.".into());
    }
    if envelope.header.format_version != FORMAT_VERSION
        && envelope.header.format_version != CREDENTIAL_FORMAT_VERSION
        && envelope.header.format_version != TEMPLATE_FORMAT_VERSION
        && envelope.header.format_version != LEGACY_FORMAT_VERSION
    {
        return Err(format!(
            "Version de vault no soportada: {}",
            envelope.header.format_version
        ));
    }
    if envelope.header.aead != AEAD_ALGORITHM {
        return Err(format!("AEAD no soportado: {}", envelope.header.aead));
    }
    if envelope.header.nonce.len() != 24 {
        return Err("Nonce XChaCha20-Poly1305 invalido.".into());
    }
    if envelope.header.suicide_bit {
        std::thread::sleep(std::time::Duration::from_millis(2_500));
        return Err(FAKE_HW_ERROR.to_string());
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
        .map_err(|_| "Credenciales invalidas o vault manipulado.".to_string())?;

    let (boot_template_name, boot_template, livencrypt_payload) =
        if envelope.header.format_version == LEGACY_FORMAT_VERSION {
            (
                DEFAULT_BOOT_TEMPLATE_NAME.to_string(),
                filelivencrypt_template(),
                plaintext,
            )
        } else {
            let body = rmp_serde::from_slice::<VaultCipherBody>(&plaintext)
                .map_err(|error| format!("Cuerpo cifrado del vault invalido: {}", error))?;
            (
                body.boot_template_name,
                body.boot_template,
                body.livencrypt_payload,
            )
        };

    let payload_bytes = livencrypt_decode_material(&livencrypt_payload, &material, &boot_template)?;
    let payload = rmp_serde::from_slice::<VaultPayload>(&payload_bytes)
        .map_err(|error| format!("No se pudo deserializar el vault: {}", error))?;
    Ok((
        payload,
        material,
        envelope.header.clone(),
        boot_template_name,
        boot_template,
    ))
}

fn new_header() -> VaultHeader {
    VaultHeader {
        magic: MAGIC.to_string(),
        format_version: FORMAT_VERSION,
        kdf: KdfParams::default(),
        salt: random_bytes(32),
        credential_mode: CREDENTIAL_MODE_SINGLE.to_string(),
        secondary_salt: Vec::new(),
        final_salt: Vec::new(),
        aead: AEAD_ALGORITHM.to_string(),
        nonce: Vec::new(),
        created_at_unix: unix_now(),
        vault_counter: 1,
        object_names: Vec::new(),
        last_audit_anchor: Vec::new(),
        suicide_bit: false,
    }
}

fn credential_mode_from_header(header: &VaultHeader) -> String {
    if header.format_version >= CREDENTIAL_FORMAT_VERSION
        && header.credential_mode == CREDENTIAL_MODE_DOUBLE
    {
        CREDENTIAL_MODE_DOUBLE.to_string()
    } else {
        CREDENTIAL_MODE_SINGLE.to_string()
    }
}

fn credential_mode_for_status() -> String {
    {
        let runtime = lock_runtime();
        if let Some(header) = runtime.header.as_ref() {
            return credential_mode_from_header(header);
        }
    }

    read_envelope()
        .map(|envelope| credential_mode_from_header(&envelope.header))
        .unwrap_or_else(|_| CREDENTIAL_MODE_SINGLE.to_string())
}

fn read_envelope() -> Result<VaultEnvelope, String> {
    let bytes =
        fs::read(vault_path()).map_err(|error| format!("No se pudo leer vault: {}", error))?;
    rmp_serde::from_slice::<VaultEnvelope>(&bytes)
        .map_err(|error| format!("Vault Boot Shield invalido: {}", error))
}

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Ruta sin directorio padre: {:?}", path))?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;

    let tmp_path = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("livencrypt")
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|error| format!("No se pudo abrir temporal {:?}: {}", tmp_path, error))?;
    file.write_all(bytes)
        .map_err(|error| format!("No se pudo escribir temporal {:?}: {}", tmp_path, error))?;
    file.sync_all()
        .map_err(|error| format!("No se pudo sincronizar temporal {:?}: {}", tmp_path, error))?;
    drop(file);

    fs::rename(&tmp_path, path)
        .map_err(|error| format!("No se pudo promover temporal {:?}: {}", tmp_path, error))?;
    sync_parent_dir(path);
    Ok(())
}

fn read_defense_state() -> VaultDefenseState {
    fs::read(defense_state_path())
        .ok()
        .and_then(|bytes| rmp_serde::from_slice::<VaultDefenseState>(&bytes).ok())
        .unwrap_or_else(default_defense_state)
}

fn write_defense_state(state: &VaultDefenseState) -> Result<(), String> {
    let bytes = rmp_serde::to_vec(state)
        .map_err(|error| format!("Error serializando estado de defensa: {}", error))?;
    write_bytes_atomically(&defense_state_path(), &bytes)
}

fn write_envelope(envelope: &VaultEnvelope) -> Result<(), String> {
    fs::create_dir_all(secure_dir()).map_err(|error| error.to_string())?;
    if vault_path().exists() {
        let backup_bytes = fs::read(vault_path())
            .map_err(|error| format!("No se pudo leer vault para backup: {}", error))?;
        write_bytes_atomically(&vault_backup_path(), &backup_bytes)
            .map_err(|error| format!("No se pudo crear backup atomico del vault: {}", error))?;
    }
    let bytes = rmp_serde::to_vec(envelope)
        .map_err(|error| format!("Error serializando vault: {}", error))?;
    write_bytes_atomically(&vault_path(), &bytes)
        .map_err(|error| format!("No se pudo escribir vault: {}", error))
}

fn check_audit_integrity_with_key(
    header: &VaultHeader,
    audit_key: Option<&[u8]>,
) -> IntegrityStatus {
    let log_path = secure_dir().join("audit.log");
    if !log_path.exists() {
        return if header.last_audit_anchor.is_empty() {
            IntegrityStatus::Valid
        } else {
            IntegrityStatus::Deleted
        };
    }

    let verification = if let Some(key) = audit_key {
        crate::security::audit::verify_audit_chain_with_key(&header.last_audit_anchor, key)
    } else {
        crate::security::audit::verify_audit_chain(&header.last_audit_anchor)
    };

    match verification {
        Ok(true) => IntegrityStatus::Valid,
        Ok(false) | Err(_) => IntegrityStatus::Truncated,
    }
}

fn check_audit_integrity(header: &VaultHeader) -> IntegrityStatus {
    check_audit_integrity_with_key(header, None)
}

pub fn current_integrity_status() -> IntegrityStatus {
    {
        let runtime = lock_runtime();
        if let Some(header) = runtime.header.as_ref() {
            return check_audit_integrity(header);
        }
    }

    read_envelope()
        .map(|envelope| check_audit_integrity(&envelope.header))
        .unwrap_or(IntegrityStatus::Valid)
}

pub fn get_mirage_decoys() -> HashMap<String, TemplateData> {
    HashMap::from([
        (
            "Network_Config_Old".to_string(),
            TemplateData {
                rows: 2,
                cols: 10,
                chars: vec![
                    "S", "E", "C", "R", "E", "T", "_", "K", "E", "Y", "0", "1", "2", "3", "4", "5",
                    "6", "7", "8", "9",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            },
        ),
        (
            "Master_Vault_Backup".to_string(),
            TemplateData {
                rows: 5,
                cols: 5,
                chars: (0..25).map(|_| "X".to_string()).collect(),
            },
        ),
        ("Config_Old".to_string(), filelivencrypt_template()),
    ])
}

fn read_templates_from_disk() -> Result<HashMap<String, TemplateData>, String> {
    let dir_path = templates_dir();
    let mut templates = HashMap::new();

    if !dir_path.exists() {
        return Ok(templates);
    }

    for entry in fs::read_dir(dir_path).map_err(|error| error.to_string())? {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("msgpack") {
            continue;
        }
        let content = fs::read(&path).map_err(|error| error.to_string())?;
        let data = rmp_serde::from_slice::<TemplateData>(&content)
            .map_err(|error| format!("Plantilla msgpack invalida: {}", error))?;
        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        templates.insert(name, data);
    }

    Ok(templates)
}

fn validate_boot_template(name: &str, template: &TemplateData) -> Result<(), String> {
    validate_template_for_scheduling(template)
        .map_err(|error| format!("Plantilla Boot Shield '{}' no valida: {}", name, error))?;

    let required = [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
    ];
    let missing = required
        .iter()
        .filter(|value| {
            !template
                .chars
                .iter()
                .any(|char_value| char_value == **value)
        })
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

fn resolve_boot_template(
    templates: &HashMap<String, TemplateData>,
    selected_name: Option<String>,
) -> Result<(String, TemplateData), String> {
    let requested_name = selected_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_BOOT_TEMPLATE_NAME);

    let template = templates
        .get(requested_name)
        .cloned()
        .or_else(|| {
            if requested_name == DEFAULT_BOOT_TEMPLATE_NAME || requested_name == "filelivencrypt" {
                Some(filelivencrypt_template())
            } else {
                None
            }
        })
        .ok_or_else(|| format!("Plantilla Boot Shield no encontrada: {}", requested_name))?;

    validate_boot_template(requested_name, &template)?;
    Ok((requested_name.to_string(), template))
}

fn write_templates_to_disk(templates: &HashMap<String, TemplateData>) -> Result<(), String> {
    fs::create_dir_all(templates_dir()).map_err(|error| error.to_string())?;
    for (name, data) in templates {
        let bytes = rmp_serde::to_vec(data)
            .map_err(|error| format!("Error serializando plantilla {}: {}", name, error))?;
        write_bytes_atomically(&templates_dir().join(format!("{}.msgpack", name)), &bytes)
            .map_err(|error| format!("No se pudo restaurar plantilla {}: {}", name, error))?;
    }
    Ok(())
}

fn purge_plaintext_templates_from_disk() -> Result<(), String> {
    let dir_path = templates_dir();
    if !dir_path.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir_path).map_err(|error| error.to_string())? {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("msgpack") {
            secure_overwrite_and_remove_file(&path).map_err(|error| {
                format!("No se pudo purgar plantilla plana {:?}: {}", path, error)
            })?;
        }
    }

    Ok(())
}

fn persist_runtime(runtime: &mut BootShieldRuntime) -> Result<(), String> {
    let payload = runtime
        .payload
        .as_ref()
        .ok_or_else(|| "Boot Shield no esta desbloqueado.".to_string())?;
    let material = runtime
        .material
        .as_ref()
        .ok_or_else(|| "Material criptografico no disponible.".to_string())?;
    let header = runtime
        .header
        .as_ref()
        .ok_or_else(|| "Cabecera Boot Shield no disponible.".to_string())?;
    let boot_template_name = runtime
        .boot_template_name
        .as_ref()
        .ok_or_else(|| "Plantilla Boot Shield no disponible.".to_string())?;
    let boot_template = runtime
        .boot_template
        .as_ref()
        .ok_or_else(|| "Plantilla Boot Shield no disponible.".to_string())?;

    let mut payload = payload.clone();
    let mut header = header.clone();
    header.vault_counter = header.vault_counter.saturating_add(1);
    payload.vault_counter = header.vault_counter;
    let envelope = encrypt_payload(
        &payload,
        material,
        header.clone(),
        boot_template_name,
        boot_template,
    )?;
    runtime.payload = Some(payload);
    runtime.header = Some(envelope.header.clone());
    write_envelope(&envelope)
}

pub fn boot_shield_status() -> Result<BootShieldStatus, String> {
    let unlocked = lock_runtime().payload.is_some();
    let state = if !vault_is_configured() {
        "not_configured"
    } else if unlocked {
        "unlocked"
    } else {
        "locked"
    };

    Ok(BootShieldStatus {
        state: state.to_string(),
        network_profile: network_profile::selected_network_profile_label(),
        credential_mode: if vault_is_configured() {
            credential_mode_for_status()
        } else {
            CREDENTIAL_MODE_SINGLE.to_string()
        },
    })
}

pub fn boot_shield_enable(
    cajas: [i64; 5],
    frase: String,
    boot_template_name: Option<String>,
    secondary_cajas: Option<[i64; 5]>,
    secondary_frase: Option<String>,
) -> Result<BootShieldStatus, String> {
    boot_shield_enable_impl(
        cajas,
        frase,
        boot_template_name,
        secondary_cajas,
        secondary_frase,
    )
}

fn boot_shield_enable_impl(
    cajas: [i64; 5],
    frase: String,
    boot_template_name: Option<String>,
    secondary_cajas: Option<[i64; 5]>,
    secondary_frase: Option<String>,
) -> Result<BootShieldStatus, String> {
    if vault_is_configured() {
        return Err("Boot Shield ya esta configurado.".into());
    }

    let secret = normalize_secret(cajas, frase)?;
    let secondary_secret = normalize_secondary_secret(secondary_cajas, secondary_frase)?;
    let mut header = new_header();
    if secondary_secret.is_some() {
        header.credential_mode = CREDENTIAL_MODE_DOUBLE.to_string();
        header.secondary_salt = random_bytes(32);
        header.final_salt = random_bytes(32);
    }
    let material = derive_material(&secret, secondary_secret.as_ref(), &header)?;
    let templates = read_templates_from_disk()?;
    let (boot_template_name, boot_template) =
        resolve_boot_template(&templates, boot_template_name)?;
    let payload = VaultPayload {
        templates,
        settings: HashMap::new(),
        network_profile: network_profile::selected_network_profile_label(),
        metadata_version: 1,
        vault_counter: header.vault_counter,
    };
    let envelope = encrypt_payload(
        &payload,
        &material,
        header,
        &boot_template_name,
        &boot_template,
    )?;
    let (
        _verified_payload,
        _verified_material,
        _verified_header,
        _verified_template_name,
        _verified_template,
    ) = decrypt_payload(&envelope, &secret, secondary_secret.as_ref())?;

    write_envelope(&envelope)?;
    write_defense_state(&default_defense_state())?;

    if let Err(error) = decrypt_payload(&read_envelope()?, &secret, secondary_secret.as_ref()) {
        let _ = secure_overwrite_and_remove_file(&vault_path());
        let _ = secure_overwrite_and_remove_file(&vault_backup_path());
        let _ = secure_overwrite_and_remove_file(&defense_state_path());
        return Err(format!("Verificacion del vault escrito fallida: {}", error));
    }

    purge_plaintext_templates_from_disk()?;

    let mut runtime = lock_runtime();
    runtime.payload = Some(payload);
    runtime.material = Some(material);
    runtime.header = Some(envelope.header);
    runtime.boot_template_name = Some(boot_template_name);
    runtime.boot_template = Some(boot_template);
    let audit_anchor = runtime
        .material
        .as_ref()
        .and_then(|material| material.audit_key().ok())
        .and_then(|audit_key| {
            crate::security::audit::append_authenticated_event(
                "BOOT_SHIELD_ENABLE",
                "vault_created",
                &audit_key,
            )
            .ok()
        })
        .or_else(|| {
            crate::security::audit::append_audit_event("BOOT_SHIELD_ENABLE", "vault_created").ok()
        });

    if let Some(anchor) = audit_anchor {
        if let Some(header) = runtime.header.as_mut() {
            header.last_audit_anchor = anchor;
        }
        let _ = persist_runtime(&mut runtime);
    }
    drop(runtime);

    boot_shield_status()
}

pub fn boot_shield_unlock(
    cajas: [i64; 5],
    frase: String,
    secondary_cajas: Option<[i64; 5]>,
    secondary_frase: Option<String>,
) -> Result<BootShieldStatus, String> {
    boot_shield_unlock_impl(cajas, frase, secondary_cajas, secondary_frase)
}

fn boot_shield_unlock_impl(
    cajas: [i64; 5],
    frase: String,
    secondary_cajas: Option<[i64; 5]>,
    secondary_frase: Option<String>,
) -> Result<BootShieldStatus, String> {
    if !vault_is_configured() {
        return Err("Boot Shield no esta configurado.".into());
    }

    let envelope = read_envelope()?;
    let mut defense_state = read_defense_state();
    let secret = normalize_secret(cajas, frase)?;
    let secondary_secret = normalize_secondary_secret(secondary_cajas, secondary_frase)?;
    match decrypt_payload(&envelope, &secret, secondary_secret.as_ref()) {
        Ok((mut payload, material, mut header, boot_template_name, boot_template)) => {
            if defense_state.failed_attempts != 0 {
                defense_state.failed_attempts = 0;
                write_defense_state(&defense_state)?;
            }

            let audit_key = material.audit_key()?;
            let integrity = check_audit_integrity_with_key(&header, Some(&audit_key));
            if matches!(integrity, IntegrityStatus::Valid) {
                crate::security::audit::absorb_tombstones()?;
                header.last_audit_anchor = crate::security::audit::append_authenticated_event(
                    "VAULT_OPEN",
                    "boot_shield_unlock",
                    &audit_key,
                )?;
            } else {
                payload.templates = get_mirage_decoys();
                payload
                    .settings
                    .insert("mirage_mode".into(), format!("{:?}", integrity));
            }

            let mut runtime = lock_runtime();
            runtime.payload = Some(payload);
            runtime.material = Some(material);
            runtime.header = Some(header);
            runtime.boot_template_name = Some(boot_template_name);
            runtime.boot_template = Some(boot_template);
            if matches!(integrity, IntegrityStatus::Valid) {
                persist_runtime(&mut runtime)?;
            }
            drop(runtime);

            boot_shield_status()
        }
        Err(_) => {
            let _ = crate::security::audit::register_tombstone("ACCESS_FAILED");

            if is_duress_key(&secret, &defense_state) {
                let _ = boot_shield_destructive_panic("DESTRUIR VAULT Y PLANTILLAS".into());
                return Err(FAKE_HW_ERROR.to_string());
            }

            defense_state.failed_attempts = defense_state.failed_attempts.saturating_add(1);
            write_defense_state(&defense_state)?;

            if defense_state.failed_attempts >= MAX_FAILED_ATTEMPTS {
                let _ = boot_shield_destructive_panic("DESTRUIR VAULT Y PLANTILLAS".into());
                return Err(FAKE_HW_ERROR.to_string());
            }

            Err("Credenciales invalidas o vault manipulado.".into())
        }
    }
}

pub fn boot_shield_lock() -> Result<BootShieldStatus, String> {
    let mut runtime = lock_runtime();
    runtime.payload = None;
    runtime.material = None;
    runtime.header = None;
    runtime.boot_template_name = None;
    runtime.boot_template = None;
    drop(runtime);
    boot_shield_status()
}

pub fn boot_shield_hardened_lock() -> Result<BootShieldStatus, String> {
    let status = boot_shield_lock()?;
    if vault_is_configured() {
        purge_plaintext_templates_from_disk()?;
    }
    Ok(status)
}

pub fn boot_shield_destructive_panic(confirmation: String) -> Result<(), String> {
    if confirmation.trim() != "DESTRUIR VAULT Y PLANTILLAS" {
        return Err(
            "Debe escribir DESTRUIR VAULT Y PLANTILLAS para ejecutar panico destructivo.".into(),
        );
    }

    boot_shield_lock()?;
    secure_overwrite_and_remove_file(&vault_path())?;
    secure_overwrite_and_remove_file(&vault_backup_path())?;
    secure_overwrite_and_remove_file(&defense_state_path())?;

    let dir_path = templates_dir();
    if dir_path.exists() {
        purge_plaintext_templates_from_disk()?;
        fs::remove_dir_all(&dir_path)
            .map_err(|error| format!("No se pudo eliminar directorio de plantillas: {}", error))?;
    }

    let local_data_dir = crate::livencrypt_base_dir().join(".livencrypt");
    if local_data_dir.exists() {
        fs::remove_dir_all(&local_data_dir).map_err(|error| {
            format!(
                "No se pudo eliminar directorio local Livencrypt {:?}: {}",
                local_data_dir, error
            )
        })?;
    }

    Ok(())
}

pub fn boot_shield_disable(
    cajas: [i64; 5],
    frase: String,
    secondary_cajas: Option<[i64; 5]>,
    secondary_frase: Option<String>,
) -> Result<BootShieldStatus, String> {
    if !vault_is_configured() {
        return boot_shield_status();
    }

    let envelope = read_envelope()?;
    let secret = normalize_secret(cajas, frase)?;
    let secondary_secret = normalize_secondary_secret(secondary_cajas, secondary_frase)?;
    let (payload, _material, _header, _boot_template_name, _boot_template) =
        decrypt_payload(&envelope, &secret, secondary_secret.as_ref())?;
    write_templates_to_disk(&payload.templates)?;
    secure_overwrite_and_remove_file(&vault_path())
        .map_err(|error| format!("No se pudo eliminar vault: {}", error))?;
    secure_overwrite_and_remove_file(&vault_backup_path())
        .map_err(|error| format!("No se pudo eliminar backup del vault: {}", error))?;
    secure_overwrite_and_remove_file(&defense_state_path())
        .map_err(|error| format!("No se pudo eliminar estado de defensa del vault: {}", error))?;

    let mut runtime = lock_runtime();
    runtime.payload = None;
    runtime.material = None;
    runtime.header = None;
    runtime.boot_template_name = None;
    runtime.boot_template = None;
    drop(runtime);
    boot_shield_status()
}

pub fn boot_shield_factory_reset(confirmation: String) -> Result<BootShieldStatus, String> {
    if confirmation.trim() != "RESTABLECER" {
        return Err("Debe escribir RESTABLECER para borrar el Boot Shield local.".into());
    }

    let base_dir = crate::livencrypt_base_dir();
    if !base_dir.is_absolute()
        || base_dir.file_name().and_then(|name| name.to_str()) != Some("livencrypt")
    {
        return Err(format!(
            "Ruta de datos Livencrypt no segura para restablecer: {:?}",
            base_dir
        ));
    }

    boot_shield_lock()?;
    secure_overwrite_and_remove_file(&vault_path())?;
    secure_overwrite_and_remove_file(&vault_backup_path())?;
    secure_overwrite_and_remove_file(&defense_state_path())?;

    let dir_path = templates_dir();
    if dir_path.exists() {
        purge_plaintext_templates_from_disk()?;
        fs::remove_dir_all(&dir_path)
            .map_err(|error| format!("No se pudo eliminar directorio de plantillas: {}", error))?;
    }

    boot_shield_status()
}

pub fn try_load_unlocked_templates() -> Result<Option<HashMap<String, TemplateData>>, String> {
    if !vault_is_configured() {
        return Ok(None);
    }

    let runtime = lock_runtime();
    match runtime.payload.as_ref() {
        Some(payload) => {
            if runtime.header.as_ref().is_some_and(|header| {
                !matches!(check_audit_integrity(header), IntegrityStatus::Valid)
            }) {
                return Ok(Some(get_mirage_decoys()));
            }
            Ok(Some(payload.templates.clone()))
        }
        None => Err("Boot Shield activo: vault bloqueado.".into()),
    }
}

pub fn save_template_to_unlocked_vault(name: String, data: TemplateData) -> Result<bool, String> {
    if !vault_is_configured() {
        return Ok(false);
    }

    let mut runtime = lock_runtime();
    if runtime
        .header
        .as_ref()
        .is_some_and(|header| !matches!(check_audit_integrity(header), IntegrityStatus::Valid))
    {
        let _ = crate::security::audit::append_audit_event("MIRAGE_WRITE_DISCARDED", &name);
        return Ok(true);
    }
    let payload = runtime
        .payload
        .as_mut()
        .ok_or_else(|| "Boot Shield activo: vault bloqueado.".to_string())?;
    payload.templates.insert(name, data);
    persist_runtime(&mut runtime)?;
    Ok(true)
}

pub fn delete_template_from_unlocked_vault(name: &str) -> Result<bool, String> {
    if !vault_is_configured() {
        return Ok(false);
    }

    let mut runtime = lock_runtime();
    if runtime
        .header
        .as_ref()
        .is_some_and(|header| !matches!(check_audit_integrity(header), IntegrityStatus::Valid))
    {
        let _ = crate::security::audit::append_audit_event("MIRAGE_DELETE_DISCARDED", name);
        return Ok(true);
    }
    let payload = runtime
        .payload
        .as_mut()
        .ok_or_else(|| "Boot Shield activo: vault bloqueado.".to_string())?;
    if payload.templates.remove(name).is_none() {
        return Err(format!("Plantilla '{}' no encontrada", name));
    }
    persist_runtime(&mut runtime)?;
    Ok(true)
}

pub fn update_unlocked_network_profile(profile: &str) -> Result<(), String> {
    if !vault_is_configured() {
        return Ok(());
    }

    let mut runtime = lock_runtime();
    let Some(payload) = runtime.payload.as_mut() else {
        return Ok(());
    };
    payload.network_profile = profile.to_string();
    persist_runtime(&mut runtime)
}

pub fn read_unlocked_settings() -> Result<Option<HashMap<String, String>>, String> {
    if !vault_is_configured() {
        return Ok(None);
    }

    let runtime = lock_runtime();
    let payload = runtime
        .payload
        .as_ref()
        .ok_or_else(|| "Boot Shield activo: vault bloqueado.".to_string())?;
    Ok(Some(payload.settings.clone()))
}

pub fn update_unlocked_settings(entries: HashMap<String, String>) -> Result<bool, String> {
    if !vault_is_configured() {
        return Ok(false);
    }

    let mut runtime = lock_runtime();
    let payload = runtime
        .payload
        .as_mut()
        .ok_or_else(|| "Boot Shield activo: vault bloqueado.".to_string())?;
    for (key, value) in entries {
        payload.settings.insert(key, value);
    }
    persist_runtime(&mut runtime)?;
    Ok(true)
}

pub fn apply_emergency_anchor_update(new_anchor: Vec<u8>) -> Result<(), String> {
    if !vault_is_configured() {
        return Err("Boot Shield no esta configurado.".into());
    }

    let mut runtime = lock_runtime();
    let header = runtime
        .header
        .as_mut()
        .ok_or_else(|| "Boot Shield activo: vault bloqueado.".to_string())?;
    header.last_audit_anchor = new_anchor;
    header.suicide_bit = false;
    persist_runtime(&mut runtime)?;
    Ok(())
}

pub fn finalize_update_handover() -> Result<(), String> {
    if !vault_is_configured() {
        return Err("Boot Shield no esta configurado.".into());
    }

    let verified = crate::security::updates::verify_pending_update()?
        .ok_or_else(|| "No hay update pendiente en staging.".to_string())?;
    if !verified {
        return Err("Update pendiente no verifica firma/hash.".into());
    }

    let payload_path = crate::security::updates::payload_path_for_handover();
    let mut payload_bytes =
        fs::read(&payload_path).map_err(|error| format!("No se pudo leer staging: {}", error))?;
    let payload_hash = hex::encode(sha2::Sha256::digest(&payload_bytes));

    let mut runtime = lock_runtime();
    let payload = runtime
        .payload
        .as_mut()
        .ok_or_else(|| "Boot Shield activo: vault bloqueado.".to_string())?;
    payload
        .settings
        .insert("last_update_payload_sha256".into(), payload_hash);
    payload
        .settings
        .insert("last_update_applied_at_unix".into(), unix_now().to_string());
    payload_bytes.zeroize();
    persist_runtime(&mut runtime)?;
    drop(runtime);

    crate::security::audit::append_audit_event("UPDATE_HANDOVER", "staging_payload_verified")?;
    crate::security::updates::clear_staging()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_livencrypt_layer_roundtrips_single_credential() {
        let material = BootMaterial {
            key: [7u8; 32],
            cajas: [11, 22, 33, 44, 55],
            secondary_cajas: None,
        };
        let template = filelivencrypt_template();
        let payload = b"vault payload with msgpack-like bytes \x00\x01\x02";

        let encoded = livencrypt_encode_material(payload, &material, &template);
        let decoded = livencrypt_decode_material(&encoded, &material, &template)
            .expect("internal Livencrypt layer must decode");

        assert_eq!(decoded, payload);
    }

    #[test]
    fn encrypt_payload_roundtrips_before_disk_write() {
        let primary = AccessSecret {
            cajas: [1, 2, 3, 4, 5],
            frase: SecretString::new("frase de prueba".to_string()),
        };
        let header = new_header();
        let material = derive_material(&primary, None, &header).expect("key derivation");
        let template = filelivencrypt_template();
        let mut templates = HashMap::new();
        templates.insert(DEFAULT_BOOT_TEMPLATE_NAME.to_string(), template.clone());
        let payload = VaultPayload {
            templates,
            settings: HashMap::new(),
            network_profile: "mock".to_string(),
            metadata_version: 1,
            vault_counter: 1,
        };

        let envelope = encrypt_payload(
            &payload,
            &material,
            header,
            DEFAULT_BOOT_TEMPLATE_NAME,
            &template,
        )
        .expect("vault encryption");
        let secret = AccessSecret {
            cajas: [1, 2, 3, 4, 5],
            frase: SecretString::new("frase de prueba".to_string()),
        };
        let (decoded_payload, _, _, boot_template_name, _) =
            decrypt_payload(&envelope, &secret, None).expect("vault decrypt");

        assert_eq!(boot_template_name, DEFAULT_BOOT_TEMPLATE_NAME);
        assert!(decoded_payload
            .templates
            .contains_key(DEFAULT_BOOT_TEMPLATE_NAME));
    }

    #[test]
    #[ignore]
    fn boot_shield_single_credential_enable_lock_unlock_roundtrip() {
        let temp_root = std::env::temp_dir().join(format!(
            "livencrypt-boot-shield-test-{}",
            hex::encode(random_bytes(8))
        ));
        std::env::set_var("XDG_DATA_HOME", &temp_root);

        let templates_path = templates_dir();
        fs::create_dir_all(&templates_path).expect("create template dir");
        let template_bytes =
            rmp_serde::to_vec(&filelivencrypt_template()).expect("serialize template");
        fs::write(
            templates_path.join(format!("{}.msgpack", DEFAULT_BOOT_TEMPLATE_NAME)),
            template_bytes,
        )
        .expect("write template");

        let cajas = [10, 20, 30, 40, 50];
        let frase = "frase interna de prueba";
        let enabled = boot_shield_enable_impl(
            cajas,
            frase.to_string(),
            Some(DEFAULT_BOOT_TEMPLATE_NAME.to_string()),
            None,
            None,
        )
        .expect("enable boot shield");
        assert_eq!(enabled.state, "unlocked");
        assert!(vault_path().exists());
        assert!(!templates_path
            .join(format!("{}.msgpack", DEFAULT_BOOT_TEMPLATE_NAME))
            .exists());

        boot_shield_lock().expect("lock runtime");
        assert_eq!(boot_shield_status().expect("status").state, "locked");

        let unlocked = boot_shield_unlock_impl(cajas, frase.to_string(), None, None)
            .expect("unlock boot shield");
        assert_eq!(unlocked.state, "unlocked");
        let templates = try_load_unlocked_templates()
            .expect("load unlocked templates")
            .expect("templates mounted");
        assert!(templates.contains_key(DEFAULT_BOOT_TEMPLATE_NAME));

        boot_shield_factory_reset("RESTABLECER".to_string()).expect("factory reset");
        let _ = fs::remove_dir_all(temp_root);
    }
}
