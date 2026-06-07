// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Orquestador seguro de comprobación y despliegue de parches locales */

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub created_at_unix: u64,
    pub changelog: String,
    pub payload_sha256: String,
    pub signature: Vec<u8>,
}

fn staging_dir() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("staging")
}

fn manifest_path() -> PathBuf {
    staging_dir().join("update.manifest")
}

fn payload_path() -> PathBuf {
    staging_dir().join("shadow_payload.bin")
}

fn system_update_key_path() -> PathBuf {
    PathBuf::from("/etc/livencrypt/update_public.key")
}

fn signed_manifest_bytes(manifest: &UpdateManifest) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"LIVENCRYPT-UPDATE-MANIFEST-V1|");
    bytes.extend_from_slice(manifest.version.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&manifest.created_at_unix.to_le_bytes());
    bytes.extend_from_slice(manifest.changelog.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(manifest.payload_sha256.as_bytes());
    bytes
}

fn read_public_key(path: &Path) -> Result<[u8; 32], String> {
    let value = fs::read_to_string(path)
        .map_err(|error| format!("No se pudo leer clave publica {:?}: {}", path, error))?;
    crate::security::recovery::parse_public_key_hex(&value)
}

pub fn inspect_pending_update() -> Result<Option<UpdateManifest>, String> {
    let path = manifest_path();
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let manifest: UpdateManifest =
        rmp_serde::from_slice(&bytes).map_err(|error| error.to_string())?;
    Ok(Some(manifest))
}

pub fn verify_payload_hash(manifest: &UpdateManifest) -> Result<bool, String> {
    let payload = fs::read(payload_path()).map_err(|error| error.to_string())?;
    Ok(hex::encode(Sha256::digest(&payload)) == manifest.payload_sha256)
}

pub fn verify_manifest_signature(manifest: &UpdateManifest) -> Result<bool, String> {
    let key = read_public_key(&system_update_key_path())?;
    let public_key = VerifyingKey::from_bytes(&key)
        .map_err(|_| "Clave publica de update invalida.".to_string())?;
    let signature = Signature::from_slice(&manifest.signature)
        .map_err(|_| "Firma de update invalida.".to_string())?;
    Ok(public_key
        .verify(&signed_manifest_bytes(manifest), &signature)
        .is_ok())
}

pub fn verify_pending_update() -> Result<Option<bool>, String> {
    let Some(manifest) = inspect_pending_update()? else {
        return Ok(None);
    };
    Ok(Some(
        verify_payload_hash(&manifest)? && verify_manifest_signature(&manifest)?,
    ))
}

pub fn clear_staging() -> Result<(), String> {
    let dir = staging_dir();
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&dir).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_file() {
            crate::security::vault::secure_delete_public_file(&path)?;
        }
    }
    fs::remove_dir_all(dir).map_err(|error| error.to_string())?;
    Ok(())
}

pub fn payload_path_for_handover() -> PathBuf {
    payload_path()
}
