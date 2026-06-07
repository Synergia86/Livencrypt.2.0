// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Algoritmos de descifrado alternativos y recuperación por frases mnemónicas físicas */

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryPayload {
    pub version: u32,
    pub timestamp_unix: u64,
    pub vault_id: Vec<u8>,
    pub anchor_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

fn system_recovery_key_path() -> PathBuf {
    PathBuf::from("/etc/livencrypt/recovery_public.key")
}

fn signed_recovery_bytes(payload: &RecoveryPayload) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"LIVENCRYPT-RECOVERY-V1|");
    bytes.extend_from_slice(&payload.version.to_le_bytes());
    bytes.extend_from_slice(&payload.timestamp_unix.to_le_bytes());
    bytes.extend_from_slice(&payload.vault_id);
    bytes.extend_from_slice(&payload.anchor_hash);
    bytes
}

pub fn parse_public_key_hex(value: &str) -> Result<[u8; 32], String> {
    let normalized = value
        .trim()
        .trim_start_matches("0x")
        .split_whitespace()
        .collect::<String>();
    let bytes = hex::decode(normalized)
        .map_err(|error| format!("Clave publica Ed25519 no es HEX valido: {}", error))?;
    bytes
        .try_into()
        .map_err(|_| "Clave publica Ed25519 debe tener 32 bytes.".to_string())
}

pub fn read_system_public_key() -> Result<[u8; 32], String> {
    let value = fs::read_to_string(system_recovery_key_path())
        .map_err(|error| format!("No se pudo leer clave publica de recuperacion: {}", error))?;
    parse_public_key_hex(&value)
}

pub fn verify_recovery_file(
    path: &Path,
    public_key_bytes: &[u8; 32],
) -> Result<RecoveryPayload, String> {
    let bytes = fs::read(path).map_err(|error| format!("No se pudo leer recovery: {}", error))?;
    let payload: RecoveryPayload =
        rmp_serde::from_slice(&bytes).map_err(|error| format!("Recovery invalido: {}", error))?;

    if payload.version != 1 {
        return Err(format!(
            "Version de recovery no soportada: {}",
            payload.version
        ));
    }
    if payload.anchor_hash.len() != 32 && !payload.anchor_hash.is_empty() {
        return Err("Anchor de recovery debe tener 32 bytes o estar vacio.".into());
    }

    let public_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|_| "Clave publica de recuperacion invalida.".to_string())?;
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| "Firma de recovery invalida.".to_string())?;

    public_key
        .verify(&signed_recovery_bytes(&payload), &signature)
        .map_err(|_| "Recovery no autentico: firma Ed25519 incorrecta.".to_string())?;

    Ok(payload)
}

pub fn verify_recovery_file_with_system_key(path: &Path) -> Result<RecoveryPayload, String> {
    let key = read_system_public_key()?;
    verify_recovery_file(path, &key)
}

pub fn apply_recovery_file(path: &Path) -> Result<(), String> {
    let payload = verify_recovery_file_with_system_key(path)?;
    crate::security::vault::apply_emergency_anchor_update(payload.anchor_hash)?;
    let _ = crate::security::audit::append_audit_event("RECOVERY_APPLIED", "ed25519_recovery_file");
    Ok(())
}
