// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Registro táctico y auditoría del sistema de archivos e integridad de memoria */

use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ForensicReport {
    pub timestamp_unix: u64,
    pub operation: String,
    pub source_path: String,
    pub result_path: String,
    pub source_hash: String,
    pub result_hash: String,
    pub duration_ms: u128,
    pub success: bool,
    pub signature_scheme: String,
    pub signature: Vec<u8>,
}

fn secure_dir() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("secure")
}

fn signing_seed_path() -> PathBuf {
    secure_dir().join("forensic_ed25519.seed")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

fn read_or_create_signing_key() -> Result<SigningKey, String> {
    let path = signing_seed_path();
    if let Ok(seed) = fs::read(&path) {
        if seed.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&seed);
            return Ok(SigningKey::from_bytes(&bytes));
        }
    }

    let parent = path
        .parent()
        .ok_or_else(|| "Ruta de clave forense invalida.".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;

    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|error| format!("No se pudo crear clave forense: {}", error))?;
    file.write_all(&seed)
        .map_err(|error| format!("No se pudo escribir clave forense: {}", error))?;
    file.sync_all()
        .map_err(|error| format!("No se pudo sincronizar clave forense: {}", error))?;
    drop(file);
    sync_parent_dir(&path);
    Ok(SigningKey::from_bytes(&seed))
}

fn calculate_hash(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("No se pudo abrir archivo para hash: {}", error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("No se pudo leer archivo para hash: {}", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        buffer[..read].zeroize();
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn generate_file_report(
    operation: &str,
    source_path: &Path,
    result_path: &Path,
    duration_ms: u128,
) -> Result<ForensicReport, String> {
    let signing_key = read_or_create_signing_key()?;
    let mut report = ForensicReport {
        timestamp_unix: unix_now(),
        operation: operation.to_string(),
        source_path: source_path.display().to_string(),
        result_path: result_path.display().to_string(),
        source_hash: calculate_hash(source_path)?,
        result_hash: calculate_hash(result_path)?,
        duration_ms,
        success: true,
        signature_scheme: "ed25519-local-v1".to_string(),
        signature: Vec::new(),
    };

    let payload = rmp_serde::to_vec(&report)
        .map_err(|error| format!("No se pudo serializar reporte forense: {}", error))?;
    report.signature = signing_key.sign(&payload).to_bytes().to_vec();
    let _ = crate::security::audit::append_audit_event(
        "FILE_FORENSIC_REPORT",
        &format!("{}:{}", operation, report.result_hash),
    );
    Ok(report)
}

pub fn export_report(report: &ForensicReport, result_path: &Path) -> Result<PathBuf, String> {
    let report_path = result_path.with_extension(format!(
        "{}lvc_report",
        result_path
            .extension()
            .and_then(|value| value.to_str())
            .map(|_| "")
            .unwrap_or("")
    ));
    let bytes = rmp_serde::to_vec(report)
        .map_err(|error| format!("No se pudo serializar reporte forense: {}", error))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&report_path)
        .map_err(|error| format!("No se pudo crear reporte forense: {}", error))?;
    file.write_all(&bytes)
        .map_err(|error| format!("No se pudo escribir reporte forense: {}", error))?;
    file.sync_all()
        .map_err(|error| format!("No se pudo sincronizar reporte forense: {}", error))?;
    drop(file);
    sync_parent_dir(&report_path);
    Ok(report_path)
}
