// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Motor de escaneo local para evaluar vectores de ataque */

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp_unix: u64,
    pub event_type: String,
    pub details: String,
    pub prev_hash: Vec<u8>,
    #[serde(default = "default_signature_scheme")]
    pub signature_scheme: String,
    pub signature: Vec<u8>,
}

impl AuditEntry {
    pub fn calculate_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_le_bytes());
        hasher.update(self.timestamp_unix.to_le_bytes());
        hasher.update(self.event_type.as_bytes());
        hasher.update(self.details.as_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.signature);
        hasher.finalize().to_vec()
    }
}

fn default_signature_scheme() -> String {
    "local-sha256-v1".to_string()
}

fn secure_dir() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("secure")
}

fn audit_log_path() -> PathBuf {
    secure_dir().join("audit.log")
}

fn tombstone_path() -> PathBuf {
    secure_dir().join("vault.tombstone")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
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

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Ruta sin directorio padre: {:?}", path))?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;

    let tmp_path = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("audit")
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

fn secure_overwrite_and_remove_file(path: &Path) -> Result<(), String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("No se pudo inspeccionar {:?}: {}", path, error)),
    };
    if !metadata.is_file() {
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| format!("No se pudo abrir {:?} para limpieza: {}", path, error))?;
    let mut remaining = metadata.len().max(1);
    while remaining > 0 {
        let chunk_len = remaining.min(64 * 1024) as usize;
        let mut random = vec![0u8; chunk_len];
        rand::rngs::OsRng.fill_bytes(&mut random);
        file.write_all(&random)
            .map_err(|error| format!("No se pudo sobrescribir {:?}: {}", path, error))?;
        remaining = remaining.saturating_sub(chunk_len as u64);
    }
    file.sync_all()
        .map_err(|error| format!("No se pudo sincronizar {:?}: {}", path, error))?;
    drop(file);

    fs::remove_file(path).map_err(|error| format!("No se pudo borrar {:?}: {}", path, error))?;
    sync_parent_dir(path);
    Ok(())
}

fn read_all_entries() -> Result<Vec<AuditEntry>, String> {
    let path = audit_log_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).map_err(|error| format!("No se pudo leer audit.log: {}", error))?;
    rmp_serde::from_slice::<Vec<AuditEntry>>(&bytes)
        .map_err(|error| format!("audit.log invalido: {}", error))
}

fn write_all_entries(entries: &[AuditEntry]) -> Result<(), String> {
    let bytes = rmp_serde::to_vec(entries)
        .map_err(|error| format!("No se pudo serializar audit.log: {}", error))?;
    write_bytes_atomically(&audit_log_path(), &bytes)
}

fn entry_signature(
    index: u64,
    timestamp_unix: u64,
    event_type: &str,
    details: &str,
    prev_hash: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"LIVENCRYPT-AUDIT-SIGNATURE-V1|");
    hasher.update(index.to_le_bytes());
    hasher.update(timestamp_unix.to_le_bytes());
    hasher.update(event_type.as_bytes());
    hasher.update(details.as_bytes());
    hasher.update(prev_hash);
    hasher.finalize().to_vec()
}

fn entry_hmac_signature(
    index: u64,
    timestamp_unix: u64,
    event_type: &str,
    details: &str,
    prev_hash: &[u8],
    audit_key: &[u8],
) -> Result<Vec<u8>, String> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(audit_key)
        .map_err(|_| "Clave de auditoria HMAC invalida.".to_string())?;
    mac.update(b"LIVENCRYPT-AUDIT-HMAC-V1|");
    mac.update(&index.to_le_bytes());
    mac.update(&timestamp_unix.to_le_bytes());
    mac.update(event_type.as_bytes());
    mac.update(details.as_bytes());
    mac.update(prev_hash);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn append_audit_event(event_type: &str, details: &str) -> Result<Vec<u8>, String> {
    let mut entries = read_all_entries()?;
    let prev_hash = entries
        .last()
        .map(AuditEntry::calculate_hash)
        .unwrap_or_default();
    let index = entries.len() as u64;
    let timestamp_unix = unix_now();
    let signature = entry_signature(index, timestamp_unix, event_type, details, &prev_hash);
    let entry = AuditEntry {
        index,
        timestamp_unix,
        event_type: event_type.to_string(),
        details: details.to_string(),
        prev_hash,
        signature_scheme: default_signature_scheme(),
        signature,
    };
    let anchor = entry.calculate_hash();
    entries.push(entry);
    write_all_entries(&entries)?;
    Ok(anchor)
}

pub fn append_authenticated_event(
    event_type: &str,
    details: &str,
    audit_key: &[u8],
) -> Result<Vec<u8>, String> {
    let mut entries = read_all_entries()?;
    let prev_hash = entries
        .last()
        .map(AuditEntry::calculate_hash)
        .unwrap_or_default();
    let index = entries.len() as u64;
    let timestamp_unix = unix_now();

    let signature = entry_hmac_signature(
        index,
        timestamp_unix,
        event_type,
        details,
        &prev_hash,
        audit_key,
    )?;

    let entry = AuditEntry {
        index,
        timestamp_unix,
        event_type: event_type.to_string(),
        details: details.to_string(),
        prev_hash,
        signature_scheme: "hmac-sha256-v1".to_string(),
        signature,
    };
    let anchor = entry.calculate_hash();
    entries.push(entry);
    write_all_entries(&entries)?;
    Ok(anchor)
}

pub fn calculate_chain_anchor_with_key(audit_key: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let entries = read_all_entries()?;
    let mut current_prev_hash = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.index != index as u64 || entry.prev_hash != current_prev_hash {
            return Err("Cadena de auditoria rota o reordenada.".into());
        }
        let expected_signature = match entry.signature_scheme.as_str() {
            "local-sha256-v1" => entry_signature(
                entry.index,
                entry.timestamp_unix,
                &entry.event_type,
                &entry.details,
                &entry.prev_hash,
            ),
            "hmac-sha256-v1" => {
                if let Some(key) = audit_key {
                    entry_hmac_signature(
                        entry.index,
                        entry.timestamp_unix,
                        &entry.event_type,
                        &entry.details,
                        &entry.prev_hash,
                        key,
                    )?
                } else {
                    entry.signature.clone()
                }
            }
            _ => return Err("Esquema de firma de auditoria no soportado.".into()),
        };
        if expected_signature != entry.signature {
            return Err("Firma de auditoria invalida.".into());
        }
        current_prev_hash = entry.calculate_hash();
    }
    Ok(current_prev_hash)
}

pub fn calculate_chain_anchor() -> Result<Vec<u8>, String> {
    calculate_chain_anchor_with_key(None)
}

pub fn verify_audit_chain(expected_anchor: &[u8]) -> Result<bool, String> {
    let path = audit_log_path();
    if !path.exists() {
        return Ok(expected_anchor.is_empty());
    }
    Ok(calculate_chain_anchor()? == expected_anchor)
}

pub fn verify_audit_chain_with_key(
    expected_anchor: &[u8],
    audit_key: &[u8],
) -> Result<bool, String> {
    let path = audit_log_path();
    if !path.exists() {
        return Ok(expected_anchor.is_empty());
    }
    Ok(calculate_chain_anchor_with_key(Some(audit_key))? == expected_anchor)
}

pub fn register_tombstone(event: &str) -> Result<(), String> {
    let path = tombstone_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let entry = format!("{}|{}\n", unix_now(), event);
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .map_err(|error| format!("No se pudo abrir tombstone: {}", error))?;
    file.write_all(entry.as_bytes())
        .map_err(|error| format!("No se pudo escribir tombstone: {}", error))?;
    file.sync_all()
        .map_err(|error| format!("No se pudo sincronizar tombstone: {}", error))?;
    Ok(())
}

pub fn absorb_tombstones() -> Result<(), String> {
    let path = tombstone_path();
    if !path.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("No se pudo leer tombstone: {}", error))?;
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        append_audit_event("TOMBSTONE", line)?;
    }
    secure_overwrite_and_remove_file(&path)
}

pub fn tombstone_count() -> usize {
    fs::read_to_string(tombstone_path())
        .map(|content| {
            content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count()
        })
        .unwrap_or(0)
}

pub fn read_recent_entries(limit: usize) -> Result<Vec<AuditEntry>, String> {
    let mut entries = read_all_entries()?;
    if entries.len() > limit {
        entries = entries.split_off(entries.len() - limit);
    }
    Ok(entries)
}
