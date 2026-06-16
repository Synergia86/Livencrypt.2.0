// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: auditoria local de lecturas RPC y decisiones Web3 */

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Web3AuditEvent {
    pub timestamp_unix: u64,
    pub origin: String,
    pub action: String,
    pub chain: String,
    pub chain_id: String,
    pub account_index: Option<u32>,
    pub address_index: Option<u32>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub contract: Option<String>,
    pub method: Option<String>,
    pub selector: Option<String>,
    pub value_native: Option<String>,
    pub value_fiat: Option<String>,
    pub endpoint_summary: Vec<String>,
    pub decision: String,
    pub warnings: Vec<String>,
    pub payload_sha256: Option<String>,
    pub signature_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainedWeb3AuditEvent {
    pub previous_hash: String,
    pub event: Web3AuditEvent,
    pub event_hash: String,
}

/// Entrada de auditoria encadenada y firmada con la clave de dispositivo (Ed25519).
/// Eleva la garantia de "detecta edicion parcial" (hash-chain) a "detecta reescritura total".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedWeb3AuditEvent {
    pub previous_hash: String,
    pub event: Web3AuditEvent,
    pub event_hash: String,
    pub event_signature: String, // firma Ed25519 hex de event_hash
}

/// Clave de dispositivo (Ed25519) para sellar el log de auditoria Web3. Se fija una sola
/// vez al arrancar el worker (tras desbloquear el vault). Si no esta fijada, las entradas
/// se escriben encadenadas pero sin firma (compatibilidad).
static AUDIT_SIGNING_KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();

/// Registra la clave de firma de auditoria (idempotente; solo la primera vez surte efecto).
pub fn set_audit_signing_key(key: SigningKey) {
    let _ = AUDIT_SIGNING_KEY.set(key);
}

/// Clave publica de verificacion del log de auditoria, si la clave de firma esta fijada.
pub fn audit_verifying_key() -> Option<VerifyingKey> {
    AUDIT_SIGNING_KEY.get().map(|key| key.verifying_key())
}

pub fn append_web3_audit_event(event: Web3AuditEvent) -> Result<(), String> {
    let path = audit_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }

    let previous_hash = last_event_hash(&path)?;
    let event_hash = event_hash(&previous_hash, &event)?;

    // Si hay clave de dispositivo fijada, sellamos la entrada con firma Ed25519.
    let line = match AUDIT_SIGNING_KEY.get() {
        Some(key) => {
            let event_signature = sign_event_hash(&event_hash, key);
            let signed = SignedWeb3AuditEvent {
                previous_hash,
                event,
                event_hash,
                event_signature,
            };
            serde_json::to_string(&signed).map_err(|error| error.to_string())?
        }
        None => {
            let chained = ChainedWeb3AuditEvent {
                previous_hash,
                event,
                event_hash,
            };
            serde_json::to_string(&chained).map_err(|error| error.to_string())?
        }
    };

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| error.to_string())?;

    file.write_all(line.as_bytes())
        .map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_data().map_err(|error| error.to_string())
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn event_hash(previous_hash: &str, event: &Web3AuditEvent) -> Result<String, String> {
    let payload = serde_json::to_vec(&(previous_hash, event)).map_err(|error| error.to_string())?;
    Ok(sha256_hex(&payload))
}

/// Firma el event_hash (hex) con la clave de dispositivo Ed25519. Devuelve la firma hex.
pub fn sign_event_hash(event_hash: &str, device_key: &SigningKey) -> String {
    let signature: Signature = device_key.sign(event_hash.as_bytes());
    hex::encode(signature.to_bytes())
}

/// Verifica la cadena completa: encadenado de hashes + firma de dispositivo por entrada.
pub fn verify_audit_chain(
    path: &std::path::Path,
    device_pubkey: &VerifyingKey,
) -> Result<(), String> {
    let file = std::fs::File::open(path)
        .map_err(|error| format!("no se pudo abrir log de auditoria: {}", error))?;
    let reader = BufReader::new(file);
    let mut previous = "GENESIS".to_string();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: SignedWeb3AuditEvent = serde_json::from_str(&line)
            .map_err(|error| format!("linea {} ilegible: {}", line_no + 1, error))?;
        if entry.previous_hash != previous {
            return Err(format!("ruptura de cadena en linea {}", line_no + 1));
        }
        if event_hash(&entry.previous_hash, &entry.event)? != entry.event_hash {
            return Err(format!("hash no coincide en linea {}", line_no + 1));
        }
        let sig_bytes: [u8; 64] = hex::decode(&entry.event_signature)
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "firma de auditoria debe tener 64 bytes".to_string())?;
        let signature = Signature::from_bytes(&sig_bytes);
        device_pubkey
            .verify(entry.event_hash.as_bytes(), &signature)
            .map_err(|error| format!("firma invalida en linea {}: {}", line_no + 1, error))?;
        previous = entry.event_hash;
    }
    Ok(())
}

/// Verifica el log de auditoria Web3 local (cadena de hashes + firma de dispositivo).
/// Requiere que la clave de firma esté fijada (worker iniciado).
pub fn verify_local_audit_chain() -> Result<(), String> {
    let pubkey = audit_verifying_key()
        .ok_or_else(|| "clave de firma de auditoria no fijada (worker no iniciado)".to_string())?;
    verify_audit_chain(&audit_path(), &pubkey)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn audit_path() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("web3_audit.jsonl")
}

fn last_event_hash(path: &PathBuf) -> Result<String, String> {
    let Ok(file) = std::fs::File::open(path) else {
        return Ok("GENESIS".to_string());
    };

    let reader = BufReader::new(file);
    let mut last = None;
    for line in reader.lines() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<ChainedWeb3AuditEvent>(&line) {
            last = Some(event.event_hash);
            continue;
        }
        let legacy: Web3AuditEvent = serde_json::from_str(&line).map_err(|error| {
            format!(
                "log de auditoria Web3 corrupto o no reconocido; revise {}: {}",
                path.display(),
                error
            )
        })?;
        let previous = last.clone().unwrap_or_else(|| "GENESIS".to_string());
        last = Some(event_hash(&previous, &legacy)?);
    }
    Ok(last.unwrap_or_else(|| "GENESIS".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> Web3AuditEvent {
        Web3AuditEvent {
            timestamp_unix: 1,
            origin: "https://dex.local".into(),
            action: "preflight".into(),
            chain: "ethereum".into(),
            chain_id: "0x1".into(),
            account_index: Some(0),
            address_index: Some(0),
            from: Some("0x1111111111111111111111111111111111111111".into()),
            to: None,
            contract: None,
            method: None,
            selector: None,
            value_native: None,
            value_fiat: None,
            endpoint_summary: vec![],
            decision: "rejected".into(),
            warnings: vec![],
            payload_sha256: None,
            signature_sha256: None,
        }
    }

    #[test]
    fn audit_event_does_not_contain_secret_fields() {
        let json = serde_json::to_string(&sample_event()).expect("json");
        assert!(!json.contains("frase"));
        assert!(!json.contains("cajas"));
        assert!(!json.contains("private"));
        assert!(!json.contains("seed"));
    }

    #[test]
    fn event_hash_changes_with_previous_hash() {
        let event = sample_event();
        let first = event_hash("GENESIS", &event).expect("hash");
        let second = event_hash(&first, &event).expect("hash");
        assert_ne!(first, second);
    }
}
