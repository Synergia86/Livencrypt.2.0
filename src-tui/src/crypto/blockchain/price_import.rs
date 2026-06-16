// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: importador de precios firmados para modo offline */

use crate::crypto::blockchain::types::{PriceBook, PriceOracleMode, PriceQuote};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct SignedPriceQuote {
    pub asset: String,
    pub fiat: String,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignedPriceEnvelope {
    pub version: u32,
    pub created_unix: u64,
    pub source: String,
    pub quotes: Vec<SignedPriceQuote>,
    pub public_key: String,
    pub signature: String,
}

fn canonical_price_payload(envelope: &SignedPriceEnvelope) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&serde_json::json!({
        "version": envelope.version,
        "created_unix": envelope.created_unix,
        "source": envelope.source,
        "quotes": envelope.quotes,
    }))
    .map_err(|error| error.to_string())
}

pub fn import_signed_price_file(path: &Path, max_age_seconds: u64) -> Result<PriceBook, String> {
    let raw = std::fs::read(path)
        .map_err(|error| format!("no se pudo leer fichero de precios: {}", error))?;
    if raw.len() > 1024 * 1024 {
        return Err("fichero de precios demasiado grande".into());
    }
    let envelope: SignedPriceEnvelope = serde_json::from_slice(&raw)
        .map_err(|error| format!("fichero de precios invalido: {}", error))?;

    let public_key_bytes = hex::decode(&envelope.public_key)
        .map_err(|error| format!("public key hex invalida: {}", error))?;
    let signature_bytes = hex::decode(&envelope.signature)
        .map_err(|error| format!("firma hex invalida: {}", error))?;

    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| "public key Ed25519 debe tener 32 bytes".to_string())?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "firma Ed25519 debe tener 64 bytes".to_string())?;

    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|error| format!("public key Ed25519 invalida: {}", error))?;
    let signature = Signature::from_bytes(&signature_array);
    let payload = canonical_price_payload(&envelope)?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|error| format!("firma de precios invalida: {}", error))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(envelope.created_unix) > max_age_seconds {
        return Err("fichero de precios caducado".into());
    }

    let mut quotes = Vec::new();
    for quote in envelope.quotes {
        let value = quote
            .value
            .parse::<Decimal>()
            .map_err(|_| "precio decimal invalido".to_string())?;
        quotes.push(PriceQuote {
            asset: quote.asset.to_uppercase(),
            fiat: quote.fiat.to_uppercase(),
            value,
            timestamp_unix: envelope.created_unix,
            source: envelope.source.clone(),
        });
    }

    Ok(PriceBook {
        mode: PriceOracleMode::SignedFile,
        primary_fiat: quotes
            .first()
            .map(|quote| quote.fiat.clone())
            .unwrap_or_else(|| "USD".to_string()),
        max_age_seconds,
        quotes,
    })
}
