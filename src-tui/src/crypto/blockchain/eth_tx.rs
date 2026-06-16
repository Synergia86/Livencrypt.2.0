// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: serializacion Ethereum legacy/EIP-2930/EIP-1559 sin firma */

use crate::crypto::blockchain::eth_rlp;
use crate::crypto::blockchain::eth_types::{EthereumTxKind, EthereumTxRequest};
use crate::crypto::blockchain::types::SignatureResponse;
use sha3::{Digest, Keccak256};

pub fn serialize_unsigned(tx: &EthereumTxRequest) -> Result<Vec<u8>, String> {
    validate_common(tx)?;
    match tx.kind {
        EthereumTxKind::Legacy => serialize_legacy(tx),
        EthereumTxKind::Eip2930 => serialize_eip2930(tx),
        EthereumTxKind::Eip1559 => serialize_eip1559(tx),
    }
}

pub fn serialize_signed(
    tx: &EthereumTxRequest,
    signature: &SignatureResponse,
) -> Result<Vec<u8>, String> {
    validate_common(tx)?;
    let (r, s) = signature_rs(signature)?;
    let y_parity = u64::from(signature.recovery_id.unwrap_or(0) & 1);
    match tx.kind {
        EthereumTxKind::Legacy => serialize_legacy_signed(tx, y_parity, r, s),
        EthereumTxKind::Eip2930 => serialize_eip2930_signed(tx, y_parity, r, s),
        EthereumTxKind::Eip1559 => serialize_eip1559_signed(tx, y_parity, r, s),
    }
}

pub fn tx_hash_hex(raw_signed_tx: &[u8]) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(raw_signed_tx)))
}

fn serialize_eip1559(tx: &EthereumTxRequest) -> Result<Vec<u8>, String> {
    let fields = eip1559_unsigned_fields(tx)?;
    let mut out = vec![0x02];
    out.extend_from_slice(&eth_rlp::encode_list(&fields));
    Ok(out)
}

fn serialize_eip1559_signed(
    tx: &EthereumTxRequest,
    y_parity: u64,
    r: &[u8],
    s: &[u8],
) -> Result<Vec<u8>, String> {
    let mut fields = eip1559_unsigned_fields(tx)?;
    fields.push(eth_rlp::encode_u64(y_parity));
    fields.push(encode_signature_scalar(r));
    fields.push(encode_signature_scalar(s));
    let mut out = vec![0x02];
    out.extend_from_slice(&eth_rlp::encode_list(&fields));
    Ok(out)
}

fn eip1559_unsigned_fields(tx: &EthereumTxRequest) -> Result<Vec<Vec<u8>>, String> {
    let to = tx.to.as_deref().unwrap_or("");
    Ok(vec![
        eth_rlp::encode_u64(tx.chain_id),
        eth_rlp::encode_u64(tx.nonce),
        eth_rlp::encode_u256_hex(required(
            tx.max_priority_fee_per_gas.as_deref(),
            "maxPriorityFeePerGas",
        )?)?,
        eth_rlp::encode_u256_hex(required(tx.max_fee_per_gas.as_deref(), "maxFeePerGas")?)?,
        eth_rlp::encode_u64(tx.gas_limit),
        eth_rlp::encode_bytes(&decode_address_or_empty(to)?),
        eth_rlp::encode_u256_hex(&tx.value)?,
        eth_rlp::encode_bytes(&decode_hex(&tx.data)?),
        eth_rlp::encode_list(&[]),
    ])
}

fn serialize_eip2930(tx: &EthereumTxRequest) -> Result<Vec<u8>, String> {
    let fields = eip2930_unsigned_fields(tx)?;
    let mut out = vec![0x01];
    out.extend_from_slice(&eth_rlp::encode_list(&fields));
    Ok(out)
}

fn serialize_eip2930_signed(
    tx: &EthereumTxRequest,
    y_parity: u64,
    r: &[u8],
    s: &[u8],
) -> Result<Vec<u8>, String> {
    let mut fields = eip2930_unsigned_fields(tx)?;
    fields.push(eth_rlp::encode_u64(y_parity));
    fields.push(encode_signature_scalar(r));
    fields.push(encode_signature_scalar(s));
    let mut out = vec![0x01];
    out.extend_from_slice(&eth_rlp::encode_list(&fields));
    Ok(out)
}

fn eip2930_unsigned_fields(tx: &EthereumTxRequest) -> Result<Vec<Vec<u8>>, String> {
    let to = tx.to.as_deref().unwrap_or("");
    Ok(vec![
        eth_rlp::encode_u64(tx.chain_id),
        eth_rlp::encode_u64(tx.nonce),
        eth_rlp::encode_u256_hex(required(tx.gas_price.as_deref(), "gasPrice")?)?,
        eth_rlp::encode_u64(tx.gas_limit),
        eth_rlp::encode_bytes(&decode_address_or_empty(to)?),
        eth_rlp::encode_u256_hex(&tx.value)?,
        eth_rlp::encode_bytes(&decode_hex(&tx.data)?),
        eth_rlp::encode_list(&[]),
    ])
}

fn serialize_legacy(tx: &EthereumTxRequest) -> Result<Vec<u8>, String> {
    Ok(eth_rlp::encode_list(&legacy_unsigned_fields(tx)?))
}

fn serialize_legacy_signed(
    tx: &EthereumTxRequest,
    y_parity: u64,
    r: &[u8],
    s: &[u8],
) -> Result<Vec<u8>, String> {
    let v = tx
        .chain_id
        .checked_mul(2)
        .and_then(|value| value.checked_add(35))
        .and_then(|value| value.checked_add(y_parity))
        .ok_or_else(|| "v Ethereum legacy fuera de rango".to_string())?;
    let mut fields = legacy_base_fields(tx)?;
    fields.push(eth_rlp::encode_u64(v));
    fields.push(encode_signature_scalar(r));
    fields.push(encode_signature_scalar(s));
    Ok(eth_rlp::encode_list(&fields))
}

fn legacy_unsigned_fields(tx: &EthereumTxRequest) -> Result<Vec<Vec<u8>>, String> {
    let mut fields = legacy_base_fields(tx)?;
    fields.push(eth_rlp::encode_u64(tx.chain_id));
    fields.push(eth_rlp::encode_u64(0));
    fields.push(eth_rlp::encode_u64(0));
    Ok(fields)
}

fn legacy_base_fields(tx: &EthereumTxRequest) -> Result<Vec<Vec<u8>>, String> {
    let to = tx.to.as_deref().unwrap_or("");
    Ok(vec![
        eth_rlp::encode_u64(tx.nonce),
        eth_rlp::encode_u256_hex(required(tx.gas_price.as_deref(), "gasPrice")?)?,
        eth_rlp::encode_u64(tx.gas_limit),
        eth_rlp::encode_bytes(&decode_address_or_empty(to)?),
        eth_rlp::encode_u256_hex(&tx.value)?,
        eth_rlp::encode_bytes(&decode_hex(&tx.data)?),
    ])
}

fn validate_common(tx: &EthereumTxRequest) -> Result<(), String> {
    if tx.chain_id == 0 {
        return Err("chain_id Ethereum no puede ser 0".into());
    }
    if tx.gas_limit == 0 {
        return Err("gas_limit Ethereum no puede ser 0".into());
    }
    if !tx.from.starts_with("0x") || decode_address_or_empty(&tx.from)?.len() != 20 {
        return Err("from Ethereum invalido".into());
    }
    if let Some(to) = &tx.to {
        decode_address_or_empty(to)?;
    }
    decode_hex(&tx.data)?;
    Ok(())
}

fn required<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str, String> {
    value.ok_or_else(|| format!("campo Ethereum obligatorio ausente: {}", field))
}

fn decode_address_or_empty(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = decode_hex(value)?;
    if bytes.len() != 20 {
        return Err("direccion Ethereum invalida".into());
    }
    Ok(bytes)
}

pub fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() % 2 != 0 {
        return Err("hex impar invalido".into());
    }
    hex::decode(value).map_err(|error| error.to_string())
}

fn signature_rs(signature: &SignatureResponse) -> Result<(&[u8], &[u8]), String> {
    if signature.raw_signature.len() != 64 {
        return Err("firma Ethereum invalida: se esperaban 64 bytes r||s".into());
    }
    Ok((
        &signature.raw_signature[..32],
        &signature.raw_signature[32..64],
    ))
}

fn encode_signature_scalar(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    eth_rlp::encode_bytes(&bytes[start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_signed_tx_adds_eip155_v_r_s() {
        let tx = EthereumTxRequest {
            chain_id: 1,
            from: "0x1111111111111111111111111111111111111111".into(),
            to: Some("0x2222222222222222222222222222222222222222".into()),
            nonce: 1,
            value: "0x01".into(),
            data: "0x".into(),
            gas_limit: 21_000,
            gas_price: Some("0x3b9aca00".into()),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            kind: EthereumTxKind::Legacy,
        };
        let signature = SignatureResponse {
            public_key: vec![],
            raw_signature: [vec![1u8; 32], vec![2u8; 32]].concat(),
            recovery_id: Some(1),
        };
        let raw = serialize_signed(&tx, &signature).expect("signed legacy");
        assert!(!raw.is_empty());
        assert!(tx_hash_hex(&raw).starts_with("0x"));
    }
}
