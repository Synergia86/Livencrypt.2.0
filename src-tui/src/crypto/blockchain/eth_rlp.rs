// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: codificador RLP minimo para transacciones Ethereum */

pub fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }
    encode_len(0x80, bytes.len(), bytes)
}

pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload = items.concat();
    encode_len(0xc0, payload.len(), &payload)
}

pub fn encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return encode_bytes(&[]);
    }
    encode_bytes(&u64_to_be(value))
}

pub fn encode_u256_hex(value: &str) -> Result<Vec<u8>, String> {
    let bytes = hex_to_minimal_bytes(value)?;
    Ok(encode_bytes(&bytes))
}

fn encode_len(offset: u8, len: usize, payload: &[u8]) -> Vec<u8> {
    if len < 56 {
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(offset + len as u8);
        out.extend_from_slice(payload);
        return out;
    }

    let len_bytes = usize_to_be(len);
    let mut out = Vec::with_capacity(1 + len_bytes.len() + payload.len());
    out.push(offset + 55 + len_bytes.len() as u8);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(payload);
    out
}

fn u64_to_be(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    bytes.iter().skip_while(|b| **b == 0).copied().collect()
}

fn usize_to_be(value: usize) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    bytes.iter().skip_while(|b| **b == 0).copied().collect()
}

fn hex_to_minimal_bytes(value: &str) -> Result<Vec<u8>, String> {
    let mut hex = value.strip_prefix("0x").unwrap_or(value).to_string();
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if hex.len() % 2 != 0 {
        hex.insert(0, '0');
    }
    let mut bytes = hex::decode(hex).map_err(|error| error.to_string())?;
    while bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    Ok(bytes)
}
