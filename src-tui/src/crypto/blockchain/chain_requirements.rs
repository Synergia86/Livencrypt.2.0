// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: primitivas base para requisitos multicadena pendientes */

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn electrum_scripthash_from_p2pkh_hash160(hash160_hex: &str) -> Result<String, String> {
    let hash160 = hex::decode(hash160_hex).map_err(|error| error.to_string())?;
    if hash160.len() != 20 {
        return Err("hash160 P2PKH invalido".into());
    }

    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(&hash160);
    script.extend_from_slice(&[0x88, 0xac]);

    let digest = Sha256::digest(&script);
    let reversed = digest.iter().rev().copied().collect::<Vec<_>>();
    Ok(hex::encode(reversed))
}

pub fn solana_get_fee_for_message_payload(message_bytes: &[u8]) -> String {
    bs58::encode(message_bytes).into_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroAccountKeys {
    pub public_spend: [u8; 32],
    pub public_view: [u8; 32],
    pub private_spend_encrypted: Vec<u8>,
    pub private_view_encrypted: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZcashAddressKind {
    Transparent,
    Sapling,
    Orchard,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZcashPublicAddress {
    pub kind: ZcashAddressKind,
    pub address: String,
    pub viewing_key_available: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarknetAccount {
    pub address: String,
    pub class_hash: String,
    pub public_key: String,
    pub chain_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn electrum_scripthash_rejects_invalid_hash160() {
        assert!(electrum_scripthash_from_p2pkh_hash160("abcd").is_err());
    }

    #[test]
    fn solana_fee_payload_is_base58() {
        assert_eq!(solana_get_fee_for_message_payload(&[1, 2, 3]), "Ldp");
    }
}
