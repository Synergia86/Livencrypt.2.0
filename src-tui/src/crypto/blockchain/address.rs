// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: derivacion de direcciones publicas presentables desde claves publicas */

use crate::crypto::blockchain::types::ChainType;
use bech32::{segwit, Hrp};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;

/// Red de la cadena: distingue parametros mainnet/testnet (prefijos, coin_type, chain_id).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Network {
    #[default]
    Mainnet,
    Testnet,
}

pub fn public_address(chain: &ChainType, public_key: &[u8]) -> Result<String, String> {
    match chain {
        ChainType::Bitcoin if public_key.len() == 33 => Ok(bitcoin_p2pkh_address(public_key)),
        ChainType::Ethereum if public_key.len() == 64 => {
            let hash = Keccak256::digest(public_key);
            to_eip55_checksummed(&hex::encode(&hash[12..]))
        }
        ChainType::Solana if public_key.len() == 32 => Ok(bs58::encode(public_key).into_string()),
        ChainType::Bitcoin => Err("clave publica Bitcoin invalida: se esperaban 33 bytes".into()),
        ChainType::Ethereum => Err("clave publica Ethereum invalida: se esperaban 64 bytes".into()),
        ChainType::Solana => Err("clave publica Solana invalida: se esperaban 32 bytes".into()),
        ChainType::Monero => Err("Monero requiere derivacion de direccion aislada".into()),
        ChainType::Zcash => Err("Zcash requiere adaptador especifico Sapling/Orchard".into()),
        ChainType::Starknet => Err("Starknet requiere adaptador de cuenta y firma Stark".into()),
    }
}

pub fn derivation_path(chain: &ChainType, account: u32, index: u32) -> String {
    let (purpose, coin_type) = match chain {
        ChainType::Bitcoin => (44, 0),
        ChainType::Ethereum => (44, 60),
        ChainType::Solana => (44, 501),
        ChainType::Monero => (44, 128),
        ChainType::Zcash => (44, 133),
        ChainType::Starknet => (44, 9004),
    };
    format!("m/{}'/{}'/{}'/0/{}", purpose, coin_type, account, index)
}

pub fn chain_id_label(chain: &ChainType) -> String {
    match chain {
        ChainType::Ethereum => "0x1".to_string(),
        ChainType::Bitcoin => "bitcoin-mainnet".to_string(),
        ChainType::Solana => "solana-mainnet-beta".to_string(),
        ChainType::Monero => "monero-mainnet".to_string(),
        ChainType::Zcash => "zcash-mainnet".to_string(),
        ChainType::Starknet => "starknet-mainnet".to_string(),
    }
}

/// Etiqueta de chain_id segun red (mainnet/testnet). Para cadenas sin testnet
/// definida cae al valor mainnet de `chain_id_label`.
pub fn chain_id_label_for(chain: &ChainType, network: Network) -> String {
    match (chain, network) {
        (ChainType::Ethereum, Network::Mainnet) => "0x1".to_string(),
        (ChainType::Ethereum, Network::Testnet) => "0xaa36a7".to_string(), // Sepolia
        (ChainType::Bitcoin, Network::Mainnet) => "bitcoin-mainnet".to_string(),
        (ChainType::Bitcoin, Network::Testnet) => "bitcoin-testnet".to_string(),
        (ChainType::Solana, Network::Mainnet) => "solana-mainnet-beta".to_string(),
        (ChainType::Solana, Network::Testnet) => "solana-devnet".to_string(),
        (chain, _) => chain_id_label(chain),
    }
}

/// coin_type BIP-44 por red. Bitcoin testnet usa coin_type 1; Ethereum y Solana mantienen
/// su coin_type en todas las redes (la misma direccion sirve en testnet, solo cambia el chain_id).
pub fn coin_type_for(chain: &ChainType, network: Network) -> u32 {
    match (chain, network) {
        (ChainType::Bitcoin, Network::Testnet) => 1,
        (ChainType::Bitcoin, Network::Mainnet) => 0,
        (ChainType::Ethereum, _) => 60,
        (ChainType::Solana, _) => 501,
        (ChainType::Monero, _) => 128,
        (ChainType::Zcash, _) => 133,
        (ChainType::Starknet, _) => 9004,
    }
}

/// Version del prefijo P2PKH Base58Check de Bitcoin segun red (0x00 main / 0x6f test).
pub fn bitcoin_p2pkh_version(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0x00,
        Network::Testnet => 0x6f,
    }
}

/// Aplica el checksum de capitalizacion EIP-55 a un hex de 40 nibbles (con o sin "0x").
pub fn to_eip55_checksummed(address_hex: &str) -> Result<String, String> {
    let clean = address_hex.trim_start_matches("0x").to_ascii_lowercase();
    if clean.len() != 40 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("direccion Ethereum debe tener 40 nibbles hexadecimales".into());
    }
    let hash = Keccak256::digest(clean.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in clean.chars().enumerate() {
        if ch.is_ascii_digit() {
            out.push(ch);
        } else {
            // Nibble alto para indice par, bajo para impar (cada byte cubre 2 caracteres).
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if nibble >= 8 {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
        }
    }
    Ok(out)
}

/// Verifica que una direccion Ethereum cumple el checksum EIP-55.
/// Acepta todo-minusculas / todo-mayusculas (sin checksum) y rechaza checksum mixto invalido.
pub fn validate_ethereum_address_checksum(address: &str) -> bool {
    let clean = address.trim_start_matches("0x");
    if clean.len() != 40 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let mixed = clean.chars().any(|c| c.is_ascii_uppercase())
        && clean.chars().any(|c| c.is_ascii_lowercase());
    if !mixed {
        return true; // Sin checksum de capitalizacion: valido por compatibilidad.
    }
    match to_eip55_checksummed(clean) {
        Ok(expected) => expected.trim_start_matches("0x") == clean,
        Err(_) => false,
    }
}

/// Valida el checksum Base58Check de una direccion Bitcoin P2PKH mainnet (version 0x00).
pub fn validate_bitcoin_address_checksum(address: &str) -> Result<(), String> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|error| format!("Base58 invalido: {}", error))?;
    if decoded.len() != 25 {
        return Err("longitud Base58Check invalida (esperados 25 bytes)".into());
    }
    if decoded[0] != 0x00 {
        return Err("version no P2PKH mainnet (esperado 0x00)".into());
    }
    let (payload, checksum) = decoded.split_at(21);
    let expected = Sha256::digest(Sha256::digest(payload));
    if checksum != &expected[..4] {
        return Err("checksum Base58Check no coincide".into());
    }
    Ok(())
}

/// Valida que una direccion Solana decodifica a exactamente 32 bytes Base58.
pub fn validate_solana_address(address: &str) -> Result<(), String> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|error| format!("Base58 invalido: {}", error))?;
    if decoded.len() != 32 {
        return Err("clave Solana debe decodificar a 32 bytes".into());
    }
    Ok(())
}

/// Direccion presentable network-aware: usa el prefijo/version correcto segun red.
/// Ethereum/Solana son agnosticos de red en el formato de direccion.
pub fn public_address_for_network(
    chain: &ChainType,
    public_key: &[u8],
    network: Network,
) -> Result<String, String> {
    match chain {
        ChainType::Bitcoin if public_key.len() == 33 => {
            Ok(bitcoin_p2pkh_address_versioned(public_key, bitcoin_p2pkh_version(network)))
        }
        _ => public_address(chain, public_key),
    }
}

fn bitcoin_p2pkh_address(public_key: &[u8]) -> String {
    bitcoin_p2pkh_address_versioned(public_key, 0x00)
}

fn bitcoin_p2pkh_address_versioned(public_key: &[u8], version: u8) -> String {
    let sha = Sha256::digest(public_key);
    let ripe = Ripemd160::digest(sha);
    let mut payload = Vec::with_capacity(25);
    payload.push(version);
    payload.extend_from_slice(&ripe);
    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);
    bs58::encode(payload).into_string()
}

/// Direccion P2WPKH (bech32, prefijo "bc1"/"tb1") desde clave publica comprimida de 33 bytes.
pub fn bitcoin_p2wpkh_address(public_key: &[u8], network: Network) -> Result<String, String> {
    if public_key.len() != 33 {
        return Err("clave publica Bitcoin invalida: se esperaban 33 bytes comprimidos".into());
    }
    let sha = Sha256::digest(public_key);
    let witness_program = Ripemd160::digest(sha); // 20 bytes (HASH160)
    let hrp = match network {
        Network::Mainnet => Hrp::parse("bc"),
        Network::Testnet => Hrp::parse("tb"),
    }
    .map_err(|error| format!("HRP bech32 invalido: {}", error))?;
    segwit::encode(hrp, segwit::VERSION_0, &witness_program)
        .map_err(|error| format!("codificacion bech32 fallida: {}", error))
}
