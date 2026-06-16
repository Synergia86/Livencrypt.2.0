// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: derivación de claves multiecosistema con zeroize en drop */

use crate::crypto::blockchain::address::{coin_type_for, Network};
use crate::crypto::blockchain::types::{ChainType, SignatureResponse};
use crate::security::vault::derive_vault_key;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};
use sha3::Keccak256;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

pub struct UniversalKeymaster {
    master_seed: [u8; 64],
}

impl Drop for UniversalKeymaster {
    fn drop(&mut self) {
        self.master_seed.zeroize();
    }
}

impl UniversalKeymaster {
    pub fn new(cajas: [i64; 5], master_phrase: &str) -> Result<Self, String> {
        let mut vault_key = derive_vault_key(cajas, master_phrase)?;
        let mut hmac = HmacSha512::new_from_slice(b"Livencrypt Universal Seed")
            .map_err(|error| error.to_string())?;
        hmac.update(&vault_key);

        let mut master_seed = [0u8; 64];
        master_seed.copy_from_slice(&hmac.finalize().into_bytes());

        vault_key.zeroize();

        Ok(Self { master_seed })
    }

    fn derive_slip10_child(
        &self,
        chain: &ChainType,
        network: Network,
        account: u32,
        index: u32,
    ) -> Result<[u8; 32], String> {
        match chain {
            ChainType::Bitcoin | ChainType::Ethereum => {
                self.derive_bip32_secp256k1_child(coin_type_for(chain, network), account, index)
            }
            ChainType::Solana => self.derive_slip10_ed25519_child(account, index),
            ChainType::Monero => Err("Monero requiere derivacion aislada".into()),
            ChainType::Zcash => Err("Zcash requiere derivacion Sapling/Orchard aislada".into()),
            ChainType::Starknet => {
                Err("Starknet requiere derivacion/firma Stark especifica".into())
            }
        }
    }

    fn derive_bip32_secp256k1_child(
        &self,
        coin_type: u32,
        account: u32,
        index: u32,
    ) -> Result<[u8; 32], String> {
        let path = [
            hardened(44),
            hardened(coin_type),
            hardened(account),
            0,
            index,
        ];
        let mut key = derive_bip32_secp_path(&self.master_seed, &path).map_err(|error| {
            format!(
                "clave secp256k1 invalida en el indice {} solicitado: {}",
                index, error
            )
        })?;
        let out = key;
        key.zeroize();
        Ok(out)
    }

    fn derive_slip10_ed25519_child(&self, account: u32, index: u32) -> Result<[u8; 32], String> {
        let path = [
            hardened(44),
            hardened(501),
            hardened(account),
            hardened(0),
            hardened(index),
        ];
        derive_slip10_ed25519_path(&self.master_seed, &path)
    }

    pub fn get_public_key(
        &self,
        chain: &ChainType,
        network: Network,
        account: u32,
        index: u32,
    ) -> Result<Vec<u8>, String> {
        let mut raw_key = self.derive_slip10_child(chain, network, account, index)?;

        let result = (|| -> Result<Vec<u8>, String> {
            match chain {
                ChainType::Bitcoin => {
                    let secp = Secp256k1::new();
                    let sk = SecretKey::from_slice(&raw_key).map_err(|error| error.to_string())?;
                    let pk = PublicKey::from_secret_key(&secp, &sk);
                    Ok(pk.serialize().to_vec())
                }
                ChainType::Ethereum => {
                    let secp = Secp256k1::new();
                    let sk = SecretKey::from_slice(&raw_key).map_err(|error| error.to_string())?;
                    let pk = PublicKey::from_secret_key(&secp, &sk);
                    Ok(pk.serialize_uncompressed()[1..].to_vec())
                }
                ChainType::Solana => {
                    let sk = SigningKey::from_bytes(&raw_key);
                    Ok(sk.verifying_key().to_bytes().to_vec())
                }
                ChainType::Monero => {
                    Err("Monero requiere derivacion multilave aislada no soportada".to_string())
                }
                ChainType::Zcash => {
                    Err("Zcash requiere derivacion Sapling/Orchard no soportada".to_string())
                }
                ChainType::Starknet => {
                    Err("Starknet requiere cuenta y firma Stark no soportadas".to_string())
                }
            }
        })();

        raw_key.zeroize();
        result
    }

    /// Deriva la clave publica dos veces de forma independiente y las compara en
    /// tiempo constante. Devuelve la clave solo si ambas pasadas coinciden.
    /// Deriva de forma determinista una clave de firma Ed25519 dedicada a sellar el log
    /// de auditoria Web3 (separada de las claves de cuenta). Estable para el mismo vault.
    pub fn audit_signing_key(&self) -> SigningKey {
        let material = hmac_sha512_bytes(b"Livencrypt Web3 Audit Signing", &self.master_seed)
            .unwrap_or([0u8; 64]);
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&material[..32]);
        let key = SigningKey::from_bytes(&sk_bytes);
        sk_bytes.zeroize();
        key
    }

    pub fn rederive_and_verify(
        &self,
        chain: &ChainType,
        network: Network,
        account: u32,
        index: u32,
    ) -> Result<Vec<u8>, String> {
        let first = self.get_public_key(chain, network, account, index)?;
        let second = self.get_public_key(chain, network, account, index)?;
        if !constant_time_eq(&first, &second) {
            return Err("derivacion no reproducible: las dos pasadas difieren".into());
        }
        Ok(first)
    }

    pub fn sign_transaction(
        &self,
        chain: &ChainType,
        network: Network,
        account: u32,
        index: u32,
        raw_payload: &[u8],
    ) -> Result<SignatureResponse, String> {
        let mut raw_key = self.derive_slip10_child(chain, network, account, index)?;

        let result = (|| -> Result<SignatureResponse, String> {
            match chain {
                ChainType::Bitcoin | ChainType::Ethereum => {
                    let secp = Secp256k1::new();
                    let sk = SecretKey::from_slice(&raw_key).map_err(|error| error.to_string())?;

                    let tx_hash = match chain {
                        ChainType::Bitcoin => {
                            let hash1 = Sha256::digest(raw_payload);
                            let hash2 = Sha256::digest(hash1);
                            let mut array = [0u8; 32];
                            array.copy_from_slice(&hash2);
                            array
                        }
                        _ => {
                            let hash = Keccak256::digest(raw_payload);
                            let mut array = [0u8; 32];
                            array.copy_from_slice(&hash);
                            array
                        }
                    };

                    let msg = Message::from_digest_slice(&tx_hash)
                        .map_err(|error| error.to_string())?;
                    let recoverable_sig = secp.sign_ecdsa_recoverable(&msg, &sk);
                    let (rec_id, sig_bytes) = recoverable_sig.serialize_compact();
                    let public_key = match chain {
                        ChainType::Bitcoin => PublicKey::from_secret_key(&secp, &sk)
                            .serialize()
                            .to_vec(),
                        _ => PublicKey::from_secret_key(&secp, &sk)
                            .serialize_uncompressed()[1..]
                            .to_vec(),
                    };

                    Ok(SignatureResponse {
                        public_key,
                        raw_signature: sig_bytes.to_vec(),
                        recovery_id: Some(rec_id.to_i32() as u8),
                    })
                }
                ChainType::Solana => {
                    let sk = SigningKey::from_bytes(&raw_key);
                    // El payload ya es el mensaje Solana serializado; ed25519 firma esos bytes.
                    let sig = sk.sign(raw_payload);

                    Ok(SignatureResponse {
                        public_key: sk.verifying_key().to_bytes().to_vec(),
                        raw_signature: sig.to_bytes().to_vec(),
                        recovery_id: None,
                    })
                }
                ChainType::Monero => Err(
                    "Monero requiere un esquema especializado de firmas en anillo y payload multilave especifico".to_string(),
                ),
                ChainType::Zcash => Err(
                    "Zcash requiere libreria ZK auditada y firma especifica Sapling/Orchard".to_string(),
                ),
                ChainType::Starknet => Err(
                    "Starknet requiere firma Stark y validacion de contrato de cuenta".to_string(),
                ),
            }
        })();

        raw_key.zeroize();
        result
    }
}

fn hardened(index: u32) -> u32 {
    index | 0x8000_0000
}

/// Comparacion en tiempo constante sin cortocircuito por contenido.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hmac_sha512_bytes(key: &[u8], data: &[u8]) -> Result<[u8; 64], String> {
    let mut hmac = HmacSha512::new_from_slice(key).map_err(|error| error.to_string())?;
    hmac.update(data);
    let bytes = hmac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn derive_bip32_secp_path(seed: &[u8; 64], path: &[u32]) -> Result<[u8; 32], String> {
    let mut master = hmac_sha512_bytes(b"Bitcoin seed", seed)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&master[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&master[32..]);
    master.zeroize();

    SecretKey::from_slice(&key)
        .map_err(|error| format!("master BIP32 secp256k1 invalida: {}", error))?;

    let secp = Secp256k1::new();
    for child_index in path {
        let mut data = Vec::with_capacity(37);
        if child_index & 0x8000_0000 != 0 {
            data.push(0);
            data.extend_from_slice(&key);
        } else {
            let parent = SecretKey::from_slice(&key)
                .map_err(|error| format!("clave padre BIP32 invalida: {}", error))?;
            let public = PublicKey::from_secret_key(&secp, &parent).serialize();
            data.extend_from_slice(&public);
        }
        data.extend_from_slice(&child_index.to_be_bytes());

        let mut material = hmac_sha512_bytes(&chain_code, &data)?;
        data.zeroize();

        let mut tweak_bytes = [0u8; 32];
        tweak_bytes.copy_from_slice(&material[..32]);
        let tweak = Scalar::from_be_bytes(tweak_bytes).map_err(|_| "tweak BIP32 fuera de rango")?;
        let parent = SecretKey::from_slice(&key)
            .map_err(|error| format!("clave padre BIP32 invalida: {}", error))?;
        let child = parent
            .add_tweak(&tweak)
            .map_err(|error| format!("clave hija BIP32 invalida: {}", error))?;
        key.copy_from_slice(child.as_ref());
        chain_code.copy_from_slice(&material[32..]);
        tweak_bytes.zeroize();
        material.zeroize();
    }

    chain_code.zeroize();
    Ok(key)
}

fn derive_slip10_ed25519_path(seed: &[u8; 64], path: &[u32]) -> Result<[u8; 32], String> {
    let mut master = hmac_sha512_bytes(b"ed25519 seed", seed)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&master[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&master[32..]);
    master.zeroize();

    for child_index in path {
        if child_index & 0x8000_0000 == 0 {
            return Err("SLIP10 ed25519 solo admite indices endurecidos".into());
        }
        let mut data = Vec::with_capacity(37);
        data.push(0);
        data.extend_from_slice(&key);
        data.extend_from_slice(&child_index.to_be_bytes());
        let mut material = hmac_sha512_bytes(&chain_code, &data)?;
        data.zeroize();
        key.copy_from_slice(&material[..32]);
        chain_code.copy_from_slice(&material[32..]);
        material.zeroize();
    }

    chain_code.zeroize();
    Ok(key)
}

