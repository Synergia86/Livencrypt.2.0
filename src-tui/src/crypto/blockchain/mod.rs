// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: enrutador maestro del subsistema blockchain universal */

pub mod address;
pub mod breaker;
pub mod chain_requirements;
pub mod eth_abi;
pub mod eth_rlp;
pub mod eth_simulation;
pub mod eth_tx;
pub mod eth_types;
pub mod firewall;
pub mod multi_curve;
pub mod nodes;
pub mod preflight;
pub mod price_import;
pub mod proxy;
pub mod rpc;
pub mod rpc_bitcoin;
pub mod rpc_client;
pub mod rpc_ethereum;
pub mod rpc_manager;
pub mod rpc_quorum;
pub mod rpc_solana;
pub mod rpc_types;
pub mod supervisor;
pub mod tx_parser;
pub mod types;
pub mod web3_audit;
pub mod worker;

use crate::crypto::blockchain::tx_parser::{parse_tx_payload, ParsedTx};
use crate::crypto::blockchain::types::{ChainType, SignatureResponse};

/// Interfaz unificada de los adaptadores de cadena: valida la estructura del
/// payload crudo y reconstruye el mensaje firmado listo para transmisión.
pub trait ChainAdapter {
    fn chain(&self) -> ChainType;
    fn parse_payload(&self, raw: &[u8]) -> Result<ParsedTx, String>;
    fn rebuild_signed_message(
        &self,
        raw: &[u8],
        signature: &SignatureResponse,
    ) -> Result<Vec<u8>, String>;
}

pub struct BitcoinAdapter;
pub struct EthereumAdapter;
pub struct SolanaAdapter;

impl ChainAdapter for BitcoinAdapter {
    fn chain(&self) -> ChainType {
        ChainType::Bitcoin
    }

    fn parse_payload(&self, raw: &[u8]) -> Result<ParsedTx, String> {
        parse_tx_payload(&ChainType::Bitcoin, raw)
    }

    fn rebuild_signed_message(
        &self,
        _raw: &[u8],
        _signature: &SignatureResponse,
    ) -> Result<Vec<u8>, String> {
        Err("reconstruccion de transaccion Bitcoin pendiente: requiere insercion de scriptSig por entrada".into())
    }
}

impl ChainAdapter for EthereumAdapter {
    fn chain(&self) -> ChainType {
        ChainType::Ethereum
    }

    fn parse_payload(&self, raw: &[u8]) -> Result<ParsedTx, String> {
        parse_tx_payload(&ChainType::Ethereum, raw)
    }

    fn rebuild_signed_message(
        &self,
        _raw: &[u8],
        _signature: &SignatureResponse,
    ) -> Result<Vec<u8>, String> {
        Err("reconstruccion de transaccion Ethereum pendiente: requiere recodificacion RLP con v, r, s".into())
    }
}

impl ChainAdapter for SolanaAdapter {
    fn chain(&self) -> ChainType {
        ChainType::Solana
    }

    fn parse_payload(&self, raw: &[u8]) -> Result<ParsedTx, String> {
        parse_tx_payload(&ChainType::Solana, raw)
    }

    fn rebuild_signed_message(
        &self,
        raw: &[u8],
        signature: &SignatureResponse,
    ) -> Result<Vec<u8>, String> {
        if signature.raw_signature.len() != 64 {
            return Err("firma Solana invalida: se esperaban 64 bytes ed25519".into());
        }
        let mut transaction = Vec::with_capacity(1 + 64 + raw.len());
        transaction.push(1);
        transaction.extend_from_slice(&signature.raw_signature);
        transaction.extend_from_slice(raw);
        Ok(transaction)
    }
}

pub fn adapter_for(chain: &ChainType) -> Result<Box<dyn ChainAdapter>, String> {
    match chain {
        ChainType::Bitcoin => Ok(Box::new(BitcoinAdapter)),
        ChainType::Ethereum => Ok(Box::new(EthereumAdapter)),
        ChainType::Solana => Ok(Box::new(SolanaAdapter)),
        ChainType::Monero => Err("Monero no soportado por los adaptadores de cadena".into()),
        ChainType::Zcash => Err("Zcash no soportado por los adaptadores de cadena".into()),
        ChainType::Starknet => Err("Starknet no soportado por los adaptadores de cadena".into()),
    }
}
