// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: tipos de datos unificados para el proxy criptografico blockchain */

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ChainType {
    Bitcoin,
    Ethereum,
    Solana,
    Monero,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TxMethod {
    EthTransfer,
    EthErc20Transfer,
    EthUnsupported(String),
    BtcRawTx,
    SolanaTransfer,
    /// Métodos no reconocidos en cadenas no EVM (Solana, Bitcoin, etc.)
    Unsupported(String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyDerivationRequest {
    pub chain: ChainType,
    pub account_index: u32,
    pub address_index: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactionSignRequest {
    pub chain: ChainType,
    pub account_index: u32,
    pub address_index: u32,
    pub raw_tx_payload: Vec<u8>,
    pub value_usd: Decimal,
    pub target_dex_cex_id: Option<String>,
}

impl Drop for TransactionSignRequest {
    fn drop(&mut self) {
        self.raw_tx_payload.zeroize();
        if let Some(target) = self.target_dex_cex_id.as_mut() {
            target.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct SignatureResponse {
    pub public_key: Vec<u8>,
    pub raw_signature: Vec<u8>,
    pub recovery_id: Option<u8>,
}
