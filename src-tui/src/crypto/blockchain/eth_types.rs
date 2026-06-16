// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: tipos Ethereum para preparacion, decodificacion y preflight */

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EthereumTxKind {
    Legacy,
    Eip2930,
    Eip1559,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumTxRequest {
    pub chain_id: u64,
    pub from: String,
    pub to: Option<String>,
    pub nonce: u64,
    pub value: String,
    pub data: String,
    pub gas_limit: u64,
    pub gas_price: Option<String>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub kind: EthereumTxKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumPrepareTransactionRequest {
    pub origin: String,
    pub account_index: u32,
    pub address_index: u32,
    pub tx: EthereumTxRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumPreparedTransaction {
    pub unsigned_payload_hex: String,
    pub decoded_method: String,
    pub risk: String,
    pub summary: String,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumSignedTransaction {
    pub raw_tx_hex: String,
    pub tx_hash: String,
    pub decoded_method: String,
    pub risk: String,
    pub summary: String,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct EthereumDecodedCall {
    pub selector: String,
    pub method: String,
    pub contract: String,
    pub spender: Option<String>,
    pub recipient: Option<String>,
    pub amount: Option<String>,
    pub risk: EthereumCallRisk,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EthereumCallRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl EthereumCallRisk {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}
