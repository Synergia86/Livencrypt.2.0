// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: tipos comunes para lecturas RPC blockchain reales */

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeHealth {
    pub chain: String,
    pub endpoint: String,
    pub network_id: String,
    pub block_height_or_slot: Option<u64>,
    pub block_time_unix: Option<u64>,
    pub latency_ms: u128,
    pub ok: bool,
    pub warning: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceResult {
    pub chain: String,
    pub address: String,
    pub asset: String,
    pub amount: Decimal,
    pub raw_amount: String,
    pub endpoint: String,
    pub block_height_or_slot: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceState {
    pub chain: String,
    pub address: String,
    pub nonce: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub chain: String,
    pub asset: String,
    pub fee_amount: Decimal,
    pub raw_fee: String,
    pub source: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionStatus {
    pub chain: String,
    pub txid: String,
    pub confirmed: bool,
    pub confirmations: Option<u64>,
    pub block_height_or_slot: Option<u64>,
    pub success: Option<bool>,
    pub endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BroadcastResult {
    pub chain: String,
    pub txid: String,
    pub endpoint: String,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainClockSample {
    pub chain: String,
    pub endpoint: String,
    pub local_unix: u64,
    pub chain_unix: Option<u64>,
    pub block_height_or_slot: Option<u64>,
    pub drift_seconds: Option<u64>,
}
