// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: tipos de datos unificados para el proxy criptografico blockchain */

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ChainType {
    Bitcoin,
    Ethereum,
    Solana,
    Monero,
    Zcash,
    Starknet,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Web3ConnectivityProfile {
    Offline,
    RpcReadOnly,
    RpcOperational,
}

impl Default for Web3ConnectivityProfile {
    fn default() -> Self {
        Self::Offline
    }
}

impl Web3ConnectivityProfile {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Offline => "OFFLINE",
            Self::RpcReadOnly => "RPC LECTURA",
            Self::RpcOperational => "RPC OPERATIVO",
        }
    }

    pub fn allows_rpc_read(&self) -> bool {
        matches!(self, Self::RpcReadOnly | Self::RpcOperational)
    }

    pub fn allows_broadcast(&self) -> bool {
        matches!(self, Self::RpcOperational)
    }

    pub fn next(&self) -> Self {
        match self {
            Self::Offline => Self::RpcReadOnly,
            Self::RpcReadOnly => Self::RpcOperational,
            Self::RpcOperational => Self::Offline,
        }
    }
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
    #[serde(default)]
    pub network: crate::crypto::blockchain::address::Network,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Web3AccountRequest {
    pub chain: ChainType,
    pub account_index: u32,
    pub address_index: u32,
    pub origin: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Web3AccountResponse {
    pub chain: ChainType,
    pub chain_id: String,
    pub account_index: u32,
    pub address_index: u32,
    pub derivation_path: String,
    pub address: String,
    pub public_key_hex: String,
    pub scope: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Web3StatusResponse {
    pub unlocked: bool,
    pub gateway_state: String,
    pub profile: String,
    pub supported_chains: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Web3OriginPolicy {
    pub origin: String,
    pub allowed_methods: Vec<String>,
    pub allowed_chain_ids: Vec<String>,
    pub allowed_accounts: Vec<(u32, u32)>,
    pub max_daily_tx: u32,
    pub max_daily_fiat: Option<Decimal>,
}

pub fn validate_origin_policy(
    policy: &Web3OriginPolicy,
    method: &str,
    chain_id: &str,
    account_index: u32,
    address_index: u32,
) -> Result<(), String> {
    if !policy.allowed_methods.iter().any(|value| value == method) {
        return Err("metodo no permitido para este dominio".into());
    }
    if !policy
        .allowed_chain_ids
        .iter()
        .any(|value| value == chain_id)
    {
        return Err("chain_id no permitido para este dominio".into());
    }
    if !policy
        .allowed_accounts
        .iter()
        .any(|(account, index)| *account == account_index && *index == address_index)
    {
        return Err("cuenta no permitida para este dominio".into());
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Web3ReadBalanceRequest {
    pub chain: String,
    pub address: String,
    pub asset: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Web3ReadNonceRequest {
    pub chain: String,
    pub address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Web3EstimateFeeRequest {
    pub chain: String,
    pub raw_payload: Vec<u8>,
}

impl Drop for Web3EstimateFeeRequest {
    fn drop(&mut self) {
        self.raw_payload.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactionSignRequest {
    pub chain: ChainType,
    pub account_index: u32,
    pub address_index: u32,
    pub raw_tx_payload: Vec<u8>,
    pub value_usd: Decimal,
    pub target_dex_cex_id: Option<String>,
    #[serde(default)]
    pub network: crate::crypto::blockchain::address::Network,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BroadcastTransactionRequest {
    pub chain: ChainType,
    pub signed_payload: Vec<u8>,
}

/// Resumen de un broadcast pendiente de autorizacion local (sin exponer el payload firmado).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BroadcastRequestPreview {
    pub request_id: u64,
    pub chain: ChainType,
    pub payload_len: usize,
    pub payload_sha256: String,
}

impl Drop for BroadcastTransactionRequest {
    fn drop(&mut self) {
        self.signed_payload.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SigningRequestPreview {
    pub request_id: u64,
    pub chain: ChainType,
    pub chain_id: u64,
    pub account_index: u32,
    pub address_index: u32,
    pub method: TxMethod,
    pub summary: String,
    pub target_dex_cex_id: Option<String>,
    pub value_usd: Decimal,
    pub effective_volume_units: Decimal,
    /// Comision estimada para mostrar al autorizar (None si OFFLINE o sin nodo).
    pub fee_estimate: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccountPolicy {
    pub chain: ChainType,
    pub account_index: u32,
    pub address_index: Option<u32>,
    pub label: String,
    pub max_tx_per_window: u32,
    pub max_native_amount: Option<Decimal>,
    pub max_asset_amounts: HashMap<String, Decimal>,
    pub max_fiat_value: Option<Decimal>,
    pub max_fiat_value_per_tx: Option<Decimal>,
    #[serde(default)]
    pub max_fee_native: Option<Decimal>,
    pub fiat_currency: String,
    pub allowed_destinations: Vec<String>,
    pub allowed_contracts: Vec<String>,
    #[serde(default)]
    pub scheduled_rules: Vec<ScheduledPolicy>,
    pub require_local_confirmation: bool,
}

impl AccountPolicy {
    pub fn applies_to(&self, chain: &ChainType, account_index: u32, address_index: u32) -> bool {
        self.chain == *chain
            && self.account_index == account_index
            && self
                .address_index
                .map(|expected| expected == address_index)
                .unwrap_or(true)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PolicyWindow {
    Daily,
    Weekly,
    Monthly,
    CustomSeconds(u64),
}

impl Default for PolicyWindow {
    fn default() -> Self {
        Self::Daily
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScheduledPolicy {
    pub name: String,
    pub enabled: bool,
    pub chain: ChainType,
    pub account_index: u32,
    pub address_index: Option<u32>,
    pub asset: String,
    pub destination: String,
    pub max_tx: u32,
    pub max_asset_amount: Option<Decimal>,
    pub max_fiat_value: Option<Decimal>,
    pub fiat_currency: String,
    pub window: PolicyWindow,
    pub expires_unix: Option<u64>,
    pub require_local_confirmation: bool,
}

impl ScheduledPolicy {
    pub fn applies_to(
        &self,
        chain: &ChainType,
        account_index: u32,
        address_index: u32,
        destination: &str,
    ) -> bool {
        self.enabled
            && self.chain == *chain
            && self.account_index == account_index
            && self
                .address_index
                .map(|expected| expected == address_index)
                .unwrap_or(true)
            && self.destination == destination
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum PriceOracleMode {
    OfflineManual,
    SignedFile,
    RpcOnline,
}

impl Default for PriceOracleMode {
    fn default() -> Self {
        Self::OfflineManual
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PriceQuote {
    pub asset: String,
    pub fiat: String,
    pub value: Decimal,
    pub timestamp_unix: u64,
    pub source: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PriceBook {
    pub mode: PriceOracleMode,
    pub primary_fiat: String,
    pub max_age_seconds: u64,
    pub quotes: Vec<PriceQuote>,
}

impl Default for PriceBook {
    fn default() -> Self {
        Self {
            mode: PriceOracleMode::OfflineManual,
            primary_fiat: "USD".to_string(),
            max_age_seconds: 86_400,
            quotes: Vec::new(),
        }
    }
}

impl PriceBook {
    pub fn quote(&self, asset: &str, fiat: &str) -> Option<&PriceQuote> {
        self.quotes.iter().find(|quote| {
            quote.asset.eq_ignore_ascii_case(asset) && quote.fiat.eq_ignore_ascii_case(fiat)
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChainTime {
    pub chain: String,
    pub unix_timestamp: Option<u64>,
    pub block_height_or_slot: Option<u64>,
    pub source_endpoint: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VerifiedClockStatus {
    pub local_unix: u64,
    pub consensus_unix: Option<u64>,
    pub drift_seconds: Option<u64>,
    pub max_drift_seconds: u64,
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeEndpointPolicy {
    pub chain: String,
    pub primary_endpoint: String,
    pub fallback_endpoints: Vec<String>,
    pub allow_broadcast: bool,
    pub require_chain_id: String,
    pub max_clock_drift_seconds: u64,
    pub timeout_ms: u64,
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
