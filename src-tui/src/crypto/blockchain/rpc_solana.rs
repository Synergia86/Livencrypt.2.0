// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: adaptador RPC real Solana */

use crate::crypto::blockchain::chain_requirements::solana_get_fee_for_message_payload;
use crate::crypto::blockchain::rpc::ChainRpcAdapter;
use crate::crypto::blockchain::rpc_client::json_rpc_call;
use crate::crypto::blockchain::rpc_types::{
    BalanceResult, BroadcastResult, ChainClockSample, FeeEstimate, NodeHealth, NonceState,
    TransactionStatus,
};
use crate::crypto::blockchain::types::NodeEndpointPolicy;
use rust_decimal::Decimal;
use serde_json::json;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct SolanaRpcAdapter {
    policy: NodeEndpointPolicy,
}

impl SolanaRpcAdapter {
    pub fn new(policy: NodeEndpointPolicy) -> Self {
        Self { policy }
    }

    fn endpoint(&self) -> &str {
        &self.policy.primary_endpoint
    }
}

fn lamports_to_sol(value: u64) -> Decimal {
    Decimal::from(value) / Decimal::from(1_000_000_000u64)
}

impl ChainRpcAdapter for SolanaRpcAdapter {
    fn chain_name(&self) -> &str {
        "solana"
    }

    fn endpoint_policy(&self) -> &NodeEndpointPolicy {
        &self.policy
    }

    fn health(&self) -> Result<NodeHealth, String> {
        let started = Instant::now();
        let health = json_rpc_call(
            self.endpoint(),
            "getHealth",
            json!([]),
            self.policy.timeout_ms,
        )?;
        let slot = json_rpc_call(
            self.endpoint(),
            "getSlot",
            json!([]),
            self.policy.timeout_ms,
        )?;
        Ok(NodeHealth {
            chain: "solana".to_string(),
            endpoint: self.endpoint().to_string(),
            network_id: health.as_str().unwrap_or("unknown").to_string(),
            block_height_or_slot: slot.as_u64(),
            block_time_unix: None,
            latency_ms: started.elapsed().as_millis(),
            ok: true,
            warning: None,
        })
    }

    fn read_balance(&self, address: &str, asset: &str) -> Result<BalanceResult, String> {
        if asset != "native" && asset != "SOL" {
            return Err("SPL token balance pendiente de implementacion".into());
        }
        let result = json_rpc_call(
            self.endpoint(),
            "getBalance",
            json!([address]),
            self.policy.timeout_ms,
        )?;
        let lamports = result
            .get("value")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| "getBalance sin value".to_string())?;
        Ok(BalanceResult {
            chain: "solana".to_string(),
            address: address.to_string(),
            asset: "SOL".to_string(),
            amount: lamports_to_sol(lamports),
            raw_amount: lamports.to_string(),
            endpoint: self.endpoint().to_string(),
            block_height_or_slot: None,
        })
    }

    fn read_nonce(&self, address: &str) -> Result<NonceState, String> {
        Ok(NonceState {
            chain: "solana".to_string(),
            address: address.to_string(),
            nonce: "Solana no usa nonce EVM; use blockhash reciente".to_string(),
            endpoint: self.endpoint().to_string(),
        })
    }

    fn estimate_fee(&self, raw_payload: &[u8]) -> Result<FeeEstimate, String> {
        if raw_payload.is_empty() {
            return Err("fee Solana requiere mensaje serializado".into());
        }
        let encoded = solana_get_fee_for_message_payload(raw_payload);
        let result = json_rpc_call(
            self.endpoint(),
            "getFeeForMessage",
            json!([encoded]),
            self.policy.timeout_ms,
        )?;
        let fee = result
            .get("value")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| "getFeeForMessage sin value".to_string())?;
        Ok(FeeEstimate {
            chain: "solana".to_string(),
            asset: "SOL".to_string(),
            fee_amount: lamports_to_sol(fee),
            raw_fee: fee.to_string(),
            source: "getFeeForMessage".to_string(),
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_transaction_status(&self, txid: &str) -> Result<TransactionStatus, String> {
        let result = json_rpc_call(
            self.endpoint(),
            "getSignatureStatuses",
            json!([[txid], { "searchTransactionHistory": true }]),
            self.policy.timeout_ms,
        )?;
        let value = result
            .get("value")
            .and_then(|value| value.as_array())
            .and_then(|items| items.first())
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let confirmed = !value.is_null();
        let slot = value.get("slot").and_then(|value| value.as_u64());
        let success = value.get("err").map(|value| value.is_null());
        Ok(TransactionStatus {
            chain: "solana".to_string(),
            txid: txid.to_string(),
            confirmed,
            confirmations: None,
            block_height_or_slot: slot,
            success,
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_chain_clock(&self) -> Result<ChainClockSample, String> {
        let slot = json_rpc_call(
            self.endpoint(),
            "getSlot",
            json!([]),
            self.policy.timeout_ms,
        )?;
        let local_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(ChainClockSample {
            chain: "solana".to_string(),
            endpoint: self.endpoint().to_string(),
            local_unix,
            chain_unix: None,
            block_height_or_slot: slot.as_u64(),
            drift_seconds: None,
        })
    }

    fn broadcast_transaction(&self, signed_payload: &[u8]) -> Result<BroadcastResult, String> {
        if !self.policy.allow_broadcast {
            return Err("broadcast Solana bloqueado por politica de endpoint".into());
        }
        let encoded = bs58::encode(signed_payload).into_string();
        let result = json_rpc_call(
            self.endpoint(),
            "sendTransaction",
            json!([encoded]),
            self.policy.timeout_ms,
        )?;
        let txid = result
            .as_str()
            .ok_or_else(|| "sendTransaction no devolvio firma".to_string())?;
        Ok(BroadcastResult {
            chain: "solana".to_string(),
            txid: txid.to_string(),
            endpoint: self.endpoint().to_string(),
            accepted: true,
        })
    }
}
