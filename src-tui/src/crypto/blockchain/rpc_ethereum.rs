// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: adaptador RPC real Ethereum/EVM */

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

pub struct EthereumRpcAdapter {
    policy: NodeEndpointPolicy,
}

impl EthereumRpcAdapter {
    pub fn new(policy: NodeEndpointPolicy) -> Self {
        Self { policy }
    }

    fn endpoint(&self) -> &str {
        &self.policy.primary_endpoint
    }
}

fn hex_u64(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| format!("hex u64 invalido: {}", error))
}

fn hex_u128(value: &str) -> Result<u128, String> {
    u128::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| format!("hex u128 invalido: {}", error))
}

fn wei_to_eth(value: u128) -> Decimal {
    Decimal::from(value) / Decimal::from(1_000_000_000_000_000_000u128)
}

impl ChainRpcAdapter for EthereumRpcAdapter {
    fn chain_name(&self) -> &str {
        "ethereum"
    }

    fn endpoint_policy(&self) -> &NodeEndpointPolicy {
        &self.policy
    }

    fn health(&self) -> Result<NodeHealth, String> {
        let started = Instant::now();
        let chain_id = json_rpc_call(
            self.endpoint(),
            "eth_chainId",
            json!([]),
            self.policy.timeout_ms,
        )?;
        let chain_id = chain_id
            .as_str()
            .ok_or_else(|| "eth_chainId no es string".to_string())?
            .to_string();

        if !self.policy.require_chain_id.is_empty() && chain_id != self.policy.require_chain_id {
            return Err(format!(
                "chain ID no coincide: esperado {}, recibido {}",
                self.policy.require_chain_id, chain_id
            ));
        }

        let block_number = json_rpc_call(
            self.endpoint(),
            "eth_blockNumber",
            json!([]),
            self.policy.timeout_ms,
        )?;
        let block_height = block_number.as_str().map(hex_u64).transpose()?;

        Ok(NodeHealth {
            chain: "ethereum".to_string(),
            endpoint: self.endpoint().to_string(),
            network_id: chain_id,
            block_height_or_slot: block_height,
            block_time_unix: None,
            latency_ms: started.elapsed().as_millis(),
            ok: true,
            warning: None,
        })
    }

    fn read_balance(&self, address: &str, asset: &str) -> Result<BalanceResult, String> {
        if asset != "native" && asset != "ETH" {
            return Err("balance ERC-20 requiere eth_call balanceOf pendiente".into());
        }
        let result = json_rpc_call(
            self.endpoint(),
            "eth_getBalance",
            json!([address, "latest"]),
            self.policy.timeout_ms,
        )?;
        let raw = result
            .as_str()
            .ok_or_else(|| "eth_getBalance no es string".to_string())?;
        let wei = hex_u128(raw)?;
        Ok(BalanceResult {
            chain: "ethereum".to_string(),
            address: address.to_string(),
            asset: "ETH".to_string(),
            amount: wei_to_eth(wei),
            raw_amount: raw.to_string(),
            endpoint: self.endpoint().to_string(),
            block_height_or_slot: None,
        })
    }

    fn read_nonce(&self, address: &str) -> Result<NonceState, String> {
        let result = json_rpc_call(
            self.endpoint(),
            "eth_getTransactionCount",
            json!([address, "latest"]),
            self.policy.timeout_ms,
        )?;
        Ok(NonceState {
            chain: "ethereum".to_string(),
            address: address.to_string(),
            nonce: result.as_str().unwrap_or_default().to_string(),
            endpoint: self.endpoint().to_string(),
        })
    }

    fn estimate_fee(&self, _raw_payload: &[u8]) -> Result<FeeEstimate, String> {
        let gas_price = json_rpc_call(
            self.endpoint(),
            "eth_gasPrice",
            json!([]),
            self.policy.timeout_ms,
        )?;
        let raw = gas_price
            .as_str()
            .ok_or_else(|| "eth_gasPrice no es string".to_string())?;
        let wei = hex_u128(raw)?;
        Ok(FeeEstimate {
            chain: "ethereum".to_string(),
            asset: "ETH".to_string(),
            fee_amount: wei_to_eth(wei),
            raw_fee: raw.to_string(),
            source: "eth_gasPrice".to_string(),
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_transaction_status(&self, txid: &str) -> Result<TransactionStatus, String> {
        let result = json_rpc_call(
            self.endpoint(),
            "eth_getTransactionReceipt",
            json!([txid]),
            self.policy.timeout_ms,
        )?;
        let confirmed = !result.is_null();
        let block = result
            .get("blockNumber")
            .and_then(|value| value.as_str())
            .map(hex_u64)
            .transpose()?;
        let success = result
            .get("status")
            .and_then(|value| value.as_str())
            .map(|status| status == "0x1");
        Ok(TransactionStatus {
            chain: "ethereum".to_string(),
            txid: txid.to_string(),
            confirmed,
            confirmations: None,
            block_height_or_slot: block,
            success,
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_chain_clock(&self) -> Result<ChainClockSample, String> {
        let block = json_rpc_call(
            self.endpoint(),
            "eth_getBlockByNumber",
            json!(["latest", false]),
            self.policy.timeout_ms,
        )?;
        let timestamp = block
            .get("timestamp")
            .and_then(|value| value.as_str())
            .map(hex_u64)
            .transpose()?;
        let number = block
            .get("number")
            .and_then(|value| value.as_str())
            .map(hex_u64)
            .transpose()?;
        let local_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let drift = timestamp.map(|chain_unix| local_unix.abs_diff(chain_unix));
        Ok(ChainClockSample {
            chain: "ethereum".to_string(),
            endpoint: self.endpoint().to_string(),
            local_unix,
            chain_unix: timestamp,
            block_height_or_slot: number,
            drift_seconds: drift,
        })
    }

    fn broadcast_transaction(&self, signed_payload: &[u8]) -> Result<BroadcastResult, String> {
        if !self.policy.allow_broadcast {
            return Err("broadcast Ethereum bloqueado por politica de endpoint".into());
        }
        let hex_payload = format!("0x{}", hex::encode(signed_payload));
        let result = json_rpc_call(
            self.endpoint(),
            "eth_sendRawTransaction",
            json!([hex_payload]),
            self.policy.timeout_ms,
        )?;
        let txid = result
            .as_str()
            .ok_or_else(|| "eth_sendRawTransaction no devolvio txid".to_string())?;
        Ok(BroadcastResult {
            chain: "ethereum".to_string(),
            txid: txid.to_string(),
            endpoint: self.endpoint().to_string(),
            accepted: true,
        })
    }
}
