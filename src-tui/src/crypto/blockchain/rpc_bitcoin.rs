// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: adaptador Bitcoin mediante endpoint Electrum HTTPS/JSON-RPC */

use crate::crypto::blockchain::rpc::ChainRpcAdapter;
use crate::crypto::blockchain::rpc_client::json_rpc_call;
use crate::crypto::blockchain::rpc_types::{
    BalanceResult, BroadcastResult, ChainClockSample, FeeEstimate, NodeHealth, NonceState,
    TransactionStatus,
};
use crate::crypto::blockchain::types::NodeEndpointPolicy;
use rust_decimal::Decimal;
use serde_json::json;
use std::str::FromStr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct BitcoinElectrumAdapter {
    policy: NodeEndpointPolicy,
}

impl BitcoinElectrumAdapter {
    pub fn new(policy: NodeEndpointPolicy) -> Self {
        Self { policy }
    }

    fn endpoint(&self) -> &str {
        &self.policy.primary_endpoint
    }
}

fn sats_to_btc(value: u64) -> Decimal {
    Decimal::from(value) / Decimal::from(100_000_000u64)
}

impl ChainRpcAdapter for BitcoinElectrumAdapter {
    fn chain_name(&self) -> &str {
        "bitcoin"
    }

    fn endpoint_policy(&self) -> &NodeEndpointPolicy {
        &self.policy
    }

    fn health(&self) -> Result<NodeHealth, String> {
        let started = Instant::now();
        let electrum = json_rpc_call(
            self.endpoint(),
            "blockchain.headers.subscribe",
            json!([]),
            self.policy.timeout_ms,
        );
        if let Ok(result) = electrum {
            let height = result.get("height").and_then(|value| value.as_u64());
            return Ok(NodeHealth {
                chain: "bitcoin".to_string(),
                endpoint: self.endpoint().to_string(),
                network_id: "electrum".to_string(),
                block_height_or_slot: height,
                block_time_unix: None,
                latency_ms: started.elapsed().as_millis(),
                ok: true,
                warning: None,
            });
        }

        let info = json_rpc_call(
            self.endpoint(),
            "getblockchaininfo",
            json!([]),
            self.policy.timeout_ms,
        )?;
        let height = info.get("blocks").and_then(|value| value.as_u64());
        let network = info
            .get("chain")
            .and_then(|value| value.as_str())
            .unwrap_or("bitcoin-core")
            .to_string();
        Ok(NodeHealth {
            chain: "bitcoin".to_string(),
            endpoint: self.endpoint().to_string(),
            network_id: network,
            block_height_or_slot: height,
            block_time_unix: None,
            latency_ms: started.elapsed().as_millis(),
            ok: true,
            warning: Some(
                "endpoint Bitcoin Core: balance por direccion requiere indexador/Electrum"
                    .to_string(),
            ),
        })
    }

    fn read_balance(&self, script_hash: &str, asset: &str) -> Result<BalanceResult, String> {
        if asset != "native" && asset != "BTC" {
            return Err("Bitcoin solo soporta BTC nativo".into());
        }
        let result = json_rpc_call(
            self.endpoint(),
            "blockchain.scripthash.get_balance",
            json!([script_hash]),
            self.policy.timeout_ms,
        )
        .map_err(|error| {
            if error.contains("Method not found") {
                "balance BTC requiere endpoint Electrum por scripthash o indexador de direcciones; Bitcoin Core RPC publico no expone balance por direccion".to_string()
            } else {
                error
            }
        })?;
        let confirmed = result
            .get("confirmed")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| "balance Electrum sin confirmed".to_string())?;
        Ok(BalanceResult {
            chain: "bitcoin".to_string(),
            address: script_hash.to_string(),
            asset: "BTC".to_string(),
            amount: sats_to_btc(confirmed),
            raw_amount: confirmed.to_string(),
            endpoint: self.endpoint().to_string(),
            block_height_or_slot: None,
        })
    }

    fn read_nonce(&self, address: &str) -> Result<NonceState, String> {
        Ok(NonceState {
            chain: "bitcoin".to_string(),
            address: address.to_string(),
            nonce: "Bitcoin usa UTXO; nonce no aplica".to_string(),
            endpoint: self.endpoint().to_string(),
        })
    }

    fn estimate_fee(&self, _raw_payload: &[u8]) -> Result<FeeEstimate, String> {
        let electrum = json_rpc_call(
            self.endpoint(),
            "blockchain.estimatefee",
            json!([6]),
            self.policy.timeout_ms,
        );
        let (raw_fee, source) = match electrum {
            Ok(result) => (result.to_string(), "blockchain.estimatefee".to_string()),
            Err(error) if error.contains("Method not found") => {
                let result = json_rpc_call(
                    self.endpoint(),
                    "estimatesmartfee",
                    json!([6]),
                    self.policy.timeout_ms,
                )?;
                let fee = result
                    .get("feerate")
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string());
                (fee, "estimatesmartfee".to_string())
            }
            Err(error) => return Err(error),
        };
        let btc_per_kb = Decimal::from_str(&raw_fee).unwrap_or(Decimal::ZERO);
        Ok(FeeEstimate {
            chain: "bitcoin".to_string(),
            asset: "BTC".to_string(),
            fee_amount: btc_per_kb,
            raw_fee,
            source,
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_transaction_status(&self, txid: &str) -> Result<TransactionStatus, String> {
        let electrum = json_rpc_call(
            self.endpoint(),
            "blockchain.transaction.get",
            json!([txid, true]),
            self.policy.timeout_ms,
        );
        let result = match electrum {
            Ok(result) => result,
            Err(error) if error.contains("Method not found") => json_rpc_call(
                self.endpoint(),
                "getrawtransaction",
                json!([txid, true]),
                self.policy.timeout_ms,
            )?,
            Err(error) => return Err(error),
        };
        let confirmations = result.get("confirmations").and_then(|value| value.as_u64());
        Ok(TransactionStatus {
            chain: "bitcoin".to_string(),
            txid: txid.to_string(),
            confirmed: confirmations.unwrap_or(0) > 0,
            confirmations,
            block_height_or_slot: result
                .get("blockheight")
                .or_else(|| result.get("height"))
                .and_then(|value| value.as_u64()),
            success: None,
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_chain_clock(&self) -> Result<ChainClockSample, String> {
        let health = self.health()?;
        let chain_unix = if health.network_id == "electrum" {
            None
        } else if let Some(height) = health.block_height_or_slot {
            let hash = json_rpc_call(
                self.endpoint(),
                "getblockhash",
                json!([height]),
                self.policy.timeout_ms,
            )?;
            let hash = hash
                .as_str()
                .ok_or_else(|| "getblockhash no devolvio string".to_string())?;
            let header = json_rpc_call(
                self.endpoint(),
                "getblockheader",
                json!([hash]),
                self.policy.timeout_ms,
            )?;
            header.get("time").and_then(|value| value.as_u64())
        } else {
            None
        };
        let local_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let drift = chain_unix.map(|chain_unix| local_unix.abs_diff(chain_unix));
        Ok(ChainClockSample {
            chain: "bitcoin".to_string(),
            endpoint: self.endpoint().to_string(),
            local_unix,
            chain_unix,
            block_height_or_slot: health.block_height_or_slot,
            drift_seconds: drift,
        })
    }

    fn broadcast_transaction(&self, signed_payload: &[u8]) -> Result<BroadcastResult, String> {
        if !self.policy.allow_broadcast {
            return Err("broadcast Bitcoin bloqueado por politica de endpoint".into());
        }
        let tx_hex = hex::encode(signed_payload);
        let result = json_rpc_call(
            self.endpoint(),
            "blockchain.transaction.broadcast",
            json!([tx_hex]),
            self.policy.timeout_ms,
        )?;
        let txid = result
            .as_str()
            .ok_or_else(|| "broadcast Bitcoin no devolvio txid".to_string())?;
        Ok(BroadcastResult {
            chain: "bitcoin".to_string(),
            txid: txid.to_string(),
            endpoint: self.endpoint().to_string(),
            accepted: true,
        })
    }
}
