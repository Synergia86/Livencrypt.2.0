// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: contrato de adaptadores RPC multicadena sin efectos de red implicitos */

use crate::crypto::blockchain::rpc_types::{
    BalanceResult, BroadcastResult, ChainClockSample, FeeEstimate, NodeHealth, NonceState,
    TransactionStatus,
};
use crate::crypto::blockchain::types::NodeEndpointPolicy;

pub trait ChainRpcAdapter {
    fn chain_name(&self) -> &str;
    fn endpoint_policy(&self) -> &NodeEndpointPolicy;
    fn health(&self) -> Result<NodeHealth, String>;
    fn read_balance(&self, address: &str, asset: &str) -> Result<BalanceResult, String>;
    fn read_nonce(&self, address: &str) -> Result<NonceState, String>;
    fn estimate_fee(&self, raw_payload: &[u8]) -> Result<FeeEstimate, String>;
    fn read_transaction_status(&self, txid: &str) -> Result<TransactionStatus, String>;
    fn read_chain_clock(&self) -> Result<ChainClockSample, String>;
    fn broadcast_transaction(&self, signed_payload: &[u8]) -> Result<BroadcastResult, String>;
}

#[derive(Clone, Debug)]
pub struct OfflineRpcAdapter {
    policy: NodeEndpointPolicy,
}

impl OfflineRpcAdapter {
    pub fn new(policy: NodeEndpointPolicy) -> Self {
        Self { policy }
    }
}

impl ChainRpcAdapter for OfflineRpcAdapter {
    fn chain_name(&self) -> &str {
        &self.policy.chain
    }

    fn endpoint_policy(&self) -> &NodeEndpointPolicy {
        &self.policy
    }

    fn health(&self) -> Result<NodeHealth, String> {
        Err("perfil OFFLINE: health RPC desactivado".into())
    }

    fn read_balance(&self, _address: &str, _asset: &str) -> Result<BalanceResult, String> {
        Err("perfil OFFLINE: lectura de saldo RPC desactivada".into())
    }

    fn read_nonce(&self, _address: &str) -> Result<NonceState, String> {
        Err("perfil OFFLINE: lectura de nonce RPC desactivada".into())
    }

    fn estimate_fee(&self, _raw_payload: &[u8]) -> Result<FeeEstimate, String> {
        Err("perfil OFFLINE: estimacion de fee RPC desactivada".into())
    }

    fn read_transaction_status(&self, _txid: &str) -> Result<TransactionStatus, String> {
        Err("perfil OFFLINE: estado de transaccion RPC desactivado".into())
    }

    fn read_chain_clock(&self) -> Result<ChainClockSample, String> {
        Err("perfil OFFLINE: reloj de cadena RPC desactivado".into())
    }

    fn broadcast_transaction(&self, _signed_payload: &[u8]) -> Result<BroadcastResult, String> {
        Err("perfil OFFLINE: broadcast bloqueado".into())
    }
}
