// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: gestor de adaptadores RPC por cadena con fallback */

use crate::crypto::blockchain::nodes::NodeRegistry;
use crate::crypto::blockchain::rpc::ChainRpcAdapter;
use crate::crypto::blockchain::rpc_bitcoin::BitcoinElectrumAdapter;
use crate::crypto::blockchain::rpc_ethereum::EthereumRpcAdapter;
use crate::crypto::blockchain::rpc_solana::SolanaRpcAdapter;
use crate::crypto::blockchain::types::VerifiedClockStatus;

pub fn adapter_for_chain(
    registry: &NodeRegistry,
    chain: &str,
) -> Result<Box<dyn ChainRpcAdapter + Send>, String> {
    if !registry.profile().allows_rpc_read() {
        return Err("perfil OFFLINE: lectura RPC bloqueada".into());
    }

    let policy = registry
        .endpoint_policy(chain)
        .ok_or_else(|| format!("no hay endpoint RPC configurado para {}", chain))?;

    match chain.to_lowercase().as_str() {
        "ethereum" => Ok(Box::new(EthereumRpcAdapter::new(policy))),
        "bitcoin" => Ok(Box::new(BitcoinElectrumAdapter::new(policy))),
        "solana" => Ok(Box::new(SolanaRpcAdapter::new(policy))),
        other => Err(format!("cadena sin adaptador RPC auditado: {}", other)),
    }
}

/// Difunde una transaccion firmada por la cadena indicada usando el adaptador auditado.
/// Bloqueado salvo perfil con broadcast habilitado (RpcOperational). Fail-closed sin nodo.
pub fn broadcast_raw_transaction(
    registry: &NodeRegistry,
    chain: &str,
    raw_signed_tx: &[u8],
) -> Result<String, String> {
    if !registry.profile().allows_broadcast() {
        return Err("perfil sin broadcast habilitado: envio bloqueado".into());
    }
    let adapter = adapter_for_chain(registry, chain)?;
    let result = adapter.broadcast_transaction(raw_signed_tx)?;
    Ok(result.txid)
}

pub fn verified_clock_from_nodes(
    registry: &NodeRegistry,
    chains: &[&str],
) -> Result<VerifiedClockStatus, String> {
    let mut samples = Vec::new();
    for chain in chains {
        if let Ok(adapter) = adapter_for_chain(registry, chain) {
            if let Ok(sample) = adapter.read_chain_clock() {
                if let Some(chain_unix) = sample.chain_unix {
                    samples.push(chain_unix);
                }
            }
        }
    }

    let local_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if samples.is_empty() {
        return Ok(VerifiedClockStatus {
            local_unix,
            consensus_unix: None,
            drift_seconds: None,
            max_drift_seconds: registry.max_clock_drift_seconds(),
            status: "sin muestras de nodos".to_string(),
        });
    }

    samples.sort_unstable();
    let consensus = samples[samples.len() / 2];
    let drift = local_unix.abs_diff(consensus);
    let ok = drift <= registry.max_clock_drift_seconds();

    Ok(VerifiedClockStatus {
        local_unix,
        consensus_unix: Some(consensus),
        drift_seconds: Some(drift),
        max_drift_seconds: registry.max_clock_drift_seconds(),
        status: if ok {
            "OK".to_string()
        } else {
            "DRIFT_EXCESIVO".to_string()
        },
    })
}
