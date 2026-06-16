// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: simulacion Ethereum previa a firma con lecturas RPC por quorum */

use crate::crypto::blockchain::eth_types::EthereumTxRequest;
use crate::crypto::blockchain::nodes::NodeRegistry;
use crate::crypto::blockchain::rpc_quorum::json_rpc_quorum;
use serde_json::json;

#[derive(Clone, Debug)]
pub struct EthereumSimulationReport {
    pub chain_id_ok: bool,
    pub nonce_ok: bool,
    pub gas_ok: bool,
    pub contract_exists: bool,
    pub call_ok: bool,
    pub warnings: Vec<String>,
}

pub fn simulate_ethereum_tx(
    registry: &NodeRegistry,
    tx: &EthereumTxRequest,
) -> Result<EthereumSimulationReport, String> {
    let mut warnings = Vec::new();

    let min_agreement = if registry.endpoints("ethereum").len() >= 2 {
        2
    } else {
        1
    };

    let chain_id = json_rpc_quorum(
        registry,
        "ethereum",
        "eth_chainId",
        json!([]),
        min_agreement,
    )?;
    let chain_id_ok = chain_id
        .value
        .as_ref()
        .and_then(|value| value.as_str())
        .map(|value| value == format!("0x{:x}", tx.chain_id))
        .unwrap_or(false);
    if !chain_id_ok {
        warnings.push("chainId no coincide entre transaccion y nodo".into());
    }

    let nonce = json_rpc_quorum(
        registry,
        "ethereum",
        "eth_getTransactionCount",
        json!([tx.from, "pending"]),
        min_agreement,
    )?;
    let nonce_ok = nonce.agreed;
    if !nonce_ok {
        warnings.push("nonce sin quorum suficiente".into());
    }

    let contract_exists = if let Some(to) = &tx.to {
        let code = json_rpc_quorum(
            registry,
            "ethereum",
            "eth_getCode",
            json!([to, "latest"]),
            min_agreement,
        )?;
        let exists = code
            .value
            .as_ref()
            .and_then(|value| value.as_str())
            .map(|value| value != "0x")
            .unwrap_or(false);
        if !exists && !tx.data.is_empty() && tx.data != "0x" {
            warnings.push("calldata contra direccion sin contrato".into());
        }
        exists
    } else {
        true
    };

    let call_object = json!({
        "from": tx.from,
        "to": tx.to,
        "value": tx.value,
        "data": tx.data
    });
    let gas = json_rpc_quorum(
        registry,
        "ethereum",
        "eth_estimateGas",
        json!([call_object.clone()]),
        min_agreement,
    )?;
    let gas_ok = gas.agreed && gas.value.is_some();
    if !gas_ok {
        warnings.push("eth_estimateGas sin quorum".into());
    }

    let call = json_rpc_quorum(
        registry,
        "ethereum",
        "eth_call",
        json!([call_object, "latest"]),
        min_agreement,
    )?;
    let call_ok = call.agreed && call.value.is_some();
    if !call_ok {
        warnings.push("eth_call sin quorum o fallo de simulacion".into());
    }

    Ok(EthereumSimulationReport {
        chain_id_ok,
        nonce_ok,
        gas_ok,
        contract_exists,
        call_ok,
        warnings,
    })
}
