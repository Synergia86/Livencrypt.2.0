// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: preflight Web3 antes de permitir preview/firma */

use crate::crypto::blockchain::eth_abi;
use crate::crypto::blockchain::eth_simulation::simulate_ethereum_tx;
use crate::crypto::blockchain::eth_types::{EthereumCallRisk, EthereumTxRequest};
use crate::crypto::blockchain::nodes::NodeRegistry;

#[derive(Clone, Debug)]
pub struct PreflightDecision {
    pub allowed: bool,
    pub requires_strong_confirmation: bool,
    pub summary: String,
    pub warnings: Vec<String>,
}

pub fn preflight_ethereum(
    registry: &NodeRegistry,
    tx: &EthereumTxRequest,
) -> Result<PreflightDecision, String> {
    let contract = tx.to.clone().unwrap_or_default();
    let decoded = eth_abi::decode_call(&contract, &tx.data)?;
    let simulation = simulate_ethereum_tx(registry, tx)?;

    let mut warnings = simulation.warnings;
    if decoded.risk == EthereumCallRisk::Critical {
        warnings.push("metodo critico o desconocido".into());
    }
    if !simulation.contract_exists && !tx.data.is_empty() && tx.data != "0x" {
        warnings.push("contrato no detectado para calldata".into());
    }

    let allowed = simulation.chain_id_ok
        && simulation.nonce_ok
        && simulation.gas_ok
        && simulation.call_ok
        && decoded.risk != EthereumCallRisk::Critical;

    Ok(PreflightDecision {
        allowed,
        requires_strong_confirmation: decoded.risk == EthereumCallRisk::High,
        summary: format!(
            "metodo={} selector={} contrato={} riesgo={}",
            decoded.method,
            decoded.selector,
            decoded.contract,
            decoded.risk.label()
        ),
        warnings,
    })
}
