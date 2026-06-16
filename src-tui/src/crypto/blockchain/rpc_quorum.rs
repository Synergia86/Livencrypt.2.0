// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: quorum de lecturas RPC para reducir dependencia de un nodo unico */

use crate::crypto::blockchain::nodes::NodeRegistry;
use crate::crypto::blockchain::rpc_client::json_rpc_call;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct QuorumResult {
    pub method: String,
    pub agreed: bool,
    pub value: Option<Value>,
    pub endpoint_results: Vec<EndpointResult>,
}

#[derive(Clone, Debug)]
pub struct EndpointResult {
    pub endpoint: String,
    pub result: Result<Value, String>,
}

pub fn json_rpc_quorum(
    registry: &NodeRegistry,
    chain: &str,
    method: &str,
    params: Value,
    min_agreement: usize,
) -> Result<QuorumResult, String> {
    if !registry.profile().allows_rpc_read() {
        return Err("perfil OFFLINE: quorum RPC bloqueado".into());
    }

    let endpoints = registry.endpoints(chain);
    if endpoints.is_empty() {
        return Err(format!("sin endpoints para {}", chain));
    }

    let required = min_agreement.max(1).min(endpoints.len());
    let mut endpoint_results = Vec::new();
    let mut counts: HashMap<String, (usize, Value)> = HashMap::new();

    for endpoint in endpoints {
        let result = json_rpc_call(&endpoint, method, params.clone(), registry.timeout_ms());
        if let Ok(value) = &result {
            let key = canonical_json(value)?;
            let entry = counts.entry(key).or_insert((0, value.clone()));
            entry.0 += 1;
        }
        endpoint_results.push(EndpointResult { endpoint, result });
    }

    let best = counts.into_iter().max_by_key(|(_, (count, _))| *count);
    if let Some((_, (count, value))) = best {
        return Ok(QuorumResult {
            method: method.to_string(),
            agreed: count >= required,
            value: Some(value),
            endpoint_results,
        });
    }

    Ok(QuorumResult {
        method: method.to_string(),
        agreed: false,
        value: None,
        endpoint_results,
    })
}

pub fn require_real_quorum(registry: &NodeRegistry, chain: &str) -> Result<(), String> {
    let endpoints = registry.endpoints(chain);
    if endpoints.len() < 2 {
        return Err(format!(
            "firma bloqueada: {} requiere al menos 2 endpoints RPC para quorum",
            chain
        ));
    }
    Ok(())
}

fn canonical_json(value: &Value) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_quorum_requires_two_endpoints_for_signing() {
        let registry = NodeRegistry::default();
        let error =
            require_real_quorum(&registry, "ethereum").expect_err("sin endpoints debe fallar");
        assert!(error.contains("requiere al menos 2 endpoints"));
    }
}
