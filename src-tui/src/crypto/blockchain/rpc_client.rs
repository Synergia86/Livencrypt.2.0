// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: cliente JSON-RPC saliente con timeout y limite de respuesta */

use serde_json::{json, Value};
use std::io::Read;
use std::time::Duration;

const MAX_RPC_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

pub fn json_rpc_call(
    endpoint: &str,
    method: &str,
    params: Value,
    timeout_ms: u64,
) -> Result<Value, String> {
    if !endpoint.starts_with("https://") && !endpoint.starts_with("http://127.0.0.1") {
        return Err("endpoint RPC no permitido: use HTTPS o localhost auditado".into());
    }

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(timeout_ms.clamp(500, 30_000)))
        .build();

    let response = agent
        .post(endpoint)
        .set("content-type", "application/json")
        .send_json(body)
        .map_err(|error| format!("RPC {} fallo: {}", method, error))?;

    let mut reader = response.into_reader().take(MAX_RPC_RESPONSE_BYTES as u64);
    let mut raw = String::new();
    reader
        .read_to_string(&mut raw)
        .map_err(|error| format!("RPC lectura respuesta fallo: {}", error))?;

    let value: Value =
        serde_json::from_str(&raw).map_err(|error| format!("RPC JSON invalido: {}", error))?;

    if let Some(error) = value.get("error") {
        return Err(format!("RPC {} devolvio error: {}", method, error));
    }

    value
        .get("result")
        .cloned()
        .ok_or_else(|| format!("RPC {} sin campo result", method))
}
