// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: despachador dinámico de nodos de infraestructura desde nodes.toml */

use crate::crypto::blockchain::types::{
    NodeEndpointPolicy, VerifiedClockStatus, Web3ConnectivityProfile,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ChainNodesConfig {
    name: String,
    primary: String,
    #[serde(default)]
    fallbacks: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct NodesFile {
    #[serde(default)]
    profile: Web3ConnectivityProfile,
    #[serde(default = "default_max_clock_drift_seconds")]
    max_clock_drift_seconds: u64,
    #[serde(default = "default_rpc_timeout_ms")]
    timeout_ms: u64,
    #[serde(default)]
    chain: Vec<ChainNodesConfig>,
}

fn default_max_clock_drift_seconds() -> u64 {
    30
}

fn default_rpc_timeout_ms() -> u64 {
    3_000
}

/// Ruta por defecto del catálogo de nodos en el directorio local de datos.
pub fn default_nodes_path() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("nodes.toml")
}

#[derive(Debug, Clone)]
struct ChainNodes {
    endpoints: Vec<String>,
    active: usize,
}

#[derive(Debug, Clone)]
pub struct NodeRegistry {
    chains: HashMap<String, ChainNodes>,
    profile: Web3ConnectivityProfile,
    max_clock_drift_seconds: u64,
    timeout_ms: u64,
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self {
            chains: HashMap::new(),
            profile: Web3ConnectivityProfile::Offline,
            max_clock_drift_seconds: default_max_clock_drift_seconds(),
            timeout_ms: default_rpc_timeout_ms(),
        }
    }
}

impl NodeRegistry {
    /// Carga tolerante a fallos: ante cualquier error de lectura o formato se
    /// devuelve un registro vacío en lugar de abortar el binario.
    pub fn load_from_path(path: &Path) -> Self {
        Self::try_load(path).unwrap_or_default()
    }

    fn try_load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|error| format!("no se pudo leer {:?}: {}", path, error))?;
        let parsed: NodesFile =
            toml::from_str(&raw).map_err(|error| format!("nodes.toml invalido: {}", error))?;

        let mut chains = HashMap::new();
        for entry in parsed.chain {
            let name = entry.name.trim().to_lowercase();
            if name.is_empty() || entry.primary.trim().is_empty() {
                continue;
            }
            let mut endpoints = vec![entry.primary.trim().to_string()];
            for fallback in entry.fallbacks {
                let fallback = fallback.trim().to_string();
                if !fallback.is_empty() {
                    endpoints.push(fallback);
                }
            }
            chains.insert(
                name,
                ChainNodes {
                    endpoints,
                    active: 0,
                },
            );
        }
        Ok(Self {
            chains,
            profile: parsed.profile,
            max_clock_drift_seconds: parsed.max_clock_drift_seconds,
            timeout_ms: parsed.timeout_ms,
        })
    }

    pub fn reload(&mut self, path: &Path) {
        *self = Self::load_from_path(path);
    }

    pub fn profile(&self) -> &Web3ConnectivityProfile {
        &self.profile
    }

    pub fn set_profile(&mut self, profile: Web3ConnectivityProfile) {
        self.profile = profile;
    }

    pub fn max_clock_drift_seconds(&self) -> u64 {
        self.max_clock_drift_seconds
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    pub fn cycle_profile(&mut self) -> Web3ConnectivityProfile {
        self.profile = self.profile.next();
        self.profile.clone()
    }

    pub fn connectivity_summary(&self) -> String {
        let chains = self.chains.len();
        let endpoints: usize = self
            .chains
            .values()
            .map(|entry| entry.endpoints.len())
            .sum();
        match self.profile {
            Web3ConnectivityProfile::Offline => {
                format!(
                    "OFFLINE: {} cadenas, {} endpoints registrados sin uso RPC",
                    chains, endpoints
                )
            }
            Web3ConnectivityProfile::RpcReadOnly => {
                format!(
                    "RPC LECTURA: {} cadenas, {} endpoints; broadcast bloqueado",
                    chains, endpoints
                )
            }
            Web3ConnectivityProfile::RpcOperational => {
                format!(
                    "RPC OPERATIVO: {} cadenas, {} endpoints; requiere politicas y confirmacion local",
                    chains, endpoints
                )
            }
        }
    }

    pub fn offline_verified_clock(&self) -> VerifiedClockStatus {
        let local_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        VerifiedClockStatus {
            local_unix,
            consensus_unix: None,
            drift_seconds: None,
            max_drift_seconds: self.max_clock_drift_seconds,
            status: if self.profile.allows_rpc_read() {
                "RPC configurado; consenso pendiente de adaptador de cadena".to_string()
            } else {
                "OFFLINE: usando reloj local sin consenso de nodos".to_string()
            },
        }
    }

    pub fn current_endpoint(&self, chain: &str) -> Option<&str> {
        let entry = self.chains.get(&chain.to_lowercase())?;
        entry.endpoints.get(entry.active).map(String::as_str)
    }

    /// Conmuta al siguiente endpoint registrado cuando el activo pierde sincronía.
    pub fn switch_to_fallback(&mut self, chain: &str) -> Option<String> {
        let entry = self.chains.get_mut(&chain.to_lowercase())?;
        if entry.endpoints.len() <= 1 {
            return None;
        }
        entry.active = (entry.active + 1) % entry.endpoints.len();
        entry.endpoints.get(entry.active).cloned()
    }

    pub fn endpoints(&self, chain: &str) -> Vec<String> {
        self.chains
            .get(&chain.to_lowercase())
            .map(|entry| entry.endpoints.clone())
            .unwrap_or_default()
    }

    pub fn chain_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.chains.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn active_index(&self, chain: &str) -> usize {
        self.chains
            .get(&chain.to_lowercase())
            .map(|entry| entry.active)
            .unwrap_or(0)
    }

    pub fn endpoint_policy(&self, chain: &str) -> Option<NodeEndpointPolicy> {
        let key = chain.to_lowercase();
        let entry = self.chains.get(&key)?;
        let primary = entry.endpoints.first()?.clone();
        Some(NodeEndpointPolicy {
            chain: key,
            primary_endpoint: primary,
            fallback_endpoints: entry.endpoints.iter().skip(1).cloned().collect(),
            allow_broadcast: self.profile.allows_broadcast(),
            require_chain_id: String::new(),
            max_clock_drift_seconds: self.max_clock_drift_seconds,
            timeout_ms: self.timeout_ms,
        })
    }

    /// Define el endpoint principal de una cadena, creándola si no existe.
    pub fn set_primary(&mut self, chain: &str, url: &str) {
        let url = url.trim().to_string();
        if url.is_empty() {
            return;
        }
        let key = chain.to_lowercase();
        match self.chains.get_mut(&key) {
            Some(entry) => {
                if entry.endpoints.is_empty() {
                    entry.endpoints.push(url);
                } else {
                    entry.endpoints[0] = url;
                }
                entry.active = 0;
            }
            None => {
                self.chains.insert(
                    key,
                    ChainNodes {
                        endpoints: vec![url],
                        active: 0,
                    },
                );
            }
        }
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        let mut chain = Vec::new();
        for name in self.chain_names() {
            if let Some(entry) = self.chains.get(&name) {
                let mut endpoints = entry.endpoints.iter();
                let primary = endpoints.next().cloned().unwrap_or_default();
                chain.push(ChainNodesConfig {
                    name,
                    primary,
                    fallbacks: endpoints.cloned().collect(),
                });
            }
        }
        let serialized = toml::to_string(&NodesFile {
            profile: self.profile.clone(),
            max_clock_drift_seconds: self.max_clock_drift_seconds,
            timeout_ms: self.timeout_ms,
            chain,
        })
        .map_err(|error| format!("no se pudo serializar nodes.toml: {}", error))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        std::fs::write(path, serialized)
            .map_err(|error| format!("no se pudo escribir nodes.toml: {}", error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("livencrypt-nodes-{}.toml", contents.len()));
        std::fs::write(&path, contents).expect("escribir nodes.toml temporal");
        path
    }

    #[test]
    fn loads_primary_and_switches_to_fallback() {
        let path = write_temp(
            r#"
[[chain]]
name = "ethereum"
primary = "https://rpc-primario.local"
fallbacks = ["https://rpc-respaldo.local"]
"#,
        );
        let mut registry = NodeRegistry::load_from_path(&path);
        assert_eq!(
            registry.current_endpoint("ethereum"),
            Some("https://rpc-primario.local")
        );
        assert_eq!(
            registry.switch_to_fallback("ethereum").as_deref(),
            Some("https://rpc-respaldo.local")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_file_yields_empty_registry() {
        let path = write_temp("esto no es toml valido =====");
        let registry = NodeRegistry::load_from_path(&path);
        assert!(registry.current_endpoint("ethereum").is_none());
        let _ = std::fs::remove_file(&path);
    }
}
