// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: despachador dinámico de nodos de infraestructura desde nodes.toml */

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
struct ChainNodesConfig {
    name: String,
    primary: String,
    #[serde(default)]
    fallbacks: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NodesFile {
    #[serde(default)]
    chain: Vec<ChainNodesConfig>,
}

#[derive(Debug, Clone)]
struct ChainNodes {
    endpoints: Vec<String>,
    active: usize,
}

#[derive(Debug, Default)]
pub struct NodeRegistry {
    chains: HashMap<String, ChainNodes>,
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
            chains.insert(name, ChainNodes { endpoints, active: 0 });
        }
        Ok(Self { chains })
    }

    pub fn reload(&mut self, path: &Path) {
        *self = Self::load_from_path(path);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "livencrypt-nodes-{}.toml",
            contents.len()
        ));
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
