// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: supervisor maestro y coordinador de la pasarela de custodia universal */

use crate::crypto::blockchain::breaker::{GatewaySecurityState, TacticalCircuitBreaker};
use crate::crypto::blockchain::firewall::LiveFirewall;
use crate::crypto::blockchain::multi_curve::UniversalKeymaster;
use crate::crypto::blockchain::proxy::{
    read_native_message, write_native_message, ExtensionRequest, ExtensionResponse,
};
use crate::crypto::blockchain::tx_parser::parse_tx_payload;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::net::UnixListener;

pub struct GatewaySupervisor {
    pub keymaster: UniversalKeymaster,
    pub firewall: LiveFirewall,
    pub breaker: TacticalCircuitBreaker,
}

impl GatewaySupervisor {
    pub fn new(keymaster: UniversalKeymaster, firewall: LiveFirewall) -> Self {
        Self {
            keymaster,
            firewall,
            breaker: TacticalCircuitBreaker::new(),
        }
    }

    pub fn run_loop_iteration(&mut self, request: ExtensionRequest) -> Result<Vec<u8>, String> {
        if self.breaker.state == GatewaySecurityState::HardLocked {
            let response = ExtensionResponse::<()>::Error(
                "acceso revocado: intervencion local requerida".to_string(),
            );
            return serde_json::to_vec(&response).map_err(|error| error.to_string());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match request {
            ExtensionRequest::DeriveKey(derivation) => {
                if matches!(self.breaker.state, GatewaySecurityState::Frozen { .. }) {
                    let response = ExtensionResponse::<Vec<u8>>::Error(
                        "operacion suspendida temporalmente".to_string(),
                    );
                    return serde_json::to_vec(&response).map_err(|error| error.to_string());
                }

                let response = match self.keymaster.get_public_key(
                    &derivation.chain,
                    derivation.account_index,
                    derivation.address_index,
                ) {
                    Ok(public_key) => ExtensionResponse::Success(public_key),
                    Err(error) => ExtensionResponse::<Vec<u8>>::Error(error),
                };
                serde_json::to_vec(&response).map_err(|error| error.to_string())
            }
            ExtensionRequest::SignTransaction(sign_request) => {
                let parsed =
                    match parse_tx_payload(&sign_request.chain, &sign_request.raw_tx_payload) {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            let error = format!("no se pudo parsear payload: {}", error);
                            self.register_integrity_failure(&error, now);
                            let response = ExtensionResponse::<()>::Error(error);
                            return serde_json::to_vec(&response)
                                .map_err(|error| error.to_string());
                        }
                    };

                if let Err(firewall_error) = self.firewall.validate_parsed_transaction(&parsed) {
                    self.register_integrity_failure(&firewall_error, now);
                    let response = ExtensionResponse::<()>::Error(format!(
                        "violacion de perimetro: {}",
                        firewall_error
                    ));
                    return serde_json::to_vec(&response).map_err(|error| error.to_string());
                }
                let effective_volume = match self.firewall.effective_volume_units(&parsed) {
                    Ok(volume) => volume,
                    Err(error) => {
                        self.register_integrity_failure(&error, now);
                        let response = ExtensionResponse::<()>::Error(error);
                        return serde_json::to_vec(&response).map_err(|error| error.to_string());
                    }
                };

                // Firmar primero para no desperdiciar contadores si la firma falla.
                let signature_response = match self.keymaster.sign_transaction(
                    &sign_request.chain,
                    sign_request.account_index,
                    sign_request.address_index,
                    &sign_request.raw_tx_payload,
                ) {
                    Ok(signature) => signature,
                    Err(error) => {
                        let response = ExtensionResponse::<()>::Error(error);
                        return serde_json::to_vec(&response).map_err(|error| error.to_string());
                    }
                };

                // Commit después de firma exitosa para que fallas de firma no desperdicien contadores.
                if let Err(commit_error) = self.firewall.commit_transaction(effective_volume) {
                    self.register_integrity_failure(&commit_error, now);
                    let response = ExtensionResponse::<()>::Error(format!(
                        "commit rechazado: {}",
                        commit_error
                    ));
                    return serde_json::to_vec(&response).map_err(|error| error.to_string());
                }

                let response = ExtensionResponse::Success(signature_response);
                serde_json::to_vec(&response).map_err(|error| error.to_string())
            }
        }
    }

    fn register_integrity_failure(&mut self, error: &str, now: u64) {
        self.breaker.integrity_failures = self.breaker.integrity_failures.saturating_add(1);
        self.breaker.trip_breaker(error, now);
        if self.breaker.integrity_failures >= 3 {
            self.breaker.trigger_hard_lock();
        }
    }

    pub fn handle_native_payload(&mut self, payload: &[u8]) -> Vec<u8> {
        let request = match serde_json::from_slice::<ExtensionRequest>(payload) {
            Ok(request) => request,
            Err(error) => {
                return error_response_bytes(format!(
                    "error de deserializacion estructurada: {}",
                    error
                ));
            }
        };

        self.run_loop_iteration(request)
            .unwrap_or_else(error_response_bytes)
    }

    #[cfg(unix)]
    pub fn serve_unix_socket(&mut self, socket_path: &Path) -> Result<(), String> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("no se pudo crear directorio IPC: {}", error))?;
        }

        if socket_path.exists() {
            std::fs::remove_file(socket_path)
                .map_err(|error| format!("no se pudo limpiar socket IPC previo: {}", error))?;
        }

        let listener = UnixListener::bind(socket_path)
            .map_err(|error| format!("no se pudo abrir socket IPC: {}", error))?;

        for stream in listener.incoming() {
            let mut stream =
                stream.map_err(|error| format!("conexion IPC entrante invalida: {}", error))?;
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(200)));
            let payload = read_native_message(&mut stream)?;
            let response = self.handle_native_payload(&payload);
            write_native_message(&mut stream, &response)?;
        }

        Ok(())
    }
}

fn error_response_bytes(error: String) -> Vec<u8> {
    serde_json::to_vec(&ExtensionResponse::<()>::Error(error)).unwrap_or_else(|_| {
        b"{\"status\":\"Error\",\"data\":\"error interno de serializacion\"}".to_vec()
    })
}
