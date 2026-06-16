// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: supervisor maestro y coordinador de la pasarela de custodia universal */

use crate::crypto::blockchain::address;
use crate::crypto::blockchain::breaker::{GatewaySecurityState, TacticalCircuitBreaker};
use crate::crypto::blockchain::firewall::LiveFirewall;
use crate::crypto::blockchain::multi_curve::UniversalKeymaster;
use crate::crypto::blockchain::proxy::{
    read_native_message, write_native_message, ExtensionRequest, ExtensionResponse,
};
use crate::crypto::blockchain::tx_parser::parse_tx_payload;
use crate::crypto::blockchain::types::{
    SigningRequestPreview, TransactionSignRequest, Web3AccountResponse, Web3StatusResponse,
};
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
        // Monitor de riesgo del entorno: un score crítico (binario manipulado,
        // LD_PRELOAD, etc.) dispara el aislamiento permanente del llavero.
        if crate::security::ai_monitor::current_risk_score()
            >= crate::security::ai_monitor::CRITICAL_RISK_THRESHOLD
        {
            self.breaker.trigger_hard_lock();
        }

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
            ExtensionRequest::Web3Status => {
                let response = ExtensionResponse::Success(Web3StatusResponse {
                    unlocked: !matches!(self.breaker.state, GatewaySecurityState::Frozen { .. }),
                    gateway_state: format!("{:?}", self.breaker.state),
                    profile: "worker-required".to_string(),
                    supported_chains: vec![
                        "ethereum".to_string(),
                        "bitcoin".to_string(),
                        "solana".to_string(),
                    ],
                });
                serde_json::to_vec(&response).map_err(|error| error.to_string())
            }
            ExtensionRequest::DeriveKey(derivation) => {
                if matches!(self.breaker.state, GatewaySecurityState::Frozen { .. }) {
                    let response = ExtensionResponse::<Vec<u8>>::Error(
                        "operacion suspendida temporalmente".to_string(),
                    );
                    return serde_json::to_vec(&response).map_err(|error| error.to_string());
                }

                let response = match self.keymaster.get_public_key(
                    &derivation.chain,
                    derivation.network,
                    derivation.account_index,
                    derivation.address_index,
                ) {
                    Ok(public_key) => ExtensionResponse::Success(public_key),
                    Err(error) => ExtensionResponse::<Vec<u8>>::Error(error),
                };
                serde_json::to_vec(&response).map_err(|error| error.to_string())
            }
            ExtensionRequest::Web3Account(request) => {
                if matches!(self.breaker.state, GatewaySecurityState::Frozen { .. }) {
                    let response = ExtensionResponse::<Web3AccountResponse>::Error(
                        "operacion suspendida temporalmente".to_string(),
                    );
                    return serde_json::to_vec(&response).map_err(|error| error.to_string());
                }

                let response = match self.keymaster.get_public_key(
                    &request.chain,
                    address::Network::Mainnet,
                    request.account_index,
                    request.address_index,
                ) {
                    Ok(public_key) => match address::public_address(&request.chain, &public_key) {
                        Ok(public_address) => ExtensionResponse::Success(Web3AccountResponse {
                            chain_id: address::chain_id_label(&request.chain),
                            derivation_path: address::derivation_path(
                                &request.chain,
                                request.account_index,
                                request.address_index,
                            ),
                            address: public_address,
                            public_key_hex: hex::encode(public_key),
                            scope: "public-address-only".to_string(),
                            chain: request.chain,
                            account_index: request.account_index,
                            address_index: request.address_index,
                        }),
                        Err(error) => ExtensionResponse::<Web3AccountResponse>::Error(error),
                    },
                    Err(error) => ExtensionResponse::<Web3AccountResponse>::Error(error),
                };
                serde_json::to_vec(&response).map_err(|error| error.to_string())
            }
            ExtensionRequest::Web3ReadBalance(_)
            | ExtensionRequest::Web3ReadNonce(_)
            | ExtensionRequest::Web3EstimateFee(_)
            | ExtensionRequest::EthereumPrepareTransaction(_)
            | ExtensionRequest::EthereumSignTransaction(_) => {
                let response = ExtensionResponse::<()>::Error(
                    "lectura RPC Web3 requiere worker activo con NodeRegistry".to_string(),
                );
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

                if let Err(target_error) = self.firewall.validate_target_destination_id(
                    &parsed,
                    sign_request.target_dex_cex_id.as_deref(),
                ) {
                    self.register_integrity_failure(&target_error, now);
                    let response = ExtensionResponse::<()>::Error(format!(
                        "violacion de perimetro: {}",
                        target_error
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
                let fiat_currency = self.firewall.rules.fiat_currency.clone();
                if let Err(policy_error) = self.firewall.validate_account_policy(
                    &parsed,
                    sign_request.account_index,
                    sign_request.address_index,
                    effective_volume,
                    sign_request.value_usd,
                    &fiat_currency,
                ) {
                    self.register_integrity_failure(&policy_error, now);
                    let response = ExtensionResponse::<()>::Error(format!(
                        "politica de cuenta rechazada: {}",
                        policy_error
                    ));
                    return serde_json::to_vec(&response).map_err(|error| error.to_string());
                }

                // Firmar primero para no desperdiciar contadores si la firma falla.
                // Si el sandbox de firma está activo, la clave solo se usa dentro de un
                // proceso hijo aislado por namespaces (sin red), y solo regresa la firma.
                let signature_result = if crate::security::sign_sandbox::sign_sandbox_requested() {
                    let keymaster = &self.keymaster;
                    let chain = sign_request.chain.clone();
                    let network = sign_request.network;
                    let account = sign_request.account_index;
                    let index = sign_request.address_index;
                    let payload = sign_request.raw_tx_payload.clone();
                    crate::security::sign_sandbox::run_isolated(move || {
                        let signature =
                            keymaster.sign_transaction(&chain, network, account, index, &payload)?;
                        serde_json::to_vec(&signature).map_err(|error| error.to_string())
                    })
                    .and_then(|bytes| {
                        serde_json::from_slice::<crate::crypto::blockchain::types::SignatureResponse>(
                            &bytes,
                        )
                        .map_err(|error| error.to_string())
                    })
                } else {
                    self.keymaster.sign_transaction(
                        &sign_request.chain,
                        sign_request.network,
                        sign_request.account_index,
                        sign_request.address_index,
                        &sign_request.raw_tx_payload,
                    )
                };
                let signature_response = match signature_result {
                    Ok(signature) => signature,
                    Err(error) => {
                        let response = ExtensionResponse::<()>::Error(error);
                        return serde_json::to_vec(&response).map_err(|error| error.to_string());
                    }
                };

                // Commit después de firma exitosa para que fallas de firma no desperdicien contadores.
                if let Err(commit_error) = self.firewall.commit_transaction_context(
                    &parsed,
                    effective_volume,
                    sign_request.value_usd,
                    &fiat_currency,
                ) {
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
            ExtensionRequest::BroadcastTransaction(_) => {
                let response = ExtensionResponse::<()>::Error(
                    "broadcast bloqueado: requiere adaptador RPC operativo auditado y politica local"
                        .to_string(),
                );
                serde_json::to_vec(&response).map_err(|error| error.to_string())
            }
        }
    }

    /// Límite de comisión nativa de la política de cuenta aplicable (C.5), si existe.
    pub fn max_fee_native_for(
        &self,
        chain: &crate::crypto::blockchain::types::ChainType,
        account_index: u32,
        address_index: u32,
    ) -> Option<rust_decimal::Decimal> {
        self.firewall
            .active_policy(chain, account_index, address_index)
            .and_then(|policy| policy.max_fee_native)
    }

    pub fn preview_sign_transaction(
        &mut self,
        sign_request: &TransactionSignRequest,
    ) -> Result<SigningRequestPreview, String> {
        if crate::security::ai_monitor::current_risk_score()
            >= crate::security::ai_monitor::CRITICAL_RISK_THRESHOLD
        {
            self.breaker.trigger_hard_lock();
        }

        if self.breaker.state == GatewaySecurityState::HardLocked {
            return Err("acceso revocado: intervencion local requerida".to_string());
        }

        if matches!(self.breaker.state, GatewaySecurityState::Frozen { .. }) {
            return Err("operacion suspendida temporalmente".to_string());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let parsed = match parse_tx_payload(&sign_request.chain, &sign_request.raw_tx_payload) {
            Ok(parsed) => parsed,
            Err(error) => {
                let error = format!("no se pudo parsear payload: {}", error);
                self.register_integrity_failure(&error, now);
                return Err(error);
            }
        };

        if let Err(error) = self.firewall.validate_parsed_transaction(&parsed) {
            self.register_integrity_failure(&error, now);
            return Err(format!("violacion de perimetro: {}", error));
        }

        if let Err(error) = self
            .firewall
            .validate_target_destination_id(&parsed, sign_request.target_dex_cex_id.as_deref())
        {
            self.register_integrity_failure(&error, now);
            return Err(format!("violacion de perimetro: {}", error));
        }

        let effective_volume_units = match self.firewall.effective_volume_units(&parsed) {
            Ok(volume) => volume,
            Err(error) => {
                self.register_integrity_failure(&error, now);
                return Err(error);
            }
        };
        let fiat_currency = self.firewall.rules.fiat_currency.clone();
        if let Err(error) = self.firewall.validate_account_policy(
            &parsed,
            sign_request.account_index,
            sign_request.address_index,
            effective_volume_units,
            sign_request.value_usd,
            &fiat_currency,
        ) {
            self.register_integrity_failure(&error, now);
            return Err(format!("politica de cuenta rechazada: {}", error));
        }

        Ok(SigningRequestPreview {
            request_id: 0,
            chain: parsed.chain,
            chain_id: parsed.chain_id,
            account_index: sign_request.account_index,
            address_index: sign_request.address_index,
            method: parsed.method,
            summary: parsed.summary,
            target_dex_cex_id: sign_request.target_dex_cex_id.clone(),
            value_usd: sign_request.value_usd,
            effective_volume_units,
            fee_estimate: None,
        })
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
            if crate::crypto::blockchain::worker::ensure_peer_is_current_user(&stream).is_err() {
                continue;
            }
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
