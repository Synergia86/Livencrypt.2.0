// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: hilo de ejecucion asincrono multi-hilo blindado contra slowloris y fugas de heap */

#![allow(unsafe_code)]

/* rol: hilo de ejecucion asincrono multi-hilo blindado contra slowloris y fugas de heap */
use crate::crypto::blockchain::address;
use crate::crypto::blockchain::address::Network;
use crate::crypto::blockchain::breaker::GatewaySecurityState;
use crate::crypto::blockchain::eth_abi;
use crate::crypto::blockchain::eth_tx;
use crate::crypto::blockchain::eth_types::{
    EthereumPreparedTransaction, EthereumSignedTransaction, EthereumTxRequest,
};
use crate::crypto::blockchain::firewall::FirewallRules;
use crate::crypto::blockchain::nodes::NodeRegistry;
use crate::crypto::blockchain::preflight;
use crate::crypto::blockchain::proxy::{
    read_native_message, write_native_message, ExtensionRequest, ExtensionResponse,
};
use crate::crypto::blockchain::rpc_manager;
use crate::crypto::blockchain::rpc_quorum;
use crate::crypto::blockchain::supervisor::GatewaySupervisor;
use crate::crypto::blockchain::types::{
    AccountPolicy, BroadcastRequestPreview, BroadcastTransactionRequest, ChainType,
    KeyDerivationRequest, PriceBook, ScheduledPolicy, SignatureResponse, SigningRequestPreview,
    TransactionSignRequest, Web3AccountResponse, Web3StatusResponse,
};
use crate::crypto::blockchain::web3_audit::{
    append_web3_audit_event, now_unix, set_audit_signing_key, sha256_hex, Web3AuditEvent,
};
use rust_decimal::Decimal;
use serde::Serialize;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use zeroize::Zeroize;

const MAX_CONCURRENT_CONNECTIONS: usize = 8;
const SOCKET_READ_TIMEOUT_MS: u64 = 200;
const MAX_WHITELIST_ITEMS: usize = 100;

struct PendingSigningRequest {
    request_id: u64,
    request: TransactionSignRequest,
    ethereum_tx: Option<EthereumTxRequest>,
    ethereum_context: Option<PendingEthereumContext>,
    stream: UnixStream,
}

struct PendingBroadcastRequest {
    request_id: u64,
    request: BroadcastTransactionRequest,
    stream: UnixStream,
}

struct PendingEthereumContext {
    origin: String,
    account_index: u32,
    address_index: u32,
    decoded_method: String,
    risk: String,
    summary: String,
    warnings: Vec<String>,
    payload_sha256: String,
}

pub enum Web3WorkerCmd {
    UpdateRules {
        max_tx: Option<u32>,
        max_vol: Option<Decimal>,
        max_fiat: Option<Decimal>,
        fiat_currency: Option<String>,
    },
    AddDexContract(String),
    AddCexDestination(String),
    SetManualPrice {
        asset: String,
        fiat: String,
        value: Decimal,
    },
    UpsertAccountPolicy(AccountPolicy),
    RemoveAccountPolicy {
        chain: ChainType,
        account_index: u32,
        address_index: Option<u32>,
    },
    AddScheduledPolicy {
        chain: ChainType,
        account_index: u32,
        address_index: Option<u32>,
        rule: ScheduledPolicy,
    },
    RemoveScheduledPolicy {
        chain: ChainType,
        account_index: u32,
        address_index: Option<u32>,
        name: String,
    },
    ImportSignedPriceFile {
        path: PathBuf,
    },
    RpcReadBalance {
        chain: String,
        address: String,
        asset: String,
    },
    RpcReadNonce {
        chain: String,
        address: String,
    },
    RpcEstimateFee {
        chain: String,
        raw_payload: Vec<u8>,
    },
    RpcReadTxStatus {
        chain: String,
        txid: String,
    },
    ResetBreaker([i64; 5], Vec<u8>),
    DerivePublicKey {
        chain: ChainType,
        network: Network,
        account_index: u32,
        address_index: u32,
    },
    VerifyDerivation {
        chain: ChainType,
        network: Network,
        account_index: u32,
        address_index: u32,
    },
    AuthorizeSigning {
        request_id: u64,
        approve: bool,
    },
    AuthorizeBroadcast {
        request_id: u64,
        approve: bool,
    },
    IncomingWebRequest(Vec<u8>, UnixStream),
    Shutdown,
}

pub enum Web3WorkerEvent {
    StatusChanged(GatewaySecurityState),
    MetricsUpdated {
        tx_count: u32,
        volume_units: Decimal,
        fiat_value: Decimal,
        fiat_currency: String,
    },
    SyncRules(FirewallRules),
    AccountPoliciesUpdated(Vec<AccountPolicy>),
    PriceBookUpdated(PriceBook),
    RpcInspectorResult {
        label: String,
        result: Result<String, String>,
    },
    SigningRequest(SigningRequestPreview),
    BroadcastRequest(BroadcastRequestPreview),
    PublicKeyDerived {
        chain: ChainType,
        account_index: u32,
        address_index: u32,
        result: Result<Vec<u8>, String>,
    },
    DerivationVerified {
        chain: ChainType,
        account_index: u32,
        address_index: u32,
        matches: bool,
        address: String,
    },
    Notification(String),
}

pub struct Web3BackgroundWorker;

impl Web3BackgroundWorker {
    pub fn spawn(
        mut supervisor: GatewaySupervisor,
        node_registry: NodeRegistry,
    ) -> (Sender<Web3WorkerCmd>, Receiver<Web3WorkerEvent>) {
        let (cmd_tx, cmd_rx) = channel::<Web3WorkerCmd>();
        let (event_tx, event_rx) = channel::<Web3WorkerEvent>();
        let running = Arc::new(AtomicBool::new(true));

        spawn_socket_reader(cmd_tx.clone(), event_tx.clone(), Arc::clone(&running));

        thread::spawn(move || {
            // Sella el log de auditoria Web3 con una clave de dispositivo derivada del vault.
            set_audit_signing_key(supervisor.keymaster.audit_signing_key());

            let mut last_tx_count = 0;
            let mut last_volume_units = Decimal::ZERO;
            let mut pending_signing: Option<PendingSigningRequest> = None;
            let mut next_signing_request_id = 1_u64;
            let mut pending_broadcast: Option<PendingBroadcastRequest> = None;
            let mut next_broadcast_request_id = 1_u64;

            loop {
                match cmd_rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(Web3WorkerCmd::Shutdown) => {
                        running.store(false, Ordering::Relaxed);
                        break;
                    }
                    Ok(cmd) => process_command(
                        cmd,
                        &mut supervisor,
                        &event_tx,
                        &mut pending_signing,
                        &mut next_signing_request_id,
                        &mut pending_broadcast,
                        &mut next_broadcast_request_id,
                        &node_registry,
                    ),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }

                let current_tx_count = supervisor.firewall.tx_count_today;
                let current_volume_units = supervisor.firewall.volume_today_units;
                let volume_changed = (current_volume_units - last_volume_units).abs()
                    > Decimal::from_str_radix("0.00000001", 10).unwrap_or(Decimal::ZERO);
                if current_tx_count != last_tx_count || volume_changed {
                    let _ = event_tx.send(Web3WorkerEvent::MetricsUpdated {
                        tx_count: current_tx_count,
                        volume_units: current_volume_units,
                        fiat_value: supervisor.firewall.fiat_value_today,
                        fiat_currency: supervisor.firewall.rules.fiat_currency.clone(),
                    });
                    last_tx_count = current_tx_count;
                    last_volume_units = current_volume_units;
                }
            }
        });

        (cmd_tx, event_rx)
    }
}

fn spawn_socket_reader(
    cmd_tx: Sender<Web3WorkerCmd>,
    event_tx: Sender<Web3WorkerEvent>,
    running: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let socket_path = match resolve_socket_path() {
            Ok(path) => path,
            Err(error) => {
                let _ = event_tx.send(Web3WorkerEvent::Notification(error));
                return;
            }
        };
        if let Err(error) = remove_existing_socket_safely(&socket_path) {
            let _ = event_tx.send(Web3WorkerEvent::Notification(error));
            return;
        }
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = event_tx.send(Web3WorkerEvent::Notification(format!(
                    "No se pudo abrir socket Web3: {}",
                    error
                )));
                return;
            }
        };
        if let Err(error) =
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        {
            let _ = event_tx.send(Web3WorkerEvent::Notification(format!(
                "Socket Web3 creado, pero no se pudieron ajustar permisos: {}",
                error
            )));
        }

        let _ = event_tx.send(Web3WorkerEvent::Notification(format!(
            "Pasarela Web3 escuchando en {}",
            socket_path.display()
        )));

        let active_connections = Arc::new(AtomicUsize::new(0));
        while running.load(Ordering::Relaxed) {
            let Ok((mut stream, _addr)) = listener.accept() else {
                thread::sleep(Duration::from_millis(50));
                continue;
            };

            #[cfg(unix)]
            if ensure_peer_is_current_user(&stream).is_err() {
                continue;
            }

            // Reserva de slot atómica: comparar-e-intercambiar evita que ráfagas
            // concurrentes superen el límite por una condición de carrera load/add.
            let mut current = active_connections.load(Ordering::Acquire);
            let reserved = loop {
                if current >= MAX_CONCURRENT_CONNECTIONS {
                    break false;
                }
                match active_connections.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break true,
                    Err(observed) => current = observed,
                }
            };
            if !reserved {
                continue;
            }
            let thread_tx = cmd_tx.clone();
            let counter = Arc::clone(&active_connections);

            thread::spawn(move || {
                let _ =
                    stream.set_read_timeout(Some(Duration::from_millis(SOCKET_READ_TIMEOUT_MS)));
                let _ =
                    stream.set_write_timeout(Some(Duration::from_millis(SOCKET_READ_TIMEOUT_MS)));
                if let Ok(payload) = read_native_message(&mut stream) {
                    let _ = thread_tx.send(Web3WorkerCmd::IncomingWebRequest(payload, stream));
                }
                counter.fetch_sub(1, Ordering::Release);
            });
        }

        let _ = std::fs::remove_file(&socket_path);
    });
}

#[allow(clippy::too_many_arguments)]
fn process_command(
    cmd: Web3WorkerCmd,
    supervisor: &mut GatewaySupervisor,
    event_tx: &Sender<Web3WorkerEvent>,
    pending_signing: &mut Option<PendingSigningRequest>,
    next_signing_request_id: &mut u64,
    pending_broadcast: &mut Option<PendingBroadcastRequest>,
    next_broadcast_request_id: &mut u64,
    node_registry: &NodeRegistry,
) {
    match cmd {
        Web3WorkerCmd::UpdateRules {
            max_tx,
            max_vol,
            max_fiat,
            fiat_currency,
        } => {
            let mut updated = false;
            let mut errors: Vec<String> = Vec::new();
            if let Some(tx) = max_tx {
                if tx > 0 {
                    supervisor.firewall.rules.max_daily_tx = tx;
                    updated = true;
                } else {
                    errors.push("max_daily_tx debe ser mayor a 0".to_string());
                }
            }
            if let Some(volume) = max_vol {
                if supervisor.firewall.set_crypto_limit(volume).is_ok() {
                    updated = true;
                } else {
                    errors.push("max_daily_crypto_amount debe ser mayor a 0".to_string());
                }
            }
            if let Some(fiat) = max_fiat {
                let currency = fiat_currency
                    .unwrap_or_else(|| supervisor.firewall.rules.fiat_currency.clone());
                if let Err(error) = supervisor.firewall.set_fiat_limit(fiat, &currency) {
                    errors.push(error);
                } else {
                    updated = true;
                }
            } else if let Some(currency) = fiat_currency {
                if !currency.trim().is_empty() {
                    supervisor.firewall.rules.fiat_currency = currency.trim().to_uppercase();
                    updated = true;
                }
            }

            let message = if errors.is_empty() && updated {
                "Limites cripto/FIAT del cortafuegos actualizados".to_string()
            } else if errors.is_empty() {
                "Error: formato numerico invalido".to_string()
            } else {
                errors.join("; ")
            };
            let _ = event_tx.send(Web3WorkerEvent::Notification(message));
            let _ = event_tx.send(Web3WorkerEvent::SyncRules(
                supervisor.firewall.rules.clone(),
            ));
        }
        Web3WorkerCmd::AddDexContract(mut contract) => {
            normalize_id(&mut contract);
            if contract.is_empty() {
                return;
            }
            if supervisor.firewall.rules.allowed_dex_contracts.len() >= MAX_WHITELIST_ITEMS {
                let _ = event_tx.send(Web3WorkerEvent::Notification(
                    "Lista DEX completa: limite maximo alcanzado".to_string(),
                ));
                return;
            }
            if !supervisor
                .firewall
                .rules
                .allowed_dex_contracts
                .contains(&contract)
            {
                supervisor
                    .firewall
                    .rules
                    .allowed_dex_contracts
                    .push(contract);
                let _ = event_tx.send(Web3WorkerEvent::SyncRules(
                    supervisor.firewall.rules.clone(),
                ));
            }
        }
        Web3WorkerCmd::AddCexDestination(mut destination) => {
            normalize_id(&mut destination);
            if destination.is_empty() {
                return;
            }
            if supervisor.firewall.rules.allowed_cex_destinations.len() >= MAX_WHITELIST_ITEMS {
                let _ = event_tx.send(Web3WorkerEvent::Notification(
                    "Lista CEX completa: limite maximo alcanzado".to_string(),
                ));
                return;
            }
            if !supervisor
                .firewall
                .rules
                .allowed_cex_destinations
                .contains(&destination)
            {
                supervisor
                    .firewall
                    .rules
                    .allowed_cex_destinations
                    .push(destination);
                let _ = event_tx.send(Web3WorkerEvent::SyncRules(
                    supervisor.firewall.rules.clone(),
                ));
            }
        }
        Web3WorkerCmd::SetManualPrice { asset, fiat, value } => {
            let message = match supervisor.firewall.set_manual_price(&asset, &fiat, value) {
                Ok(()) => format!("Precio manual registrado: {} {}={}", asset, fiat, value),
                Err(error) => format!("Error registrando precio manual: {}", error),
            };
            let _ = event_tx.send(Web3WorkerEvent::Notification(message));
            let _ = event_tx.send(Web3WorkerEvent::PriceBookUpdated(
                supervisor.firewall.rules.price_book.clone(),
            ));
            let _ = event_tx.send(Web3WorkerEvent::SyncRules(
                supervisor.firewall.rules.clone(),
            ));
        }
        Web3WorkerCmd::UpsertAccountPolicy(policy) => {
            supervisor.firewall.upsert_account_policy(policy);
            let _ = event_tx.send(Web3WorkerEvent::Notification(
                "Politica por cuenta guardada.".to_string(),
            ));
            let _ = event_tx.send(Web3WorkerEvent::AccountPoliciesUpdated(
                supervisor.firewall.rules.account_policies.clone(),
            ));
            let _ = event_tx.send(Web3WorkerEvent::SyncRules(
                supervisor.firewall.rules.clone(),
            ));
        }
        Web3WorkerCmd::RemoveAccountPolicy {
            chain,
            account_index,
            address_index,
        } => {
            let removed =
                supervisor
                    .firewall
                    .remove_account_policy(&chain, account_index, address_index);
            let _ = event_tx.send(Web3WorkerEvent::Notification(if removed {
                "Politica por cuenta eliminada.".to_string()
            } else {
                "No se encontro politica por cuenta para eliminar.".to_string()
            }));
            let _ = event_tx.send(Web3WorkerEvent::AccountPoliciesUpdated(
                supervisor.firewall.rules.account_policies.clone(),
            ));
            let _ = event_tx.send(Web3WorkerEvent::SyncRules(
                supervisor.firewall.rules.clone(),
            ));
        }
        Web3WorkerCmd::AddScheduledPolicy {
            chain,
            account_index,
            address_index,
            rule,
        } => {
            let message = match supervisor.firewall.add_scheduled_policy(
                &chain,
                account_index,
                address_index,
                rule,
            ) {
                Ok(()) => "Regla programada guardada.".to_string(),
                Err(error) => format!("No se pudo guardar regla programada: {}", error),
            };
            let _ = event_tx.send(Web3WorkerEvent::Notification(message));
            let _ = event_tx.send(Web3WorkerEvent::AccountPoliciesUpdated(
                supervisor.firewall.rules.account_policies.clone(),
            ));
            let _ = event_tx.send(Web3WorkerEvent::SyncRules(
                supervisor.firewall.rules.clone(),
            ));
        }
        Web3WorkerCmd::RemoveScheduledPolicy {
            chain,
            account_index,
            address_index,
            name,
        } => {
            let removed = supervisor.firewall.remove_scheduled_policy(
                &chain,
                account_index,
                address_index,
                &name,
            );
            let _ = event_tx.send(Web3WorkerEvent::Notification(if removed {
                "Regla programada eliminada.".to_string()
            } else {
                "No se encontro regla programada para eliminar.".to_string()
            }));
            let _ = event_tx.send(Web3WorkerEvent::AccountPoliciesUpdated(
                supervisor.firewall.rules.account_policies.clone(),
            ));
            let _ = event_tx.send(Web3WorkerEvent::SyncRules(
                supervisor.firewall.rules.clone(),
            ));
        }
        Web3WorkerCmd::ImportSignedPriceFile { path } => {
            match crate::crypto::blockchain::price_import::import_signed_price_file(
                &path,
                supervisor.firewall.rules.price_book.max_age_seconds,
            ) {
                Ok(price_book) => {
                    supervisor.firewall.rules.price_book = price_book.clone();
                    supervisor.firewall.rules.fiat_currency = price_book.primary_fiat.clone();
                    let _ = event_tx.send(Web3WorkerEvent::PriceBookUpdated(price_book));
                    let _ = event_tx.send(Web3WorkerEvent::SyncRules(
                        supervisor.firewall.rules.clone(),
                    ));
                    let _ = event_tx.send(Web3WorkerEvent::Notification(format!(
                        "Precios firmados importados desde {}",
                        path.display()
                    )));
                }
                Err(error) => {
                    let _ = event_tx.send(Web3WorkerEvent::Notification(format!(
                        "No se pudieron importar precios firmados: {}",
                        error
                    )));
                }
            }
        }
        Web3WorkerCmd::RpcReadBalance {
            chain,
            address,
            asset,
        } => {
            let result = rpc_manager::adapter_for_chain(node_registry, &chain)
                .and_then(|adapter| adapter.read_balance(&address, &asset))
                .map(|balance| {
                    format!(
                        "{} {} | direccion={} | bloque={:?} | endpoint={}",
                        balance.amount,
                        balance.asset,
                        balance.address,
                        balance.block_height_or_slot,
                        balance.endpoint
                    )
                });
            let _ = event_tx.send(Web3WorkerEvent::RpcInspectorResult {
                label: "balance".to_string(),
                result,
            });
        }
        Web3WorkerCmd::RpcReadNonce { chain, address } => {
            let result = rpc_manager::adapter_for_chain(node_registry, &chain)
                .and_then(|adapter| adapter.read_nonce(&address))
                .map(|nonce| format!("nonce={} | endpoint={}", nonce.nonce, nonce.endpoint));
            let _ = event_tx.send(Web3WorkerEvent::RpcInspectorResult {
                label: "nonce".to_string(),
                result,
            });
        }
        Web3WorkerCmd::RpcEstimateFee {
            chain,
            mut raw_payload,
        } => {
            let result = rpc_manager::adapter_for_chain(node_registry, &chain)
                .and_then(|adapter| adapter.estimate_fee(&raw_payload))
                .map(|fee| {
                    format!(
                        "fee={} | unidad={} | endpoint={}",
                        fee.fee_amount, fee.asset, fee.endpoint
                    )
                });
            raw_payload.zeroize();
            let _ = event_tx.send(Web3WorkerEvent::RpcInspectorResult {
                label: "fee".to_string(),
                result,
            });
        }
        Web3WorkerCmd::RpcReadTxStatus { chain, txid } => {
            let result = rpc_manager::adapter_for_chain(node_registry, &chain)
                .and_then(|adapter| adapter.read_transaction_status(&txid))
                .map(|status| {
                    format!(
                        "estado={} | confirmaciones={:?} | bloque={:?} | endpoint={}",
                        if status.confirmed {
                            "confirmada"
                        } else {
                            "pendiente"
                        },
                        status.confirmations,
                        status.block_height_or_slot,
                        status.endpoint
                    )
                });
            let _ = event_tx.send(Web3WorkerEvent::RpcInspectorResult {
                label: "tx_status".to_string(),
                result,
            });
        }
        Web3WorkerCmd::ResetBreaker(cajas, mut phrase_bytes) => {
            const MAX_PHRASE_BYTES: usize = 1024;
            if phrase_bytes.len() > MAX_PHRASE_BYTES {
                let _ = event_tx.send(Web3WorkerEvent::Notification(
                    "Error: frase excede longitud maxima de 1KB".to_string(),
                ));
                phrase_bytes.zeroize();
                return;
            }
            match std::str::from_utf8(&phrase_bytes) {
                Ok(phrase) => {
                    if supervisor.breaker.resolve_and_reset(cajas, phrase).is_ok() {
                        let _ = event_tx.send(Web3WorkerEvent::StatusChanged(
                            supervisor.breaker.state.clone(),
                        ));
                        let _ = event_tx.send(Web3WorkerEvent::Notification(
                            "Circuito de seguridad rearmado".to_string(),
                        ));
                    } else {
                        supervisor.breaker.integrity_failures =
                            supervisor.breaker.integrity_failures.saturating_add(1);
                        if supervisor.breaker.integrity_failures >= 3 {
                            supervisor.breaker.trigger_hard_lock();
                            let _ = event_tx.send(Web3WorkerEvent::StatusChanged(
                                supervisor.breaker.state.clone(),
                            ));
                        }
                        let _ = event_tx.send(Web3WorkerEvent::Notification(
                            "Error: credenciales de rearme invalidas".to_string(),
                        ));
                    }
                }
                Err(_) => {
                    let _ = event_tx.send(Web3WorkerEvent::Notification(
                        "Error: frase con codificacion UTF-8 invalida".to_string(),
                    ));
                }
            }
            phrase_bytes.zeroize();
        }
        Web3WorkerCmd::DerivePublicKey {
            chain,
            network,
            account_index,
            address_index,
        } => {
            let old_state = supervisor.breaker.state.clone();
            let request = ExtensionRequest::DeriveKey(KeyDerivationRequest {
                chain: chain.clone(),
                network,
                account_index,
                address_index,
            });
            let result = supervisor.run_loop_iteration(request).and_then(|bytes| {
                serde_json::from_slice::<ExtensionResponse<Vec<u8>>>(&bytes)
                    .map_err(|error| error.to_string())
                    .and_then(|response| match response {
                        ExtensionResponse::Success(public_key) => Ok(public_key),
                        ExtensionResponse::Error(error) => Err(error),
                    })
            });
            let _ = event_tx.send(Web3WorkerEvent::PublicKeyDerived {
                chain,
                account_index,
                address_index,
                result,
            });
            if supervisor.breaker.state != old_state {
                let _ = event_tx.send(Web3WorkerEvent::StatusChanged(
                    supervisor.breaker.state.clone(),
                ));
            }
        }
        Web3WorkerCmd::VerifyDerivation {
            chain,
            network,
            account_index,
            address_index,
        } => {
            // Reutiliza el camino auditado run_loop_iteration -> DeriveKey, dos veces,
            // y compara las dos derivaciones en tiempo constante.
            let derive = |sup: &mut GatewaySupervisor| -> Result<Vec<u8>, String> {
                let request = ExtensionRequest::DeriveKey(KeyDerivationRequest {
                    chain: chain.clone(),
                    network,
                    account_index,
                    address_index,
                });
                sup.run_loop_iteration(request).and_then(|bytes| {
                    serde_json::from_slice::<ExtensionResponse<Vec<u8>>>(&bytes)
                        .map_err(|error| error.to_string())
                        .and_then(|response| match response {
                            ExtensionResponse::Success(public_key) => Ok(public_key),
                            ExtensionResponse::Error(error) => Err(error),
                        })
                })
            };

            let outcome = derive(supervisor).and_then(|first| {
                derive(supervisor).and_then(|second| {
                    if worker_constant_time_eq(&first, &second) {
                        let address = address::public_address_for_network(&chain, &first, network)
                            .unwrap_or_else(|_| "address-no-presentable".to_string());
                        Ok(address)
                    } else {
                        Err("derivacion no reproducible".to_string())
                    }
                })
            });

            let (matches, address) = match outcome {
                Ok(address) => (true, address),
                Err(_) => (false, String::new()),
            };
            let _ = event_tx.send(Web3WorkerEvent::DerivationVerified {
                chain,
                account_index,
                address_index,
                matches,
                address,
            });
        }
        Web3WorkerCmd::AuthorizeSigning {
            request_id,
            approve,
        } => {
            let Some(mut pending) = pending_signing.take() else {
                let _ = event_tx.send(Web3WorkerEvent::Notification(
                    "No hay firma Web3 pendiente.".to_string(),
                ));
                return;
            };
            if pending.request_id != request_id {
                let _ = event_tx.send(Web3WorkerEvent::Notification(
                    "Solicitud de firma Web3 no coincide; rechazada.".to_string(),
                ));
                write_error_response(&mut pending.stream, "solicitud de firma obsoleta");
                return;
            }

            if !approve {
                write_error_response(&mut pending.stream, "firma rechazada por operador");
                let _ = event_tx.send(Web3WorkerEvent::Notification(
                    "Firma Web3 rechazada por operador.".to_string(),
                ));
                return;
            }

            let old_state = supervisor.breaker.state.clone();
            let response =
                supervisor.run_loop_iteration(ExtensionRequest::SignTransaction(pending.request));
            let bytes = match response {
                Ok(bytes) => {
                    if let (Some(ethereum_tx), Some(context)) = (
                        pending.ethereum_tx.as_ref(),
                        pending.ethereum_context.as_ref(),
                    ) {
                        ethereum_signed_response_bytes(&bytes, ethereum_tx, context)
                            .unwrap_or_else(error_response_bytes)
                    } else {
                        bytes
                    }
                }
                Err(error) => error_response_bytes(error),
            };
            let _ = write_native_message(&mut pending.stream, &bytes);
            if supervisor.breaker.state != old_state {
                let _ = event_tx.send(Web3WorkerEvent::StatusChanged(
                    supervisor.breaker.state.clone(),
                ));
            }
            let _ = event_tx.send(Web3WorkerEvent::Notification(
                "Firma Web3 procesada tras autorizacion local.".to_string(),
            ));
        }
        Web3WorkerCmd::AuthorizeBroadcast {
            request_id,
            approve,
        } => {
            let Some(mut pending) = pending_broadcast.take() else {
                let _ = event_tx.send(Web3WorkerEvent::Notification(
                    "No hay broadcast Web3 pendiente.".to_string(),
                ));
                return;
            };
            if pending.request_id != request_id {
                let _ = event_tx.send(Web3WorkerEvent::Notification(
                    "Solicitud de broadcast Web3 no coincide; rechazada.".to_string(),
                ));
                write_error_response(&mut pending.stream, "solicitud de broadcast obsoleta");
                return;
            }
            if !approve {
                write_error_response(&mut pending.stream, "broadcast rechazado por operador");
                let _ = event_tx.send(Web3WorkerEvent::Notification(
                    "Broadcast Web3 rechazado por operador.".to_string(),
                ));
                return;
            }

            let payload_sha = sha256_hex(&pending.request.signed_payload);
            let result = match chain_rpc_name(&pending.request.chain) {
                Some(name) => rpc_manager::broadcast_raw_transaction(
                    node_registry,
                    name,
                    &pending.request.signed_payload,
                ),
                None => Err("cadena sin adaptador de broadcast auditado".to_string()),
            };

            let _ = append_web3_audit_event(Web3AuditEvent {
                timestamp_unix: now_unix(),
                origin: "operador-local".to_string(),
                action: "broadcast".to_string(),
                chain: format!("{:?}", pending.request.chain),
                chain_id: address::chain_id_label(&pending.request.chain),
                account_index: None,
                address_index: None,
                from: None,
                to: None,
                contract: None,
                method: Some("broadcast_raw_transaction".to_string()),
                selector: None,
                value_native: None,
                value_fiat: None,
                endpoint_summary: vec![],
                decision: if result.is_ok() {
                    "broadcast_ok"
                } else {
                    "broadcast_error"
                }
                .to_string(),
                warnings: vec![],
                payload_sha256: Some(payload_sha),
                signature_sha256: None,
            });

            match result {
                Ok(txid) => {
                    let response = ExtensionResponse::Success(txid.clone());
                    let bytes = serde_json::to_vec(&response)
                        .unwrap_or_else(|error| error_response_bytes(error.to_string()));
                    let _ = write_native_message(&mut pending.stream, &bytes);
                    let _ = event_tx.send(Web3WorkerEvent::Notification(format!(
                        "Broadcast Web3 enviado: {}",
                        txid
                    )));
                }
                Err(error) => {
                    write_error_response(&mut pending.stream, &error);
                    let _ = event_tx.send(Web3WorkerEvent::Notification(format!(
                        "Broadcast Web3 fallido: {}",
                        error
                    )));
                }
            }
        }
        Web3WorkerCmd::IncomingWebRequest(mut payload, mut stream) => {
            let request = serde_json::from_slice::<ExtensionRequest>(&payload);
            payload.zeroize();
            match request {
                Ok(ExtensionRequest::SignTransaction(sign_request)) => {
                    if pending_signing.is_some() {
                        write_error_response(
                            &mut stream,
                            "ya existe una firma pendiente de autorizacion local",
                        );
                        return;
                    }

                    let old_state = supervisor.breaker.state.clone();
                    match supervisor.preview_sign_transaction(&sign_request) {
                        Ok(mut preview) => {
                            let request_id = *next_signing_request_id;
                            *next_signing_request_id = (*next_signing_request_id).saturating_add(1);
                            preview.request_id = request_id;
                            preview.fee_estimate =
                                estimate_fee_label(node_registry, &sign_request.chain, &sign_request.raw_tx_payload);
                            if let Some(violation) =
                                fee_policy_violation(node_registry, supervisor, &sign_request)
                            {
                                write_error_response(&mut stream, &violation);
                                let _ = event_tx.send(Web3WorkerEvent::Notification(format!(
                                    "Firma Web3 rechazada por politica de comision: {}",
                                    violation
                                )));
                                return;
                            }
                            *pending_signing = Some(PendingSigningRequest {
                                request_id,
                                request: sign_request,
                                ethereum_tx: None,
                                ethereum_context: None,
                                stream,
                            });
                            let _ = event_tx.send(Web3WorkerEvent::SigningRequest(preview));
                            let _ = event_tx.send(Web3WorkerEvent::Notification(
                                "Firma Web3 pendiente de autorizacion local.".to_string(),
                            ));
                        }
                        Err(error) => {
                            write_error_response(&mut stream, &error);
                            let _ = event_tx.send(Web3WorkerEvent::Notification(format!(
                                "Firma Web3 rechazada en prevalidacion: {}",
                                error
                            )));
                        }
                    }
                    if supervisor.breaker.state != old_state {
                        let _ = event_tx.send(Web3WorkerEvent::StatusChanged(
                            supervisor.breaker.state.clone(),
                        ));
                    }
                }
                Ok(ExtensionRequest::Web3Account(request)) => {
                    let result = supervisor
                        .keymaster
                        .get_public_key(
                            &request.chain,
                            Network::Mainnet,
                            request.account_index,
                            request.address_index,
                        )
                        .and_then(|public_key| {
                            let public_address =
                                address::public_address(&request.chain, &public_key)?;
                            Ok(Web3AccountResponse {
                                chain_id: address::chain_id_label(&request.chain),
                                derivation_path: address::derivation_path(
                                    &request.chain,
                                    request.account_index,
                                    request.address_index,
                                ),
                                address: public_address,
                                public_key_hex: hex::encode(public_key),
                                scope: "public-address-only".to_string(),
                                chain: request.chain.clone(),
                                account_index: request.account_index,
                                address_index: request.address_index,
                            })
                        });
                    if let Some(origin) =
                        request.origin.as_deref().filter(|value| !value.is_empty())
                    {
                        let _ = event_tx.send(Web3WorkerEvent::Notification(format!(
                            "Solicitud Web3 de cuenta publica desde {}.",
                            origin
                        )));
                    }
                    write_result_response(&mut stream, result);
                }
                Ok(ExtensionRequest::Web3ReadBalance(request)) => {
                    let result = rpc_manager::adapter_for_chain(node_registry, &request.chain)
                        .and_then(|adapter| adapter.read_balance(&request.address, &request.asset));
                    write_result_response(&mut stream, result);
                }
                Ok(ExtensionRequest::Web3ReadNonce(request)) => {
                    let result = rpc_manager::adapter_for_chain(node_registry, &request.chain)
                        .and_then(|adapter| adapter.read_nonce(&request.address));
                    write_result_response(&mut stream, result);
                }
                Ok(ExtensionRequest::Web3EstimateFee(mut request)) => {
                    let result = rpc_manager::adapter_for_chain(node_registry, &request.chain)
                        .and_then(|adapter| adapter.estimate_fee(&request.raw_payload));
                    request.raw_payload.zeroize();
                    write_result_response(&mut stream, result);
                }
                Ok(ExtensionRequest::Web3Status) => {
                    let status = Web3StatusResponse {
                        unlocked: !matches!(
                            supervisor.breaker.state,
                            GatewaySecurityState::Frozen { .. }
                        ),
                        gateway_state: format!("{:?}", supervisor.breaker.state),
                        profile: node_registry.profile().label().to_string(),
                        supported_chains: vec![
                            "ethereum".to_string(),
                            "bitcoin".to_string(),
                            "solana".to_string(),
                        ],
                    };
                    write_result_response(&mut stream, Ok(status));
                }
                Ok(ExtensionRequest::EthereumPrepareTransaction(request)) => {
                    let origin = request.origin.clone();
                    let tx = request.tx.clone();
                    let result = (|| -> Result<EthereumPreparedTransaction, String> {
                        let unsigned_payload = eth_tx::serialize_unsigned(&tx)?;
                        let decoded =
                            eth_abi::decode_call(tx.to.as_deref().unwrap_or_default(), &tx.data)?;
                        let preflight = preflight::preflight_ethereum(node_registry, &tx)?;
                        let decision = if preflight.allowed {
                            "preview"
                        } else {
                            "rejected"
                        };
                        let payload_hash = sha256_hex(&unsigned_payload);
                        let _ = append_web3_audit_event(Web3AuditEvent {
                            timestamp_unix: now_unix(),
                            origin,
                            action: "preflight".to_string(),
                            chain: "ethereum".to_string(),
                            chain_id: format!("0x{:x}", tx.chain_id),
                            account_index: Some(request.account_index),
                            address_index: Some(request.address_index),
                            from: Some(tx.from.clone()),
                            to: tx.to.clone(),
                            contract: tx.to.clone(),
                            method: Some(decoded.method.clone()),
                            selector: Some(decoded.selector.clone()),
                            value_native: Some(tx.value.clone()),
                            value_fiat: None,
                            endpoint_summary: node_registry.endpoints("ethereum"),
                            decision: decision.to_string(),
                            warnings: preflight.warnings.clone(),
                            payload_sha256: Some(payload_hash),
                            signature_sha256: None,
                        });
                        if !preflight.allowed {
                            return Err(format!(
                                "preflight Web3 rechazado: {}",
                                preflight.warnings.join("; ")
                            ));
                        }
                        Ok(EthereumPreparedTransaction {
                            unsigned_payload_hex: format!("0x{}", hex::encode(unsigned_payload)),
                            decoded_method: decoded.method,
                            risk: decoded.risk.label().to_string(),
                            summary: preflight.summary,
                            warnings: preflight.warnings,
                        })
                    })();
                    write_result_response(&mut stream, result);
                }
                Ok(ExtensionRequest::EthereumSignTransaction(request)) => {
                    if pending_signing.is_some() {
                        write_error_response(
                            &mut stream,
                            "ya existe una firma Web3 pendiente de autorizacion local",
                        );
                        return;
                    }

                    let origin = request.origin.clone();
                    let tx = request.tx.clone();
                    let prepared = prepare_ethereum_for_signing(
                        node_registry,
                        &origin,
                        request.account_index,
                        request.address_index,
                        &tx,
                    );
                    let (sign_request, context) = match prepared {
                        Ok(value) => value,
                        Err(error) => {
                            write_error_response(&mut stream, &error);
                            return;
                        }
                    };

                    let old_state = supervisor.breaker.state.clone();
                    match supervisor.preview_sign_transaction(&sign_request) {
                        Ok(mut preview) => {
                            let request_id = *next_signing_request_id;
                            *next_signing_request_id = (*next_signing_request_id).saturating_add(1);
                            preview.request_id = request_id;
                            preview.fee_estimate =
                                estimate_fee_label(node_registry, &sign_request.chain, &sign_request.raw_tx_payload);
                            *pending_signing = Some(PendingSigningRequest {
                                request_id,
                                request: sign_request,
                                ethereum_tx: Some(tx),
                                ethereum_context: Some(context),
                                stream,
                            });
                            let _ = event_tx.send(Web3WorkerEvent::SigningRequest(preview));
                            let _ = event_tx.send(Web3WorkerEvent::Notification(
                                "Firma Ethereum Web3 pendiente de autorizacion local.".to_string(),
                            ));
                        }
                        Err(error) => {
                            write_error_response(&mut stream, &error);
                            let _ = event_tx.send(Web3WorkerEvent::Notification(format!(
                                "Firma Ethereum rechazada en prevalidacion: {}",
                                error
                            )));
                        }
                    }
                    if supervisor.breaker.state != old_state {
                        let _ = event_tx.send(Web3WorkerEvent::StatusChanged(
                            supervisor.breaker.state.clone(),
                        ));
                    }
                }
                Ok(ExtensionRequest::BroadcastTransaction(broadcast_request)) => {
                    if pending_broadcast.is_some() {
                        write_error_response(
                            &mut stream,
                            "ya existe un broadcast pendiente de autorizacion local",
                        );
                        return;
                    }
                    if !node_registry.profile().allows_broadcast() {
                        write_error_response(
                            &mut stream,
                            "perfil sin broadcast habilitado: active RPC operativo",
                        );
                        return;
                    }
                    let request_id = *next_broadcast_request_id;
                    *next_broadcast_request_id = (*next_broadcast_request_id).saturating_add(1);
                    let preview = BroadcastRequestPreview {
                        request_id,
                        chain: broadcast_request.chain.clone(),
                        payload_len: broadcast_request.signed_payload.len(),
                        payload_sha256: sha256_hex(&broadcast_request.signed_payload),
                    };
                    *pending_broadcast = Some(PendingBroadcastRequest {
                        request_id,
                        request: broadcast_request,
                        stream,
                    });
                    let _ = event_tx.send(Web3WorkerEvent::BroadcastRequest(preview));
                    let _ = event_tx.send(Web3WorkerEvent::Notification(
                        "Broadcast Web3 pendiente de autorizacion local.".to_string(),
                    ));
                }
                Ok(request) => {
                    let old_state = supervisor.breaker.state.clone();
                    let response = supervisor
                        .run_loop_iteration(request)
                        .unwrap_or_else(error_response_bytes);
                    let _ = write_native_message(&mut stream, &response);
                    if supervisor.breaker.state != old_state {
                        let _ = event_tx.send(Web3WorkerEvent::StatusChanged(
                            supervisor.breaker.state.clone(),
                        ));
                    }
                }
                Err(error) => {
                    write_error_response(
                        &mut stream,
                        &format!("error de deserializacion estructurada: {}", error),
                    );
                }
            }
        }
        Web3WorkerCmd::Shutdown => {}
    }
}

/// Nombre RPC auditado por cadena (None si no hay adaptador para esa cadena).
fn chain_rpc_name(chain: &ChainType) -> Option<&'static str> {
    match chain {
        ChainType::Ethereum => Some("ethereum"),
        ChainType::Bitcoin => Some("bitcoin"),
        ChainType::Solana => Some("solana"),
        _ => None,
    }
}

/// C.5: si hay política de comisión máxima y la comisión estimada la excede, devuelve el motivo.
/// Devuelve None si no hay límite, no hay adaptador, o la comisión no se puede estimar (offline).
fn fee_policy_violation(
    node_registry: &NodeRegistry,
    supervisor: &GatewaySupervisor,
    sign_request: &TransactionSignRequest,
) -> Option<String> {
    let max = supervisor.max_fee_native_for(
        &sign_request.chain,
        sign_request.account_index,
        sign_request.address_index,
    )?;
    let chain_name = chain_rpc_name(&sign_request.chain)?;
    let fee = rpc_manager::adapter_for_chain(node_registry, chain_name)
        .and_then(|adapter| adapter.estimate_fee(&sign_request.raw_tx_payload))
        .ok()?;
    if fee.fee_amount > max {
        Some(format!(
            "comision {} {} excede el maximo de politica {}",
            fee.fee_amount, fee.asset, max
        ))
    } else {
        None
    }
}

/// Estima la comision via adaptador RPC para mostrarla en el preview de firma.
/// Devuelve None en perfil OFFLINE o si no hay nodo (el preview lo mostrara como no disponible).
fn estimate_fee_label(
    node_registry: &NodeRegistry,
    chain: &ChainType,
    raw_payload: &[u8],
) -> Option<String> {
    let chain_name = chain_rpc_name(chain)?;
    rpc_manager::adapter_for_chain(node_registry, chain_name)
        .and_then(|adapter| adapter.estimate_fee(raw_payload))
        .map(|fee| format!("{} {} ({})", fee.fee_amount, fee.asset, fee.endpoint))
        .ok()
}

/// Comparacion en tiempo constante sin cortocircuito por contenido.
fn worker_constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn normalize_id(value: &mut String) {
    *value = value.trim().to_string();
}

fn write_error_response(stream: &mut UnixStream, error: &str) {
    let payload = error_response_bytes(error.to_string());
    let _ = write_native_message(stream, &payload);
}

fn write_result_response<T: Serialize>(stream: &mut UnixStream, result: Result<T, String>) {
    let response = match result {
        Ok(value) => ExtensionResponse::Success(value),
        Err(error) => ExtensionResponse::<T>::Error(error),
    };
    match serde_json::to_vec(&response) {
        Ok(payload) => {
            let _ = write_native_message(stream, &payload);
        }
        Err(error) => {
            write_error_response(stream, &format!("error serializando respuesta: {}", error))
        }
    }
}

fn prepare_ethereum_for_signing(
    node_registry: &NodeRegistry,
    origin: &str,
    account_index: u32,
    address_index: u32,
    tx: &EthereumTxRequest,
) -> Result<(TransactionSignRequest, PendingEthereumContext), String> {
    rpc_quorum::require_real_quorum(node_registry, "ethereum")?;
    let unsigned_payload = eth_tx::serialize_unsigned(tx)?;
    let decoded = eth_abi::decode_call(tx.to.as_deref().unwrap_or_default(), &tx.data)?;
    let preflight = preflight::preflight_ethereum(node_registry, tx)?;
    let payload_sha256 = sha256_hex(&unsigned_payload);
    let decision = if preflight.allowed {
        "preview"
    } else {
        "rejected"
    };
    let _ = append_web3_audit_event(Web3AuditEvent {
        timestamp_unix: now_unix(),
        origin: origin.to_string(),
        action: "preflight".to_string(),
        chain: "ethereum".to_string(),
        chain_id: format!("0x{:x}", tx.chain_id),
        account_index: Some(account_index),
        address_index: Some(address_index),
        from: Some(tx.from.clone()),
        to: tx.to.clone(),
        contract: tx.to.clone(),
        method: Some(decoded.method.clone()),
        selector: Some(decoded.selector.clone()),
        value_native: Some(tx.value.clone()),
        value_fiat: None,
        endpoint_summary: node_registry.endpoints("ethereum"),
        decision: decision.to_string(),
        warnings: preflight.warnings.clone(),
        payload_sha256: Some(payload_sha256.clone()),
        signature_sha256: None,
    });
    if !preflight.allowed {
        return Err(format!(
            "preflight Web3 rechazado: {}",
            preflight.warnings.join("; ")
        ));
    }

    Ok((
        TransactionSignRequest {
            chain: ChainType::Ethereum,
            account_index,
            address_index,
            raw_tx_payload: unsigned_payload,
            value_usd: Decimal::ZERO,
            target_dex_cex_id: tx.to.clone(),
            network: Network::Mainnet,
        },
        PendingEthereumContext {
            origin: origin.to_string(),
            account_index,
            address_index,
            decoded_method: decoded.method,
            risk: decoded.risk.label().to_string(),
            summary: preflight.summary,
            warnings: preflight.warnings,
            payload_sha256,
        },
    ))
}

fn ethereum_signed_response_bytes(
    signature_response_bytes: &[u8],
    tx: &EthereumTxRequest,
    context: &PendingEthereumContext,
) -> Result<Vec<u8>, String> {
    let response =
        serde_json::from_slice::<ExtensionResponse<SignatureResponse>>(signature_response_bytes)
            .map_err(|error| error.to_string())?;
    let signature = match response {
        ExtensionResponse::Success(signature) => signature,
        ExtensionResponse::Error(error) => {
            return serde_json::to_vec(&ExtensionResponse::<EthereumSignedTransaction>::Error(
                error,
            ))
            .map_err(|error| error.to_string());
        }
    };
    let raw_signed = eth_tx::serialize_signed(tx, &signature)?;
    let raw_tx_hex = format!("0x{}", hex::encode(&raw_signed));
    let tx_hash = eth_tx::tx_hash_hex(&raw_signed);
    let signature_hash = sha256_hex(&signature.raw_signature);
    let _ = append_web3_audit_event(Web3AuditEvent {
        timestamp_unix: now_unix(),
        origin: context.origin.clone(),
        action: "signature".to_string(),
        chain: "ethereum".to_string(),
        chain_id: format!("0x{:x}", tx.chain_id),
        account_index: Some(context.account_index),
        address_index: Some(context.address_index),
        from: Some(tx.from.clone()),
        to: tx.to.clone(),
        contract: tx.to.clone(),
        method: Some(context.decoded_method.clone()),
        selector: None,
        value_native: Some(tx.value.clone()),
        value_fiat: None,
        endpoint_summary: Vec::new(),
        decision: "signed_after_local_confirmation".to_string(),
        warnings: context.warnings.clone(),
        payload_sha256: Some(context.payload_sha256.clone()),
        signature_sha256: Some(signature_hash),
    });

    let signed = EthereumSignedTransaction {
        raw_tx_hex,
        tx_hash,
        decoded_method: context.decoded_method.clone(),
        risk: context.risk.clone(),
        summary: context.summary.clone(),
        warnings: context.warnings.clone(),
    };
    serde_json::to_vec(&ExtensionResponse::Success(signed)).map_err(|error| error.to_string())
}

fn error_response_bytes(error: String) -> Vec<u8> {
    serde_json::to_vec(&ExtensionResponse::<()>::Error(error)).unwrap_or_else(|_| {
        b"{\"status\":\"Error\",\"data\":\"error interno de serializacion\"}".to_vec()
    })
}

fn resolve_socket_path() -> Result<PathBuf, String> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
        "XDG_RUNTIME_DIR no esta definido; no se abrira socket inseguro en /tmp.".to_string()
    })?;

    let dir = PathBuf::from(runtime_dir).join("livencrypt");
    std::fs::create_dir_all(&dir)
        .map_err(|error| format!("No se pudo crear directorio IPC: {}", error))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("No se pudo asegurar permisos IPC: {}", error))?;

    Ok(dir.join("livencrypt.sock"))
}

fn remove_existing_socket_safely(socket_path: &PathBuf) -> Result<(), String> {
    if let Ok(meta) = std::fs::symlink_metadata(socket_path) {
        if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
            return Err("Ruta IPC existente no es socket seguro; abortando.".to_string());
        }
        std::fs::remove_file(socket_path)
            .map_err(|error| format!("No se pudo eliminar socket previo: {}", error))?;
    }
    Ok(())
}

#[cfg(unix)]
pub fn ensure_peer_is_current_user(stream: &UnixStream) -> Result<(), String> {
    use std::mem;
    use std::os::fd::AsRawFd;

    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;

        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if rc != 0 {
            return Err("No se pudo verificar credenciales del peer IPC.".to_string());
        }

        let current_uid = unsafe { libc::geteuid() };
        if cred.uid != current_uid {
            return Err("Conexion IPC rechazada: UID no autorizado.".to_string());
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::io::AsRawFd;

        let fd = stream.as_raw_fd();
        let mut euid: libc::uid_t = 0;
        let mut egid: libc::gid_t = 0;

        let rc = unsafe { libc::getpeereid(fd, &mut euid, &mut egid) };

        if rc != 0 {
            return Err("No se pudo verificar credenciales del peer IPC.".to_string());
        }

        let current_uid = unsafe { libc::geteuid() };
        if euid != current_uid {
            return Err("Conexion IPC rechazada: UID no autorizado.".to_string());
        }

        Ok(())
    }
}
