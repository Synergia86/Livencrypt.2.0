// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: hilo de ejecucion asincrono multi-hilo blindado contra slowloris y fugas de heap */

#![allow(unsafe_code)]

/* rol: hilo de ejecucion asincrono multi-hilo blindado contra slowloris y fugas de heap */
use crate::crypto::blockchain::breaker::GatewaySecurityState;
use crate::crypto::blockchain::firewall::FirewallRules;
use crate::crypto::blockchain::proxy::{read_native_message, write_native_message};
use crate::crypto::blockchain::supervisor::GatewaySupervisor;
use rust_decimal::Decimal;
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

pub enum Web3WorkerCmd {
    UpdateRules {
        max_tx: Option<u32>,
        max_vol: Option<Decimal>,
    },
    AddDexContract(String),
    AddCexDestination(String),
    ResetBreaker([i64; 5], Vec<u8>),
    IncomingWebRequest(Vec<u8>, UnixStream),
    Shutdown,
}

pub enum Web3WorkerEvent {
    StatusChanged(GatewaySecurityState),
    MetricsUpdated {
        tx_count: u32,
        volume_units: Decimal,
    },
    SyncRules(FirewallRules),
    Notification(String),
}

pub struct Web3BackgroundWorker;

impl Web3BackgroundWorker {
    pub fn spawn(
        mut supervisor: GatewaySupervisor,
    ) -> (Sender<Web3WorkerCmd>, Receiver<Web3WorkerEvent>) {
        let (cmd_tx, cmd_rx) = channel::<Web3WorkerCmd>();
        let (event_tx, event_rx) = channel::<Web3WorkerEvent>();
        let running = Arc::new(AtomicBool::new(true));

        spawn_socket_reader(cmd_tx.clone(), event_tx.clone(), Arc::clone(&running));

        thread::spawn(move || {
            let mut last_tx_count = 0;
            let mut last_volume_units = Decimal::ZERO;

            loop {
                match cmd_rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(Web3WorkerCmd::Shutdown) => {
                        running.store(false, Ordering::Relaxed);
                        break;
                    }
                    Ok(cmd) => process_command(cmd, &mut supervisor, &event_tx),
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

            if active_connections.load(Ordering::Relaxed) >= MAX_CONCURRENT_CONNECTIONS {
                continue;
            }

            active_connections.fetch_add(1, Ordering::Relaxed);
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
                counter.fetch_sub(1, Ordering::Relaxed);
            });
        }

        let _ = std::fs::remove_file(&socket_path);
    });
}

fn process_command(
    cmd: Web3WorkerCmd,
    supervisor: &mut GatewaySupervisor,
    event_tx: &Sender<Web3WorkerEvent>,
) {
    match cmd {
        Web3WorkerCmd::UpdateRules { max_tx, max_vol } => {
            let mut updated = false;
            let mut errors = Vec::new();
            if let Some(tx) = max_tx {
                if tx > 0 {
                    supervisor.firewall.rules.max_daily_tx = tx;
                    updated = true;
                } else {
                    errors.push("max_daily_tx debe ser mayor a 0");
                }
            }
            if let Some(volume) = max_vol {
                if volume > Decimal::ZERO {
                    supervisor.firewall.rules.max_daily_volume_units = volume;
                    updated = true;
                } else {
                    errors.push("max_daily_volume_units debe ser mayor a 0");
                }
            }

            let message = if errors.is_empty() && updated {
                "Limites del cortafuegos actualizados".to_string()
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
        Web3WorkerCmd::IncomingWebRequest(mut payload, mut stream) => {
            let old_state = supervisor.breaker.state.clone();
            let response = supervisor.handle_native_payload(&payload);
            let _ = write_native_message(&mut stream, &response);
            payload.zeroize();

            if supervisor.breaker.state != old_state {
                let _ = event_tx.send(Web3WorkerEvent::StatusChanged(
                    supervisor.breaker.state.clone(),
                ));
            }
        }
        Web3WorkerCmd::Shutdown => {}
    }
}

fn normalize_id(value: &mut String) {
    *value = value.trim().to_string();
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
fn ensure_peer_is_current_user(stream: &UnixStream) -> Result<(), String> {
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
