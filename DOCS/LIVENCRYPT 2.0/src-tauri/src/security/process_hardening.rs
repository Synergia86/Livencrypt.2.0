// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(unsafe_code)]

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

const SYSTEM_EXPECTED_SHA256_PATH: &str = "/etc/livencrypt/expected.sha256";

#[derive(Clone, Serialize)]
pub struct ProcessHardeningStatus {
    pub core_dumps_disabled: bool,
    pub dumpable_disabled: bool,
    pub dumpable_requested: bool,
    pub mlockall_applied: bool,
    pub mlockall_requested: bool,
    pub running_as_root: bool,
    pub ld_preload_present: bool,
    pub binary_sha256: String,
    pub expected_sha256: Option<String>,
    pub binary_integrity_ok: Option<bool>,
    pub warnings: Vec<String>,
}

static HARDENING_STATUS: OnceLock<ProcessHardeningStatus> = OnceLock::new();

fn hash_current_exe() -> Result<String, String> {
    let path = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut file = File::open(&path)
        .map_err(|error| format!("No se pudo abrir binario {:?}: {}", path, error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];

    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn normalize_expected_sha256(value: String) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() == 64 && normalized.chars().all(|char| char.is_ascii_hexdigit()) {
        Some(normalized)
    } else {
        None
    }
}

fn read_expected_sha256() -> Option<String> {
    std::env::var("LIVENCRYPT_EXPECTED_SHA256")
        .ok()
        .and_then(normalize_expected_sha256)
        .or_else(|| {
            std::fs::read_to_string(Path::new(SYSTEM_EXPECTED_SHA256_PATH))
                .ok()
                .and_then(normalize_expected_sha256)
        })
}

#[cfg(target_os = "linux")]
fn disable_core_dumps() -> bool {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 }
}

#[cfg(not(target_os = "linux"))]
fn disable_core_dumps() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn disable_dumpable() -> bool {
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 }
}

#[cfg(not(target_os = "linux"))]
fn disable_dumpable() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn apply_mlockall() -> bool {
    raise_memlock_soft_limit();

    unsafe {
        const MCL_ONFAULT: libc::c_int = 4;
        if libc::mlockall(libc::MCL_CURRENT | MCL_ONFAULT) == 0 {
            return true;
        }

        if libc::mlockall(libc::MCL_CURRENT) == 0 {
            return true;
        }

        false
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_mlockall() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn raise_memlock_soft_limit() {
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) != 0 {
            return;
        }

        if limit.rlim_cur >= limit.rlim_max {
            return;
        }

        let raised = libc::rlimit {
            rlim_cur: limit.rlim_max,
            rlim_max: limit.rlim_max,
        };
        let _ = libc::setrlimit(libc::RLIMIT_MEMLOCK, &raised);
    }
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(target_os = "linux"))]
fn running_as_root() -> bool {
    false
}

pub fn initialize_process_hardening() -> ProcessHardeningStatus {
    HARDENING_STATUS
        .get_or_init(|| {
            let core_dumps_disabled = disable_core_dumps();
            let dumpable_requested = true;
            let mlockall_requested = true;
            let dumpable_disabled = disable_dumpable();
            let mlockall_applied = apply_mlockall();
            let running_as_root = running_as_root();
            let ld_preload_present = std::env::var_os("LD_PRELOAD").is_some();
            let binary_sha256 = hash_current_exe().unwrap_or_else(|error| format!("error:{}", error));
            let expected_sha256 = read_expected_sha256();
            let binary_integrity_ok = expected_sha256
                .as_ref()
                .map(|expected| expected == &binary_sha256);

            let mut warnings = Vec::new();
            if !core_dumps_disabled {
                warnings.push("No se pudo deshabilitar RLIMIT_CORE.".to_string());
            }
            if !dumpable_disabled {
                warnings.push("No se pudo aplicar PR_SET_DUMPABLE=0.".to_string());
            }
            if !mlockall_applied {
                warnings.push("MLOCKALL REAL NO APLICADO: el kernel rechazo mlockall; revise RLIMIT_MEMLOCK, CAP_IPC_LOCK o limites del usuario.".to_string());
            }
            if running_as_root {
                warnings.push("Livencrypt se esta ejecutando como root; no es recomendable para uso normal.".to_string());
            }
            if ld_preload_present {
                warnings.push("LD_PRELOAD esta definido; puede permitir inyeccion/intercepcion de librerias.".to_string());
            }
            if binary_integrity_ok == Some(false) {
                warnings.push("El hash del binario no coincide con LIVENCRYPT_EXPECTED_SHA256.".to_string());
            }

            ProcessHardeningStatus {
                core_dumps_disabled,
                dumpable_disabled,
                dumpable_requested,
                mlockall_applied,
                mlockall_requested,
                running_as_root,
                ld_preload_present,
                binary_sha256,
                expected_sha256,
                binary_integrity_ok,
                warnings,
            }
        })
        .clone()
}

#[tauri::command]
pub fn process_hardening_status() -> ProcessHardeningStatus {
    initialize_process_hardening()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn hardening_startup_controls_report_real_state() {
        let status = initialize_process_hardening();

        assert!(status.core_dumps_disabled);
        assert!(status.dumpable_disabled);
        assert_eq!(
            status.mlockall_applied,
            !status
                .warnings
                .iter()
                .any(|warning| warning.contains("MLOCKALL REAL NO APLICADO"))
        );
        if let Some(expected_sha256) = &status.expected_sha256 {
            assert_eq!(
                status.binary_integrity_ok,
                Some(expected_sha256 == &status.binary_sha256)
            );
        } else {
            assert!(status.binary_integrity_ok.is_none());
        }
    }
}
