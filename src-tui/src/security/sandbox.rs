// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Inicialización del entorno de aislamiento y mitigación de privilegios de usuario */

#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
pub fn enter_restricted_child() -> Result<(), String> {
    use libc::{
        prctl, rlimit, setrlimit, unshare, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
        PR_SET_NO_NEW_PRIVS, RLIMIT_AS, RLIMIT_CPU, RLIMIT_FSIZE,
    };

    unsafe {
        if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err("No se pudo aplicar PR_SET_NO_NEW_PRIVS.".into());
        }

        if unshare(CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWIPC) != 0 {
            return Err("No se pudieron crear namespaces de sandbox.".into());
        }

        let memory = rlimit {
            rlim_cur: 512 * 1024 * 1024,
            rlim_max: 512 * 1024 * 1024,
        };
        let cpu = rlimit {
            rlim_cur: 120,
            rlim_max: 120,
        };
        let file_size = rlimit {
            rlim_cur: 64 * 1024 * 1024,
            rlim_max: 64 * 1024 * 1024,
        };

        let _ = setrlimit(RLIMIT_AS, &memory);
        let _ = setrlimit(RLIMIT_CPU, &cpu);
        let _ = setrlimit(RLIMIT_FSIZE, &file_size);
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enter_restricted_child() -> Result<(), String> {
    Err("Sandbox expu solo soportado en Linux.".into())
}

#[cfg(target_os = "linux")]
pub fn terminate_sandbox(pid: i32, reason: &str) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = crate::security::audit::register_tombstone(&format!("SANDBOX_TERMINATED:{}", reason));
}

#[cfg(not(target_os = "linux"))]
pub fn terminate_sandbox(_pid: i32, reason: &str) {
    let _ = crate::security::audit::register_tombstone(&format!("SANDBOX_UNSUPPORTED:{}", reason));
}

pub fn sandbox_capability_summary() -> Vec<String> {
    vec![
        format!("SO Linux: {}", cfg!(target_os = "linux")),
        "NO_NEW_PRIVS: integrado en hijo".to_string(),
        "Namespaces: NEWNET/NEWNS/NEWIPC en hijo Linux".to_string(),
        "RLIMIT_AS: 512 MiB".to_string(),
        "RLIMIT_CPU: 120 segundos".to_string(),
        "RLIMIT_FSIZE: 64 MiB".to_string(),
    ]
}
