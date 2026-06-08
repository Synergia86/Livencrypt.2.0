// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Inicialización del entorno de aislamiento y mitigación de privilegios de usuario */

#![allow(unsafe_code)]

#[derive(Clone, Copy, Debug)]
pub struct SandboxLimits {
    pub memory_mib: u64,
    pub cpu_seconds: u64,
    pub file_size_mib: u64,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            memory_mib: 512,
            cpu_seconds: 120,
            file_size_mib: 64,
        }
    }
}

#[cfg(target_os = "linux")]
pub fn enter_restricted_child() -> Result<(), String> {
    enter_restricted_child_with_limits(SandboxLimits::default())
}

#[cfg(target_os = "linux")]
pub fn enter_restricted_child_with_limits(limits: SandboxLimits) -> Result<(), String> {
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
            rlim_cur: limits.memory_mib.saturating_mul(1024 * 1024),
            rlim_max: limits.memory_mib.saturating_mul(1024 * 1024),
        };
        let cpu = rlimit {
            rlim_cur: limits.cpu_seconds,
            rlim_max: limits.cpu_seconds,
        };
        let file_size = rlimit {
            rlim_cur: limits.file_size_mib.saturating_mul(1024 * 1024),
            rlim_max: limits.file_size_mib.saturating_mul(1024 * 1024),
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

#[cfg(not(target_os = "linux"))]
pub fn enter_restricted_child_with_limits(_limits: SandboxLimits) -> Result<(), String> {
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
        "RLIMIT_AS: configurable en lanzador TUI".to_string(),
        "RLIMIT_CPU: configurable en lanzador TUI".to_string(),
        "RLIMIT_FSIZE: configurable en lanzador TUI".to_string(),
    ]
}
