// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: filtro seccomp BPF de denegación de syscalls peligrosas */

#[cfg(target_os = "linux")]
use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
#[cfg(target_os = "linux")]
use std::collections::HashMap;

pub const SECCOMP_ENV_FLAG: &str = "LIVENCRYPT_SECCOMP";

pub fn seccomp_requested() -> bool {
    std::env::var_os(SECCOMP_ENV_FLAG).is_some()
}

#[cfg(target_os = "linux")]
fn denied_syscalls() -> Vec<libc::c_long> {
    // Llamadas que comprometen memoria, depuracion o persistencia del nucleo.
    let mut syscalls = vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_perf_event_open,
        libc::SYS_personality,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_setns,
        libc::SYS_swapon,
        libc::SYS_swapoff,
    ];

    // Acceso directo a puertos de E/S, exclusivo de la arquitectura amd64.
    #[cfg(target_arch = "x86_64")]
    {
        syscalls.push(libc::SYS_iopl);
        syscalls.push(libc::SYS_ioperm);
    }

    syscalls
}

/// Aplica una lista negra de syscalls peligrosas (acción por defecto permitir,
/// matar el proceso si se invoca una de la lista). No es una lista blanca estricta
/// para no bloquear el arranque de la TUI; el endurecimiento total se activa con
/// la variable de entorno y puede afinarse a whitelist tras pruebas en destino.
#[cfg(target_os = "linux")]
pub fn apply_syscall_denylist() -> Result<(), String> {
    let mut rules: HashMap<i32, Vec<SeccompRule>> = HashMap::new();
    for syscall in denied_syscalls() {
        rules.insert(syscall as i32, Vec::new());
    }

    let target_arch: TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| "arquitectura no soportada por el filtro seccomp".to_string())?;

    let filter = SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Trap, target_arch)
        .map_err(|error| format!("no se pudo construir el filtro seccomp: {}", error))?;

    let program: BpfProgram = filter
        .try_into()
        .map_err(|error| format!("no se pudo compilar el filtro seccomp: {}", error))?;

    apply_filter(&program).map_err(|error| format!("no se pudo aplicar el filtro seccomp: {}", error))
}

#[cfg(not(target_os = "linux"))]
pub fn apply_syscall_denylist() -> Result<(), String> {
    Err("seccomp solo esta disponible en Linux".to_string())
}
