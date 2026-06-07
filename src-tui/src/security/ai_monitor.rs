// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Sistema reactivo de detección de intrusiones mediante análisis de actividad local */

/// Umbral de riesgo a partir del cual el disyuntor táctico debe pasar a HardLocked.
pub const CRITICAL_RISK_THRESHOLD: f32 = 0.5;

pub fn heuristic_risk_score(syscalls: &[u32]) -> f32 {
    let socket_like = syscalls
        .iter()
        .filter(|id| **id == 41 || **id == 42)
        .count();
    let ptrace_like = syscalls.iter().filter(|id| **id == 101).count();
    let mount_like = syscalls.iter().filter(|id| **id == 165).count();
    let exec_like = syscalls.iter().filter(|id| **id == 59).count();

    let score = (socket_like as f32 * 0.10)
        + (ptrace_like as f32 * 0.50)
        + (mount_like as f32 * 0.70)
        + (exec_like as f32 * 0.15);

    score.min(1.0)
}

/// Puntuación de riesgo del entorno de ejecución real, derivada del estado de
/// endurecimiento del proceso (inyección de librerías, integridad del binario,
/// volcados de memoria y bloqueo en RAM). Alimenta al disyuntor táctico.
pub fn current_risk_score() -> f32 {
    let Some(status) = crate::security::process_hardening::hardening_status_peek() else {
        return 0.0;
    };
    let mut score = 0.0f32;

    if status.binary_integrity_ok == Some(false) {
        score += 0.6;
    }
    if status.ld_preload_present {
        score += 0.4;
    }
    if status.running_as_root {
        score += 0.2;
    }
    if !status.dumpable_disabled {
        score += 0.1;
    }
    if !status.mlockall_applied {
        score += 0.1;
    }

    score.min(1.0)
}

pub fn expu_baseline_risk() -> f32 {
    heuristic_risk_score(&[])
}
