// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Sistema reactivo de detección de intrusiones mediante análisis de actividad local */

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

pub fn expu_baseline_risk() -> f32 {
    heuristic_risk_score(&[])
}
