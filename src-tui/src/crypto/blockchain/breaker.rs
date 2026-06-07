// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: disyuntor tactico de seguridad, congelacion forense y aislamiento */

use crate::security::vault::derive_vault_key;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq)]
pub enum GatewaySecurityState {
    Operational,
    Frozen { reason: String, timestamp: u64 },
    HardLocked,
}

pub struct TacticalCircuitBreaker {
    pub state: GatewaySecurityState,
    pub integrity_failures: u32,
    /// Verificador de la combinación exacta (5 cajas + frase maestra) exigida por
    /// el README para descongelar la pasarela. Se vincula al instanciar el gateway.
    rearm_verifier: Option<[u8; 32]>,
}

impl Drop for TacticalCircuitBreaker {
    fn drop(&mut self) {
        if let Some(verifier) = self.rearm_verifier.as_mut() {
            verifier.zeroize();
        }
    }
}

impl TacticalCircuitBreaker {
    pub fn new() -> Self {
        Self {
            state: GatewaySecurityState::Operational,
            integrity_failures: 0,
            rearm_verifier: None,
        }
    }

    /// Vincula las credenciales de rearme. Debe llamarse al inicializar la pasarela
    /// con las MISMAS cajas + frase que generan el llavero. Sin este vínculo, el
    /// rearme se rechaza (fail-closed) en lugar de aceptar cualquier credencial.
    pub fn set_rearm_credentials(
        &mut self,
        cajas: [i64; 5],
        master_phrase: &str,
    ) -> Result<(), String> {
        self.rearm_verifier = Some(compute_rearm_verifier(cajas, master_phrase)?);
        Ok(())
    }

    pub fn trip_breaker(&mut self, reason: &str, timestamp: u64) {
        self.state = GatewaySecurityState::Frozen {
            reason: reason.to_string(),
            timestamp,
        };
    }

    pub fn trigger_hard_lock(&mut self) {
        self.state = GatewaySecurityState::HardLocked;
    }

    pub fn resolve_and_reset(
        &mut self,
        cajas: [i64; 5],
        master_phrase: &str,
    ) -> Result<(), String> {
        if self.state == GatewaySecurityState::HardLocked {
            return Err(
                "bloqueo perimetral permanente: reinicio completo del binario requerido"
                    .to_string(),
            );
        }

        // Fail-closed: si no hay credenciales vinculadas no se puede autorizar el rearme.
        let expected = self.rearm_verifier.ok_or_else(|| {
            "rearme no disponible: pasarela sin credenciales de autorizacion vinculadas".to_string()
        })?;

        // Comparación en tiempo constante contra la combinación EXACTA registrada.
        let mut candidate = compute_rearm_verifier(cajas, master_phrase)?;
        let authorized = constant_time_eq(&candidate, &expected);
        candidate.zeroize();

        if !authorized {
            return Err("credenciales de autorizacion locales invalidas".to_string());
        }

        self.state = GatewaySecurityState::Operational;
        self.integrity_failures = 0;
        Ok(())
    }
}

impl Default for TacticalCircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

/// Deriva un verificador estable de la combinación (5 cajas + frase maestra) usando
/// la misma KDF (Argon2id) que protege el llavero, sin retener material de clave en claro.
fn compute_rearm_verifier(cajas: [i64; 5], master_phrase: &str) -> Result<[u8; 32], String> {
    let mut key = derive_vault_key(cajas, master_phrase)?;
    let mut hasher = Sha256::new();
    hasher.update(b"LIVENCRYPT-BREAKER-REARM-V1");
    hasher.update(&key);
    key.zeroize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Ok(out)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frozen_breaker() -> TacticalCircuitBreaker {
        let mut breaker = TacticalCircuitBreaker::new();
        breaker
            .set_rearm_credentials([1, 2, 3, 4, 5], "frase maestra de prueba")
            .expect("vincular credenciales");
        breaker.trip_breaker("violacion de prueba", 0);
        breaker
    }

    #[test]
    fn rearm_rejects_wrong_credentials() {
        let mut breaker = frozen_breaker();
        assert!(matches!(
            breaker.state,
            GatewaySecurityState::Frozen { .. }
        ));
        // Frase incorrecta -> rechazo.
        assert!(breaker
            .resolve_and_reset([1, 2, 3, 4, 5], "frase incorrecta")
            .is_err());
        // Cajas incorrectas -> rechazo.
        assert!(breaker
            .resolve_and_reset([9, 9, 9, 9, 9], "frase maestra de prueba")
            .is_err());
        // El estado sigue congelado tras intentos fallidos.
        assert!(matches!(
            breaker.state,
            GatewaySecurityState::Frozen { .. }
        ));
    }

    #[test]
    fn rearm_accepts_exact_credentials() {
        let mut breaker = frozen_breaker();
        breaker
            .resolve_and_reset([1, 2, 3, 4, 5], "frase maestra de prueba")
            .expect("rearme con credenciales exactas");
        assert_eq!(breaker.state, GatewaySecurityState::Operational);
        assert_eq!(breaker.integrity_failures, 0);
    }

    #[test]
    fn rearm_without_bound_credentials_is_rejected() {
        let mut breaker = TacticalCircuitBreaker::new();
        breaker.trip_breaker("violacion de prueba", 0);
        // Sin set_rearm_credentials previo no se puede autorizar (fail-closed).
        assert!(breaker
            .resolve_and_reset([1, 2, 3, 4, 5], "cualquier frase")
            .is_err());
    }

    #[test]
    fn hardlocked_breaker_never_rearms() {
        let mut breaker = frozen_breaker();
        breaker.trigger_hard_lock();
        assert!(breaker
            .resolve_and_reset([1, 2, 3, 4, 5], "frase maestra de prueba")
            .is_err());
        assert_eq!(breaker.state, GatewaySecurityState::HardLocked);
    }
}
