// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: disyuntor tactico de seguridad, congelacion forense y aislamiento */

use crate::security::vault::derive_vault_key;
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
}

impl TacticalCircuitBreaker {
    pub fn new() -> Self {
        Self {
            state: GatewaySecurityState::Operational,
            integrity_failures: 0,
        }
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

        let mut verification_key = derive_vault_key(cajas, master_phrase)?;
        if verification_key.is_empty() {
            verification_key.zeroize();
            return Err("credenciales de autorizacion locales invalidas".to_string());
        }

        verification_key.zeroize();
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
