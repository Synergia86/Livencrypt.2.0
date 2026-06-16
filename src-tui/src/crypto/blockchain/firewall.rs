// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: cortafuegos de politicas en caliente y listas blancas */

use crate::crypto::blockchain::tx_parser::{native_units, ParsedDestinationKind, ParsedTx};
use crate::crypto::blockchain::types::{
    AccountPolicy, ChainType, PriceBook, PriceQuote, ScheduledPolicy, TxMethod,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FirewallRules {
    pub max_daily_tx: u32,
    #[serde(default)]
    pub max_daily_volume_units: Decimal,
    #[serde(default)]
    pub max_daily_crypto_amount: Decimal,
    #[serde(default)]
    pub max_daily_fiat_value: Decimal,
    #[serde(default = "default_fiat_currency")]
    pub fiat_currency: String,
    pub allowed_dex_contracts: Vec<String>,
    pub allowed_cex_destinations: Vec<String>,
    pub allowed_erc20_contracts: Vec<String>,
    pub allowed_chain_ids: Vec<u64>,
    /// Decimales registrados por dirección de contrato ERC-20.
    /// Sin registro en `token_decimals`, la transacción ERC-20 es rechazada.
    pub token_decimals: HashMap<String, u8>,
    #[serde(default)]
    pub account_policies: Vec<AccountPolicy>,
    #[serde(default)]
    pub price_book: PriceBook,
}

impl Default for FirewallRules {
    fn default() -> Self {
        Self {
            max_daily_tx: 10,
            max_daily_volume_units: Decimal::new(5000, 0),
            max_daily_crypto_amount: Decimal::new(5000, 0),
            max_daily_fiat_value: Decimal::new(5000, 0),
            fiat_currency: default_fiat_currency(),
            allowed_dex_contracts: Vec::new(),
            allowed_cex_destinations: Vec::new(),
            allowed_erc20_contracts: Vec::new(),
            allowed_chain_ids: vec![0, 1, 501],
            token_decimals: HashMap::new(),
            account_policies: Vec::new(),
            price_book: PriceBook::default(),
        }
    }
}

fn default_fiat_currency() -> String {
    "USD".to_string()
}

pub struct LiveFirewall {
    pub rules: FirewallRules,
    pub tx_count_today: u32,
    pub volume_today_units: Decimal,
    pub crypto_amount_today: Decimal,
    pub fiat_value_today: Decimal,
    pub native_amount_by_chain: HashMap<String, Decimal>,
    pub asset_amount_by_token: HashMap<String, Decimal>,
    pub fiat_value_by_currency: HashMap<String, Decimal>,
    pub last_reset_timestamp: u64,
    reset_instant: Instant,
}

impl Default for LiveFirewall {
    fn default() -> Self {
        Self::new(FirewallRules::default())
    }
}

impl LiveFirewall {
    pub fn new(rules: FirewallRules) -> Self {
        Self {
            rules,
            tx_count_today: 0,
            volume_today_units: Decimal::ZERO,
            crypto_amount_today: Decimal::ZERO,
            fiat_value_today: Decimal::ZERO,
            native_amount_by_chain: HashMap::new(),
            asset_amount_by_token: HashMap::new(),
            fiat_value_by_currency: HashMap::new(),
            last_reset_timestamp: now_unix(),
            reset_instant: Instant::now(),
        }
    }

    fn check_and_reset_daily_counters(&mut self) {
        // El reinicio diario se mide con un reloj monotónico, inmune a retrocesos
        // del reloj de pared que un atacante local podría usar para refrescar cuotas.
        if self.reset_instant.elapsed() >= Duration::from_secs(86_400) {
            self.tx_count_today = 0;
            self.volume_today_units = Decimal::ZERO;
            self.crypto_amount_today = Decimal::ZERO;
            self.fiat_value_today = Decimal::ZERO;
            self.native_amount_by_chain.clear();
            self.asset_amount_by_token.clear();
            self.fiat_value_by_currency.clear();
            self.reset_instant = Instant::now();
            self.last_reset_timestamp = now_unix();
        }
    }

    pub fn validate_parsed_transaction(&mut self, parsed: &ParsedTx) -> Result<(), String> {
        self.check_and_reset_daily_counters();

        if self.tx_count_today >= self.rules.max_daily_tx {
            return Err(format!(
                "restriccion de frecuencia: limite maximo de {} transacciones diarias alcanzado",
                self.rules.max_daily_tx
            ));
        }

        // Anti-replay: el chain_id parseado debe estar permitido para evitar
        // firmas reutilizables entre redes. No se usa value_usd externo porque
        // aceptar valores no parseados es blind signing inseguro.
        if !self.rules.allowed_chain_ids.contains(&parsed.chain_id) {
            return Err(format!(
                "chain_id {} no autorizado, posible replay cross-chain",
                parsed.chain_id
            ));
        }

        // Reject unsupported Ethereum methods only for Ethereum chain.
        // Bitcoin (BtcRawTx) and Solana (SolanaTransfer) are not rejected by method.
        if parsed.chain == ChainType::Ethereum {
            if let TxMethod::EthUnsupported(sel) = &parsed.method {
                return Err(format!("método de contrato Ethereum no soportado: {}", sel));
            }
        }

        // Reject any generic unsupported method on any chain.
        if let TxMethod::Unsupported(sel) = &parsed.method {
            return Err(format!(
                "método no soportado para la cadena {:?}: {}",
                parsed.chain, sel
            ));
        }

        let effective_volume = self.effective_volume_units(parsed)?;
        let projected_volume = safe_volume_add(self.volume_today_units, effective_volume)?;
        if projected_volume > self.rules.max_daily_volume_units {
            return Err(format!(
                "umbral de volumen excedido desde payload real: limite diario de {} unidades",
                self.rules.max_daily_volume_units
            ));
        }
        if projected_volume > self.rules.max_daily_crypto_amount {
            return Err(format!(
                "umbral cripto excedido desde payload real: limite diario de {} activos/token",
                self.rules.max_daily_crypto_amount
            ));
        }

        for destination in &parsed.destinations {
            match destination.kind {
                ParsedDestinationKind::Erc20Contract => {
                    if !self
                        .rules
                        .allowed_erc20_contracts
                        .contains(&destination.address)
                    {
                        return Err(format!(
                            "contrato ERC-20 no autorizado: {}",
                            destination.address
                        ));
                    }
                }
                ParsedDestinationKind::Erc20Receiver | ParsedDestinationKind::Native => {
                    let is_authorized_dex = self
                        .rules
                        .allowed_dex_contracts
                        .contains(&destination.address);
                    let is_authorized_cex = self
                        .rules
                        .allowed_cex_destinations
                        .contains(&destination.address);

                    if !is_authorized_dex && !is_authorized_cex {
                        return Err(format!(
                            "bloqueo: destino '{}' no autorizado",
                            destination.address
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Gobernanza de destino inmutable: toda firma debe declarar un `target_dex_cex_id`
    /// que coincida con un destino real de la transacción y esté en lista blanca.
    pub fn validate_target_destination_id(
        &self,
        parsed: &ParsedTx,
        target_id: Option<&str>,
    ) -> Result<(), String> {
        let target = target_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "destino inmutable obligatorio ausente: se requiere target_dex_cex_id".to_string()
            })?;

        let matches_real_destination = parsed.destinations.iter().any(|destination| {
            matches!(
                destination.kind,
                ParsedDestinationKind::Native | ParsedDestinationKind::Erc20Receiver
            ) && destination.address == target
        });
        if !matches_real_destination {
            return Err(format!(
                "violacion de destino inmutable: target_dex_cex_id '{}' no coincide con el destino real de la transaccion",
                target
            ));
        }

        let whitelisted = self
            .rules
            .allowed_dex_contracts
            .iter()
            .any(|contract| contract == target)
            || self
                .rules
                .allowed_cex_destinations
                .iter()
                .any(|destination| destination == target);
        if !whitelisted {
            return Err(format!(
                "violacion de destino inmutable: '{}' no esta en la lista blanca de DEX/CEX",
                target
            ));
        }

        Ok(())
    }

    pub fn validate_account_policy(
        &self,
        parsed: &ParsedTx,
        account_index: u32,
        address_index: u32,
        effective_volume: Decimal,
        fiat_value: Decimal,
        fiat_currency: &str,
    ) -> Result<(), String> {
        let Some(policy) = self.active_policy(&parsed.chain, account_index, address_index) else {
            return self.validate_global_fiat_limit(fiat_value, fiat_currency);
        };

        if self.tx_count_today >= policy.max_tx_per_window {
            return Err(format!(
                "politica de cuenta '{}': limite de {} TX alcanzado",
                policy.label, policy.max_tx_per_window
            ));
        }

        if let Some(max_native) = policy.max_native_amount {
            let projected = safe_volume_add(self.crypto_amount_today, effective_volume)?;
            if projected > max_native {
                return Err(format!(
                    "politica de cuenta '{}': limite cripto excedido {} > {}",
                    policy.label, projected, max_native
                ));
            }
        }

        let fiat_currency = fiat_currency.trim().to_uppercase();
        if let Some(max_fiat) = policy.max_fiat_value {
            if fiat_value <= Decimal::ZERO {
                return Err(format!(
                    "politica de cuenta '{}': valor fiat local requerido para aplicar limite",
                    policy.label
                ));
            }
            let current = self
                .fiat_value_by_currency
                .get(&fiat_currency)
                .copied()
                .unwrap_or(Decimal::ZERO);
            let projected = safe_volume_add(current, fiat_value)?;
            if projected > max_fiat {
                return Err(format!(
                    "politica de cuenta '{}': limite fiat excedido {} {} > {} {}",
                    policy.label, projected, fiat_currency, max_fiat, fiat_currency
                ));
            }
        } else {
            self.validate_global_fiat_limit(fiat_value, &fiat_currency)?;
        }

        for destination in &parsed.destinations {
            match destination.kind {
                ParsedDestinationKind::Erc20Contract => {
                    if !policy.allowed_contracts.is_empty()
                        && !policy.allowed_contracts.contains(&destination.address)
                    {
                        return Err(format!(
                            "politica de cuenta '{}': contrato no autorizado {}",
                            policy.label, destination.address
                        ));
                    }
                }
                ParsedDestinationKind::Native | ParsedDestinationKind::Erc20Receiver => {
                    if !policy.allowed_destinations.is_empty()
                        && !policy.allowed_destinations.contains(&destination.address)
                    {
                        return Err(format!(
                            "politica de cuenta '{}': destino no autorizado {}",
                            policy.label, destination.address
                        ));
                    }
                    if let Some(schedule_error) = self.validate_scheduled_rules(
                        policy,
                        parsed,
                        account_index,
                        address_index,
                        &destination.address,
                        effective_volume,
                        fiat_value,
                    ) {
                        return Err(schedule_error);
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_global_fiat_limit(
        &self,
        fiat_value: Decimal,
        fiat_currency: &str,
    ) -> Result<(), String> {
        if self.rules.max_daily_fiat_value <= Decimal::ZERO {
            return Ok(());
        }
        if fiat_value <= Decimal::ZERO {
            return Err(
                "limite fiat activo: se requiere valoracion local/manual/RPC fiable".to_string(),
            );
        }
        let fiat_currency = fiat_currency.trim().to_uppercase();
        let current = self
            .fiat_value_by_currency
            .get(&fiat_currency)
            .copied()
            .unwrap_or(Decimal::ZERO);
        let projected = safe_volume_add(current, fiat_value)?;
        if projected > self.rules.max_daily_fiat_value {
            return Err(format!(
                "limite fiat diario excedido: {} {} > {} {}",
                projected, fiat_currency, self.rules.max_daily_fiat_value, fiat_currency
            ));
        }
        Ok(())
    }

    fn validate_scheduled_rules(
        &self,
        policy: &AccountPolicy,
        parsed: &ParsedTx,
        account_index: u32,
        address_index: u32,
        destination: &str,
        effective_volume: Decimal,
        fiat_value: Decimal,
    ) -> Option<String> {
        let matching = policy.scheduled_rules.iter().find(|rule| {
            rule.applies_to(&parsed.chain, account_index, address_index, destination)
        })?;
        if let Some(expires_unix) = matching.expires_unix {
            if now_unix() > expires_unix {
                return Some(format!("regla programada '{}' caducada", matching.name));
            }
        }
        if matching.max_tx > 0 && self.tx_count_today >= matching.max_tx {
            return Some(format!(
                "regla programada '{}': limite de {} TX alcanzado",
                matching.name, matching.max_tx
            ));
        }
        if let Some(max_asset) = matching.max_asset_amount {
            if effective_volume > max_asset {
                return Some(format!(
                    "regla programada '{}': importe {} supera {}",
                    matching.name, effective_volume, max_asset
                ));
            }
        }
        if let Some(max_fiat) = matching.max_fiat_value {
            if fiat_value <= Decimal::ZERO {
                return Some(format!(
                    "regla programada '{}': valor fiat requerido",
                    matching.name
                ));
            }
            if fiat_value > max_fiat {
                return Some(format!(
                    "regla programada '{}': fiat {} supera {}",
                    matching.name, fiat_value, max_fiat
                ));
            }
        }
        None
    }

    pub fn commit_transaction(&mut self, estimated_volume_units: Decimal) -> Result<(), String> {
        let projected = safe_volume_add(self.volume_today_units, estimated_volume_units)?;
        if projected > self.rules.max_daily_volume_units {
            return Err(format!(
                "volumen diario excedido: {} > limite {}",
                projected, self.rules.max_daily_volume_units
            ));
        }
        self.tx_count_today = self.tx_count_today.saturating_add(1);
        self.volume_today_units = projected;
        self.crypto_amount_today = projected;
        Ok(())
    }

    pub fn commit_transaction_context(
        &mut self,
        parsed: &ParsedTx,
        estimated_volume_units: Decimal,
        fiat_value: Decimal,
        fiat_currency: &str,
    ) -> Result<(), String> {
        self.commit_transaction(estimated_volume_units)?;
        for (asset, amount) in parsed_asset_amounts(parsed, estimated_volume_units) {
            let target = if asset.starts_with("native:") {
                &mut self.native_amount_by_chain
            } else {
                &mut self.asset_amount_by_token
            };
            let current = target.get(&asset).copied().unwrap_or(Decimal::ZERO);
            target.insert(asset, safe_volume_add(current, amount)?);
        }
        if fiat_value > Decimal::ZERO {
            let currency = fiat_currency.trim().to_uppercase();
            let current = self
                .fiat_value_by_currency
                .get(&currency)
                .copied()
                .unwrap_or(Decimal::ZERO);
            let projected = safe_volume_add(current, fiat_value)?;
            self.fiat_value_by_currency.insert(currency, projected);
            self.fiat_value_today = projected;
        }
        Ok(())
    }

    pub fn active_policy(
        &self,
        chain: &ChainType,
        account_index: u32,
        address_index: u32,
    ) -> Option<&AccountPolicy> {
        self.rules
            .account_policies
            .iter()
            .find(|policy| policy.applies_to(chain, account_index, address_index))
    }

    pub fn upsert_account_policy(&mut self, policy: AccountPolicy) {
        self.rules.account_policies.retain(|existing| {
            !(existing.chain == policy.chain
                && existing.account_index == policy.account_index
                && existing.address_index == policy.address_index)
        });
        self.rules.account_policies.push(policy);
    }

    pub fn remove_account_policy(
        &mut self,
        chain: &ChainType,
        account_index: u32,
        address_index: Option<u32>,
    ) -> bool {
        let before = self.rules.account_policies.len();
        self.rules.account_policies.retain(|policy| {
            !(policy.chain == *chain
                && policy.account_index == account_index
                && policy.address_index == address_index)
        });
        self.rules.account_policies.len() != before
    }

    pub fn add_scheduled_policy(
        &mut self,
        chain: &ChainType,
        account_index: u32,
        address_index: Option<u32>,
        rule: ScheduledPolicy,
    ) -> Result<(), String> {
        let policy = self
            .rules
            .account_policies
            .iter_mut()
            .find(|policy| {
                policy.chain == *chain
                    && policy.account_index == account_index
                    && policy.address_index == address_index
            })
            .ok_or_else(|| "politica de cuenta no encontrada".to_string())?;
        policy
            .scheduled_rules
            .retain(|existing| existing.name != rule.name);
        policy.scheduled_rules.push(rule);
        Ok(())
    }

    pub fn remove_scheduled_policy(
        &mut self,
        chain: &ChainType,
        account_index: u32,
        address_index: Option<u32>,
        name: &str,
    ) -> bool {
        let Some(policy) = self.rules.account_policies.iter_mut().find(|policy| {
            policy.chain == *chain
                && policy.account_index == account_index
                && policy.address_index == address_index
        }) else {
            return false;
        };
        let before = policy.scheduled_rules.len();
        policy.scheduled_rules.retain(|rule| rule.name != name);
        policy.scheduled_rules.len() != before
    }

    pub fn set_crypto_limit(&mut self, value: Decimal) -> Result<(), String> {
        if value <= Decimal::ZERO {
            return Err("el limite cripto debe ser mayor a 0".into());
        }
        self.rules.max_daily_crypto_amount = value;
        self.rules.max_daily_volume_units = value;
        Ok(())
    }

    pub fn set_fiat_limit(&mut self, value: Decimal, currency: &str) -> Result<(), String> {
        if value <= Decimal::ZERO {
            return Err("el limite fiat debe ser mayor a 0".into());
        }
        let currency = currency.trim().to_uppercase();
        if currency.is_empty() || currency.len() > 8 {
            return Err("moneda fiat invalida".into());
        }
        self.rules.max_daily_fiat_value = value;
        self.rules.fiat_currency = currency;
        Ok(())
    }

    pub fn set_manual_price(
        &mut self,
        asset: &str,
        fiat: &str,
        value: Decimal,
    ) -> Result<(), String> {
        let asset = asset.trim().to_uppercase();
        let fiat = fiat.trim().to_uppercase();
        if asset.is_empty() || asset.len() > 32 {
            return Err("activo de precio invalido".into());
        }
        if fiat.is_empty() || fiat.len() > 8 {
            return Err("moneda fiat invalida".into());
        }
        if value <= Decimal::ZERO {
            return Err("precio manual debe ser mayor a 0".into());
        }
        self.rules
            .price_book
            .quotes
            .retain(|quote| !(quote.asset == asset && quote.fiat == fiat));
        self.rules.price_book.primary_fiat = fiat.clone();
        self.rules.price_book.quotes.push(PriceQuote {
            asset,
            fiat,
            value,
            timestamp_unix: now_unix(),
            source: "manual-local".to_string(),
        });
        Ok(())
    }

    pub fn effective_volume_units(&self, parsed: &ParsedTx) -> Result<Decimal, String> {
        let mut total = Decimal::ZERO;
        let erc20_contract = parsed
            .destinations
            .iter()
            .find(|destination| matches!(destination.kind, ParsedDestinationKind::Erc20Contract))
            .map(|destination| destination.address.as_str());

        for destination in &parsed.destinations {
            let volume = match destination.kind {
                ParsedDestinationKind::Erc20Contract => Decimal::ZERO,
                ParsedDestinationKind::Erc20Receiver => {
                    let contract =
                        erc20_contract.ok_or_else(|| "ERC-20 sin contrato parseado".to_string())?;
                    let decimals = match self.rules.token_decimals.get(contract).copied() {
                        Some(decimals) => decimals,
                        None => {
                            return Err(format!(
                                "Token no registrado: se requiere especificar decimales para {}",
                                contract
                            ))
                        }
                    };
                    token_units(destination.value_units, decimals)
                }
                ParsedDestinationKind::Native => {
                    native_units(parsed.chain.clone(), destination.value_units)
                }
            };
            total = safe_volume_add(total, volume)?;
        }
        Ok(total)
    }
}

fn parsed_asset_amounts(
    parsed: &ParsedTx,
    effective_volume_units: Decimal,
) -> Vec<(String, Decimal)> {
    let token_contract = parsed
        .destinations
        .iter()
        .find(|destination| matches!(destination.kind, ParsedDestinationKind::Erc20Contract))
        .map(|destination| destination.address.clone());
    if let Some(contract) = token_contract {
        return vec![(format!("token:{}", contract), effective_volume_units)];
    }
    vec![(
        format!("native:{:?}:{}", parsed.chain, parsed.chain_id),
        effective_volume_units,
    )]
}

fn token_units(value_units: u128, decimals: u8) -> Decimal {
    Decimal::from(value_units) / Decimal::from(10u128.pow(u32::from(decimals.min(38))))
}

fn safe_volume_add(left: Decimal, right: Decimal) -> Result<Decimal, String> {
    if left.is_sign_negative() || right.is_sign_negative() {
        return Err("volumen parseado invalido".into());
    }
    let out = left
        .checked_add(right)
        .ok_or_else(|| "suma de volumen no valida: desbordamiento".to_string())?;
    Ok(out)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::blockchain::tx_parser::{ParsedDestination, ParsedDestinationKind};
    use crate::crypto::blockchain::types::{ChainType, TxMethod};
    use rust_decimal::prelude::*;

    #[test]
    fn rejects_bitcoin_if_any_output_is_not_allowed() {
        let mut firewall = LiveFirewall::new(FirewallRules {
            max_daily_tx: 10,
            max_daily_volume_units: Decimal::from(10),
            allowed_dex_contracts: vec!["btc:p2wpkh:permitido".to_string()],
            allowed_cex_destinations: Vec::new(),
            ..FirewallRules::default()
        });
        let parsed = ParsedTx {
            chain: ChainType::Bitcoin,
            to_address: "btc:p2wpkh:permitido".to_string(),
            value_units: 75_000_000,
            volume_units: Decimal::from_str("0.75").unwrap(),
            destinations: vec![
                ParsedDestination {
                    address: "btc:p2wpkh:permitido".to_string(),
                    value_units: 50_000_000,
                    kind: ParsedDestinationKind::Native,
                },
                ParsedDestination {
                    address: "btc:p2wpkh:no-permitido".to_string(),
                    value_units: 25_000_000,
                    kind: ParsedDestinationKind::Native,
                },
            ],
            chain_id: 0,
            method: TxMethod::BtcRawTx,
            summary: String::new(),
        };

        assert!(firewall.validate_parsed_transaction(&parsed).is_err());
    }

    #[test]
    fn volume_limit_uses_native_units_not_smallest_units() {
        let destination = "0x1111111111111111111111111111111111111111".to_string();
        let mut firewall = LiveFirewall::new(FirewallRules {
            max_daily_tx: 10,
            max_daily_volume_units: Decimal::ONE,
            allowed_dex_contracts: vec![destination.clone()],
            allowed_cex_destinations: Vec::new(),
            ..FirewallRules::default()
        });
        let parsed = ParsedTx {
            chain: ChainType::Ethereum,
            to_address: destination.clone(),
            value_units: 1_000_000_000_000_000_000,
            volume_units: Decimal::ONE,
            destinations: vec![ParsedDestination {
                address: destination,
                value_units: 1_000_000_000_000_000_000,
                kind: ParsedDestinationKind::Native,
            }],
            chain_id: 1,
            method: TxMethod::EthTransfer,
            summary: String::new(),
        };

        assert!(firewall.validate_parsed_transaction(&parsed).is_ok());
        let _ = firewall.commit_transaction(firewall.effective_volume_units(&parsed).unwrap());
        assert_eq!(firewall.volume_today_units, Decimal::ONE);
    }

    #[test]
    fn rejects_unallowed_erc20_contract() {
        let receiver = "0x2222222222222222222222222222222222222222".to_string();
        let contract = "0x1111111111111111111111111111111111111111".to_string();
        let mut firewall = LiveFirewall::new(FirewallRules {
            max_daily_tx: 10,
            max_daily_volume_units: Decimal::from(10),
            allowed_dex_contracts: vec![receiver.clone()],
            allowed_cex_destinations: Vec::new(),
            allowed_erc20_contracts: Vec::new(),
            ..FirewallRules::default()
        });
        let parsed = ParsedTx {
            chain: ChainType::Ethereum,
            to_address: receiver.clone(),
            value_units: 1_000_000,
            volume_units: Decimal::ONE,
            destinations: vec![
                ParsedDestination {
                    address: contract,
                    value_units: 0,
                    kind: ParsedDestinationKind::Erc20Contract,
                },
                ParsedDestination {
                    address: receiver,
                    value_units: 1_000_000,
                    kind: ParsedDestinationKind::Erc20Receiver,
                },
            ],
            chain_id: 1,
            method: TxMethod::EthErc20Transfer,
            summary: String::new(),
        };

        assert!(firewall.validate_parsed_transaction(&parsed).is_err());
    }

    #[test]
    fn erc20_decimals_define_effective_volume() {
        let receiver = "0x2222222222222222222222222222222222222222".to_string();
        let contract = "0x1111111111111111111111111111111111111111".to_string();
        let mut decimals = HashMap::new();
        decimals.insert(contract.clone(), 6);
        let firewall = LiveFirewall::new(FirewallRules {
            max_daily_tx: 10,
            max_daily_volume_units: Decimal::from(10),
            allowed_dex_contracts: vec![receiver.clone()],
            allowed_cex_destinations: Vec::new(),
            allowed_erc20_contracts: vec![contract.clone()],
            token_decimals: decimals,
            ..FirewallRules::default()
        });
        let parsed = ParsedTx {
            chain: ChainType::Ethereum,
            to_address: receiver.clone(),
            value_units: 1_000_000,
            volume_units: Decimal::ZERO,
            destinations: vec![
                ParsedDestination {
                    address: contract,
                    value_units: 0,
                    kind: ParsedDestinationKind::Erc20Contract,
                },
                ParsedDestination {
                    address: receiver,
                    value_units: 1_000_000,
                    kind: ParsedDestinationKind::Erc20Receiver,
                },
            ],
            chain_id: 1,
            method: TxMethod::EthErc20Transfer,
            summary: String::new(),
        };

        assert_eq!(
            firewall.effective_volume_units(&parsed).unwrap(),
            Decimal::from(1)
        );
    }

    #[test]
    fn rejects_registered_contract_without_token_decimals() {
        let receiver = "0x2222222222222222222222222222222222222222".to_string();
        let contract = "0x1111111111111111111111111111111111111111".to_string();
        let firewall = LiveFirewall::new(FirewallRules {
            max_daily_tx: 10,
            max_daily_volume_units: Decimal::from(10),
            allowed_dex_contracts: vec![receiver.clone()],
            allowed_cex_destinations: Vec::new(),
            allowed_erc20_contracts: vec![contract.clone()],
            token_decimals: HashMap::new(),
            ..FirewallRules::default()
        });
        let parsed = ParsedTx {
            chain: ChainType::Ethereum,
            to_address: receiver.clone(),
            value_units: 1_000_000,
            volume_units: Decimal::ZERO,
            destinations: vec![
                ParsedDestination {
                    address: contract,
                    value_units: 0,
                    kind: ParsedDestinationKind::Erc20Contract,
                },
                ParsedDestination {
                    address: receiver,
                    value_units: 1_000_000,
                    kind: ParsedDestinationKind::Erc20Receiver,
                },
            ],
            chain_id: 1,
            method: TxMethod::EthErc20Transfer,
            summary: String::new(),
        };

        assert!(firewall.effective_volume_units(&parsed).is_err());
    }

    #[test]
    fn safe_volume_addition_rejects_nan_inf_and_negative() {
        // Note: Decimal handles finite checks differently, but we can test sign.
        assert!(safe_volume_add(Decimal::ONE, Decimal::from(-1)).is_err());
    }

    #[test]
    fn rejects_disallowed_chain_id() {
        let destination = "0x1111111111111111111111111111111111111111".to_string();
        let mut firewall = LiveFirewall::new(FirewallRules {
            max_daily_tx: 10,
            max_daily_volume_units: Decimal::from(10),
            allowed_dex_contracts: vec![destination.clone()],
            allowed_cex_destinations: Vec::new(),
            allowed_chain_ids: vec![1],
            ..FirewallRules::default()
        });
        let parsed = ParsedTx {
            chain: ChainType::Ethereum,
            to_address: destination.clone(),
            value_units: 1,
            volume_units: Decimal::ZERO,
            destinations: vec![ParsedDestination {
                address: destination,
                value_units: 1,
                kind: ParsedDestinationKind::Native,
            }],
            chain_id: 11155111,
            method: TxMethod::EthTransfer,
            summary: String::new(),
        };

        assert!(firewall.validate_parsed_transaction(&parsed).is_err());
    }

    #[test]
    fn commit_transaction_error_aborts() {
        let mut fw = LiveFirewall::default();
        fw.rules.max_daily_volume_units = Decimal::new(1, 0); // 1 unit
                                                              // Simula volumen de 2 unidades
        let result = fw.commit_transaction(Decimal::new(2, 0));
        assert!(result.is_err());
    }

    #[test]
    fn erc20_without_registration_rejected() {
        let mut fw = LiveFirewall::default();
        fw.rules.allowed_chain_ids = vec![1];
        fw.rules.allowed_erc20_contracts = vec!["0xToken".into()];
        fw.rules.token_decimals = HashMap::new();

        let parsed = ParsedTx {
            chain: ChainType::Ethereum,
            to_address: "0xReceiver".into(),
            value_units: 1_000_000,
            volume_units: Decimal::ZERO,
            destinations: vec![
                ParsedDestination {
                    address: "0xToken".into(),
                    value_units: 0,
                    kind: ParsedDestinationKind::Erc20Contract,
                },
                ParsedDestination {
                    address: "0xReceiver".into(),
                    value_units: 1_000_000,
                    kind: ParsedDestinationKind::Erc20Receiver,
                },
            ],
            chain_id: 1,
            method: TxMethod::EthErc20Transfer,
            summary: String::new(),
        };
        assert!(fw.validate_parsed_transaction(&parsed).is_err());
    }

    #[test]
    fn unsupported_method_is_rejected() {
        let mut fw = LiveFirewall::default();
        fw.rules.allowed_chain_ids = vec![1];
        let parsed = ParsedTx {
            chain: ChainType::Ethereum,
            to_address: "0xReceiver".into(),
            value_units: 1_000_000,
            volume_units: Decimal::ZERO,
            destinations: vec![ParsedDestination {
                address: "0xReceiver".into(),
                value_units: 1_000_000,
                kind: ParsedDestinationKind::Native,
            }],
            chain_id: 1,
            method: TxMethod::EthUnsupported("0x12345678".into()),
            summary: String::new(),
        };
        assert!(fw.validate_parsed_transaction(&parsed).is_err());
    }

    #[test]
    fn bitcoin_not_rejected_by_method() {
        let mut fw = LiveFirewall::default();
        fw.rules.allowed_chain_ids = vec![0];
        fw.rules.allowed_dex_contracts = vec!["btc:p2wpkh:addr".into()];
        let parsed = ParsedTx {
            chain: ChainType::Bitcoin,
            to_address: "btc:p2wpkh:addr".into(),
            value_units: 1_000_000,
            volume_units: Decimal::new(1, 0),
            destinations: vec![ParsedDestination {
                address: "btc:p2wpkh:addr".into(),
                value_units: 1_000_000,
                kind: ParsedDestinationKind::Native,
            }],
            chain_id: 0,
            method: TxMethod::BtcRawTx,
            summary: String::new(),
        };
        assert!(fw.validate_parsed_transaction(&parsed).is_ok());
    }

    #[test]
    fn solana_transfer_not_rejected_by_method() {
        let mut fw = LiveFirewall::default();
        fw.rules.allowed_chain_ids = vec![501];
        fw.rules.allowed_dex_contracts = vec!["sol:addr".into()];
        let parsed = ParsedTx {
            chain: ChainType::Solana,
            to_address: "sol:addr".into(),
            value_units: 1_000_000,
            volume_units: Decimal::new(1, 0),
            destinations: vec![ParsedDestination {
                address: "sol:addr".into(),
                value_units: 1_000_000,
                kind: ParsedDestinationKind::Native,
            }],
            chain_id: 501,
            method: TxMethod::SolanaTransfer,
            summary: String::new(),
        };
        assert!(fw.validate_parsed_transaction(&parsed).is_ok());
    }

    #[test]
    fn safe_volume_add_detects_overflow() {
        let max = Decimal::MAX;
        let one = Decimal::ONE;
        assert!(safe_volume_add(max, one).is_err());
        let small = Decimal::from_str("123456789012345678").unwrap();
        assert!(safe_volume_add(small, one).is_ok());
    }

    #[test]
    fn solana_unsupported_method_rejected() {
        let mut fw = LiveFirewall::default();
        fw.rules.allowed_chain_ids = vec![501];
        fw.rules.allowed_dex_contracts = vec!["sol:addr".into()];
        let parsed = ParsedTx {
            chain: ChainType::Solana,
            to_address: "sol:addr".into(),
            value_units: 1_000_000,
            volume_units: Decimal::new(1, 0),
            destinations: vec![ParsedDestination {
                address: "sol:addr".into(),
                value_units: 1_000_000,
                kind: ParsedDestinationKind::Native,
            }],
            chain_id: 501,
            method: TxMethod::Unsupported("stake_deactivate".into()),
            summary: String::new(),
        };
        assert!(fw.validate_parsed_transaction(&parsed).is_err());
    }
}
