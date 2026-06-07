// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Suite de pruebas para la pasarela blockchain y custodia */

use livencrypt_lib::crypto::blockchain::firewall::{FirewallRules, LiveFirewall};
use livencrypt_lib::crypto::blockchain::multi_curve::UniversalKeymaster;
use livencrypt_lib::crypto::blockchain::proxy::{ExtensionRequest, ExtensionResponse};
use livencrypt_lib::crypto::blockchain::supervisor::GatewaySupervisor;
use livencrypt_lib::crypto::blockchain::types::{
    ChainType, SignatureResponse, TransactionSignRequest,
};
use rust_decimal::Decimal;

fn ethereum_legacy_payload(to_byte: u8) -> Vec<u8> {
    let mut tx = vec![0xdd, 0x80, 0x01, 0x01, 0x94];
    tx.extend_from_slice(&[to_byte; 20]);
    tx.extend_from_slice(&[0x05, 0x80, 0x25, 0x80, 0x80]);
    tx
}

fn supervisor_with_allowed(destination: String) -> GatewaySupervisor {
    let keymaster = UniversalKeymaster::new(
        [1, 2, 3, 4, 5],
        "frase maestra de prueba para gateway blockchain",
    )
    .expect("keymaster");
    let firewall = LiveFirewall::new(FirewallRules {
        max_daily_tx: 10,
        max_daily_volume_units: Decimal::from(10_000),
        allowed_dex_contracts: vec![destination],
        allowed_cex_destinations: Vec::new(),
        ..FirewallRules::default()
    });
    GatewaySupervisor::new(keymaster, firewall)
}

#[test]
fn sign_transaction_allowed_only_after_parsing_real_destination() {
    let destination = format!("0x{}", hex::encode([0x11; 20]));
    let mut supervisor = supervisor_with_allowed(destination);

    let response = supervisor
        .run_loop_iteration(ExtensionRequest::SignTransaction(TransactionSignRequest {
            chain: ChainType::Ethereum,
            account_index: 0,
            address_index: 0,
            raw_tx_payload: ethereum_legacy_payload(0x11),
            value_usd: Decimal::from(999_999),
            target_dex_cex_id: Some("campo-externo-ignorado".to_string()),
        }))
        .expect("response");

    let decoded: ExtensionResponse<SignatureResponse> =
        serde_json::from_slice(&response).expect("json response");
    match decoded {
        ExtensionResponse::Success(signature) => {
            assert!(!signature.raw_signature.is_empty());
            assert_eq!(supervisor.firewall.tx_count_today, 1);
        }
        ExtensionResponse::Error(error) => panic!("firma autorizada rechazada: {error}"),
    }
}

#[test]
fn sign_transaction_rejects_unparseable_payload() {
    let destination = format!("0x{}", hex::encode([0x11; 20]));
    let mut supervisor = supervisor_with_allowed(destination);

    let response = supervisor
        .run_loop_iteration(ExtensionRequest::SignTransaction(TransactionSignRequest {
            chain: ChainType::Ethereum,
            account_index: 0,
            address_index: 0,
            raw_tx_payload: vec![1, 2, 3, 4],
            value_usd: Decimal::ONE,
            target_dex_cex_id: Some("externo".to_string()),
        }))
        .expect("response");

    let decoded: ExtensionResponse<()> = serde_json::from_slice(&response).expect("json response");
    match decoded {
        ExtensionResponse::Error(error) => assert!(error.contains("no se pudo parsear payload")),
        ExtensionResponse::Success(()) => panic!("payload no parseable no debe firmarse"),
    }
}

#[test]
fn sign_transaction_rejects_unauthorized_real_destination() {
    let allowed = format!("0x{}", hex::encode([0x22; 20]));
    let mut supervisor = supervisor_with_allowed(allowed);

    let response = supervisor
        .run_loop_iteration(ExtensionRequest::SignTransaction(TransactionSignRequest {
            chain: ChainType::Ethereum,
            account_index: 0,
            address_index: 0,
            raw_tx_payload: ethereum_legacy_payload(0x11),
            value_usd: Decimal::ONE,
            target_dex_cex_id: Some(format!("0x{}", hex::encode([0x22; 20]))),
        }))
        .expect("response");

    let decoded: ExtensionResponse<()> = serde_json::from_slice(&response).expect("json response");
    match decoded {
        ExtensionResponse::Error(error) => assert!(error.contains("destino")),
        ExtensionResponse::Success(()) => panic!("destino real autorizado no debe firmarse"),
    }
}
