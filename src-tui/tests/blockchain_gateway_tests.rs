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

/// Construye un supervisor con un límite FIAT personalizado (0 = ilimitado), demostrando
/// que el límite fiat admite cualquier valor.
fn supervisor_with_fiat_limit(destination: String, fiat_limit: Decimal) -> GatewaySupervisor {
    let keymaster = UniversalKeymaster::new(
        [1, 2, 3, 4, 5],
        "frase maestra de prueba para gateway blockchain",
    )
    .expect("keymaster");
    let firewall = LiveFirewall::new(FirewallRules {
        max_daily_tx: 10,
        max_daily_volume_units: Decimal::from(10_000_000),
        max_daily_crypto_amount: Decimal::from(10_000_000),
        max_daily_fiat_value: fiat_limit,
        allowed_dex_contracts: vec![destination],
        allowed_cex_destinations: Vec::new(),
        ..FirewallRules::default()
    });
    GatewaySupervisor::new(keymaster, firewall)
}

fn supervisor_with_allowed(destination: String) -> GatewaySupervisor {
    // Sin límite fiat (0 = ilimitado): estos tests verifican el parseo de destino, no el fiat.
    supervisor_with_fiat_limit(destination, Decimal::ZERO)
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
            target_dex_cex_id: Some(format!("0x{}", hex::encode([0x11; 20]))),
            network: livencrypt_lib::crypto::blockchain::address::Network::Mainnet,
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
            network: livencrypt_lib::crypto::blockchain::address::Network::Mainnet,
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
            network: livencrypt_lib::crypto::blockchain::address::Network::Mainnet,
        }))
        .expect("response");

    let decoded: ExtensionResponse<()> = serde_json::from_slice(&response).expect("json response");
    match decoded {
        ExtensionResponse::Error(error) => assert!(error.contains("destino")),
        ExtensionResponse::Success(()) => panic!("destino real autorizado no debe firmarse"),
    }
}

#[test]
fn fiat_limit_is_customizable_to_any_value() {
    let destination = format!("0x{}", hex::encode([0x11; 20]));

    // Límite personalizado alto: una operación por debajo del límite se firma.
    let mut under = supervisor_with_fiat_limit(destination.clone(), Decimal::from(2_000_000));
    let response_under = under
        .run_loop_iteration(ExtensionRequest::SignTransaction(TransactionSignRequest {
            chain: ChainType::Ethereum,
            account_index: 0,
            address_index: 0,
            raw_tx_payload: ethereum_legacy_payload(0x11),
            value_usd: Decimal::from(1_500_000),
            target_dex_cex_id: Some(destination.clone()),
            network: livencrypt_lib::crypto::blockchain::address::Network::Mainnet,
        }))
        .expect("response");
    let decoded_under: ExtensionResponse<SignatureResponse> =
        serde_json::from_slice(&response_under).expect("json response");
    assert!(
        matches!(decoded_under, ExtensionResponse::Success(_)),
        "fiat por debajo de un limite personalizado alto debe firmarse"
    );

    // El mismo valor con un límite personalizado menor se rechaza.
    let mut over = supervisor_with_fiat_limit(destination.clone(), Decimal::from(1_000_000));
    let response_over = over
        .run_loop_iteration(ExtensionRequest::SignTransaction(TransactionSignRequest {
            chain: ChainType::Ethereum,
            account_index: 0,
            address_index: 0,
            raw_tx_payload: ethereum_legacy_payload(0x11),
            value_usd: Decimal::from(1_500_000),
            target_dex_cex_id: Some(destination.clone()),
            network: livencrypt_lib::crypto::blockchain::address::Network::Mainnet,
        }))
        .expect("response");
    let decoded_over: ExtensionResponse<()> =
        serde_json::from_slice(&response_over).expect("json response");
    match decoded_over {
        ExtensionResponse::Error(error) => assert!(error.contains("fiat")),
        ExtensionResponse::Success(()) => panic!("fiat sobre el limite personalizado debe rechazarse"),
    }

    // Límite 0 = ilimitado: cualquier valor se firma.
    let mut unlimited = supervisor_with_fiat_limit(destination.clone(), Decimal::ZERO);
    let response_unlimited = unlimited
        .run_loop_iteration(ExtensionRequest::SignTransaction(TransactionSignRequest {
            chain: ChainType::Ethereum,
            account_index: 0,
            address_index: 0,
            raw_tx_payload: ethereum_legacy_payload(0x11),
            value_usd: Decimal::from(9_999_999),
            target_dex_cex_id: Some(destination),
            network: livencrypt_lib::crypto::blockchain::address::Network::Mainnet,
        }))
        .expect("response");
    let decoded_unlimited: ExtensionResponse<SignatureResponse> =
        serde_json::from_slice(&response_unlimited).expect("json response");
    assert!(
        matches!(decoded_unlimited, ExtensionResponse::Success(_)),
        "fiat ilimitado (0) debe permitir cualquier valor"
    );
}
