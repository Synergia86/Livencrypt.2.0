// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: decodificador ABI minimo deny-by-default para previsualizacion */

use crate::crypto::blockchain::eth_types::{EthereumCallRisk, EthereumDecodedCall};

pub fn decode_call(contract: &str, data: &str) -> Result<EthereumDecodedCall, String> {
    let data = data.strip_prefix("0x").unwrap_or(data);
    if data.is_empty() {
        return Ok(EthereumDecodedCall {
            selector: "0x".into(),
            method: "native_transfer".into(),
            contract: contract.to_string(),
            spender: None,
            recipient: None,
            amount: None,
            risk: EthereumCallRisk::Low,
        });
    }
    if data.len() < 8 {
        return Err("calldata Ethereum demasiado corto".into());
    }

    let selector = format!("0x{}", &data[..8]);
    match selector.as_str() {
        "0xa9059cbb" => decode_erc20_transfer(contract, data),
        "0x095ea7b3" => decode_erc20_approve(contract, data),
        "0x23b872dd" => decode_erc20_transfer_from(contract, data),
        "0xa22cb465" => decode_set_approval_for_all(contract, data),
        other => Ok(EthereumDecodedCall {
            selector: other.to_string(),
            method: "unknown".into(),
            contract: contract.to_string(),
            spender: None,
            recipient: None,
            amount: None,
            risk: EthereumCallRisk::Critical,
        }),
    }
}

fn decode_erc20_transfer(contract: &str, data: &str) -> Result<EthereumDecodedCall, String> {
    Ok(EthereumDecodedCall {
        selector: "0xa9059cbb".into(),
        method: "erc20.transfer".into(),
        contract: contract.to_string(),
        spender: None,
        recipient: Some(word_address(data, 0)?),
        amount: Some(word_u256(data, 1)?),
        risk: EthereumCallRisk::Low,
    })
}

fn decode_erc20_approve(contract: &str, data: &str) -> Result<EthereumDecodedCall, String> {
    let amount = word_u256(data, 1)?;
    let risk = if is_unlimited(&amount) {
        EthereumCallRisk::Critical
    } else {
        EthereumCallRisk::High
    };
    Ok(EthereumDecodedCall {
        selector: "0x095ea7b3".into(),
        method: "erc20.approve".into(),
        contract: contract.to_string(),
        spender: Some(word_address(data, 0)?),
        recipient: None,
        amount: Some(amount),
        risk,
    })
}

fn decode_erc20_transfer_from(contract: &str, data: &str) -> Result<EthereumDecodedCall, String> {
    Ok(EthereumDecodedCall {
        selector: "0x23b872dd".into(),
        method: "erc20.transferFrom".into(),
        contract: contract.to_string(),
        spender: Some(word_address(data, 0)?),
        recipient: Some(word_address(data, 1)?),
        amount: Some(word_u256(data, 2)?),
        risk: EthereumCallRisk::High,
    })
}

fn decode_set_approval_for_all(contract: &str, data: &str) -> Result<EthereumDecodedCall, String> {
    Ok(EthereumDecodedCall {
        selector: "0xa22cb465".into(),
        method: "erc721.setApprovalForAll".into(),
        contract: contract.to_string(),
        spender: Some(word_address(data, 0)?),
        recipient: None,
        amount: Some(word_u256(data, 1)?),
        risk: EthereumCallRisk::Critical,
    })
}

fn word_address(data: &str, index: usize) -> Result<String, String> {
    let word = word(data, index)?;
    Ok(format!("0x{}", &word[24..64]))
}

fn word_u256(data: &str, index: usize) -> Result<String, String> {
    Ok(format!("0x{}", word(data, index)?))
}

fn word(data: &str, index: usize) -> Result<&str, String> {
    let start = 8 + index * 64;
    let end = start + 64;
    data.get(start..end)
        .ok_or_else(|| "calldata ABI incompleto".to_string())
}

fn is_unlimited(value: &str) -> bool {
    value.eq_ignore_ascii_case("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_selector_is_critical() {
        let decoded = decode_call(
            "0x2222222222222222222222222222222222222222",
            "0xdeadbeef0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("decode");
        assert_eq!(decoded.risk, EthereumCallRisk::Critical);
    }
}
