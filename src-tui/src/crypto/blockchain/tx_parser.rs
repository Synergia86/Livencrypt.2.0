// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: parser forense minimo de transacciones antes de firma */

use crate::crypto::blockchain::types::{ChainType, TxMethod};
use rust_decimal::Decimal;

#[derive(Clone, Debug, PartialEq)]
pub enum ParsedDestinationKind {
    Native,
    Erc20Contract,
    Erc20Receiver,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedDestination {
    pub address: String,
    pub value_units: u128,
    pub kind: ParsedDestinationKind,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedTx {
    pub chain: ChainType,
    pub to_address: String,
    pub value_units: u128,
    /// Volumen legacy calculado en la cadena de origen. No utilizado por el cortafuegos;
    /// usar `Firewall::effective_volume_units()` para cálculo de volumen diario.
    pub volume_units: Decimal,
    pub destinations: Vec<ParsedDestination>,
    pub chain_id: u64,
    pub method: TxMethod,
    pub summary: String,
}

pub fn parse_tx_payload(chain: &ChainType, raw_tx_payload: &[u8]) -> Result<ParsedTx, String> {
    match chain {
        ChainType::Ethereum => parse_ethereum_payload(raw_tx_payload),
        ChainType::Bitcoin => parse_bitcoin_payload(raw_tx_payload),
        ChainType::Solana => parse_solana_payload(raw_tx_payload),
        ChainType::Monero => Err("Monero requiere parser forense especifico no integrado".into()),
    }
}

fn parse_ethereum_payload(raw: &[u8]) -> Result<ParsedTx, String> {
    if raw.is_empty() {
        return Err("payload Ethereum vacio".into());
    }

    let (tx_type, fields) = if raw[0] == 0x02 {
        (Some(0x02), parse_rlp_list(&raw[1..])?)
    } else if raw[0] == 0x01 {
        (Some(0x01), parse_rlp_list(&raw[1..])?)
    } else {
        (None, parse_rlp_list(raw)?)
    };

    let (chain_id, to, value, data) = match tx_type {
        Some(0x02) => {
            if fields.len() < 9 {
                return Err("EIP-1559 incompleto".into());
            }
            (
                bytes_to_u64(fields[0])?,
                fields[5],
                bytes_to_u128(fields[6])?,
                fields[7],
            )
        }
        Some(0x01) => {
            if fields.len() < 8 {
                return Err("EIP-2930 incompleto".into());
            }
            (
                bytes_to_u64(fields[0])?,
                fields[4],
                bytes_to_u128(fields[5])?,
                fields[6],
            )
        }
        _ => {
            if fields.len() < 9 {
                return Err("transaccion Ethereum legacy incompleta".into());
            }
            let v = bytes_to_u64(fields[6])?;
            let chain_id = if v >= 35 {
                (v - 35) / 2
            } else {
                return Err("Ethereum legacy sin chain_id EIP-155".into());
            };
            (chain_id, fields[3], bytes_to_u128(fields[4])?, fields[5])
        }
    };

    if to.len() != 20 {
        return Err("Ethereum sin destino externo de 20 bytes".into());
    }
    let contract_or_to = format!("0x{}", hex::encode(to));
    let (to_address, value_units, method) =
        if data.starts_with(&[0xa9, 0x05, 0x9c, 0xbb]) && data.len() >= 68 {
            let token_receiver = format!("0x{}", hex::encode(&data[16..36]));
            let amount = bytes_to_u128_word(&data[36..68])?;
            (token_receiver.clone(), amount, TxMethod::EthErc20Transfer)
        } else if data.is_empty() {
            (contract_or_to.clone(), value, TxMethod::EthTransfer)
        } else {
            (
                contract_or_to.clone(),
                value,
                TxMethod::EthUnsupported(format!("0x{}", hex::encode(&data[..4]))),
            )
        };

    let destinations = if let TxMethod::EthErc20Transfer = method {
        let token_receiver = format!("0x{}", hex::encode(&data[16..36]));
        let amount = bytes_to_u128_word(&data[36..68])?;
        vec![
            ParsedDestination {
                address: contract_or_to.clone(),
                value_units: 0,
                kind: ParsedDestinationKind::Erc20Contract,
            },
            ParsedDestination {
                address: token_receiver,
                value_units: amount,
                kind: ParsedDestinationKind::Erc20Receiver,
            },
        ]
    } else {
        vec![ParsedDestination {
            address: contract_or_to.clone(),
            value_units: value,
            kind: ParsedDestinationKind::Native,
        }]
    };

    let summary = match &method {
        TxMethod::EthTransfer => {
            format!("transferencia_eth to={} value={}", to_address, value_units)
        }
        TxMethod::EthErc20Transfer => format!(
            "erc20_transfer contrato={} value={}",
            contract_or_to, value_units
        ),
        TxMethod::EthUnsupported(sel) => format!(
            "unsupported_method {} to={} value={}",
            sel, contract_or_to, value_units
        ),
        TxMethod::BtcRawTx => format!("bitcoin_raw_tx to={} value={}", to_address, value_units),
        TxMethod::SolanaTransfer => {
            format!("solana_transfer to={} value={}", to_address, value_units)
        }
        TxMethod::Unsupported(sel) => format!(
            "unsupported_chain_method {} to={} value={}",
            sel, to_address, value_units
        ),
    };

    Ok(ParsedTx {
        chain: ChainType::Ethereum,
        to_address,
        value_units,
        volume_units: Decimal::ZERO,
        destinations,
        chain_id,
        method,
        summary,
    })
}

fn parse_bitcoin_payload(raw: &[u8]) -> Result<ParsedTx, String> {
    let mut reader = ByteReader::new(raw);
    reader.take(4)?;
    let input_count = reader.read_varint()?;
    if input_count == 0 || input_count > 10_000 {
        return Err("Bitcoin inputs invalidos".into());
    }
    for _ in 0..input_count {
        reader.take(32)?;
        reader.take(4)?;
        let script_len = reader.read_varint()?;
        if script_len > 10_000 {
            return Err("script Bitcoin demasiado largo".into());
        }
        reader.take_usize(script_len)?;
        reader.take(4)?;
    }

    let output_count = reader.read_varint()?;
    if output_count == 0 || output_count > 50 {
        return Err("Bitcoin outputs invalidos (limite 50)".into());
    }

    let mut destinations = Vec::new();
    let mut total_value = 0u128;
    for output_index in 0..output_count {
        let value = reader.read_u64_le()? as u128;
        let script_len = reader.read_varint()?;
        if script_len > 10_000 {
            return Err("script Bitcoin demasiado largo".into());
        }
        let script = reader.take_usize(script_len)?;
        let address = bitcoin_script_destination(script).ok_or_else(|| {
            format!(
                "Bitcoin script tipo no soportado en output {}",
                output_index
            )
        })?;
        total_value = total_value.saturating_add(value);
        destinations.push(ParsedDestination {
            address,
            value_units: value,
            kind: ParsedDestinationKind::Native,
        });
    }
    reader.take(4)?;

    let to_address = destinations
        .first()
        .map(|destination| destination.address.clone())
        .ok_or_else(|| "Bitcoin sin outputs".to_string())?;
    let volume_units = native_units(ChainType::Bitcoin, total_value);
    let summary = format!(
        "Bitcoin outputs={} total_sats={} volume_units={:.8}",
        output_count, total_value, volume_units
    );
    Ok(ParsedTx {
        chain: ChainType::Bitcoin,
        to_address,
        value_units: total_value,
        volume_units,
        destinations,
        chain_id: 0,
        method: TxMethod::BtcRawTx,
        summary,
    })
}

fn parse_solana_payload(raw: &[u8]) -> Result<ParsedTx, String> {
    // Decodifica un mensaje de transaccion Solana serializado (legacy o v0) y extrae
    // una unica instruccion de transferencia nativa del System Program. Los bytes del
    // mensaje son exactamente los que firma ed25519, igual que el binario en BTC/ETH.
    const SYSTEM_TRANSFER_DISCRIMINANT: [u8; 4] = [2, 0, 0, 0];
    const SOLANA_LAMPORTS_LIMIT: u64 = 100_000_000_000_000;

    let first = *raw.first().ok_or_else(|| "mensaje Solana vacio".to_string())?;
    let mut reader = ByteReader::new(raw);

    if first & 0x80 != 0 {
        let version = first & 0x7f;
        if version != 0 {
            return Err(format!(
                "version de mensaje Solana no soportada: {}",
                version
            ));
        }
        reader.take(1)?;
    }

    reader.take(3)?; // cabecera: firmas requeridas y cuentas de solo lectura

    let account_count = reader.read_compact_u16()? as usize;
    if account_count == 0 || account_count > 256 {
        return Err("numero de cuentas Solana invalido".into());
    }
    let mut accounts = Vec::with_capacity(account_count);
    for _ in 0..account_count {
        let mut key = [0u8; 32];
        key.copy_from_slice(reader.take(32)?);
        accounts.push(key);
    }

    reader.take(32)?; // blockhash reciente

    let instruction_count = reader.read_compact_u16()? as usize;
    if instruction_count == 0 || instruction_count > 64 {
        return Err("numero de instrucciones Solana invalido".into());
    }

    let system_program = [0u8; 32];
    let mut transfer: Option<(usize, u64)> = None;
    for _ in 0..instruction_count {
        let program_id_index = reader.take(1)?[0] as usize;
        let account_index_count = reader.read_compact_u16()? as u64;
        let account_indexes = reader.take_usize(account_index_count)?.to_vec();
        let data_len = reader.read_compact_u16()? as u64;
        let data = reader.take_usize(data_len)?;

        let program_id = accounts
            .get(program_id_index)
            .ok_or_else(|| "indice de programa Solana fuera de rango".to_string())?;
        if *program_id != system_program {
            return Err(
                "instruccion Solana no soportada: solo transferencias del System Program".into(),
            );
        }
        if data.len() != 12 || data[0..4] != SYSTEM_TRANSFER_DISCRIMINANT {
            return Err("instruccion System Program no soportada (solo Transfer)".into());
        }
        if account_indexes.len() != 2 {
            return Err("transferencia Solana debe referenciar exactamente 2 cuentas".into());
        }
        if transfer.is_some() {
            return Err("solo se admite una transferencia Solana por mensaje".into());
        }
        let mut lamports_bytes = [0u8; 8];
        lamports_bytes.copy_from_slice(&data[4..12]);
        transfer = Some((account_indexes[1] as usize, u64::from_le_bytes(lamports_bytes)));
    }

    let (to_index, lamports) =
        transfer.ok_or_else(|| "mensaje Solana sin transferencia".to_string())?;
    if lamports > SOLANA_LAMPORTS_LIMIT {
        return Err("Solana lamports excesivos (limite 10^14)".into());
    }
    let recipient = accounts
        .get(to_index)
        .ok_or_else(|| "indice de destinatario Solana fuera de rango".to_string())?;
    let to_address = bs58::encode(recipient.as_slice()).into_string();
    let value_units = lamports as u128;
    let summary = format!("solana_transfer to={} lamports={}", to_address, lamports);

    Ok(ParsedTx {
        chain: ChainType::Solana,
        to_address: to_address.clone(),
        value_units,
        volume_units: native_units(ChainType::Solana, value_units),
        destinations: vec![ParsedDestination {
            address: to_address,
            value_units,
            kind: ParsedDestinationKind::Native,
        }],
        chain_id: 501,
        method: TxMethod::SolanaTransfer,
        summary,
    })
}

fn parse_rlp_list(input: &[u8]) -> Result<Vec<&[u8]>, String> {
    parse_rlp_list_inner(input, 0)
}

fn parse_rlp_list_inner(input: &[u8], depth: usize) -> Result<Vec<&[u8]>, String> {
    const MAX_RLP_DEPTH: usize = 16;
    if depth > MAX_RLP_DEPTH {
        return Err("RLP excede profundidad maxima de recursion".into());
    }
    let (payload, consumed) = parse_rlp_payload(input, true)?;
    if consumed != input.len() {
        return Err("RLP con bytes sobrantes".into());
    }
    let mut fields = Vec::new();
    let mut offset = 0usize;
    while offset < payload.len() {
        let (field, consumed) = parse_rlp_payload(&payload[offset..], false)?;
        fields.push(field);
        offset += consumed;
    }
    Ok(fields)
}

fn parse_rlp_payload(input: &[u8], expect_list: bool) -> Result<(&[u8], usize), String> {
    let Some(&prefix) = input.first() else {
        return Err("RLP vacio".into());
    };
    match prefix {
        0x00..=0x7f if !expect_list => Ok((&input[..1], 1)),
        0x80..=0xb7 if !expect_list => {
            let len = (prefix - 0x80) as usize;
            bounded_slice(input, 1, len).map(|value| (value, 1 + len))
        }
        0xb8..=0xbf if !expect_list => {
            let len_len = (prefix - 0xb7) as usize;
            let len = read_be_len(bounded_slice(input, 1, len_len)?)?;
            bounded_slice(input, 1 + len_len, len).map(|value| (value, 1 + len_len + len))
        }
        0xc0..=0xf7 if expect_list => {
            let len = (prefix - 0xc0) as usize;
            bounded_slice(input, 1, len).map(|value| (value, 1 + len))
        }
        0xf8..=0xff if expect_list => {
            let len_len = (prefix - 0xf7) as usize;
            let len = read_be_len(bounded_slice(input, 1, len_len)?)?;
            bounded_slice(input, 1 + len_len, len).map(|value| (value, 1 + len_len + len))
        }
        _ => Err("RLP tipo inesperado".into()),
    }
}

fn bounded_slice(input: &[u8], start: usize, len: usize) -> Result<&[u8], String> {
    input
        .get(start..start.saturating_add(len))
        .ok_or_else(|| "RLP truncado".to_string())
}

fn read_be_len(bytes: &[u8]) -> Result<usize, String> {
    if bytes.is_empty() || bytes.len() > std::mem::size_of::<usize>() {
        return Err("longitud RLP invalida".into());
    }
    let mut out = 0usize;
    for byte in bytes {
        out = (out << 8) | (*byte as usize);
    }
    Ok(out)
}

fn bytes_to_u64(bytes: &[u8]) -> Result<u64, String> {
    if bytes.len() > 8 {
        return Err("entero demasiado grande para u64".into());
    }
    let mut out = 0u64;
    for byte in bytes {
        out = (out << 8) | (*byte as u64);
    }
    Ok(out)
}

fn bytes_to_u128(bytes: &[u8]) -> Result<u128, String> {
    if bytes.len() > 16 {
        return Err("entero demasiado grande para u128".into());
    }
    let mut out = 0u128;
    for byte in bytes {
        out = (out << 8) | (*byte as u128);
    }
    Ok(out)
}

fn bytes_to_u128_word(bytes: &[u8]) -> Result<u128, String> {
    if bytes.len() > 32 {
        return Err("uint256 demasiado largo".into());
    }
    if bytes.len() > 16 && bytes[..bytes.len() - 16].iter().any(|byte| *byte != 0) {
        return Err(
            "valor de token excede 128 bits; no soportado (ERC-20 con mas de 128 bits)".into(),
        );
    }
    let start = bytes.len().saturating_sub(16);
    bytes_to_u128(&bytes[start..])
}

fn bitcoin_script_destination(script: &[u8]) -> Option<String> {
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        return Some(format!("btc:p2pkh:{}", hex::encode(&script[3..23])));
    }
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        return Some(format!("btc:p2sh:{}", hex::encode(&script[2..22])));
    }
    if script.len() == 22 && script[0] == 0x00 && script[1] == 0x14 {
        return Some(format!("btc:p2wpkh:{}", hex::encode(&script[2..22])));
    }
    if script.len() == 34 && script[0] == 0x00 && script[1] == 0x20 {
        return Some(format!("btc:p2wsh:{}", hex::encode(&script[2..34])));
    }
    None
}

pub fn native_units(chain: ChainType, value_units: u128) -> Decimal {
    match chain {
        ChainType::Ethereum => {
            Decimal::from(value_units) / Decimal::from(1_000_000_000_000_000_000u128)
        }
        ChainType::Bitcoin => Decimal::from(value_units) / Decimal::from(100_000_000u64),
        ChainType::Solana => Decimal::from(value_units) / Decimal::from(1_000_000_000u64),
        ChainType::Monero => Decimal::from(value_units),
    }
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "offset fuera de rango".to_string())?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "payload truncado".to_string())?;
        self.offset = end;
        Ok(slice)
    }

    fn take_usize(&mut self, len: u64) -> Result<&'a [u8], String> {
        let len = usize::try_from(len).map_err(|_| "longitud excesiva".to_string())?;
        self.take(len)
    }

    fn read_u64_le(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(array))
    }

    fn read_compact_u16(&mut self) -> Result<u16, String> {
        let mut value: u32 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.take(1)?[0];
            value |= ((byte & 0x7f) as u32) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 14 {
                return Err("compact-u16 Solana invalido".into());
            }
        }
        u16::try_from(value).map_err(|_| "compact-u16 Solana fuera de rango".to_string())
    }

    fn read_varint(&mut self) -> Result<u64, String> {
        let tag = self.take(1)?[0];
        match tag {
            0x00..=0xfc => Ok(tag as u64),
            0xfd => {
                let mut array = [0u8; 2];
                array.copy_from_slice(self.take(2)?);
                Ok(u16::from_le_bytes(array) as u64)
            }
            0xfe => {
                let mut array = [0u8; 4];
                array.copy_from_slice(self.take(4)?);
                Ok(u32::from_le_bytes(array) as u64)
            }
            0xff => self.read_u64_le(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::prelude::*;

    fn p2wpkh_script(byte: u8) -> Vec<u8> {
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&[byte; 20]);
        script
    }

    fn bitcoin_tx_with_outputs(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&[0u8; 32]);
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.push(0);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        tx.push(outputs.len() as u8);
        for (value, script) in outputs {
            tx.extend_from_slice(&value.to_le_bytes());
            tx.push(script.len() as u8);
            tx.extend_from_slice(script);
        }
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    }

    #[test]
    fn parses_ethereum_legacy_destination() {
        let mut tx = vec![0xdd, 0x80, 0x01, 0x01, 0x94];
        tx.extend_from_slice(&[0x11; 20]);
        tx.extend_from_slice(&[0x05, 0x80, 0x25, 0x80, 0x80]);
        let parsed = parse_tx_payload(&ChainType::Ethereum, &tx).unwrap();
        assert_eq!(parsed.to_address, format!("0x{}", hex::encode([0x11; 20])));
        assert_eq!(parsed.value_units, 5);
        assert_eq!(parsed.destinations.len(), 1);
        assert_eq!(parsed.chain_id, 1);
        assert!(parsed.volume_units < Decimal::from_str("0.00000001").unwrap());
    }

    #[test]
    fn parses_ethereum_erc20_transfer_contract_and_receiver() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&[0x22; 20]);
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&123u128.to_be_bytes());
        let mut tx = vec![0xf8, 0x62, 0x80, 0x01, 0x01, 0x94];
        tx.extend_from_slice(&[0x11; 20]);
        tx.push(0x80);
        tx.push(0xb8);
        tx.push(data.len() as u8);
        tx.extend_from_slice(&data);
        tx.extend_from_slice(&[0x25, 0x80, 0x80]);
        let parsed = parse_tx_payload(&ChainType::Ethereum, &tx).unwrap();
        assert_eq!(parsed.to_address, format!("0x{}", hex::encode([0x22; 20])));
        assert_eq!(parsed.value_units, 123);
        assert_eq!(parsed.destinations.len(), 2);
        assert!(matches!(parsed.method, TxMethod::EthErc20Transfer));
    }

    #[test]
    fn parses_all_bitcoin_outputs_and_total_volume() {
        let tx = bitcoin_tx_with_outputs(&[
            (50_000_000, p2wpkh_script(0x11)),
            (25_000_000, p2wpkh_script(0x22)),
        ]);
        let parsed = parse_tx_payload(&ChainType::Bitcoin, &tx).unwrap();
        assert_eq!(parsed.destinations.len(), 2);
        assert_eq!(parsed.value_units, 75_000_000);
        assert!(
            (parsed.volume_units - Decimal::from_str("0.75").unwrap()).abs()
                < Decimal::from_str("0.00000001").unwrap()
        );
    }

    #[test]
    fn rejects_unparseable_payload() {
        assert!(parse_tx_payload(&ChainType::Ethereum, b"no-rlp").is_err());
    }

    #[test]
    fn rejects_bitcoin_script_too_long() {
        let mut tx = vec![0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let large_len = 10001u64;
        tx.extend_from_slice(&large_len.to_le_bytes());
        assert!(parse_tx_payload(&ChainType::Bitcoin, &tx).is_err());
    }

    #[test]
    fn bitcoin_uses_btc_raw_tx_method() {
        let tx = bitcoin_tx_with_outputs(&[(50_000_000, p2wpkh_script(0x11))]);
        let parsed = parse_tx_payload(&ChainType::Bitcoin, &tx).unwrap();
        assert!(matches!(parsed.method, TxMethod::BtcRawTx));
    }

    fn solana_transfer_message(to: [u8; 32], lamports: u64) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&[1, 0, 1]); // cabecera del mensaje
        message.push(3); // tres cuentas: emisor, destino, System Program
        message.extend_from_slice(&[0x01; 32]); // emisor
        message.extend_from_slice(&to); // destino
        message.extend_from_slice(&[0x00; 32]); // System Program (todo ceros)
        message.extend_from_slice(&[0x09; 32]); // blockhash reciente
        message.push(1); // una instruccion
        message.push(2); // program_id_index -> System Program
        message.extend_from_slice(&[2, 0, 1]); // dos cuentas: emisor(0), destino(1)
        message.push(12); // longitud de los datos
        message.extend_from_slice(&[2, 0, 0, 0]); // discriminante Transfer
        message.extend_from_slice(&lamports.to_le_bytes());
        message
    }

    #[test]
    fn solana_parses_system_transfer() {
        let to = [0x2a; 32];
        let message = solana_transfer_message(to, 1_000_000);
        let parsed = parse_tx_payload(&ChainType::Solana, &message).unwrap();
        assert!(matches!(parsed.method, TxMethod::SolanaTransfer));
        assert_eq!(parsed.value_units, 1_000_000);
        assert_eq!(parsed.to_address, bs58::encode(to).into_string());
        assert_eq!(parsed.destinations.len(), 1);
        assert_eq!(parsed.chain_id, 501);
    }

    #[test]
    fn solana_rejects_non_system_instruction() {
        let mut message = solana_transfer_message([0x2a; 32], 1_000_000);
        // Corrompe la cuenta del System Program (offset cabecera+len+emisor+destino).
        let system_offset = 3 + 1 + 32 + 32;
        message[system_offset] = 0xff;
        assert!(parse_tx_payload(&ChainType::Solana, &message).is_err());
    }

    #[test]
    fn solana_rejects_lamports_above_limit() {
        let message = solana_transfer_message([0x2a; 32], 100_000_000_000_001);
        assert!(parse_tx_payload(&ChainType::Solana, &message).is_err());
    }

    #[test]
    fn bitcoin_rejects_unsupported_script_type() {
        let script = vec![0xff; 25];
        let tx = bitcoin_tx_with_outputs(&[(50_000_000, script)]);
        assert!(parse_tx_payload(&ChainType::Bitcoin, &tx).is_err());
    }
}
