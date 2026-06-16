// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: host de mensajeria nativa seguro para extension web stateless */

use crate::crypto::blockchain::eth_types::EthereumPrepareTransactionRequest;
use crate::crypto::blockchain::types::{
    BroadcastTransactionRequest, KeyDerivationRequest, TransactionSignRequest, Web3AccountRequest,
    Web3EstimateFeeRequest, Web3ReadBalanceRequest, Web3ReadNonceRequest,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use zeroize::Zeroize;

const MAX_NATIVE_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum ExtensionRequest {
    Web3Status,
    DeriveKey(KeyDerivationRequest),
    Web3Account(Web3AccountRequest),
    Web3ReadBalance(Web3ReadBalanceRequest),
    Web3ReadNonce(Web3ReadNonceRequest),
    Web3EstimateFee(Web3EstimateFeeRequest),
    EthereumPrepareTransaction(EthereumPrepareTransactionRequest),
    EthereumSignTransaction(EthereumPrepareTransactionRequest),
    SignTransaction(TransactionSignRequest),
    BroadcastTransaction(BroadcastTransactionRequest),
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum ExtensionResponse<T> {
    Success(T),
    Error(String),
}

pub struct NativeProxyChannel;

impl NativeProxyChannel {
    pub fn read_next_request() -> Result<ExtensionRequest, String> {
        let mut length_buffer = [0u8; 4];
        io::stdin()
            .read_exact(&mut length_buffer)
            .map_err(|error| format!("error al leer longitud del mensaje: {}", error))?;

        let message_length = u32::from_le_bytes(length_buffer) as usize;
        if message_length > MAX_NATIVE_MESSAGE_BYTES {
            return Err("longitud de mensaje excede el limite de seguridad de 1MB".to_string());
        }

        let mut json_buffer = vec![0u8; message_length];
        io::stdin()
            .read_exact(&mut json_buffer)
            .map_err(|error| format!("error al leer cuerpo del mensaje: {}", error))?;

        let request = serde_json::from_slice(&json_buffer)
            .map_err(|error| format!("error de deserializacion estructurada: {}", error))?;

        json_buffer.zeroize();
        Ok(request)
    }

    pub fn write_response<T: Serialize>(response: &ExtensionResponse<T>) -> Result<(), String> {
        let json_bytes = serde_json::to_vec(response)
            .map_err(|error| format!("error de serializacion de respuesta: {}", error))?;
        write_stdout_native_message(&json_bytes)
    }
}

pub fn read_native_message<R: Read>(reader: &mut R) -> Result<Vec<u8>, String> {
    let mut length_buffer = [0u8; 4];
    reader
        .read_exact(&mut length_buffer)
        .map_err(|error| format!("error al leer longitud del mensaje: {}", error))?;

    let message_length = u32::from_le_bytes(length_buffer) as usize;
    if message_length > MAX_NATIVE_MESSAGE_BYTES {
        return Err("longitud de mensaje excede el limite de seguridad de 1MB".to_string());
    }

    let mut payload = vec![0u8; message_length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| format!("error al leer cuerpo del mensaje: {}", error))?;
    Ok(payload)
}

pub fn write_native_message<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_NATIVE_MESSAGE_BYTES {
        return Err("respuesta excede el limite de seguridad de 1MB".to_string());
    }

    let length_prefix = (payload.len() as u32).to_le_bytes();
    writer
        .write_all(&length_prefix)
        .map_err(|error| format!("error al escribir prefijo de longitud: {}", error))?;
    writer
        .write_all(payload)
        .map_err(|error| format!("error al escribir cuerpo de la respuesta: {}", error))?;
    writer
        .flush()
        .map_err(|error| format!("error al vaciar el canal de salida: {}", error))
}

fn write_stdout_native_message(payload: &[u8]) -> Result<(), String> {
    let mut stdout = io::stdout();
    write_native_message(&mut stdout, payload)
}
