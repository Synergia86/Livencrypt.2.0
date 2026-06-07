// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Puente de comunicación entre la extensión Web del navegador y el Socket Unix de la TUI */

#![deny(unsafe_code)]

use livencrypt_lib::crypto::blockchain::proxy::{
    read_native_message, write_native_message, ExtensionResponse,
};
use std::io::Write;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

fn main() {
    if let Err(error) = run_bridge() {
        let response = ExtensionResponse::<()>::Error(error);
        if let Ok(payload) = serde_json::to_vec(&response) {
            let mut stdout = std::io::stdout();
            let _ = write_native_message(&mut stdout, &payload);
        }
    }
}

#[cfg(unix)]
fn run_bridge() -> Result<(), String> {
    let mut stdin = std::io::stdin();
    loop {
        let mut payload = match read_native_message(&mut stdin) {
            Ok(payload) => payload,
            Err(error) if error.contains("failed to fill whole buffer") => return Ok(()),
            Err(error) if error.contains("early eof") => return Ok(()),
            Err(error) => return Err(error),
        };

        let mut socket = UnixStream::connect(resolve_socket_path()?)
            .map_err(|error| format!("pasarela local no disponible: {}", error))?;
        write_native_message(&mut socket, &payload)?;
        payload.fill(0);

        let mut response = read_native_message(&mut socket)?;
        let mut stdout = std::io::stdout();
        write_native_message(&mut stdout, &response)?;
        stdout
            .flush()
            .map_err(|error| format!("error al vaciar stdout del bridge: {}", error))?;
        response.fill(0);
    }
}

#[cfg(not(unix))]
fn run_bridge() -> Result<(), String> {
    Err("livencrypt-bridge requiere socket Unix y solo esta disponible en sistemas Unix".into())
}

#[cfg(unix)]
fn resolve_socket_path() -> Result<std::path::PathBuf, String> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| "XDG_RUNTIME_DIR no definido; bridge no usara /tmp.".to_string())?;

    Ok(std::path::PathBuf::from(runtime_dir)
        .join("livencrypt")
        .join("livencrypt.sock"))
}
