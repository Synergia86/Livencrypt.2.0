// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: utilidad CLI de verificación pre-arranque para ganchos de initramfs */

use livencrypt_lib::security::boot_shield::{self, BootKey};
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "uso: livencrypt-boot-shield <seal|unseal|verify> <clave-hex-32B> <entrada> [salida]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        return usage();
    }

    let command = args[1].as_str();
    let key = match BootKey::from_hex(&args[2]) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("error: {}", error);
            return ExitCode::FAILURE;
        }
    };
    let input = match std::fs::read(&args[3]) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("error leyendo {}: {}", args[3], error);
            return ExitCode::FAILURE;
        }
    };

    match command {
        "seal" => write_result(boot_shield::seal_config(&key, &input), args.get(4)),
        "unseal" => write_result(boot_shield::open_config(&key, &input), args.get(4)),
        "verify" => {
            if boot_shield::verify_config(&key, &input) {
                println!("ok");
                ExitCode::SUCCESS
            } else {
                eprintln!("verificacion fallida");
                ExitCode::FAILURE
            }
        }
        _ => usage(),
    }
}

fn write_result(result: Result<Vec<u8>, String>, output: Option<&String>) -> ExitCode {
    let Some(output) = output else {
        return usage();
    };
    match result {
        Ok(bytes) => match std::fs::write(output, bytes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error escribiendo {}: {}", output, error);
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("error: {}", error);
            ExitCode::FAILURE
        }
    }
}
