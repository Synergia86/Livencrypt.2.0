// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Generación e inyección dinámica del perfil de seguridad AppArmor del host */

use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const INSTALLED_PROFILE_PATH: &str = "/etc/apparmor.d/usr.bin.livencrypt-core";
const SYSTEM_PROFILE_SOURCE: &str = "/usr/share/livencrypt/apparmor/livencrypt-core";

#[derive(Clone, Debug, Serialize)]
pub struct AppArmorStatus {
    pub os_id: String,
    pub supported: bool,
    pub kernel_enabled: bool,
    pub parser_available: bool,
    pub profile_source: String,
    pub profile_installed: bool,
    pub profile_path: String,
    pub message: String,
}

fn os_release_value(key: &str) -> Option<String> {
    let content = fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name == key {
            return Some(value.trim_matches('"').to_ascii_lowercase());
        }
    }
    None
}

fn detect_os_id() -> String {
    let id = os_release_value("ID").unwrap_or_else(|| std::env::consts::OS.to_string());
    let like = os_release_value("ID_LIKE").unwrap_or_default();
    if like.is_empty() {
        id
    } else {
        format!("{}:{}", id, like)
    }
}

fn apparmor_supported_for_os(os_id: &str) -> bool {
    cfg!(target_os = "linux")
        && !os_id.contains("fedora")
        && !os_id.contains("rhel")
        && !os_id.contains("centos")
}

fn kernel_enabled() -> bool {
    PathBuf::from("/sys/module/apparmor").exists()
        || PathBuf::from("/sys/kernel/security/apparmor").exists()
}

fn command_available(name: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {} >/dev/null 2>&1", name)])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn profile_source_path() -> PathBuf {
    let system = PathBuf::from(SYSTEM_PROFILE_SOURCE);
    if system.exists() {
        return system;
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("packaging")
        .join("apparmor")
        .join("livencrypt-core")
}

fn run_direct(command: &str, args: &[String]) -> bool {
    Command::new(command)
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn run_privileged(command: &str, args: &[String]) -> Result<(), String> {
    if run_direct(command, args) {
        return Ok(());
    }

    if !command_available("pkexec") {
        return Err(format!(
            "Se requieren permisos de administrador para ejecutar '{}', pero pkexec no esta disponible.",
            command
        ));
    }

    let status = Command::new("pkexec")
        .arg(command)
        .args(args)
        .status()
        .map_err(|error| format!("No se pudo solicitar permisos con pkexec: {}", error))?;

    if status.success() {
        Ok(())
    } else {
        Err("Permiso de administrador denegado o comando AppArmor fallido.".into())
    }
}

pub fn apparmor_status() -> AppArmorStatus {
    let os_id = detect_os_id();
    let supported = apparmor_supported_for_os(&os_id);
    let kernel_enabled = kernel_enabled();
    let parser_available = command_available("apparmor_parser");
    let profile_source = profile_source_path();
    let profile_installed = PathBuf::from(INSTALLED_PROFILE_PATH).exists();

    let message = if !cfg!(target_os = "linux") {
        "AppArmor solo soportado en Linux.".to_string()
    } else if !supported {
        "Este sistema parece usar otra politica MAC; AppArmor no se activa automaticamente."
            .to_string()
    } else if !kernel_enabled {
        "Kernel AppArmor no detectado.".to_string()
    } else if !parser_available {
        "apparmor_parser no esta disponible.".to_string()
    } else if profile_installed {
        "Perfil AppArmor instalado.".to_string()
    } else {
        "Perfil AppArmor disponible para activar.".to_string()
    };

    AppArmorStatus {
        os_id,
        supported,
        kernel_enabled,
        parser_available,
        profile_source: profile_source.display().to_string(),
        profile_installed,
        profile_path: INSTALLED_PROFILE_PATH.to_string(),
        message,
    }
}

pub fn enable_apparmor_profile() -> Result<AppArmorStatus, String> {
    let status = apparmor_status();
    if !status.supported {
        return Err(status.message);
    }
    if !status.kernel_enabled {
        return Err("Kernel AppArmor no detectado.".into());
    }
    if !status.parser_available {
        return Err("apparmor_parser no esta disponible.".into());
    }

    let source = profile_source_path();
    if !source.exists() {
        return Err(format!(
            "No existe perfil AppArmor origen: {}",
            source.display()
        ));
    }

    run_privileged(
        "install",
        &[
            "-m".to_string(),
            "0644".to_string(),
            source.display().to_string(),
            INSTALLED_PROFILE_PATH.to_string(),
        ],
    )?;
    run_privileged(
        "apparmor_parser",
        &["-r".to_string(), INSTALLED_PROFILE_PATH.to_string()],
    )?;
    Ok(apparmor_status())
}

pub fn disable_apparmor_profile() -> Result<AppArmorStatus, String> {
    if PathBuf::from(INSTALLED_PROFILE_PATH).exists() && command_available("apparmor_parser") {
        let _ = run_privileged(
            "apparmor_parser",
            &["-R".to_string(), INSTALLED_PROFILE_PATH.to_string()],
        );
    }
    run_privileged(
        "rm",
        &["-f".to_string(), INSTALLED_PROFILE_PATH.to_string()],
    )?;
    Ok(apparmor_status())
}
