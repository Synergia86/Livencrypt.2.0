// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Gobernanza de aislamiento de la pila de red local */

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const CONFIRM_REAL_NETWORK_MODE: &str = "ENTENDIDO";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkProfile {
    #[default]
    Mock,
    Manual,
    DropDefaultRoute,
    NmcliOff,
}

impl NetworkProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Manual => "manual",
            Self::DropDefaultRoute => "drop-default-route",
            Self::NmcliOff => "nmcli-off",
        }
    }

    fn from_input(value: &str) -> Result<Self, String> {
        match value.trim() {
            "mock" => Ok(Self::Mock),
            "manual" => Ok(Self::Manual),
            "drop-default-route" => Ok(Self::DropDefaultRoute),
            "nmcli-off" => Ok(Self::NmcliOff),
            other => Err(format!("Perfil de red no permitido: {}", other)),
        }
    }
}

fn secure_dir() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("secure")
}

fn profile_path() -> PathBuf {
    secure_dir().join("network_profile.conf")
}

fn default_routes_backup_path() -> PathBuf {
    secure_dir().join("default_routes.backup")
}

pub fn load_network_profile_value() -> NetworkProfile {
    let Ok(value) = fs::read_to_string(profile_path()) else {
        return NetworkProfile::default();
    };

    NetworkProfile::from_input(&value).unwrap_or_default()
}

fn save_network_profile_value(profile: &NetworkProfile) -> Result<(), String> {
    fs::create_dir_all(secure_dir()).map_err(|error| error.to_string())?;
    fs::write(profile_path(), profile.as_str()).map_err(|error| error.to_string())
}

fn command_available(name: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {} >/dev/null 2>&1", name)])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn require_linux_tool(name: &str) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err(format!(
            "La funcion de red '{}' solo esta soportada en Linux.",
            name
        ));
    }
    if !command_available(name) {
        return Err(format!("Herramienta de sistema no disponible: {}", name));
    }
    Ok(())
}

fn run_pkexec(args: &[String]) -> Result<(), String> {
    require_linux_tool("pkexec")?;
    let status = Command::new("pkexec")
        .args(args)
        .status()
        .map_err(|error| {
            format!(
                "No se pudo solicitar permisos de administrador con pkexec: {}",
                error
            )
        })?;

    if !status.success() {
        return Err("Permiso de administrador denegado o comando de red fallido.".into());
    }

    Ok(())
}

fn current_default_routes() -> Result<Vec<String>, String> {
    require_linux_tool("ip")?;
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|error| format!("No se pudieron leer las rutas por defecto: {}", error))?;

    if !output.status.success() {
        return Err("No se pudieron consultar las rutas por defecto.".into());
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("default"))
        .map(str::to_string)
        .collect())
}

fn backup_default_routes(routes: &[String]) -> Result<(), String> {
    fs::create_dir_all(secure_dir()).map_err(|error| error.to_string())?;
    fs::write(default_routes_backup_path(), routes.join("\n"))
        .map_err(|error| format!("No se pudo crear backup de rutas: {}", error))
}

fn route_command(action: &str, route_line: &str) -> Vec<String> {
    let mut args = vec!["ip".to_string(), "route".to_string(), action.to_string()];
    args.extend(route_line.split_whitespace().map(str::to_string));
    args
}

pub fn get_network_profile() -> Result<String, String> {
    Ok(load_network_profile_value().as_str().to_string())
}

pub fn set_network_profile(
    profile: String,
    confirmation: Option<String>,
) -> Result<String, String> {
    let profile = NetworkProfile::from_input(&profile)?;
    if matches!(
        profile,
        NetworkProfile::DropDefaultRoute | NetworkProfile::NmcliOff
    ) {
        let confirmed = confirmation
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| value == CONFIRM_REAL_NETWORK_MODE);
        if !confirmed {
            return Err(format!(
                "Para perfiles reales confirme exactamente: {}",
                CONFIRM_REAL_NETWORK_MODE
            ));
        }
    }

    save_network_profile_value(&profile)?;
    let _ = crate::security::vault::update_unlocked_network_profile(profile.as_str());
    Ok(profile.as_str().to_string())
}

pub fn selected_network_profile_label() -> String {
    load_network_profile_value().as_str().to_string()
}

pub fn toggle_network_safely(disable: bool) -> Result<bool, String> {
    match load_network_profile_value() {
        NetworkProfile::Mock => Ok(!disable),
        NetworkProfile::Manual => Err(
            "Perfil de red manual activo: cambie la red fuera de Livencrypt segun su entorno."
                .into(),
        ),
        NetworkProfile::DropDefaultRoute => toggle_default_route(disable),
        NetworkProfile::NmcliOff => toggle_nmcli(disable),
    }
}

fn toggle_default_route(disable: bool) -> Result<bool, String> {
    require_linux_tool("ip")?;
    if disable {
        let routes = current_default_routes()?;
        backup_default_routes(&routes)?;

        for route in routes {
            run_pkexec(&route_command("del", &route))?;
        }
        return Ok(false);
    }

    let backup = fs::read_to_string(default_routes_backup_path())
        .map_err(|_| "No existe backup de rutas por defecto para restaurar.".to_string())?;
    let routes = backup
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("default"))
        .collect::<Vec<_>>();

    if routes.is_empty() {
        return Ok(true);
    }

    for route in routes {
        run_pkexec(&route_command("add", route))?;
    }
    Ok(true)
}

fn toggle_nmcli(disable: bool) -> Result<bool, String> {
    require_linux_tool("nmcli")?;
    let arg = if disable { "off" } else { "on" };
    run_pkexec(&[
        "nmcli".to_string(),
        "networking".to_string(),
        arg.to_string(),
    ])?;

    Ok(!disable)
}
