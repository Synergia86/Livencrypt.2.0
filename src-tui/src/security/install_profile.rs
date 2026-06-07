// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Instalador persistente de reglas de seguridad y binarios en el host */

#![allow(clippy::should_implement_trait)]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum InstallProfile {
    Standard,
    Isolated,
    Expu,
    Pba,
}

impl InstallProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Isolated => "isolated",
            Self::Expu => "expu",
            Self::Pba => "pba",
        }
    }

    pub fn from_str(value: &str) -> Self {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized == "isolated" || normalized == "aislado" {
            Self::Isolated
        } else if normalized == "expu" {
            Self::Expu
        } else if normalized == "pba" || normalized == "preboot" || normalized == "pre-boot" {
            Self::Pba
        } else {
            Self::Standard
        }
    }
}

fn user_profile_path() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("secure")
        .join("install_profile.msgpack")
}

fn system_profile_path() -> PathBuf {
    PathBuf::from("/etc/livencrypt/install_profile.conf")
}

pub fn read_install_profile() -> InstallProfile {
    if let Ok(value) = fs::read_to_string(system_profile_path()) {
        return InstallProfile::from_str(&value);
    }

    fs::read(user_profile_path())
        .ok()
        .and_then(|bytes| rmp_serde::from_slice::<InstallProfile>(&bytes).ok())
        .unwrap_or(InstallProfile::Standard)
}

pub fn write_install_profile(profile: InstallProfile) -> Result<(), String> {
    let path = user_profile_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let bytes = rmp_serde::to_vec(&profile).map_err(|error| error.to_string())?;
    fs::write(path, bytes).map_err(|error| error.to_string())
}

pub fn installed_profile_label() -> String {
    read_install_profile().as_str().to_string()
}
