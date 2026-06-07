// SPDX-License-Identifier: GPL-3.0-or-later

pub mod network_profile;
pub mod process_hardening;
pub mod vault;

use crate::templates::TemplateData;
use std::collections::HashMap;

pub use network_profile::{get_network_profile, set_network_profile, toggle_network_safely};
pub use process_hardening::{initialize_process_hardening, process_hardening_status};
pub use vault::{
    boot_shield_destructive_panic, boot_shield_disable, boot_shield_enable,
    boot_shield_factory_reset, boot_shield_hardened_lock, boot_shield_lock, boot_shield_status,
    boot_shield_unlock, BootShieldStatus,
};

pub fn vault_is_configured() -> bool {
    vault::vault_is_configured()
}

pub fn try_load_unlocked_templates() -> Result<Option<HashMap<String, TemplateData>>, String> {
    vault::try_load_unlocked_templates()
}

pub fn save_template_to_unlocked_vault(name: String, data: TemplateData) -> Result<bool, String> {
    vault::save_template_to_unlocked_vault(name, data)
}

pub fn delete_template_from_unlocked_vault(name: &str) -> Result<bool, String> {
    vault::delete_template_from_unlocked_vault(name)
}
