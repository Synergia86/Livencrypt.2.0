// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: aislamiento de proceso y endurecimiento de mitigaciones en Windows */

#![allow(unsafe_code)]

use std::os::raw::c_void;

type Bool = i32;

const PROCESS_DYNAMIC_CODE_POLICY: i32 = 2;
const PROCESS_SIGNATURE_POLICY: i32 = 8;
const PROHIBIT_DYNAMIC_CODE: u32 = 0x1;
const MICROSOFT_SIGNED_ONLY: u32 = 0x1;

#[repr(C)]
struct ProcessMitigationDynamicCodePolicy {
    flags: u32,
}

#[repr(C)]
struct ProcessMitigationBinarySignaturePolicy {
    flags: u32,
}

extern "system" {
    fn SetProcessMitigationPolicy(policy: i32, buffer: *mut c_void, size: usize) -> Bool;
}

/// Aplica políticas de mitigación herméticas al proceso actual: prohíbe la
/// generación de código dinámico en tiempo de ejecución y restringe la carga de
/// binarios a imágenes firmadas, reduciendo la superficie de inyección.
pub fn apply_process_mitigations() -> Result<(), String> {
    let mut dynamic_code = ProcessMitigationDynamicCodePolicy {
        flags: PROHIBIT_DYNAMIC_CODE,
    };
    let dynamic_rc = unsafe {
        SetProcessMitigationPolicy(
            PROCESS_DYNAMIC_CODE_POLICY,
            &mut dynamic_code as *mut _ as *mut c_void,
            std::mem::size_of::<ProcessMitigationDynamicCodePolicy>(),
        )
    };
    if dynamic_rc == 0 {
        return Err("no se pudo prohibir el codigo dinamico del proceso en Windows".into());
    }

    let mut signature = ProcessMitigationBinarySignaturePolicy {
        flags: MICROSOFT_SIGNED_ONLY,
    };
    let signature_rc = unsafe {
        SetProcessMitigationPolicy(
            PROCESS_SIGNATURE_POLICY,
            &mut signature as *mut _ as *mut c_void,
            std::mem::size_of::<ProcessMitigationBinarySignaturePolicy>(),
        )
    };
    if signature_rc == 0 {
        return Err("no se pudo restringir la carga de binarios firmados en Windows".into());
    }

    Ok(())
}
