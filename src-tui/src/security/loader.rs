// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Cargador del vault y descodificación de metadatos seguros */

#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
pub fn load_and_execute_in_ram(name: &str, binary_data: &mut [u8]) -> Result<i32, String> {
    use libc::{c_char, close, execve, fork, memfd_create};
    use std::ffi::CString;
    use std::ptr;
    use zeroize::Zeroize;

    let c_name = CString::new(name).map_err(|error| error.to_string())?;
    let fd = unsafe { memfd_create(c_name.as_ptr(), 0) };
    if fd < 0 {
        binary_data.zeroize();
        return Err("Fallo memfd_create.".into());
    }

    let write_result = write_all_fd(fd, binary_data);
    binary_data.zeroize();
    if let Err(error) = write_result {
        unsafe {
            close(fd);
        }
        return Err(error);
    }

    let pid = unsafe { fork() };
    if pid == 0 {
        if crate::security::sandbox::enter_restricted_child().is_err() {
            unsafe {
                close(fd);
            }
            std::process::exit(126);
        }
        let path = CString::new(format!("/proc/self/fd/{}", fd)).unwrap();
        let argv: [*const c_char; 2] = [path.as_ptr(), ptr::null()];
        let envp: [*const c_char; 1] = [ptr::null()];
        unsafe {
            execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        std::process::exit(127);
    }

    unsafe {
        close(fd);
    }

    if pid < 0 {
        return Err("Fallo fork.".into());
    }

    let _ = crate::security::audit::append_audit_event("LOADER_MEMFD_EXEC", name);
    Ok(pid)
}

#[cfg(target_os = "linux")]
fn write_all_fd(fd: i32, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let written =
            unsafe { libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };

        if written < 0 {
            return Err("No se pudo escribir binario completo en memfd.".to_string());
        }
        if written == 0 {
            return Err("Escritura parcial en memfd.".to_string());
        }

        bytes = &bytes[written as usize..];
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn load_and_execute_in_ram(_name: &str, binary_data: &mut [u8]) -> Result<i32, String> {
    use zeroize::Zeroize;
    binary_data.zeroize();
    Err("memfd_create solo esta disponible en Linux.".into())
}
