// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: aislamiento por namespaces del momento de firma criptográfica */

#![allow(unsafe_code)]

pub const SIGN_SANDBOX_ENV_FLAG: &str = "LIVENCRYPT_SIGN_SANDBOX";

pub fn sign_sandbox_requested() -> bool {
    std::env::var_os(SIGN_SANDBOX_ENV_FLAG).is_some()
}

/// Ejecuta `producer` en un proceso hijo aislado por namespaces de Linux
/// (red, montajes y PID) y devuelve sus bytes a través de un socketpair. El hijo
/// queda sin pila de red para impedir la exfiltración de claves; si no logra
/// aislarse, no firma (fail-closed). El padre conserva firewall y disyuntor.
#[cfg(target_os = "linux")]
pub fn run_isolated<F>(producer: F) -> Result<Vec<u8>, String>
where
    F: FnOnce() -> Result<Vec<u8>, String>,
{
    use std::io::{Read, Write};
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::os::unix::net::UnixStream;

    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err("no se pudo crear el socketpair del sandbox de firma".into());
    }
    let parent_fd = fds[0];
    let child_fd = fds[1];

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(parent_fd);
            libc::close(child_fd);
        }
        return Err("no se pudo bifurcar el proceso de firma".into());
    }

    if pid == 0 {
        unsafe {
            libc::close(parent_fd);
        }
        let isolated = isolate_child().is_ok();
        let mut stream = unsafe { UnixStream::from_raw_fd(child_fd) };
        let payload = if isolated {
            producer().unwrap_or_default()
        } else {
            Vec::new()
        };
        let length = (payload.len() as u32).to_le_bytes();
        let _ = stream.write_all(&length);
        let _ = stream.write_all(&payload);
        let _ = stream.flush();
        unsafe { libc::_exit(0) };
    }

    unsafe {
        libc::close(child_fd);
    }
    let mut stream = unsafe { UnixStream::from_raw_fd(parent_fd) };
    let mut length_buffer = [0u8; 4];
    let read_result = stream.read_exact(&mut length_buffer);

    let outcome = (|| {
        read_result.map_err(|_| "el firmante aislado no devolvio longitud".to_string())?;
        let length = u32::from_le_bytes(length_buffer) as usize;
        if length == 0 {
            return Err("el firmante aislado no produjo firma (aislamiento no disponible)".to_string());
        }
        let mut payload = vec![0u8; length];
        stream
            .read_exact(&mut payload)
            .map_err(|_| "el firmante aislado no devolvio la firma completa".to_string())?;
        Ok(payload)
    })();

    let mut status: libc::c_int = 0;
    unsafe {
        libc::waitpid(pid, &mut status as *mut libc::c_int, 0);
    }
    outcome
}

#[cfg(target_os = "linux")]
fn isolate_child() -> Result<(), String> {
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err("no se pudo aplicar PR_SET_NO_NEW_PRIVS".into());
        }
        if libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWPID) != 0 {
            return Err("no se pudieron crear los namespaces de firma".into());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn run_isolated<F>(_producer: F) -> Result<Vec<u8>, String>
where
    F: FnOnce() -> Result<Vec<u8>, String>,
{
    Err("el sandbox de firma por namespaces solo esta disponible en Linux".into())
}
