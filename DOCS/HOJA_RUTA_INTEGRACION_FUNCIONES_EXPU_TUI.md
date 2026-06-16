# Hoja de ruta de integracion de expu Livencrypt 2.0 TUI

## 1. Objetivo

Esta hoja de ruta define lo que falta por integrar en Livencrypt 2.0 tras la migracion a Rust-TUI. El objetivo es convertir Livencrypt en una herramienta de seguridad avanzada para proteccion de documentos criticos, uso de expu y equipos aislados.

La instalacion `.deb` ya solicita permisos de administrador. Por tanto, las funciones que requieren privilegios deben configurarse durante `postinstall`, segun el sistema operativo detectado, para que el usuario no tenga que introducir contrasena de administrador en cada ejecucion.

Principio operativo:

```text
instalacion con root -> configuracion del sistema -> ejecucion diaria sin root
```

Queda prohibido depender de permisos elevados en tiempo de uso normal salvo para funciones expresamente destructivas o administrativas.

## 2. Estado actual del codigo

### Ya integrado

```text
src-tui/src/main.rs
  TUI Ratatui
  Boot Shield unlock
  dashboard basico
  monitor de sistema
  teclado virtual barajado
  glifo de integridad . / ·
  banner de hardening degradado

src-tui/src/security/process_hardening.rs
  core dumps OFF
  dumpable OFF
  mlockall best-effort/real
  hash SHA-256 del binario
  deteccion LD_PRELOAD/root

src-tui/src/security/vault.rs
  vault cifrado
  Argon2id
  XChaCha20-Poly1305
  capa interna Livencrypt
  doble credencial
  auto-wipe por intentos fallidos
  clave de coaccion
  vault v4 con last_audit_anchor
  modo espejismo basico
  contenedores decoy basicos

src-tui/src/security/audit.rs
  AuditEntry
  cadena hash SHA-256
  tombstone log
  absorcion de tombstones tras desbloqueo valido

src-tui/scripts/postinstall.sh
  CAP_IPC_LOCK
  hash esperado en /etc/livencrypt/expected.sha256
  aviso de memlock bajo
```

### Pendiente principal

```text
1. configuracion completa por SO en postinstall
2. perfiles de expu de instalacion
3. recovery Ed25519
4. updates/staging VFS con firma Ed25519
5. loader fileless con memfd_create
6. sandbox con namespaces/seccomp/cgroups
7. PBA/initramfs
8. TUI de expu multicapa
9. auditoria reforzada con MAC derivada del vault
10. modo espejismo completo
11. integracion opcional eBPF/IA local
```

## 3. Fase 1: instalacion de expu por sistema operativo

### Objetivo

Detectar el sistema operativo durante instalacion y configurar solo las funciones compatibles:

```text
Linux Debian/Ubuntu/Mint:
  setcap CAP_IPC_LOCK
  hash esperado del binario
  limits.d memlock
  sysctl recomendado
  perfil AppArmor opcional
  hook initramfs opcional

Fedora/RHEL:
  setcap CAP_IPC_LOCK
  SELinux aviso/configuracion pendiente
  systemd tmpfiles/sysusers opcional

Arch:
  setcap CAP_IPC_LOCK
  pacman hook opcional

Otros Linux:
  aplicar hardening disponible
  emitir avisos claros

Windows/macOS:
  no aplicar funciones Linux
  mostrar no soportado para mlockall/seccomp/namespaces
```

### Archivos implicados

```text
src-tui/scripts/postinstall.sh
src-tui/scripts/postremove.sh
src-tui/scripts/build-deb.sh
src-tui/src/security/process_hardening.rs
```

### Codigo a integrar en `postinstall.sh`

```sh
detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "${ID:-unknown}:${ID_LIKE:-}"
  else
    uname -s
  fi
}

configure_linux_capabilities() {
  binary_path="/usr/bin/livencrypt-core"

  if command -v setcap >/dev/null 2>&1; then
    setcap cap_ipc_lock=ep "$binary_path" || {
      echo "Livencrypt: no se pudo aplicar CAP_IPC_LOCK." >&2
      echo "Revise si la particion esta montada con nosuid o si libcap2-bin falta." >&2
      exit 1
    }
  else
    echo "Livencrypt: setcap no disponible." >&2
    exit 1
  fi
}

configure_memlock_limits() {
  install -d -m 0755 /etc/security/limits.d
  cat > /etc/security/limits.d/99-livencrypt.conf <<EOF
* soft memlock unlimited
* hard memlock unlimited
root soft memlock unlimited
root hard memlock unlimited
EOF
}

configure_expected_hash() {
  binary_path="/usr/bin/livencrypt-core"
  install -d -m 0755 /etc/livencrypt
  sha256sum "$binary_path" | awk '{print $1}' > /etc/livencrypt/expected.sha256
  chmod 0644 /etc/livencrypt/expected.sha256
}

case "$(detect_os)" in
  *debian*|*ubuntu*|*linuxmint*|debian:*|ubuntu:*|linuxmint:*)
    configure_linux_capabilities
    configure_memlock_limits
    configure_expected_hash
    ;;
  *fedora*|*rhel*|*centos*)
    configure_linux_capabilities
    configure_expected_hash
    echo "Livencrypt: SELinux detectado; perfil especifico pendiente."
    ;;
  Linux|linux:*|*:*)
    configure_linux_capabilities
    configure_expected_hash
    ;;
  *)
    echo "Livencrypt: SO no soportado para hardening Linux avanzado."
    ;;
esac
```

### Criterio de aceptacion

```text
livencrypt-core --hardening-check
  CORE DUMPS: OFF
  DUMPABLE: OFF
  MLOCKALL: OK
  INTEGRIDAD: OK
```

## 4. Fase 2: perfiles de expu de seguridad

### Objetivo

No todos los equipos deben recibir el mismo nivel de integracion. Se deben definir perfiles:

```text
standard:
  hardening proceso
  vault
  auditoria

isolated:
  hardening proceso
  vault
  auditoria
  red manual/aislada
  sin actualizaciones online

expu:
  hardening proceso
  vault
  auditoria
  sandbox
  recovery Ed25519
  staging updates
  AppArmor/seccomp

pba:
  expu
  initramfs hook
  binario estatico
```

### Archivos implicados

```text
src-tui/src/security/install_profile.rs   NUEVO
src-tui/src/security/mod.rs
src-tui/scripts/postinstall.sh
src-tui/src/main.rs
```

### Codigo a integrar

```rust
// src-tui/src/security/install_profile.rs
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum InstallProfile {
    Standard,
    Isolated,
    ExperiencedUser,
    Pba,
}

fn profile_path() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("secure")
        .join("install_profile.msgpack")
}

pub fn read_install_profile() -> InstallProfile {
    fs::read(profile_path())
        .ok()
        .and_then(|bytes| rmp_serde::from_slice::<InstallProfile>(&bytes).ok())
        .unwrap_or(InstallProfile::Standard)
}

pub fn write_install_profile(profile: InstallProfile) -> Result<(), String> {
    let path = profile_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let bytes = rmp_serde::to_vec(&profile).map_err(|error| error.to_string())?;
    fs::write(path, bytes).map_err(|error| error.to_string())
}
```

## 5. Fase 3: recuperacion Ed25519

### Objetivo

Permitir reparar la confianza del vault si la cadena de auditoria se rompe, sin restaurar un vault completo.

Uso previsto:

```text
1. equipo comprometido
2. usuario apaga
3. extrae vault
4. formatea/reinstala equipo
5. restaura vault
6. aplica archivo .lvc_recovery firmado
7. se actualiza last_audit_anchor
```

### Archivos implicados

```text
src-tui/Cargo.toml
src-tui/src/security/recovery.rs   NUEVO
src-tui/src/security/mod.rs
src-tui/src/security/vault.rs
src-tui/src/main.rs
```

### Dependencias

```toml
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
```

### Codigo a integrar

```rust
// src-tui/src/security/recovery.rs
// SPDX-License-Identifier: GPL-3.0-or-later

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryPayload {
    pub version: u32,
    pub timestamp_unix: u64,
    pub vault_id: Vec<u8>,
    pub anchor_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

fn signed_recovery_bytes(payload: &RecoveryPayload) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"LIVENCRYPT-RECOVERY-V1|");
    bytes.extend_from_slice(&payload.version.to_le_bytes());
    bytes.extend_from_slice(&payload.timestamp_unix.to_le_bytes());
    bytes.extend_from_slice(&payload.vault_id);
    bytes.extend_from_slice(&payload.anchor_hash);
    bytes
}

pub fn verify_recovery_file(
    path: &Path,
    public_key_bytes: &[u8; 32],
) -> Result<RecoveryPayload, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let payload: RecoveryPayload =
        rmp_serde::from_slice(&bytes).map_err(|error| error.to_string())?;

    let public_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|_| "Clave publica de recuperacion invalida.".to_string())?;
    let signature = Signature::from_slice(&payload.signature)
        .map_err(|_| "Firma de recuperacion invalida.".to_string())?;

    public_key
        .verify(&signed_recovery_bytes(&payload), &signature)
        .map_err(|_| "Archivo de recuperacion no autentico.".to_string())?;

    Ok(payload)
}
```

### Funcion a integrar en `vault.rs`

```rust
pub fn apply_emergency_anchor_update(new_anchor: Vec<u8>) -> Result<(), String> {
    let mut runtime = lock_runtime();
    let payload = runtime
        .payload
        .clone()
        .ok_or_else(|| "Vault bloqueado.".to_string())?;
    let material = runtime
        .material
        .as_ref()
        .ok_or_else(|| "Material Boot Shield no disponible.".to_string())?;
    let boot_template_name = runtime
        .boot_template_name
        .clone()
        .ok_or_else(|| "Plantilla Boot Shield no disponible.".to_string())?;
    let boot_template = runtime
        .boot_template
        .clone()
        .ok_or_else(|| "Plantilla Boot Shield no disponible.".to_string())?;

    let mut header = runtime
        .header
        .clone()
        .ok_or_else(|| "Cabecera Boot Shield no disponible.".to_string())?;

    header.last_audit_anchor = new_anchor;
    header.vault_counter = header.vault_counter.saturating_add(1);

    let envelope = encrypt_payload(
        &payload,
        material,
        header,
        &boot_template_name,
        &boot_template,
    )?;

    runtime.header = Some(envelope.header.clone());
    write_envelope(&envelope)?;
    crate::security::audit::append_audit_event("RECOVERY_APPLIED", "anchor_updated")?;
    Ok(())
}
```

## 6. Fase 4: staging VFS y actualizaciones firmadas

### Objetivo

Gestionar actualizaciones o paquetes avanzados sin ejecutar contenido no verificado.

Flujo:

```text
1. paquete .lvc_upd llega al equipo
2. se copia a staging
3. Livencrypt lee manifiesto
4. verifica Ed25519
5. muestra metadatos en TUI
6. usuario autoriza con Boot Shield desbloqueado
7. se realiza handover cifrado
8. se borra staging con overwrite+sync
```

### Archivos implicados

```text
src-tui/src/security/updates.rs   NUEVO
src-tui/src/security/recovery.rs
src-tui/src/security/vault.rs
src-tui/src/security/audit.rs
src-tui/src/main.rs
```

### Codigo a integrar

```rust
// src-tui/src/security/updates.rs
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub created_at_unix: u64,
    pub changelog: String,
    pub payload_sha256: String,
    pub signature: Vec<u8>,
}

fn staging_dir() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("staging")
}

pub fn inspect_pending_update() -> Result<Option<UpdateManifest>, String> {
    let path = staging_dir().join("update.manifest");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let manifest: UpdateManifest =
        rmp_serde::from_slice(&bytes).map_err(|error| error.to_string())?;
    Ok(Some(manifest))
}

pub fn verify_payload_hash(manifest: &UpdateManifest) -> Result<bool, String> {
    let payload_path = staging_dir().join("shadow_payload.bin");
    let payload = fs::read(payload_path).map_err(|error| error.to_string())?;
    let digest = Sha256::digest(&payload);
    Ok(hex::encode(digest) == manifest.payload_sha256)
}

pub fn clear_staging() -> Result<(), String> {
    let dir = staging_dir();
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&dir).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_file() {
            crate::security::vault::secure_delete_public_file(&path)?;
        }
    }
    fs::remove_dir_all(dir).map_err(|error| error.to_string())
}
```

### Funcion publica necesaria en `vault.rs`

```rust
pub fn secure_delete_public_file(path: &std::path::Path) -> Result<(), String> {
    secure_overwrite_and_remove_file(path)
}
```

## 7. Fase 5: cargador fileless con `memfd_create`

### Objetivo

Ejecutar binarios externos descifrados sin escribirlos en disco.

Importante:

```text
solo Linux
solo perfil expu/pba
solo despues de Boot Shield desbloqueado
solo binarios de confianza o firmados
debe ir unido a sandbox
```

### Archivos implicados

```text
src-tui/src/security/loader.rs   NUEVO
src-tui/src/security/sandbox.rs  NUEVO
src-tui/src/security/mod.rs
src-tui/src/main.rs
src-tui/Cargo.toml
```

### Codigo a integrar

```rust
// src-tui/src/security/loader.rs
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(target_os = "linux")]
pub fn load_and_execute_in_ram(name: &str, binary_data: &mut [u8]) -> Result<i32, String> {
    use libc::{c_char, execve, fork, memfd_create, write};
    use std::ffi::CString;
    use std::ptr;
    use zeroize::Zeroize;

    let c_name = CString::new(name).map_err(|error| error.to_string())?;
    let fd = unsafe { memfd_create(c_name.as_ptr(), 0) };
    if fd < 0 {
        binary_data.zeroize();
        return Err("Fallo memfd_create.".into());
    }

    let written = unsafe {
        write(
            fd,
            binary_data.as_ptr() as *const _,
            binary_data.len(),
        )
    };
    binary_data.zeroize();

    if written < 0 {
        return Err("No se pudo escribir binario en memfd.".into());
    }

    let pid = unsafe { fork() };
    if pid == 0 {
        let path = CString::new(format!("/proc/self/fd/{}", fd)).unwrap();
        let argv: [*const c_char; 2] = [path.as_ptr(), ptr::null()];
        let envp: [*const c_char; 1] = [ptr::null()];
        unsafe { execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        std::process::exit(127);
    }

    if pid < 0 {
        return Err("Fallo fork.".into());
    }

    Ok(pid)
}

#[cfg(not(target_os = "linux"))]
pub fn load_and_execute_in_ram(_name: &str, binary_data: &mut [u8]) -> Result<i32, String> {
    use zeroize::Zeroize;
    binary_data.zeroize();
    Err("memfd_create solo esta disponible en Linux.".into())
}
```

## 8. Fase 6: sandbox de expu

### Objetivo

Aislar el proceso ejecutado desde RAM para impedir:

```text
exfiltracion por red
lectura del host
escritura fuera de tmpfs
ptrace/debug
mount
fork bomb
agotamiento de RAM/CPU
```

### Archivos implicados

```text
src-tui/src/security/sandbox.rs   NUEVO
src-tui/src/security/loader.rs
src-tui/src/security/audit.rs
src-tui/src/main.rs
src-tui/Cargo.toml
```

### Dependencias recomendadas

```toml
nix = { version = "0.28", features = ["process", "sched", "signal", "resource", "fs"] }
```

### Codigo a integrar

```rust
// src-tui/src/security/sandbox.rs
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(target_os = "linux")]
pub fn enter_restricted_child() -> Result<(), String> {
    use libc::{
        prctl, setrlimit, rlimit, unshare, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
        PR_SET_NO_NEW_PRIVS, RLIMIT_AS, RLIMIT_CPU, RLIMIT_FSIZE,
    };

    unsafe {
        if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err("No se pudo aplicar NO_NEW_PRIVS.".into());
        }

        if unshare(CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWIPC) != 0 {
            return Err("No se pudieron crear namespaces.".into());
        }

        let mem = rlimit {
            rlim_cur: 512 * 1024 * 1024,
            rlim_max: 512 * 1024 * 1024,
        };
        let cpu = rlimit {
            rlim_cur: 120,
            rlim_max: 120,
        };
        let fsize = rlimit {
            rlim_cur: 64 * 1024 * 1024,
            rlim_max: 64 * 1024 * 1024,
        };

        setrlimit(RLIMIT_AS, &mem);
        setrlimit(RLIMIT_CPU, &cpu);
        setrlimit(RLIMIT_FSIZE, &fsize);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn terminate_sandbox(pid: i32, reason: &str) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = crate::security::audit::register_tombstone(&format!(
        "SANDBOX_TERMINATED:{}",
        reason
    ));
}
```

### Configuracion en instalacion

```sh
install -d -m 0755 /etc/livencrypt/sandbox
cat > /etc/livencrypt/sandbox/profile.conf <<EOF
network=isolated
mount=private
cpu_seconds=120
memory_mb=512
file_size_mb=64
EOF
chmod 0644 /etc/livencrypt/sandbox/profile.conf
```

## 9. Fase 7: AppArmor y seccomp

### Objetivo

Completar el aislamiento con politicas de sistema configuradas durante instalacion.

### Archivos implicados

```text
src-tui/scripts/postinstall.sh
src-tui/scripts/postremove.sh
packaging/apparmor/livencrypt-core  NUEVO
src-tui/src/security/sandbox.rs
```

### Perfil AppArmor base

```text
# packaging/apparmor/livencrypt-core
#include <tunables/global>

/usr/bin/livencrypt-core {
  #include <abstractions/base>

  capability ipc_lock,
  capability setpcap,
  capability sys_resource,

  deny network,

  owner @{HOME}/.local/share/livencrypt/** rwk,
  /etc/livencrypt/** r,
  /usr/bin/livencrypt-core rix,

  deny /etc/shadow r,
  deny /root/** rwklx,
}
```

### Integracion en `postinstall.sh`

```sh
if command -v apparmor_parser >/dev/null 2>&1 && [ -d /etc/apparmor.d ]; then
  install -m 0644 "$package_apparmor_profile" /etc/apparmor.d/usr.bin.livencrypt-core
  apparmor_parser -r /etc/apparmor.d/usr.bin.livencrypt-core || {
    echo "Livencrypt: aviso, no se pudo cargar perfil AppArmor." >&2
  }
fi
```

## 10. Fase 8: Pre-Boot Authentication e initramfs

### Objetivo

Ejecutar Livencrypt antes de que el sistema operativo cargue servicios, red o usuarios.

### Requisitos

```text
Linux con initramfs-tools o dracut
binario estatico recomendado
perfil pba seleccionado
backup fisico obligatorio
procedimiento reversible documentado
```

### Archivos implicados

```text
src-tui/scripts/initramfs-build.sh     NUEVO
src-tui/scripts/initramfs-install.sh   NUEVO
src-tui/scripts/postinstall.sh
src-tui/Cargo.toml
```

### Script orientativo

```sh
#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="x86_64-unknown-linux-musl"

rustup target add "$TARGET"
cargo build --release --locked --target "$TARGET" --manifest-path "$ROOT_DIR/Cargo.toml"

install -d -m 0755 "$ROOT_DIR/target/initramfs"
cat > "$ROOT_DIR/target/initramfs/livencrypt_hook" <<EOF
#!/bin/sh
PREREQ=""
prereqs() { echo "\$PREREQ"; }
case "\$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
copy_exec "$ROOT_DIR/target/$TARGET/release/livencrypt-core" /bin/livencrypt-core
EOF
chmod +x "$ROOT_DIR/target/initramfs/livencrypt_hook"
```

### Criterio de seguridad

No activar PBA automaticamente en `postinstall`. Debe requerir:

```text
1. perfil pba
2. confirmacion explicita
3. backup del initramfs anterior
4. instrucciones de rollback
5. prueba en equipo no critico
```

## 11. Fase 9: dashboard de expu multicapa

### Objetivo

Convertir la TUI en centro de mando.

Pantallas:

```text
Dashboard
Monitor de auditoria
Staging/updates
Sandbox manager
Recovery mode
Hardening details
Install profile
```

### Archivos implicados

```text
src-tui/src/main.rs
src-tui/src/security/audit.rs
src-tui/src/security/updates.rs
src-tui/src/security/recovery.rs
src-tui/src/security/install_profile.rs
```

### Codigo a integrar

```rust
#[derive(Clone, PartialEq, Eq)]
enum Screen {
    Unlock,
    Dashboard,
    SystemMonitor,
    AuditMonitor,
    FirmwareStaging,
    SandboxManager,
    RecoveryMode,
    InstallProfile,
}

fn handle_dashboard_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Char('a') => state.screen = Screen::AuditMonitor,
        KeyCode::Char('f') => state.screen = Screen::FirmwareStaging,
        KeyCode::Char('s') => state.screen = Screen::SandboxManager,
        KeyCode::Char('e') => state.screen = Screen::RecoveryMode,
        KeyCode::Char('p') => state.screen = Screen::InstallProfile,
        KeyCode::Char('l') => state.lock(),
        KeyCode::Char('q') | KeyCode::Esc => {
            let _ = security::vault::boot_shield_hardened_lock();
            state.should_quit = true;
        }
        _ => {}
    }
}
```

## 12. Fase 10: auditoria reforzada con MAC real

### Estado actual

La auditoria actual usa:

```text
SHA-256 encadenado
firma local deterministica derivada de campos
tombstones persistentes
```

Es valida para deteccion basica de truncado, pero para nivel de expu debe protegerse con una MAC derivada del material del vault.

### Archivos implicados

```text
src-tui/src/security/audit.rs
src-tui/src/security/vault.rs
```

### Codigo conceptual

```rust
pub fn append_authenticated_event(
    event_type: &str,
    details: &str,
    audit_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::XChaCha20Poly1305;

    // Alternativa recomendada:
    // usar keyed BLAKE3 o HMAC-SHA256.
    // Si se mantiene el set actual de dependencias:
    // derivar audit_key con HKDF desde BootMaterial.key y firmar SHA-256(key || entry).

    todo!("integrar MAC real derivada de BootMaterial");
}
```

Recomendacion concreta:

```toml
hmac = "0.12"
```

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn entry_mac(audit_key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(audit_key)
        .expect("HMAC acepta claves de cualquier tamano");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
```

## 13. Fase 11: modo espejismo completo

### Estado actual

Ya existe:

```text
glifo . / ·
deteccion de integridad
plantillas decoy
descartado de escrituras en modo espejismo
```

### Pendiente

```text
logs señuelo
retardos artificiales configurables
contador de actividad en espejismo
modo solo lectura invisible
recuperacion mediante .lvc_recovery
```

### Archivos implicados

```text
src-tui/src/security/vault.rs
src-tui/src/security/audit.rs
src-tui/src/main.rs
```

### Codigo a integrar

```rust
pub fn mirage_delay(status: IntegrityStatus) {
    match status {
        IntegrityStatus::Valid => {}
        IntegrityStatus::Truncated => std::thread::sleep(std::time::Duration::from_millis(700)),
        IntegrityStatus::Deleted => std::thread::sleep(std::time::Duration::from_millis(1_500)),
    }
}

pub fn record_mirage_interaction(action: &str) {
    let _ = crate::security::audit::register_tombstone(&format!(
        "MIRAGE_INTERACTION:{}",
        action
    ));
}
```

## 14. Fase 12: eBPF e IA local

### Valoracion

Esta fase es de alto impacto y no debe integrarse hasta tener sandbox funcional.

Riesgos:

```text
requiere kernel compatible
requiere privilegios/capacidades
requiere bytecode eBPF compilado
puede romper portabilidad
Burn/ONNX aumenta mucho el binario
```

### Archivos implicados

```text
src-tui/src/security/ebpf_sensor.rs  NUEVO
src-tui/src/security/ai_monitor.rs   NUEVO
src-tui/src/security/sandbox.rs
src-tui/src/main.rs
src-tui/Cargo.toml
```

### Dependencias posibles

```toml
aya = "0.13"
aya-log = "0.2"
```

Para IA local se recomienda evaluar fuera del binario principal:

```text
opcion A: motor heuristico Rust simple
opcion B: ONNX en binario separado
opcion C: modelo cifrado en vault cargado solo para perfil expu
```

### Codigo minimo recomendado antes de IA

```rust
// src-tui/src/security/ai_monitor.rs

pub fn heuristic_risk_score(syscalls: &[u32]) -> f32 {
    let socket_like = syscalls.iter().filter(|id| **id == 41 || **id == 42).count();
    let ptrace_like = syscalls.iter().filter(|id| **id == 101).count();
    let mount_like = syscalls.iter().filter(|id| **id == 165).count();

    let score = (socket_like as f32 * 0.10)
        + (ptrace_like as f32 * 0.50)
        + (mount_like as f32 * 0.70);

    score.min(1.0)
}
```

## 15. Orden recomendado de integracion

### Pasada 1

```text
1. install_profile.rs
2. postinstall por SO
3. pantalla TUI de perfil instalado
4. recovery.rs Ed25519
5. apply_emergency_anchor_update en vault.rs
```

### Pasada 2

```text
1. updates.rs
2. staging VFS
3. pantalla FirmwareStaging
4. verificacion Ed25519
5. borrado seguro de staging
```

### Pasada 3

```text
1. loader.rs memfd
2. sandbox.rs namespaces basico
3. limites RLIMIT
4. audit de eventos sandbox
5. pantalla SandboxManager
```

### Pasada 4

```text
1. AppArmor
2. seccomp
3. cgroups v2
4. perfiles expu/pba
```

### Pasada 5

```text
1. initramfs build
2. initramfs install
3. rollback
4. documentacion operativa PBA
```

### Pasada 6

```text
1. eBPF
2. heuristica local
3. IA local opcional
4. riesgo en TUI
```

## 16. Reglas de seguridad para implementar

```text
1. Ninguna funcion de red real debe ejecutarse en pruebas automaticas.
2. Ningun modo PBA debe activarse automaticamente.
3. Ningun sandbox debe ejecutarse sin perfil instalado.
4. Ningun loader fileless debe aceptar binarios sin firma o sin autorizacion.
5. Todo archivo temporal debe borrarse con overwrite + sync.
6. Todo secreto debe pasar por zeroize.
7. Todo cambio de vault debe ser atomico.
8. Todo evento avanzado debe registrarse en auditoria.
9. Modo espejismo nunca debe mostrar "modo espejismo" al atacante.
10. Recovery debe requerir firma externa.
```

## 17. Comandos de compilacion esperados

Compilacion normal:

```bash
cd "/home/Divad/Escritorio/LIVENCRYPT 2.0/src-tui"
cargo build --release --locked
```

Empaquetado `.deb`:

```bash
cd "/home/Divad/Escritorio/LIVENCRYPT 2.0/src-tui"
./scripts/build-deb.sh
```

Diagnostico instalado:

```bash
/usr/bin/livencrypt-core --hardening-check
```

## 18. Resultado final esperado

Al finalizar la hoja de ruta, Livencrypt 2.0 debe poder operar en tres niveles:

```text
Nivel 1: expu
  TUI
  Boot Shield
  vault cifrado
  auditoria
  hardening proceso

Nivel 2: equipo aislado/expu
  todo Nivel 1
  recovery firmado
  staging firmado
  sandbox local
  AppArmor/seccomp
  perfiles de instalacion

Nivel 3: pre-arranque/PBA
  todo Nivel 2
  binario estatico
  initramfs
  acceso antes del SO
  flujo de rollback
```

La prioridad real debe ser:

```text
confidencialidad del vault
integridad del historial
recuperacion de confianza
aislamiento de ejecucion
control del arranque
```
