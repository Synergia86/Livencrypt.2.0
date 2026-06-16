# Cargador (Crypter/Loader) y Bit de Suicidio

Este módulo detalla cómo Livencrypt 2.0 protege software externo sin alterar su código a través de un cargador en memoria (*Sobre Digital*) y cómo ejecuta un protocolo de autodestrucción lógica permanente (*Bit de Suicidio*) si se detecta manipulación en el sistema.

---

## 1. Diseño y Principios Técnicos

### A. Livencrypt como Cargador ("Sobre Digital")
Para proteger programas de código abierto o binarios propietarios sin modificar su código original ni arriesgarse a corromperlos:
1. **Encapsulamiento**: El archivo ejecutable externo y sus carpetas de configuración se cifran por completo y se empaquetan como el payload cifrado de un archivo `.lvcvault`.
2. **Ejecución Fileless (Sin Archivo en Disco)**: Al ingresar las credenciales, Livencrypt no extrae el binario al disco duro (lo que expondría el ejecutable a interceptación o copia). En su lugar, utiliza la llamada al sistema de Linux `memfd_create`.
3. **Mecanismo**: `memfd_create` crea un archivo anónimo en la memoria física (RAM) que el kernel de Linux trata como un archivo regular. Livencrypt descifra el payload directamente en este espacio de memoria blindada (`mlockall`) y ejecuta el binario mediante `execve` sobre el descriptor de archivo de memoria.
4. **Ciclo de Vida Estéril**: El software externo solo existe en claro dentro de los límites de la memoria física mientras el proceso está activo. Al cerrarse, la memoria se libera y se limpia con ceros criptográficos.

### B. Modo de Respuesta Automática: El "Bit de Suicidio"
Si el sistema detecta que el registro de auditoría ha sido manipulado (`IntegrityStatus::Truncated` o `Deleted`), se dispara el protocolo de pánico inmutable:
* **El Marcador**: Livencrypt escribe un flag (bit) de **"Bloqueo Permanente"** dentro de la estructura cifrada del encabezado del vault (`VaultHeader`). Dado que el encabezado se firma con Poly1305, esta escritura solo la puede hacer el propio proceso legítimo usando la clave de sesión en RAM en ese momento.
* **Bloqueo de Derivación**: Una vez activado este bit, la lógica interna de derivación de claves cambia. En los arranques posteriores, aunque el usuario teclee la secuencia correcta de las 5 cajas y la frase, Livencrypt detecta el flag de suicidio y **se niega a derivar las subclaves finales** para abrir los archivos críticos, simulando una corrupción de datos física.
* **Resistencia a Malware**: Un malware con permisos de Root no puede "desmarcar" el bit de suicidio, ya que para modificar el encabezado firmado necesitaría conocer la frase y secuencia del usuario, las cuales no posee.
* **Recuperación mediante Backup Físico**: Este bloqueo es deliberadamente irreversible. Para recuperar el acceso, el usuario debe restaurar el archivo del vault (`.lvcvault`) desde una copia de seguridad física externa (como un disco USB desconectado antes del ataque) que contenga el encabezado limpio (sin el bit de suicidio activado).

---

## 2. Archivos Implicados en el Proyecto

* **`src-tui/src/security/loader.rs`** *(Módulo propuesto)*: Manejará el uso de `memfd_create`, la redirección de descriptores de archivos, y el lanzamiento mediante `execve` del proceso hijo en RAM.
* **[vault.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs)**: Debe actualizarse para incluir el campo `suicide_bit: bool` en el `VaultHeader` y modificar la función `derive_material` para que rechace la generación de claves si el bit de suicidio está activo.

---

## 3. Estado de la Integración

### ¿Qué está YA integrado?
* [x] **Destrucción Física (`boot_shield_destructive_panic`)**: El borrado seguro físico mediante sobrescritura con ruido aleatorio y `sync_all` está plenamente operativo en `vault.rs`, aunque destruye los archivos de inmediato en lugar de realizar el bloqueo lógico preventivo en el encabezado.
* [x] **Escritura Atómica Segura**: La infraestructura para modificar el encabezado de forma segura sin peligro de corrupción ante cortes de energía está lista.

### ¿Qué falta por integrar?
* [ ] **Llamada `memfd_create` en Rust**: No se cuenta con código que implemente archivos de memoria virtuales para la carga *fileless* de binarios.
* [ ] **Módulo `loader.rs`**: Falta crear el cargador que gestione la bifurcación del proceso ejecutable (`fork`/`execve`) dentro de la RAM blindada.
* [ ] **Flag de Suicidio en `VaultHeader`**: Falta añadir `suicide_bit: bool` en la definición de la cabecera y en los tests de verificación.
* [ ] **Bifurcación en `derive_material`**: Modificar el método para lanzar el error `FAKE_HW_ERROR` si el bit de suicidio está presente en el encabezado, ignorando la validez de la clave derivada.

---

## Enlaces Relacionados
* Volver al [[00_indice|Índice General]].
* Ver cómo se aísla el binario cargado en memoria: [[06_cuarentena_memoria_y_aislamiento_sandbox|Cuarentena de Memoria y Aislamiento (Zero-Trust Sandbox)]].

## Código a integrar
1. Implementación de memfd_create y Módulo loader.rs
Este nuevo módulo permite crear descriptores de archivo que residen únicamente en la RAM, permitiendo ejecutar binarios descifrados sin dejar rastro en el sistema de archivos físico.

Archivo implicado: src-tui/src/security/loader.rs (NUEVO ARCHIVO)

Código:

Rust
// SPDX-License-Identifier: GPL-3.0-or-later
use libc::{c_char, c_int, execve, fork, memfd_create, write};
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::ptr;
use zeroize::Zeroize;

/* Rol: Cargador de ejecución volátil (Fileless Loader) */

pub fn load_and_execute_in_ram(name: &str, binary_data: &mut [u8]) -> Result<(), String> {
    let c_name = CString::new(name).map_err(|e| e.to_string())?;
    
    // 1. Crear archivo anónimo en RAM (memfd)
    let fd = unsafe { memfd_create(c_name.as_ptr(), 0) };
    if fd == -1 { return Err("Fallo al crear memfd".into()); }

    // 2. Escribir el binario descifrado en el descriptor de memoria
    let write_res = unsafe { write(fd, binary_data.as_ptr() as *const _, binary_data.len()) };
    
    // LIMPIEZA: Sobrescribir el búfer original inmediatamente
    binary_data.zeroize();

    if write_res == -1 { return Err("Error al escribir binario en RAM".into()); }

    // 3. Bifurcar proceso para ejecución aislada
    let pid = unsafe { fork() };
    if pid == 0 {
        // Proceso HIJO: Ejecutar el binario desde /proc/self/fd/X
        let path = CString::new(format!("/proc/self/fd/{}", fd)).unwrap();
        let argv: [*const c_char; 2] = [path.as_ptr(), ptr::null()];
        let envp: [*const c_char; 1] = [ptr::null()];

        unsafe { execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        std::process::exit(1); // Solo llega aquí si falla execve
    } else if pid > 0 {
        // Proceso PADRE: Continúa Livencrypt
        Ok(())
    } else {
        Err("Fallo en fork".into())
    }
}
2. Modificación de VaultHeader (Bit de Suicidio)
Añadiremos el flag de inmutabilidad al encabezado para permitir el bloqueo permanente.

Archivo implicado: src-tui/src/security/vault.rs

Código a editar: Actualizar VaultHeader y VaultAssociatedDataV3.

Rust
/* Editar en src-tui/src/security/vault.rs */

#[derive(Clone, Serialize, Deserialize)]
struct VaultHeader {
    // ... campos existentes
    pub suicide_bit: bool, // NUEVO: Bloqueo permanente tras manipulación
    pub last_audit_anchor: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultAssociatedDataV3 {
    // ... campos existentes
    pub suicide_bit: bool, // NUEVO: Protegido por Poly1305
    pub last_audit_anchor: Vec<u8>,
}

// Actualizar mapeo en associated_data(...)
fn associated_data(header: &VaultHeader) -> Result<Vec<u8>, String> {
    if header.format_version >= FORMAT_VERSION {
        return rmp_serde::to_vec(&VaultAssociatedDataV3 {
            // ... campos existentes
            suicide_bit: header.suicide_bit,
            last_audit_anchor: header.last_audit_anchor.clone(),
        }).map_err(|e| e.to_string());
    }
    // ...
}
3. Bifurcación en la lógica de desbloqueo
Modificaremos la entrada al vault para que, si el suicide_bit está activo, se ignore cualquier clave y se devuelva el error de hardware falso.

Archivo implicado: src-tui/src/security/vault.rs

Código a editar: Modificar boot_shield_unlock_impl.

Rust
/* Editar en src-tui/src/security/vault.rs */

pub fn boot_shield_unlock_impl(
    cajas: [i64; 5],
    frase: String,
    // ...
) -> Result<BootShieldStatus, String> {
    let mut envelope = read_envelope()?;

    // 1. COMPROBACIÓN DE SUICIDIO: Si está activo, simular fallo físico irremediable
    if envelope.header.suicide_bit {
        // Inyectar retardo artificial para simular "lectura lenta de sector dañado"
        std::thread::sleep(std::time::Duration::from_millis(2500));
        return Err(super::vault::FAKE_HW_ERROR.to_string());
    }

    // 2. Flujo normal de derivación y descifrado
    let secret = match derive_material(cajas, frase, &envelope.header) {
        Ok(s) => s,
        Err(_) => {
            // Registrar intento fallido y gestionar contador
            // ... (lógica existente de incremento de fallos)
            return Err(INVALID_ACCESS.into());
        }
    };
    
    // ... resto de la lógica de desbloqueo
}
Valoración de Ingeniería de Seguridad
Ejecución Invisible (loader.rs): Al usar memfd_create, el binario externo nunca existe en el disco duro. Un perito forense que examine el almacenamiento no encontrará rastro del software ejecutado, ya que este "muere" al cerrar la memoria RAM .

Inmutabilidad Definitiva: El suicide_bit integrado en el AAD (Datos Asociados Autenticados) de Poly1305 impide que un malware con permisos de root pueda "desactivar" el bloqueo. Como no conoce la clave del vault, cualquier intento de cambiar ese false por true invalidará la firma del encabezado .

Engaño Técnico: Al devolver FAKE_HW_ERROR independientemente de si la clave es correcta o no, el sistema protege la propia existencia de la clave. El atacante nunca sabrá si sus credenciales son válidas o no, pues el sistema siempre responderá como si el disco estuviera físicamente roto.
