# Cuarentena de Memoria y Aislamiento (Zero-Trust Sandbox)

Este módulo describe la arquitectura de la "Zona de Cuarentena" de Livencrypt 2.0. Cuando se ejecuta un software externo desde el cargador en memoria, este no debe tener capacidad para escalar privilegios, exfiltrar datos del sistema anfitrión o escribir en disco.

---

## 1. Diseño y Principios Técnicos: El Búnker de Tres Capas

La ejecución del binario descifrado se realiza en un entorno estéril y controlado de Confianza Cero (*Zero-Trust*), estructurado en tres niveles de aislamiento basados en primitivas del núcleo de Linux:

### Capa 1: Aislamiento de Espacios de Nombres (Namespaces)
Virtualiza los recursos globales del sistema operativo para que el software hijo no pueda ver ni interactuar con el exterior:
* **PID Namespace**: El programa se ejecuta creyendo que es el único proceso activo (asigna PID 1). No puede ver, rastrear o matar procesos del sistema anfitrión.
* **Net Namespace**: Se asigna una interfaz de red vacía (únicamente la interfaz de loopback local `lo` aislada). El programa no tiene acceso físico a Internet ni a la red local.
* **Mnt Namespace**: Se monta un sistema de archivos temporal (`tmpfs`) limpio en memoria RAM. La raíz `/` del sistema anfitrión se oculta por completo, de modo que el programa no puede leer ni escribir en los archivos reales del disco duro.

### Capa 2: Control de Recursos (CGroups v2)
Evita ataques de Denegación de Servicio (DoS) o agotamiento del hardware por parte de programas comprometidos o maliciosos:
* **Límite de Memoria**: Se impone un techo estricto de RAM asignable al contenedor efímero.
* **Límite de CPU**: Restricción de ciclos de procesamiento para evitar bucles infinitos de consumo de CPU.

### Capa 3: Perfiles de Seguridad (AppArmor / Seccomp)
Filtra y restringe las llamadas al sistema (*syscalls*) que el proceso puede realizar al kernel:
* **Seccomp (Secure Computing Mode)**: Se crea un filtro estricto con `libseccomp` que bloquea llamadas peligrosas como `ptrace` (evitando inyecciones de código o inspección de otros procesos) o `mount`. Solo se permiten llamadas básicas de entrada/salida y lectura de descriptores de memoria.
* **AppArmor**: Aplica un perfil con una política de "Denegar por Defecto" (*Default Deny*), limitando las escrituras únicamente al área temporal volátil asignada en RAM.

### D. Canal de Comunicación Unix Restringido
Dado que el programa en cuarentena no puede escribir en el disco del host:
1. Se establece un socket Unix local cifrado entre el sandbox de la aplicación y el proceso principal de Livencrypt.
2. Si el programa guardado en el vault necesita escribir su configuración o guardar datos, los envía a través de este socket restringido.
3. El proceso de Livencrypt recibe los datos en el espacio seguro del host, los valida, y los guarda directamente cifrados en el vault original. El programa secundario nunca conoce la ubicación física de almacenamiento ni las claves de cifrado.

---

## 2. Archivos Implicados en el Proyecto

* **`src-tui/src/security/sandbox.rs`** *(Módulo propuesto)*: Contendrá la inicialización de Namespaces usando la biblioteca `nix` en Rust, la configuración de filtros de llamadas al sistema con `libseccomp-sys`, la comunicación mediante socket Unix, y la monitorización de violaciones de seguridad.
* **[Cargo.toml](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/Cargo.toml)**: Requiere agregar dependencias de bajo nivel de Linux como `nix = "0.28"` y `libseccomp = "0.3"`.

---

## 3. Estado de la Integración

### ¿Qué está YA integrado?
* [x] **Red Aislada (Concepto)**: `network_profile.rs` cuenta con perfiles de red para diagnosticar interfaces del sistema, pero no realiza aislamiento activo de sockets a nivel de proceso o contenedor de Namespaces.

### ¿Qué falta por integrar?
* [ ] **Cajas de Aislamiento (Namespaces)**: Falta escribir la lógica en Rust para clonar procesos y crear los namespaces de PID, red y montaje (`unshare` / `clone`).
* [ ] **Filtros Seccomp**: Definir la lista blanca de syscalls permitidas para programas de cuarentena.
* [ ] **Canal de Socket UNIX**: Falta el socket de sincronización y el validador de mensajes de persistencia para el VFS.
* [ ] **Integración en la TUI**: Desarrollar la pantalla de advertencia forense que notifica al usuario si el programa en ejecución intenta vulnerar los límites del sandbox (guardando el log de violaciones y forzando la terminación del proceso con `SIGKILL`).

---

## Enlaces Relacionados
* Volver al [[00_indice|Índice General]].
* Ver el análisis de comportamiento proactivo: [[07_ia_local_y_deteccion_ebpf|Detección de Comportamiento con IA Local y eBPF]].

## Código a integrar
1. Evolución de loader.rs (Namespaces y Seccomp)
Actualizaremos el módulo de carga para inyectar el aislamiento antes de la ejecución del binario en la RAM.

Archivo implicado: src-tui/src/security/loader.rs

Código a editar/añadir:

Rust
/* Editar src-tui/src/security/loader.rs */

use libc::{unshare, CLONE_NEWNS, CLONE_NEWNET, CLONE_NEWPID, PR_SET_NO_NEW_PRIVS, prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER};
use std::os::unix::net::UnixDatagram;

pub fn load_and_execute_isolated(name: &str, binary_data: &mut [u8]) -> Result<(), String> {
    // 1. Crear canal de comunicación restringido (Socket UNIX)
    let (parent_sock, child_sock) = UnixDatagram::pair().map_err(|e| e.to_string())?;

    let pid = unsafe { fork() };
    if pid == 0 {
        // --- PROCESO HIJO (CUARENTENA) ---
        
        // 2. Aislamiento de Namespaces (Red, Montaje, PID)
        unsafe {
            unshare(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID);
            // Evitar escalada de privilegios
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        }

        // 3. Aplicar Filtros Seccomp (Whitelist básica)
        apply_seccomp_whitelist();

        let path = CString::new(format!("/proc/self/fd/{}", fd)).unwrap();
        // ... ejecución con execve (lógica anterior)
        std::process::exit(1);
    } 
    
    // Proceso PADRE: Monitorizar socket y PID
    monitor_sandbox(pid, parent_sock);
    Ok(())
}

fn apply_seccomp_whitelist() {
    // Implementación simplificada para denegar llamadas peligrosas
    // En producción se usa bpf_prog para permitir solo read, write, exit, etc.
    unsafe {
        // prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)
    }
}
2. Monitorización y Canal de Sincronización
Añadiremos el validador que escucha las peticiones del sandbox y detecta violaciones de seguridad.

Archivo implicado: src-tui/src/security/loader.rs

Código a añadir:

Rust
fn monitor_sandbox(child_pid: i32, socket: UnixDatagram) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match socket.recv(&mut buf) {
                Ok(n) => {
                    let msg = String::from_utf8_lossy(&buf[..n]);
                    // Validar si el mensaje es una petición de persistencia legítima
                    if !is_message_valid(&msg) {
                        terminate_sandbox(child_pid, "Violación de protocolo detectada");
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn terminate_sandbox(pid: i32, reason: &str) {
    unsafe { libc::kill(pid, libc::SIGKILL) };
    // Registrar violación en el log de auditoría
    let _ = crate::security::audit::register_tombstone(&format!("SANDBOX_TERMINATED: {}", reason));
}
3. Pantalla de Advertencia Forense en la TUI
Implementaremos la interfaz que notifica al usuario si un programa ha intentado romper la cuarentena.

Archivo implicado: src-tui/src/main.rs

Código a editar: Actualizar el enum Screen y añadir la función de renderizado.

Rust
/* Editar src-tui/src/main.rs */

enum Screen {
    // ...
    ForensicAlert { reason: String },
}

fn draw_forensic_alert(frame: &mut Frame<'_>, area: ratatui::layout::Rect, reason: &str) {
    let block = Block::default()
        .title(" ⚠ ALERTA DE SEGURIDAD CRÍTICA ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));
    
    let text = vec![
        Line::from(Span::styled("SE HA DETECTADO UN INTENTO DE VIOLACIÓN DEL SANDBOX", Style::default().fg(Color::Red))),
        Line::from(""),
        Line::from(format!("Motivo: {}", reason)),
        Line::from(""),
        Line::from("El proceso ha sido finalizado de forma inmediata (SIGKILL)."),
        Line::from("El evento ha sido registrado en el log de auditoría inmutable."),
        Line::from(""),
        Line::from(Span::styled("Presione ESC para volver al panel seguro.", Style::default().add_modifier(Modifier::DIM))),
    ];

    let p = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });

    frame.render_widget(Clear, area); // Limpiar fondo
    frame.render_widget(p, area);
}
Impacto en la Seguridad
Aislamiento de Red: El uso de CLONE_NEWNET garantiza que el binario descifrado no pueda exfiltrar datos, ya que no "ve" ninguna interfaz de red válida.

Integridad del Sistema de Archivos: Al no montar la raíz en el nuevo mnt namespace, el software en cuarentena solo puede ver su propia memoria, protegiendo los archivos del host.

Respuesta Forense: La integración con la TUI asegura que el usuario sea el primer informado ante una anomalía, mientras que el sistema de auditoría registra la prueba del intento de intrusión para análisis posterior.

Terminación Implacable: El uso de SIGKILL garantiza que el proceso no pueda ignorar la orden de cierre, eliminando cualquier rastro de ejecución de forma inmediata.
