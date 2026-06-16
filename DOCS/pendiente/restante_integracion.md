# Hoja de ruta actualizada: pendientes de integración en el frontend Rust-TUI

Este documento ha sido generado tras auditar el estado actual de integración del frontend de la TUI en [main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs), detallando los componentes de interfaz que faltan por implementar y las refactorizaciones estructurales requeridas en el búnker criptográfico del backend.

## 1. Auditoría del estado de integración actual

Una comparación directa revela que se ha avanzado significativamente en varias defensas críticas en el archivo [main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs). Sin embargo, persisten varios gaps funcionales y de seguridad que impiden que el sistema funcione al 100% de su capacidad teórica.

| Módulo/funcionalidad | Estado actual en código | Estado de integración | Prioridad y observaciones |
| :--- | :--- | :--- | :--- |
| **Doble credencial** | Implementada en `draw_unlock` y `draw_settings` | **COMPLETO** | Integración finalizada para entrada de caja B1..B5 y frase B. |
| **Clave de coacción** | Implementada en `draw_settings` y flujo de desbloqueo | **COMPLETO** | Integración finalizada para destrucción física simulando fallo de hardware. |
| **Sandbox memfd** | Panel interactivo en `draw_sandbox_manager` | **COMPLETO** | Integración finalizada para lanzamientos de payloads en RAM. |
| **Auditor de direcciones** | Integrado en `draw_wallet_auditor` con huella visual | **PARCIAL** | **Prioridad alta**: Genera direcciones correctas, pero requiere código QR en formato ASCII y función de copiado rápido. |
| **Infraestructura de nodos** | Sin código de gestión ni carga de TOML en caliente | **FALTANTE** | **Prioridad alta**: Modificación de `nodes.toml` y selección de proveedores desde la TUI. |
| **Búnker criptográfico** | Restricciones de longitud rígidas y llamadas de baja entropía | **FALTANTE** | **Prioridad alta**: Migración a `cipher_text_secure` y eliminación de validaciones de longitud mínima. |
| **Sandbox del kernel** | Namespace sin user namespace y con riesgo de procesos zombies | **FALTANTE** | **Prioridad alta**: Integración de `CLONE_NEWUSER` y doble fork en `sign_sandbox.rs`. |
| **Filtros seccomp** | Syscalls rígidas exclusivas de x86 | **FALTANTE** | **Prioridad media**: Aislamiento condicional de `SYS_iopl` y `SYS_ioperm` mediante macros `#[cfg]`. |
| **Seguridad de sockets** | Sin validación de UID del cliente UNIX | **FALTANTE** | **Prioridad alta**: Forzar comprobación de `SO_PEERCRED` mediante `getsockopt`. |
| **Internacionalización (i18n)** | Sin estructura de traducción ni convertidor de numerales | **FALTANTE** | **Fase final**: Post-construcción total del backend y frontend para evitar dispersión en traducciones intermedias. |

---

## 2. Especificación técnica de los componentes faltantes

A continuación, se define la especificación técnica detallada y los diseños ingeniosos para implementar los componentes restantes en el frontend, divididos según su orden de ejecución prioritario.

### MÓDULO A: Internacionalización (i18n) y normalización de numerales (fase final)
> [!IMPORTANT]
> **REGLA DE CONSTRUCCIÓN**: La internacionalización y normalización de numerales de cajas se posponen de manera estricta para la fase final del proyecto. Este módulo se desarrollará únicamente cuando el 100% de la funcionalidad del backend y el frontend restante estén finalizados y verificados.

#### 1. Estructura del módulo de traducción ligero (i18n)
Se propone crear un subdirectorio en `src-tui/src/i18n` con los siguientes archivos:
* `mod.rs`: Enrutador del catálogo e inicializador de la configuración de idioma público.
* `locales.rs`: Estructura de mapeo con cero costo en heap, usando `match` para claves estáticas.
* `parser.rs`: Módulo de traducción y normalización Unicode de numerales localizados.

```rust
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: mapeo estatico de literales multilenguaje sin asignacion dinamica en memoria heap */

pub enum Language {
    Es,
    En,
    Zh,
    Ar,
}

pub fn translate(key: &str, lang: Language) -> &'static str {
    match lang {
        Language::Es => match key {
            "boot.title" => "LIVENCRYPT BOOT SHIELD",
            "boot.phrase" => "Frase de acceso:",
            "errors.invalid_credentials" => "CREDENCIALES INVALIDAS O VAULT MANIPULADO",
            _ => key,
        },
        Language::En => match key {
            "boot.title" => "LIVENCRYPT BOOT SHIELD",
            "boot.phrase" => "Access phrase:",
            "errors.invalid_credentials" => "INVALID CREDENTIALS OR CORRUPTED VAULT",
            _ => key,
        },
        Language::Zh => match key {
            "boot.title" => "LIVENCRYPT 安全启动屏障",
            "boot.phrase" => "访问密码短语:",
            "errors.invalid_credentials" => "凭证无效或保险库被篡改",
            _ => key,
        },
        Language::Ar => match key {
            "boot.title" => "درع التمهيد ليفينكريبت",
            "boot.phrase" => "عبارة المرور:",
            "errors.invalid_credentials" => "اعتمادات غير صالح أو تم التلاعب بالخزنة",
            _ => key,
        }
    }
}
2. Normalización de numerales para el boot shield
Cuando el usuario tiene la terminal en un idioma como chino, árabe o devanágari, las cajas pueden recibir glifos de sus sistemas de escritura locales. El convertidor debe interceptar la entrada en main.rs y traducirla:

Rust
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: parser y normalizador unicode de sistemas numéricos orientales a enteros nativos */

pub fn parse_localized_digit(c: char) -> Option<i64> {
    match c {
        // ASCII / Fullwidth
        '0' | '０' => Some(0),
        '1' | '１' => Some(1),
        '2' | '２' => Some(2),
        '3' | '３' => Some(3),
        '4' | '４' => Some(4),
        '5' | '５' => Some(5),
        '6' | '６' => Some(6),
        '7' | '７' => Some(7),
        '8' | '８' => Some(8),
        '9' | '９' => Some(9),
        // Árabe-Indic (العربية الشرقية)
        '٠' => Some(0),
        '١' => Some(1),
        '٢' => Some(2),
        '٣' => Some(3),
        '٤' => Some(4),
        '٥' => Some(5),
        '٦' => Some(6),
        '٧' => Some(7),
        '٨' => Some(8),
        '٩' => Some(9),
        // Devanágari (Hindi / संस्कृत)
        '०' => Some(0),
        '१' => Some(1),
        '२' => Some(2),
        '३' => Some(3),
        '४' => Some(4),
        '५' => Some(5),
        '६' => Some(6),
        '७' => Some(7),
        '८' => Some(8),
        '९' => Some(9),
        // Chino Simplificado / Tradicional
        '零' => Some(0),
        '一' | '壹' => Some(1),
        '二' | '貳' => Some(2),
        '三' | '參' => Some(3),
        '四' | '肆' => Some(4),
        '五' | '伍' => Some(5),
        '六' | '陸' => Some(6),
        '七' | '柒' => Some(7),
        '八' | '捌' => Some(8),
        '九' | '玖' => Some(9),
        _ => None,
    }
}
MÓDULO B: Lector y editor de infraestructura de nodos (nodes.toml)
[!IMPORTANT]
El núcleo multicadena interactúa con nodos RPC para Bitcoin, Ethereum y Solana. La TUI debe permitir al usuario auditar y editar en caliente estas direcciones para evitar enrutamientos forzados o ataques de eclipse (Eclipse Attacks) sin comprometer el aislamiento físico.

Se propone la creación de Screen::NodesManager accesible desde la pestaña de configuración del sistema (c), permitiendo leer y escribir en caliente un archivo nodes.toml cifrado en reposo.

Propuesta de interfaz en TUI
Plaintext
+---------------------------------------------------------------------------------+
|                       GESTIÓN DE INFRAESTRUCTURA DE NODOS                       |
+---------------------------------------------------------------------------------+
|  Cadenas Registradas:                      | Detalles del Nodo Seleccionado:    |
|                                            |                                    |
|  [x] Bitcoin Mainnet (Local Node)          | Nombre: Bitcoin Mainnet            |
|  [ ] Ethereum Mainnet (Infura Link)        | URL: [http://127.0.0.1:8332]       |
|  [ ] Solana Mainnet (Public RPC)           | Protocolo: JSON-RPC (Cookie Auth)  |
|                                            | Estado: CONECTADO (Ping: 45ms)     |
|                                            |                                    |
|                                            | Fallback: blockstream.info/api     |
|                                            |                                    |
|                                            | Token de Acceso (Cifrado):         |
|                                            | [ ***************** ************* ]|
|                                            |                                    |
|  Acciones Generales:                       | Acciones de Edición:               |
|  - Flechas: Navegar por la lista           | - [ E ] Editar Endpoint URL        |
|  - [ Espacio ]: Cambiar a Nodo Activo      | - [ T ] Introducir Token Auth      |
|  - [ G ]: Guardar cambios en Vault         | - [ Enter ]: Probar Conectividad   |
|                                            |                                    |
+---------------------------------------------------------------------------------+
MÓDULO C: Generador de código QR en ASCII para auditoría
[!TIP]
En la pantalla de auditoría visual de direcciones públicas (draw_wallet_auditor), mostrar un código QR real renderizado mediante bloques Unicode en terminal permite al operador transferir saldos desde un dispositivo móvil de manera totalmente segura y offline.

Implementación del renderizador QR en terminal
Para renderizar un código QR en consola se deben usar caracteres de bloque medio alto (▄), medio bajo (▀) y bloque completo (█). Esto permite condensar 2 píxeles verticales en un solo carácter de terminal, logrando que el código QR sea cuadrado y escaneable por cualquier cámara móvil.

Rust
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: renderizador dinamico de matrices qr codificadas en caracteres de bloque unicode */

pub fn draw_ascii_qr(frame: &mut Frame<'_>, area: Rect, address: &str) {
    // 1. Generar la matriz de bits del código QR (usando crate ligero qrcode)
    let qr = match qrcode::QrCode::new(address.as_bytes()) {
        Ok(code) => code,
        Err(_) => return,
    };
    let image = qr.render::<char>()
        .quiet_zone(false)
        .dark_color('#')
        .light_color(' ')
        .build();

    // 2. Mapear la matriz de caracteres a bloques Unicode condensados
    let mut lines = Vec::new();
    let rows: Vec<&str> = image.lines().collect();
    
    // Iteramos de 2 en 2 filas para condensar verticalmente
    for y in (0..rows.len()).step_by(2) {
        let mut line_spans = Vec::new();
        let current_row = rows[y];
        let next_row = if y + 1 < rows.len() { Some(rows[y + 1]) } else { None };
        
        for (x, char_top) in current_row.chars().enumerate() {
            let char_bottom = next_row.map(|row| row.chars().nth(x).unwrap_or(' ')).unwrap_or(' ');
            
            // Condensación vertical de píxeles:
            let block = match (char_top == '#', char_bottom == '#') {
                (true, true) => "█",   // Ambos negros
                (true, false) => "▀",  // Superior negro, inferior blanco
                (false, true) => "▄",  // Superior blanco, inferior negro
                (false, false) => " ", // Ambos blancos
            };
            line_spans.push(Span::raw(block));
        }
        lines.push(Line::from(line_spans));
    }

    // 3. Pintar en el panel correspondiente de la TUI
    let paragraph = Paragraph::new(lines).alignment(Alignment::Center);
    frame.render_widget(paragraph, area);
}
MÓDULO D: Refactorización y robustecimiento de seguridad del backend
1. Libertad absoluta en el espacio de claves (secure_text.rs)
Eliminar la constante MIN_SECRET_CHARS = 12; y toda la lógica de validación de longitud. El motor de derivación basado en Argon2id debe procesar de forma silenciosa cadenas de cualquier tamaño. La TUI no realizará validaciones interactivas ni emitirá advertencias visuales sobre el tamaño de la contraseña para mitigar ataques de canal lateral o inferencias.

2. Activación del espacio de nombres de usuario y doble fork (sign_sandbox.rs)
Modificar el aislamiento de sign_sandbox.rs para incluir la bandera libc::CLONE_NEWUSER a la llamada de unshare. Además, se implementará un esquema de doble fork en run_isolated para que el proceso que ejecuta la firma actúe como un PID 1 real en el espacio aislado (CLONE_NEWPID), previniendo procesos zombies y garantizando el cierre seguro de descriptores.

3. Higiene multiarquitectura en filtros seccomp (seccomp.rs)
Aislar las syscalls de control físico libc::SYS_iopl y libc::SYS_ioperm mediante macros de preprocesador condicionales #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] para evitar fallos de compilación en arquitecturas ARM (aarch64).

4. Validación ACL en sockets IPC (supervisor.rs)
Integrar la comprobación de credenciales del par mediante la llamada a getsockopt con la bandera SO_PEERCRED en el socket IPC UNIX /run/user/UID/livencrypt/livencrypt.sock para rechazar conexiones cuyo UID no coincida con el UID del operador que instanció el proceso original.

5. Capa de abstracción multicadena (blockchain/mod.rs)
Diseñar e implementar el rasgo asíncrono genérico ChainAdapter dentro del subsistema de contabilidad de la pasarela. Este componente encapsula las firmas de validación y decodificación binaria de transacciones nativas, abstrayendo por entero la lógica operativa del supervisor transaccional. Esto desvincula el motor central de los analizadores estáticos actuales de Bitcoin, Ethereum y Solana, dotando a la arquitectura de una modularidad limpia y expansiones futuras en caliente hacia redes de anonimato (Monero, Zcash), infraestructuras de capa 2 (Starknet) o ecosistemas paralelos (BNB Chain) sin riesgo de regresión de código.

3. Plan de mitigación forense y saneamiento del entorno
Al implementar la carga de nodos y robustecer el búnker criptográfico, se deben observar las siguientes reglas forenses estrictas:

Destrucción de buffers de entrada: Durante la edición de URLs de nodos o claves en la TUI, utilizar buffers mutables dinámicos que se sobreescriban con Zeroize en el momento en que el foco de edición abandone el campo o la pantalla cambie.

Normalización Unicode estricta: Todas las entradas de frase deben ser normalizadas a la forma NFC (Normalization Form Canonical Composition) usando el crate unicode-normalization antes de ser inyectadas en la KDF, evitando denegaciones de acceso por bytes diferentes en caracteres visualmente idénticos.

