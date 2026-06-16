# Análisis de Gaps y Plan de Integración de la Interfaz Rust-TUI (Livencrypt 2.0)

Este documento detalla exhaustivamente las características del motor criptográfico y de seguridad (backend en Rust) que se encuentran parcial o totalmente desconectadas del frontend interactivo en terminal (**Rust-TUI**), ubicado en [main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs). 

Se proponen soluciones ingeniosas, profesionales y seguras de diseño de interfaz de usuario en terminal, aplicando los más altos estándares para evitar la persistencia en disco de secretos (Mitigación del ataque *Demonic*), asegurar la pureza del heap de memoria y optimizar la experiencia de usuario táctil y por teclado.

---

## 1. Mapa General de Integración y Gaps Críticos

| Subsistema Backend | Módulo de Código Backend | Estado en la TUI Actual | Diagnóstico y Funcionalidad Faltante |
| :--- | :--- | :--- | :--- |
| **Doble Credencial (Split Custody)** | [vault.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs) | Parcial (Sin Entradas) | El backend soporta `secondary_cajas` y `secondary_frase`. La TUI de desbloqueo y configuración solo permite una credencial simple. Es imposible configurar o desbloquear un vault de doble factor. |
| **Clave de Coacción (Duress Key)** | [vault.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs) | Nulo (Solo segundo plano) | El backend ejecuta el borrado silencioso al recibir la clave de coacción, pero la TUI no permite configurar este secreto alternativo ni muestra la simulación pericial de "error de hardware". |
| **Pasarela de Firma asíncrona** | [worker.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/worker.rs) | Parcial (Sin Diálogos) | El hilo de red asíncrono recibe solicitudes de firma de transacciones (`Web3WorkerCmd::IncomingWebRequest`), pero no hay una interfaz en la TUI para visualizar, auditar los campos parseados y firmar interactivamente. |
| **Gestión Dinámica de Nodos** | [types.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/types.rs) | Nulo (Sin Interfaz) | Abstracción de nodos multicadena propuesta en `propuestamejora.md`. La TUI carece de una pantalla para cambiar RPCs, tokens de autorización en caliente o leer archivos de infraestructura. |
| **Derivación BIP-44 / Auditoría** | [multi_curve.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/multi_curve.rs) | Nulo (Sin Interfaz) | El TUI no expone una pantalla de cuentas que use `UniversalKeymaster` para derivar claves públicas y direcciones públicas de Bitcoin, Ethereum y Solana, imposibilitando la auditoría visual de saldos. |
| **Sandbox dinámico memfd** | [loader.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/loader.rs) | Parcial (Estático) | La pantalla del Sandbox es estática. No permite seleccionar un ejecutable temporal de staging o del navegador mediante `FileBrowser`, configurar sus límites `rlimit` y ejecutarlo de forma aislada. |
| **Localización Local (i18n)** | [vault.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs) | Nulo (Sin Selector) | Se soporta la canonicalización de números localizados (Chino, Árabe, Hindi) para el pre-arranque, pero el usuario no puede seleccionar el idioma del sistema ni visualizar el teclado en dichos glifos. |

---

## 2. Especificación de Gaps y Diseños de Frontend Propuestos

### A. Doble Credencial & Custodia Compartida (Boot Shield)
> [!IMPORTANT]
> El sistema de custodia compartida permite la división física del secreto maestro. El desbloqueo del vault cifrado requiere la validación de un par de credenciales (cada una compuesta por 5 cajas numéricas y una frase).

#### Gap Técnico
La función de desbloqueo [boot_shield_unlock](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs#L1200) y la de habilitación [boot_shield_enable](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs#L1094) aceptan argumentos opcionales `secondary_cajas` y `secondary_frase`. Actualmente, en [main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs#L4325), la vista `draw_unlock` pinta únicamente 6 campos de entrada correspondientes al primer juego de claves.

#### Propuesta de Diseño de Interfaz
Para no comprometer la superficie táctil ni sobrecargar la pantalla del terminal con 12 campos simultáneos, se propone una **entrada secuencial bifásica**. Si el archivo de cabecera del vault indica que el modo de credencial es `double` (doble factor):
1. **Fase 1 (Custodio A)**: Se solicitan las primeras 5 cajas y la frase usando un teclado virtual barajado.
2. **Fase 2 (Custodio B)**: Tras pulsar `Enter` en la Fase 1, la interfaz realiza una transición visual limpia (limpiando el búfer de pantalla con ceros) y solicita las credenciales secundarias. El teclado virtual se vuelve a barajar en el heap para mitigar ataques de análisis físico residual.

```text
+---------------------------------------------------------------------------------+
|                         LIVENCRYPT BOOT SHIELD - MODO DOBLE                     |
|                                                                                 |
|  [ Fase 2/2: Custodio Secundario (B) ]                                          |
|                                                                                 |
|   CAJA 1: [ 105 ]   CAJA 2: [ 020 ]   CAJA 3: [ 730 ]   CAJA 4: [ 004 ] ...     |
|   FRASE SECUNDARIA: [ ************************ ]                                |
|                                                                                 |
|  +---------------------------------------------------------------------------+  |
|  | Teclado Virtual Aislado (Barajado):                                       |  |
|  | [ 7 ] [ 2 ] [ 9 ] [ 0 ] [ 4 ] [ 8 ] [ 1 ] [ 3 ] [ 6 ] [ 5 ]               |  |
|  | [ a ] [ d ] [ f ] [ e ] [ c ] [ b ] [ p ] [ q ] [ r ] [ s ]               |  |
|  +---------------------------------------------------------------------------+  |
|                                                                                 |
|   Tab/Flechas: Navegar  |  Espacio: Insertar  |  F10: Desbloquear  |  Esc: Limpiar|
+---------------------------------------------------------------------------------+
```

---

### B. Gestión Avanzada de la Pasarela Web3 (Confirmación de Firma)
> [!IMPORTANT]
> El cortafuegos local analiza los detalles de las transacciones entrantes antes de delegar la firma al `UniversalKeymaster`. Si no se dispone de una UI de confirmación de firma, la TUI actúa como un sistema "ciego" que procesa peticiones automáticas del socket sin consentimiento explícito del operador.

#### Gap Técnico
El subsistema de fondo en [worker.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/worker.rs) lee comandos del socket IPC Unix. Cuando una extensión o DApp envía una solicitud de firma de transacción (`Web3WorkerCmd::IncomingWebRequest`), la TUI debe congelar temporalmente el estado y mostrar una pantalla interactiva con el resumen de la transacción extraído por el módulo [tx_parser.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/tx_parser.rs).

#### Propuesta de Diseño de Interfaz
Se propone la creación de `Screen::TransactionAuthorization`, la cual será invocada automáticamente por la recepción asíncrona de eventos en `process_background_web3_events`. Esta pantalla detalla de manera semántica la transacción:

```text
+---------------------------------------------------------------------------------+
| ⚠️  AUTORIZACIÓN REQUERIDA - PASARELA WEB3 SECURE GATEWAY                        |
+---------------------------------------------------------------------------------+
|                                                                                 |
|  Red: SOLANA MAINNET (Chain ID: 501)                                           |
|  Ruta Derivación: m/44'/501'/0'/0'/0'                                           |
|  Origen: Chrome Extension (ID: pbbge... - Validado local-UID)                    |
|                                                                                 |
|  DETALLES DE LA TRANSACCIÓN:                                                    |
|  -----------------------------------------------------------------------------  |
|  Método: SolanaTransfer                                                         |
|  Destinatario: sol:4xR8vD9b... (Nativo)                                        |
|  Valor: 15.50000000 SOL (~ $2,100.00 USD)                                       |
|  Estado del Cortafuegos: OK (Dentro de límites de volumen diario)               |
|                                                                                 |
|  POLÍTICAS DE HARDENING ACTIVAS:                                                |
|  - RFC-6979 Firma Determinista secp256k1: N/A (Ed25519)                         |
|  - Aislamiento de Memoria RAM: ACTIVO (mlockall heredado)                       |
|                                                                                 |
|  Para autorizar la firma física y devolver el payload al socket:                |
|  --> Mantenga pulsado [ F10 ] durante 2 segundos.                               |
|  --> Presione [ Esc ] para abortar y congelar el canal de inmediato.            |
|                                                                                 |
+---------------------------------------------------------------------------------+
```

---

### C. Auditoría y Visualización del Árbol de Claves BIP-44 / SLIP-10
> [!TIP]
> Permitir al operador visualizar y exportar las llaves públicas o las direcciones generadas de forma segura desde la propia interfaz física evita la necesidad de utilizar utilidades externas que puedan carecer del endurecimiento necesario.

#### Gap Técnico
El backend implementa de forma excelente la estructura matemática en [multi_curve.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/multi_curve.rs#L91), incluyendo `get_public_key` y la derivación jerárquica para Bitcoin, Ethereum y Solana. La TUI carece de una interfaz interactiva de exploración del llavero para inspeccionar y copiar las direcciones públicas.

#### Propuesta de Diseño de Interfaz
Se propone la pantalla `Screen::WalletAuditor`, accesible con la tecla `w` en el Dashboard. El operador puede seleccionar la red, la cuenta y el índice, y visualizar la clave pública y la dirección resultante. Se integrará una biblioteca de renderizado ASCII en la TUI para dibujar el código QR de la dirección pública en la consola.

```text
+---------------------------------------------------------------------------------+
|                 EXPLORADOR DE DIRECCIONES Y AUDITORÍA DE SALDOS                  |
+---------------------------------------------------------------------------------+
|  [ Red ]  > Bitcoin Mainnet (BIP-84 Native SegWit)                              |
|           Ethereum Mainnet (BIP-44)                                             |
|           Solana Mainnet (SLIP-10 Ed25519)                                      |
|                                                                                 |
|  [ Parámetros de Ruta ]                                                         |
|  Cuenta Index: [ 0   ]   Dirección Index: [ 0   ]                               |
|  Ruta Derivada: m/84'/0'/0'/0/0                                                 |
|                                                                                 |
|  DATOS COMPROBADOS:                                                             |
|  Dirección Bech32: bc1q5r8p7w93lkfhe274as82j9fkw...                             |
|  Clave Pública (HEX): 03a1f4b8c...                                              |
|                                                                                 |
|  CÓDIGO QR PARA DEPÓSITO:                                                       |
|  █████████████████████████                                                      |
|  ████  ████  ████  ███████                                                      |
|  ██████      ████  ███████                                                      |
|  ████  ██████████  ███████                                                      |
|  █████████████████████████                                                      |
|                                                                                 |
|  Presione [ C ] para copiar al portapapeles interno  |  [ Esc ] vuelve          |
+---------------------------------------------------------------------------------+
```

---

### D. Lanzador y Monitor del Sandbox memfd Interactivo
> [!IMPORTANT]
> El cargador seguro de binarios [loader.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/loader.rs) aprovecha las facilidades dinámicas del kernel de Linux mediante `memfd_create` para evitar la escritura del binario en almacenamiento secundario. La ejecución del sandbox carece de mandos en la interfaz TUI.

#### Gap Técnico
Aunque [sandbox.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/sandbox.rs) y [loader.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/loader.rs) proveen aislamiento de red (`CLONE_NEWNET`), namespaces y restricciones del planificador de CPU, la pantalla actual en la TUI (`draw_sandbox_manager`) es estática. No permite al usuario:
1. Buscar y seleccionar un binario en el explorador integrado.
2. Definir límites de CPU y memoria (`RLIMIT_AS`, `RLIMIT_CPU`).
3. Disparar el cargador asíncrono y monitorizar la salida del proceso sandboxed o terminarlo (`kill`).

#### Propuesta de Diseño de Interfaz
Se propone rediseñar `Screen::SandboxManager` dividiéndola en dos paneles (Configuración del Lanzador y Monitor de Procesos Activos):

```text
+---------------------------------------------------------------------------------+
|                       GESTOR DEL SANDBOX INTERACTIVO (MEMFD)                     |
+---------------------------------------------------------------------------------+
|  [ Lanzador de Procesos en RAM ]           | [ Procesos Sandboxed Activos ]    |
|                                            |                                    |
|  Ruta Binario: /home/user/payload.bin      | PID: 140231 (Isolated)             |
|  Límites RLIMIT:                           | CPU: 1.2%   RAM: 3.5 MB            |
|  - Memoria Max (AS):  [ 32MB ]             | Red: Aislada (CLONE_NEWNET)        |
|  - Tiempo CPU:        [ 10s  ]             | Estado: Ejecutando                 |
|  - Tamaño Archivo:    [ 1MB  ]             |                                    |
|                                            | PID: 140255 (Terminated)           |
|  Directivas Adicionales:                   | Código Salida: 0                   |
|  [x] Bloquear llamadas sys (Seccomp BPF)   |                                    |
|  [x] Denegar privilegios (NO_NEW_PRIVS)   |                                    |
|                                            |                                    |
|  Acción:                                   | Acción:                            |
|  - Presione [ L ] para buscar ruta.        | - Presione [ K ] para matar PID.   |
|  - Presione [ Enter ] para lanzar en memfd.| - Presione [ R ] para refrescar.   |
|                                            |                                    |
+---------------------------------------------------------------------------------+
```

---

### E. Integración Completa de la Configuración de Red
> [!WARNING]
> La selección de un perfil de red restrictivo (como `nmcli-off` o `drop-default-route`) puede alterar la conectividad del equipo host. La TUI debe exigir una confirmación explícita mediante teclado antes de aplicar las modificaciones destructivas en los adaptadores.

#### Gap Técnico
El perfil de red actual se almacena en el vault mediante [update_unlocked_network_profile](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/vault.rs#L1461), y es leído desde [network_profile.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/security/network_profile.rs). La TUI en `draw_settings` no expone una caja de confirmación restrictiva para evitar que el operador corte su interfaz de administración de red local accidentalmente.

#### Propuesta de Diseño de Interfaz
Integrar un modal de advertencia crítica antes de invocar la conmutación de red:

```text
+---------------------------------------------------------------------------------+
| ⚠️  ADVERTENCIA DE SEGURIDAD - CONMUTACIÓN DE PERFIL DE RED                     |
+---------------------------------------------------------------------------------+
|                                                                                 |
|  Ha seleccionado el perfil de aislamiento de red: [ nmcli-off ]                |
|                                                                                 |
|  Esta acción ejecutará comandos privilegiados en el sistema host para:          |
|  1. Desactivar todos los adaptadores inalámbricos y cableados vía NetworkManager|
|  2. Eliminar las tablas de enrutamiento por defecto en el espacio de nombres.   |
|                                                                                 |
|  Si está conectado remotamente por SSH, su sesión se perderá de forma          |
|  irreversible hasta que finalice el proceso físico de Livencrypt.               |
|                                                                                 |
|  Para confirmar y aplicar esta configuración de cortafuegos:                   |
|  -> Escriba la palabra: [ AISLAR ]                                              |
|  -> Presione [ Enter ] para aislar o [ Esc ] para mantener el modo mock.        |
|                                                                                 |
+---------------------------------------------------------------------------------+
```

---

## 3. Plan de Acción Técnico para la TUI Frontend

Para llevar a cabo la integración de estos componentes, se deben planificar las siguientes modificaciones estructurales en el bucle principal de la aplicación:

### Pasada 1: Modificación de Variables de Estado en `TuiState`
Añadir campos para soportar la visualización y control dinámico:
```rust
struct TuiState {
    // ... campos existentes ...
    
    // Gaps del Boot Shield Doble
    settings_boot_cajas_secundarias: [String; 5],
    settings_boot_frase_secundaria: String,
    show_secondary_unlock_prompt: bool,
    
    // Gaps de la Pasarela Web3
    pending_signing_request: Option<TransactionSignRequest>,
    show_signing_modal: bool,
    signing_held_duration: Duration,
    
    // Gaps del Explorador de Llaveros
    auditor_selected_chain: ChainType,
    auditor_account_idx: u32,
    auditor_address_idx: u32,
    auditor_derived_address: String,
    
    // Gaps del Sandbox memfd
    sandbox_payload_path: String,
    sandbox_max_memory_mb: u32,
    sandbox_max_cpu_sec: u32,
    sandbox_active_pids: Vec<i32>,
}
```

### Pasada 2: Prevención Forense de Memoria (Limpieza en Drop)
Asegurar que todas las variables nuevas que almacenen de forma intermedia datos del llavero o secretos secundarios sean purgadas en la implementación del trait `Drop` para `TuiState`:
```rust
impl Drop for TuiState {
    fn drop(&mut self) {
        // ... limpiezas existentes ...
        self.settings_boot_frase_secundaria.zeroize();
        self.auditor_derived_address.zeroize();
        // Las claves y semillas del UniversalKeymaster se destruyen
        // en sus propios bloques mediante sus respectivas estructuras.
    }
}
```

### Pasada 3: Mitigación de condiciones de carrera y ataques de tipo "Demonic"
Para alinearse con las directrices del [PDF revisarblockchain.pdf](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/DOCS/pendiente/revisarblockchain.pdf), se deben asegurar las siguientes reglas de captura de entradas de usuario en la TUI:
- **No persistencia del portapapeles**: Al pegar texto en el input de frases mediante la TUI (`Ctrl+V` o paste del emulador de terminal), interceptar el evento de paste, poblar la memoria interna del buffer de Rust y borrar de inmediato el clipboard del entorno gráfico del sistema operativo usando comandos externos (`xclip -selection clipboard /dev/null` o utilidades equivalentes del host si están disponibles).
- **Separación Física de Cajas**: La validación de cajas del Boot Shield debe seguir procesándose por celdas individuales indexadas en memoria. Al ingresar datos numéricos, no concatenar en campos planos persistentes de terminal; mantener la estructura segmentada de 5 cajas de 3 caracteres independientes.
