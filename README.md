# Livencrypt 2.0

Livencrypt 2.0 es una suite criptográfica avanzada de confianza cero (zero-trust) y **pasarela de custodia universal** diseñada en Rust para operar de manera local y descentralizada a través de una interfaz interactiva de terminal (TUI). El sistema proporciona un entorno fortificado para el cifrado posicional de datos, la gestión de almacenamiento criptográfico blindado en memoria volátil y la **intermediación segura de operaciones Web3** con navegadores web (compatible con dApps mediante el estándar EIP-1193) a través de una extensión y canales de comunicación aislados (IPC). Incluye un **auditor visual de direcciones públicas** y un **registro de auditoría firmado** a prueba de manipulaciones.

## 1. Arquitectura y modelo de confianza cero

La suite está estructurada bajo una filosofía de diseño compartimentado para mitigar de raíz la persistencia de secretos en entornos inseguros (como el espacio de memoria de un navegador). **La clave privada nunca abandona el núcleo seguro local.**

```
                                  [ENTORNO INSEGURO]
                           +------------------------------+
                           | Extensión web EIP-1193 (JS)  |  <- window.ethereum / window.livencrypt
                           +--------------+---------------+
                                          |
                        Mensajería nativa (Payloads JSON)
                                          |
                                  [CORTAFUEGOS IPC]
                           +--------------v---------------+
                           |  Host puente de mensajería   |
                           |    (com.livencrypt.gateway)  |
                           +--------------+---------------+
                                          |
                              Socket Unix (Permisos 0600)
                                          |
                               [NÚCLEO SEGURO (RUST)]
     +------------------------------------+------------------------------------+
     |                      Hilo asíncrono secundario                          |
     |  +-------------------------------------------------------------------+  |
     |  |                         Web3BackgroundWorker                      |  |
     |  |                                                                   |  |
     |  |   +--------------------+     +--------------------------------+   |  |
     |  |   |   LiveFirewall     |---->|       GatewaySupervisor        |   |  |
     |  |   | (Cuotas / Límites) |     | (run_loop_iteration / Sockets) |   |  |
     |  |   +--------------------+     +---------------+----------------+   |  |
     |  |            |                                 |                    |  |
     |  |   +--------v---------+         +-------------v--------------+     |  |
     |  |   | RPC Manager      |         | Auditoría firmada (Ed25519)|     |  |
     |  |   | (quórum de nodos)|         | web3_audit.jsonl encadenada|     |  |
     |  |   +------------------+         +----------------------------+     |  |
     |  +----------------------------------------------|--------------------+  |
     |                                     Canal asíncrono MPSC                |
     |                      Hilo maestro interactivo   v                       |
     |  +-------------------------------------------------------------------+  |
     |  |                          Bucle TUI Ratatui                        |  |
     |  |    Pasarela "w" (custodia/firma)  ·  Auditor "k" (direcciones)    |  |
     |  +-------------------------------------------------------------------+  |
     +-------------------------------------------------------------------------+
```

El núcleo se divide en hilos asíncronos concurrentes:

1. **Hilo maestro interactivo (TUI):** renderiza con Ratatui/Crossterm, consume eventos del worker por canales MPSC y mantiene una caché local (`TuiState`).
2. **Hilo perimetral de lectura Unix:** escucha peticiones externas con límite estricto de conexiones concurrentes (anti-DoS / anti-slowloris).
3. **Hilo del supervisor (Background Worker):** valida en caliente el cortafuegos, orquesta el llavero multicurva, gestiona los adaptadores RPC y sella la auditoría.

## 2. Características principales

### A. Cifrado posicional de texto y archivos autenticados
- **Agnosticismo de datos:** el motor `PositionalCipher` usa matrices de sustitución/permutación basadas en plantillas lingüísticas (chino, coreano, katakana, árabe, etc.), eliminando codificaciones Unicode corruptas.
- **Cifrado de archivos con doble factor de secreto:** `FileCipher` separa estrictamente la referencia pública del HUD de la frase mnemónica real del archivo.

### B. Pasarela Web3 asíncrona y custodia universal (tecla `w`)
- **Llavero multicurva volátil (`UniversalKeymaster`):** `master_seed` de 64 bytes derivada por KDF sobre la matriz de 5 cajas + frase maestra. Derivación determinista BIP-32/BIP-44/SLIP-10:
  - **secp256k1** (ECDSA) para Bitcoin y Ethereum.
  - **ed25519** (Edwards) para Solana.
  - Cadenas que requieren criptografía especializada (Monero/Zcash/Starknet) se **rechazan de forma determinista** (fail-closed).
- **Autorización local en dos pasos:** ninguna **firma** ni **broadcast** ocurre sin confirmación física (F10/A) en la consola; nunca se firma a ciegas (se parsea y se muestra método, destino, valor y **comisión estimada**).
- **Broadcast en dos pasos auditado:** el envío real a la red solo procede con perfil `RpcOperational`, nodo auditado y autorización local, registrándose en la auditoría firmada.
- **Importación de precios firmados (`.lvcprices`, Ed25519):** oráculo offline para valoración fiat.
- **Políticas por cuenta, reglas programadas e inspector RPC:** límites por cuenta/ventana, **comisión máxima por política**, lecturas de saldo/nonce/fee/estado por cadena.
- **Conciencia de red testnet/mainnet** y firma network-aware.

### C. Auditor visual de direcciones públicas (tecla `k`)
- **Deriva claves públicas sin firmar nunca** (aislamiento criptográfico del motor de custodia).
- **Checksum EIP-55** en Ethereum (anti-typo) y validación de checksum de entrada (Base58Check / Base58).
- **Re-derivación verificable** (tecla `V`): doble derivación comparada en tiempo constante para detectar inconsistencias antes de recibir fondos.
- **Comparación anti-spoofing:** se teclea/pega la dirección esperada, se valida su checksum y se compara con la derivada.
- **SegWit/bech32 (P2WPKH)** para Bitcoin (`bc1`/`tb1`) y direcciones por red correcta.
- **QR + vínculo público** (sin secretos) y **gate de re-confirmación Boot Shield** antes de derivar/verificar/exportar.

### D. Cortafuegos de políticas activo (`LiveFirewall`)
Cada solicitud de firma supera una evaluación lineal antes de exponer material criptográfico: límite de frecuencia (`max_daily_tx`), límite de volumen/valor fiat (**personalizable a cualquier valor**, `0` = ilimitado), validación obligatoria de destino contra **listas blancas de DEX/CEX**, `chain_id` (anti-replay), política por cuenta y **comisión máxima**. Las cuotas solo se asientan si la firma tiene éxito.

### E. Disyuntor táctico (Circuit Breaker)
`Operational` → `Frozen` (congelación forense ante violación) → `HardLocked` (aislamiento permanente tras 3 fallos de integridad, requiere reinicio del binario). Rearme físico local con las 5 cajas + frase maestra, comparación en tiempo constante y borrado `Zeroize`.

### F. Auditoría firmada e integridad
- **Registro Web3 encadenado y firmado (Ed25519):** cada decisión se enlaza por hash y se firma con una clave de dispositivo derivada del vault; eleva la garantía de "detecta edición parcial" a "detecta reescritura total". Verificable desde la UI (`V` en el Monitor de Auditoría).
- **Verificador de credenciales read-only sin efectos** para re-confirmaciones de identidad (un fallo no toca el contador del vault), con **opción destructiva configurable** (Ajustes, tecla `Z`) para quien mantiene backup externo.

### G. Extensión Web3 EIP-1193 (para dApps)
- Proveedor `window.ethereum`/`window.livencrypt` (Manifest V3) que enruta cada método al núcleo seguro vía host nativo `com.livencrypt.gateway`.
- Allowlist de orígenes por dominio (TTL 24 h, por método); errores normalizados EIP-1193 (`4001/4100/4200/4900`).
- Métodos operativos: `eth_requestAccounts`, `eth_accounts`, `eth_chainId`, `net_version`, `eth_getBalance`, `eth_getTransactionCount`, `eth_gasPrice`, `livencrypt_prepareTransaction`, `eth_sendTransaction`, `livencrypt_status`.
- Pendientes (hoja de ruta): `eth_estimateGas`, `personal_sign`, `eth_signTypedData_v4` (EIP-712/Permit2) y conmutación multicadena.

### H. Blindaje del sistema operativo y memoria
- **Process Hardening:** `libc::prctl` deshabilita volcados (`PR_SET_DUMPABLE = 0`), restringe ptrace y fija `RLIMIT_CORE = 0`.
- **Boot Shield:** cifra plantillas críticas en reposo con ChaCha20Poly1305, las monta en RAM aislada y destruye trazas mediante ganchos de initramfs.
- **Seccomp y sandbox de firma:** la firma puede ejecutarse en un proceso hijo aislado por *namespaces* (sin red); filtros seccomp del sistema.
- **Monitor heurístico (`ai_monitor`):** puntúa syscalls anómalas (inyección, montajes corruptos, depuradores) y puede disparar el aislamiento del llavero.

### I. Usabilidad y prevención de errores de entrada
- **Pegado del portapapeles:** `Ctrl+V` o **doble clic** sobre la caja pegan los datos (evita errores al teclear direcciones/IDs).
- **Validación por tipo de campo:** los campos numéricos (USD/BTC/ETH y montos) solo aceptan dígitos + separador decimal; los de texto aceptan texto+números+caracteres especiales.

## 3. Estructura del proyecto

```
├── Cargo.toml                          # Dependencias criptográficas y empaquetado
├── README.md
├── DOCS/                               # Documentación local (no versionada)
├── src-tui/
│   ├── extension/livencrypt-web3/      # Extensión Web3 EIP-1193 (Manifest V3)
│   │   ├── manifest.json  background.js  content.js  inject.js  popup.*
│   ├── scripts/                        # Empaquetado, AppArmor, initramfs, mensajería nativa
│   ├── tests/blockchain_gateway_tests.rs
│   └── src/
│       ├── lib.rs                      # Inicializador del núcleo y endurecimiento
│       ├── main.rs                     # TUI: pasarela "w", auditor "k", pegado validado
│       ├── crypto/
│       │   ├── file_cipher.rs  positional.rs  secure_text.rs
│       │   └── blockchain/             # Subsistema Web3 y gobernanza criptográfica
│       │       ├── address.rs          # Direcciones (EIP-55, P2PKH/P2WPKH, red, checksums)
│       │       ├── breaker.rs          # Disyuntor táctico
│       │       ├── chain_requirements.rs
│       │       ├── eth_abi.rs  eth_rlp.rs  eth_simulation.rs  eth_tx.rs  eth_types.rs
│       │       ├── firewall.rs         # Cuotas, listas blancas, política de cuenta/comisión
│       │       ├── multi_curve.rs      # BIP-32/44 secp256k1 + SLIP-10 ed25519, clave de auditoría
│       │       ├── nodes.rs            # Registro de nodos y perfiles de conectividad
│       │       ├── preflight.rs        # Análisis de riesgo pre-firma Ethereum
│       │       ├── price_import.rs     # Importación de precios firmados (.lvcprices)
│       │       ├── proxy.rs            # Canal de mensajería nativa stateless
│       │       ├── rpc.rs  rpc_manager.rs  rpc_quorum.rs  rpc_client.rs  rpc_types.rs
│       │       ├── rpc_bitcoin.rs  rpc_ethereum.rs  rpc_solana.rs
│       │       ├── supervisor.rs       # Orquestador, firma, prevalidación, sockets Unix
│       │       ├── tx_parser.rs        # Parseo de transacciones (sin firma a ciegas)
│       │       ├── types.rs            # Tipos compartidos (peticiones/respuestas/políticas)
│       │       ├── web3_audit.rs       # Auditoría encadenada y firmada (Ed25519)
│       │       └── worker.rs           # Worker asíncrono, broadcast, anti-slowloris
│       └── security/
│           ├── ai_monitor.rs  apparmor.rs  audit.rs  boot_shield.rs  forensics.rs
│           ├── install_profile.rs  loader.rs  network_profile.rs  platform_windows.rs
│           ├── process_hardening.rs  recovery.rs  sandbox.rs  seccomp.rs
│           ├── sign_sandbox.rs        # Firma en proceso hijo aislado (sin red)
│           ├── updates.rs
│           └── vault.rs               # Boot Shield, derivación de clave, verificador read-only
```

## 4. Requisitos del sistema e instalación

**Requisitos previos:** Linux (kernel con AppArmor recomendado), Rustc/Cargo (edición 2021+), navegador con mensajería nativa (Brave, Chrome o Chromium).

**Compilación y empaquetado Debian:**
```bash
chmod +x src-tui/scripts/build-deb.sh
./src-tui/scripts/build-deb.sh
sudo dpkg -i target/debian/livencrypt-core_2.11.0_amd64.deb
```

Al instalar, las utilidades configuran de forma atómica: límites del sistema (`99-livencrypt.conf`, core 0 + mlock), confinamiento AppArmor (`usr.bin.livencrypt-core`) y el registro del manifiesto de mensajería nativa (`com.livencrypt.gateway.json`) en Chrome/Chromium/Brave.

**Extensión Web3:** cargar `src-tui/extension/livencrypt-web3/` en el navegador (modo desarrollador) y aprobar el dominio de la dApp la primera vez.

## 5. Uso básico

```bash
livencrypt-core
```
En el primer arranque se ejecuta el análisis heurístico y se solicita configurar la matriz de 5 cajas + frase maestra para instanciar el llavero volátil en RAM.

**Controles principales:**
- `w` — Pasarela Web3 / custodia · `k` — Auditor visual de direcciones.
- En la pasarela: `P` políticas · `S` reglas · `$` precios · `I` inspector RPC · `N` nodos · `M` perfil · `Y` red · `R` rearme del disyuntor.
- Firma/broadcast: `F10`/`A` autoriza · `Esc`/`D` rechaza.
- En el auditor: `Enter` deriva · `V` verifica (doble derivación) · `C` copia · `n` red · `[Verificar]` compara dirección.
- Entrada de datos: `Ctrl+V` o **doble clic** pegan del portapapeles (validado por tipo de campo).
- Ajustes: `Z` activa/desactiva la re-confirmación destructiva del auditor.
- `Tab` cambia de campo · `Esc` vuelve al Dashboard.

## 6. Licencia y derechos de autor

Software libre bajo **GNU General Public License v3.0**.

```
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
```

Consulta el archivo `LICENSE` en la raíz del repositorio para el texto legal íntegro y las garantías de exención de responsabilidad.
