# Resumen de integración — Livencrypt 2.0

Documento de traspaso para David. Resume todo el trabajo realizado en la rama
`feature/dev-alexander` del repositorio `Synergia86/Livencrypt.2.0`.

- **Rama:** `feature/dev-alexander`
- **Commits (de más antiguo a más reciente):**
  1. `34a4905` — autenticación del rearme del disyuntor + fuga de fuerza bruta en cifrado de archivo
  2. `d75a87a` — firma Solana nativa + endurecimientos varios
  3. `34b4b71` — seccomp, sandbox de firma, Boot Shield, texto AEAD
  4. `9c45b28` — UI de texto a AEAD, sandbox sin sudo, ChainAdapter, nodos
  5. `0a17d64` — API real de seccompiler, limpieza del modal, aislamiento Windows
  6. `8d861bf` — gestor de nodos con QR, espacio de claves libre con NFC, ACL en IPC
- **Aviso clave:** todo se ha escrito sin compilar en local (entorno de desarrollo Windows, crate Linux-only). **Debe pasar `cargo build` y `cargo test` en Linux x86_64.** `cargo` regenerará `Cargo.lock` con las dependencias nuevas.

---

## 1. Estado por módulo

| Módulo / funcionalidad | Estado | Detalle |
| :--- | :--- | :--- |
| Rearme del disyuntor (autenticación real) | Hecho | Verificación exacta de cajas + frase, tiempo constante, fail-closed. |
| Cifrado de archivo (fuga de hashes) | Hecho | Eliminados los SHA-256 sin sal de cajas/referencia; AEAD como única autoridad. |
| Firma Solana nativa | Hecho | Parser del mensaje binario serializado; firma ed25519 válida y retransmisible. |
| Argon2id del llavero | Hecho | Subido de 64 a 128 MiB. |
| Condición de carrera DoS (sockets) | Hecho | Reserva de slot atómica con `compare_exchange`. |
| Desviación silenciosa de índice BIP32 | Hecho | `Result::Err` estricto, sin avanzar el índice. |
| Retroceso de reloj en cuotas | Hecho | Reinicio diario con reloj monotónico (`Instant`). |
| Destino inmutable (`target_dex_cex_id`) | Hecho | Obligatorio; coincide con destino real + lista blanca. |
| Monitor de syscalls (seccomp BPF) | Hecho | Lista negra de syscalls peligrosas; `LIVENCRYPT_SECCOMP`. |
| Monitor de riesgo del entorno | Hecho | `current_risk_score` real; dispara HardLocked si es crítico. |
| Sandbox de firma por namespaces | Hecho | `CLONE_NEWUSER` + `NEWNET/NEWNS/NEWPID` + doble fork; sin sudo; `LIVENCRYPT_SIGN_SANDBOX`. |
| Higiene multiarquitectura seccomp | Hecho | `SYS_iopl`/`SYS_ioperm` aisladas a `cfg(any(x86, x86_64))`. |
| Validación ACL en sockets IPC | Hecho | `SO_PEERCRED` en `worker.rs` y `supervisor.rs`. |
| Boot Shield (initramfs) | Hecho | Sellado/verificación ChaCha20Poly1305 + binario CLI `livencrypt-boot-shield`. |
| Texto cifrado fuerte (AEAD) | Hecho | UI usa solo `cipher_text_secure`/`decipher_text_secure`; posicional extirpado del menú. |
| Espacio de claves libre + NFC | Hecho | Sin longitud mínima; normalización NFC antes del KDF. |
| Abstracción multicadena (`ChainAdapter`) | Hecho (síncrono) | Trait + adaptadores BTC/ETH/SOL + `adapter_for`. |
| Infraestructura de nodos (`nodes.toml`) | Hecho | `NodeRegistry` + pantalla `NodesManager` (lectura, edición, recarga, guardado). |
| Código QR ASCII | Hecho | `qr_lines` con bloques Unicode, en el detalle del nodo. |
| Aislamiento macOS | Hecho (best-effort) | `sandbox_init` con perfil `deny network*`. |
| Aislamiento Windows | Parcial | `SetProcessMitigationPolicy` por FFI; el port completo (Named Pipes) es pendiente. |
| Reconstrucción de tx firmada ETH/BTC | Pendiente | Solana hecho; ETH/BTC devuelven error explícito (RLP/scriptSig por implementar). |
| Internacionalización (i18n) | Pospuesto | Fase final por regla del documento original. |

---

## 2. Detalle por área

### 2.1. Núcleo criptográfico
- **Disyuntor** (`crypto/blockchain/breaker.rs`, `main.rs`): el rearme ya no aceptaba cualquier credencial (el chequeo `is_empty()` sobre `[u8;32]` nunca disparaba). Ahora se vincula la combinación exacta de 5 cajas + frase maestra al inicializar la pasarela y se compara en tiempo constante. Reactiva el HardLock a los 3 fallos. Cuatro tests unitarios.
- **Cifrado de archivo** (`crypto/file_cipher.rs`): la cabecera publicaba SHA-256 sin sal de las cajas y la referencia (valores de baja entropía), forzables offline sin pagar Argon2. Se eliminan; el AEAD (que ya incluye esos datos en la clave) es la única autoridad. Lectura compatible con archivos antiguos.
- **Texto** (`crypto/secure_text.rs`): motor Argon2id + XChaCha20Poly1305, no determinista y autenticado. Sin longitud mínima de clave. Normalización Unicode NFC de la frase antes del KDF.

### 2.2. Pasarela Web3
- **Solana** (`crypto/blockchain/tx_parser.rs`, `multi_curve.rs`): se sustituyó el parser JSON por un decodificador del mensaje Solana serializado real (cabecera, cuentas compact-u16, blockhash, instrucciones; transferencia del System Program; dirección en base58). ed25519 firma esos bytes, por lo que la firma es válida para retransmisión.
- **Firewall** (`crypto/blockchain/firewall.rs`, `supervisor.rs`): `target_dex_cex_id` es obligatorio y debe coincidir con un destino real de la transacción y estar en lista blanca; cuotas diarias con reloj monotónico.
- **BIP32** (`multi_curve.rs`): la derivación secp256k1 ya no avanza el índice en silencio; devuelve error si el candidato es inválido.
- **`ChainAdapter`** (`crypto/blockchain/mod.rs`): trait que unifica el parseo y la reconstrucción del mensaje firmado, con adaptadores para Bitcoin, Ethereum y Solana y un dispatcher `adapter_for`. La reconstrucción está implementada para Solana; ETH y BTC devuelven un error de "pendiente". Es síncrono: el crate no tiene runtime asíncrono y un trait async sería código muerto.

### 2.3. Subsistemas de kernel (zero-trust)
- **seccomp** (`security/seccomp.rs`): filtro BPF (crate `seccompiler`) que deniega (acción `Trap`) syscalls peligrosas — `ptrace`, `kexec_load`, módulos del kernel, `mount`, `setns`, etc.; `SYS_iopl`/`SYS_ioperm` solo en x86/x86_64. Se activa con la variable `LIVENCRYPT_SECCOMP` para no bloquear el arranque por defecto.
- **Monitor** (`security/ai_monitor.rs`): `current_risk_score` puntúa el entorno real (binario manipulado, `LD_PRELOAD`, root, dumpable, mlock) leyendo el estado sin reinicializarlo; el supervisor pasa a HardLocked si supera el umbral.
- **Sandbox de firma** (`security/sign_sandbox.rs`, `supervisor.rs`): la firma se ejecuta en un proceso hijo aislado con `unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID)` y un segundo fork para que el namespace de PID surta efecto real; sin red para impedir exfiltración; fail-closed si no logra aislarse. Se activa con `LIVENCRYPT_SIGN_SANDBOX`.
- **IPC** (`crypto/blockchain/worker.rs`, `supervisor.rs`): validación `SO_PEERCRED` del par (rechaza UID distinto al del operador) en ambos servidores de socket; reserva de conexiones atómica.
- **Boot Shield** (`security/boot_shield.rs` + `src/bin/livencrypt-boot-shield.rs`): sellado y verificación de la configuración de arranque con ChaCha20Poly1305 y utilidad CLI `seal`/`unseal`/`verify` para ganchos de initramfs.

### 2.4. Frontend (TUI)
- **Texto a cifrado fuerte** (`main.rs`): la pantalla de texto opera exclusivamente con el motor AEAD; se extirpó `PositionalCipher` del flujo y se eliminó el modal durmiente de contraseña posicional. La etiqueta del material secreto pasó a "Clave secreta".
- **Gestor de nodos** (`main.rs`, `crypto/blockchain/nodes.rs`): pantalla `Screen::NodesManager` accesible con `N` desde Ajustes. Lista las cadenas registradas, muestra los endpoints (principal y respaldos) con el activo marcado, permite conmutar el nodo activo en caliente (Espacio), editar el endpoint principal (E), recargar desde disco (R), guardar a `nodes.toml` (G) y copiar el endpoint (Ctrl+C). El buffer de edición se purga con Zeroize al salir.
- **Código QR** (`main.rs`): `qr_lines` renderiza la matriz QR del endpoint activo con bloques Unicode condensados para escaneo offline.

### 2.5. Portabilidad
- **macOS** (`security/sign_sandbox.rs`): aislamiento de la firma con `sandbox_init` (perfil `deny default` / `deny network*` / `allow file-read*`).
- **Windows** (`security/platform_windows.rs`): endurecimiento por `SetProcessMitigationPolicy` (prohibición de código dinámico y carga de binarios firmados) mediante FFI nativa.

---

## 3. Dependencias nuevas
- `bs58 = "0.5"` — direcciones Solana en base58.
- `toml = "0.8"` — lectura/escritura de `nodes.toml`.
- `qrcode = "0.14"` — generación de la matriz QR.
- `unicode-normalization = "0.1"` — normalización NFC de frases.
- `seccompiler = "0.4"` — filtro seccomp (solo Linux: `[target.'cfg(target_os = "linux")'.dependencies]`).

---

## 4. Cómo compilar y verificar (Linux x86_64)
1. `cargo build` (regenera `Cargo.lock`).
2. `cargo test` (incluye tests de breaker, firewall, tx_parser, secure_text, boot_shield, nodes).
3. Variables de entorno opcionales para activar las defensas de kernel:
   - `LIVENCRYPT_SECCOMP=1` — aplica el filtro de syscalls.
   - `LIVENCRYPT_SIGN_SANDBOX=1` — firma dentro del sandbox por namespaces.
4. Binario auxiliar: `cargo build --bin livencrypt-boot-shield`.

---

## 5. Pendientes y avisos honestos
1. **Compilación**: el `NodesManager` es una pantalla TUI nueva escrita sin compilar; es lo más probable que requiera un retoque menor (tipos de `ratatui`, API exacta de `qrcode` 0.14, algún borrow). Igualmente conviene verificar la API de `seccompiler` 0.4.
2. **`nodes.toml` en claro**: se guarda como fichero en el directorio local, no cifrado dentro del vault. Integrarlo en el vault es una iteración aparte.
3. **Sin prueba de conectividad de nodos**: la aplicación es un firmante offline (sin pila de red), por lo que no hay ping/RPC real; el panel solo gestiona configuración.
4. **NFC**: solo se aplica al motor de texto (nuevo). El KDF del vault y de ficheros no se tocó para no invalidar credenciales existentes.
5. **Argon2id del llavero a 128 MiB** cambia el `master_seed` derivado respecto a versiones previas: las direcciones de wallet derivadas cambian (los vaults existentes siguen abriéndose con sus parámetros guardados).
6. **Reconstrucción ETH/BTC** en `ChainAdapter`: pendiente (recodificación RLP con v,r,s y scriptSig por entrada).
7. **Windows**: el módulo de mitigaciones está, pero el build completo en Windows requiere migrar todo el código unix (worker/supervisor/vault) e IPC a Named Pipes — esfuerzo dedicado.
8. **i18n**: pospuesto a la fase final por la regla del documento de hoja de ruta.

---

## 6. Disciplina aplicada
- `unsafe` localizado en `seccomp`, `sign_sandbox` y `platform_windows`; el resto del crate mantiene `#![deny(unsafe_code)]`.
- Material sensible (claves derivadas, buffers de frase y de edición) purgado con `Zeroize`.
- Sin notas de cambio dentro de los archivos; encabezados de rol respetados.
- Ortografía española con mayúscula solo inicial en títulos y textos.
