> ⚠️ **DOCUMENTO OBSOLETO (2026-06-13).** Este catálogo describía los huecos **antes de implementarlos**; ya fueron integrados (C.1–C.9 y C.11) en la rama `feat/integracion-w-k-auditoria`. El estado actual y el código restante a integrar están en **`AUDITORIA_FUNCIONES_W_CUSTODIA_K_AUDITOR_ESTADO_ACTUAL.md`**. Se conserva solo como referencia histórica.

# Auditoría de funciones — `w` Pasarela Web3 / Custodia y `k` Auditor visual de direcciones públicas

> **Proyecto:** LIVENCRYPT 2.0 · TUI (`src-tui`)
> **Fecha de auditoría:** 2026-06-13
> **Alcance:** código y funciones de los dos flujos accesibles desde el Dashboard mediante las teclas `w` (`Screen::WalletGateway`) y `k` (`Screen::WalletAuditor`).
> **Tipo:** auditoría de implementación + análisis de huecos (qué funciones faltan integrar para que la seguridad y el uso real sean completos).
> **Método:** lectura directa del código fuente. Cada afirmación referencia `archivo:línea`.

Mapeo de teclas (origen): `src-tui/src/main.rs:2869-2870`

```rust
KeyCode::Char('w') | KeyCode::Char('W') => state.screen = Screen::WalletGateway,
KeyCode::Char('k') | KeyCode::Char('K') => state.screen = Screen::WalletAuditor,
```

---

## 1. Resumen ejecutivo

Ambos flujos están **implementados y operativos en su núcleo**, con una arquitectura de custodia de defensa en profundidad (parser obligatorio → firewall por capas → política de cuenta → circuit breaker → autorización local en dos pasos). El motor criptográfico de derivación y firma multicurva es real (secp256k1 + ed25519, BIP32/SLIP10). La separación de privilegios entre el flujo `k` (solo claves públicas, **no firma**) y el flujo `w` (firma bajo autorización) está bien delimitada.

Sin embargo, existen **huecos concretos** que afectan a la seguridad de presentación (anti-spoofing de direcciones) y al funcionamiento real de extremo a extremo (broadcast, estimación de comisiones, importación de precios desde la UI, cadenas adicionales).

### Veredicto por flujo

| Flujo | Núcleo | Seguridad de firma/custodia | Seguridad de presentación | Funcionamiento real E2E |
|-------|--------|-----------------------------|---------------------------|--------------------------|
| `w` Pasarela / Custodia | ✅ Completo | ✅ Sólido (multicapa + breaker) | n/a | ⚠️ Parcial (broadcast bloqueado, fee estimation, `.lvcprices` sin UI) |
| `k` Auditor direcciones | ✅ Completo | ✅ No firma (aislado) | ⚠️ Débil (sin EIP-55, sin re-derivación verificable, sin gate Boot Shield) | ✅ Operativo |

### Tabla de severidad de hallazgos

| ID | Hallazgo | Severidad | Flujo | Ubicación |
|----|----------|-----------|-------|-----------|
| H-1 | Direcciones Ethereum sin checksum EIP-55 (todo minúsculas) | **Alta** | `k` | `address.rs:13-16` |
| H-2 | Sin re-derivación verificable ni doble-comprobación de la dirección mostrada | **Alta** | `k` | `main.rs:2887`, `multi_curve.rs:95` |
| H-3 | Auditor deriva sin re-confirmación Boot Shield (TUI ya desbloqueada) | Media | `k` | `main.rs:2887-2916` |
| H-4 | Bitcoin solo P2PKH legacy (`0x00`); sin SegWit/bech32 | Media | `k` | `address.rs:50-59` |
| H-5 | Mainnet cableado; sin conciencia testnet/mainnet | Media | `k`/`w` | `address.rs:39-48` |
| H-6 | Log de auditoría = hash-chain SHA256 **no firmado** | Media | `w`/`k` | `web3_audit.rs:42-76` |
| H-7 | `BroadcastTransaction` bloqueado (stub deliberado) | Media (funcional) | `w` | `supervisor.rs:246-252` |
| H-8 | Estimación de comisiones RPC incompleta | Media (funcional) | `w` | `rpc_manager.rs`, `rpc_ethereum.rs` |
| H-9 | Importación `.lvcprices` firmada existe en backend pero **sin cableado UI** | Baja (funcional) | `w` | `main.rs:3966`, `price_import.rs:38` |
| H-10 | Parsers Monero/Zcash/Starknet no integrados (rechazo explícito) | Baja (alcance) | `w` | `tx_parser.rs:41-46` |
| H-11 | Sin validación de checksum de direcciones de entrada (BTC/ETH/SOL) | Media | `k`/`w` | `address.rs` (ausente) |

> **Nota:** "stub deliberado" (H-7) y "rechazo explícito" (H-10) son decisiones de diseño fail-closed correctas; se listan porque limitan el **uso real** hasta que se integren los adaptadores auditados.

---

## Parte A — `w` Pasarela Web3 / Custodia

### A.1 Mapa de flujo de extremo a extremo

```
Extensión/App externa
   │  (ExtensionRequest::SignTransaction, JSON sobre socket)
   ▼
spawn_socket_reader ─► Web3WorkerCmd::IncomingWebRequest(payload, stream)   worker.rs:298
   ▼
process_command ─► supervisor.preview_sign_transaction(&sign_request)        worker.rs:733 → supervisor.rs:256
   │   1) riesgo crítico IA → trigger_hard_lock                              supervisor.rs:263
   │   2) estado breaker (HardLocked/Frozen → rechazo)
   │   3) parse_tx_payload(chain, raw)                                       tx_parser.rs:36
   │   4) firewall.validate_parsed_transaction                              firewall.rs:112
   │   5) firewall.validate_target_destination_id                          firewall.rs:202
   │   6) firewall.effective_volume_units                                   firewall.rs:596
   │   7) firewall.validate_account_policy                                 firewall.rs:247
   │      (cualquier fallo → register_integrity_failure → trip/hard_lock)   supervisor.rs:334
   ▼
event_tx.send(Web3WorkerEvent::SigningRequest(preview))                     worker.rs:759
   ▼
TUI: Web3WorkerEvent::SigningRequest → pending_signing_preview              main.rs:2066
   ▼
Operador: F10/A autoriza · Esc/D rechaza                                    main.rs:3301
   ▼
submit_signing_authorization → Web3WorkerCmd::AuthorizeSigning              main.rs:3315
   ▼
process_command(AuthorizeSigning) → run_loop_iteration(SignTransaction)     worker.rs:680 → supervisor.rs:37
   │   (acceso a clave privada SOLO aquí, tras autorización)
   ▼
write_native_message(stream, signed_bytes)  →  extensión hace broadcast     proxy.rs
```

**Principio de seguridad clave:** la prevalidación (`preview_sign_transaction`) se ejecuta **sin** acceder a la clave privada y **sin** firmar; la firma real (`run_loop_iteration`) solo ocurre tras la autorización local explícita del operador.

### A.2 Inventario de funciones implementadas

| Función | Archivo:línea | Rol | Estado |
|---------|---------------|-----|--------|
| `handle_wallet_gateway_key` | `main.rs:3332` | Teclas del gateway (campos, P/S/$/I/N/E/M/R) | ✅ |
| `handle_wallet_gateway_mouse` | `main.rs:2441` | Clics en campos y secciones | ✅ |
| `submit_wallet_gateway_field` | `main.rs:3452` | Envía `UpdateRules`/`SetManualPrice`/`AddDexContract`/`AddCexDestination` | ✅ |
| `draw_wallet_gateway` | `main.rs:6623` | Render (estado, límites, listas blancas, precios) | ✅ |
| `draw_wallet_gateway_reset_modal` | `main.rs:7239` | Modal de rearme del breaker (5 cajas + frase) | ✅ |
| `handle_signing_authorization_key` | `main.rs:3301` | F10/A aprueba · Esc/D rechaza | ✅ |
| `submit_signing_authorization` | `main.rs:3315` | Envía `Web3WorkerCmd::AuthorizeSigning` | ✅ |
| `Web3BackgroundWorker::spawn` | `worker.rs:160` | Hilo worker + lector de socket | ✅ |
| `process_command` | `worker.rs:312` | Despacha todos los `Web3WorkerCmd` | ✅ |
| `preview_sign_transaction` | `supervisor.rs:256` | Prevalidación sin firma | ✅ |
| `run_loop_iteration` | `supervisor.rs:37` | Firma real + serialización | ✅ |
| `register_integrity_failure` | `supervisor.rs:334` | Contador de fallos → hard lock a los 3 | ✅ |
| `validate_parsed_transaction` | `firewall.rs:112` | Límites diarios, chain_id, método, volumen, listas blancas | ✅ |
| `validate_target_destination_id` | `firewall.rs:202` | Coincidencia destino ↔ DEX/CEX declarado | ✅ |
| `validate_account_policy` | `firewall.rs:247` | Política por cuenta (ventana, montos, fiat, confirmación) | ✅ |
| `effective_volume_units` | `firewall.rs:596` | Volumen efectivo de la tx | ✅ |
| `parse_tx_payload` | `tx_parser.rs:36` | Parser ETH/BTC/SOL (rechaza no soportadas) | ✅ (parcial cadenas) |
| `GatewaySecurityState` | `breaker.rs:10` | `Operational`/`Frozen`/`HardLocked` | ✅ |
| `import_signed_price_file` | `price_import.rs:38` | Verifica `.lvcprices` Ed25519 + antigüedad | ✅ (sin UI) |
| `ExtensionRequest::BroadcastTransaction` | `supervisor.rs:246` | Bloqueado fail-closed | ⛔ stub |

**Pantallas auxiliares del gateway** (handlers en `main.rs`): `Web3AccountPolicies` (P), `Web3ScheduledRules` (S), `Web3PriceOracle` ($), `Web3RpcInspector` (I), `Web3AccountEditor` (E) — todas implementadas con su CRUD respectivo.

### A.3 Modelo de seguridad (lo que protege hoy)

- **Autorización local en dos pasos:** ninguna firma sin que el operador pulse F10/A en la TUI (`main.rs:3301-3330`).
- **Validación por capas previa a la clave privada:** parser + 4 validaciones de firewall antes de exponer el secreto.
- **Listas blancas obligatorias:** destinos DEX/CEX/ERC-20 deben estar declarados; `validate_target_destination_id` exige coincidencia (`firewall.rs:202`).
- **Circuit breaker fail-closed:** 3 fallos de integridad → `HardLocked` irreversible salvo reinicio (`supervisor.rs:334-339`); rearme con comparación en tiempo constante (`breaker.rs`).
- **Anti-replay:** `chain_id` validado obligatoriamente (`firewall.rs`, capa de `validate_parsed_transaction`).
- **Zeroización:** payloads y campos secretos se limpian (`worker.rs` zeroiza payload; `main.rs:1403` `clear_gateway_secret_fields`; `Drop` en `BroadcastTransactionRequest` `types.rs:183`).
- **Auditoría:** cada decisión se encadena en `web3_audit.jsonl` con hash SHA256 (`web3_audit.rs:42`).

### A.4 Huecos del flujo `w` (resumen; detalle en Parte C)

- **H-7** Broadcast bloqueado: `supervisor.rs:246` devuelve error deliberado. No hay envío real a la red.
- **H-8** Estimación de comisiones: comandos RPC aceptados pero sin adaptador de `fee/gas` completo por cadena.
- **H-9** `.lvcprices`: el verificador Ed25519 **ya existe** (`price_import.rs:38`); falta el selector de fichero y la llamada desde el handler del oráculo (`main.rs:3966`, `main.rs:7156`).
- **H-10** Parsers Monero/Zcash/Starknet: rechazo explícito en `tx_parser.rs:41-46`.
- **H-6** Auditoría no firmada: la cadena de hashes detecta edición parcial pero no reescritura total del fichero.

---

## Parte B — `k` Auditor visual de direcciones públicas

### B.1 Mapa de flujo de derivación

```
TUI (Screen::WalletAuditor)
   │  Enter
   ▼
submit_wallet_auditor_derivation                                           main.rs:2887
   │  valida índices u32 · selected_auditor_chain
   ▼
Web3WorkerCmd::DerivePublicKey { chain, account_index, address_index }     worker.rs (cmd) → 649
   ▼
ExtensionRequest::DeriveKey → run_loop_iteration                            worker.rs:655
   ▼
UniversalKeymaster::get_public_key                                         multi_curve.rs:95
   │   BTC/ETH → derive_bip32_secp_path (secp256k1)                        multi_curve.rs:228
   │   SOL     → derive_slip10_ed25519_path (ed25519, todo endurecido)     multi_curve.rs:274
   ▼
Web3WorkerEvent::PublicKeyDerived { result: Ok(pubkey) }                    worker.rs:668
   ▼
TUI recibe evento                                                          main.rs:2071
   │   address::public_address(&chain, &pubkey)                            address.rs:10
   │   auditor_public_key_hex = hex::encode(pubkey)
   ▼
draw_wallet_auditor (dirección, hex, QR ASCII, fingerprint, clipboard)     main.rs:7310
```

**Aislamiento clave:** el auditor **solo** emite `DerivePublicKey`; nunca `SignTransaction`. El subtítulo de la pantalla lo declara: "solo deriva claves publicas; no firma transacciones" (`main.rs:7310+`).

### B.2 Inventario de funciones implementadas

| Función | Archivo:línea | Rol | Estado |
|---------|---------------|-----|--------|
| `handle_wallet_auditor_key` | `main.rs:2936` | Teclas (red, cuenta, índice, C copia, Enter deriva) | ✅ |
| `handle_wallet_auditor_mouse` | `main.rs:2999` | Clics (derivar/copiar/volver, focos) | ✅ |
| `submit_wallet_auditor_derivation` | `main.rs:2887` | Valida índices y envía `DerivePublicKey` | ✅ |
| `auditor_chains` | `main.rs:1680` | `[Bitcoin, Ethereum, Solana]` | ✅ |
| `derivation_path_label` | `main.rs:1742` | Etiqueta BIP-44 `m/44'/coin'/acc'/0/idx` | ✅ |
| `public_key_address_label` | `main.rs:1708` | Pubkey → dirección presentable (fallback) | ✅ |
| `wallet_qr_payload` | `main.rs:1760` | JSON para QR (`livencrypt-wallet`) | ✅ |
| `qr_lines` | `main.rs:6462` | Render QR ASCII (medios bloques Unicode) | ✅ |
| `wallet_clipboard_payload` | `main.rs:1781` | JSON "vínculo público" (sin secretos) | ✅ |
| `address_fingerprint_lines` | `main.rs:7522` | Patrón visual mientras está pendiente | ✅ |
| `draw_wallet_auditor` | `main.rs:7310` | Render completo de la pantalla | ✅ |
| `UniversalKeymaster::get_public_key` | `multi_curve.rs:95` | Deriva pubkey por curva | ✅ |
| `derive_bip32_secp_path` | `multi_curve.rs:228` | BIP32 secp256k1 | ✅ |
| `derive_slip10_ed25519_path` | `multi_curve.rs:274` | SLIP10 ed25519 | ✅ |
| `public_address` | `address.rs:10` | Pubkey → dirección (BTC/ETH/SOL) | ✅ (sin EIP-55) |
| `bitcoin_p2pkh_address` | `address.rs:50` | P2PKH Base58Check `0x00` | ✅ (legacy) |

### B.3 Modelo de seguridad y de presentación (hoy)

- **No firma:** el auditor está criptográficamente separado del motor de firma.
- **Zeroización:** `auditor_public_key_hex` y `auditor_address` se limpian al error/cambio de pantalla; `UniversalKeymaster` zeroiza la seed en `Drop` (`multi_curve.rs:20`).
- **Vínculo público sin secretos:** `wallet_clipboard_payload` incluye `scope: "public-address-only"` y `warning` explícito (`main.rs:1781`).
- **Comparación visual:** QR + fingerprint para verificación humana antes de usar la dirección.

### B.4 Huecos del flujo `k` (resumen; detalle en Parte C)

- **H-1** ETH sin EIP-55 (`address.rs:13-16`): la dirección se imprime `0x{hex}` en minúsculas → un typo de capitalización no es detectable.
- **H-2** Sin re-derivación verificable: el operador ve **una** derivación sin garantía de reproducibilidad ni doble comprobación.
- **H-3** Sin gate Boot Shield previo a derivar.
- **H-4** Solo P2PKH legacy en Bitcoin.
- **H-5** Mainnet cableado (sin testnet).
- **H-11** Sin validación de checksum de direcciones introducidas para comparar.

---

## Parte C — Funciones necesarias a integrar (catálogo de remediación con código)

Para cada hueco: **archivo destino**, **código Rust completo a insertar** (cuerpos reales que encajan con los tipos y `use` ya presentes en cada módulo), punto de integración y criterio de seguridad. Verificado contra dependencias reales de `src-tui/Cargo.toml` (`bs58 0.5`, `sha3 0.10`, `ripemd 0.1`, `secp256k1 0.29`, `ed25519-dalek 2.1`, `hmac 0.12`).

### C.0 Dependencias, campos y variantes nuevas requeridas

Cambios de soporte que habilitan el resto del catálogo:

| Cambio | Archivo | Detalle |
|--------|---------|---------|
| Dependencia `bech32 = "0.11"` | `src-tui/Cargo.toml` | Necesaria solo para C.6 (P2WPKH). El resto reutiliza crates existentes. |
| Campo `fee_estimate: Option<String>` | `types.rs` (`SigningRequestPreview`, `types.rs:190`) | C.8: adjuntar comisión estimada al preview de firma. |
| Variantes `Web3WorkerCmd::VerifyDerivation` y `Web3WorkerEvent::DerivationVerified` | `worker.rs:67` / `worker.rs:133` | C.2: re-derivación verificable. |
| Campos `last_identity_confirmation_unix: u64`, `show_reauth_modal: bool`, `pending_action_after_reauth: Option<PendingAction>` | `main.rs` (`TuiState`) | C.4: gate Boot Shield del auditor. |
| Struct `SignedWeb3AuditEvent` (+ campo `event_signature`) | `web3_audit.rs:35` | C.11: sellado firmado del log. |

> Nota de hallazgo refinada tras releer el código: parte del backend de H-8 y H-9 **ya existe** — `RpcEstimateFee` está cableado en `worker.rs:570` (`adapter.estimate_fee`) y `Web3WorkerCmd::ImportSignedPriceFile` existe en `worker.rs:99`. El hueco real es de **presentación/cableado UI**, reflejado abajo.

---

### C.1 Checksum EIP-55 para Ethereum (H-1) — **P0**

**Archivo destino:** `src-tui/src/crypto/blockchain/address.rs` (usa `sha3::Keccak256`, ya importado en `address.rs:8`).

```rust
/// Aplica el checksum de capitalización EIP-55 a un hex de 40 nibbles (con o sin "0x").
pub fn to_eip55_checksummed(address_hex: &str) -> Result<String, String> {
    let clean = address_hex.trim_start_matches("0x").to_ascii_lowercase();
    if clean.len() != 40 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("direccion Ethereum debe tener 40 nibbles hexadecimales".into());
    }
    let hash = Keccak256::digest(clean.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in clean.chars().enumerate() {
        if ch.is_ascii_digit() {
            out.push(ch);
        } else {
            // Nibble alto para índice par, bajo para impar (cada byte cubre 2 caracteres).
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if nibble >= 8 {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
        }
    }
    Ok(out)
}

/// Verifica que una dirección Ethereum cumple el checksum EIP-55.
/// Acepta todo-minúsculas / todo-mayúsculas (sin checksum) y rechaza checksum mixto inválido.
pub fn validate_ethereum_address_checksum(address: &str) -> bool {
    let clean = address.trim_start_matches("0x");
    if clean.len() != 40 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let mixed = clean.chars().any(|c| c.is_ascii_uppercase())
        && clean.chars().any(|c| c.is_ascii_lowercase());
    if !mixed {
        return true; // Sin checksum de capitalización: válido por compatibilidad.
    }
    match to_eip55_checksummed(clean) {
        Ok(expected) => expected.trim_start_matches("0x") == clean,
        Err(_) => false,
    }
}
```

**Integración** — en `public_address` (`address.rs:13-16`), sustituir la rama Ethereum:

```rust
ChainType::Ethereum if public_key.len() == 64 => {
    let hash = Keccak256::digest(public_key);
    to_eip55_checksummed(&hex::encode(&hash[12..]))
}
```

- **Criterio de seguridad:** la capitalización codifica el hash de la propia dirección; un typo deja de pasar desapercibido.

---

### C.2 Re-derivación verificable y doble comprobación (H-2) — **P0**

**Archivo destino 1:** `multi_curve.rs` (dentro de `impl UniversalKeymaster`, junto a `get_public_key`, `multi_curve.rs:95`).

```rust
/// Deriva la clave pública dos veces de forma independiente y las compara en
/// tiempo constante. Devuelve la clave solo si ambas pasadas coinciden.
pub fn rederive_and_verify(
    &self,
    chain: &ChainType,
    account: u32,
    index: u32,
) -> Result<Vec<u8>, String> {
    let first = self.get_public_key(chain, account, index)?;
    let second = self.get_public_key(chain, account, index)?;
    if !constant_time_eq(&first, &second) {
        return Err("derivacion no reproducible: las dos pasadas difieren".into());
    }
    Ok(first)
}
```

Helper a nivel de módulo en `multi_curve.rs` (no introduce dependencias; el repo evita `subtle`):

```rust
/// Comparación en tiempo constante sin cortocircuito por longitud de contenido.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
```

**Archivo destino 2:** `worker.rs`. Variantes nuevas (ver C.0) y handler en `process_command` (junto a `DerivePublicKey`, `worker.rs:649`):

```rust
Web3WorkerCmd::VerifyDerivation {
    chain,
    account_index,
    address_index,
} => {
    // Reutiliza el camino auditado run_loop_iteration → DeriveKey, dos veces.
    let derive = |sup: &mut GatewaySupervisor| -> Result<Vec<u8>, String> {
        let request = ExtensionRequest::DeriveKey(KeyDerivationRequest {
            chain: chain.clone(),
            account_index,
            address_index,
        });
        sup.run_loop_iteration(request).and_then(|bytes| {
            serde_json::from_slice::<ExtensionResponse<Vec<u8>>>(&bytes)
                .map_err(|error| error.to_string())
                .and_then(|response| match response {
                    ExtensionResponse::Success(public_key) => Ok(public_key),
                    ExtensionResponse::Error(error) => Err(error),
                })
        })
    };

    let outcome = derive(supervisor).and_then(|first| {
        derive(supervisor).and_then(|second| {
            if worker_constant_time_eq(&first, &second) {
                let address = address::public_address(&chain, &first)
                    .unwrap_or_else(|_| "address-no-presentable".to_string());
                Ok(address)
            } else {
                Err("derivacion no reproducible".to_string())
            }
        })
    });

    let (matches, address) = match outcome {
        Ok(address) => (true, address),
        Err(_) => (false, String::new()),
    };
    let _ = event_tx.send(Web3WorkerEvent::DerivationVerified {
        chain,
        account_index,
        address_index,
        matches,
        address,
    });
}
```

Helper a nivel de módulo en `worker.rs`:

```rust
fn worker_constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
```

**Archivo destino 3:** `main.rs` — tecla `V` en `handle_wallet_auditor_key` (`main.rs:2936`) que envía `Web3WorkerCmd::VerifyDerivation`, y manejo del evento `DerivationVerified` (junto a `PublicKeyDerived`, `main.rs:2071`) para pintar ✔/✘ y la dirección re-derivada.

- **Criterio de seguridad:** garantiza reproducibilidad de la dirección antes de que el usuario reciba fondos; detecta derivación inconsistente o memoria corrupta.

---

### C.3 Validación de checksum de direcciones de entrada (H-11) — **P1**

**Archivo destino:** `address.rs` (usa `bs58`, `Sha256`, ya importados).

```rust
/// Valida el checksum Base58Check de una dirección Bitcoin P2PKH mainnet (versión 0x00).
pub fn validate_bitcoin_address_checksum(address: &str) -> Result<(), String> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|error| format!("Base58 invalido: {}", error))?;
    if decoded.len() != 25 {
        return Err("longitud Base58Check invalida (esperados 25 bytes)".into());
    }
    if decoded[0] != 0x00 {
        return Err("version no P2PKH mainnet (esperado 0x00)".into());
    }
    let (payload, checksum) = decoded.split_at(21);
    let expected = Sha256::digest(Sha256::digest(payload));
    if checksum != &expected[..4] {
        return Err("checksum Base58Check no coincide".into());
    }
    Ok(())
}

/// Valida que una dirección Solana decodifica a exactamente 32 bytes Base58.
pub fn validate_solana_address(address: &str) -> Result<(), String> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|error| format!("Base58 invalido: {}", error))?;
    if decoded.len() != 32 {
        return Err("clave Solana debe decodificar a 32 bytes".into());
    }
    Ok(())
}
```

- **Integración:** caja "introduce la dirección esperada para comparar" en `draw_wallet_auditor`; validar checksum y comparar con la derivada (cierra el bucle anti-spoofing con C.2).
- **Criterio de seguridad:** confirmación por doble entrada con detección de error de transcripción.

---

### C.4 Gate de re-confirmación Boot Shield en el auditor (H-3) — **P1**

**Archivo destino:** `main.rs` (campos nuevos en `TuiState` según C.0; gate al inicio de `submit_wallet_auditor_derivation`, `main.rs:2887`, y de `copy_wallet_link_payload`, `main.rs:1805`).

```rust
/// Exige re-verificación Boot Shield reciente antes de derivar/exportar en el auditor.
/// Devuelve Ok(()) si la sesión re-validó credenciales dentro de la ventana; si no,
/// arma el modal de re-autenticación y devuelve Err para abortar la acción en curso.
fn require_boot_shield_confirmation_for_auditor(state: &mut TuiState) -> Result<(), String> {
    const AUDITOR_REAUTH_WINDOW_SECS: u64 = 120;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(state.last_identity_confirmation_unix) <= AUDITOR_REAUTH_WINDOW_SECS {
        return Ok(());
    }
    state.pending_action_after_reauth = Some(PendingAction::AuditorDerive);
    state.show_reauth_modal = true;
    Err("re-confirmacion Boot Shield requerida".into())
}
```

Uso en `submit_wallet_auditor_derivation` (primera línea del cuerpo):

```rust
fn submit_wallet_auditor_derivation(state: &mut TuiState) {
    if let Err(message) = require_boot_shield_confirmation_for_auditor(state) {
        state.auditor_status = message;
        return;
    }
    // … resto del flujo de derivación existente …
}
```

> El modal de re-autenticación debe reutilizar el verificador de credenciales Boot Shield ya existente; al éxito, fijar `last_identity_confirmation_unix = now` y re-disparar `pending_action_after_reauth`.

- **Criterio de seguridad:** acceso físico a una TUI desbloqueada no basta para enumerar/exportar direcciones sin re-autenticar.

---

### C.5 Conciencia de red (testnet/mainnet) (H-5) — **P1**

**Archivo destino:** `address.rs`.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

/// coin_type BIP-44 por red. Por convención BIP-44 toda testnet usa coin_type 1.
pub fn coin_type_for(chain: &ChainType, network: Network) -> u32 {
    match (chain, network) {
        (_, Network::Testnet) => 1,
        (ChainType::Bitcoin, Network::Mainnet) => 0,
        (ChainType::Ethereum, Network::Mainnet) => 60,
        (ChainType::Solana, Network::Mainnet) => 501,
        (ChainType::Monero, Network::Mainnet) => 128,
        (ChainType::Zcash, Network::Mainnet) => 133,
        (ChainType::Starknet, Network::Mainnet) => 9004,
    }
}

/// Versión del prefijo P2PKH Base58Check de Bitcoin según red (0x00 main / 0x6f test).
pub fn bitcoin_p2pkh_version(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0x00,
        Network::Testnet => 0x6f,
    }
}

pub fn chain_id_label_for(chain: &ChainType, network: Network) -> String {
    match (chain, network) {
        (ChainType::Ethereum, Network::Mainnet) => "0x1".to_string(),
        (ChainType::Ethereum, Network::Testnet) => "0xaa36a7".to_string(), // Sepolia
        (ChainType::Bitcoin, Network::Mainnet) => "bitcoin-mainnet".to_string(),
        (ChainType::Bitcoin, Network::Testnet) => "bitcoin-testnet".to_string(),
        (ChainType::Solana, Network::Mainnet) => "solana-mainnet-beta".to_string(),
        (ChainType::Solana, Network::Testnet) => "solana-devnet".to_string(),
        (chain, _) => chain_id_label(chain),
    }
}
```

- **Integración:** parametrizar `bitcoin_p2pkh_address`/`derivation_path` con `Network`; propagarla desde el auditor y el gateway; mostrar la red de forma destacada en `draw_wallet_auditor`/`draw_wallet_gateway`.
- **Criterio de seguridad:** prefijo de versión y coin_type difieren entre redes; evita usar una dirección de testnet como si fuera mainnet.

---

### C.6 Direcciones Bitcoin SegWit/bech32 (H-4) — **P2**

**Cargo.toml:** añadir `bech32 = "0.11"`. **Archivo destino:** `address.rs` (usa `Sha256`, `Ripemd160`, ya importados).

```rust
use bech32::{segwit, Hrp};

/// Dirección P2WPKH (bech32, prefijo "bc1") desde clave pública comprimida de 33 bytes.
pub fn bitcoin_p2wpkh_address(public_key: &[u8], network: Network) -> Result<String, String> {
    if public_key.len() != 33 {
        return Err("clave publica Bitcoin invalida: se esperaban 33 bytes comprimidos".into());
    }
    let sha = Sha256::digest(public_key);
    let witness_program = Ripemd160::digest(sha); // 20 bytes (HASH160)
    let hrp = match network {
        Network::Mainnet => Hrp::parse("bc"),
        Network::Testnet => Hrp::parse("tb"),
    }
    .map_err(|error| format!("HRP bech32 invalido: {}", error))?;
    segwit::encode(hrp, segwit::VERSION_0, &witness_program)
        .map_err(|error| format!("codificacion bech32 fallida: {}", error))
}
```

- **Integración:** ampliar la rama `Bitcoin` de `public_address` con selector de formato (legacy P2PKH / segwit P2WPKH).
- **Criterio de seguridad/uso:** bech32 incorpora detección de errores; compatibilidad con la práctica actual y comisiones menores.

---

### C.7 Broadcast con adaptador RPC auditado (H-7) — **P1 (uso real)**

El trait `ChainRpcAdapter` **ya define** `broadcast_transaction` (`rpc.rs:20`) y existe `adapter_for_chain` (`rpc_manager.rs:12`). El broadcast vive en el **worker** (tiene `NodeRegistry`), no en el supervisor offline.

**Archivo destino 1:** `rpc_manager.rs`.

```rust
/// Difunde una transacción firmada por la cadena indicada usando el adaptador auditado.
/// Bloqueado salvo perfil con escritura RPC habilitada.
pub fn broadcast_raw_transaction(
    registry: &NodeRegistry,
    chain: &str,
    raw_signed_tx: &[u8],
) -> Result<String, String> {
    if !registry.profile().allows_rpc_write() {
        return Err("perfil sin escritura RPC: broadcast bloqueado".into());
    }
    let adapter = adapter_for_chain(registry, chain)?;
    let result = adapter.broadcast_transaction(raw_signed_tx)?;
    Ok(result.txid)
}
```

> Si `allows_rpc_write()` no existe aún en `NodeRegistry::profile()`, añadirlo junto a `allows_rpc_read()` (perfil `RpcOperational`); mantiene fail-closed en `Offline`/`RpcReadOnly`.

**Archivo destino 2:** `worker.rs` — nueva variante `Web3WorkerCmd::AuthorizeBroadcast { request_id, approve }` que sigue **la misma autorización local en dos pasos que la firma**. Tras aprobar:

```rust
let txid = rpc_manager::broadcast_raw_transaction(
    node_registry,
    &chain_name,
    &pending_broadcast.raw_signed_tx,
);
let _ = append_web3_audit_event(Web3AuditEvent {
    timestamp_unix: now_unix(),
    origin: "operador-local".to_string(),
    action: "broadcast".to_string(),
    chain: chain_name.clone(),
    chain_id: chain_id_label.clone(),
    account_index: None,
    address_index: None,
    from: None,
    to: pending_broadcast.to.clone(),
    contract: None,
    method: Some("broadcast_raw_transaction".to_string()),
    selector: None,
    value_native: None,
    value_fiat: None,
    endpoint_summary: vec![],
    decision: match &txid { Ok(_) => "broadcast_ok", Err(_) => "broadcast_error" }.to_string(),
    warnings: vec![],
    payload_sha256: Some(sha256_hex(&pending_broadcast.raw_signed_tx)),
    signature_sha256: None,
});
```

**Archivo destino 3:** `supervisor.rs:246` — el stub se mantiene como guarda offline (devuelve "broadcast bloqueado…"); el broadcast real solo procede por el worker con `NodeRegistry`.

- **Criterio de seguridad:** doble autorización local + perfil con escritura + adaptador auditado + auditoría obligatoria; fail-closed sin nodo verificado.

---

### C.8 Comisión estimada en el preview de firma (H-8) — **P1 (uso real)**

El cálculo ya existe (`adapter.estimate_fee`, cableado en `worker.rs:570`). Falta **mostrarlo al autorizar**.

**Archivo destino 1:** `types.rs` — añadir al `SigningRequestPreview` (`types.rs:190`):

```rust
pub fee_estimate: Option<String>,
```

**Archivo destino 2:** `worker.rs` — en el manejo de `IncomingWebRequest`, tras obtener el `preview` de `preview_sign_transaction` y antes de emitir `SigningRequest`:

```rust
let chain_name = match preview.chain {
    ChainType::Ethereum => "ethereum",
    ChainType::Bitcoin => "bitcoin",
    ChainType::Solana => "solana",
    _ => "",
};
preview.fee_estimate = rpc_manager::adapter_for_chain(node_registry, chain_name)
    .and_then(|adapter| adapter.estimate_fee(&sign_request.raw_tx_payload))
    .map(|fee| format!("{} {} ({})", fee.fee_amount, fee.asset, fee.endpoint))
    .ok(); // None en perfil OFFLINE → el preview lo muestra como "no disponible".
```

**Archivo destino 3:** `main.rs` — `draw_wallet_gateway` (`main.rs:6623`) renderiza `fee_estimate` en el bloque de firma pendiente.

- **Criterio de seguridad/uso:** el operador autoriza conociendo el coste real; habilita políticas de "comisión máxima".

---

### C.9 Cableado UI de importación `.lvcprices` (H-9) — **P2**

Backend completo: verificador Ed25519 `price_import::import_signed_price_file` (`price_import.rs:38`) **y** comando `Web3WorkerCmd::ImportSignedPriceFile { path }` (`worker.rs:99`). Solo falta enviar el comando desde la UI.

**Archivo destino:** `main.rs` (handler del oráculo `Web3PriceOracle`, sustituye el placeholder de `main.rs:3966`).

```rust
/// Envía el fichero de precios firmado al worker (verificación Ed25519 + antigüedad en backend).
fn submit_lvcprices_import(state: &mut TuiState, path_text: &str) {
    let path = std::path::PathBuf::from(path_text.trim());
    if !path.is_file() {
        state.status = "Ruta .lvcprices no encontrada.".to_string();
        return;
    }
    match &state.web3_cmd_tx {
        Some(tx) => {
            let _ = tx.send(Web3WorkerCmd::ImportSignedPriceFile { path });
            state.status =
                "Importacion .lvcprices enviada; verificando firma Ed25519 en backend.".to_string();
        }
        None => {
            state.status = "Web3 no inicializado: no se puede importar precios.".to_string();
        }
    }
}
```

- **Integración:** añadir un campo de ruta en `Web3PriceOracle` y una tecla `I` que invoque `submit_lvcprices_import`; reemplazar el texto `"Importacion .lvcprices pendiente de selector/verificador Ed25519."`.
- **Criterio de seguridad:** ya garantizado por el backend (`price_import.rs:54-73`); solo se expone.

---

### C.10 Parsers de cadenas adicionales (H-10) — **P2 (alcance)**

**Archivo destino:** `tx_parser.rs:41-46` (hoy rechazo explícito). Mantener fail-closed hasta integrar y auditar. Contrato propuesto:

```rust
/// Parser Monero (RingCT/stealth). NO INTEGRADO: requiere librería forense auditada.
fn parse_monero_tx(_raw: &[u8]) -> Result<ParsedTx, String> {
    Err("Monero requiere parser forense especifico no integrado".into())
}

/// Parser Zcash Sapling/Orchard. NO INTEGRADO.
fn parse_zcash_tx(_raw: &[u8]) -> Result<ParsedTx, String> {
    Err("Zcash requiere parser Sapling/Orchard especifico no integrado".into())
}

/// Parser Starknet (calldata / account abstraction). NO INTEGRADO.
fn parse_starknet_tx(_raw: &[u8]) -> Result<ParsedTx, String> {
    Err("Starknet requiere parser de calldata/account abstraction no integrado".into())
}
```

- **Decisión recomendada:** mantener el rechazo explícito; cuando se integren, deben producir un `ParsedTx` con `destinations`/`volume_units` reales para que el firewall pueda validarlos. Documentado para no transmitir falsa cobertura.

---

### C.11 Sellado firmado del log de auditoría (H-6) — **P2**

**Archivo destino:** `web3_audit.rs` (usa `Sha256`, `BufRead`/`BufReader`, ya importados; añadir `use ed25519_dalek::...`).

Struct extendida (junto a `ChainedWeb3AuditEvent`, `web3_audit.rs:35`):

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedWeb3AuditEvent {
    pub previous_hash: String,
    pub event: Web3AuditEvent,
    pub event_hash: String,
    pub event_signature: String, // firma Ed25519 hex de event_hash
}
```

Funciones:

```rust
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Firma el event_hash (hex) con la clave de dispositivo Ed25519. Devuelve la firma hex.
pub fn sign_event_hash(event_hash: &str, device_key: &SigningKey) -> String {
    let signature: Signature = device_key.sign(event_hash.as_bytes());
    hex::encode(signature.to_bytes())
}

/// Verifica la cadena completa: encadenado de hashes + firma de dispositivo por entrada.
pub fn verify_audit_chain(
    path: &std::path::Path,
    device_pubkey: &VerifyingKey,
) -> Result<(), String> {
    let file = std::fs::File::open(path)
        .map_err(|error| format!("no se pudo abrir log de auditoria: {}", error))?;
    let reader = BufReader::new(file);
    let mut previous = "GENESIS".to_string();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: SignedWeb3AuditEvent = serde_json::from_str(&line)
            .map_err(|error| format!("linea {} ilegible: {}", line_no + 1, error))?;
        if entry.previous_hash != previous {
            return Err(format!("ruptura de cadena en linea {}", line_no + 1));
        }
        if event_hash(&entry.previous_hash, &entry.event)? != entry.event_hash {
            return Err(format!("hash no coincide en linea {}", line_no + 1));
        }
        let sig_bytes: [u8; 64] = hex::decode(&entry.event_signature)
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "firma de auditoria debe tener 64 bytes".to_string())?;
        let signature = Signature::from_bytes(&sig_bytes);
        device_pubkey
            .verify(entry.event_hash.as_bytes(), &signature)
            .map_err(|error| format!("firma invalida en linea {}: {}", line_no + 1, error))?;
        previous = entry.event_hash;
    }
    Ok(())
}
```

> `append_web3_audit_event` (`web3_audit.rs:42`) debe pasar a escribir `SignedWeb3AuditEvent` invocando `sign_event_hash`; la clave de dispositivo se deriva del vault (reutilizar el patrón Ed25519 ya presente en `price_import.rs`).

- **Criterio de seguridad:** eleva la garantía de "detecta edición parcial" (hash-chain) a "detecta reescritura total" (firma de dispositivo).

---

## Parte D — Matriz de cobertura y recomendaciones priorizadas

| Prioridad | Acción | Hallazgos | Funciones (Parte C) |
|-----------|--------|-----------|---------------------|
| **P0 — Anti-spoofing de firma/dirección** | EIP-55 + re-derivación verificable | H-1, H-2 | C.1, C.2 |
| **P1 — Seguridad operativa** | Gate Boot Shield, checksum de entrada, conciencia de red | H-3, H-11, H-5 | C.3, C.4, C.5 |
| **P1 — Uso real E2E** | Broadcast auditado + estimación de comisiones | H-7, H-8 | C.7, C.8 |
| **P2 — Completitud** | SegWit, UI `.lvcprices`, sellado de auditoría | H-4, H-9, H-6 | C.6, C.9, C.11 |
| **P2 — Alcance de cadenas** | Parsers Monero/Zcash/Starknet (o mantener rechazo) | H-10 | C.10 |

**Recomendación de secuencia:** C.1 → C.2 (cierran el riesgo de spoofing del auditor, que es el de mayor impacto para un usuario que recibe fondos) → C.4/C.3 (endurecen acceso) → C.7/C.8 (habilitan el ciclo real de transacción) → resto.

---

## Apéndice — Glosario de tipos clave

| Tipo | Archivo:línea | Descripción |
|------|---------------|-------------|
| `Web3WorkerCmd` | `worker.rs:67` | Comandos de la TUI al worker (`DerivePublicKey`, `AuthorizeSigning`, `UpdateRules`, `SetManualPrice`, …) |
| `Web3WorkerEvent` | `worker.rs:133` | Eventos del worker a la TUI (`SigningRequest`, `PublicKeyDerived`, `MetricsUpdated`, …) |
| `SigningRequestPreview` | `types.rs:190` | Resumen de firma mostrado al operador (chain, método, valor, volumen) |
| `AccountPolicy` | `types.rs:204` | Política por cuenta (ventana, montos, fiat, destinos/contratos, confirmación) |
| `BroadcastTransactionRequest` | `types.rs:178` | Solicitud de broadcast (con `Drop` que zeroiza, `types.rs:183`) |
| `GatewaySecurityState` | `breaker.rs:10` | `Operational` / `Frozen { reason, timestamp }` / `HardLocked` |
| `ParsedTx` | `tx_parser.rs` | Resultado del parser (destinos, volumen, chain_id, método, resumen) |
| `UniversalKeymaster` | `multi_curve.rs:16` | Motor de derivación multicurva (seed zeroizada en `Drop`, `multi_curve.rs:20`) |
| `ChainedWeb3AuditEvent` | `web3_audit.rs:36` | Entrada de auditoría encadenada (`previous_hash`, `event`, `event_hash`) |

---

*Documento generado a partir de lectura directa del código en `src-tui/`. Las referencias `archivo:línea` corresponden al estado del árbol en la fecha de auditoría; verificar tras refactors con `grep -n` de los símbolos citados.*
