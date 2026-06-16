# Auditoría de funciones (estado actual) — `w` Pasarela Web3 / Custodia y `k` Auditor visual de direcciones públicas

> **Proyecto:** LIVENCRYPT 2.0 · TUI (`src-tui`)
> **Fecha:** 2026-06-13
> **Alcance:** código y funciones de los dos flujos del Dashboard: `w` (`Screen::WalletGateway`) y `k` (`Screen::WalletAuditor`).
> **Naturaleza:** auditoría del estado **tras integrar** el catálogo de remediación (rama `feat/integracion-w-k-auditoria`). Sustituye, en cuanto a estado, al documento previo `AUDITORIA_FUNCIONES_W_CUSTODIA_K_AUDITOR.md` (que describía los huecos antes de implementarlos).
> **Método:** lectura directa del código. Cada afirmación referencia `archivo:línea` (verificado en esta fecha; reverificar con `grep -n` tras refactors).
> **Verificación:** `cargo check`/`cargo build` sin errores ni warnings; tests del módulo de auditoría en verde.

Mapeo de teclas (`src-tui/src/main.rs:2982-2983`):

```rust
KeyCode::Char('w') | KeyCode::Char('W') => state.screen = Screen::WalletGateway,
KeyCode::Char('k') | KeyCode::Char('K') => state.screen = Screen::WalletAuditor,
```

---

## 1. Resumen ejecutivo

Ambos flujos están **implementados, cableados y operativos**, con defensa en profundidad real:

- **`w` Pasarela/Custodia:** parser obligatorio → firewall por capas → política de cuenta → circuit breaker → **autorización local en dos pasos** para *firma* **y para *broadcast***. La firma muestra la **comisión estimada** antes de autorizar. El broadcast se ejecuta solo con perfil `RpcOperational`, adaptador auditado y auditoría obligatoria.
- **`k` Auditor:** deriva claves públicas (nunca firma), con **checksum EIP-55**, **re-derivación verificable** (doble pasada en tiempo constante), **comparación anti-spoofing** contra una dirección esperada, **selector de red** testnet/mainnet con derivación correcta, **SegWit/bech32** para Bitcoin, y **gate de re-confirmación Boot Shield** antes de derivar/verificar/exportar.
- **Auditoría:** el log Web3 se **sella con firma Ed25519** de dispositivo (cadena de hashes + firma → detecta reescritura total).
- **Configuración:** opción en *Configuraciones* (tecla `Z`) para que la re-confirmación del auditor use un verificador **destructivo** (un fallo destruye el vault) en lugar del *read-only* seguro por defecto.

Queda como pendiente acotado: parsers de Monero/Zcash/Starknet (rechazo *fail-closed* deliberado) y algunas extensiones de alcance descritas en la Parte C.

### Estado por hallazgo histórico

| ID | Hallazgo original | Estado actual | Evidencia |
|----|-------------------|---------------|-----------|
| H-1 | ETH sin EIP-55 | ✅ Implementado | `address.rs:97` `to_eip55_checksummed`, aplicado en `public_address` |
| H-2 | Sin re-derivación verificable | ✅ Implementado | `multi_curve.rs:154`, worker `VerifyDerivation`, tecla `V` |
| H-3 | Auditor sin re-confirmación Boot Shield | ✅ Implementado | `main.rs:3085` gate + modal |
| H-4 | Bitcoin solo P2PKH legacy | ✅ Implementado | `address.rs:200` `bitcoin_p2wpkh_address` |
| H-5 | Sin conciencia testnet/mainnet | ✅ Implementado | `Network` threaded hasta la derivación |
| H-6 | Log de auditoría no firmado | ✅ Implementado | `web3_audit.rs` firma Ed25519 |
| H-7 | Broadcast bloqueado | ✅ Implementado (2 pasos) | worker `AuthorizeBroadcast` + `rpc_manager:34` |
| H-8 | Comisión no mostrada al firmar | ✅ Implementado | `SigningRequestPreview.fee_estimate` |
| H-9 | `.lvcprices` sin UI | ✅ Implementado | `main.rs:4395` `submit_lvcprices_import` |
| H-10 | Parsers Monero/Zcash/Starknet | ⛔ Fail-closed (a propósito) | `tx_parser.rs` rechazo explícito |
| H-11 | Sin validación de checksum de entrada | ✅ Implementado | `address.rs:140/159` + caja de comparación |

---

## Parte A — `w` Pasarela Web3 / Custodia

### A.1 Flujo de firma (extremo a extremo)

```
Extensión/App  ──(ExtensionRequest::SignTransaction, socket)──►
worker IncomingWebRequest  ──► supervisor.preview_sign_transaction          supervisor.rs:258
   parser obligatorio (tx_parser) → firewall x4 capas → política de cuenta
   (cualquier fallo → register_integrity_failure → trip/hard_lock)          supervisor.rs:337
worker adjunta fee_estimate (adapter.estimate_fee)                          worker.rs (estimate_fee_label)
   ──► Web3WorkerEvent::SigningRequest(preview)  ──► TUI modal
Operador: F10/A autoriza · Esc/D rechaza                                    main.rs:3688
   ──► Web3WorkerCmd::AuthorizeSigning ──► run_loop_iteration(SignTransaction)  supervisor.rs:37
   (acceso a clave privada SOLO aquí) ──► respuesta firmada al socket
```

### A.2 Flujo de broadcast (NUEVO — autorización local en dos pasos)

```
Extensión  ──(ExtensionRequest::BroadcastTransaction)──►
worker intercepta (antes del catch-all); exige allows_broadcast()          worker.rs (IncomingWebRequest)
   crea PendingBroadcastRequest + emite Web3WorkerEvent::BroadcastRequest   worker.rs:58 / 168
TUI modal de broadcast (payload_len + SHA-256, "IRREVERSIBLE")             main.rs:6385
Operador: F10/A autoriza · Esc/D rechaza                                    main.rs:3705
   ──► Web3WorkerCmd::AuthorizeBroadcast ──► rpc_manager::broadcast_raw_transaction  rpc_manager.rs:34
   auditoría obligatoria (append_web3_audit_event) + respuesta/txid al socket
```

El stub `supervisor.rs:248` permanece como guarda *offline*; el broadcast real solo procede por el worker con `NodeRegistry`, perfil `RpcOperational` y doble autorización.

### A.3 Inventario de funciones (flujo `w`)

| Función | Archivo:línea | Rol | Estado |
|---------|---------------|-----|--------|
| `handle_wallet_gateway_key` | `main.rs:3736` | Teclas del gateway | ✅ |
| `submit_signing_authorization` | `main.rs:3688` | Autoriza/rechaza firma | ✅ |
| `handle_broadcast_authorization_key` | `main.rs:3705` | Teclas de autorización de broadcast | ✅ |
| `submit_broadcast_authorization` | `main.rs:3719` | Envía `AuthorizeBroadcast` | ✅ |
| `draw_broadcast_authorization_modal` | `main.rs:6385` | Modal de broadcast | ✅ |
| `submit_lvcprices_import` | `main.rs:4395` | Importa `.lvcprices` firmado | ✅ |
| `preview_sign_transaction` | `supervisor.rs:258` | Prevalidación sin firma | ✅ |
| `run_loop_iteration` | `supervisor.rs:37` | Firma real / despacho | ✅ |
| `register_integrity_failure` | `supervisor.rs:337` | 3 fallos → hard lock | ✅ |
| `validate_parsed_transaction` | `firewall.rs:112` | Límites/chain_id/listas blancas | ✅ |
| `validate_target_destination_id` | `firewall.rs:202` | Destino ↔ DEX/CEX declarado | ✅ |
| `validate_account_policy` | `firewall.rs:247` | Política por cuenta | ✅ |
| `broadcast_raw_transaction` | `rpc_manager.rs:34` | Envío real (perfil `RpcOperational`) | ✅ |
| `Web3WorkerCmd` / `Web3WorkerEvent` | `worker.rs:75 / 152` | + `AuthorizeBroadcast` / `BroadcastRequest` | ✅ |
| `SigningRequestPreview.fee_estimate` | `types.rs:201` | Comisión mostrada al autorizar | ✅ |
| `BroadcastRequestPreview` | `types.rs:187` | Resumen de broadcast pendiente | ✅ |
| `ExtensionRequest::BroadcastTransaction` (stub) | `supervisor.rs:248` | Guarda offline | ⛔ a propósito |

### A.4 Modelo de seguridad (flujo `w`)

- **Doble autorización local** para firma y broadcast (nada sale sin F10/A en la TUI).
- **Validación por capas previa a la clave privada**; **listas blancas** obligatorias.
- **Circuit breaker** fail-closed (`HardLocked` irreversible salvo reinicio; rearme en tiempo constante).
- **Anti-replay** por `chain_id`; **zeroización** de payloads/secretos.
- **Broadcast** restringido a perfil `RpcOperational` + adaptador auditado + **auditoría obligatoria**.
- **Comisión visible** antes de autorizar la firma.

---

## Parte B — `k` Auditor visual de direcciones públicas

### B.1 Flujo de derivación y verificación

```
TUI (Enter)  ──► gate Boot Shield (require_boot_shield_confirmation_for_auditor)  main.rs:3085
   modal re-auth (5 cajas + frase) ──► verify_credentials_readonly  vault.rs:1214
       (o boot_shield_unlock DESTRUCTIVO si el toggle de Config está ON)
   ──► Web3WorkerCmd::DerivePublicKey { chain, network, account, index }
   ──► supervisor DeriveKey ──► multi_curve::get_public_key(chain, network, ...)  multi_curve.rs:97
   ──► Web3WorkerEvent::PublicKeyDerived
TUI: public_address_for_network (EIP-55 / P2PKH versión por red / base58)   address.rs:171
     + SegWit P2WPKH (bech32) si Bitcoin                                    address.rs:200
     + recompute_auditor_match (checksum + comparación anti-spoofing)       main.rs:3243
Tecla V ──► VerifyDerivation (doble derivación en tiempo constante)         multi_curve.rs:154
```

**Aislamiento:** el auditor solo emite `DerivePublicKey`/`VerifyDerivation`; **nunca** firma.

### B.2 Inventario de funciones (flujo `k`)

| Función | Archivo:línea | Rol | Estado |
|---------|---------------|-----|--------|
| `handle_wallet_auditor_key` | `main.rs:3295` | Teclas (red, cuenta, índice, verificar, V, C, n) | ✅ |
| `submit_wallet_auditor_derivation` | `main.rs:3000` | Deriva (con gate Boot Shield) | ✅ |
| `submit_wallet_auditor_verification` | `main.rs:3192` | Re-derivación verificable (tecla `V`) | ✅ |
| `require_boot_shield_confirmation_for_auditor` | `main.rs:3085` | Gate de re-confirmación | ✅ |
| `handle_reauth_modal_key` / `submit_reauth` | `main.rs:3106 / 3149` | Modal de re-auth + verificación | ✅ |
| `toggle_auditor_network` | `main.rs:3227` | Alterna testnet/mainnet | ✅ |
| `recompute_auditor_match` | `main.rs:3243` | Checksum + comparación (C.3) | ✅ |
| `public_key_address_label` | `main.rs:1756` | Pubkey → dirección (network-aware) | ✅ |
| `draw_reauth_modal` / `draw_wallet_auditor` | `main.rs:6431 / 7865` | Modales/render | ✅ |
| `get_public_key` | `multi_curve.rs:97` | Deriva pubkey (con `Network`) | ✅ |
| `rederive_and_verify` | `multi_curve.rs:154` | Doble derivación en tiempo constante | ✅ |
| `to_eip55_checksummed` | `address.rs:97` | Checksum EIP-55 | ✅ |
| `validate_ethereum/bitcoin/solana_*` | `address.rs:123/140/159` | Validación de entrada | ✅ |
| `public_address_for_network` | `address.rs:171` | Dirección por red | ✅ |
| `bitcoin_p2wpkh_address` | `address.rs:200` | SegWit bech32 | ✅ |
| `chain_id_label_for` / `coin_type_for` | `address.rs:62 / 76` | Etiquetas/coin_type por red | ✅ |

### B.3 Modelo de seguridad (flujo `k`)

- **No firma** (separación criptográfica del motor de custodia).
- **EIP-55** en Ethereum: la capitalización codifica el hash → un typo deja de pasar desapercibido.
- **Re-derivación verificable**: dos derivaciones independientes comparadas en tiempo constante (detecta inconsistencia/corrupción antes de recibir fondos).
- **Comparación anti-spoofing**: el operador introduce la dirección esperada; se valida checksum y se compara con la derivada (legacy o SegWit).
- **Conciencia de red correcta**: Bitcoin testnet usa coin_type 1 + prefijo `0x6f`/`tb1`; Ethereum/Solana mantienen su derivación (solo cambia el `chain_id`), evitando direcciones engañosas.
- **Gate Boot Shield** antes de derivar/verificar/exportar; ventana de 120 s.
- **Zeroización** de todos los campos sensibles del auditor en cada salida y en `Drop`.

### B.4 Configuración de seguridad — verificación de re-auth (Configuraciones, tecla `Z`)

- **Por defecto (OFF):** `verify_credentials_readonly` (`vault.rs:1214`) — **sin efectos**: no incrementa el contador de intentos, no registra tombstones, **no destruye el vault**. Un typo nunca pone en riesgo el vault.
- **Activado (ON):** la re-confirmación usa `boot_shield_unlock` (destructivo): un fallo cuenta intento y puede **destruir el vault** / disparar coacción. Pensado para proteger las wallets cuando el usuario mantiene **backup externo**.
- Persiste cifrado en el vault (`auditor_destructive_reauth`); `submit_reauth` lee el valor en vivo (`main.rs:3149`); toggle en `main.rs:3064`.

---

## Parte C — Funciones aún necesarias a integrar (con archivos y código)

Lo restante para cobertura total. Para cada punto: **archivos a actualizar** + **código Rust a insertar** (encaja con los tipos verificados: `TransactionSignRequest` `types.rs:170`, `FeeEstimate` `rpc_types.rs:40`, `AccountPolicy` `types.rs:217`, `verify_credentials_readonly` `vault.rs:1214`).

### C.0 Resumen de archivos a actualizar

| Punto | Archivos | Naturaleza |
|-------|----------|------------|
| C.1 Parsers privados/AA | `tx_parser.rs` | Mantener fail-closed; integrar con librería auditada |
| C.2 Firma network-aware | `types.rs`, `multi_curve.rs`, `supervisor.rs`, `worker.rs` | Threading de `Network` por el flujo de firma |
| C.3 Re-auth dual-secret | `vault.rs`, `main.rs` | Verificador dual + campos de modal |
| C.4 Verificación UI de auditoría | `main.rs` | Acción que llama a `verify_audit_chain` |
| C.5 Política de comisión máxima | `types.rs`, `supervisor.rs`, `worker.rs` | Campo `max_fee_native` + check |
| C.6 Selector de red en gateway | `main.rs` | Campo + toggle + render |

---

### C.1 Parsers de cadenas privadas/AA (H-10) — **P2 (alcance)**

**Archivo:** `src-tui/src/crypto/blockchain/tx_parser.rs` (hoy rechazo explícito *fail-closed*). Hasta integrar y auditar una librería, **mantener el rechazo**. Contrato e integración:

```rust
// tx_parser.rs — funciones dedicadas (hoy inline en parse_tx_payload).
/// Monero (RingCT/stealth). NO INTEGRADO: requiere libreria forense auditada.
fn parse_monero_tx(_raw: &[u8]) -> Result<ParsedTx, String> {
    Err("Monero requiere parser forense especifico no integrado".into())
}
/// Zcash Sapling/Orchard. NO INTEGRADO.
fn parse_zcash_tx(_raw: &[u8]) -> Result<ParsedTx, String> {
    Err("Zcash requiere parser Sapling/Orchard especifico no integrado".into())
}
/// Starknet (calldata / account abstraction). NO INTEGRADO.
fn parse_starknet_tx(_raw: &[u8]) -> Result<ParsedTx, String> {
    Err("Starknet requiere parser de calldata/account abstraction no integrado".into())
}

// En parse_tx_payload, despachar a estas funciones en lugar del Err inline:
//   ChainType::Monero => parse_monero_tx(raw_tx_payload),
//   ChainType::Zcash => parse_zcash_tx(raw_tx_payload),
//   ChainType::Starknet => parse_starknet_tx(raw_tx_payload),
```

Cuando se integren, deben producir un `ParsedTx` con `destinations`/`volume_units` reales para que el firewall pueda validarlos.

---

### C.2 Firma network-aware en la pasarela — **P2**

Hoy la firma (`sign_transaction`, `multi_curve.rs:169`) opera siempre en `Network::Mainnet`. Para firmar en testnet hay que propagar la red.

**1) `types.rs`** — añadir red a la solicitud de firma (`TransactionSignRequest`, `types.rs:170`):

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactionSignRequest {
    pub chain: ChainType,
    pub account_index: u32,
    pub address_index: u32,
    pub raw_tx_payload: Vec<u8>,
    pub value_usd: Decimal,
    pub target_dex_cex_id: Option<String>,
    #[serde(default)]
    pub network: crate::crypto::blockchain::address::Network,
}
```

**2) `multi_curve.rs`** — `sign_transaction` recibe la red y la usa en la derivación:

```rust
pub fn sign_transaction(
    &self,
    chain: &ChainType,
    network: Network,
    account: u32,
    index: u32,
    raw_payload: &[u8],
) -> Result<SignatureResponse, String> {
    let mut raw_key = self.derive_slip10_child(chain, network, account, index)?;
    // … resto idéntico …
}
```

**3) `supervisor.rs`** — en la rama `ExtensionRequest::SignTransaction` (`run_loop_iteration`, ~`supervisor.rs:205/215`), pasar `sign_request.network`:

```rust
let signature_response =
    keymaster.sign_transaction(&chain, sign_request.network, account, index, &payload)?;
```

> No requiere cambios en el worker salvo que la extensión ya envía `network` en el JSON (campo `#[serde(default)]`, retrocompatible con Mainnet).

---

### C.3 Re-auth con doble credencial (dual-secret) — **P1**

**1) `vault.rs`** — verificador *read-only* que admite credencial secundaria (mismo patrón sin efectos que `verify_credentials_readonly`, `vault.rs:1214`):

```rust
/// Igual que verify_credentials_readonly pero admite credencial secundaria (vaults dual-secret).
/// Read-only: no toca contadores, tombstones ni dispara destruccion.
pub fn verify_credentials_readonly_dual(
    cajas: [i64; 5],
    frase: &str,
    secondary_cajas: Option<[i64; 5]>,
    secondary_frase: Option<&str>,
) -> bool {
    if !vault_is_configured() {
        return false;
    }
    let Ok(envelope) = read_envelope() else {
        return false;
    };
    let Ok(secret) = normalize_secret(cajas, frase.to_string()) else {
        return false;
    };
    let secondary = match normalize_secondary_secret(
        secondary_cajas,
        secondary_frase.map(|value| value.to_string()),
    ) {
        Ok(secondary) => secondary,
        Err(_) => return false,
    };
    decrypt_payload(&envelope, &secret, secondary.as_ref()).is_ok()
}
```

**2) `main.rs`** — el modal de re-auth (`draw_reauth_modal`/`handle_reauth_modal_key`) añade 5 cajas + frase secundarias (campos `reauth_secondary_cajas: [String;5]`, `reauth_secondary_phrase: String`) cuando el vault las exige. En `submit_reauth` (`main.rs:3149`), sustituir el verificador read-only:

```rust
let verified = if destructive {
    security::vault::boot_shield_unlock(
        cajas, state.reauth_phrase.clone(), secondary_cajas, secondary_frase,
    ).is_ok()
} else {
    security::vault::verify_credentials_readonly_dual(
        cajas,
        &state.reauth_phrase,
        secondary_cajas,
        state.reauth_secondary_phrase.is_empty()
            .then(|| None)
            .unwrap_or(Some(state.reauth_secondary_phrase.as_str())),
    )
};
```

> Reutilizar `state.unlock_requires_secondary()` (`main.rs:1251`) para decidir si pedir la secundaria. Zeroizar los nuevos campos en `clear_reauth_secret_fields` y `Drop`.

---

### C.4 Verificación visible de la cadena de auditoría — **P2**

El sellado firmado ya existe (`web3_audit.rs`). Falta exponer la verificación en la UI.

**Archivo:** `main.rs` (acción en `Screen::AuditMonitor` o tecla en el gateway):

```rust
fn verify_web3_audit_chain_ui(state: &mut TuiState) {
    let Some(pubkey) = livencrypt_lib::crypto::blockchain::web3_audit::audit_verifying_key() else {
        state.status = "Auditoria Web3 sin clave de firma fijada (worker no iniciado).".to_string();
        return;
    };
    let path = livencrypt_lib::livencrypt_base_dir()
        .join(".livencrypt")
        .join("web3_audit.jsonl");
    match livencrypt_lib::crypto::blockchain::web3_audit::verify_audit_chain(&path, &pubkey) {
        Ok(()) => {
            state.status = "Cadena de auditoria Web3 integra y firmada correctamente.".to_string();
        }
        Err(error) => {
            state.status = format!("AUDITORIA WEB3 COMPROMETIDA: {}", error);
        }
    }
}
```

---

### C.5 Política de comisión máxima — **P2**

`fee_estimate` ya se muestra; falta poder **bloquear** por comisión excesiva.

**1) `types.rs`** — campo en `AccountPolicy` (`types.rs:217`):

```rust
#[serde(default)]
pub max_fee_native: Option<rust_decimal::Decimal>,
```

**2) `supervisor.rs`** — accesor para que el worker (que tiene el `NodeRegistry` y la `FeeEstimate`) consulte el límite de la cuenta:

```rust
impl GatewaySupervisor {
    pub fn max_fee_native_for(
        &self,
        chain: &ChainType,
        account_index: u32,
        address_index: u32,
    ) -> Option<rust_decimal::Decimal> {
        self.firewall
            .account_policy(chain, account_index, address_index)
            .and_then(|policy| policy.max_fee_native)
    }
}
```

**3) `worker.rs`** — en el manejo de `IncomingWebRequest::SignTransaction`, tras estimar la comisión y antes de emitir `SigningRequest`, rechazar si excede el límite (`FeeEstimate.fee_amount` es `Decimal`):

```rust
if let Some(fee) = rpc_manager::adapter_for_chain(node_registry, chain_name)
    .and_then(|adapter| adapter.estimate_fee(&sign_request.raw_tx_payload))
    .ok()
{
    if let Some(max) = supervisor.max_fee_native_for(
        &sign_request.chain,
        sign_request.account_index,
        sign_request.address_index,
    ) {
        if fee.fee_amount > max {
            write_error_response(
                &mut stream,
                &format!("comision {} excede el maximo de politica {}", fee.fee_amount, max),
            );
            return;
        }
    }
}
```

> Requiere un accesor `LiveFirewall::account_policy(...)` si no existe; si ya existe con otro nombre, reusarlo.

---

### C.6 Selector de red en el gateway — **P2**

`Network` está cableado en el auditor; replicarlo en el gateway para mostrar `chain_id_label_for` por red en el contexto de firma/inspector RPC.

**Archivo:** `main.rs`.

```rust
// TuiState: nuevo campo
gateway_network: Network,            // init Network::Mainnet

// handle_wallet_gateway_key: tecla para alternar (p. ej. 'Y'):
KeyCode::Char('Y') | KeyCode::Char('y') => {
    state.gateway_network = match state.gateway_network {
        Network::Mainnet => Network::Testnet,
        Network::Testnet => Network::Mainnet,
    };
    state.system_notification = format!("Red gateway: {:?}", state.gateway_network);
}

// draw_wallet_gateway: mostrar la red activa en la cabecera
Line::from(format!(
    "Red: {:?} | chain_id ETH: {}",
    state.gateway_network,
    address::chain_id_label_for(&ChainType::Ethereum, state.gateway_network)
)),
```

> Para que la firma respete esa red, combinar con C.2 (propagar `gateway_network` al construir/serializar la transacción).

---

## Parte D — Matriz de cobertura

| Área | Estado | Funciones clave |
|------|--------|-----------------|
| Anti-spoofing de dirección | ✅ Completo | EIP-55, re-derivación, comparación con checksum |
| Custodia / firma | ✅ Completo | preview + autorización 2 pasos + breaker + firewall |
| Broadcast real | ✅ Completo (2 pasos) | `broadcast_raw_transaction` + auditoría |
| Comisiones | ✅ Visible / ⏳ política | `fee_estimate` (falta `max_fee_native`) |
| Conciencia de red | ✅ Auditor / ⏳ firma | `Network` threaded (falta firma testnet) |
| Auditoría firmada | ✅ Backend / ⏳ UI verif. | `sign_event_hash`, `verify_audit_chain` |
| Cadenas privadas/AA | ⛔ Fail-closed | parsers Monero/Zcash/Starknet |
| Re-auth destructiva opcional | ✅ Configurable | toggle `Z` + `verify_credentials_readonly` |

**Prioridad sugerida del restante:** C.3 (dual-secret) → C.5 (política de comisión) → C.4 (verificación UI de auditoría) → C.2/C.6 (red en firma/gateway) → C.1 (parsers, cuando haya librerías auditadas).

---

## Apéndice — Tipos y artefactos clave

| Tipo / artefacto | Archivo:línea | Notas |
|------------------|---------------|-------|
| `Network` | `address.rs:14` | `Mainnet`/`Testnet`, `Serialize/Deserialize/Default` |
| `KeyDerivationRequest` | `types.rs:71` | incluye `network` (`#[serde(default)]`) |
| `SigningRequestPreview` | `types.rs:201` | incluye `fee_estimate` |
| `BroadcastRequestPreview` | `types.rs:187` | resumen sin payload secreto |
| `Web3WorkerCmd` | `worker.rs:75` | + `VerifyDerivation`, `AuthorizeBroadcast` |
| `Web3WorkerEvent` | `worker.rs:152` | + `DerivationVerified`, `BroadcastRequest` |
| `SignedWeb3AuditEvent` | `web3_audit.rs:46` | cadena de hashes + firma Ed25519 |
| `verify_credentials_readonly` | `vault.rs:1214` | verificador sin efectos (gate auditor) |
| `audit_signing_key` | `multi_curve.rs:144` | clave Ed25519 de auditoría derivada del vault |

---

*Generado por lectura directa del código en `src-tui/` (rama `feat/integracion-w-k-auditoria`). Las referencias `archivo:línea` corresponden a esta fecha; reverificar con `grep -n` tras refactors. Restricción operativa del proyecto: de la capa de Red solo se ejecuta lo relacionado con Blockchain; los tests de aislamiento de red del sistema están prohibidos.*
