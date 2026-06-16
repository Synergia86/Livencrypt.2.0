> ⚠️ **DOCUMENTO OBSOLETO (2026-06-13).** Describe el estado **previo a la integración** del catálogo de remediación. El estado actual del código está en **`AUDITORIA_FUNCIONES_W_CUSTODIA_K_AUDITOR_ESTADO_ACTUAL.md`**. Se conserva solo como referencia histórica.

# Auditoria completa: Pasarela Web3 / custodia y auditor visual de direcciones publicas

## 1. Alcance

Este documento audita el codigo y las funciones relacionadas con:

```text
w = Pasarela Web3 / custodia
k = Auditor visual de direcciones publicas
```

El objetivo es evaluar si Livencrypt 2.0 puede operar como custodio local Web3, auditor de direcciones publicas y pasarela de firma con seguridad real, indicando:

```text
estado actual del codigo
riesgos actuales
funciones ya integradas
funciones pendientes
requisitos por blockchain
tests necesarios
fases recomendadas de integracion
```

## 2. Archivos auditados

### 2.1. Backend blockchain

```text
src-tui/src/crypto/blockchain/address.rs
src-tui/src/crypto/blockchain/breaker.rs
src-tui/src/crypto/blockchain/eth_abi.rs
src-tui/src/crypto/blockchain/eth_rlp.rs
src-tui/src/crypto/blockchain/eth_simulation.rs
src-tui/src/crypto/blockchain/eth_tx.rs
src-tui/src/crypto/blockchain/eth_types.rs
src-tui/src/crypto/blockchain/firewall.rs
src-tui/src/crypto/blockchain/mod.rs
src-tui/src/crypto/blockchain/multi_curve.rs
src-tui/src/crypto/blockchain/nodes.rs
src-tui/src/crypto/blockchain/preflight.rs
src-tui/src/crypto/blockchain/price_import.rs
src-tui/src/crypto/blockchain/proxy.rs
src-tui/src/crypto/blockchain/rpc.rs
src-tui/src/crypto/blockchain/rpc_bitcoin.rs
src-tui/src/crypto/blockchain/rpc_client.rs
src-tui/src/crypto/blockchain/rpc_ethereum.rs
src-tui/src/crypto/blockchain/rpc_manager.rs
src-tui/src/crypto/blockchain/rpc_quorum.rs
src-tui/src/crypto/blockchain/rpc_solana.rs
src-tui/src/crypto/blockchain/rpc_types.rs
src-tui/src/crypto/blockchain/supervisor.rs
src-tui/src/crypto/blockchain/tx_parser.rs
src-tui/src/crypto/blockchain/types.rs
src-tui/src/crypto/blockchain/web3_audit.rs
src-tui/src/crypto/blockchain/worker.rs
```

### 2.2. TUI

```text
src-tui/src/main.rs
```

Funciones relevantes:

```text
draw_wallet_gateway
draw_wallet_auditor
wallet_qr_payload
wallet_clipboard_payload
submit_wallet_auditor_derivation
handle_wallet_auditor_key
handle_wallet_gateway_key
```

### 2.3. Bridge nativo

```text
src-tui/src/bin/livencrypt-bridge.rs
src-tui/scripts/com.livencrypt.gateway.json
```

### 2.4. Extension Web3

```text
src-tui/extension/livencrypt-web3/manifest.json
src-tui/extension/livencrypt-web3/background.js
src-tui/extension/livencrypt-web3/content.js
src-tui/extension/livencrypt-web3/inject.js
src-tui/extension/livencrypt-web3/popup.html
src-tui/extension/livencrypt-web3/popup.js
src-tui/extension/livencrypt-web3/popup.css
```

## 3. Modelo de seguridad esperado

Livencrypt debe comportarse como custodio local. El navegador, DEX, extension y nodo RPC nunca deben recibir:

```text
clave privada
seed
master_seed
frase Boot Shield
cajas Boot Shield
clave derivada del vault
plantillas privadas descifradas
payload interno del vault
```

Solo pueden salir al navegador:

```text
direccion publica
clave publica
chain_id
payload publico livencrypt-wallet-link
firma final aprobada localmente
raw signed tx ya autorizado
errores genericos
```

Regla principal:

```text
sin confirmacion local en TUI no debe existir firma.
```

## 4. Auditoria de `w = Pasarela Web3 / custodia`

## 4.1. Estado actual

La pasarela Web3 ya dispone de:

```text
extension MV3 inicial
permisos por dominio mediante popup
host nativo livencrypt-bridge
socket Unix local
worker Web3 separado
limite de mensajes nativos
limite de conexiones concurrentes
perfil OFFLINE / RPC LECTURA / RPC OPERATIVO
derivacion de cuentas publicas
lectura de balance
lectura de nonce
lectura de gas price
preparacion Ethereum
preflight Ethereum
quorum RPC
auditoria JSONL
firma pendiente con confirmacion local
reconstruccion raw signed tx con v/r/s o yParity/r/s
broadcast bloqueado por defecto
```

## 4.2. Flujo real de firma Ethereum integrado

Flujo actual:

```text
DEX
  -> window.livencrypt.request({ method: "eth_sendTransaction", params: [...] })
  -> extension background.js
  -> EthereumSignTransaction
  -> livencrypt-bridge
  -> socket Unix
  -> worker Web3
  -> serialize_unsigned
  -> eth_abi decode_call
  -> preflight_ethereum
  -> eth_call / eth_estimateGas / eth_getCode / eth_chainId por quorum
  -> preview TUI
  -> usuario aprueba
  -> keymaster firma
  -> serialize_signed
  -> raw_tx_hex + tx_hash
  -> extension
  -> DEX
```

## 4.3. Seguridad actual positiva

```text
la extension no guarda claves privadas;
la extension exige dominio aprobado;
la extension no pisa MetaMask si window.ethereum ya existe;
el bridge no guarda secretos;
el bridge solo reenvia stdin/stdout hacia socket local;
el socket exige usuario local;
el worker mantiene la confirmacion local;
el preflight se ejecuta antes de firma estructurada;
los selectores ABI desconocidos son riesgo critico;
approve ilimitado se marca critico;
el broadcast no esta abierto por defecto;
se registra auditoria de preflight y firma.
```

## 4.4. Riesgos actuales

### Riesgo 1: permisos de extension basicos

La extension ya tiene popup de permisos, pero falta endurecer:

```text
caducidad de permisos por dominio
permisos por cuenta
permisos por metodo
permisos por contrato
permisos por chain_id
modo solo lectura por dominio
confirmacion visual en popup antes de cada firma
rechazo explicito de iframes
proteccion contra phishing visual
```

### Riesgo 2: serializador Ethereum inicial

Existe serializacion Legacy/EIP-2930/EIP-1559, pero falta ampliar:

```text
accessList real
validacion estricta de cantidades U256
normalizacion completa de EIP-1193
soporte de create contract
soporte de chainId distinto de mainnet bajo politica
vectores oficiales de prueba
comparacion con libreria Ethereum auditada
```

### Riesgo 3: ABI decoder limitado

Actualmente cubre:

```text
erc20.transfer
erc20.approve
erc20.transferFrom
erc721.setApprovalForAll
native_transfer
unknown -> Critical
```

Falta:

```text
permit
safeTransferFrom
multicall
Uniswap V2 swaps
Uniswap V3 exactInput/exactOutput
1inch router
0x protocol
Seaport
Gnosis Safe
proxy contracts
delegatecall detection indirecta
```

### Riesgo 4: quorum RPC parcial

El quorum existe, pero su seguridad depende de tener varios endpoints reales configurados. Si solo existe un nodo:

```text
no hay quorum real;
hay lectura unica con min_agreement = 1;
un nodo malicioso podria mentir.
```

Falta:

```text
exigir minimo 2 nodos para firma;
politica de quorum por cadena;
bloqueo si hay divergencia;
comparacion de altura;
comparacion de chainId;
comparacion de code hash;
marcar endpoint atrasado;
rotacion automatica de fallback.
```

### Riesgo 5: auditoria no encadenada

La auditoria JSONL registra eventos, pero debe endurecerse:

```text
hash encadenado tipo append-only
HMAC local del evento
firma local de auditoria
rotacion de logs
exportacion verificable
alerta si el log se borra
modo inmutable si el SO lo permite
```

### Riesgo 6: broadcast pendiente

`raw_tx_hex` ya puede devolverse, pero emitir transacciones debe seguir separado.

Debe permanecer bloqueado hasta cumplir:

```text
perfil RPC OPERATIVO
testnet/devnet superada
quorum RPC obligatorio
auditoria completa
confirmacion local reforzada
politica por dominio
politica por cuenta
politica por contrato
seguimiento post-broadcast
```

## 5. Auditoria de `k = Auditor visual de direcciones publicas`

## 5.1. Estado actual

El auditor ya permite:

```text
seleccionar Bitcoin/Ethereum/Solana
seleccionar cuenta
seleccionar indice
derivar clave publica
generar direccion Ethereum
generar direccion Solana
generar direccion Bitcoin P2PKH
mostrar ruta HD
mostrar clave publica hex
mostrar QR ASCII individual
copiar payload publico livencrypt-wallet-link
mostrar politica asociada
mostrar soporte por cadena
```

## 5.2. Seguridad positiva

```text
no expone clave privada;
no expone seed;
no expone frase/cajas;
payload publico declara scope public-address-only;
QR es individual por wallet;
cuenta e indice cambian la direccion;
la derivacion pasa por backend local.
```

## 5.3. Riesgos actuales

### Riesgo 1: Bitcoin solo P2PKH

Falta:

```text
P2WPKH bech32
P2SH-P2WPKH
Taproot P2TR
selector de tipo de direccion
derivation path coherente
validacion de checksum
```

### Riesgo 2: sin libreta persistente de direcciones

Falta:

```text
alias de cuenta
alias de direccion
historial de direcciones generadas
favoritos
watch-only exports
marcar direccion usada/no usada
ocultar direcciones sensibles
```

### Riesgo 3: QR ASCII insuficiente para flujos externos

Falta:

```text
exportar PNG
exportar SVG
copiar solo direccion
copiar URI por cadena
mostrar QR compacto para terminal pequena
verificacion visual checksum
```

### Riesgo 4: soporte multicadena incompleto

No hay soporte operativo para:

```text
Monero
ZCash
Starknet
```

Estas cadenas no deben presentarse como funcionales hasta integrar derivacion, direccion, parser, RPC y firma propios.

## 6. Funciones necesarias para uso real seguro

## 6.1. Extension Web3

Funciones pendientes:

```text
caducidad de permisos
permisos por cuenta
permisos por metodo
permisos por contrato
modo solo lectura
modo firma
modo DEX autorizado
panel de actividad reciente
exportar auditoria de permisos
notificacion cuando Livencrypt no este desbloqueado
notificacion cuando el perfil sea OFFLINE
proteccion anti-iframe
proteccion anti-clickjacking en popup
```

## 6.2. Pasarela nativa

Funciones pendientes:

```text
versionado de protocolo native messaging
handshake inicial extension <-> bridge
comando status
comando list_accounts
comando get_permissions_state
errores normalizados EIP-1193
limites por metodo
rate limit por origen
auditoria de origen para cada mensaje
```

## 6.3. Ethereum/EVM

Funciones pendientes:

```text
accessList real EIP-2930/EIP-1559
typed data EIP-712
personal_sign con politicas
eth_signTypedData_v4
feeHistory
maxFee recomendada
soporte de multiples chainId
contratos proxy
decodificador ABI ampliado
base local de selectores
simulacion con balance y allowance
deteccion de approvals ilimitados
alerta de NFT approvals
alerta de permit
alerta de multicall
```

## 6.4. Bitcoin

Funciones pendientes:

```text
P2WPKH
P2TR
PSBT
UTXO selection
change address
fee sat/vB
Electrum scripthash
Esplora indexer
firma por input
validacion de outputs
bloqueo dust
watch-only wallet
```

## 6.5. Solana

Funciones pendientes:

```text
getLatestBlockhash
Message v0
versioned transactions
address lookup tables
SPL token transfer
associated token account
simulateTransaction
parser de instrucciones
fee para mensaje real
validacion de cuentas afectadas
```

## 6.6. Monero

Funciones pendientes:

```text
spend key
view key
subaddresses
wallet-rpc
monerod RPC
key images
ring signatures
confidential transactions
modo view-only
```

## 6.7. ZCash

Funciones pendientes:

```text
t-address
Sapling
Orchard
viewing keys
shielded notes
seleccion de libreria ZK auditada
parser de transacciones
firma especifica
```

## 6.8. Starknet

Funciones pendientes:

```text
account abstraction
contrato de cuenta
nonce
calldata
selectors
Poseidon/Pedersen
firma Stark
RPC Starknet
validacion de clase de cuenta
```

## 7. Tests necesarios

## 7.1. Tests sin red

```text
derivacion determinista Bitcoin/Ethereum/Solana
direccion esperada por clave publica
QR distinto por cuenta/indice
payload livencrypt-wallet-link valido
extension no pisa MetaMask
dominio no aprobado rechaza eth_requestAccounts
dominio aprobado permite eth_requestAccounts
dominio revocado vuelve a rechazar
iframe no autorizado rechaza
serializacion Legacy con vector conocido
serializacion EIP-2930 con vector conocido
serializacion EIP-1559 con vector conocido
serialize_signed reconstruye v/r/s
tx_hash coincide con keccak256 raw signed tx
ABI transfer decode correcto
ABI approve ilimitado Critical
selector desconocido Critical
auditoria no contiene secretos
native message > 1 MB rechazado
```

## 7.2. Tests RPC reales

```text
Ethereum chainId con 2 nodos
Ethereum balance con 2 nodos
Ethereum nonce pending con 2 nodos
Ethereum eth_getCode con 2 nodos
Ethereum eth_call con 2 nodos
Ethereum eth_estimateGas con 2 nodos
divergencia entre nodos bloquea preflight
nodo caido no bloquea si quorum suficiente
Solana health
Solana balance
Solana fee con mensaje real
Bitcoin Core health
Bitcoin fee
Electrum scripthash balance
Bitcoin estado TX
```

## 7.3. Tests de firma

```text
firma rechazada por usuario no devuelve raw_tx_hex
firma aprobada devuelve raw_tx_hex
raw_tx_hex decodifica correctamente
v legacy = chain_id * 2 + 35 + yParity
yParity typed tx es 0 o 1
r/s tienen 32 bytes antes de trim RLP
raw tx produce tx_hash esperado
payload manipulado cambia hash
chainId incorrecto bloquea
destino no permitido bloquea
contrato no permitido bloquea
limite FIAT excedido bloquea
approval ilimitado exige confirmacion reforzada o bloquea
```

## 7.4. Tests de extension

```text
popup lista pendientes
popup aprueba dominio
popup revoca dominio
eth_accounts sin permiso devuelve []
eth_getBalance sin permiso rechaza
eth_getBalance con permiso consulta backend
eth_sendTransaction sin permiso rechaza
eth_sendTransaction con permiso abre confirmacion TUI
metodo desconocido falla cerrado
http remoto rechaza
localhost permite modo desarrollo
```

## 8. Fases recomendadas

### Fase 1: cerrar seguridad de extension

```text
caducidad de permisos
permisos por metodo
permisos por cuenta
rechazo iframe
errores EIP-1193 normalizados
panel de actividad
```

### Fase 2: robustecer Ethereum

```text
vectores oficiales RLP
accessList real
EIP-712
ABI decoder ampliado
proxy detection
allowance checks
feeHistory
```

### Fase 3: quorum obligatorio para firma

```text
minimo 2 nodos para eth_sendTransaction
bloqueo por divergencia
detector de nodo atrasado
chainId pinning
code hash pinning opcional
```

### Fase 4: auditoria fuerte

```text
hash chain de eventos
HMAC local
firma de auditoria
rotacion
exportacion verificable
deteccion de borrado
```

### Fase 5: broadcast controlado

```text
solo testnet/devnet inicialmente
RPC OPERATIVO
confirmacion reforzada
seguimiento post-broadcast
registro txid
alerta si no confirma
```

### Fase 6: multicadena real

```text
Bitcoin PSBT + Electrum/Esplora
Solana Message v0 + SPL
Monero
ZCash
Starknet
```

## 9. Codigo legitimo a integrar por bloque

Esta seccion completa los bloques criticos con codigo orientativo directamente trasladable al repositorio.

## 9.1. Flujo real de firma Ethereum con `raw signed tx`

### 9.1.1. Objetivo

El flujo seguro debe ser:

```text
objeto EIP-1193
  -> normalizacion
  -> serializacion unsigned
  -> preflight/quorum
  -> preview TUI
  -> confirmacion local
  -> firma secp256k1
  -> reconstruccion raw signed tx
  -> tx_hash
  -> respuesta a extension
```

### 9.1.2. Tipo de respuesta firmada

Archivo:

```text
src-tui/src/crypto/blockchain/eth_types.rs
```

Codigo:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumSignedTransaction {
    pub raw_tx_hex: String,
    pub tx_hash: String,
    pub decoded_method: String,
    pub risk: String,
    pub summary: String,
    pub warnings: Vec<String>,
}
```

### 9.1.3. Reconstruccion `v/r/s` y `yParity/r/s`

Archivo:

```text
src-tui/src/crypto/blockchain/eth_tx.rs
```

Codigo:

```rust
use crate::crypto::blockchain::eth_rlp;
use crate::crypto::blockchain::eth_types::{EthereumTxKind, EthereumTxRequest};
use crate::crypto::blockchain::types::SignatureResponse;
use sha3::{Digest, Keccak256};

pub fn serialize_signed(
    tx: &EthereumTxRequest,
    signature: &SignatureResponse,
) -> Result<Vec<u8>, String> {
    validate_common(tx)?;
    let (r, s) = signature_rs(signature)?;
    let y_parity = u64::from(signature.recovery_id.unwrap_or(0) & 1);

    match tx.kind {
        EthereumTxKind::Legacy => serialize_legacy_signed(tx, y_parity, r, s),
        EthereumTxKind::Eip2930 => serialize_eip2930_signed(tx, y_parity, r, s),
        EthereumTxKind::Eip1559 => serialize_eip1559_signed(tx, y_parity, r, s),
    }
}

pub fn tx_hash_hex(raw_signed_tx: &[u8]) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(raw_signed_tx)))
}

fn serialize_legacy_signed(
    tx: &EthereumTxRequest,
    y_parity: u64,
    r: &[u8],
    s: &[u8],
) -> Result<Vec<u8>, String> {
    let v = tx
        .chain_id
        .checked_mul(2)
        .and_then(|value| value.checked_add(35))
        .and_then(|value| value.checked_add(y_parity))
        .ok_or_else(|| "v Ethereum legacy fuera de rango".to_string())?;

    let mut fields = legacy_base_fields(tx)?;
    fields.push(eth_rlp::encode_u64(v));
    fields.push(encode_signature_scalar(r));
    fields.push(encode_signature_scalar(s));
    Ok(eth_rlp::encode_list(&fields))
}

fn serialize_eip2930_signed(
    tx: &EthereumTxRequest,
    y_parity: u64,
    r: &[u8],
    s: &[u8],
) -> Result<Vec<u8>, String> {
    let mut fields = eip2930_unsigned_fields(tx)?;
    fields.push(eth_rlp::encode_u64(y_parity));
    fields.push(encode_signature_scalar(r));
    fields.push(encode_signature_scalar(s));

    let mut out = vec![0x01];
    out.extend_from_slice(&eth_rlp::encode_list(&fields));
    Ok(out)
}

fn serialize_eip1559_signed(
    tx: &EthereumTxRequest,
    y_parity: u64,
    r: &[u8],
    s: &[u8],
) -> Result<Vec<u8>, String> {
    let mut fields = eip1559_unsigned_fields(tx)?;
    fields.push(eth_rlp::encode_u64(y_parity));
    fields.push(encode_signature_scalar(r));
    fields.push(encode_signature_scalar(s));

    let mut out = vec![0x02];
    out.extend_from_slice(&eth_rlp::encode_list(&fields));
    Ok(out)
}

fn signature_rs(signature: &SignatureResponse) -> Result<(&[u8], &[u8]), String> {
    if signature.raw_signature.len() != 64 {
        return Err("firma Ethereum invalida: se esperaban 64 bytes r||s".into());
    }
    Ok((
        &signature.raw_signature[..32],
        &signature.raw_signature[32..64],
    ))
}

fn encode_signature_scalar(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    eth_rlp::encode_bytes(&bytes[start..])
}
```

### 9.1.4. Worker: respuesta final a la extension

Archivo:

```text
src-tui/src/crypto/blockchain/worker.rs
```

Codigo:

```rust
fn ethereum_signed_response_bytes(
    signature_response_bytes: &[u8],
    tx: &EthereumTxRequest,
    context: &PendingEthereumContext,
) -> Result<Vec<u8>, String> {
    let response = serde_json::from_slice::<ExtensionResponse<SignatureResponse>>(
        signature_response_bytes,
    )
    .map_err(|error| error.to_string())?;

    let signature = match response {
        ExtensionResponse::Success(signature) => signature,
        ExtensionResponse::Error(error) => {
            return serde_json::to_vec(&ExtensionResponse::<EthereumSignedTransaction>::Error(error))
                .map_err(|error| error.to_string());
        }
    };

    let raw_signed = eth_tx::serialize_signed(tx, &signature)?;
    let raw_tx_hex = format!("0x{}", hex::encode(&raw_signed));
    let tx_hash = eth_tx::tx_hash_hex(&raw_signed);

    let signed = EthereumSignedTransaction {
        raw_tx_hex,
        tx_hash,
        decoded_method: context.decoded_method.clone(),
        risk: context.risk.clone(),
        summary: context.summary.clone(),
        warnings: context.warnings.clone(),
    };

    serde_json::to_vec(&ExtensionResponse::Success(signed))
        .map_err(|error| error.to_string())
}
```

### 9.1.5. Extension: `eth_sendTransaction`

Archivo:

```text
src-tui/extension/livencrypt-web3/background.js
```

Codigo:

```javascript
async function signTransaction(params, origin) {
  const tx = params?.[0];
  if (!tx || typeof tx !== "object") {
    throw new Error("Transaccion Ethereum invalida");
  }

  const raw = tx.raw_tx_payload || tx.rawTxPayload;
  if (!raw) {
    const response = await sendNative({
      type: "EthereumSignTransaction",
      payload: buildEthereumPreparePayload(params, origin)
    });
    return unwrapSuccess(response).raw_tx_hex;
  }

  const response = await sendNative({
    type: "SignTransaction",
    payload: {
      chain: "Ethereum",
      account_index: DEFAULT_ACCOUNT,
      address_index: DEFAULT_INDEX,
      raw_tx_payload: hexToBytes(String(raw)),
      value_usd: 0,
      target_dex_cex_id: tx.to || null,
      origin
    }
  });

  return unwrapSuccess(response);
}
```

## 9.2. Riesgos actuales y codigo para mitigarlos

### 9.2.1. Riesgo: permisos demasiado amplios por dominio

Mitigacion:

```text
permisos con caducidad;
permisos por metodo;
permisos por cuenta;
modo solo lectura;
revocacion.
```

Codigo recomendado para `background.js`:

```javascript
const PERMISSION_TTL_MS = 24 * 60 * 60 * 1000;

async function isOriginAllowedForMethod(origin, method) {
  const data = await chrome.storage.local.get({ allowedOrigins: {} });
  const entry = data.allowedOrigins[origin];
  if (!entry) return false;

  if (Date.now() - Number(entry.approved_at || 0) > PERMISSION_TTL_MS) {
    delete data.allowedOrigins[origin];
    await chrome.storage.local.set({ allowedOrigins: data.allowedOrigins });
    return false;
  }

  if (Array.isArray(entry.methods) && !entry.methods.includes(method)) {
    return false;
  }

  return true;
}
```

### 9.2.2. Riesgo: iframe malicioso

Mitigacion en `content.js`:

```javascript
if (window.top !== window) {
  throw new Error("Livencrypt Web3 bloqueado en iframes");
}
```

Version tolerante:

```javascript
const isTopFrame = window.top === window;
if (!isTopFrame) {
  console.warn("Livencrypt Web3: iframe bloqueado");
} else {
  injectProvider();
}
```

### 9.2.3. Riesgo: nodo RPC unico malicioso

Mitigacion en Rust:

```rust
pub fn require_real_quorum(registry: &NodeRegistry, chain: &str) -> Result<(), String> {
    let endpoints = registry.endpoints(chain);
    if endpoints.len() < 2 {
        return Err(format!(
            "firma bloqueada: {} requiere al menos 2 endpoints RPC para quorum",
            chain
        ));
    }
    Ok(())
}
```

Aplicacion antes de firma:

```rust
require_real_quorum(node_registry, "ethereum")?;
let preflight = preflight::preflight_ethereum(node_registry, &tx)?;
```

### 9.2.4. Riesgo: auditoria manipulable

Mitigacion: cadena hash de auditoria.

Codigo recomendado:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainedWeb3AuditEvent {
    pub previous_hash: String,
    pub event: Web3AuditEvent,
    pub event_hash: String,
}

pub fn event_hash(previous_hash: &str, event: &Web3AuditEvent) -> Result<String, String> {
    let payload = serde_json::to_vec(&(previous_hash, event))
        .map_err(|error| error.to_string())?;
    Ok(hex::encode(sha2::Sha256::digest(payload)))
}
```

## 9.3. Funciones pendientes para uso seguro real con codigo base

### 9.3.1. Errores EIP-1193 normalizados

Archivo:

```text
src-tui/extension/livencrypt-web3/background.js
```

Codigo:

```javascript
function providerError(code, message, data = undefined) {
  const error = new Error(message);
  error.code = code;
  if (data !== undefined) error.data = data;
  return error;
}

function normalizeLivencryptError(error) {
  const message = String(error?.message || error);
  if (message.includes("no autorizado")) return providerError(4100, message);
  if (message.includes("rechazada")) return providerError(4001, message);
  if (message.includes("no soportado")) return providerError(4200, message);
  if (message.includes("desconectado")) return providerError(4900, message);
  return providerError(-32603, message);
}
```

### 9.3.2. Comando nativo `Web3Status`

Rust:

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Web3StatusResponse {
    pub unlocked: bool,
    pub gateway_state: String,
    pub profile: String,
    pub supported_chains: Vec<String>,
}

pub enum ExtensionRequest {
    Web3Status,
    // resto...
}
```

Worker:

```rust
Ok(ExtensionRequest::Web3Status) => {
    let status = Web3StatusResponse {
        unlocked: !matches!(supervisor.breaker.state, GatewaySecurityState::Frozen { .. }),
        gateway_state: format!("{:?}", supervisor.breaker.state),
        profile: node_registry.profile().label().to_string(),
        supported_chains: vec!["ethereum".into(), "bitcoin".into(), "solana".into()],
    };
    write_result_response(&mut stream, Ok(status));
}
```

### 9.3.3. Politica por dominio en backend

Rust:

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Web3OriginPolicy {
    pub origin: String,
    pub allowed_methods: Vec<String>,
    pub allowed_chain_ids: Vec<String>,
    pub allowed_accounts: Vec<(u32, u32)>,
    pub max_daily_tx: u32,
    pub max_daily_fiat: Option<rust_decimal::Decimal>,
}
```

Validacion:

```rust
pub fn validate_origin_policy(
    policy: &Web3OriginPolicy,
    method: &str,
    chain_id: &str,
    account_index: u32,
    address_index: u32,
) -> Result<(), String> {
    if !policy.allowed_methods.iter().any(|value| value == method) {
        return Err("metodo no permitido para este dominio".into());
    }
    if !policy.allowed_chain_ids.iter().any(|value| value == chain_id) {
        return Err("chain_id no permitido para este dominio".into());
    }
    if !policy
        .allowed_accounts
        .iter()
        .any(|(account, index)| *account == account_index && *index == address_index)
    {
        return Err("cuenta no permitida para este dominio".into());
    }
    Ok(())
}
```

## 9.4. Requisitos por blockchain con codigo de arranque

### 9.4.1. Bitcoin: scripthash Electrum

Codigo requerido:

```rust
use sha2::{Digest, Sha256};

pub fn electrum_scripthash_from_p2pkh_hash160(hash160_hex: &str) -> Result<String, String> {
    let hash160 = hex::decode(hash160_hex).map_err(|error| error.to_string())?;
    if hash160.len() != 20 {
        return Err("hash160 P2PKH invalido".into());
    }
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(&hash160);
    script.extend_from_slice(&[0x88, 0xac]);
    let digest = Sha256::digest(&script);
    let reversed = digest.iter().rev().copied().collect::<Vec<_>>();
    Ok(hex::encode(reversed))
}
```

### 9.4.2. Solana: fee con mensaje real

Codigo requerido:

```rust
pub fn solana_get_fee_for_message_payload(message_bytes: &[u8]) -> String {
    bs58::encode(message_bytes).into_string()
}
```

Uso:

```rust
let encoded = solana_get_fee_for_message_payload(&message);
json_rpc_call(endpoint, "getFeeForMessage", serde_json::json!([encoded]), timeout_ms)?;
```

### 9.4.3. Monero

Estructura minima:

```rust
pub struct MoneroAccountKeys {
    pub public_spend: [u8; 32],
    pub public_view: [u8; 32],
    pub private_spend_encrypted: Vec<u8>,
    pub private_view_encrypted: Vec<u8>,
}
```

No integrar firma hasta usar libreria Monero auditada.

### 9.4.4. ZCash

Estructura minima:

```rust
pub enum ZcashAddressKind {
    Transparent,
    Sapling,
    Orchard,
}

pub struct ZcashPublicAddress {
    pub kind: ZcashAddressKind,
    pub address: String,
    pub viewing_key_available: bool,
}
```

### 9.4.5. Starknet

Estructura minima:

```rust
pub struct StarknetAccount {
    pub address: String,
    pub class_hash: String,
    pub public_key: String,
    pub chain_id: String,
}
```

## 9.5. Tests necesarios con codigo

### 9.5.1. Test Rust: raw signed tx Legacy

```rust
#[test]
fn legacy_signed_tx_adds_eip155_v_r_s() {
    let tx = EthereumTxRequest {
        chain_id: 1,
        from: "0x1111111111111111111111111111111111111111".into(),
        to: Some("0x2222222222222222222222222222222222222222".into()),
        nonce: 1,
        value: "0x01".into(),
        data: "0x".into(),
        gas_limit: 21_000,
        gas_price: Some("0x3b9aca00".into()),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        kind: EthereumTxKind::Legacy,
    };
    let signature = SignatureResponse {
        public_key: vec![],
        raw_signature: [vec![1u8; 32], vec![2u8; 32]].concat(),
        recovery_id: Some(1),
    };
    let raw = serialize_signed(&tx, &signature).expect("signed legacy");
    assert!(!raw.is_empty());
    assert!(!tx_hash_hex(&raw).is_empty());
}
```

### 9.5.2. Test Rust: selector desconocido critico

```rust
#[test]
fn unknown_selector_is_critical() {
    let decoded = decode_call(
        "0x2222222222222222222222222222222222222222",
        "0xdeadbeef0000000000000000000000000000000000000000000000000000000000000000",
    )
    .expect("decode");
    assert_eq!(decoded.risk, EthereumCallRisk::Critical);
}
```

### 9.5.3. Test JS: dominio no aprobado

```javascript
async function testUnauthorizedOrigin() {
  await chrome.storage.local.clear();
  try {
    await handleProviderRequest({ method: "eth_requestAccounts", params: [] }, "https://dex.local");
    throw new Error("debio rechazar");
  } catch (error) {
    console.assert(String(error.message).includes("Origen no autorizado"));
  }
}
```

### 9.5.4. Test RPC: quorum insuficiente

```rust
#[test]
fn real_quorum_requires_two_endpoints_for_signing() {
    let registry = NodeRegistry::default();
    let error = require_real_quorum(&registry, "ethereum")
        .expect_err("sin endpoints debe fallar");
    assert!(error.contains("requiere al menos 2 endpoints"));
}
```

### 9.5.5. Test auditoria: no secretos

```rust
#[test]
fn audit_event_does_not_contain_secret_fields() {
    let event = Web3AuditEvent {
        timestamp_unix: 1,
        origin: "https://dex.local".into(),
        action: "preflight".into(),
        chain: "ethereum".into(),
        chain_id: "0x1".into(),
        account_index: Some(0),
        address_index: Some(0),
        from: Some("0x1111111111111111111111111111111111111111".into()),
        to: None,
        contract: None,
        method: None,
        selector: None,
        value_native: None,
        value_fiat: None,
        endpoint_summary: vec![],
        decision: "rejected".into(),
        warnings: vec![],
        payload_sha256: None,
        signature_sha256: None,
    };
    let json = serde_json::to_string(&event).expect("json");
    assert!(!json.contains("frase"));
    assert!(!json.contains("cajas"));
    assert!(!json.contains("private"));
    assert!(!json.contains("seed"));
}
```

## 10. Dictamen profesional

Estado actual:

```text
la arquitectura base es correcta;
la separacion navegador/bridge/TUI esta bien orientada;
la custodia local no expone claves privadas al navegador;
el auditor publico ya es funcional en Bitcoin/Ethereum/Solana;
Ethereum ya tiene preparacion, preflight, quorum, firma local y reconstruccion raw signed tx;
la auditoria Web3 existe pero debe endurecerse;
el broadcast debe permanecer bloqueado hasta completar controles operativos.
```

Conclusion:

```text
Livencrypt 2.0 ya puede considerarse una base funcional de custodia local y auditoria publica.
No debe considerarse todavia una wallet Web3 de produccion completa para DEX hasta completar:

1. permisos avanzados por dominio/metodo/cuenta;
2. ABI decoder ampliado;
3. quorum obligatorio con varios nodos;
4. auditoria encadenada;
5. tests reales de firma con vectores y testnet;
6. broadcast operativo controlado.
```
