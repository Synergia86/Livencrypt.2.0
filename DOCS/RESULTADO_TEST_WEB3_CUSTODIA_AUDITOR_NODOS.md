# Resultado de test: Web3 custodia, auditor visual y nodos blockchain

## 1. Alcance

Este informe resume el estado real de pruebas sobre las funciones:

```text
w = Pasarela Web3 / custodia
k = Auditor visual de direcciones publicas
```

No se han ejecutado pruebas de red del sistema Livencrypt 2.0:

```text
nmcli-off
drop-default-route
firewall del SO
AppArmor operativo
funciones que puedan aislar el equipo
```

Las pruebas de red mencionadas en este documento se refieren exclusivamente a nodos blockchain.

## 2. Pruebas realizadas

### 2.1. Compilacion del proyecto TUI

Comando ejecutado:

```bash
cd "/home/Divad/Escritorio/LIVENCRYPT 2.0/src-tui"
cargo check --bins --locked
```

Resultado:

```text
OK
Finished `dev` profile [unoptimized + debuginfo]
```

Conclusion:

```text
El codigo compila correctamente.
```

### 2.2. Verificacion estatica de integracion frontend/backend

Se verifico que existen y estan conectadas las funciones principales:

```text
draw_web3_account_policies
draw_web3_scheduled_rules
draw_web3_price_oracle
draw_web3_rpc_inspector
wallet_qr_payload
RpcReadBalance
RpcReadNonce
RpcEstimateFee
RpcReadTxStatus
BroadcastTransaction
ChainRpcAdapter
OfflineRpcAdapter
```

Resultado:

```text
OK parcial.
```

Conclusion:

```text
El frontend TUI ya tiene pantallas y comandos conectados.
El backend ya recibe comandos de politicas, reglas, precios y consultas RPC.
```

## 3. Resultado por funcion

## 3.1. Pasarela Web3 / custodia

Estado:

```text
Integrada en frontend y backend.
```

Funciones presentes:

```text
perfil Web3 OFFLINE / RPC LECTURA / RPC OPERATIVO
limite diario TX
limite cripto/token
limite FIAT
moneda FIAT
precios manuales/offline
DEX permitidos
CEX permitidos
politicas por cuenta
reglas programadas
inspector RPC
rearme del disyuntor
```

Resultado:

```text
OK a nivel de interfaz y flujo interno.
```

Limitacion:

```text
Las consultas reales a nodos blockchain no estan implementadas todavia.
```

## 3.2. Politicas por cuenta

Estado:

```text
Integrado.
```

Funciones presentes:

```text
crear politica
editar politica
eliminar politica
asignar chain
asignar cuenta
asignar indice o wildcard
etiqueta
max TX
max cripto/token
max FIAT
moneda FIAT
confirmacion local
destinos permitidos
contratos permitidos
activo/limite
```

Backend:

```text
upsert_account_policy
remove_account_policy
validate_account_policy
```

Resultado:

```text
OK a nivel de compilacion e integracion interna.
```

Pendiente para test funcional completo:

```text
persistencia cifrada de politicas dentro del vault
confirmacion visual antes de eliminar
validacion visual mas estricta de direcciones por cadena
edicion avanzada de varios limites por activo
```

## 3.3. Reglas programadas

Estado:

```text
Integrado.
```

Funciones presentes:

```text
crear regla
eliminar regla por nombre
nombre
activo
destino
max TX
max activo
max FIAT
moneda
ventana diaria/semanal/mensual/custom
caducidad UNIX
```

Backend:

```text
add_scheduled_policy
remove_scheduled_policy
validate_scheduled_rules
```

Resultado:

```text
OK a nivel de compilacion e integracion interna.
```

Pendiente para test funcional completo:

```text
contador independiente por regla
ventana temporal real por regla
historial local de ejecuciones por regla
persistencia cifrada
confirmacion visual antes de eliminar
selector de fecha legible en vez de UNIX manual
```

## 3.4. Oraculo de precios

Estado:

```text
Integrado en modo manual/offline.
```

Funciones presentes:

```text
activo
fiat
valor
fuente manual-local
lista de precios
sin consulta automatica externa
```

Resultado:

```text
OK para modo offline manual.
```

Pendiente para test funcional completo:

```text
importador .lvcprices real
firma Ed25519 de fichero de precios
clave publica de proveedor de precios
rechazo de fichero manipulado
rechazo de fichero caducado
modo RPC/API online
mediana entre fuentes
cache cifrada dentro del vault
```

## 3.5. Auditor visual de direcciones publicas

Estado:

```text
Integrado.
```

Funciones presentes:

```text
seleccion de blockchain soportada
cuenta
indice
ruta HD
direccion/etiqueta
clave publica hexadecimal
estado de soporte por cadena
politica asociada
QR ASCII individual por wallet
copiado de payload publico para extension/aplicacion
```

Payload copiado:

```json
{
  "type": "livencrypt-wallet-link",
  "version": 1,
  "chain": "Ethereum",
  "account": 0,
  "address_index": 0,
  "derivation_path": "m/44'/60'/0'/0/0",
  "address": "0x...",
  "public_key_hex": "...",
  "scope": "public-address-only",
  "warning": "No contiene clave privada ni frase secreta"
}
```

Resultado:

```text
OK a nivel de frontend/backend.
```

Pendiente para test funcional completo:

```text
validacion visual de formato de direccion por cadena
exportacion QR a archivo imagen
selector de cuenta con alias persistente
historial de direcciones generadas
soporte real para Monero/ZCash/Starknet cuando existan adaptadores
```

## 3.6. Inspector RPC blockchain

Estado:

```text
Interfaz integrada.
Backend RPC real pendiente.
```

Funciones presentes:

```text
seleccion de red
direccion
activo
balance
nonce
fee
estado TX
bloqueo en OFFLINE
```

Resultado actual esperado al pedir lectura RPC:

```text
RPC lectura pendiente de adaptador auditado
RPC nonce pendiente de adaptador auditado
RPC fee pendiente de adaptador auditado
RPC estado TX pendiente de adaptador auditado
```

Conclusion:

```text
El test real contra nodos blockchain NO puede considerarse superado todavia.
La interfaz esta preparada, pero falta implementar adaptadores RPC reales.
```

## 3.7. Broadcast

Estado:

```text
Bloqueado por seguridad.
```

Resultado esperado:

```text
broadcast bloqueado: requiere adaptador RPC operativo auditado y politica local
```

Conclusion:

```text
Correcto. No debe abrirse hasta existir RPC OPERATIVO real, adaptador auditado, politica local, confirmacion y pruebas en testnet/devnet.
```

## 4. Test de nodos blockchain no realizado

No se ha podido realizar check real de nodos blockchain porque faltan funciones de backend.

Funciones ausentes:

```text
EthereumRpcAdapter real
BitcoinRpcAdapter real o ElectrumAdapter real
SolanaRpcAdapter real
cliente RPC HTTP/WebSocket
validacion chain ID
lectura balance
lectura nonce
estimacion fee/gas
estado de transaccion
lectura altura/slot
lectura timestamp de bloque
fallback automatico
comparacion primario/fallback
deteccion de nodo atrasado
control de divergencia entre nodos
registro de endpoint usado
```

## 5. Detalle de adaptadores pendientes

### 5.1. Ethereum / EVM

Falta integrar:

```text
EthereumRpcAdapter
eth_chainId
eth_getBalance
eth_getTransactionCount
eth_gasPrice o eth_feeHistory
eth_getTransactionReceipt
eth_getBlockByNumber
validacion de chain ID permitido
validacion de endpoint permitido
timeout por request
fallback RPC
normalizacion wei -> ETH
normalizacion ERC-20 con decimals
```

Test pendiente:

```text
consultar balance real
consultar nonce real
consultar gas real
consultar estado TX real
comparar con explorador independiente
comparar primario/fallback
```

### 5.2. Bitcoin

Falta integrar:

```text
BitcoinRpcAdapter o ElectrumAdapter
getblockchaininfo
getblockcount
getblockhash
getblockheader
lectura UTXO o balance por direccion
estado de TX
fee estimate
validacion de red mainnet/testnet
normalizacion satoshis -> BTC
```

Test pendiente:

```text
altura real
timestamp real de bloque
balance real si endpoint lo permite
estado TX real
fee real
fallback
```

### 5.3. Solana

Falta integrar:

```text
SolanaRpcAdapter
getHealth
getVersion
getBalance
getLatestBlockhash
getFeeForMessage
getSignatureStatuses
getSlot
validacion cluster mainnet/devnet/testnet
normalizacion lamports -> SOL
```

Test pendiente:

```text
balance real
slot real
fee real
estado de firma real
fallback
```

### 5.4. Monero

Falta integrar:

```text
MoneroKeymaster separado
MoneroRpcAdapter
view key / spend key
subaddresses
key images
parser Monero
validacion de fees
estado de transaccion
```

Estado correcto actual:

```text
no soportado para firma real
```

### 5.5. ZCash

Falta integrar:

```text
ZcashTransparentAdapter
ZcashShieldedAdapter
Sapling/Orchard si se soporta shielded
viewing keys
parser especifico
pruebas ZK mediante libreria auditada
```

Estado correcto actual:

```text
no soportado para firma real
```

### 5.6. Starknet

Falta integrar:

```text
StarknetAdapter
modelo account abstraction
nonce
calldata
selectors
firma Stark/Pedersen/Poseidon segun cuenta
validacion de contrato de cuenta
```

Estado correcto actual:

```text
no soportado para firma real
```

## 6. Test que si puede considerarse aprobado ahora

```text
compilacion del proyecto
presencia de pantallas frontend Web3
conexiones de comandos worker
modelo de politicas por cuenta
modelo de reglas programadas
modelo de precios manuales
bloqueo de RPC en OFFLINE
rechazo seguro de broadcast
QR ASCII individual por wallet
copiado de payload publico
separacion de clave publica frente a clave privada
```

## 7. Test que no puede aprobarse aun

```text
check real de nodos Ethereum
check real de nodos Bitcoin
check real de nodos Solana
lectura real de balance
lectura real de nonce
estimacion real de fee
estado real de TX
reloj verificado por consenso de nodos
fallback real entre nodos
deteccion real de nodo malicioso o atrasado
actualizacion online de precios
broadcast real en testnet/devnet
```

Motivo:

```text
faltan adaptadores RPC reales por cadena.
```

## 8. Proximo codigo a integrar

Prioridad 1:

```text
src-tui/src/crypto/blockchain/rpc_ethereum.rs
src-tui/src/crypto/blockchain/rpc_bitcoin.rs
src-tui/src/crypto/blockchain/rpc_solana.rs
```

Prioridad 2:

```text
NodeHealth
BalanceResult
NonceState
FeeEstimate
TransactionStatus
BroadcastResult
ChainClockSample
```

Prioridad 3:

```text
gestor de endpoints permitidos
fallback primario/secundario
comparador de respuestas
detector de drift temporal
cache de precios cifrada
importador firmado .lvcprices
```

Prioridad 4:

```text
testnet/devnet broadcast controlado
confirmacion local reforzada
registro de auditoria de cada lectura RPC
```

## 9. Conclusion

El estado actual es:

```text
Frontend Web3: integrado parcialmente completo.
Politicas y reglas: integradas a nivel de flujo interno.
Auditor visual: integrado con QR y copiado publico.
RPC blockchain real: pendiente.
Broadcast: correctamente bloqueado.
```

No se puede declarar completado el test real contra nodos blockchain hasta implementar adaptadores RPC reales para cada cadena.

## 10. Codigo necesario para completar el test real de nodos blockchain

Esta seccion define el codigo que debe integrarse en la aplicacion para que el test real de nodos blockchain pueda ejecutarse y aprobarse.

Objetivo:

```text
reemplazar las respuestas "pendiente de adaptador auditado"
por lecturas RPC reales, verificables y controladas por perfil.
```

## 10.1. Archivos nuevos a crear

```text
src-tui/src/crypto/blockchain/rpc_types.rs
src-tui/src/crypto/blockchain/rpc_client.rs
src-tui/src/crypto/blockchain/rpc_ethereum.rs
src-tui/src/crypto/blockchain/rpc_bitcoin.rs
src-tui/src/crypto/blockchain/rpc_solana.rs
src-tui/src/crypto/blockchain/rpc_manager.rs
src-tui/src/crypto/blockchain/price_import.rs
src-tui/src/crypto/blockchain/web3_audit.rs
```

Actualizar:

```text
src-tui/src/crypto/blockchain/mod.rs
src-tui/src/crypto/blockchain/rpc.rs
src-tui/src/crypto/blockchain/worker.rs
src-tui/src/crypto/blockchain/nodes.rs
src-tui/src/main.rs
```

## 10.2. Tipos RPC comunes

Archivo:

```text
src-tui/src/crypto/blockchain/rpc_types.rs
```

Codigo:

```rust
// SPDX-License-Identifier: GPL-3.0-or-later
/* rol: tipos comunes para lecturas RPC blockchain reales */

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeHealth {
    pub chain: String,
    pub endpoint: String,
    pub network_id: String,
    pub block_height_or_slot: Option<u64>,
    pub block_time_unix: Option<u64>,
    pub latency_ms: u128,
    pub ok: bool,
    pub warning: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceResult {
    pub chain: String,
    pub address: String,
    pub asset: String,
    pub amount: Decimal,
    pub raw_amount: String,
    pub endpoint: String,
    pub block_height_or_slot: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceState {
    pub chain: String,
    pub address: String,
    pub nonce: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub chain: String,
    pub asset: String,
    pub fee_amount: Decimal,
    pub raw_fee: String,
    pub source: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionStatus {
    pub chain: String,
    pub txid: String,
    pub confirmed: bool,
    pub confirmations: Option<u64>,
    pub block_height_or_slot: Option<u64>,
    pub success: Option<bool>,
    pub endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BroadcastResult {
    pub chain: String,
    pub txid: String,
    pub endpoint: String,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainClockSample {
    pub chain: String,
    pub endpoint: String,
    pub local_unix: u64,
    pub chain_unix: Option<u64>,
    pub block_height_or_slot: Option<u64>,
    pub drift_seconds: Option<u64>,
}
```

## 10.3. Cliente HTTP JSON-RPC controlado

Archivo:

```text
src-tui/src/crypto/blockchain/rpc_client.rs
```

Dependencias necesarias en `src-tui/Cargo.toml`:

```toml
ureq = { version = "2.12", default-features = false, features = ["json", "tls"] }
```

Codigo:

```rust
// SPDX-License-Identifier: GPL-3.0-or-later
/* rol: cliente JSON-RPC saliente con timeout y limite de respuesta */

use serde_json::{json, Value};
use std::time::Duration;

const MAX_RPC_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

pub fn json_rpc_call(
    endpoint: &str,
    method: &str,
    params: Value,
    timeout_ms: u64,
) -> Result<Value, String> {
    if !endpoint.starts_with("https://") && !endpoint.starts_with("http://127.0.0.1") {
        return Err("endpoint RPC no permitido: use HTTPS o localhost auditado".into());
    }

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(timeout_ms.clamp(500, 30_000)))
        .build();

    let response = agent
        .post(endpoint)
        .set("content-type", "application/json")
        .send_json(body)
        .map_err(|error| format!("RPC {} fallo: {}", method, error))?;

    let mut reader = response.into_reader().take(MAX_RPC_RESPONSE_BYTES as u64);
    let mut raw = String::new();
    std::io::Read::read_to_string(&mut reader, &mut raw)
        .map_err(|error| format!("RPC lectura respuesta fallo: {}", error))?;

    let value: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("RPC JSON invalido: {}", error))?;

    if let Some(error) = value.get("error") {
        return Err(format!("RPC {} devolvio error: {}", method, error));
    }

    value
        .get("result")
        .cloned()
        .ok_or_else(|| format!("RPC {} sin campo result", method))
}
```

## 10.4. Ampliar trait `ChainRpcAdapter`

Archivo:

```text
src-tui/src/crypto/blockchain/rpc.rs
```

Sustituir o ampliar el trait:

```rust
use crate::crypto::blockchain::rpc_types::{
    BalanceResult, BroadcastResult, ChainClockSample, FeeEstimate, NodeHealth, NonceState,
    TransactionStatus,
};

pub trait ChainRpcAdapter {
    fn chain_name(&self) -> &str;
    fn endpoint_policy(&self) -> &NodeEndpointPolicy;

    fn health(&self) -> Result<NodeHealth, String>;
    fn read_balance(&self, address: &str, asset: &str) -> Result<BalanceResult, String>;
    fn read_nonce(&self, address: &str) -> Result<NonceState, String>;
    fn estimate_fee(&self, raw_payload: &[u8]) -> Result<FeeEstimate, String>;
    fn read_transaction_status(&self, txid: &str) -> Result<TransactionStatus, String>;
    fn read_chain_clock(&self) -> Result<ChainClockSample, String>;
    fn broadcast_transaction(&self, signed_payload: &[u8]) -> Result<BroadcastResult, String>;
}
```

Regla obligatoria:

```text
broadcast_transaction solo se ejecuta si perfil == RPC OPERATIVO
```

## 10.5. EthereumRpcAdapter

Archivo:

```text
src-tui/src/crypto/blockchain/rpc_ethereum.rs
```

Codigo base:

```rust
// SPDX-License-Identifier: GPL-3.0-or-later
/* rol: adaptador RPC real Ethereum/EVM */

use crate::crypto::blockchain::rpc::ChainRpcAdapter;
use crate::crypto::blockchain::rpc_client::json_rpc_call;
use crate::crypto::blockchain::rpc_types::*;
use crate::crypto::blockchain::types::NodeEndpointPolicy;
use rust_decimal::Decimal;
use serde_json::json;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct EthereumRpcAdapter {
    policy: NodeEndpointPolicy,
}

impl EthereumRpcAdapter {
    pub fn new(policy: NodeEndpointPolicy) -> Self {
        Self { policy }
    }

    fn endpoint(&self) -> &str {
        &self.policy.primary_endpoint
    }

    fn timeout_ms(&self) -> u64 {
        self.policy.timeout_ms
    }
}

fn hex_u64(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| format!("hex u64 invalido: {}", error))
}

fn hex_u128(value: &str) -> Result<u128, String> {
    u128::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| format!("hex u128 invalido: {}", error))
}

fn wei_to_eth(value: u128) -> Decimal {
    Decimal::from(value) / Decimal::from(1_000_000_000_000_000_000u128)
}

impl ChainRpcAdapter for EthereumRpcAdapter {
    fn chain_name(&self) -> &str {
        "ethereum"
    }

    fn endpoint_policy(&self) -> &NodeEndpointPolicy {
        &self.policy
    }

    fn health(&self) -> Result<NodeHealth, String> {
        let started = Instant::now();
        let chain_id = json_rpc_call(self.endpoint(), "eth_chainId", json!([]), self.timeout_ms())?;
        let chain_id = chain_id.as_str().ok_or("eth_chainId no es string")?.to_string();

        if !self.policy.require_chain_id.is_empty() && chain_id != self.policy.require_chain_id {
            return Err(format!(
                "chain ID no coincide: esperado {}, recibido {}",
                self.policy.require_chain_id, chain_id
            ));
        }

        let block_number = json_rpc_call(self.endpoint(), "eth_blockNumber", json!([]), self.timeout_ms())?;
        let block_height = block_number.as_str().map(hex_u64).transpose()?;

        Ok(NodeHealth {
            chain: "ethereum".to_string(),
            endpoint: self.endpoint().to_string(),
            network_id: chain_id,
            block_height_or_slot: block_height,
            block_time_unix: None,
            latency_ms: started.elapsed().as_millis(),
            ok: true,
            warning: None,
        })
    }

    fn read_balance(&self, address: &str, asset: &str) -> Result<BalanceResult, String> {
        if asset != "native" && asset != "ETH" {
            return Err("balance ERC-20 requiere llamada eth_call balanceOf pendiente".into());
        }
        let result = json_rpc_call(
            self.endpoint(),
            "eth_getBalance",
            json!([address, "latest"]),
            self.timeout_ms(),
        )?;
        let raw = result.as_str().ok_or("eth_getBalance no es string")?;
        let wei = hex_u128(raw)?;
        Ok(BalanceResult {
            chain: "ethereum".to_string(),
            address: address.to_string(),
            asset: "ETH".to_string(),
            amount: wei_to_eth(wei),
            raw_amount: raw.to_string(),
            endpoint: self.endpoint().to_string(),
            block_height_or_slot: None,
        })
    }

    fn read_nonce(&self, address: &str) -> Result<NonceState, String> {
        let result = json_rpc_call(
            self.endpoint(),
            "eth_getTransactionCount",
            json!([address, "latest"]),
            self.timeout_ms(),
        )?;
        Ok(NonceState {
            chain: "ethereum".to_string(),
            address: address.to_string(),
            nonce: result.as_str().unwrap_or_default().to_string(),
            endpoint: self.endpoint().to_string(),
        })
    }

    fn estimate_fee(&self, _raw_payload: &[u8]) -> Result<FeeEstimate, String> {
        let gas_price = json_rpc_call(self.endpoint(), "eth_gasPrice", json!([]), self.timeout_ms())?;
        let raw = gas_price.as_str().ok_or("eth_gasPrice no es string")?;
        let wei = hex_u128(raw)?;
        Ok(FeeEstimate {
            chain: "ethereum".to_string(),
            asset: "ETH".to_string(),
            fee_amount: wei_to_eth(wei),
            raw_fee: raw.to_string(),
            source: "eth_gasPrice".to_string(),
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_transaction_status(&self, txid: &str) -> Result<TransactionStatus, String> {
        let result = json_rpc_call(
            self.endpoint(),
            "eth_getTransactionReceipt",
            json!([txid]),
            self.timeout_ms(),
        )?;
        let confirmed = !result.is_null();
        let block = result
            .get("blockNumber")
            .and_then(|value| value.as_str())
            .map(hex_u64)
            .transpose()?;
        let success = result
            .get("status")
            .and_then(|value| value.as_str())
            .map(|status| status == "0x1");
        Ok(TransactionStatus {
            chain: "ethereum".to_string(),
            txid: txid.to_string(),
            confirmed,
            confirmations: None,
            block_height_or_slot: block,
            success,
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_chain_clock(&self) -> Result<ChainClockSample, String> {
        let block = json_rpc_call(
            self.endpoint(),
            "eth_getBlockByNumber",
            json!(["latest", false]),
            self.timeout_ms(),
        )?;
        let timestamp = block
            .get("timestamp")
            .and_then(|value| value.as_str())
            .map(hex_u64)
            .transpose()?;
        let number = block
            .get("number")
            .and_then(|value| value.as_str())
            .map(hex_u64)
            .transpose()?;
        let local_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let drift = timestamp.map(|chain_unix| local_unix.abs_diff(chain_unix));
        Ok(ChainClockSample {
            chain: "ethereum".to_string(),
            endpoint: self.endpoint().to_string(),
            local_unix,
            chain_unix: timestamp,
            block_height_or_slot: number,
            drift_seconds: drift,
        })
    }

    fn broadcast_transaction(&self, signed_payload: &[u8]) -> Result<BroadcastResult, String> {
        if !self.policy.allow_broadcast {
            return Err("broadcast Ethereum bloqueado por politica de endpoint".into());
        }
        let hex_payload = format!("0x{}", hex::encode(signed_payload));
        let result = json_rpc_call(
            self.endpoint(),
            "eth_sendRawTransaction",
            json!([hex_payload]),
            self.timeout_ms(),
        )?;
        let txid = result.as_str().ok_or("eth_sendRawTransaction no devolvio txid")?;
        Ok(BroadcastResult {
            chain: "ethereum".to_string(),
            txid: txid.to_string(),
            endpoint: self.endpoint().to_string(),
            accepted: true,
        })
    }
}
```

## 10.6. SolanaRpcAdapter

Archivo:

```text
src-tui/src/crypto/blockchain/rpc_solana.rs
```

Codigo base:

```rust
// SPDX-License-Identifier: GPL-3.0-or-later
/* rol: adaptador RPC real Solana */

use crate::crypto::blockchain::rpc::ChainRpcAdapter;
use crate::crypto::blockchain::rpc_client::json_rpc_call;
use crate::crypto::blockchain::rpc_types::*;
use crate::crypto::blockchain::types::NodeEndpointPolicy;
use rust_decimal::Decimal;
use serde_json::json;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct SolanaRpcAdapter {
    policy: NodeEndpointPolicy,
}

impl SolanaRpcAdapter {
    pub fn new(policy: NodeEndpointPolicy) -> Self {
        Self { policy }
    }
    fn endpoint(&self) -> &str {
        &self.policy.primary_endpoint
    }
}

fn lamports_to_sol(value: u64) -> Decimal {
    Decimal::from(value) / Decimal::from(1_000_000_000u64)
}

impl ChainRpcAdapter for SolanaRpcAdapter {
    fn chain_name(&self) -> &str {
        "solana"
    }

    fn endpoint_policy(&self) -> &NodeEndpointPolicy {
        &self.policy
    }

    fn health(&self) -> Result<NodeHealth, String> {
        let started = Instant::now();
        let health = json_rpc_call(self.endpoint(), "getHealth", json!([]), self.policy.timeout_ms)?;
        let slot = json_rpc_call(self.endpoint(), "getSlot", json!([]), self.policy.timeout_ms)?;
        Ok(NodeHealth {
            chain: "solana".to_string(),
            endpoint: self.endpoint().to_string(),
            network_id: health.as_str().unwrap_or("unknown").to_string(),
            block_height_or_slot: slot.as_u64(),
            block_time_unix: None,
            latency_ms: started.elapsed().as_millis(),
            ok: true,
            warning: None,
        })
    }

    fn read_balance(&self, address: &str, asset: &str) -> Result<BalanceResult, String> {
        if asset != "native" && asset != "SOL" {
            return Err("SPL token balance pendiente de implementacion".into());
        }
        let result = json_rpc_call(
            self.endpoint(),
            "getBalance",
            json!([address]),
            self.policy.timeout_ms,
        )?;
        let lamports = result
            .get("value")
            .and_then(|value| value.as_u64())
            .ok_or("getBalance sin value")?;
        Ok(BalanceResult {
            chain: "solana".to_string(),
            address: address.to_string(),
            asset: "SOL".to_string(),
            amount: lamports_to_sol(lamports),
            raw_amount: lamports.to_string(),
            endpoint: self.endpoint().to_string(),
            block_height_or_slot: None,
        })
    }

    fn read_nonce(&self, address: &str) -> Result<NonceState, String> {
        Ok(NonceState {
            chain: "solana".to_string(),
            address: address.to_string(),
            nonce: "Solana no usa nonce EVM; use blockhash reciente".to_string(),
            endpoint: self.endpoint().to_string(),
        })
    }

    fn estimate_fee(&self, raw_payload: &[u8]) -> Result<FeeEstimate, String> {
        if raw_payload.is_empty() {
            return Err("fee Solana requiere mensaje serializado".into());
        }
        let encoded = bs58::encode(raw_payload).into_string();
        let result = json_rpc_call(
            self.endpoint(),
            "getFeeForMessage",
            json!([encoded]),
            self.policy.timeout_ms,
        )?;
        let fee = result
            .get("value")
            .and_then(|value| value.as_u64())
            .ok_or("getFeeForMessage sin value")?;
        Ok(FeeEstimate {
            chain: "solana".to_string(),
            asset: "SOL".to_string(),
            fee_amount: lamports_to_sol(fee),
            raw_fee: fee.to_string(),
            source: "getFeeForMessage".to_string(),
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_transaction_status(&self, txid: &str) -> Result<TransactionStatus, String> {
        let result = json_rpc_call(
            self.endpoint(),
            "getSignatureStatuses",
            json!([[txid], { "searchTransactionHistory": true }]),
            self.policy.timeout_ms,
        )?;
        let value = result
            .get("value")
            .and_then(|value| value.as_array())
            .and_then(|items| items.first())
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let confirmed = !value.is_null();
        let slot = value.get("slot").and_then(|value| value.as_u64());
        let success = value.get("err").map(|value| value.is_null());
        Ok(TransactionStatus {
            chain: "solana".to_string(),
            txid: txid.to_string(),
            confirmed,
            confirmations: None,
            block_height_or_slot: slot,
            success,
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_chain_clock(&self) -> Result<ChainClockSample, String> {
        let slot = json_rpc_call(self.endpoint(), "getSlot", json!([]), self.policy.timeout_ms)?;
        let slot = slot.as_u64();
        let local_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(ChainClockSample {
            chain: "solana".to_string(),
            endpoint: self.endpoint().to_string(),
            local_unix,
            chain_unix: None,
            block_height_or_slot: slot,
            drift_seconds: None,
        })
    }

    fn broadcast_transaction(&self, signed_payload: &[u8]) -> Result<BroadcastResult, String> {
        if !self.policy.allow_broadcast {
            return Err("broadcast Solana bloqueado por politica de endpoint".into());
        }
        let encoded = bs58::encode(signed_payload).into_string();
        let result = json_rpc_call(
            self.endpoint(),
            "sendTransaction",
            json!([encoded]),
            self.policy.timeout_ms,
        )?;
        let txid = result.as_str().ok_or("sendTransaction no devolvio firma")?;
        Ok(BroadcastResult {
            chain: "solana".to_string(),
            txid: txid.to_string(),
            endpoint: self.endpoint().to_string(),
            accepted: true,
        })
    }
}
```

## 10.7. Bitcoin/Electrum adapter

Bitcoin Core no permite consultar balances por direccion de forma universal sin indexador. Para Livencrypt se recomienda usar Electrum Server auditado para lectura de direcciones.

Archivo:

```text
src-tui/src/crypto/blockchain/rpc_bitcoin.rs
```

Codigo base recomendado:

```rust
// SPDX-License-Identifier: GPL-3.0-or-later
/* rol: adaptador Bitcoin mediante endpoint Electrum HTTPS/JSON-RPC */

use crate::crypto::blockchain::rpc::ChainRpcAdapter;
use crate::crypto::blockchain::rpc_client::json_rpc_call;
use crate::crypto::blockchain::rpc_types::*;
use crate::crypto::blockchain::types::NodeEndpointPolicy;
use rust_decimal::Decimal;
use serde_json::json;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct BitcoinElectrumAdapter {
    policy: NodeEndpointPolicy,
}

impl BitcoinElectrumAdapter {
    pub fn new(policy: NodeEndpointPolicy) -> Self {
        Self { policy }
    }
    fn endpoint(&self) -> &str {
        &self.policy.primary_endpoint
    }
}

fn sats_to_btc(value: u64) -> Decimal {
    Decimal::from(value) / Decimal::from(100_000_000u64)
}

impl ChainRpcAdapter for BitcoinElectrumAdapter {
    fn chain_name(&self) -> &str {
        "bitcoin"
    }

    fn endpoint_policy(&self) -> &NodeEndpointPolicy {
        &self.policy
    }

    fn health(&self) -> Result<NodeHealth, String> {
        let started = Instant::now();
        let height = json_rpc_call(
            self.endpoint(),
            "blockchain.headers.subscribe",
            json!([]),
            self.policy.timeout_ms,
        )?
        .get("height")
        .and_then(|value| value.as_u64());

        Ok(NodeHealth {
            chain: "bitcoin".to_string(),
            endpoint: self.endpoint().to_string(),
            network_id: self.policy.require_chain_id.clone(),
            block_height_or_slot: height,
            block_time_unix: None,
            latency_ms: started.elapsed().as_millis(),
            ok: true,
            warning: None,
        })
    }

    fn read_balance(&self, script_hash: &str, asset: &str) -> Result<BalanceResult, String> {
        if asset != "native" && asset != "BTC" {
            return Err("Bitcoin solo soporta BTC nativo".into());
        }
        let result = json_rpc_call(
            self.endpoint(),
            "blockchain.scripthash.get_balance",
            json!([script_hash]),
            self.policy.timeout_ms,
        )?;
        let confirmed = result
            .get("confirmed")
            .and_then(|value| value.as_u64())
            .ok_or("balance Electrum sin confirmed")?;
        Ok(BalanceResult {
            chain: "bitcoin".to_string(),
            address: script_hash.to_string(),
            asset: "BTC".to_string(),
            amount: sats_to_btc(confirmed),
            raw_amount: confirmed.to_string(),
            endpoint: self.endpoint().to_string(),
            block_height_or_slot: None,
        })
    }

    fn read_nonce(&self, address: &str) -> Result<NonceState, String> {
        Ok(NonceState {
            chain: "bitcoin".to_string(),
            address: address.to_string(),
            nonce: "Bitcoin usa UTXO; nonce no aplica".to_string(),
            endpoint: self.endpoint().to_string(),
        })
    }

    fn estimate_fee(&self, _raw_payload: &[u8]) -> Result<FeeEstimate, String> {
        let result = json_rpc_call(
            self.endpoint(),
            "blockchain.estimatefee",
            json!([6]),
            self.policy.timeout_ms,
        )?;
        let btc_per_kb = Decimal::from_f64_retain(result.as_f64().unwrap_or_default())
            .unwrap_or(Decimal::ZERO);
        Ok(FeeEstimate {
            chain: "bitcoin".to_string(),
            asset: "BTC".to_string(),
            fee_amount: btc_per_kb,
            raw_fee: result.to_string(),
            source: "blockchain.estimatefee".to_string(),
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_transaction_status(&self, txid: &str) -> Result<TransactionStatus, String> {
        let result = json_rpc_call(
            self.endpoint(),
            "blockchain.transaction.get",
            json!([txid, true]),
            self.policy.timeout_ms,
        )?;
        let confirmations = result.get("confirmations").and_then(|value| value.as_u64());
        Ok(TransactionStatus {
            chain: "bitcoin".to_string(),
            txid: txid.to_string(),
            confirmed: confirmations.unwrap_or(0) > 0,
            confirmations,
            block_height_or_slot: result.get("blockheight").and_then(|value| value.as_u64()),
            success: None,
            endpoint: self.endpoint().to_string(),
        })
    }

    fn read_chain_clock(&self) -> Result<ChainClockSample, String> {
        let health = self.health()?;
        let local_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(ChainClockSample {
            chain: "bitcoin".to_string(),
            endpoint: self.endpoint().to_string(),
            local_unix,
            chain_unix: health.block_time_unix,
            block_height_or_slot: health.block_height_or_slot,
            drift_seconds: None,
        })
    }

    fn broadcast_transaction(&self, signed_payload: &[u8]) -> Result<BroadcastResult, String> {
        if !self.policy.allow_broadcast {
            return Err("broadcast Bitcoin bloqueado por politica de endpoint".into());
        }
        let tx_hex = hex::encode(signed_payload);
        let result = json_rpc_call(
            self.endpoint(),
            "blockchain.transaction.broadcast",
            json!([tx_hex]),
            self.policy.timeout_ms,
        )?;
        let txid = result.as_str().ok_or("broadcast Bitcoin no devolvio txid")?;
        Ok(BroadcastResult {
            chain: "bitcoin".to_string(),
            txid: txid.to_string(),
            endpoint: self.endpoint().to_string(),
            accepted: true,
        })
    }
}
```

Nota:

```text
Para Bitcoin, el campo "address" del inspector debe aceptar scripthash Electrum
o debe integrarse una funcion address -> scriptpubkey -> scripthash.
```

## 10.8. RpcManager con fallback

Archivo:

```text
src-tui/src/crypto/blockchain/rpc_manager.rs
```

Codigo base:

```rust
// SPDX-License-Identifier: GPL-3.0-or-later
/* rol: gestor de adaptadores RPC por cadena con fallback */

use crate::crypto::blockchain::nodes::NodeRegistry;
use crate::crypto::blockchain::rpc::ChainRpcAdapter;
use crate::crypto::blockchain::rpc_bitcoin::BitcoinElectrumAdapter;
use crate::crypto::blockchain::rpc_ethereum::EthereumRpcAdapter;
use crate::crypto::blockchain::rpc_solana::SolanaRpcAdapter;

pub fn adapter_for_chain(
    registry: &NodeRegistry,
    chain: &str,
) -> Result<Box<dyn ChainRpcAdapter + Send>, String> {
    let policy = registry
        .endpoint_policy(chain)
        .ok_or_else(|| format!("no hay endpoint RPC configurado para {}", chain))?;

    match chain.to_lowercase().as_str() {
        "ethereum" => Ok(Box::new(EthereumRpcAdapter::new(policy))),
        "bitcoin" => Ok(Box::new(BitcoinElectrumAdapter::new(policy))),
        "solana" => Ok(Box::new(SolanaRpcAdapter::new(policy))),
        other => Err(format!("cadena sin adaptador RPC auditado: {}", other)),
    }
}
```

## 10.9. Integracion en `worker.rs`

Actualmente los comandos RPC responden:

```text
pendiente de adaptador auditado
```

Debe sustituirse por:

```rust
Web3WorkerCmd::RpcReadBalance { chain, address, asset } => {
    let result = crate::crypto::blockchain::rpc_manager::adapter_for_chain(&node_registry, &chain)
        .and_then(|adapter| adapter.read_balance(&address, &asset))
        .map(|balance| format!(
            "{} {} {} en {}",
            balance.amount, balance.asset, balance.address, balance.endpoint
        ));

    let _ = event_tx.send(Web3WorkerEvent::RpcInspectorResult {
        label: "balance".to_string(),
        result,
    });
}

Web3WorkerCmd::RpcReadNonce { chain, address } => {
    let result = crate::crypto::blockchain::rpc_manager::adapter_for_chain(&node_registry, &chain)
        .and_then(|adapter| adapter.read_nonce(&address))
        .map(|nonce| nonce.nonce);

    let _ = event_tx.send(Web3WorkerEvent::RpcInspectorResult {
        label: "nonce".to_string(),
        result,
    });
}

Web3WorkerCmd::RpcEstimateFee { chain, raw_payload } => {
    let result = crate::crypto::blockchain::rpc_manager::adapter_for_chain(&node_registry, &chain)
        .and_then(|adapter| adapter.estimate_fee(&raw_payload))
        .map(|fee| format!("{} {} ({})", fee.fee_amount, fee.asset, fee.source));

    let _ = event_tx.send(Web3WorkerEvent::RpcInspectorResult {
        label: "fee".to_string(),
        result,
    });
}

Web3WorkerCmd::RpcReadTxStatus { chain, txid } => {
    let result = crate::crypto::blockchain::rpc_manager::adapter_for_chain(&node_registry, &chain)
        .and_then(|adapter| adapter.read_transaction_status(&txid))
        .map(|status| format!(
            "confirmed={} confirmations={:?} success={:?}",
            status.confirmed, status.confirmations, status.success
        ));

    let _ = event_tx.send(Web3WorkerEvent::RpcInspectorResult {
        label: "tx_status".to_string(),
        result,
    });
}
```

Requisito previo:

```text
Web3BackgroundWorker debe recibir o cargar NodeRegistry.
```

Firma recomendada:

```rust
pub fn spawn(
    mut supervisor: GatewaySupervisor,
    node_registry: NodeRegistry,
) -> (Sender<Web3WorkerCmd>, Receiver<Web3WorkerEvent>)
```

## 10.10. Integracion en `main.rs`

Actualizar llamada:

```rust
let node_registry = NodeRegistry::load_from_path(&nodes::default_nodes_path());
let (tx, rx) = Web3BackgroundWorker::spawn(supervisor, node_registry);
```

Actualizar inspector RPC:

```rust
fn request_rpc_balance(state: &mut TuiState) {
    if !state.nodes.profile().allows_rpc_read() {
        state.web3_rpc_status = "Perfil OFFLINE: lectura RPC bloqueada.".to_string();
        return;
    }
    if let Some(tx) = &state.web3_cmd_tx {
        let _ = tx.send(Web3WorkerCmd::RpcReadBalance {
            chain: selected_rpc_chain_name(state).to_lowercase(),
            address: state.web3_rpc_address.clone(),
            asset: state.web3_rpc_asset.clone(),
        });
    }
}
```

## 10.11. Reloj verificado por consenso

Agregar en `rpc_manager.rs`:

```rust
pub fn verified_clock_from_nodes(
    registry: &NodeRegistry,
    chains: &[&str],
) -> Result<VerifiedClockStatus, String> {
    let mut samples = Vec::new();
    for chain in chains {
        if let Ok(adapter) = adapter_for_chain(registry, chain) {
            if let Ok(sample) = adapter.read_chain_clock() {
                if let Some(chain_unix) = sample.chain_unix {
                    samples.push(chain_unix);
                }
            }
        }
    }

    let local_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if samples.is_empty() {
        return Ok(VerifiedClockStatus {
            local_unix,
            consensus_unix: None,
            drift_seconds: None,
            max_drift_seconds: registry.max_clock_drift_seconds(),
            status: "sin muestras de nodos".to_string(),
        });
    }

    samples.sort_unstable();
    let consensus = samples[samples.len() / 2];
    let drift = local_unix.abs_diff(consensus);
    let ok = drift <= registry.max_clock_drift_seconds();

    Ok(VerifiedClockStatus {
        local_unix,
        consensus_unix: Some(consensus),
        drift_seconds: Some(drift),
        max_drift_seconds: registry.max_clock_drift_seconds(),
        status: if ok { "OK".to_string() } else { "DRIFT_EXCESIVO".to_string() },
    })
}
```

Regla:

```text
si perfil RPC OPERATIVO y drift > limite, bloquear firma y broadcast.
```

## 10.12. Importador firmado `.lvcprices`

Archivo:

```text
src-tui/src/crypto/blockchain/price_import.rs
```

Dependencia:

```toml
ed25519-dalek = "2.2"
```

Codigo base:

```rust
// SPDX-License-Identifier: GPL-3.0-or-later
/* rol: importador de precios firmados para modo offline */

use crate::crypto::blockchain::types::{PriceBook, PriceOracleMode, PriceQuote};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct SignedPriceQuote {
    pub asset: String,
    pub fiat: String,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignedPriceEnvelope {
    pub version: u32,
    pub created_unix: u64,
    pub source: String,
    pub quotes: Vec<SignedPriceQuote>,
    pub public_key: String,
    pub signature: String,
}

fn canonical_price_payload(envelope: &SignedPriceEnvelope) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&serde_json::json!({
        "version": envelope.version,
        "created_unix": envelope.created_unix,
        "source": envelope.source,
        "quotes": envelope.quotes,
    }))
    .map_err(|error| error.to_string())
}

pub fn import_signed_price_file(path: &Path, max_age_seconds: u64) -> Result<PriceBook, String> {
    let raw = std::fs::read(path)
        .map_err(|error| format!("no se pudo leer fichero de precios: {}", error))?;
    if raw.len() > 1024 * 1024 {
        return Err("fichero de precios demasiado grande".into());
    }
    let envelope: SignedPriceEnvelope = serde_json::from_slice(&raw)
        .map_err(|error| format!("fichero de precios invalido: {}", error))?;

    let public_key_bytes = hex::decode(&envelope.public_key)
        .map_err(|error| format!("public key hex invalida: {}", error))?;
    let signature_bytes = hex::decode(&envelope.signature)
        .map_err(|error| format!("firma hex invalida: {}", error))?;

    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| "public key Ed25519 debe tener 32 bytes".to_string())?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "firma Ed25519 debe tener 64 bytes".to_string())?;

    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|error| format!("public key Ed25519 invalida: {}", error))?;
    let signature = Signature::from_bytes(&signature_array);
    let payload = canonical_price_payload(&envelope)?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|error| format!("firma de precios invalida: {}", error))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(envelope.created_unix) > max_age_seconds {
        return Err("fichero de precios caducado".into());
    }

    let mut quotes = Vec::new();
    for quote in envelope.quotes {
        let value = quote
            .value
            .parse::<Decimal>()
            .map_err(|_| "precio decimal invalido".to_string())?;
        quotes.push(PriceQuote {
            asset: quote.asset.to_uppercase(),
            fiat: quote.fiat.to_uppercase(),
            value,
            timestamp_unix: envelope.created_unix,
            source: envelope.source.clone(),
        });
    }

    Ok(PriceBook {
        mode: PriceOracleMode::SignedFile,
        primary_fiat: quotes.first().map(|q| q.fiat.clone()).unwrap_or_else(|| "USD".to_string()),
        max_age_seconds,
        quotes,
    })
}
```

## 10.13. Registro de auditoria Web3

Archivo:

```text
src-tui/src/crypto/blockchain/web3_audit.rs
```

Codigo:

```rust
// SPDX-License-Identifier: GPL-3.0-or-later
/* rol: auditoria local de lecturas RPC y decisiones Web3 */

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Web3AuditEvent {
    pub timestamp_unix: u64,
    pub category: String,
    pub chain: String,
    pub endpoint: Option<String>,
    pub action: String,
    pub result: String,
}

pub fn append_web3_audit_event(event: Web3AuditEvent) -> Result<(), String> {
    let path = crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("web3_audit.jsonl");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let line = serde_json::to_string(&event).map_err(|error| error.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    use std::io::Write;
    writeln!(file, "{}", line).map_err(|error| error.to_string())
}
```

## 10.14. Actualizacion de `mod.rs`

Archivo:

```text
src-tui/src/crypto/blockchain/mod.rs
```

Agregar:

```rust
pub mod rpc_types;
pub mod rpc_client;
pub mod rpc_ethereum;
pub mod rpc_bitcoin;
pub mod rpc_solana;
pub mod rpc_manager;
pub mod price_import;
pub mod web3_audit;
```

## 10.15. Criterio tecnico para aprobar test real

El test real se aprueba solo si:

```text
EthereumRpcAdapter consulta eth_chainId real
EthereumRpcAdapter consulta balance/nonce/fee/tx real
BitcoinElectrumAdapter consulta altura/balance/fee/tx real
SolanaRpcAdapter consulta slot/balance/fee/status real
NodeRegistry aplica endpoint primario/fallback
se rechaza chain ID incorrecto
se rechaza endpoint no HTTPS salvo localhost
OFFLINE no realiza ninguna consulta
RPC LECTURA no hace broadcast
RPC OPERATIVO no hace broadcast sin politica local
broadcast solo se prueba en testnet/devnet o importe minimo
```

## 10.16. Orden recomendado de implementacion

1. Crear `rpc_types.rs`.
2. Crear `rpc_client.rs`.
3. Crear `rpc_ethereum.rs`.
4. Integrar Ethereum en `rpc_manager.rs`.
5. Conectar worker con `NodeRegistry`.
6. Probar `eth_chainId`, balance, nonce y gas.
7. Crear `rpc_solana.rs`.
8. Crear `rpc_bitcoin.rs`.
9. Integrar reloj verificado.
10. Integrar auditoria Web3.
11. Integrar `.lvcprices`.
12. Probar broadcast solo en testnet/devnet.

