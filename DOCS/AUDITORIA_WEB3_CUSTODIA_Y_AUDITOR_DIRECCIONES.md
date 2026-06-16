> ⚠️ **DOCUMENTO OBSOLETO (2026-06-13).** Describe el estado **previo a la integración** del catálogo de remediación. El estado actual del código está en **`AUDITORIA_FUNCIONES_W_CUSTODIA_K_AUDITOR_ESTADO_ACTUAL.md`**. Se conserva solo como referencia histórica.

# Auditoria tecnica: Pasarela Web3 / custodia y auditor visual de direcciones publicas

## 1. Alcance

Este documento audita las funciones:

```text
w = Pasarela Web3 / custodia
k = Auditor visual de direcciones publicas
```

El objetivo es determinar que existe, que riesgos mantiene y que funciones faltan para que Livencrypt 2.0 pueda usarse de forma real como custodio local Web3 sin exponer claves privadas al navegador, DEX, extension o nodo RPC.

## 2. Componentes implicados

Backend/TUI:

```text
src-tui/src/main.rs
src-tui/src/crypto/blockchain/address.rs
src-tui/src/crypto/blockchain/breaker.rs
src-tui/src/crypto/blockchain/firewall.rs
src-tui/src/crypto/blockchain/multi_curve.rs
src-tui/src/crypto/blockchain/nodes.rs
src-tui/src/crypto/blockchain/proxy.rs
src-tui/src/crypto/blockchain/rpc.rs
src-tui/src/crypto/blockchain/rpc_bitcoin.rs
src-tui/src/crypto/blockchain/rpc_client.rs
src-tui/src/crypto/blockchain/rpc_ethereum.rs
src-tui/src/crypto/blockchain/rpc_manager.rs
src-tui/src/crypto/blockchain/rpc_solana.rs
src-tui/src/crypto/blockchain/rpc_types.rs
src-tui/src/crypto/blockchain/supervisor.rs
src-tui/src/crypto/blockchain/tx_parser.rs
src-tui/src/crypto/blockchain/types.rs
src-tui/src/crypto/blockchain/worker.rs
src-tui/src/bin/livencrypt-bridge.rs
```

Extension:

```text
src-tui/extension/livencrypt-web3/manifest.json
src-tui/extension/livencrypt-web3/background.js
src-tui/extension/livencrypt-web3/content.js
src-tui/extension/livencrypt-web3/inject.js
```

Empaquetado:

```text
src-tui/scripts/com.livencrypt.gateway.json
src-tui/scripts/build-deb.sh
src-tui/scripts/postinstall.sh
src-tui/scripts/postremove.sh
```

## 3. Modelo de seguridad esperado

Livencrypt debe actuar como custodio local. El navegador nunca debe recibir:

```text
clave privada
seed
frase Boot Shield
cajas Boot Shield
clave derivada Argon2id
master_seed
payload interno del vault
```

El navegador solo puede recibir:

```text
direccion publica
clave publica
chain_id
estado de solicitud
firma final autorizada
error generico
```

La firma solo debe producirse cuando:

```text
Boot Shield esta desbloqueado
pasarela Web3 esta inicializada
el origen web esta permitido
la cadena coincide
el payload se parsea correctamente
el destino esta permitido
el metodo esta permitido
los limites TX/cripto/FIAT no se exceden
la TUI muestra preview legible
el usuario confirma localmente
```

## 4. Auditoria de `w = Pasarela Web3 / custodia`

### 4.1. Funciones presentes

Estado actual:

```text
host nativo livencrypt-bridge
socket Unix local
worker Web3 separado
limite de conexiones concurrentes
lectura de mensajes nativos con limite 1 MB
derivacion de clave publica
peticiones Web3Account
lectura RPC de balance
lectura RPC de nonce
estimacion fee/gas
preview de firma
confirmacion local pendiente en TUI
broadcast bloqueado por defecto
perfiles OFFLINE / RPC LECTURA / RPC OPERATIVO
politicas por cuenta
reglas programadas
precios manuales/offline
oraculo de precios firmado previsto
QR/payload publico por wallet
```

### 4.2. Riesgos corregidos o mitigados

```text
el navegador no abre la TUI directamente;
el manifiesto apunta a /usr/bin/livencrypt-bridge;
el bridge no custodia claves;
el socket Unix exige usuario local;
el worker valida solicitudes de firma antes de confirmar;
el broadcast sigue bloqueado salvo integracion operativa futura;
la extension no sobrescribe MetaMask si ya existe window.ethereum;
se expone window.livencrypt como proveedor separado.
```

### 4.3. Riesgos residuales

#### Riesgo 1: extension sin UI propia de permisos

La extension actual expone proveedor y reenvia peticiones, pero falta una interfaz propia para aprobar dominios.

Riesgo:

```text
una pagina podria invocar window.livencrypt y solicitar cuentas si la extension esta cargada.
```

Requisito:

```text
lista blanca por dominio;
popup de aprobacion;
recordar decision por origen;
revocacion manual;
mostrar origen en la TUI;
rechazar iframes o contextos no principales.
```

#### Riesgo 2: firma Ethereum incompleta para DEX reales

El flujo `eth_sendTransaction` necesita convertir objetos EIP-1193 normales a transacciones serializadas.

Falta:

```text
serializador EIP-1559
serializador legacy
serializador EIP-2930
normalizacion nonce
normalizacion gasLimit
normalizacion maxFeePerGas
normalizacion maxPriorityFeePerGas
validacion chainId
RLP auditado
hash de firma correcto
reconstruccion v/r/s
devolucion rawTx firmada
```

Sin esto, la extension no debe firmar objetos DEX genericos.

#### Riesgo 3: parser Ethereum limitado

El parser reconoce transferencias ETH y ERC-20 `transfer`, pero DEX reales usan llamadas complejas:

```text
approve
transferFrom
permit
swapExactTokensForTokens
multicall
exactInputSingle
execute
setApprovalForAll
safeTransferFrom
```

Requisito:

```text
ABI decoder minimo para selectores conocidos;
deny-by-default para selectores desconocidos;
base local de selectores permitidos;
preview legible de allowances;
alerta para approvals ilimitados;
alerta para permisos NFT;
alerta para contratos proxy;
```

#### Riesgo 4: no hay simulacion de transaccion

Para DEX, antes de firmar se debe simular o verificar:

```text
saldo suficiente
nonce correcto
gas estimado
contrato existente
metodo conocido
chainId correcto
impacto esperado
tokens entrantes/salientes
slippage
spender aprobado
```

Requisito:

```text
eth_call
eth_estimateGas
eth_getCode
eth_feeHistory
eth_getTransactionCount pending
modo lectura contra nodos primario/fallback
comparacion de respuestas entre nodos
```

#### Riesgo 5: nodos RPC maliciosos

Un nodo puede mentir sobre:

```text
balance
nonce
fee
estado TX
chainId
timestamp
codigo de contrato
resultado eth_call
```

Requisito:

```text
lista blanca de endpoints;
chainId obligatorio;
consulta a dos o mas nodos;
fallback con quorum;
detector de altura atrasada;
detector de drift temporal;
registro de endpoint usado;
bloqueo si hay divergencia critica.
```

#### Riesgo 6: broadcast operativo no esta completo

El broadcast debe permanecer bloqueado hasta cumplir:

```text
perfil RPC OPERATIVO;
endpoint auditado;
testnet/devnet validada;
confirmacion local reforzada;
registro de auditoria;
politica por cuenta;
limites activos;
rollback no aplicable;
monitor de estado TX tras envio.
```

## 5. Auditoria de `k = Auditor visual de direcciones publicas`

### 5.1. Funciones presentes

```text
seleccion de cadena Bitcoin/Ethereum/Solana
cuenta
indice
derivacion de clave publica
direccion publica Ethereum
direccion publica Solana
direccion publica Bitcoin P2PKH
ruta HD visible
clave publica hex
payload publico livencrypt-wallet-link
QR ASCII individual
copiado de payload publico
separacion de clave publica y clave privada
```

### 5.2. Riesgos residuales

#### Riesgo 1: Bitcoin solo P2PKH

El auditor genera P2PKH. Para uso moderno faltan:

```text
P2WPKH bech32
P2SH-P2WPKH
Taproot P2TR
selector de tipo de direccion
derivation path coherente por tipo
validacion de checksum
```

Rutas recomendadas:

```text
P2PKH: m/44'/0'/cuenta'/0/indice
P2SH-P2WPKH: m/49'/0'/cuenta'/0/indice
P2WPKH: m/84'/0'/cuenta'/0/indice
P2TR: m/86'/0'/cuenta'/0/indice
```

#### Riesgo 2: QR ASCII no sustituye QR imagen

QR ASCII es util en TUI, pero para integraciones externas conviene:

```text
exportar PNG/SVG
copiar payload JSON
copiar solo direccion
copiar URI por cadena
```

Formatos:

```text
ethereum:0x...
bitcoin:bc1...
solana:<address>
livencrypt-wallet-link:<base64url-json>
```

#### Riesgo 3: falta libreta de cuentas

Actualmente cuenta e indice son manuales. Para uso real falta:

```text
alias por cuenta
etiqueta por direccion
historial de direcciones derivadas
favoritos
ocultar direcciones sensibles
marcar direccion observada/no observada
exportacion watch-only
```

#### Riesgo 4: Monero/ZCash/Starknet no soportados

No deben mostrarse como operativos hasta implementar:

```text
derivacion propia;
formato de direccion;
RPC propio;
parser propio;
firma propia;
validacion de transacciones.
```

## 6. Funciones necesarias para seguridad completa

### 6.1. Extension Web3

Imprescindible:

```text
popup de permisos por dominio
lista blanca de dominios
revocacion de permisos
estado conectado/desconectado
selector de cuenta
selector de indice
selector de cadena
indicador de TUI desbloqueada
indicador de perfil OFFLINE/RPC LECTURA/RPC OPERATIVO
rechazo de iframes no autorizados
proteccion contra sitios no HTTPS salvo localhost
logs minimos sin secretos
```

### 6.2. Proveedor EIP-1193

Metodos obligatorios:

```text
eth_requestAccounts
eth_accounts
eth_chainId
net_version
wallet_switchEthereumChain
wallet_addEthereumChain
eth_getBalance
eth_getTransactionCount
eth_gasPrice
eth_feeHistory
eth_estimateGas
eth_call
eth_sendTransaction
personal_sign
eth_signTypedData_v4
```

Regla:

```text
todo metodo no implementado debe fallar cerrado.
```

### 6.3. Serializacion y firma Ethereum

Falta integrar:

```text
RLP seguro
EIP-155 legacy
EIP-2930
EIP-1559
chainId obligatorio
nonce obligatorio
gas obligatorio
to/data/value normalizados
hash de firma correcto
reconstruccion raw signed tx
validacion de from contra cuenta derivada
```

### 6.4. Decodificador ABI

Falta integrar:

```text
tabla de selectores locales
ERC-20 transfer
ERC-20 approve
ERC-20 transferFrom
ERC-20 permit
ERC-721 setApprovalForAll
ERC-721 safeTransferFrom
Uniswap V2/V3 swaps principales
multicall con decodificacion recursiva
bloqueo de selectores desconocidos
```

### 6.5. Politicas Web3

Falta endurecer:

```text
limite por dominio
limite por contrato
limite por token
limite por spender
limite por metodo
limite por chainId
limite por sesion
limite por ventana temporal
limite por fiat
limite por slippage
prohibicion de approvals ilimitados
confirmacion reforzada para contratos nuevos
```

### 6.6. Auditoria local

Debe registrar:

```text
timestamp
dominio origen
chainId
cuenta
indice
direccion from
direccion to
contrato
selector
metodo decodificado
valor nativo
valor token
fiat estimado
endpoint RPC usado
resultado de prevalidacion
decision usuario
hash del payload
hash de la firma
estado broadcast si aplica
```

No debe registrar:

```text
frase
cajas
clave privada
seed
master_seed
payload secreto del vault
```

### 6.7. Nodos RPC

Falta integrar:

```text
quorum entre nodos
fallback automatico
timeout por endpoint
chainId obligatorio
altura minima
drift maximo
endpoint pinning
modo solo lectura
modo operativo separado
cache local cifrada
alerta de nodo divergente
```

## 7. Funciones necesarias por blockchain

### 7.1. Ethereum/EVM

Prioridad maxima:

```text
EIP-1559 completo
EIP-712 typed data
eth_call
eth_estimateGas
ABI decoder
ERC-20 allowances
ERC-721/1155 approvals
deteccion de proxy contracts
simulacion previa
raw tx firmada
broadcast testnet
```

### 7.2. Bitcoin

Falta:

```text
P2WPKH
P2TR
PSBT
UTXO selection
change address
fee rate sat/vB
Electrum scripthash
Esplora indexer
firma por input
validacion de outputs
bloqueo de dust
```

### 7.3. Solana

Falta:

```text
getLatestBlockhash
constructor de Message
fee para mensaje real
parser de instrucciones
SystemProgram transfer
SPL Token transfer
Associated Token Account
versioned transactions
address lookup tables
simulacion simulateTransaction
```

### 7.4. Monero

Falta:

```text
spend/view keys
subaddresses
wallet-rpc
key images
ring signatures
confidential transactions
view-only mode
```

### 7.5. ZCash

Falta:

```text
t-address
Sapling
Orchard
viewing keys
shielded notes
librerias ZK auditadas
```

### 7.6. Starknet

Falta:

```text
account abstraction
contrato de cuenta
nonce
calldata
selectors
Poseidon/Pedersen
firma Stark
RPC Starknet
```

## 8. Tests necesarios

### 8.1. Tests sin red

```text
derivacion determinista por cadena
direccion esperada por clave publica
QR distinto por wallet
payload livencrypt-wallet-link valido
rechazo de cadena no soportada
rechazo de indice invalido
no exposicion de claves privadas
serializacion/deserializacion de mensajes nativos
limite 1 MB de native messaging
```

### 8.2. Tests RPC reales

```text
Ethereum health
Ethereum chainId
Ethereum balance
Ethereum nonce
Ethereum gas
Ethereum estado TX
Solana health
Solana slot
Solana balance
Solana fee con mensaje real
Bitcoin health
Bitcoin fee
Bitcoin scripthash balance con Electrum
Bitcoin estado TX
quorum entre nodos
fallo controlado de nodo caido
```

### 8.3. Tests extension

```text
window.livencrypt existe
window.ethereum no se pisa si MetaMask existe
eth_requestAccounts devuelve cuenta
eth_accounts respeta permisos
eth_getBalance consulta backend
eth_getTransactionCount consulta backend
eth_gasPrice consulta backend
metodo no soportado falla cerrado
dominio no permitido falla cerrado
iframe no permitido falla cerrado
```

### 8.4. Tests firma

```text
preview aparece en TUI
rechazo usuario no firma
aprobacion usuario firma
payload manipulado falla
chainId incorrecto falla
destino no permitido falla
contrato no permitido falla
limite TX excedido falla
limite FIAT excedido falla
approval ilimitado exige confirmacion reforzada
```

## 9. Prioridad de integracion

### Fase 1: Extension utilizable en lectura

```text
popup permisos por dominio
eth_requestAccounts real
eth_accounts con cache por dominio
eth_getBalance real
eth_getTransactionCount real
eth_gasPrice real
estado visual de conexion
```

### Fase 2: Firma Ethereum segura

```text
serializador EIP-1559
parser/preview ABI
confirmacion local reforzada
firma raw tx
devolucion raw signed tx
broadcast bloqueado
```

### Fase 3: RPC operativo controlado

```text
quorum de nodos
broadcast testnet
seguimiento de TX
auditoria completa
limites por dominio/contrato/metodo
```

### Fase 4: Multicadena real

```text
Bitcoin PSBT + Electrum/Esplora
Solana versioned transactions
Monero
ZCash
Starknet
```

## 10. Bloques de integracion con codigo

Esta seccion detalla como integrar los tres bloques criticos pendientes.

```text
1. extension con permisos por dominio y UI propia;
2. serializacion/decodificacion Ethereum completa;
3. simulacion, quorum RPC y auditoria completa antes de firma.
```

## 10.1. Bloque 1: extension con permisos por dominio y UI propia

### 10.1.1. Archivos implicados

```text
src-tui/extension/livencrypt-web3/manifest.json
src-tui/extension/livencrypt-web3/background.js
src-tui/extension/livencrypt-web3/content.js
src-tui/extension/livencrypt-web3/inject.js
src-tui/extension/livencrypt-web3/popup.html
src-tui/extension/livencrypt-web3/popup.js
src-tui/extension/livencrypt-web3/popup.css
```

### 10.1.2. Objetivo

La extension no debe conceder acceso automatico a cualquier dominio. Debe exigir permiso por origen:

```text
https://app.uniswap.org
https://1inch.io
https://app.aave.com
```

La clave del diseno:

```text
el dominio pide acceso;
la extension guarda el dominio como pendiente;
el usuario abre popup;
el usuario aprueba o rechaza;
solo dominios aprobados pueden invocar eth_requestAccounts y firma.
```

### 10.1.3. Actualizacion de `manifest.json`

```json
{
  "manifest_version": 3,
  "name": "Livencrypt Web3 Bridge",
  "version": "0.2.0",
  "description": "Proveedor Web3 local para Livencrypt 2.0 mediante livencrypt-bridge.",
  "permissions": [
    "nativeMessaging",
    "storage",
    "activeTab"
  ],
  "host_permissions": [
    "https://*/*",
    "http://localhost/*",
    "http://127.0.0.1/*"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": [
        "https://*/*",
        "http://localhost/*",
        "http://127.0.0.1/*"
      ],
      "js": [
        "content.js"
      ],
      "run_at": "document_start"
    }
  ],
  "web_accessible_resources": [
    {
      "resources": [
        "inject.js"
      ],
      "matches": [
        "https://*/*",
        "http://localhost/*",
        "http://127.0.0.1/*"
      ]
    }
  ],
  "action": {
    "default_title": "Livencrypt Web3",
    "default_popup": "popup.html"
  }
}
```

### 10.1.4. Gestor de permisos en `background.js`

```javascript
const HOST = "com.livencrypt.gateway";
const DEFAULT_CHAIN = "Ethereum";
const DEFAULT_ACCOUNT = 0;
const DEFAULT_INDEX = 0;

async function getPermissions() {
  const data = await chrome.storage.local.get({
    allowedOrigins: {},
    pendingOrigins: {}
  });
  return data;
}

async function setOriginPending(origin) {
  const data = await getPermissions();
  data.pendingOrigins[origin] = {
    origin,
    requested_at: Date.now()
  };
  await chrome.storage.local.set({ pendingOrigins: data.pendingOrigins });
}

async function isOriginAllowed(origin) {
  if (!origin || origin === "null") return false;
  const parsed = new URL(origin);
  const isHttps = parsed.protocol === "https:";
  const isLocal = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  if (!isHttps && !isLocal) return false;

  const data = await getPermissions();
  return Boolean(data.allowedOrigins[origin]);
}

async function requireAllowedOrigin(origin, method) {
  if (await isOriginAllowed(origin)) return;
  await setOriginPending(origin);
  throw new Error(`Origen no autorizado para ${method}. Apruebe el dominio en la extension Livencrypt.`);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.scope !== "livencrypt-web3") {
    return false;
  }

  handleProviderRequest(message.request, message.origin || sender.origin || "")
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));

  return true;
});

async function handleProviderRequest(request, origin) {
  if (!request || typeof request.method !== "string") {
    throw new Error("Solicitud Web3 invalida");
  }

  switch (request.method) {
    case "eth_requestAccounts":
      await requireAllowedOrigin(origin, request.method);
      return requestAccounts(origin);

    case "eth_accounts":
      if (!(await isOriginAllowed(origin))) return [];
      return cachedAccounts(origin);

    case "eth_chainId":
      return "0x1";

    case "net_version":
      return "1";

    case "eth_getBalance":
    case "eth_getTransactionCount":
    case "eth_gasPrice":
      await requireAllowedOrigin(origin, request.method);
      return handleReadMethod(request);

    case "eth_sendTransaction":
    case "personal_sign":
    case "eth_signTypedData_v4":
      await requireAllowedOrigin(origin, request.method);
      return handleSigningMethod(request, origin);

    default:
      throw new Error(`Metodo no soportado por Livencrypt: ${request.method}`);
  }
}
```

### 10.1.5. Popup de permisos

`popup.html`:

```html
<!doctype html>
<html lang="es">
  <head>
    <meta charset="utf-8">
    <link rel="stylesheet" href="popup.css">
    <title>Livencrypt Web3</title>
  </head>
  <body>
    <header>
      <strong>Livencrypt Web3</strong>
      <span id="status">verificando...</span>
    </header>

    <section>
      <h2>Solicitudes pendientes</h2>
      <div id="pending"></div>
    </section>

    <section>
      <h2>Dominios autorizados</h2>
      <div id="allowed"></div>
    </section>

    <script src="popup.js"></script>
  </body>
</html>
```

`popup.js`:

```javascript
async function loadState() {
  const data = await chrome.storage.local.get({
    allowedOrigins: {},
    pendingOrigins: {}
  });
  renderList("pending", Object.keys(data.pendingOrigins), true);
  renderList("allowed", Object.keys(data.allowedOrigins), false);
  document.getElementById("status").textContent = "listo";
}

function renderList(targetId, origins, pending) {
  const target = document.getElementById(targetId);
  target.textContent = "";

  if (origins.length === 0) {
    target.textContent = "Sin registros.";
    return;
  }

  for (const origin of origins) {
    const row = document.createElement("div");
    row.className = "row";

    const label = document.createElement("span");
    label.textContent = origin;
    row.appendChild(label);

    if (pending) {
      row.appendChild(button("Aprobar", () => approveOrigin(origin)));
      row.appendChild(button("Rechazar", () => rejectOrigin(origin)));
    } else {
      row.appendChild(button("Revocar", () => revokeOrigin(origin)));
    }

    target.appendChild(row);
  }
}

function button(text, fn) {
  const element = document.createElement("button");
  element.textContent = text;
  element.addEventListener("click", fn);
  return element;
}

async function approveOrigin(origin) {
  const data = await chrome.storage.local.get({
    allowedOrigins: {},
    pendingOrigins: {}
  });
  data.allowedOrigins[origin] = {
    origin,
    approved_at: Date.now()
  };
  delete data.pendingOrigins[origin];
  await chrome.storage.local.set(data);
  await loadState();
}

async function rejectOrigin(origin) {
  const data = await chrome.storage.local.get({ pendingOrigins: {} });
  delete data.pendingOrigins[origin];
  await chrome.storage.local.set({ pendingOrigins: data.pendingOrigins });
  await loadState();
}

async function revokeOrigin(origin) {
  const data = await chrome.storage.local.get({ allowedOrigins: {} });
  delete data.allowedOrigins[origin];
  await chrome.storage.local.set({ allowedOrigins: data.allowedOrigins });
  await loadState();
}

loadState();
```

`popup.css`:

```css
body {
  width: 380px;
  margin: 0;
  padding: 12px;
  background: #06111f;
  color: #dbeafe;
  font-family: system-ui, sans-serif;
}

header {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  border-bottom: 1px solid #1e3a5f;
  padding-bottom: 8px;
}

h2 {
  font-size: 12px;
  margin: 14px 0 8px;
  color: #67e8f9;
}

.row {
  display: grid;
  grid-template-columns: 1fr auto auto;
  gap: 6px;
  align-items: center;
  padding: 6px 0;
  border-bottom: 1px solid #10243a;
  font-size: 12px;
}

button {
  border: 1px solid #155e75;
  background: #083344;
  color: #cffafe;
  border-radius: 4px;
  padding: 4px 7px;
  cursor: pointer;
}
```

### 10.1.6. Tests necesarios para permisos

```text
dominio HTTPS no aprobado -> eth_requestAccounts rechaza;
dominio aprobado -> eth_requestAccounts devuelve cuenta;
dominio revocado -> eth_accounts devuelve [];
http://localhost permitido;
http://sitio-remoto rechazado;
iframe no autorizado rechazado;
metodo desconocido rechazado;
window.ethereum existente no se sobrescribe.
```

## 10.2. Bloque 2: serializacion/decodificacion Ethereum completa

### 10.2.1. Archivos nuevos recomendados

```text
src-tui/src/crypto/blockchain/eth_types.rs
src-tui/src/crypto/blockchain/eth_rlp.rs
src-tui/src/crypto/blockchain/eth_abi.rs
src-tui/src/crypto/blockchain/eth_tx.rs
src-tui/src/crypto/blockchain/eth_preview.rs
```

### 10.2.2. Tipos de transaccion Ethereum

`eth_types.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EthereumTxKind {
    Legacy,
    Eip2930,
    Eip1559,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumTxRequest {
    pub chain_id: u64,
    pub from: String,
    pub to: Option<String>,
    pub nonce: u64,
    pub value: String,
    pub data: String,
    pub gas_limit: u64,
    pub gas_price: Option<String>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub kind: EthereumTxKind,
}

#[derive(Clone, Debug)]
pub struct EthereumDecodedCall {
    pub selector: String,
    pub method: String,
    pub contract: String,
    pub spender: Option<String>,
    pub recipient: Option<String>,
    pub amount: Option<String>,
    pub risk: EthereumCallRisk,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EthereumCallRisk {
    Low,
    Medium,
    High,
    Critical,
}
```

### 10.2.3. RLP minimo

`eth_rlp.rs`:

```rust
pub fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }
    encode_len(0x80, bytes.len(), bytes)
}

pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload = items.concat();
    encode_len(0xc0, payload.len(), &payload)
}

fn encode_len(offset: u8, len: usize, payload: &[u8]) -> Vec<u8> {
    if len < 56 {
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(offset + len as u8);
        out.extend_from_slice(payload);
        return out;
    }

    let len_bytes = usize_to_be(len);
    let mut out = Vec::with_capacity(1 + len_bytes.len() + payload.len());
    out.push(offset + 55 + len_bytes.len() as u8);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(payload);
    out
}

pub fn encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return encode_bytes(&[]);
    }
    encode_bytes(&u64_to_be(value))
}

pub fn encode_u256_hex(value: &str) -> Result<Vec<u8>, String> {
    let bytes = hex_to_minimal_bytes(value)?;
    Ok(encode_bytes(&bytes))
}

fn u64_to_be(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    bytes.iter().skip_while(|b| **b == 0).copied().collect()
}

fn usize_to_be(value: usize) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    bytes.iter().skip_while(|b| **b == 0).copied().collect()
}

fn hex_to_minimal_bytes(value: &str) -> Result<Vec<u8>, String> {
    let mut hex = value.strip_prefix("0x").unwrap_or(value).to_string();
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if hex.len() % 2 != 0 {
        hex.insert(0, '0');
    }
    let mut bytes = hex::decode(hex).map_err(|e| e.to_string())?;
    while bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    Ok(bytes)
}
```

### 10.2.4. Serializador EIP-1559

`eth_tx.rs`:

```rust
use crate::crypto::blockchain::eth_rlp;
use crate::crypto::blockchain::eth_types::{EthereumTxKind, EthereumTxRequest};

pub fn serialize_unsigned(tx: &EthereumTxRequest) -> Result<Vec<u8>, String> {
    match tx.kind {
        EthereumTxKind::Legacy => serialize_legacy(tx),
        EthereumTxKind::Eip2930 => serialize_eip2930(tx),
        EthereumTxKind::Eip1559 => serialize_eip1559(tx),
    }
}

fn serialize_eip1559(tx: &EthereumTxRequest) -> Result<Vec<u8>, String> {
    let to = tx.to.as_deref().unwrap_or("");
    let fields = vec![
        eth_rlp::encode_u64(tx.chain_id),
        eth_rlp::encode_u64(tx.nonce),
        eth_rlp::encode_u256_hex(required(tx.max_priority_fee_per_gas.as_deref(), "maxPriorityFeePerGas")?)?,
        eth_rlp::encode_u256_hex(required(tx.max_fee_per_gas.as_deref(), "maxFeePerGas")?)?,
        eth_rlp::encode_u64(tx.gas_limit),
        eth_rlp::encode_bytes(&decode_address_or_empty(to)?),
        eth_rlp::encode_u256_hex(&tx.value)?,
        eth_rlp::encode_bytes(&decode_hex(&tx.data)?),
        eth_rlp::encode_list(&[]),
    ];

    let mut out = vec![0x02];
    out.extend_from_slice(&eth_rlp::encode_list(&fields));
    Ok(out)
}

fn serialize_eip2930(tx: &EthereumTxRequest) -> Result<Vec<u8>, String> {
    let to = tx.to.as_deref().unwrap_or("");
    let fields = vec![
        eth_rlp::encode_u64(tx.chain_id),
        eth_rlp::encode_u64(tx.nonce),
        eth_rlp::encode_u256_hex(required(tx.gas_price.as_deref(), "gasPrice")?)?,
        eth_rlp::encode_u64(tx.gas_limit),
        eth_rlp::encode_bytes(&decode_address_or_empty(to)?),
        eth_rlp::encode_u256_hex(&tx.value)?,
        eth_rlp::encode_bytes(&decode_hex(&tx.data)?),
        eth_rlp::encode_list(&[]),
    ];

    let mut out = vec![0x01];
    out.extend_from_slice(&eth_rlp::encode_list(&fields));
    Ok(out)
}

fn serialize_legacy(tx: &EthereumTxRequest) -> Result<Vec<u8>, String> {
    let to = tx.to.as_deref().unwrap_or("");
    let fields = vec![
        eth_rlp::encode_u64(tx.nonce),
        eth_rlp::encode_u256_hex(required(tx.gas_price.as_deref(), "gasPrice")?)?,
        eth_rlp::encode_u64(tx.gas_limit),
        eth_rlp::encode_bytes(&decode_address_or_empty(to)?),
        eth_rlp::encode_u256_hex(&tx.value)?,
        eth_rlp::encode_bytes(&decode_hex(&tx.data)?),
        eth_rlp::encode_u64(tx.chain_id),
        eth_rlp::encode_u64(0),
        eth_rlp::encode_u64(0),
    ];
    Ok(eth_rlp::encode_list(&fields))
}

fn required<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str, String> {
    value.ok_or_else(|| format!("campo Ethereum obligatorio ausente: {}", field))
}

fn decode_address_or_empty(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = decode_hex(value)?;
    if bytes.len() != 20 {
        return Err("direccion Ethereum invalida".into());
    }
    Ok(bytes)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() % 2 != 0 {
        return Err("hex impar invalido".into());
    }
    hex::decode(value).map_err(|e| e.to_string())
}
```

### 10.2.5. Decodificador ABI minimo

`eth_abi.rs`:

```rust
use crate::crypto::blockchain::eth_types::{EthereumCallRisk, EthereumDecodedCall};

pub fn decode_call(contract: &str, data: &str) -> Result<EthereumDecodedCall, String> {
    let data = data.strip_prefix("0x").unwrap_or(data);
    if data.is_empty() {
        return Ok(EthereumDecodedCall {
            selector: "0x".into(),
            method: "native_transfer".into(),
            contract: contract.to_string(),
            spender: None,
            recipient: None,
            amount: None,
            risk: EthereumCallRisk::Low,
        });
    }
    if data.len() < 8 {
        return Err("calldata Ethereum demasiado corto".into());
    }

    let selector = format!("0x{}", &data[..8]);
    match selector.as_str() {
        "0xa9059cbb" => decode_erc20_transfer(contract, data),
        "0x095ea7b3" => decode_erc20_approve(contract, data),
        "0x23b872dd" => decode_erc20_transfer_from(contract, data),
        "0xa22cb465" => decode_set_approval_for_all(contract, data),
        other => Ok(EthereumDecodedCall {
            selector: other.to_string(),
            method: "unknown".into(),
            contract: contract.to_string(),
            spender: None,
            recipient: None,
            amount: None,
            risk: EthereumCallRisk::Critical,
        }),
    }
}

fn decode_erc20_transfer(contract: &str, data: &str) -> Result<EthereumDecodedCall, String> {
    Ok(EthereumDecodedCall {
        selector: "0xa9059cbb".into(),
        method: "erc20.transfer".into(),
        contract: contract.to_string(),
        spender: None,
        recipient: Some(word_address(data, 0)?),
        amount: Some(word_u256(data, 1)?),
        risk: EthereumCallRisk::Low,
    })
}

fn decode_erc20_approve(contract: &str, data: &str) -> Result<EthereumDecodedCall, String> {
    let amount = word_u256(data, 1)?;
    let risk = if is_unlimited(&amount) {
        EthereumCallRisk::Critical
    } else {
        EthereumCallRisk::High
    };
    Ok(EthereumDecodedCall {
        selector: "0x095ea7b3".into(),
        method: "erc20.approve".into(),
        contract: contract.to_string(),
        spender: Some(word_address(data, 0)?),
        recipient: None,
        amount: Some(amount),
        risk,
    })
}

fn decode_erc20_transfer_from(contract: &str, data: &str) -> Result<EthereumDecodedCall, String> {
    Ok(EthereumDecodedCall {
        selector: "0x23b872dd".into(),
        method: "erc20.transferFrom".into(),
        contract: contract.to_string(),
        spender: Some(word_address(data, 0)?),
        recipient: Some(word_address(data, 1)?),
        amount: Some(word_u256(data, 2)?),
        risk: EthereumCallRisk::High,
    })
}

fn decode_set_approval_for_all(contract: &str, data: &str) -> Result<EthereumDecodedCall, String> {
    Ok(EthereumDecodedCall {
        selector: "0xa22cb465".into(),
        method: "erc721.setApprovalForAll".into(),
        contract: contract.to_string(),
        spender: Some(word_address(data, 0)?),
        recipient: None,
        amount: Some(word_u256(data, 1)?),
        risk: EthereumCallRisk::Critical,
    })
}

fn word_address(data: &str, index: usize) -> Result<String, String> {
    let word = word(data, index)?;
    Ok(format!("0x{}", &word[24..64]))
}

fn word_u256(data: &str, index: usize) -> Result<String, String> {
    Ok(format!("0x{}", word(data, index)?))
}

fn word(data: &str, index: usize) -> Result<&str, String> {
    let start = 8 + index * 64;
    let end = start + 64;
    data.get(start..end)
        .ok_or_else(|| "calldata ABI incompleto".to_string())
}

fn is_unlimited(value: &str) -> bool {
    value.eq_ignore_ascii_case(
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
}
```

### 10.2.6. Integracion en extension

La extension no debe enviar objetos DEX sin normalizar. Debe pedir al backend que serialice o enviar solo payload ya serializado.

Operacion recomendada:

```text
DEX object -> extension valida campos basicos -> backend serializa -> backend parsea -> backend preview -> usuario confirma -> backend firma
```

Nuevo mensaje nativo:

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EthereumPrepareTransactionRequest {
    pub origin: String,
    pub account_index: u32,
    pub address_index: u32,
    pub tx: EthereumTxRequest,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EthereumPreparedTransaction {
    pub unsigned_payload_hex: String,
    pub decoded_method: String,
    pub risk: String,
    pub summary: String,
}
```

Nueva variante:

```rust
pub enum ExtensionRequest {
    // existentes...
    EthereumPrepareTransaction(EthereumPrepareTransactionRequest),
}
```

### 10.2.7. Tests necesarios para Ethereum

```text
RLP legacy conocido contra vector oficial;
RLP EIP-1559 conocido contra vector oficial;
chainId incorrecto rechaza;
from no coincide con cuenta derivada rechaza;
ERC-20 transfer decodifica receptor y cantidad;
approve ilimitado marca Critical;
selector desconocido marca Critical;
transaccion con data impar rechaza;
to invalido rechaza;
nonce ausente rechaza;
gas ausente rechaza.
```

## 10.3. Bloque 3: simulacion, quorum RPC y auditoria completa antes de firma

### 10.3.1. Archivos nuevos recomendados

```text
src-tui/src/crypto/blockchain/rpc_quorum.rs
src-tui/src/crypto/blockchain/eth_simulation.rs
src-tui/src/crypto/blockchain/preflight.rs
src-tui/src/crypto/blockchain/web3_audit.rs
```

### 10.3.2. Quorum RPC

El adaptador actual usa endpoint activo. Para seguridad real, las respuestas criticas deben compararse entre nodos.

`rpc_quorum.rs`:

```rust
use crate::crypto::blockchain::nodes::NodeRegistry;
use crate::crypto::blockchain::rpc_client::json_rpc_call;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct QuorumResult {
    pub method: String,
    pub agreed: bool,
    pub value: Option<Value>,
    pub endpoint_results: Vec<EndpointResult>,
}

#[derive(Clone, Debug)]
pub struct EndpointResult {
    pub endpoint: String,
    pub result: Result<Value, String>,
}

pub fn json_rpc_quorum(
    registry: &NodeRegistry,
    chain: &str,
    method: &str,
    params: Value,
    min_agreement: usize,
) -> Result<QuorumResult, String> {
    let endpoints = registry.endpoints(chain);
    if endpoints.is_empty() {
        return Err(format!("sin endpoints para {}", chain));
    }

    let mut endpoint_results = Vec::new();
    let mut counts: HashMap<String, (usize, Value)> = HashMap::new();

    for endpoint in endpoints {
        let result = json_rpc_call(&endpoint, method, params.clone(), registry.timeout_ms());
        if let Ok(value) = &result {
            let key = canonical_json(value)?;
            let entry = counts.entry(key).or_insert((0, value.clone()));
            entry.0 += 1;
        }
        endpoint_results.push(EndpointResult { endpoint, result });
    }

    let best = counts
        .into_iter()
        .max_by_key(|(_, (count, _))| *count);

    if let Some((_, (count, value))) = best {
        return Ok(QuorumResult {
            method: method.to_string(),
            agreed: count >= min_agreement,
            value: Some(value),
            endpoint_results,
        });
    }

    Ok(QuorumResult {
        method: method.to_string(),
        agreed: false,
        value: None,
        endpoint_results,
    })
}

fn canonical_json(value: &Value) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}
```

### 10.3.3. Simulacion Ethereum

`eth_simulation.rs`:

```rust
use crate::crypto::blockchain::eth_types::EthereumTxRequest;
use crate::crypto::blockchain::nodes::NodeRegistry;
use crate::crypto::blockchain::rpc_quorum::json_rpc_quorum;
use serde_json::json;

#[derive(Clone, Debug)]
pub struct EthereumSimulationReport {
    pub chain_id_ok: bool,
    pub nonce_ok: bool,
    pub gas_ok: bool,
    pub contract_exists: bool,
    pub call_ok: bool,
    pub warnings: Vec<String>,
}

pub fn simulate_ethereum_tx(
    registry: &NodeRegistry,
    tx: &EthereumTxRequest,
) -> Result<EthereumSimulationReport, String> {
    let mut warnings = Vec::new();

    let chain_id = json_rpc_quorum(registry, "ethereum", "eth_chainId", json!([]), 2)?;
    let chain_id_ok = chain_id
        .value
        .as_ref()
        .and_then(|value| value.as_str())
        .map(|value| value == format!("0x{:x}", tx.chain_id))
        .unwrap_or(false);
    if !chain_id_ok {
        warnings.push("chainId no coincide entre transaccion y nodo".into());
    }

    let nonce = json_rpc_quorum(
        registry,
        "ethereum",
        "eth_getTransactionCount",
        json!([tx.from, "pending"]),
        2,
    )?;
    let nonce_ok = nonce.agreed;
    if !nonce_ok {
        warnings.push("nonce sin quorum suficiente".into());
    }

    let code_ok = if let Some(to) = &tx.to {
        let code = json_rpc_quorum(registry, "ethereum", "eth_getCode", json!([to, "latest"]), 2)?;
        let contract_exists = code
            .value
            .as_ref()
            .and_then(|value| value.as_str())
            .map(|value| value != "0x")
            .unwrap_or(false);
        if !contract_exists && !tx.data.is_empty() && tx.data != "0x" {
            warnings.push("calldata contra direccion sin contrato".into());
        }
        contract_exists
    } else {
        true
    };

    let gas = json_rpc_quorum(
        registry,
        "ethereum",
        "eth_estimateGas",
        json!([{
            "from": tx.from,
            "to": tx.to,
            "value": tx.value,
            "data": tx.data
        }]),
        2,
    )?;
    let gas_ok = gas.agreed && gas.value.is_some();
    if !gas_ok {
        warnings.push("eth_estimateGas sin quorum".into());
    }

    let call = json_rpc_quorum(
        registry,
        "ethereum",
        "eth_call",
        json!([{
            "from": tx.from,
            "to": tx.to,
            "value": tx.value,
            "data": tx.data
        }, "latest"]),
        2,
    )?;
    let call_ok = call.agreed && call.value.is_some();
    if !call_ok {
        warnings.push("eth_call sin quorum o fallo de simulacion".into());
    }

    Ok(EthereumSimulationReport {
        chain_id_ok,
        nonce_ok,
        gas_ok,
        contract_exists: code_ok,
        call_ok,
        warnings,
    })
}
```

### 10.3.4. Preflight antes de firma

`preflight.rs`:

```rust
use crate::crypto::blockchain::eth_abi;
use crate::crypto::blockchain::eth_simulation::simulate_ethereum_tx;
use crate::crypto::blockchain::eth_types::{EthereumCallRisk, EthereumTxRequest};
use crate::crypto::blockchain::nodes::NodeRegistry;

#[derive(Clone, Debug)]
pub struct PreflightDecision {
    pub allowed: bool,
    pub requires_strong_confirmation: bool,
    pub summary: String,
    pub warnings: Vec<String>,
}

pub fn preflight_ethereum(
    registry: &NodeRegistry,
    tx: &EthereumTxRequest,
) -> Result<PreflightDecision, String> {
    let contract = tx.to.clone().unwrap_or_default();
    let decoded = eth_abi::decode_call(&contract, &tx.data)?;
    let simulation = simulate_ethereum_tx(registry, tx)?;

    let mut warnings = simulation.warnings;
    if decoded.risk == EthereumCallRisk::Critical {
        warnings.push("metodo critico o desconocido".into());
    }

    let allowed = simulation.chain_id_ok
        && simulation.nonce_ok
        && simulation.gas_ok
        && simulation.call_ok
        && decoded.risk != EthereumCallRisk::Critical;

    Ok(PreflightDecision {
        allowed,
        requires_strong_confirmation: decoded.risk == EthereumCallRisk::High,
        summary: format!(
            "metodo={} contrato={} riesgo={:?}",
            decoded.method, decoded.contract, decoded.risk
        ),
        warnings,
    })
}
```

### 10.3.5. Auditoria completa

`web3_audit.rs` debe registrar eventos antes y despues de cada decision.

```rust
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Web3AuditEvent {
    pub timestamp_unix: u64,
    pub origin: String,
    pub action: String,
    pub chain: String,
    pub chain_id: String,
    pub account_index: u32,
    pub address_index: u32,
    pub from: String,
    pub to: Option<String>,
    pub contract: Option<String>,
    pub method: Option<String>,
    pub selector: Option<String>,
    pub value_native: Option<String>,
    pub value_fiat: Option<String>,
    pub endpoint_summary: Vec<String>,
    pub decision: String,
    pub warnings: Vec<String>,
    pub payload_sha256: String,
    pub signature_sha256: Option<String>,
}

pub fn append_web3_audit_event(event: Web3AuditEvent) -> Result<(), String> {
    let path = audit_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| error.to_string())?;

    let line = serde_json::to_string(&event).map_err(|error| error.to_string())?;
    file.write_all(line.as_bytes()).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_data().map_err(|error| error.to_string())
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn audit_path() -> PathBuf {
    crate::livencrypt_base_dir()
        .join(".livencrypt")
        .join("web3_audit.jsonl")
}
```

### 10.3.6. Integracion en flujo de firma

Dentro de `worker.rs`, antes de aceptar una firma:

```rust
let preflight = preflight_ethereum(&node_registry, &ethereum_tx)?;

append_web3_audit_event(Web3AuditEvent {
    timestamp_unix: now_unix(),
    origin: origin.clone(),
    action: "preflight".into(),
    chain: "ethereum".into(),
    chain_id: format!("0x{:x}", ethereum_tx.chain_id),
    account_index,
    address_index,
    from: ethereum_tx.from.clone(),
    to: ethereum_tx.to.clone(),
    contract: ethereum_tx.to.clone(),
    method: Some(preflight.summary.clone()),
    selector: None,
    value_native: Some(ethereum_tx.value.clone()),
    value_fiat: None,
    endpoint_summary: vec![],
    decision: if preflight.allowed { "preview" } else { "rejected" }.into(),
    warnings: preflight.warnings.clone(),
    payload_sha256: sha256_hex(&unsigned_payload),
    signature_sha256: None,
})?;

if !preflight.allowed {
    return Err("preflight Web3 rechazado".into());
}
```

Despues de firmar:

```rust
append_web3_audit_event(Web3AuditEvent {
    timestamp_unix: now_unix(),
    origin,
    action: "signature".into(),
    chain: "ethereum".into(),
    chain_id,
    account_index,
    address_index,
    from,
    to,
    contract,
    method,
    selector,
    value_native,
    value_fiat,
    endpoint_summary,
    decision: "signed_after_local_confirmation".into(),
    warnings,
    payload_sha256,
    signature_sha256: Some(sha256_hex(&signature_bytes)),
})?;
```

### 10.3.7. Tests necesarios para quorum, simulacion y auditoria

```text
un nodo caido no rompe si hay quorum;
dos nodos divergentes bloquean firma;
chainId distinto bloquea firma;
eth_call fallido bloquea firma;
eth_estimateGas fallido bloquea firma;
selector desconocido bloquea firma;
approve ilimitado requiere confirmacion reforzada;
evento preflight se registra;
evento firma se registra;
evento rechazo se registra;
auditoria no contiene clave privada, frase ni cajas;
payload_sha256 coincide;
signature_sha256 coincide.
```

## 10.4. Riesgos actuales actualizados

```text
extension inicial no tiene todavia popup de permisos;
eth_sendTransaction no acepta objetos DEX normales sin serializador;
no hay ABI decoder completo;
no hay eth_call/eth_estimateGas con quorum antes de firma;
no hay auditoria completa encadenada para Web3;
Bitcoin no tiene aun Electrum/indexador para balance por direccion;
Solana no calcula fee sin mensaje serializado real;
Monero/ZCash/Starknet siguen fuera de soporte operativo.
```

## 10.5. Funciones pendientes para uso real seguro

```text
popup de permisos;
gestion de dominios;
serializador Ethereum completo;
ABI decoder;
simulacion RPC;
quorum entre nodos;
preflight obligatorio;
auditoria JSONL con hashes;
confirmacion reforzada por riesgo;
testnet broadcast controlado;
PSBT Bitcoin;
Solana versioned transactions;
adaptadores Monero/ZCash/Starknet.
```

## 10.6. Requisitos por blockchain

Ethereum:

```text
EIP-1559, EIP-2930, legacy, ABI, eth_call, estimateGas, feeHistory, typed data.
```

Bitcoin:

```text
P2WPKH, P2TR, PSBT, Electrum/Esplora, UTXO selection, change, fee sat/vB.
```

Solana:

```text
Message v0, address lookup tables, SPL Token, simulateTransaction, getLatestBlockhash.
```

Monero:

```text
spend/view keys, subaddresses, wallet-rpc, key images, ring signatures.
```

ZCash:

```text
t-address, Sapling, Orchard, viewing keys, shielded notes.
```

Starknet:

```text
account abstraction, nonce, calldata, Poseidon/Pedersen, firma Stark.
```

## 10.7. Fases de integracion recomendadas actualizadas

Fase 1:

```text
popup de permisos;
eth_requestAccounts con permisos;
eth_accounts por dominio;
lectura RPC con quorum para balance/nonce/gas;
auditoria de lecturas.
```

Fase 2:

```text
serializacion Ethereum;
ABI decoder;
preflight con eth_call/estimateGas;
preview TUI reforzado.
```

Fase 3:

```text
firma Ethereum real;
devolucion raw signed tx;
broadcast bloqueado por defecto;
broadcast testnet bajo RPC OPERATIVO.
```

Fase 4:

```text
Bitcoin PSBT;
Solana transaction builder;
Monero/ZCash/Starknet.
```

## 11. Dictamen

Estado actual:

```text
base arquitectonica correcta;
custodia local correctamente separada del navegador;
bridge nativo preparado;
auditor publico funcional para Bitcoin/Ethereum/Solana;
lectura RPC basica real integrada;
extension Web3 inicial integrada;
broadcast bloqueado correctamente.
```

No esta listo aun para firmar transacciones DEX reales de forma general.

Para uso real seguro faltan tres bloques criticos:

```text
1. extension con permisos por dominio y UI propia;
2. serializacion/decodificacion Ethereum completa;
3. simulacion, quorum RPC y auditoria completa antes de firma.
```

La recomendacion profesional es mantener el modo actual como:

```text
auditor de direcciones publicas;
lector Web3 controlado;
custodio local en fase de preparacion;
firma real solo cuando el parser, serializador, politicas y confirmacion local esten completos.
```
