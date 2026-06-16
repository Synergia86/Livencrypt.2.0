# Hoja de ruta: extension Livencrypt Web3, EIP-1193 y livencrypt-bridge

## 1. Objetivo

Integrar Livencrypt 2.0 como custodio local de wallets para aplicaciones Web3 y DEX sin exponer claves privadas al navegador.

El objetivo no es que MetaMask lea directamente el payload `livencrypt-wallet-link`, porque MetaMask no reconoce ese formato. El objetivo correcto es crear una extension/adaptador Livencrypt compatible con el modelo EIP-1193, que actue como proveedor Web3 y traduzca las peticiones del navegador hacia `livencrypt-bridge`.

## 2. Estado actual

### 2.1. Ya integrado

```text
livencrypt-bridge esta preparado como host de mensajeria nativa.
```

Componentes existentes:

```text
src-tui/src/bin/livencrypt-bridge.rs
src-tui/scripts/com.livencrypt.gateway.json
src-tui/scripts/postinstall.sh
src-tui/src/crypto/blockchain/proxy.rs
src-tui/src/crypto/blockchain/worker.rs
src-tui/src/crypto/blockchain/supervisor.rs
```

El manifiesto nativo apunta al binario puente:

```json
{
  "name": "com.livencrypt.gateway",
  "description": "Proxy criptografico universal aislado de Livencrypt 2.0",
  "path": "/usr/bin/livencrypt-bridge",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://iealgmhdifbjdmlffgkccejpbnmefkkl/"
  ]
}
```

La TUI conserva el control de sesion, vault, politicas y confirmacion local. El navegador solo debe hablar con el puente mediante mensajeria nativa.

### 2.2. No integrado todavia

```text
MetaMask no acepta directamente el payload livencrypt-wallet-link.
```

MetaMask espera su propio estado interno, cuentas gestionadas por la extension y un proveedor compatible con su arquitectura. Un JSON público como:

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
  "scope": "public-address-only"
}
```

sirve para vincular una wallet publica, pero no convierte automaticamente a Livencrypt en proveedor Web3 dentro de MetaMask.

## 3. Arquitectura recomendada

```text
DEX / portal Web3
  -> window.ethereum compatible EIP-1193
  -> extension Livencrypt
  -> chrome.runtime
  -> chrome.runtime.connectNative("com.livencrypt.gateway")
  -> /usr/bin/livencrypt-bridge
  -> socket Unix: $XDG_RUNTIME_DIR/livencrypt/livencrypt.sock
  -> worker Web3 de Livencrypt TUI
  -> Boot Shield / vault / politicas / firma local
```

La extension Livencrypt debe implementar un proveedor EIP-1193 propio:

```text
window.livencrypt
window.ethereum si el usuario decide exponerlo como proveedor principal
```

Recomendacion:

```text
no sobrescribir window.ethereum si ya existe MetaMask;
exponer window.livencrypt;
permitir seleccion manual de proveedor en la DEX si es posible;
solo activar window.ethereum bajo consentimiento explicito.
```

## 4. Responsabilidad de cada componente

### 4.1. Livencrypt TUI

Responsabilidades:

```text
desbloquear Boot Shield
custodiar claves en memoria
derivar direcciones publicas
mostrar QR/payload publico por wallet
validar politicas por cuenta
validar limites por activo/FIAT/TX
previsualizar transacciones
pedir confirmacion fisica local
firmar si la politica lo permite
registrar auditoria local
bloquear broadcast si el perfil no es RPC OPERATIVO
```

### 4.2. livencrypt-bridge

Responsabilidades:

```text
recibir mensajes JSON desde la extension
validar longitud y formato basico
reenviar al socket Unix local
devolver respuesta JSON al navegador
no abrir TUI
no tocar claves
no guardar secretos
no decidir politicas
```

### 4.3. Extension Livencrypt

Responsabilidades:

```text
inyectar proveedor EIP-1193
gestionar permisos por dominio
traducir metodos Web3 a comandos Livencrypt
mostrar estado conectado/desconectado
mostrar cuentas publicas disponibles
enviar peticiones al host nativo
mostrar errores genericos seguros
no almacenar claves privadas
```

## 5. Metodos EIP-1193 minimos

La extension debe soportar inicialmente:

```text
eth_requestAccounts
eth_accounts
eth_chainId
wallet_switchEthereumChain
wallet_addEthereumChain
eth_getBalance
eth_getTransactionCount
eth_estimateGas
eth_sendTransaction
personal_sign
eth_signTypedData_v4
```

Fase inicial recomendada:

```text
solo Ethereum/EVM
solo lectura de cuentas
solo firma con confirmacion local
broadcast bloqueado hasta validar testnet/devnet
```

## 6. Traduccion de mensajes

### 6.1. Solicitar cuentas

Entrada DEX:

```json
{
  "method": "eth_requestAccounts",
  "params": []
}
```

Extension -> Livencrypt:

```json
{
  "type": "DeriveKey",
  "data": {
    "chain": "Ethereum",
    "account_index": 0,
    "address_index": 0
  }
}
```

Respuesta hacia DEX:

```json
[
  "0xa84b6c911a824b905398f9bcae5b17c9d063bdf7"
]
```

### 6.2. Firmar transaccion

Entrada DEX:

```json
{
  "method": "eth_sendTransaction",
  "params": [
    {
      "from": "0x...",
      "to": "0x...",
      "value": "0x...",
      "data": "0x..."
    }
  ]
}
```

Extension -> Livencrypt:

```json
{
  "type": "SignTransaction",
  "data": {
    "chain": "Ethereum",
    "account_index": 0,
    "address_index": 0,
    "raw_tx_payload": "...",
    "value_usd": "0",
    "target_dex_cex_id": "0x..."
  }
}
```

Livencrypt debe:

```text
parsear payload
validar chain_id
validar destino
validar contrato/metodo
validar limites
mostrar previsualizacion
pedir confirmacion local en TUI
firmar solo si se aprueba fisicamente
devolver firma o rechazo
```

## 7. Codigo base de extension

### 7.1. manifest.json

```json
{
  "manifest_version": 3,
  "name": "Livencrypt Web3 Bridge",
  "version": "0.1.0",
  "description": "Proveedor Web3 local para Livencrypt 2.0",
  "permissions": [
    "nativeMessaging",
    "storage",
    "activeTab"
  ],
  "host_permissions": [
    "<all_urls>"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["inject.js"],
      "run_at": "document_start",
      "world": "MAIN"
    }
  ],
  "action": {
    "default_title": "Livencrypt Web3"
  }
}
```

### 7.2. background.js

```javascript
const HOST = "com.livencrypt.gateway";

function sendNative(payload) {
  return new Promise((resolve, reject) => {
    const port = chrome.runtime.connectNative(HOST);
    let settled = false;

    port.onMessage.addListener((message) => {
      settled = true;
      resolve(message);
      port.disconnect();
    });

    port.onDisconnect.addListener(() => {
      if (!settled) {
        reject(new Error(chrome.runtime.lastError?.message || "Livencrypt desconectado"));
      }
    });

    port.postMessage(payload);
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.scope !== "livencrypt-web3") {
    return false;
  }

  handleProviderRequest(message.request, sender)
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));

  return true;
});

async function handleProviderRequest(request, sender) {
  switch (request.method) {
    case "eth_requestAccounts":
    case "eth_accounts":
      return await requestAccounts(sender);
    case "eth_chainId":
      return "0x1";
    case "eth_getBalance":
      return await rpcReadBalance(request.params);
    case "eth_getTransactionCount":
      return await rpcReadNonce(request.params);
    case "eth_sendTransaction":
      return await signTransaction(request.params, sender);
    default:
      throw new Error(`Metodo no soportado por Livencrypt: ${request.method}`);
  }
}
```

### 7.3. inject.js

```javascript
class LivencryptProvider {
  constructor() {
    this.isLivencrypt = true;
    this.selectedAddress = null;
    this.chainId = "0x1";
  }

  async request(args) {
    const response = await chrome.runtime.sendMessage({
      scope: "livencrypt-web3",
      request: args
    });

    if (!response?.ok) {
      throw new Error(response?.error || "Error Livencrypt Web3");
    }

    if (args.method === "eth_requestAccounts" && response.result?.[0]) {
      this.selectedAddress = response.result[0];
    }

    return response.result;
  }

  on() {}
  removeListener() {}
}

Object.defineProperty(window, "livencrypt", {
  value: new LivencryptProvider(),
  writable: false,
  configurable: false
});
```

## 8. Seguridad obligatoria en la extension

Reglas:

```text
no guardar claves privadas
no guardar frase Boot Shield
no guardar cajas
no firmar sin TUI desbloqueada
no firmar sin confirmacion local
no aceptar peticiones desde iframes no autorizados
pedir permiso por dominio
mostrar dominio solicitante en la TUI
validar chain_id contra la red activa
mostrar contrato y selector de metodo
bloquear metodos desconocidos
usar mensajes de error genericos para fallos sensibles
```

## 9. Integracion con DEX

Flujo esperado:

```text
1. usuario abre Livencrypt TUI
2. desbloquea Boot Shield
3. activa Pasarela Web3
4. extension detecta livencrypt-bridge disponible
5. DEX solicita eth_requestAccounts
6. extension pide direccion publica a Livencrypt
7. DEX prepara transaccion
8. extension envia payload a Livencrypt
9. Livencrypt muestra previsualizacion local
10. usuario confirma o rechaza en TUI
11. Livencrypt firma si procede
12. extension devuelve la firma o txid segun modo
```

## 10. Broadcast

El broadcast no debe activarse por defecto.

Perfiles:

```text
OFFLINE:
  deriva direcciones
  firma payloads validados
  no consulta nodos
  no emite transacciones

RPC LECTURA:
  consulta balance, nonce, fees y estado
  no emite transacciones

RPC OPERATIVO:
  permite transmitir transacciones
  requiere politica local
  requiere confirmacion fisica
  requiere nodos auditados
```

## 11. Pendientes reales por cadena

### 11.1. Monero

Estado:

```text
pendiente de adaptador de derivacion/RPC.
```

Falta:

```text
derivacion spend/view key
subaddresses
view-only wallet
key images
RPC monerod/wallet-rpc
parser de transacciones
validacion de fee
firma compatible con Monero
```

### 11.2. ZCash

Estado:

```text
pendiente de adaptador de derivacion/RPC.
```

Falta:

```text
soporte transparente t-address
soporte shielded Sapling/Orchard si se decide integrar
viewing keys
librerias auditadas ZK
parser de transacciones
validacion de fee
firma especifica ZCash
```

### 11.3. Starknet

Estado:

```text
pendiente de adaptador de derivacion/RPC.
```

Falta:

```text
modelo account abstraction
contrato de cuenta
nonce por cuenta
calldata
selectors
hash Pedersen/Poseidon segun version
firma Stark
RPC Starknet
validacion de chain_id
```

### 11.4. Bitcoin

Estado actual:

```text
derivacion publica P2PKH integrada;
health, altura, fee y reloj via Bitcoin Core RPC integrados;
balance por direccion no disponible con Bitcoin Core RPC publico generico.
```

Falta para balance por direccion:

```text
endpoint Electrum real
conversion direccion -> scripthash
indexador Esplora propio o auditado
cache local de UTXO
validacion de confirmaciones
```

### 11.5. Solana

Estado actual:

```text
derivacion publica integrada;
health, slot y balance integrados;
fee requiere mensaje serializado valido.
```

Falta:

```text
constructor de mensaje Solana de prueba
getLatestBlockhash
getFeeForMessage con mensaje real
parser completo de instrucciones
validacion de cuentas afectadas
```

## 12. Criterio de finalizacion

La integracion se considerara completa cuando:

```text
extension Livencrypt instalada
manifest native messaging registrado
livencrypt-bridge responde desde navegador
eth_requestAccounts devuelve cuenta real derivada
eth_getBalance consulta nodo real
eth_sendTransaction genera preview en TUI
firma requiere confirmacion local
broadcast bloqueado en OFFLINE/RPC LECTURA
broadcast probado solo en testnet/devnet bajo RPC OPERATIVO
auditoria local registra dominio, metodo, cuenta, chain_id, destino y decision
```

