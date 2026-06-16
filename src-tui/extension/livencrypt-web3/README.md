# Livencrypt Web3 Bridge

Extension MV3 para exponer `window.livencrypt` como proveedor EIP-1193 parcial y reenviar peticiones al host nativo `com.livencrypt.gateway`.

## Estado

Integrado:

- `eth_requestAccounts`
- `eth_accounts`
- `eth_chainId`
- `net_version`
- `eth_getBalance`
- `eth_getTransactionCount`
- `eth_gasPrice`
- `wallet_switchEthereumChain`
- `wallet_addEthereumChain`

Pendiente:

- serializador RLP/EIP-1559 para `eth_sendTransaction` desde objetos DEX;
- `eth_estimateGas` con simulacion EVM auditada;
- `personal_sign`;
- `eth_signTypedData_v4`;
- UI de permisos por dominio.

## Carga manual en Chromium/Brave

```bash
chrome://extensions
Modo desarrollador
Cargar desempaquetada
Seleccionar: /usr/share/livencrypt/extension/livencrypt-web3
```

La TUI de Livencrypt debe estar abierta, Boot Shield desbloqueado y la pasarela Web3 inicializada.

