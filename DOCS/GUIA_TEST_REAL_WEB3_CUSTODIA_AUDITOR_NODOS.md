# Guia de test real: Pasarela Web3, custodia y auditor visual de direcciones

## 1. Objetivo

Esta guia define como realizar un test real, no simulado, de las funciones:

```text
w = Pasarela Web3 / custodia
k = Auditor visual de direcciones publicas
```

El objetivo es verificar:

- configuracion completa de politicas Web3;
- reglas programadas;
- precios manuales/offline;
- perfiles `OFFLINE`, `RPC LECTURA` y `RPC OPERATIVO`;
- derivacion de wallets por blockchain;
- QR ASCII individual por wallet;
- copiado del vinculo publico para extension o aplicacion externa;
- comprobacion real de nodos blockchain;
- separacion estricta entre lectura, firma y broadcast.

## 2. Condicion importante

Un test real de nodos no puede ser una simulacion.

Por tanto, para que el check sea valido se necesita:

- conexion real a endpoints RPC;
- adaptador RPC real por cadena;
- validacion de chain ID/red;
- lectura real de balance/nonce/fees/estado;
- control de timeout;
- comparacion con fallback cuando exista;
- rechazo de nodos no coincidentes.

Si Livencrypt responde:

```text
RPC lectura pendiente de adaptador auditado
```

entonces el test de red real no esta implementado todavia para esa cadena. Ese resultado no debe considerarse test superado.

## 3. Alcance por cadena

### Bitcoin

Debe verificarse:

- derivacion de clave publica;
- ruta HD tipo `m/84'/0'/cuenta'/0/indice`;
- QR ASCII individual;
- copiado del payload publico;
- consulta real a nodo Bitcoin o Electrum compatible cuando exista adaptador;
- comprobacion de altura/bloque/tiempo;
- lectura de balance si el adaptador lo soporta.

### Ethereum / EVM

Debe verificarse:

- derivacion de direccion `0x...`;
- ruta HD tipo `m/44'/60'/cuenta'/0/indice`;
- chain ID real;
- balance nativo;
- nonce;
- gas/fee;
- estado de transaccion;
- parser de transferencias ETH/ERC-20;
- bloqueo de broadcast fuera de `RPC OPERATIVO`.

### Solana

Debe verificarse:

- derivacion de direccion base58;
- ruta HD tipo `m/44'/501'/cuenta'/0/indice`;
- lectura de balance;
- slot/tiempo de cadena;
- fee estimado;
- estado de transaccion;
- bloqueo de broadcast fuera de `RPC OPERATIVO`.

### Monero, ZCash, Starknet y otras

No deben marcarse como soportadas si no existe adaptador especifico.

Resultado correcto mientras falte adaptador:

```text
solo auditoria / no soportada / requiere adaptador especifico
```

No es aceptable mostrar estas cadenas como listas para firma real si no existen:

- derivador correcto;
- parser;
- normalizador de cantidades;
- formato de direccion;
- firma;
- verificacion de transaccion;
- cliente RPC.

## 4. Entorno de prueba recomendado

Usar un equipo de pruebas, no el equipo de custodia principal.

Requisitos:

```text
Linux Mint / Debian compatible
Livencrypt 2.0 instalado
terminal con soporte TUI
conexion a Internet solo si se va a probar RPC real
endpoints RPC propios o auditados
sin claves privadas reales de produccion
fondos reales solo en importes minimos o testnet
```

Para pruebas de lectura real se recomienda usar direcciones publicas conocidas o wallets de prueba.

Para pruebas de firma/broadcast:

```text
usar testnet/devnet cuando sea posible
usar importes minimos si se usa mainnet
no usar cuentas de custodia real hasta completar auditoria
```

## 5. Preparacion

Compilar:

```bash
cd "/home/Divad/Escritorio/LIVENCRYPT 2.0/src-tui"
cargo build --release --locked
```

Ejecutar:

```bash
./target/release/livencrypt-core
```

Si esta instalado desde `.deb`:

```bash
/usr/bin/livencrypt-core
```

## 6. Preparar nodos reales

Abrir Livencrypt y entrar en:

```text
N = Gestion de nodos
```

Configurar endpoints reales por cadena.

Ejemplo `nodes.toml`:

```toml
profile = "RpcReadOnly"
max_clock_drift_seconds = 30
timeout_ms = 3000

[[chain]]
name = "ethereum"
primary = "https://ENDPOINT-ETHEREUM-PRIMARIO"
fallbacks = ["https://ENDPOINT-ETHEREUM-FALLBACK"]

[[chain]]
name = "bitcoin"
primary = "https://ENDPOINT-BITCOIN-PRIMARIO"
fallbacks = ["https://ENDPOINT-BITCOIN-FALLBACK"]

[[chain]]
name = "solana"
primary = "https://ENDPOINT-SOLANA-PRIMARIO"
fallbacks = ["https://ENDPOINT-SOLANA-FALLBACK"]
```

Guardar desde la TUI:

```text
G = guardar nodes.toml
```

Cambiar perfil:

```text
M = OFFLINE -> RPC LECTURA -> RPC OPERATIVO
```

## 7. Test 1: Auditor visual de direcciones publicas

Entrar en:

```text
k = Auditor visual de direcciones publicas
```

Para cada cadena soportada:

```text
Red: Bitcoin / Ethereum / Solana
Cuenta: 0
Indice: 0
Enter = derivar
```

Verificar:

```text
direccion generada
ruta HD correcta
estado de soporte correcto
QR ASCII individual visible
payload publico copiable
no se muestra clave privada
no se muestra frase
```

Copiar vinculo publico:

```text
C
```

o:

```text
Ctrl+C
```

Payload esperado:

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

El QR ASCII debe ser diferente si cambia cualquiera de estos valores:

```text
chain
account
address_index
derivation_path
address
```

## 8. Test 2: Pasarela Web3 / custodia

Entrar en:

```text
w = Pasarela Web3 / custodia
```

Verificar panel principal:

```text
Perfil Web3
TX hoy
Cantidad cripto/token hoy
Valor fiat estimado hoy
Reloj verificado
Limites
Precios manuales/offline
DEX permitidos
CEX permitidos
```

Configurar limites globales:

```text
[1] Max TX diario: 10
[2] Max cripto/token diario: 1
[3] Max valor fiat diario: 5000
[4] Moneda fiat: USD
Enter = aplicar
```

Resultado esperado:

```text
Limites cripto/FIAT del cortafuegos actualizados
```

## 9. Test 3: Precios manuales/offline

Desde Pasarela Web3:

```text
$ = Precios / oraculo
```

Insertar precios reales consultados externamente:

```text
Activo: BTC
Fiat: USD
Valor: precio real actual
Enter

Activo: ETH
Fiat: USD
Valor: precio real actual
Enter

Activo: SOL
Fiat: USD
Valor: precio real actual
Enter
```

Verificar:

```text
precio aparece en lista
fuente = manual-local
no hay consulta externa automatica
no hay simulacion
```

Si se usa fichero firmado `.lvcprices`, el test solo sera valido cuando exista:

```text
verificador Ed25519
clave publica configurada
rechazo de firma invalida
rechazo de fichero caducado
```

## 10. Test 4: Politicas por cuenta

Desde Pasarela Web3:

```text
P = Politicas por cuenta
```

Crear politica Ethereum operativa:

```text
Red: Ethereum
Cuenta: 1
Indice: *
Etiqueta: Operativa ETH
Max TX: 10
Max cripto/token: 1
Max FIAT: 5000
Moneda: USD
Confirmacion local: si
Destinos: 0xDESTINO_PERMITIDO
Contratos: 0xCONTRATO_TOKEN_PERMITIDO
Activo: USDT
Limite activo: 1000
Enter
```

Resultado esperado:

```text
Politica por cuenta guardada.
```

Crear politica fria:

```text
Red: Bitcoin
Cuenta: 0
Indice: *
Etiqueta: Boveda fria BTC
Max TX: 1
Max cripto/token: 0
Max FIAT: 0
Moneda: USD
Confirmacion local: si
Enter
```

Resultado esperado:

```text
Politica por cuenta guardada.
```

## 11. Test 5: Reglas programadas

Desde Politicas:

```text
S = Reglas programadas
```

Crear regla:

```text
Nombre: Pago proveedor A
Activo: USDT
Destino: 0xDESTINO_PERMITIDO
Max TX: 4
Max activo: 1000
Max FIAT: 1000
Moneda: USD
Ventana: mensual
Caduca UNIX: 1798675200
Enter
```

Resultado esperado:

```text
Regla programada guardada.
```

Verificar que la regla:

```text
no firma automaticamente
solo permite prevalidar operaciones coincidentes
rechaza destino distinto
rechaza activo distinto
rechaza importe superior
rechaza regla caducada
```

## 12. Test 6: Inspector RPC real

Desde Pasarela Web3:

```text
I = Inspector RPC
```

### Perfil OFFLINE

Seleccionar:

```text
Perfil: OFFLINE
```

Ejecutar:

```text
B = balance
N = nonce
F = fee
T = estado TX
```

Resultado esperado:

```text
Perfil OFFLINE: lectura RPC bloqueada.
```

### Perfil RPC LECTURA

Seleccionar:

```text
Perfil: RPC LECTURA
```

Probar Ethereum:

```text
Red: Ethereum
Direccion: 0xDIRECCION_REAL
Activo: native
B = balance
N = nonce
F = fee
```

Resultado esperado en test real:

```text
balance real desde nodo
nonce real desde nodo
fee real desde nodo
chain ID validado
timeout aplicado
endpoint usado registrado
```

Si aparece:

```text
RPC lectura pendiente de adaptador auditado
```

entonces la interfaz esta integrada, pero el adaptador RPC real no esta implementado. No marcar como test superado.

### Perfil RPC OPERATIVO

Seleccionar:

```text
Perfil: RPC OPERATIVO
```

Verificar:

```text
lecturas permitidas
broadcast bloqueado si no existe adaptador auditado
firma requiere confirmacion local
politicas por cuenta aplicadas antes de firma
```

No transmitir transacciones mainnet durante la primera prueba. Usar testnet/devnet o importes minimos.

## 13. Test 7: Comprobacion real de nodos

Para cada cadena con adaptador RPC real:

```text
1. leer chain ID o identificador de red
2. leer altura de bloque / slot
3. leer timestamp de bloque si existe
4. leer balance de direccion publica
5. leer nonce si aplica
6. estimar fee
7. consultar estado de TX conocida
8. repetir contra fallback
9. comparar respuestas
10. registrar divergencias
```

Criterios de aceptacion:

```text
chain ID coincide con configuracion
endpoint responde dentro de timeout
fallback responde
altura no esta atrasada de forma anomala
timestamp no supera drift maximo
balance coincide con explorador independiente
nonce coincide con explorador independiente
fee es razonable
estado TX coincide con explorador independiente
```

Criterios de rechazo:

```text
chain ID distinto
timeout repetido
nodo muy atrasado
respuestas divergentes entre primario/fallback
balance imposible
nonce inferior al esperado
fee fuera de rango
endpoint no autorizado
```

## 14. Test 8: Firma y politicas

Solo ejecutar si existe payload real validado y entorno seguro.

Secuencia:

```text
1. configurar politica por cuenta
2. configurar destino permitido
3. configurar contrato permitido si token
4. configurar precio FIAT
5. recibir solicitud de firma desde extension/app
6. revisar modal de autorizacion
7. verificar resumen
8. autorizar
9. confirmar que contador TX aumenta
10. confirmar que cripto/token aumenta
11. confirmar que FIAT aumenta
```

Pruebas negativas:

```text
destino no permitido -> rechazo
contrato no permitido -> rechazo
chain ID no permitido -> rechazo
importe superior -> rechazo
FIAT superior -> rechazo
sin precio FIAT requerido -> rechazo
regla caducada -> rechazo
```

## 15. Test 9: Broadcast

El broadcast no debe estar permitido salvo:

```text
perfil RPC OPERATIVO
adaptador RPC auditado
endpoint autorizado
politica por cuenta valida
confirmacion local
payload parseado
fee validado
nonce validado
chain ID validado
```

Resultado esperado si no hay adaptador:

```text
broadcast bloqueado: requiere adaptador RPC operativo auditado y politica local
```

Este resultado es correcto y seguro.

No marcar el broadcast como test real superado hasta transmitir una transaccion real en testnet/devnet o con importe minimo controlado.

## 16. Registro de resultados

Crear tabla de resultados:

```text
Fecha:
Equipo:
Version Livencrypt:
Perfil Web3:
Endpoints:

Cadena | Funcion | Resultado | Evidencia | Estado
BTC    | derivacion | OK | direccion/QR | aprobado
ETH    | balance RPC | OK/FALLO | hash/log | pendiente
SOL    | fee RPC | OK/FALLO | respuesta nodo | pendiente
```

Estados permitidos:

```text
aprobado
rechazado
pendiente adaptador
pendiente endpoint
pendiente auditoria
```

## 17. Conclusiones esperadas

El test completo solo puede considerarse superado si:

```text
la TUI permite configurar todas las funciones
las politicas se aplican antes de firmar
el auditor genera QR individual por wallet
el copiado produce payload publico valido
los nodos reales responden y validan chain ID
RPC LECTURA nunca transmite
OFFLINE nunca consulta red
RPC OPERATIVO no transmite sin politica y confirmacion
broadcast permanece bloqueado si no hay adaptador auditado
```

Si cualquier funcion devuelve "pendiente de adaptador auditado", el frontend esta conectado pero falta backend RPC real para completar el test-check de nodos.

