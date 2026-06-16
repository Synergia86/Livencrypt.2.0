# Informe de mejora: Pasarela Web3, limites por cuenta y auditor multicadena

## 1. Contexto observado

En la pantalla:

```text
PASARELA WEB3 SECURE GATEWAY [ CONGELADA - Pasarela Web3 no inicializada ]
```

aparecen los campos:

```text
Volumen diario consumido: 0.0000000 unidades

Configuracion de limites
[2] Techo diario unidades: 5000
```

La duda es correcta: el termino `unidades` no es suficientemente preciso para un operador real. En custodia cripto, el limite debe poder expresarse por:

- cantidad de moneda nativa consumida;
- cantidad de token consumido;
- valor equivalente en USD/EUR;
- numero de transacciones;
- combinacion de las anteriores;
- reglas personalizadas por cuenta, red, token, contrato, destino y ventana temporal.

## 2. Que significa actualmente `unidades`

Segun el backend actual, el firewall Web3 usa:

```rust
max_daily_volume_units
volume_today_units
effective_volume_units()
```

Esto indica que el volumen se calcula como una cantidad normalizada del activo transferido.

Ejemplos:

```text
BTC: unidades ~= BTC transferidos
ETH: unidades ~= ETH transferidos
SOL: unidades ~= SOL transferidos
ERC-20/SPL: unidades ~= token normalizado segun decimales registrados
```

Por tanto, `5000 unidades` no significa necesariamente `5000 USD`. Puede significar:

```text
5000 ETH
5000 USDT
5000 SOL
5000 unidades de un token ERC-20
```

El problema es que una unica palabra no permite distinguir entre:

```text
limite por cantidad cripto
limite por valor fiat
limite por cantidad de transacciones
limite por token concreto
```

## 3. Riesgo operativo del modelo actual

El modelo actual es util como primera barrera, pero es insuficiente para custodia real.

Riesgos:

- Un limite de `5000 unidades` puede ser seguro para USDT, pero catastrófico para BTC.
- Un token sin decimales registrados puede calcularse mal o rechazarse.
- No hay separacion clara entre volumen de moneda nativa y valor fiat.
- El limite parece global, no por cuenta.
- No permite reglas diferentes para wallet fria, wallet operativa, hot wallet, cuenta de pruebas o cuenta institucional.
- No permite programar autorizaciones futuras segun volumen acumulado.

## 4. Cambio recomendado de interfaz

La pantalla debe abandonar el texto ambiguo:

```text
Volumen diario consumido: 0.0000000 unidades
[2] Techo diario unidades: 5000
```

Debe cambiar a un panel con tres limites independientes:

```text
Limites de gasto
[1] Max TX por dia:              10
[2] Max cripto por activo:       0.50000000 BTC / 10 ETH / 1000 USDT
[3] Max valor fiat diario:       5000 USD
[4] Max valor fiat por TX:       500 USD
[5] Ventana temporal:            diario / semanal / mensual / personalizado
```

Y el estado debe mostrarse asi:

```text
Consumo actual
TX hoy:               2 / 10
BTC hoy:              0.01000000 / 0.50000000 BTC
ETH hoy:              0.00000000 / 10 ETH
USDT hoy:             120.00 / 1000 USDT
USD estimado hoy:     438.50 / 5000 USD
```

## 5. Reglas por cuenta

Cada cuenta debe tener politica propia.

Ejemplo:

```text
Cuenta 0 - Boveda fria
  firmar: desactivado por defecto
  max TX/dia: 1
  max USD/dia: 0
  requiere doble confirmacion: si

Cuenta 1 - Operativa
  firmar: activado
  max TX/dia: 10
  max USD/dia: 5000
  max por TX: 500
  tokens permitidos: BTC, ETH, USDT, USDC

Cuenta 2 - Pruebas
  firmar: activado
  max TX/dia: 50
  max USD/dia: 100
  redes permitidas: testnet/devnet
```

La clave de diseño es que la regla no debe ser global. Debe indexarse por:

```text
chain_id
chain_type
account_index
address_index
asset_id
destination_id
time_window
```

## 6. Programacion de transacciones permitidas

Debe existir una seccion para transacciones programadas.

Casos de uso:

- permitir hasta `N` transacciones diarias a una direccion concreta;
- permitir retiros acumulados hasta `X BTC`;
- permitir gasto acumulado hasta `Y USD`;
- bloquear todo fuera de horario;
- permitir solo DEX/CEX preautorizados;
- permitir pagos recurrentes;
- exigir revalidacion si cambia el destino, contrato o token.

Modelo recomendado:

```text
Regla programada
  nombre: Pago proveedor A
  cuenta: 1
  red: Ethereum
  activo: USDT
  destino: 0x...
  ventana: mensual
  max TX: 4
  max token acumulado: 1000 USDT
  max fiat acumulado: 1000 USD
  requiere confirmacion local: si
  caduca: 2026-12-31
```

Importante: una regla programada no debe firmar automaticamente sin control. Debe permitir la operacion solo si coincide exactamente con la politica y aun asi mostrar confirmacion local cuando el perfil lo exija.

## 7. Oraculo de precio fiat

Para limitar por USD/EUR hace falta convertir cripto a fiat.

Opciones:

### Opcion A: modo offline estricto

El usuario introduce manualmente precios de referencia:

```text
BTC/USD = 105000
ETH/USD = 3800
SOL/USD = 170
USDT/USD = 1
USDC/USD = 1
```

Ventaja:

- compatible con equipo aislado;
- no depende de APIs externas;
- reduce superficie de red.

Desventaja:

- el precio puede quedar desactualizado;
- requiere procedimiento operativo.

### Opcion B: fichero de precios firmado

Importar un archivo:

```text
prices_2026-06-12.lvcprices
```

Contenido:

```text
activo
precio_usd
timestamp
fuente
firma Ed25519
```

Ventaja:

- valido para entornos aislados;
- auditable;
- puede integrarse con flujo institucional.

### Opcion C: consulta online

Solo recomendable para perfiles conectados.

Requisitos:

- endpoints permitidos;
- TLS validado;
- cache firmada;
- tolerancia maxima de antiguedad;
- no mezclar consulta online con wallet fria.

## 8. Conexion a nodos blockchain y perfiles operativos

La arquitectura prevista debe permitir conexion a nodos reales, pero esa capacidad no debe activarse de forma indiscriminada. El usuario debe decidir que perfil mantener activo en cada instalacion o sesion.

La arquitectura apunta a:

- gestor de nodos por cadena;
- endpoints RPC configurables;
- nodos primarios y fallback;
- politicas por cuenta;
- validacion de transacciones antes de firmar;
- pasarela Web3 mediante `livencrypt-bridge`.

Pero conectar con nodos reales implica mas que guardar URLs RPC. Para cada blockchain hace falta:

- cliente RPC especifico;
- parser de respuestas;
- validacion de chain ID/red;
- control de timeouts;
- listas blancas de endpoints;
- modo offline/aislado;
- proteccion contra nodos maliciosos;
- verificacion de saldos, nonce, fees y estado de transaccion;
- separacion entre modo auditoria y modo firma.

### 8.1. Perfiles seleccionables por usuario

Livencrypt 2.0 debe mostrar una seccion de perfil Web3:

```text
PERFIL WEB3
[ ] OFFLINE
[ ] RPC LECTURA
[ ] RPC OPERATIVO
```

El perfil activo debe guardarse en el vault cifrado y aplicarse al iniciar la sesion. Si Boot Shield esta activo, este perfil no debe quedar en texto claro fuera del vault.

### 8.2. Perfil OFFLINE

```text
OFFLINE
```

Comportamiento:

- no consulta nodos;
- no abre conexiones RPC;
- no actualiza precios online;
- deriva direcciones;
- custodia claves;
- firma solo payloads validados localmente si el perfil de cuenta lo permite;
- permite importar precios/saldos/nonce mediante archivos firmados.

Uso recomendado:

- equipos aislados;
- cold wallets;
- custodia de largo plazo;
- operaciones institucionales con datos importados por canal controlado.

### 8.3. Perfil RPC LECTURA

```text
RPC LECTURA
```

Comportamiento:

- consulta saldos;
- consulta nonce;
- consulta fees/gas;
- consulta estado de transacciones;
- consulta precios cripto/fiat si hay oraculo configurado;
- no transmite transacciones;
- no firma automaticamente;
- no permite broadcast.

Uso recomendado:

- auditoria;
- seguimiento de balances;
- calculo de limites fiat;
- comprobacion de estado antes de firmar offline.

### 8.4. Perfil RPC OPERATIVO

```text
RPC OPERATIVO
```

Comportamiento:

- permite preparar transacciones;
- permite transmitir transacciones;
- aplica politicas por cuenta;
- aplica limites por TX, cripto, token y fiat;
- exige confirmacion fisica/local antes de firmar;
- exige validacion de destino, contrato, chain ID, nonce y fee;
- registra auditoria local.

Uso recomendado:

- wallets operativas;
- equipos conectados bajo reglas estrictas;
- cuentas con limites bajos y destinos permitidos.

No debe usarse para bovedas frias salvo decision expresa del operador.

## 9. Actualizacion de precios cripto/fiat en tiempo real

Si el usuario activa `RPC LECTURA` o `RPC OPERATIVO`, Livencrypt 2.0 puede actualizar precios de cripto y fiat en tiempo real.

Debe soportar:

```text
BTC/USD
BTC/EUR
ETH/USD
ETH/EUR
SOL/USD
USDT/USD
USDC/EUR
token/custom/USD
```

Requisitos:

- definir moneda fiat principal: USD, EUR u otra;
- permitir varias monedas fiat simultaneas;
- asociar precio a timestamp;
- registrar fuente del precio;
- definir tolerancia maxima de antiguedad;
- rechazar precios fuera de rango;
- usar mediana entre varias fuentes cuando sea posible;
- cachear precios en memoria;
- si se persisten, cifrarlos dentro del vault.

Ejemplo de panel:

```text
PRECIOS
Perfil: RPC LECTURA
Fiat principal: EUR

BTC: 105000 USD / 97000 EUR     edad: 8s
ETH: 3800 USD / 3510 EUR        edad: 9s
SOL: 170 USD / 157 EUR          edad: 11s
USDT: 1.000 USD / 0.924 EUR     edad: 7s

Estado: 3 nodos OK, 1 fuente precio OK, reloj consensuado OK
```

Con esto los limites pueden expresarse asi:

```text
max 0.05 BTC por dia
max 1000 USDT por dia
max 5000 USD por dia
max 4600 EUR por dia
```

## 10. Doble check temporal y reloj interno Livencrypt

Al conectarse a varios nodos blockchain, Livencrypt 2.0 puede usar un doble check temporal para detectar desajustes de reloj local.

No debe llamarse literalmente "reloj atomico" salvo que use una fuente atomica real. Lo correcto es:

```text
reloj interno verificado por consenso de nodos
```

Fuentes posibles:

- hora local del sistema;
- median time past o timestamp de bloque Bitcoin;
- timestamp de bloque Ethereum;
- slot/timestamp Solana;
- altura de bloque;
- respuesta de varios nodos RPC;
- archivo horario firmado en modo offline.

Objetivo:

- detectar reloj local manipulado;
- detectar nodos RPC desfasados;
- impedir reglas programadas si la hora no es fiable;
- evitar replay temporal;
- comprobar caducidad de politicas;
- validar ventanas de gasto.

Modelo recomendado:

```text
local_time = reloj del sistema
chain_time[BTC] = timestamp bloque confirmado
chain_time[ETH] = timestamp bloque confirmado
chain_time[SOL] = timestamp/slot confirmado

consensus_time = mediana(chain_time[])
drift = abs(local_time - consensus_time)

si drift > limite:
  bloquear firma operativa
  permitir solo auditoria
  mostrar alerta
```

Panel propuesto:

```text
RELOJ VERIFICADO
Sistema:      2026-06-12 12:20:30
BTC:          2026-06-12 12:20:04  bloque 000...
ETH:          2026-06-12 12:20:24  bloque 22...
SOL:          slot 341...          edad 2s
Mediana:      2026-06-12 12:20:18
Desviacion:   12s
Estado:       OK
```

Regla:

```text
OFFLINE:
  usar hora local + archivo horario firmado opcional

RPC LECTURA:
  calcular drift y avisar

RPC OPERATIVO:
  bloquear firma si drift supera el limite configurado
```

## 11. Defensa frente a nodos maliciosos

Un nodo RPC puede mentir o estar desfasado. Por tanto, Livencrypt no debe confiar en un unico nodo.

Medidas:

- configurar varios nodos por cadena;
- separar nodo primario y fallback;
- comprobar chain ID;
- comprobar altura de bloque minima;
- comparar respuestas entre nodos;
- detectar forks o nodos atrasados;
- aplicar timeout estricto;
- registrar endpoint usado;
- no aceptar cambios de destino sugeridos por RPC;
- no aceptar payloads opacos sin parseo local.

Politica recomendada:

```text
si 1 nodo falla:
  usar fallback

si respuestas divergen:
  congelar pasarela

si chain ID no coincide:
  bloquear operacion

si nodo esta atrasado:
  modo lectura degradado

si destino/contrato no coincide con politica:
  rechazar firma
```

## 12. Auditor visual de direcciones publicas

Pantalla actual:

```text
AUDITOR VISUAL DE DIRECCIONES PUBLICAS
solo deriva claves publicas; no firma transacciones

[Red]
[Cuenta]
[Indice]
```

La funcion actual deriva claves publicas desde el llavero desbloqueado. No firma transacciones. Es una pantalla de inspeccion.

En modo `RPC LECTURA`, esta pantalla puede ampliar su funcion para consultar saldo, nonce, historial resumido y precio fiat estimado de la direccion seleccionada.

En modo `OFFLINE`, debe seguir funcionando sin consultar nodos.

## 13. Que significa `Cuenta`

`Cuenta` debe mapearse a un nivel de derivacion jerarquica.

En BIP-44/BIP-84:

```text
m / purpose' / coin_type' / account' / change / address_index
```

Ejemplo Ethereum:

```text
m/44'/60'/0'/0/0
```

Aqui:

```text
account = 0
address_index = 0
```

Si cambia `Cuenta`:

```text
m/44'/60'/1'/0/0
m/44'/60'/2'/0/0
```

se derivan familias distintas de direcciones.

## 14. Que significa `Indice`

`Indice` es el numero de direccion dentro de una cuenta.

Ejemplo:

```text
Cuenta 0, Indice 0 -> primera direccion
Cuenta 0, Indice 1 -> segunda direccion
Cuenta 0, Indice 2 -> tercera direccion
```

En wallets HD, esto permite generar muchas direcciones sin guardar cada clave privada por separado.

Problema de UX actual:

- no queda claro que `Cuenta` y `Indice` generan direcciones distintas;
- no se muestra la ruta derivada completa;
- no se puede nombrar cada cuenta;
- no se puede editar metadatos de cuenta;
- no se puede vincular politica de limites a una cuenta concreta.

## 15. Cambio recomendado para el auditor

La pantalla debe cambiar de:

```text
[Red] Bitcoin
[Cuenta] 0
[Indice] 0
```

a:

```text
Red:              Ethereum
Cuenta:           1 - Operativa
Indice direccion: 0
Ruta:             m/44'/60'/1'/0/0

Direccion:
0x...

Politica asociada:
max TX/dia: 10
max USD/dia: 5000
tokens permitidos: USDT, USDC, ETH
```

Tambien debe permitir:

- crear cuenta;
- renombrar cuenta;
- marcar cuenta como fria/operativa/pruebas;
- asignar limites;
- asignar redes permitidas;
- asignar destinos permitidos;
- exportar solo clave publica/direccion;
- nunca exportar clave privada.

## 16. Multicadena real

Actualmente el codigo contempla Bitcoin, Ethereum, Solana y Monero como tipo parcial, pero Monero devuelve error especializado.

Para custodiar "todas las criptomonedas" no basta con agregar nombres al enum. Cada blockchain puede requerir:

- curva criptografica distinta;
- esquema de firma distinto;
- formato de direccion distinto;
- parser de transacciones propio;
- normalizacion de importes;
- decimales por activo;
- reglas de memo/tag/payment id;
- protecciones anti-replay;
- soporte multisig o shielded;
- libreria auditada.

## 17. Monero

Monero no debe tratarse como Ethereum o Bitcoin.

Requiere:

- claves de vista y gasto;
- subaddresses;
- ring signatures CLSAG;
- Bulletproofs/Bulletproofs+;
- key images;
- privacidad de cantidades;
- parser especifico;
- validacion de fees y unlock time.

Riesgo: una implementacion incompleta puede generar direcciones o firmas incorrectas y perder fondos.

Recomendacion:

```text
MoneroAdapter separado
MoneroKeymaster separado
no mezclar con BIP-44 generico
usar libreria madura o binding auditado
mostrar estado "solo auditoria" hasta soportar firma segura
```

## 18. ZCash

ZCash tiene dos mundos:

```text
transparent addresses
shielded Sapling/Orchard
```

Requiere:

- soporte diferenciado para direcciones transparentes y shielded;
- pruebas de conocimiento cero;
- viewing keys;
- manejo de notas;
- arboles de compromiso;
- libreria especializada.

Recomendacion:

```text
ZcashTransparentAdapter
ZcashShieldedAdapter
soporte inicial solo transparente si no hay libreria shielded auditada
```

## 19. Starknet

Starknet no usa el modelo EVM clasico aunque comparte ecosistema Ethereum.

Requiere:

- curva Stark/secp256k1 segun cuenta y version;
- account abstraction;
- contratos de cuenta;
- nonce y calldata especificos;
- firma Pedersen/Poseidon/Stark;
- parseo de invoke/declare/deploy_account.

Recomendacion:

```text
StarknetAdapter
StarknetAccountModel
validacion de contrato de cuenta
politicas por selector/calldata
```

## 20. Arquitectura recomendada

Crear una capa por blockchain:

```rust
trait ChainWalletAdapter {
    fn chain_id(&self) -> ChainId;
    fn derive_public_address(&self, account: u32, index: u32) -> Result<AddressPreview, String>;
    fn parse_transaction(&self, raw: &[u8]) -> Result<ParsedTransaction, String>;
    fn estimate_assets(&self, tx: &ParsedTransaction) -> Result<Vec<AssetDelta>, String>;
    fn sign_transaction(&self, request: SignRequest) -> Result<SignatureResponse, String>;
}
```

Agregar una capa RPC separada:

```rust
trait ChainRpcAdapter {
    fn chain_id(&self) -> ChainId;
    fn endpoint_health(&self) -> Result<NodeHealth, String>;
    fn get_balance(&self, address: &str, asset: Option<&str>) -> Result<AssetAmount, String>;
    fn get_nonce(&self, address: &str) -> Result<NonceState, String>;
    fn estimate_fee(&self, tx: &ParsedTransaction) -> Result<FeeEstimate, String>;
    fn get_transaction_status(&self, txid: &str) -> Result<TransactionStatus, String>;
    fn get_chain_time(&self) -> Result<ChainTime, String>;
    fn broadcast_transaction(&self, signed_tx: &[u8]) -> Result<BroadcastResult, String>;
}
```

El uso de `broadcast_transaction` debe estar bloqueado salvo perfil `RPC OPERATIVO`.

Y una capa de politicas independiente:

```rust
struct AccountPolicy {
    chain: String,
    account_index: u32,
    address_index: Option<u32>,
    max_tx_per_window: u32,
    max_native_amount: Option<Decimal>,
    max_asset_amounts: HashMap<String, Decimal>,
    max_fiat_value: Option<Decimal>,
    fiat_currency: String,
    allowed_destinations: Vec<String>,
    allowed_contracts: Vec<String>,
    schedule: PolicySchedule,
    require_local_confirmation: bool,
}
```

Y una configuracion de perfil:

```rust
enum Web3ConnectivityProfile {
    Offline,
    RpcReadOnly,
    RpcOperational,
}

struct NodeEndpointPolicy {
    chain: String,
    primary_endpoint: String,
    fallback_endpoints: Vec<String>,
    allow_broadcast: bool,
    require_chain_id: String,
    max_clock_drift_seconds: u64,
    timeout_ms: u64,
}
```

## 21. Modelo de limites recomendado

Separar los acumuladores:

```text
tx_count
native_amount_by_chain
asset_amount_by_token
fiat_value_by_currency
destination_count
contract_count
```

Ejemplo:

```text
Cuenta 1 Ethereum
  TX hoy: 2/10
  ETH hoy: 0.05/1.00
  USDT hoy: 100/1000
  USD hoy: 290/5000
```

## 22. Cambios concretos necesarios en codigo

Archivos implicados:

```text
src-tui/src/crypto/blockchain/types.rs
src-tui/src/crypto/blockchain/firewall.rs
src-tui/src/crypto/blockchain/tx_parser.rs
src-tui/src/crypto/blockchain/multi_curve.rs
src-tui/src/crypto/blockchain/nodes.rs
src-tui/src/crypto/blockchain/supervisor.rs
src-tui/src/crypto/blockchain/worker.rs
src-tui/src/main.rs
```

Cambios:

1. Renombrar `max_daily_volume_units` a un concepto explicito:

```text
max_daily_native_or_asset_amount
```

o dividirlo directamente:

```text
max_daily_crypto_amounts
max_daily_fiat_value
```

2. Crear estructura `AccountPolicy`.

3. Crear pantalla TUI de politicas por cuenta.

4. Mostrar ruta derivada completa en el auditor.

5. Permitir renombrar cuentas.

6. Asociar cada cuenta a reglas de gasto.

7. Implementar importacion de precios fiat offline firmados.

8. Agregar adaptadores por cadena, no solo variantes en `ChainType`.

9. Mostrar claramente si una cadena esta en modo:

```text
auditoria
firma experimental
firma soportada
solo lectura
no soportada
```

10. Crear perfiles:

```text
OFFLINE
RPC LECTURA
RPC OPERATIVO
```

11. Crear `ChainRpcAdapter` por cadena.

12. Crear `PriceOracle` con modo offline, fichero firmado y modo RPC/API.

13. Crear comprobacion de reloj interno por consenso de nodos.

14. Guardar el perfil activo dentro del vault cifrado.

15. Bloquear broadcast si el perfil no es `RPC OPERATIVO`.

## 23. Propuesta de pantalla final

```text
PASARELA WEB3 SECURE GATEWAY
Estado: OPERATIVA / CONGELADA / BLOQUEADA
Perfil: OFFLINE / RPC LECTURA / RPC OPERATIVO

Cuenta activa:
  Ethereum / Cuenta 1 - Operativa / m/44'/60'/1'/0/*

Consumo:
  TX:        2 / 10 diario
  ETH:       0.05 / 1.00 diario
  USDT:      100 / 1000 diario
  USD:       290 / 5000 diario

Politicas:
  Destinos permitidos: 4
  Contratos permitidos: 8
  Programadas activas: 3

Nodos:
  Ethereum RPC: primario OK, fallback 1 OK
  Bitcoin RPC: primario OK
  Solana RPC: degradado

Reloj verificado:
  drift: 12s
  estado: OK

Acciones:
  [P] Politicas por cuenta
  [A] Auditor direcciones
  [N] Nodos
  [M] Modo Web3
  [$] Precios
  [R] Rearmar disyuntor
```

## 24. Prioridad de integracion

### Critico

1. Cambiar `unidades` por etiquetas explicitas.
2. Separar limites por cripto y por fiat.
3. Aplicar reglas por cuenta.
4. Mostrar ruta derivada completa.
5. Evitar que Monero/ZCash/Starknet aparezcan como soportados si solo son nombres.
6. Implementar perfiles `OFFLINE`, `RPC LECTURA` y `RPC OPERATIVO`.
7. Bloquear broadcast fuera del perfil `RPC OPERATIVO`.

### Alto

1. Crear editor de politicas por cuenta.
2. Crear importador offline de precios fiat firmados.
3. Programar transacciones permitidas por ventana temporal.
4. Mostrar estado de soporte por cadena.
5. Integrar gestor de nodos por cadena con primario/fallback.
6. Integrar comprobacion de reloj interno por consenso de nodos.
7. Actualizar precios cripto/fiat en tiempo real si el perfil lo permite.

### Medio

1. Exportar direcciones publicas en formato QR.
2. Etiquetar cuentas.
3. Historial local de consumo por cuenta.
4. Alertas por cercania a limite.
5. Mostrar salud de nodos y drift temporal por cadena.

## 25. Conclusion

La palabra `unidades` debe eliminarse de la UX porque no expresa riesgo financiero real. Livencrypt 2.0 debe distinguir entre cantidad cripto, cantidad de token, valor fiat y numero de transacciones.

La Pasarela Web3 debe evolucionar hacia politicas por cuenta y por activo. El Auditor Visual debe pasar de ser una derivacion simple de clave publica a un gestor de cuentas multicadena con rutas, etiquetas, limites y estado de soporte por blockchain.

Para soportar Monero, ZCash, Starknet y otras redes no basta con anadirlas a una lista. Cada una requiere adaptador criptografico, parser, formato de direccion, reglas de firma y validacion de importes propios.

La conexion a nodos debe ser una capacidad controlada por perfil. En equipos aislados, el modo natural es `OFFLINE`. En equipos conectados, `RPC LECTURA` permite auditoria y precios sin emitir transacciones. `RPC OPERATIVO` debe reservarse para cuentas con politicas estrictas, confirmacion fisica/local y endpoints auditados.

La actualizacion instantanea de precios cripto/fiat y el reloj interno verificado por nodos son utiles, pero solo si se implementan con defensa frente a nodos maliciosos, control de drift, cache segura y separacion estricta entre lectura, firma y broadcast.
