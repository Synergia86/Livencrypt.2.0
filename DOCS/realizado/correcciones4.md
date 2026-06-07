Vulnerabilidades y errores restantes
Transacciones Bitcoin con múltiples salidas.
El parser parse_bitcoin_payload() sólo analiza la primera salida (first_destination) y su valor. Una transacción puede añadir salidas adicionales a direcciones no autorizadas; el firewall la aprobará porque la primera salida es legítima. Esto permite evadir el control de destino y de volumen. Se debería analizar todas las salidas y rechazar la firma si cualquiera va a un destino no autorizado, o sumar el valor de todas las salidas para el límite diario.
Límites de volumen incoherentes.
El firewall calcula volume_today_usd sumando directamente los valores de value_units (wei, satoshis o lamports), comparándolos con max_daily_volume_usd como si fueran dólares. En Ethereum, 1 ETH = 1e18 wei; la transferencia de 1 ETH se contabilizaría como 1e18 USD, excediendo siempre el límite y bloqueando todas las transacciones. Debería:
Convertir value_units a la unidad nativa adecuada (ETH, BTC, SOL) usando divisores fijos (1e18, 1e8, 1e9) y compararlos con un nuevo umbral max_daily_volume_units, o
Requerir que la aplicación obtenga una estimación de valor en USD antes de validar el volumen, pero no confiar en valores enviados por la extensión (principio de “blind‑signing”).
Transacciones con token-contracts.
parse_ethereum_payload() sólo examina el campo value y el primer selector de método. No interpreta transferencias de tokens ERC‑20; una llamada transfer(address,uint256) con value=0 puede mover tokens a un destino no autorizado sin activar el límite de volumen. Es necesario analizar data para extraer el valor de tokens y considerar el contrato real como destino.
Pruebas de self‑test usan la referencia como clave de archivo.
Aunque la TUI obliga a usar una clave de archivo distinta de la referencia, el test safe_test_file_cipher sigue cifrando y descifrando con DEFAULT_FILE_REFERENCE para ambos campos. Esto no reproduce el uso real ni detectaría errores si el código volviera a aceptar referencias como clave.
Prompt para Codex/OpenCode (en español)

El siguiente prompt incluye cambios concretos para corregir las vulnerabilidades descritas. Pégalo en Codex/OpenCode y ejecútalo sobre el árbol del proyecto Rust:

Audita y corrige Livencrypt 2.0 en Rust. Trabaja en el árbol real (src-tui/src/*). Aplica parches pequeños y verificables, manteniendo las mejoras ya implementadas (AEAD, semilla XOR derivada, sanitización de plantillas, sockets en XDG_RUNTIME_DIR y scripts seguros).

OBJETIVOS PENDIENTES:
1) **Evitar transacciones Bitcoin con salidas no autorizadas**: modifica `parse_bitcoin_payload()` para leer *todas* las salidas, construir una lista de destinos y su valor en satoshis, y devolverla en `ParsedTx`. El firewall (`validate_parsed_transaction()`) debe comprobar que **todas** las direcciones están en `allowed_dex_contracts` o `allowed_cex_destinations` y sumar sus valores. Si alguna no está autorizada, rechazar la transacción y registrar el fallo. Ajusta `commit_transaction()` para sumar el valor total de satoshis en `volume_today_units` (ver punto 2).

2) **Normalizar volumen diario**: sustituye `max_daily_volume_usd` y `volume_today_usd` por `max_daily_volume_units` y `volume_today_units`. Para Ethereum, divide `value_units` entre `1e18` para obtener ETH; para Bitcoin divide entre `1e8` y para Solana entre `1e9`. Suma estas unidades (no USD) a `volume_today_units` y compara con `max_daily_volume_units` definido en la configuración. No vuelvas a confiar en un campo `value_usd` de la extensión, porque firmar sin verificar el valor real expone a ataques de “blind signing”:contentReference[oaicite:4]{index=4}.

3) **Analizar transferencias ERC‑20**: amplía `parse_ethereum_payload()` para detectar si `data` comienza con el selector `0xa9059cbb` (`transfer(address,uint256)`). Extrae la dirección de destino y la cantidad de tokens (uint256), conviértela a `u128` y utilízala como `value_units`. Marca el método como `erc20_transfer` e incluye el contrato destinatario (`to` original) y el nuevo destinatario (del payload) en `ParsedTx`. En el firewall, comprueba el contrato y la dirección final con las listas permitidas.

4) **Actualizar self‑test**: modifica `safe_test_file_cipher()` para usar una clave de archivo distinta de la referencia, por ejemplo añadiendo una constante `DEFAULT_FILE_SECRET` y pasando ese valor a `cipher_file_with_secret()` y `decipher_file_with_secret()`. Añade un test que falle si `reference` y `file_secret` son iguales. Esto mantiene la separación de secretos y previene errores de regresión.

5) **Documentar cambios**: añade comentarios en el código indicando por qué se analizan todas las salidas en Bitcoin, por qué se normalizan los valores y por qué se valida cada salida/destino. Cita brevemente la recomendación de evitar IVs predecibles:contentReference[oaicite:5]{index=5} y los riesgos de blind signing:contentReference[oaicite:6]{index=6}.

Después de estos cambios, ejecuta `cargo fmt`, `cargo clippy -- -D warnings` y `cargo test --locked` para asegurar que todo compila y los tests pasan. Asegúrate de añadir nuevas pruebas unitarias que verifiquen que:
- Se rechaza una transacción Bitcoin con múltiples salidas si una está fuera de la lista permitida.
- El volumen diario se cuenta en unidades normales (ETH, BTC o SOL) y no se desborda con wei o satoshis.
- El parser Ethereum detecta y procesa transferencias ERC‑20.


Este prompt orienta las correcciones necesarias para cerrar los vectores de ataque detectados, respetando las normas de criptografía segura (semillas y IVs impredecibles) y de validación contextual al firmar transacciones.
