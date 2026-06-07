he identificado algunos problemas adicionales que podrían comprometer la seguridad o generar fallos lógicos. También se han detectado incoherencias menores que conviene resolver.

Principales problemas detectados en v9
Uso de EthereumMethod::UnsupportedMethod para Bitcoin y Solana.
El parser asigna EthereumMethod::UnsupportedMethod("raw_tx_outputs") a cualquier transacción Bitcoin y EthereumMethod::UnsupportedMethod(method_str) a cualquier transferencia Solana. El firewall rechaza todas las transacciones con UnsupportedMethod sin comprobar la cadena. Como consecuencia, ninguna operación Bitcoin ni Solana pasa el cortafuegos, impidiendo su uso. Esto parece un error de diseño; debería existir un tipo de método genérico por cadena (por ejemplo, BtcRawTx, SolanaTransfer) o, al menos, que el cortafuegos sólo rechace métodos no reconocidos para Ethereum.
Posibles desbordamientos o pérdidas de precisión en el cálculo del volumen.
Aunque safe_volume_add usa Decimal, únicamente comprueba que los sumandos no sean negativos. No detecta sumas que sobrepasen los límites de Decimal, ni NaN o valores infinitos. El informe de Zealynx destaca que asumir decimales incorrectos en tokens ERC‑20 provoca cálculos erróneos y pérdidas de fondos. Es recomendable proteger safe_volume_add contra sumas excesivas o resultados no finitos.
Dependencia de value_units como u128 para valores ERC‑20 y nativos.
Los tokens ERC‑20 utilizan enteros de 256 bits; al convertirlos a u128 se truncan los bits superiores, pudiendo dar lugar a valores falsos o underflows cuando el valor supera 2^128. Aunque poco probable en tokens corrientes, conviene soportar cantidades mayores o al menos detectar el truncado.
Falta de validación específica para Solana y Bitcoin.
Para Solana se acepta cualquier cadena method de la entrada JSON. No hay validaciones de décimas de lamports o límites máximos. Las transacciones con lamports gigantes o métodos no soportados podrían pasar a la lógica del firewall, aunque después se rechacen por UnsupportedMethod. Igualmente, el parser de Bitcoin sólo comprueba script_len <= 10 000, pero no establece un límite al número total de salidas ni verifica el tipo de dirección.
Prompt para Codex/OpenCode con parches concretos

A continuación se detalla un prompt listo para aplicar que corrige estos problemas de manera integral. Debe ejecutarse en el árbol real de Rust (src-tui/src/*).

Audita y corrige Livencrypt 2.0 (versión 9). Mantén las mejoras anteriores (AEAD, derivación BIP‑32/SLIP‑0010, listas blancas, token_decimals, `Decimal`, chain_id) y aplica cambios atómicos para resolver los problemas restantes.

OBJETIVOS:
1. **Separar los métodos por cadena y evitar rechazos erróneos.**  
   Crea una enumeración `TxMethod` en `src-tui/src/crypto/blockchain/types.rs` con variantes:  
   ```rust
   #[derive(Serialize, Deserialize, Clone, Debug)]
   pub enum TxMethod {
       EthTransfer,
       EthErc20Transfer,
       EthUnsupported(String),
       BtcRawTx,
       SolanaTransfer,
   }

Cambia ParsedTx.method a TxMethod. Actualiza los parsers para asignar:

EthTransfer o EthErc20Transfer en Ethereum.
BtcRawTx en Bitcoin.
SolanaTransfer en Solana, usando method del JSON si es "transfer" y TxMethod::EthUnsupported en caso contrario.
Ajusta LiveFirewall::validate_parsed_transaction() para que sólo rechace transacciones con TxMethod::EthUnsupported si la cadena es Ethereum. Las transacciones Bitcoin (BtcRawTx) y Solana (SolanaTransfer) no se rechazan sólo por el método.
Añadir comprobaciones en safe_volume_add.
En src-tui/src/crypto/blockchain/firewall.rs, modifica safe_volume_add para comprobar que left + right no desborda Decimal, no genera NaN ni un valor infinito. Si se detecta un resultado no finito, devuelve un error (“suma de volumen no válida”). Esto garantiza que los límites diarios no se eludan por saturación o precisión limitada, siguiendo la recomendación de no suponer decimales fijos en tokens.
Detectar valores ERC‑20 superiores a 128 bits.
En tx_parser.rs, cambia value_units de u128 a ethereum_types::U256 o, si se desea mantener Decimal, convierte de U256 a Decimal con manejo de overflow. Si no se puede representar la cantidad con precisión, devuelve un error (“valor de token demasiado grande”). Esto evita truncado silencioso.
Validar transacciones Solana y Bitcoin.
Para Solana (parse_solana_gateway_payload), restringe el campo method a "transfer". Si se recibe otro valor, asigna TxMethod::EthUnsupported(method) y deja que el firewall lo rechace. También establece un límite máximo razonable de lamports (por ejemplo, 10^14) para proteger contra saturación.
Para Bitcoin (parse_bitcoin_payload), añade un límite total al número de salidas (por ejemplo 50) y verifica que cada dirección generada por bitcoin_script_destination sea de un formato soportado (p2pkh, p2wpkh o similar). Rechaza scripts de tipos desconocidos.
Pruebas unitarias.
Escribe pruebas en firewall.rs y tx_parser.rs que verifiquen:
Bitcoin y Solana no se rechazan sólo por tener UnsupportedMethod.
safe_volume_add devuelve error si la suma produce un valor no finito.
Se detecta y rechaza un value_units mayor de 128 bits.
Se rechaza un método Solana diferente a "transfer".
Se rechaza un Bitcoin con más de 50 salidas o con dirección no soportada.

Ejecuta después:

cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
./target/release/livencrypt-core --self-test-safe
./target/release/livencrypt-core --hardening-check

Asegura que todos los tests (incluidos los nuevos) pasen.


### Justificación de los cambios

- **Separar los métodos por cadena evita rechazar transacciones válidas**: actualmente, Bitcoin y Solana se interpretan como `EthereumMethod::UnsupportedMethod`, lo que provoca que el cortafuegos rechace todas sus operaciones. Distinguir `BtcRawTx` y `SolanaTransfer` permite aplicar reglas específicas y evita esta falsa alarma.

- **Comprobaciones adicionales de volumen y decimales**: los auditores advierten que asumir 18 decimales en tokens ERC‑20 o permitir cálculos imprecisos con `f64` o incluso con `Decimal` puede causar pérdidas de fondos:contentReference[oaicite:2]{index=2}. Extender `safe_volume_add` y detectar grandes cantidades protege contra ataques de saturación y errores de cálculo.

- **Verificar chain ID y métodos específicos**: la literatura sobre replay attacks indica que siempre debe comprobarse el chain ID y limitar los métodos a los admitidos:contentReference[oaicite:3]{index=3}. Al diferenciar los métodos, el cortafuegos conserva la protección contra replays sin bloquear transacciones de cadenas distintas.

Con estas correcciones, Livencrypt mejora la compatibilidad multi‑cadena y elimina varias incoherencias lógicas, reduciendo la superficie de ataque y cumpliendo con las mejores prácticas de seguridad.
