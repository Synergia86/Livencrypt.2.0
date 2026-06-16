in embargo siguen existiendo problemas de diseño y riesgos de seguridad que conviene solucionar. A continuación se resume la auditoría y se propone un prompt con parches concretos.

Hallazgos clave
Severidad	Problema	Riesgo
Alta	Tokens ERC‑20 sin decimales registrados: aunque la lógica del firewall permite asignar decimales por contrato, en la práctica se usa un valor por defecto (18) cuando un token no figura en el mapa token_decimals. Asumir 18 decimales puede causar errores en la conversión de unidades y abre la puerta a transferencias fraudulentas; auditores independientes alertan de que muchos tokens usan 6 u 8 decimales y suponer 18 puede generar pérdidas o quemas incorrectas.	Un atacante podría registrar un token con 6 decimales como autorizado pero omitir sus decimales en la configuración; el firewall trataría 10 millones de unidades como 0,01 unidades y permitiría transferencias grandes sin rebasar el límite.
Media	Uso de f64 para el volumen: todo el cálculo de volume_units se realiza con f64. Esto introduce pérdidas de precisión para cantidades grandes y decimales finos y facilita desbordamientos o saturaciones erróneas.	Con transacciones muy grandes (por ejemplo, múltiples BTC o billones de satoshis) el valor acumulado podría perder precisión o saturarse a infinito, provocando rechazos injustificados o pasando inadvertido el rebasamiento.
Media	Llamadas a contratos Ethereum no reconocidas: parse_ethereum_payload() sólo reconoce el selector de transferencia estándar ERC‑20 (0xa9059cbb); cualquier otra llamada a contratos (por ejemplo, transferFrom, approve o un swap()) se clasifica como “native” y se valida solo por la dirección. El firewall no comprueba que el método sea seguro.	Permite firmar interacciones con contratos autorizados (DEX/CEX) usando funciones desconocidas que podrían transferir tokens o ETH de manera inesperada.
Baja	Commit sin manejo de error: commit_transaction() acumula el volumen diario usando safe_volume_add, pero ignora cualquier Err. Una saturación o valor no finito en el volumen diario no se registra como error.	Podría llevar a registros inconsistentes o permitir que el contador de volumen no se actualice tras un overflow.
Prompt para Codex/OpenCode (español)

Copia y pega el siguiente texto en Codex/OpenCode para aplicar las correcciones necesarias. Las instrucciones están organizadas por módulos y deben ejecutarse sobre el árbol real (src-tui/src/*).

Audita y corrige Livencrypt 2.0 (junio 2026) en Rust. Trabaja sobre el árbol real (no los .txt) y mantiene las mejoras previas (AEAD, derivación BIP‑32/SLIP‑10, sanitización de plantillas, sockets en XDG_RUNTIME_DIR, separación de referencia y clave de archivo). Aplica parches pequeños y verificables.

OBJETIVOS:
1) Obligar a registrar los decimales de cada contrato ERC‑20 autorizado; rechazar cualquier transferencia de tokens cuyo contrato no figure en `token_decimals` para evitar suponer 18 decimales:contentReference[oaicite:1]{index=1}.  
2) Sustituir `f64` por un tipo de precisión arbitraria (`rust_decimal::Decimal`) para `volume_today_units`, `max_daily_volume_units` y cálculos de volumen. Comprobar que el volumen nunca se vuelve `NaN` ni infinito y que no hay desbordamientos.  
3) Clasificar las llamadas de contrato Ethereum no reconocidas como `UnsupportedMethod` y rechazarlas en el firewall a menos que exista una regla específica. A corto plazo, permitir sólo llamadas `transfer()` y `erc20_transfer()`.  
4) Propagar errores en `commit_transaction()` y registrar mensajes cuando no pueda acumularse el volumen.  
5) Añadir pruebas que verifiquen el rechazo de tokens sin decimales registrados, el cálculo exacto del volumen con `Decimal`, el rechazo de métodos desconocidos y el manejo de errores en `commit_transaction()`.

────────────────────────────────────────
PATCH 1 — src-tui/src/crypto/blockchain/types.rs
────────────────────────────────────────

Reemplaza `max_daily_volume_units` y `volume_today_units` de `f64` por `Decimal` y añade una enumeración para métodos Ethereum soportados.

```rust
use rust_decimal::Decimal;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum EthereumMethod {
    Transfer,
    Erc20Transfer,
    UnsupportedMethod(String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FirewallRules {
    pub max_daily_tx: u32,
    pub max_daily_volume_units: Decimal,
    pub allowed_dex_contracts: Vec<String>,
    pub allowed_cex_destinations: Vec<String>,
    pub allowed_erc20_contracts: Vec<String>,
    pub allowed_chain_ids: Vec<u64>,
    pub token_decimals: std::collections::HashMap<String, u8>,
    pub require_token_registration: bool,
}

Actualiza la implementación de Default inicializando max_daily_volume_units con Decimal::new(10, 0) (equivale a 10).

────────────────────────────────────────
PATCH 2 — src-tui/src/crypto/blockchain/tx_parser.rs
────────────────────────────────────────

Modifica ParsedTx para que volume_units sea Decimal y method sea de tipo EthereumMethod. Cambia parse_ethereum_payload() así:

use rust_decimal::Decimal;

fn parse_ethereum_payload(raw: &[u8]) -> Result<ParsedTx, String> {
    // ... código existente para extraer chain_id, to, value y data ...

    // Reconocer sólo transferencia ETH y transfer() ERC20
    let (to_address, value_units, destinations, method) =
        if data.starts_with(&[0xa9, 0x05, 0x9c, 0xbb]) && data.len() >= 68 {
            // ERC-20 transfer(address,uint256)
            // ...
            (
                token_receiver.clone(),
                amount,
                vec![
                    ParsedDestination {
                        address: contract_or_to.clone(),
                        value_units: 0,
                        kind: ParsedDestinationKind::Erc20Contract,
                    },
                    ParsedDestination {
                        address: token_receiver,
                        value_units: amount,
                        kind: ParsedDestinationKind::Erc20Receiver,
                    },
                ],
                EthereumMethod::Erc20Transfer,
            )
        } else if data.is_empty() {
            (
                contract_or_to.clone(),
                value,
                vec![ParsedDestination {
                    address: contract_or_to.clone(),
                    value_units: value,
                    kind: ParsedDestinationKind::Native,
                }],
                EthereumMethod::Transfer,
            )
        } else {
            (
                contract_or_to.clone(),
                value,
                vec![ParsedDestination {
                    address: contract_or_to.clone(),
                    value_units: value,
                    kind: ParsedDestinationKind::Native,
                }],
                EthereumMethod::UnsupportedMethod(format!("0x{}", hex::encode(&data[..4]))),
            )
        };

    let summary = match &method {
        EthereumMethod::Transfer => format!("transferencia_eth to={} value={}", to_address, value_units),
        EthereumMethod::Erc20Transfer => format!("erc20_transfer contrato={} value={}", contract_or_to, value_units),
        EthereumMethod::UnsupportedMethod(sel) => format!("unsupported_method {} to={} value={}", sel, contract_or_to, value_units),
    };

    Ok(ParsedTx {
        chain: ChainType::Ethereum,
        to_address,
        value_units,
        volume_units: Decimal::ZERO, // se calcula más tarde
        destinations,
        chain_id,
        method,
        summary,
    })
}

Haz que parse_bitcoin_payload() y parse_solana_gateway_payload() devuelvan volume_units como Decimal usando conversiones: Decimal::from(value_units) / Decimal::new(10i64.pow(decimals), 0).

────────────────────────────────────────
PATCH 3 — src-tui/src/crypto/blockchain/firewall.rs
────────────────────────────────────────

Cambia volume_today_units a Decimal. En validate_parsed_transaction():

Usa el chain_id de ParsedTx como hasta ahora.
Convierte el volumen efectivo a Decimal con effective_volume_units() (que ahora devuelve Decimal).
Rechaza ParsedTx con method == EthereumMethod::UnsupportedMethod(..) retornando error: “método de contrato Ethereum no soportado”.

Actualiza commit_transaction() para aceptar Decimal y propagar cualquier error:

pub fn commit_transaction(&mut self, estimated_volume_units: Decimal) -> Result<(), String> {
    self.tx_count_today = self.tx_count_today.saturating_add(1);
    self.volume_today_units = safe_volume_add(self.volume_today_units, estimated_volume_units)?;
    Ok(())
}

La función safe_volume_add() ahora debe recibir y devolver Decimal y comprobar que el resultado es finito (usa result.is_sign_negative() o result.is_zero() para detectar anomalías).

────────────────────────────────────────
PATCH 4 — src-tui/src/crypto/blockchain/tx_parser.rs (funciones auxiliares)
────────────────────────────────────────

Reemplaza native_units() y token_units() por versiones que devuelvan Decimal. Por ejemplo:

use rust_decimal::prelude::*;

fn native_units(chain: ChainType, value_units: u128) -> Decimal {
    match chain {
        ChainType::Ethereum => Decimal::from(value_units) / Decimal::from(1_000_000_000_000_000_000u128),
        ChainType::Bitcoin  => Decimal::from(value_units) / Decimal::from(100_000_000u64),
        ChainType::Solana   => Decimal::from(value_units) / Decimal::from(1_000_000_000u64),
        ChainType::Monero   => Decimal::from(value_units),
    }
}

fn token_units(value_units: u128, decimals: u8) -> Decimal {
    Decimal::from(value_units) / Decimal::from(10u128.pow(u32::from(decimals)))
}

Actualiza effective_volume_units() para devolver Decimal y utilizar estas funciones.

────────────────────────────────────────
PATCH 5 — src-tui/src/crypto/blockchain/firewall.rs (manejo de métodos)
────────────────────────────────────────

Añade el rechazo de métodos no soportados:

match &parsed.method {
    EthereumMethod::UnsupportedMethod(sel) => {
        return Err(format!("método de contrato Ethereum no soportado: {}", sel));
    }
    _ => {}
}

────────────────────────────────────────
PATCH 6 — Tests
────────────────────────────────────────

Escribe nuevas pruebas:

rejects_transfer_without_registered_decimals(): crea una transacción ERC‑20 con require_token_registration = true y sin registrar decimales; debe ser rechazada.
uses_decimal_for_volume() verifica que sumar 0,1 + 0,2 produce 0,3 exacto con Decimal.
rejects_unsupported_method() crea un ParsedTx con method = UnsupportedMethod("0xabcdef00".into()) y confirma que validate_parsed_transaction() devuelve un error.
commit_transaction_propagates_error() verifica que, si safe_volume_add() devuelve error, commit_transaction() también retorna Err.

────────────────────────────────────────
DOCUMENTACIÓN
────────────────────────────────────────

Actualiza los comentarios en el firewall y en el parser explicando por qué es peligroso asumir 18 decimales y por qué se debe verificar el chain ID para evitar replays cross‑chain. Indica que sólo se admiten métodos conocidos (transfer y erc20_transfer) y que cualquier otro se rechaza por defecto.

────────────────────────────────────────
COMPROBACIÓN FINAL
────────────────────────────────────────

Después de aplicar los parches, ejecuta:

cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
./target/release/livencrypt-core --self-test-safe
./target/release/livencrypt-core --hardening-check

Todos los tests (incluidos los nuevos) deben pasar y el volumen debe acumularse sin pérdidas de precisión.


La aplicación de estos cambios elimina las presunciones de 18 decimales en tokens ERC‑20, endurece la validación de métodos en llamadas a contratos, evita pérdidas de precisión al calcular volúmenes y se ajusta a las recomendaciones de no confiar en parámetros externos ni en flujos de “blind signing”:contentReference[oaicite:4]{index=4}:contentReference[oaicite:5]{index=5}.
