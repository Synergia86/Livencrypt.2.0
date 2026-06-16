Hallazgos clave
Severidad	Problema	Riesgo
Alta	Métodos de transacción mal tipados: el parser asigna TxMethod::EthUnsupported a payloads de Bitcoin y Solana que no sean transferencias básicas. El firewall sólo rechaza EthUnsupported en Ethereum, pero usa ese mismo valor para otras cadenas; esto confunde la lógica y provoca que Bitcoin y Solana se procesen con un tipo erróneo o incluso se rechacen sin necesidad.	
Alta	Commit ignora errores: aunque el firewall devuelve Result en commit_transaction(), el supervisor manejaba mal estos errores en versiones anteriores. En la versión actual ya se comprueba, pero conviene revisarlo en todas las rutas de código para asegurarse de que no se ignoran fallos al actualizar contadores.	
Media	Chequeo de volumen mejorable: safe_volume_add sólo comprueba sumandos negativos y usa checked_add; no detecta casos en los que el resultado no es finito o sobrepasa la precisión del tipo Decimal. El informe de Zealynx recuerda que asumir decimales incorrectos en tokens ERC‑20 o manejar mal los límites puede producir pérdidas de fondos.	
Media	Uso ambiguo de u128 para cantidades: las cantidades de tokens ERC‑20 se almacenan en u128 después de verificar que los bytes de valor (uint256) caben en 128 bits. Si un contrato usa más de 128 bits, se devuelve un error genérico; podría implementarse soporte para U256 o BigInt.	
Baja	Asignación de métodos Solana como EthUnsupported: en parse_solana_gateway_payload() los métodos diferentes a "transfer" se etiquetan como EthUnsupported, cuando deberían considerarse no soportados de forma genérica o específica de Solana.	
Prompt de corrección (español)

A continuación se propone un prompt listo para Codex/OpenCode que corrige los problemas mencionados. Copia este texto en Codex/OpenCode y ejecútalo sobre el árbol real (ruta src-tui/src/crypto/blockchain). Los cambios propuestos se organizan por módulo.

Audita y corrige Livencrypt 2.0 (versión de junio 2026). Mantén los parches previos (AEAD, derivación BIP‑32/SLIP‑10, listas blancas, decimales obligatorios, `Decimal` para volumen y verificación de `chain_id`). Aplica las siguientes correcciones y pruebas unitarias.

OBJETIVOS:
1. Introducir un tipo de método genérico y por cadena para evitar etiquetar como `EthUnsupported` las transacciones de Bitcoin o Solana. 
2. Verificar y propagar errores de `commit_transaction()` en todas las rutas de firma.
3. Robustecer `safe_volume_add()` comprobando que el resultado no exceda la precisión del tipo `Decimal` ni genere valores no finitos.
4. Añadir soporte preliminar para valores ERC‑20 > 2¹²⁸ o, en su defecto, devolver un error más descriptivo. 
5. Asignar métodos Solana no reconocidos a un valor genérico `Unsupported(String)` en lugar de `EthUnsupported`.
6. Incorporar pruebas que validen estos cambios y aseguren que Bitcoin y Solana no se bloquean por un método mal etiquetado.

────────────────────────────────────────
PATCH 1 — src-tui/src/crypto/blockchain/types.rs
────────────────────────────────────────

Define una enumeración de métodos global:

```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TxMethod {
    EthTransfer,
    EthErc20Transfer,
    EthUnsupported(String),
    BtcRawTx,
    SolanaTransfer,
    Unsupported(String),
}

Modifica ParsedTx.method para usar esta variante. Documenta en comentarios que Unsupported(String) se emplea para métodos no reconocidos en cadenas no EVM.

────────────────────────────────────────
PATCH 2 — src-tui/src/crypto/blockchain/tx_parser.rs
────────────────────────────────────────

Ethereum: mantiene la lógica actual; cualquier selector desconocido sigue mappeándose a TxMethod::EthUnsupported(selector).
Bitcoin: asigna siempre TxMethod::BtcRawTx.
Solana: cambia la asignación de métodos:
let method = if method_str == "transfer" {
    TxMethod::SolanaTransfer
} else {
    TxMethod::Unsupported(method_str.to_string())
};
Soporte a valores mayores (opcional): evalúa reemplazar u128 por un tipo que acepte U256 de la crate ethereum-types. En caso de no implementarlo, actualiza bytes_to_u128_word() para devolver un error más descriptivo: "valor de token excede 128 bits; no soportado".

────────────────────────────────────────
PATCH 3 — src-tui/src/crypto/blockchain/firewall.rs
────────────────────────────────────────

Rechazar métodos no soportados genéricamente:
match parsed.method {
    TxMethod::EthUnsupported(ref sel) => {
        if parsed.chain == ChainType::Ethereum {
            return Err(format!("método de contrato Ethereum no soportado: {}", sel));
        }
    }
    TxMethod::Unsupported(ref sel) => {
        return Err(format!("método no soportado para la cadena {:?}: {}", parsed.chain, sel));
    }
    _ => {}
}
Mejorar safe_volume_add() para detectar resultados no finitos:
fn safe_volume_add(left: Decimal, right: Decimal) -> Result<Decimal, String> {
    if left.is_sign_negative() || right.is_sign_negative() {
        return Err("volumen parseado invalido".into());
    }
    let sum = left
        .checked_add(right)
        .ok_or_else(|| "desbordamiento en suma de volumen".to_string())?;
    if !sum.is_finite() {
        return Err("resultado de la suma no finito".into());
    }
    Ok(sum)
}
Propagación de errores: verifica que todos los lugares que llaman a commit_transaction() comprueban el Result. En particular, en GatewaySupervisor.run_loop_iteration(), si commit_transaction() retorna Err, devuelve ExtensionResponse::Error(err) y no procede a firmar.

────────────────────────────────────────
PATCH 4 — src-tui/src/crypto/blockchain/firewall.rs (opcional)
────────────────────────────────────────

Si se desea soportar U256, añade:

use ethereum_types::U256;

fn bytes_to_u256(bytes: &[u8]) -> Result<U256, String> { /* ... */ }

fn bytes_to_decimal(bytes: &[u8], decimals: u8) -> Result<Decimal, String> {
    let value = bytes_to_u256(bytes)?;
    // convertir U256 a Decimal evitando pérdidas de precisión
    // o retornar error si la conversión supera la capacidad de Decimal
}

Luego ajusta el parser Ethereum para usar U256 y convertir a Decimal correctamente.

────────────────────────────────────────
PATCH 5 — Pruebas unitarias (src-tui/tests/firewall.rs y tx_parser.rs)
────────────────────────────────────────

Añade pruebas:

#[test]
fn solana_unsupported_method_rejected() {
    let mut fw = LiveFirewall::default();
    fw.rules.allowed_chain_ids = vec![501];
    // transacción con método no soportado en Solana
    let parsed = ParsedTx {
        chain: ChainType::Solana,
        to_address: "sol:addr".into(),
        value_units: 1_000_000,
        volume_units: Decimal::new(1, 0),
        destinations: vec![ParsedDestination {
            address: "sol:addr".into(),
            value_units: 1_000_000,
            kind: ParsedDestinationKind::Native,
        }],
        chain_id: 501,
        method: TxMethod::Unsupported("stake_deactivate".into()),
        summary: String::new(),
    };
    assert!(fw.validate_parsed_transaction(&parsed).is_err());
}

#[test]
fn bitcoin_parsed_correctly() {
    // verifica que BtcRawTx no sea tratado como EthUnsupported
    // y que no se rechace por método
}

#[test]
fn safe_volume_add_detects_nonfinite() {
    use rust_decimal_macros::dec;
    // suma que produce overflow para comprobar error
    assert!(safe_volume_add(Decimal::MAX, dec!(1)).is_err());
}

────────────────────────────────────────
Instrucciones finales:

Aplica los cambios y ejecuta:

cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
Asegúrate de que todos los tests, incluidos los nuevos, pasen.
Documenta en comentarios que las IV deben generarse de forma aleatoria y segura, tal y como recomienda la guía en el PDF revisado.

Este prompt aborda los errores aún presentes: homogeneiza el manejo de métodos por cadena, refuerza el control de volumen, mejora la gestión de errores y prepara el sistema para valores de tokens grandes. Así se reduce la superficie de ataque y se mejora la resiliencia de la billetera multi‑cadena.
