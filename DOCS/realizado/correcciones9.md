los principales problemas detectados y presento un prompt listo para Codex/OpenCode que incorpora cambios concretos y pruebas unitarias para solucionarlos.

Principales hallazgos
Severidad	Problema	Riesgo
Alta	Commit ignora errores: GatewaySupervisor.run_loop_iteration() llama a self.firewall.commit_transaction(effective_volume) sin capturar el Result. Si safe_volume_add devuelve un error (por ejemplo, volumen negativo o infinito), la transacción se marca como firmada pese a que el firewall no actualizó los contadores.	Posibilidad de firmar operaciones que superan los límites diarios o contadores inconsistentes.
Alta	Inconsistencia de tipos en ParsedTx: ParsedTx.method se define como String, pero el firewall lo interpreta como EthereumMethod (enumeración). Esta discrepancia puede provocar compilación errónea o, si se usa String, no se detectan métodos no soportados.	Llamadas a contratos Ethereum desconocidos podrían pasar desapercibidas y comprometer fondos.
Media	Uso residual de f64 en ParsedTx.volume_units: aunque el firewall utiliza Decimal, el parser sigue devolviendo f64 en volume_units, que puede sufrir pérdidas de precisión.	Riesgo de evasión de límites por redondeos o errores de conversión.
Baja	Token no registrado tratado como 18 decimales: effective_volume_units aplica 18 decimales por defecto cuando no se encuentra el token y require_token_registration es false. OWASP advierte que asumir 18 decimales puede causar errores graves.	Desbordamiento de límites de volumen si un token tiene 6 u 8 decimales y no está registrado.
Baja	Longitud de script de Bitcoin ilimitada: parse_bitcoin_payload acepta cualquier longitud de script_len; un atacante podría enviar scripts extremadamente grandes para agotar memoria.	DoS al parser.
Prompt de corrección (español)

Copia este texto en Codex/OpenCode; contiene los parches y las pruebas necesarias. Ajusta rutas si difieren.

Audita y corrige Livencrypt 2.0 (versión 8) en Rust. Trabaja sobre los archivos reales bajo `src-tui/src/crypto/blockchain`. Mantén las mejoras previas (AEAD, derivación BIP‑32/SLIP‑10, sanitización de plantillas, separación de secretos). Realiza cambios mínimos pero seguros:

OBJETIVOS:
1. **Propagar errores de `commit_transaction()`**: en `GatewaySupervisor.run_loop_iteration()`, si `commit_transaction()` retorna `Err`, cancela la firma y devuelve `ExtensionResponse::Error`. No ignores el `Result`.
2. **Unificar tipo `ParsedTx`**: cambia `ParsedTx.method` a la enumeración `EthereumMethod` y `volume_units` a `Decimal`. Ajusta los parsers para que devuelvan este tipo y el firewall para que haga `match` sobre `EthereumMethod`. Rechaza explícitamente cualquier `UnsupportedMethod`.
3. **Corrección de decimales y tokens no registrados**: obliga a que `require_token_registration` sea `true` por defecto y elimina el valor por defecto de 18 decimales cuando falta registro:contentReference[oaicite:1]{index=1}. Si un token ERC‑20 no está en `token_decimals`, devuelve un error.
4. **Limitar tamaño de scripts de Bitcoin**: en `parse_bitcoin_payload()`, limita `script_len` a un máximo (por ejemplo, 10 000 bytes) y rechaza scripts más grandes para evitar DoS.
5. **Actualizar pruebas**: añade tests que verifiquen los cambios:  
   - Se cancela la firma si `commit_transaction()` devuelve error.  
   - `ParsedTx.method` detecta correctamente `UnsupportedMethod` y el firewall rechaza la transacción.  
   - Un token ERC‑20 sin registro de decimales es rechazado.  
   - Se rechaza una transacción Bitcoin con `script_len` superior al máximo permitido.

────────────────────────────────────────
PATCH 1 — src-tui/src/crypto/blockchain/worker.rs
────────────────────────────────────────

Dentro de `run_loop_iteration()`, propaga el resultado de `commit_transaction()`:

```rust
// Antes: self.firewall.commit_transaction(effective_volume);
if let Err(err) = self.firewall.commit_transaction(effective_volume) {
    return serde_json::to_vec(&ExtensionResponse::Error(err)).map_err(|e| e.to_string());
}
// Solo firmar si no hay error:
ExtensionResponse::Success(signature)

────────────────────────────────────────
PATCH 2 — src-tui/src/crypto/blockchain/tx_parser.rs
────────────────────────────────────────

Cambia ParsedTx:
pub struct ParsedTx {
    pub chain: ChainType,
    pub to_address: String,
    pub value_units: u128,
    pub volume_units: Decimal,
    pub destinations: Vec<ParsedDestination>,
    pub chain_id: u64,
    pub method: EthereumMethod,
    pub summary: String,
}
En parse_ethereum_payload(), devuelve EthereumMethod:
let method = if data.starts_with(&[0xa9,0x05,0x9c,0xbb]) && data.len() >= 68 {
    EthereumMethod::Erc20Transfer
} else if data.is_empty() {
    EthereumMethod::Transfer
} else {
    EthereumMethod::UnsupportedMethod(format!("0x{}", hex::encode(&data[..4])))
};
...
Ok(ParsedTx {
    chain: ChainType::Ethereum,
    to_address,
    value_units,
    // volumen se rellena con Decimal::ZERO; se calcula en effective_volume_units()
    volume_units: Decimal::ZERO,
    destinations,
    chain_id,
    method,
    summary,
})
En parse_bitcoin_payload() y parse_solana_gateway_payload(), cambia volume_units a Decimal usando native_units() (ya devuelve Decimal). Limita script_len:
let script_len = reader.read_varint()?;
if script_len > 10_000 { return Err("script Bitcoin demasiado largo".into()); }
reader.take_usize(script_len)?;

────────────────────────────────────────
PATCH 3 — src-tui/src/crypto/blockchain/firewall.rs
────────────────────────────────────────

Ajusta validate_parsed_transaction() para el nuevo tipo:
match parsed.method {
    EthereumMethod::UnsupportedMethod(ref sel) => {
        return Err(format!("método de contrato Ethereum no soportado: {}", sel));
    }
    _ => {}
}
En effective_volume_units(), elimina la rama None => 18 y devuelve error si require_token_registration es true y el token no está registrado. Usa Decimal consistentemente.

────────────────────────────────────────
PATCH 4 — src-tui/src/crypto/blockchain/types.rs
────────────────────────────────────────

Asegúrate de que require_token_registration se inicialice a true en FirewallRules::default(). Documenta que no se asumen 18 decimales.

────────────────────────────────────────
PATCH 5 — src-tui/tests/firewall.rs
────────────────────────────────────────

Añade pruebas:

#[test]
fn commit_transaction_error_aborts() {
    let mut fw = LiveFirewall::default();
    fw.rules.max_daily_volume_units = Decimal::new(1, 0); // 1 unidad
    // Simula volumen de 2 unidades
    let result = fw.commit_transaction(Decimal::new(2,0));
    assert!(result.is_err());
}

// Token sin registro
#[test]
fn erc20_without_registration_rejected() {
    let mut fw = LiveFirewall::default();
    fw.rules.allowed_chain_ids = vec![1];
    fw.rules.allowed_erc20_contracts = vec!["0xToken".into()];
    // require_token_registration = true
    // no token_decimals para 0xToken
    let parsed = ParsedTx { /* llena con metodo Erc20Transfer ... */ };
    assert!(fw.validate_parsed_transaction(&parsed).is_err());
}

// Método no soportado
#[test]
fn unsupported_method_is_rejected() {
    let mut fw = LiveFirewall::default();
    fw.rules.allowed_chain_ids = vec![1];
    let parsed = ParsedTx { method: EthereumMethod::UnsupportedMethod("0x12345678".into()), /* ... */ };
    assert!(fw.validate_parsed_transaction(&parsed).is_err());
}

// Script Bitcoin demasiado largo
#[test]
fn bitcoin_script_too_long_rejected() {
    let raw = vec![ /* construye transacción con script_len > 10000 */ ];
    assert!(parse_bitcoin_payload(&raw).is_err());
}

────────────────────────────────────────
INSTRUCCIONES FINALES
────────────────────────────────────────

Tras aplicar los parches ejecuta:

cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked

Asegúrate de que todo compile y los tests pasen. Documenta en comentarios que la verificación del chain ID es esencial para prevenir replays cross‑chain y que no deben asumirse 18 decimales para tokens.


Estos cambios corrigen la omisión del resultado de `commit_transaction()`, unifican el tratamiento de métodos y volúmenes, rechazan tokens ERC‑20 no registrados y previenen scripts de Bitcoin excesivamente grandes. Con ello se reduce la superficie de ataque y se mejora la fiabilidad del firewall.
