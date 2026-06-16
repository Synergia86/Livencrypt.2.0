todavía quedan riesgos que conviene mitigar:

El firewall no verifica el chain_id de las transacciones firmadas. Los artículos de seguridad recomiendan usar firmas específicas de cadena (EIP‑155) e incluir el chain_id en la verificación para impedir ataques de replay entre redes.
El parser de Ethereum asume que todos los tokens ERC‑20 tienen 18 decimales (divide la cantidad entre 1e18). Muchos tokens usan 6 u 8 decimales; de ese modo, un atacante podría transferir millones de unidades de un token con pocos decimales sin superar el límite diario.
Se usa f64 para acumular volume_units. Con valores grandes (por ejemplo, transacciones de muchos tokens o de satoshis) podría perderse precisión o desbordar, permitiendo eludir el control de volumen.
No existe un mapeo para comprobar que las transferencias ERC‑20 (contrato) pertenezcan a tokens autorizados ni para conocer sus decimales.

A continuación se proporciona un prompt listo para Codex/OpenCode en español con parches concretos que corrigen estos vectores de ataque manteniendo los cambios ya aplicados. Copia y ejecuta este prompt sobre el árbol real del proyecto (src‑tui/src/*).

Audita y corrige Livencrypt 2.0 en Rust. Trabaja sobre el árbol real (no sobre .txt). Aplica cambios atómicos y seguros, manteniendo las mejoras existentes (AEAD, semilla XOR derivada, sanitización de nombres, sockets en XDG_RUNTIME_DIR, script postremove seguro).

OBJETIVOS:
1) **Verificar chain_id**: añadir `allowed_chain_ids` en `FirewallRules` (p. ej. `[1]` para Ethereum mainnet, `[0]` para Bitcoin, `[501]` para Solana). En `LiveFirewall::validate_parsed_transaction()` comprueba que, si `parsed.chain_id` es `Some(id)`, este valor está presente en `allowed_chain_ids` para la cadena correspondiente; en caso contrario, devuelve un error (“chain_id no autorizado, posible replay cross‑chain”). Esto evita ataques de replay entre redes:contentReference[oaicite:2]{index=2}.
2) **Soporte de decimales para tokens ERC‑20**: extiende `FirewallRules` con un nuevo mapa `token_decimals: HashMap<String, u8>` donde la clave es la dirección del contrato y el valor son sus decimales. En `parse_ethereum_payload()`, cuando detectes `erc20_transfer`, lee el campo de decimales de `token_decimals` (si no existe, usa 18 por defecto). Calcula `volume_units` como `amount / 10^decimales`. Incluye en `ParsedDestination` la dirección del contrato y del destinatario. Añade un test de que transferir 1000000 unidades de un token con 6 decimales produce `volume_units=1.0`.
3) **Ajustar acumulación de volumen en tipo seguro**: cambia `volume_today_units` y `max_daily_volume_units` de `f64` a `Decimal` o `f64` controlado. Puedes usar el crate `rust_decimal` para sumar volúmenes sin pérdida de precisión; de lo contrario, valida que `parsed.volume_units` no sea `NaN` ni `Infinite` antes de acumularlo. Usa saturación (`saturating_add`) para evitar desbordamientos.
4) **Verificar contratos de tokens autorizados**: añade un nuevo campo `allowed_erc20_contracts` en `FirewallRules`. En `validate_parsed_transaction()`, para cada destino de tipo “erc20_transfer”, comprueba que la primera dirección (contrato) está en `allowed_erc20_contracts`. Si no, rechaza (“contrato ERC‑20 no autorizado”). Esto complementa las listas blancas de DEX y CEX.
5) **Mantener separación de secretos**: refuerza las pruebas unitarias asegurando que `DEFAULT_FILE_SECRET` sea distinto de `DEFAULT_FILE_REFERENCE`. Añade un test que falle si se pasa la misma cadena a ambos parámetros.
6) **Documentar cambios**: en `tx_parser.rs`, documenta que se dividen cantidades según decimales definidos y se verifican todas las salidas y contratos. Añade comentarios en `firewall.rs` explicando que se valida el `chain_id` para prevenir ataques de replay:contentReference[oaicite:3]{index=3} y que no se utiliza `value_usd` de la extensión porque se considera “blind signing” inseguro:contentReference[oaicite:4]{index=4}.

PATCH 1 — src-tui/src/crypto/blockchain/types.rs
-------------------------------------------------

Añade:

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FirewallRules {
    pub max_daily_tx: u32,
    pub max_daily_volume_units: Decimal,  // usar rust_decimal
    pub allowed_dex_contracts: Vec<String>,
    pub allowed_cex_destinations: Vec<String>,
    pub allowed_erc20_contracts: Vec<String>,
    pub allowed_chain_ids: Vec<u64>,
    pub token_decimals: std::collections::HashMap<String, u8>,
}

Ajusta Default para inicializar los nuevos campos.

PATCH 2 — src-tui/src/crypto/blockchain/firewall.rs
Cambia volume_today_units y max_daily_volume_units a Decimal (usa rust_decimal::Decimal).
En validate_parsed_transaction(), añade:
if let Some(chain_id) = parsed.chain_id {
    if !self.rules.allowed_chain_ids.contains(&chain_id) {
        return Err(format!("chain_id {} no permitido para la cadena {:?}", chain_id, parsed.chain));
    }
}
for destination in &parsed.destinations {
    if parsed.method.starts_with("erc20_transfer") {
        // la primera direccion es el contrato
        let contract = &parsed.destinations[0].address;
        if !self.rules.allowed_erc20_contracts.contains(contract) {
            return Err(format!("contrato ERC20 no autorizado: {}", contract));
        }
        let decimals = *self.rules.token_decimals.get(contract).unwrap_or(&18u8);
        let vol = Decimal::from(destination.value_units)
            / Decimal::new(10i64.pow(decimals as u32), 0);
        if self.volume_today_units + vol > self.rules.max_daily_volume_units {
            return Err(format!("umbral de volumen excedido: {:.8}", (self.volume_today_units + vol).to_f64().unwrap()));
        }
    } else {
        // salidas normales
        let vol = Decimal::from(destination.value_units)
            / native_units_decimal(parsed.chain);
        if self.volume_today_units + vol > self.rules.max_daily_volume_units {
            return Err(format!("umbral de volumen excedido: {:.8}", (self.volume_today_units + vol).to_f64().unwrap()));
        }
    }
}
En commit_transaction(), suma Decimal y asigna.
PATCH 3 — src-tui/src/crypto/blockchain/tx_parser.rs
Cambia la firma de native_units() para devolver Decimal.
En parse_ethereum_payload(), cuando detectes erc20_transfer, busca el decimal: let decimals = *token_decimals.get(&contract_or_to).unwrap_or(&18u8); y usa native_units_decimal() con ese decimals para calcular volume_units. Guarda decimals en el ParsedTx o calcula volume_units como Decimal que luego conviertas a f64 solo al presentar el resumen.
Ajusta ParsedTx para que volume_units sea Decimal.
PATCH 4 — src-tui/src/crypto/blockchain/mod.rs y supervisor
Ajusta los tipos importados y conversiones para Decimal.
En GatewaySupervisor::run_loop_iteration(), convierte Decimal a f64 sólo para imprimir el resumen.
PATCH 5 — Configuración
Actualiza los archivos de configuración (por ejemplo config/base.json) para añadir allowed_chain_ids, allowed_erc20_contracts y token_decimals. Establece allowed_chain_ids a [1] para Ethereum Mainnet, [0] para Bitcoin y [501] para Solana. Para tokens aprobados, añade el contrato y sus decimales.
PATCH 6 — Tests
Añade pruebas que verifiquen:
Se rechaza una transacción Ethereum con chain_id no permitido.
Se rechaza una transferencia ERC‑20 si el contrato no está en allowed_erc20_contracts.
Se calcula correctamente volume_units para un token con 6 decimales.
Las cantidades se suman con Decimal sin perder precisión.
DEFAULT_FILE_SECRET es distinto de DEFAULT_FILE_REFERENCE.

Después de aplicar los parches, ejecuta:

cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
./target/release/livencrypt-core --self-test-safe
./target/release/livencrypt-core --hardening-check

Todos los tests deben pasar y el programa debe seguir funcionando sin advertencias.


Estos cambios añaden una comprobación de `chain_id` para evitar replays de transacciones entre diferentes redes:contentReference[oaicite:5]{index=5}, ajustan el cálculo de volumen según los decimales de cada token para impedir superar límites con tokens de baja denominación, usan un tipo seguro para sumar volúmenes sin desbordar y exigen que los contratos ERC‑20 estén en una lista blanca. Además refuerzan la separación de secretos y mantienen las protecciones contra “blind signing”:contentReference[oaicite:6]{index=6} y IVs predecibles:contentReference[oaicite:7]{index=7}.
