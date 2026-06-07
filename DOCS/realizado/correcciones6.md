He incorporado las mejoras recientes (control de chain ID, manejo de decimales y salidas múltiples, separación de clave de archivo, sanitización de rutas, etc.), pero también he identificado nuevos vectores de ataque y errores lógicos que requieren atención.

Hallazgos de seguridad (versión 5)
Severidad	Problema	Riesgo
Alta	Manejo estático de decimales de tokens ERC‑20: el firewall usa un mapa de decimales definido en la configuración; si un token tiene decimales distintos de 18 y no aparece en ese mapa, se asume 18. Esto contradice las buenas prácticas; una auditoría reciente señala que asumir 18 decimales conduce a transferencias incorrectas y posibles pérdidas de fondos.	Un atacante podría usar un token con 6 u 8 decimales no registrado para transferir grandes cantidades sin sobrepasar el límite diario, eludiendo así el control de volumen.
Media	Validación incompleta del chain_id: la comprobación del chain ID se aplica sólo en Ethereum pero no valida todas las cadenas o tokens. Las mejores prácticas recomiendan incluir y verificar siempre el chain ID en las firmas para evitar replays entre redes.	Un replay entre testnet/mainnet podría permitir el movimiento de fondos en redes no autorizadas.
Media	Riesgo de saturación y precisión en safe_volume_add(): aunque el código usa saturating add, sigue acumulando Decimal sin verificar valores anómalos (NaN o Inf). Un error de lectura o de parser podría convertir el volumen en infinito y bloquear el firewall o permitir desbordamientos.	Ataques de denegación de servicio o bypass de límites por desbordamiento.
Baja	Actualización manual de listas blancas: la configuración (allowed_chain_ids, allowed_erc20_contracts, token_decimals) depende de actualizaciones manuales. Si se agrega un nuevo token o se cambia el chain ID, el firewall no lo detectará.	Gestión operativa compleja; riesgo de que un administrador olvide actualizar reglas y se produzca un bypass.
Prompt para Codex/OpenCode (en español)

Copia y pega este bloque en Codex/OpenCode y ejecútalo sobre el árbol real del proyecto. Incluye parches concretos y pruebas unitarias.

Audita y corrige Livencrypt 2.0 en Rust. Trabaja en el árbol real (src-tui/src/*). Aplica cambios pequeños y comprobables, manteniendo las mejoras ya implementadas (AEAD, semilla XOR derivada, sanitización de nombres, sockets en XDG_RUNTIME_DIR, separación de secretos). Sigue estos objetivos y parches:

OBJETIVOS:
1) Evitar que el firewall asuma 18 decimales para tokens ERC‑20. Implementar detección dinámica de decimales o, como mínimo, obligar a registrar cada token autorizado con su número exacto de decimales. Rechazar transferencias de tokens cuyo contrato no figure en `token_decimals`.
2) Validar el `chain_id` en todas las firmas, no solo para Ethereum; cualquier transacción sin chain ID o con un ID no autorizado debe ser rechazada para mitigar ataques de replay:contentReference[oaicite:2]{index=2}.
3) Endurecer `safe_volume_add()` para que rechace valores especiales (`NaN`, `Inf`) y asegure que nunca reduce el volumen acumulado.
4) Añadir pruebas que verifiquen que las transferencias de tokens con decimales no registrados se rechazan, que un chain ID incorrecto no se acepta y que la función de suma de volúmenes maneja correctamente casos límite.
5) Documentar en el código la importancia de no asumir decimales fijos y de verificar el `chain_id` para prevenir ataques de replay:contentReference[oaicite:3]{index=3} y errores de cálculo:contentReference[oaicite:4]{index=4}.

────────────────────────────────────────
PATCH 1 — src-tui/src/crypto/blockchain/types.rs
────────────────────────────────────────

Modifica la estructura `FirewallRules` para que `token_decimals` sea obligatoria para cada contrato de token aprobado y añade un nuevo campo `require_token_registration`:

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FirewallRules {
    pub max_daily_tx: u32,
    pub max_daily_volume_units: Decimal,
    pub allowed_dex_contracts: Vec<String>,
    pub allowed_cex_destinations: Vec<String>,
    pub allowed_erc20_contracts: Vec<String>,
    pub allowed_chain_ids: Vec<u64>,
    pub token_decimals: HashMap<String, u8>,
    /// Si es true, rechaza transferencias de cualquier token ERC‑20 cuyo contrato no figure en token_decimals.
    pub require_token_registration: bool,
}

impl Default for FirewallRules {
    fn default() -> Self {
        Self {
            max_daily_tx: 5,
            max_daily_volume_units: Decimal::from(10),
            allowed_dex_contracts: vec![],
            allowed_cex_destinations: vec![],
            allowed_erc20_contracts: vec![],
            allowed_chain_ids: vec![],
            token_decimals: HashMap::new(),
            require_token_registration: true,
        }
    }
}

────────────────────────────────────────
PATCH 2 — src-tui/src/crypto/blockchain/firewall.rs
────────────────────────────────────────

Añade una comprobación antes de calcular el volumen:

// Dentro de validate_parsed_transaction()
if parsed.method.starts_with("erc20_") {
    let contract = &parsed.destinations[0].address;
    // Rechaza tokens no registrados
    if self.rules.require_token_registration && !self.rules.token_decimals.contains_key(contract) {
        return Err(format!("Token no registrado: se requiere especificar decimales para {}", contract));
    }
    let decimals = *self.rules.token_decimals.get(contract).unwrap_or(&18u8);
    // ...
}

Verifica el chain_id para todas las cadenas admitidas:

if let Some(id) = parsed.chain_id {
    if !self.rules.allowed_chain_ids.contains(&id) {
        return Err(format!("chain_id {} no autorizado para {:?}", id, parsed.chain));
    }
} else {
    // Debe venir siempre un chain_id para cadenas EVM y Solana. Rechaza en caso contrario.
    return Err("Falta chain_id; no se permite firmar sin chain_id".into());
}

Refuerza safe_volume_add() para que devuelva Err en vez de saturar si se detecta NaN, Inf o un valor negativo:

fn safe_volume_add(a: Decimal, b: Decimal) -> Result<Decimal, String> {
    if a.is_sign_negative() || b.is_sign_negative() {
        return Err("volumen negativo detectado".into());
    }
    let c = a.checked_add(b).ok_or("overflow en acumulación de volumen")?;
    if !c.is_finite() {
        return Err("volumen no finito".into());
    }
    Ok(c)
}

Actualiza las llamadas correspondientes y propaga el Result.

────────────────────────────────────────
PATCH 3 — src-tui/src/crypto/blockchain/tx_parser.rs
────────────────────────────────────────

Cambia la estructura ParsedTx para que chain_id nunca sea None:

pub struct ParsedTx {
    pub chain: ChainType,
    pub chain_id: u64,
    pub destinations: Vec<ParsedDestination>,
    pub volume_units: Decimal,
    pub method: String,
    pub summary: String,
}

Ajusta parse_*_payload() para devolver un error si no se puede determinar el chain_id y actualiza las llamadas a chain_id en el firewall.

────────────────────────────────────────
PATCH 4 — src-tui/tests/firewall.rs (o fichero de tests equivalente)
────────────────────────────────────────

Añade pruebas nuevas:

#[test]
fn reject_unregistered_token() {
    let mut fw = LiveFirewall::default();
    fw.rules.allowed_chain_ids = vec![1];
    fw.rules.allowed_erc20_contracts = vec!["0xTokenAddr".into()];
    // require_token_registration = true por defecto
    // no se añade token_decimals["0xTokenAddr"]
    let tx = ParsedTx {
        chain: ChainType::Ethereum,
        chain_id: 1,
        destinations: vec![ParsedDestination {
            address: "0xTokenAddr".into(),
            value_units: Decimal::from(1000),
        }],
        volume_units: Decimal::from(1),
        method: "erc20_transfer".into(),
        summary: String::new(),
    };
    assert!(fw.validate_parsed_transaction(&tx).is_err());
}

#[test]
fn reject_invalid_chain_id() {
    let mut fw = LiveFirewall::default();
    fw.rules.allowed_chain_ids = vec![1];
    let tx = ParsedTx {
        chain: ChainType::Ethereum,
        chain_id: 99,
        destinations: vec![],
        volume_units: Decimal::zero(),
        method: "native_transfer".into(),
        summary: String::new(),
    };
    assert!(fw.validate_parsed_transaction(&tx).is_err());
}

#[test]
fn safe_volume_addition_checks_nan_inf() {
    use rust_decimal_macros::dec;
    assert!(safe_volume_add(dec!(1), dec!(::std::f64::INFINITY)).is_err());
    assert!(safe_volume_add(dec!(1), dec!(-1)).is_err());
}

────────────────────────────────────────
PATCH 5 — Documentación
────────────────────────────────────────

Añade comentarios en firewall.rs y tx_parser.rs explicando que:

No se debe asumir que todos los tokens tienen 18 decimales; se deben registrar manualmente o consultar on‑chain.
El chain_id siempre debe incluirse y verificarse para prevenir replays entre redes.
Se usan Decimal y comprobaciones extra para evitar desbordamientos y valores no finitos.

────────────────────────────────────────
INSTRUCCIONES FINALES
────────────────────────────────────────

Después de aplicar estos parches:

cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
./target/release/livencrypt-core --self-test-safe
./target/release/livencrypt-core --hardening-check

Verifica que todas las pruebas pasen, incluidos los nuevos casos de rechazo de tokens no registrados y chain IDs no autorizados.


---

### Explicación resumida

Estas correcciones complementan las mejoras ya presentes en Livencrypt 2.0:

- **Manejo dinámico de decimales**: evita los errores derivados de asumir 18 decimales, que pueden causar transferencias incorrectas o pérdidas de fondos:contentReference[oaicite:7]{index=7}.
- **Verificación estricta del chain ID**: previene ataques de replay cross‑chain al requerir que cada transacción incluya y cumpla con un chain ID autorizado:contentReference[oaicite:8]{index=8}.
- **Control robusto del volumen**: previene desbordamientos y denegaciones de servicio al detectar valores negativos o infinitos en la suma de volúmenes.
- **Documentación y pruebas**: garantizan que futuras modificaciones no reintroduzcan estos riesgos y que los desarrolladores comprendan por qué son necesarias estas validaciones.
