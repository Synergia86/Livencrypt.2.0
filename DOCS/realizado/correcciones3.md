aún existen vectores de ataque y malas prácticas de seguridad que hay que subsanar. A continuación se resumen los hallazgos y se propone un “prompt” para Codex/OpenCode con los parches necesarios.

Hallazgos de seguridad
Severidad	Problema	Riesgo
Alta	Todavía no se analizan los datos reales de la transacción Web3 antes de firmar. El firewall se basa en los campos value_usd y target_dex_cex_id proporcionados por la extensión en vez de parsear y validar el contenido de raw_tx_payload.	Firmar ciegamente deja a los usuarios expuestos a “blind signing”: los dispositivos de firma no verifican los detalles del payload y sólo confían en la interfaz externa. Esto permite ataques “man‑in‑the‑middle” donde el usuario ve una transacción legítima mientras se firma otra distinta,.
Media	Las claves derivadas de la función pseudo‑BIP32 siguen usando HMAC propio sin realizar comprobaciones de validez ni seguir SLIP‑0010/BIP‑32 oficiales.	La derivación puede generar claves secp256k1 no válidas o no interoperables, y no se elimina la dependencia de un HMAC improvisado.
Media	Los tests de la TUI siguen utilizando la referencia de archivo como clave secreta en algunos casos. Aunque la interfaz ya obliga a introducir una “clave de archivo” distinta, hay que reforzar pruebas y rechazar esa reutilización.	Reutilizar la referencia como clave viola el principio de separación de secretos y expone la clave si la referencia se registra o se comparte.
Baja	Aunque se ha añadido AEAD y una semilla XOR derivada, es importante documentar que usar semillas o IVs constantes es inseguro. La generación de IVs debe ser única y aleatoria para cada cifrado.	Un IV fijo permite ataques de diccionario o correlación porque dos textos iguales producen el mismo cifrado.
Prompt para Codex/OpenCode

El siguiente prompt, escrito en español, especifica los parches concretos para corregir los problemas restantes. Cópialo tal cual en Codex/OpenCode y ejecútalo sobre el árbol real del proyecto.

Audita y corrige Livencrypt 2.0 en Rust. Trabaja sobre el árbol real (no sobre los .txt). Aplica cambios pequeños, seguros y comprobables. Mantén las mejoras existentes (AEAD, semilla XOR derivada, saneamiento de nombres, sockets en XDG_RUNTIME_DIR, script postremove sin borrar datos).

OBJETIVOS PENDIENTES:
1) **Validar transacciones Web3**: parsear `raw_tx_payload` según la cadena (`ChainType`) para extraer el contrato/ dirección de destino real, `chain_id`, cantidad y método antes de firmar. Comparar el destino real con `allowed_dex_contracts` y `allowed_cex_destinations` de la configuración. Rechazar cualquier payload que no se pueda parsear o cuyo destino no coincida. No confiar en `value_usd` ni `target_dex_cex_id` recibidos desde la extensión. Mostrar al usuario un resumen claro antes de firmar para evitar “blind signing”:contentReference[oaicite:4]{index=4},:contentReference[oaicite:5]{index=5}.
2) **Refactorizar derivación de claves**: sustituir `derive_bip32_child()` por un derivador conforme a SLIP‑0010/BIP‑32. Puedes usar `secp256k1::SecretKey::from_slice()` dentro de un bucle para descartar claves inválidas. Para cadenas distintas, aplicar el derivador apropiado (por ejemplo `ed25519_dalek::DerivationPath` para Solana). Documenta la limitación de Monero si sigue sin soporte.
3) **Refuerzo de pruebas**: actualiza las pruebas de la TUI y del núcleo para asegurarte de que la clave de archivo (`file_key_phrase`) es distinta de la referencia (`file_reference_phrase`). Añade un test que falle si se intenta usar la referencia como clave. Mantén las pruebas existentes de sanitización y AEAD.
4) **Documentación y consejos de seguridad**: añade comentarios explicando por qué las IVs y semillas no pueden ser constantes. Cita CWE‑1204/329 y la guía de CodeQL: los IVs deben ser aleatorios para evitar correlaciones:contentReference[oaicite:6]{index=6}.

───────────────────────────────
PATCH 1 — src-tui/src/crypto/blockchain/worker.rs o módulo equivalente
───────────────────────────────

Implementa una función `parse_tx_payload()` que reciba `(chain, raw_tx_payload: &[u8]) -> ParsedTx`, donde `ParsedTx` contenga `to_address`, `value` y otras métricas relevantes. Para Ethereum, decodifica RLP o EIP‑1559 y obtén `to`, `value`, `data` y `chain_id`. Para Bitcoin, descompón inputs y outputs (puedes usar una librería como `bitcoin` si ya está en dependencias; si no, crea un parser simple de transacción raw). Para Solana, extrae los campos de destino y cantidad de SOL/Tokens.

En la verificación de firewall (`validate_transaction()`), reemplace el uso de `request.target_dex_cex_id` y `estimated_value_usd` por:

```rust
let parsed = parse_tx_payload(request.chain, &request.raw_tx_payload)
    .map_err(|e| format!("no se pudo parsear payload: {e}"))?;
let destination = parsed.to_address;
let is_authorized_dex = self.rules.allowed_dex_contracts.contains(&destination);
let is_authorized_cex = self.rules.allowed_cex_destinations.contains(&destination);
if !is_authorized_dex && !is_authorized_cex {
    return Err(format!("bloqueo: destino '{}' no autorizado", destination));
}

Muestra al usuario un resumen de destination, value, chain_id y método antes de firmar. Sólo incrementa tx_count_today y volume_today_usd si la firma se completa correctamente.

───────────────────────────────
PATCH 2 — src-tui/src/crypto/blockchain/multi_curve.rs
───────────────────────────────

Reemplaza derive_bip32_child() por una implementación compatible con SLIP‑0010/BIP‑32. Por ejemplo:

use bip32::{XPrv, DerivationPath, Prefix};
// ...

fn derive_slip10_child(&self, chain: &ChainType, account: u32, index: u32) -> Result<[u8; 32], String> {
    let seed = &self.master_seed;
    let xprv = XPrv::new(seed)?;
    let path = match chain {
        ChainType::Bitcoin | ChainType::Ethereum => DerivationPath::from_str(&format!("m/44'/{}'/{}'/0/{}", coin_id(chain), account, index))?,
        ChainType::Solana => DerivationPath::from_str(&format!("m/44'/501'/{}'/0/{}", account, index))?,
        ChainType::Monero => return Err("Monero requiere derivación aislada".into()),
    };
    let child_prv = xprv.derive_priv(&path)?;
    Ok(child_prv.to_bytes())
}

Actualiza get_public_key() y sign_transaction() para usar derive_slip10_child() y descartar claves secp256k1 no válidas mediante un bucle while SecretKey::from_slice(...).is_err() { index += 1; ... }. Mantén la eliminación segura (zeroize) de claves temporales.

───────────────────────────────
PATCH 3 — src-tui/src/frontend y tests
───────────────────────────────

Refuerza la lógica de la TUI para que nunca reutilice la referencia como clave secreta. En encrypt y decrypt, ya se comprueba que ambas frases tengan al menos 12 caracteres y que sean distintas; añade un test:

#[test]
fn file_secret_and_reference_must_be_distinct() {
    let mut state = TuiState::default();
    state.file_reference_phrase = "ReferenciaLarga123".to_string();
    state.file_key_phrase = state.file_reference_phrase.clone();
    handle_file_action(&mut state, cajas); // función ficticia
    assert!(state.status.contains("debe ser distinta"));
}

Mantén las pruebas existentes de template_path_traversal_rejected, template_invalid_dimensions_rejected, file_aead_tamper_rejected, etc.

───────────────────────────────
PATCH 4 — Comentarios y documentación
───────────────────────────────

Añade comentarios en derive_xor_seed() y las funciones de AEAD explicando que usar una semilla o IV constante compromete la confidencialidad: “según CWE‑1204/CWE‑329, un IV fijo permite correlacionar mensajes e incluso ataques de diccionario; se recomienda utilizar valores aleatorios para cada cifrado”.

───────────────────────────────
TEST FINAL

Tras aplicar estos parches, ejecuta:

cd src-tui
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
./target/release/livencrypt-core --self-test-safe
./target/release/livencrypt-core --hardening-check

Todos los tests deben pasar. Asegúrate de que las nuevas pruebas de parseo de transacciones y derivación de claves cubren los casos normales y de error.


### Explicación resumida
Estas modificaciones abordan los principales riesgos aún presentes en Livencrypt 2.0:

- **Blind signing**: la firma de transacciones sin verificar el contenido real es un riesgo de seguridad; las plataformas de hardware reconocen que los usuarios dependen de la interfaz y que esto abre la puerta a ataques “man‑in‑the‑middle”:contentReference[oaicite:8]{index=8}. Parsear y validar el `raw_tx_payload` antes de firmar elimina esa dependencia.
- **Derivación de claves**: la función HMAC improvisada no cumple con estándares; BIP‑32/SLIP‑0010 garantiza interoperabilidad y seguridad.
- **Separación de secretos**: asegurar que la clave de archivo sea distinta de la referencia evita la exposición accidental de la clave.

Adoptando estos parches se mejora la defensa en profundidad de Livencrypt 2.0, se reduce la superficie de ataque y se ajusta el producto a prácticas recomendadas por OWASP y otras fuentes de referencia:contentReference[oaicite:9]{index=9}.
