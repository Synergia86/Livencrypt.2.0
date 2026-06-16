He examinado los archivos actualizados y, aunque muchas de las recomendaciones previas ya están aplicadas (AEAD con XChaCha20‑Poly1305, validación de nombres de plantilla, no usar /tmp para sockets, etc.), siguen existiendo errores y vectores de ataque:

El cifrado interno aún usa una semilla nula:
En FileCipher::encrypt_file_authenticated() se llama a Self::encrypt_file() con la semilla estática &[0u8; 32]. Un IV o “seed” predecible debilita la seguridad; la CWE‑1204 advierte que IVs no únicos o poco aleatorios permiten filtrar datos y que es preferible generar valores impredecibles. Aunque el archivo se protege luego con AEAD, la capa interna sin semilla debilita el patrón posicional y favorece ataques por análisis diferencial.
Se reutiliza la frase de referencia como clave de archivo: la TUI toma file_secret = reference; no pide una clave independiente ni limita su reutilización. Esto expone la clave si la referencia se muestra o registra.
El supervisor Web3 aún no parsea la transacción: simplemente rechaza todas las firmas si no hay “parser forense”. No se analiza raw_tx_payload ni se comprueban los contratos destinatarios; cuando se active esta lógica, debe parsear y comparar los valores reales con allowed_dex_contracts y allowed_cex_destinations.
Persisten ataques de path traversal si no se valida el nombre de plantilla: aunque el código implementa sanitize_template_name(), conviene recordar que OWASP recomienda no permitir que el usuario controle la ruta y validar la entrada aceptando sólo valores conocidos para evitar que ../ o secuencias equivalentes escapen del directorio.

A continuación propongo un prompt de corrección para Codex/OpenCode que soluciona estas deficiencias (traduce y aplica cada “PATCH” sobre el árbol real de Rust):

Audita y corrige Livencrypt 2.0 en Rust. Trabaja sobre el árbol real (no sobre los .txt). Aplica cambios pequeños y comprobables.

OBJETIVOS:
1) El cifrado interno no puede usar semilla `[0u8; 32]`; derive una semilla impredecible de la clave/frase de archivo.
2) La TUI debe solicitar una clave de archivo distinta de la referencia y no reutilizarlas silenciosamente.
3) Al parsear transacciones Web3, validar destino real y monto antes de firmar, ignorando `value_usd` y `target_dex_cex_id` externos.
4) Mantener la sanitización de nombres de plantilla y evitar path traversal siguiendo las recomendaciones de OWASP:contentReference[oaicite:3]{index=3}.
5) Mantener AEAD, sockets en `XDG_RUNTIME_DIR` y no borrar datos de usuario en `postremove.sh`.

────────────────────────────────────────
PATCH A — src-tui/src/crypto/file_cipher.rs
────────────────────────────────────────

Dentro de `FileCipher::encrypt_file_authenticated()` y `decrypt_file_authenticated()`, derive un `xor_seed` de 32 bytes a partir de `file_secret`, `referencia` y `cajas` y úselo al llamar a `Self::encrypt_file()`/`Self::decrypt_file()`. Ejemplo:

```rust
// Deriva semilla XOR (32 bytes) con SHA256 de secret|referencia|cajas
fn derive_xor_seed(file_secret: &str, referencia: &str, cajas: [i64; 5]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    use zeroize::Zeroize;

    let mut material = Vec::new();
    material.extend_from_slice(file_secret.as_bytes());
    material.extend_from_slice(referencia.as_bytes());
    for caja in cajas {
        material.extend_from_slice(&caja.to_le_bytes());
    }

    let hash = Sha256::digest(&material);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash[..32]);
    material.zeroize();
    seed
}

En encrypt_file_authenticated():

let xor_seed = derive_xor_seed(file_secret, referencia, cajas);
let inner_result = Self::encrypt_file(
    input_path, &inner_path, referencia, template,
    cajas[0], cajas[1], cajas[2], cajas[3], cajas[4], &xor_seed
);
// ... después de usarla, borre la semilla:
xor_seed.zeroize();

En decrypt_file_authenticated() haga lo mismo:

let xor_seed = derive_xor_seed(file_secret, referencia, cajas);
// ... después de decodificar:
let result = Self::decrypt_file(
    &inner_path, output_path, referencia,
    is_txt_output, template,
    cajas[0], cajas[1], cajas[2], cajas[3], cajas[4], &xor_seed
);
xor_seed.zeroize();

De este modo la capa posicional utiliza una semilla fuerte, evitando IVs fijos, lo cual mitiga las debilidades descritas en CWE‑1204.

────────────────────────────────────────
PATCH B — src-tui/src/lib.rs y TUI
────────────────────────────────────────

Añada un campo “clave de archivo” en la interfaz de cifrado/descifrado para que el usuario introduzca una frase distinta de la referencia. Cambie la lógica que actualmente usa file_secret = reference.clone() a:

let file_secret = state.file_key_phrase.clone();
if file_secret.trim().chars().count() < 12 {
    state.status = "La clave de archivo debe tener al menos 12 caracteres.".to_string();
    return;
}

Asegúrese de que la referencia sigue siendo visible en el reporte forense pero no reutilizada como clave. Añada en la vista un campo de entrada separado para file_key_phrase.

────────────────────────────────────────
PATCH C — src-tui/src/crypto/blockchain/worker.rs

Implemente análisis de raw_tx_payload según el ChainType. Extraiga destino real, monto y otros parámetros y verifique:

El contrato o dirección destino se encuentra en allowed_dex_contracts o allowed_cex_destinations.
El valor y chain_id son coherentes con la política local.
Las peticiones con parsing fallido se rechazan, registrando auditoría.
value_usd y target_dex_cex_id de la extensión no se utilizan para decisiones de seguridad.

Mostrar al usuario un resumen claro de la transacción (destino, cantidad, cadena, método) antes de firmar.

────────────────────────────────────────
PATCH D — src-tui/src/templates.rs (o módulo equivalente)

Mantenga y refuerce sanitize_template_name() y validate_template_strict(). No permita ../, /, \\ ni nombres vacíos, y valide filas, columnas y duplicados. La guía OWASP recuerda que hay que evitar que el usuario controle toda la ruta y aceptar sólo valores buenos. Las funciones actuales cumplen estos requisitos; deje los tests de rechazo y aceptación.

────────────────────────────────────────
PATCH E — scripts/postremove.sh y configuración Tauri

Conserve el script postremove.sh actual (no borra datos de usuario) y la política CSP definida en tauri.conf.json. No regrese a versiones con "csp": null.

────────────────────────────────────────
PATCH F — Tests

Añada tests nuevos:

xor_seed_changes_with_secret() — comprueba que derive_xor_seed() produce semillas distintas para claves diferentes.
encrypt_file_inner_not_zero_seed() — verifica que la semilla que llega a encrypt_file() no es [0u8; 32].
file_secret_and_reference_separated() — asegura que la TUI no reutiliza la referencia como clave.

Asegure que todos los tests anteriores (cargo test --locked) pasan y que cargo clippy no reporta advertencias.


Estas correcciones eliminan los vectores críticos restantes: evitan una semilla predecible en el cifrado, separan referencia y clave, preparan el futuro análisis forense en Web3 y conservan las protecciones contra path traversal:contentReference[oaicite:6]{index=6} y IVs débiles:contentReference[oaicite:7]{index=7}.
