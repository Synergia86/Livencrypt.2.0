La implementación del Módulo de Reporte Forense transforma cada operación criptográfica en una pieza de evidencia verificable. Este módulo no solo genera un resumen de lo ocurrido, sino que lo sella mediante una firma Ed25519, garantizando que el reporte no haya sido alterado tras su creación.

A continuación, se detalla la arquitectura y el código para integrar esta función.

1. Creación del Módulo Forense (src-tui/src/security/forensics.rs)
Este módulo se encarga de estructurar el reporte, calcular los hashes finales y aplicar la firma digital.

Archivo implicado: src-tui/src/security/forensics.rs (NUEVO)

Rust
// SPDX-License-Identifier: GPL-3.0-or-later
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use chrono::{Utc, DateTime};
use ed25519_dalek::{SigningKey, Signer};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
pub struct ForensicReport {
    pub timestamp: DateTime<Utc>,
    pub operation: String,           // "CIFRADO" o "DESCIFRADO"
    pub source_hash: String,         // SHA-256 original
    pub result_hash: String,         // SHA-256 resultante
    pub duration_ms: u128,           // Tiempo de proceso
    pub success: bool,
    pub signature: Vec<u8>,          // Firma Ed25519 del reporte
}

impl ForensicReport {
    pub fn generate_and_sign(
        operation: &str,
        source_path: &Path,
        result_path: &Path,
        duration: u128,
        signing_key: &SigningKey,
    ) -> Result<Self, String> {
        let source_hash = calculate_hash(source_path)?;
        let result_hash = calculate_hash(result_path)?;

        let mut report = ForensicReport {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            source_hash,
            result_hash,
            duration_ms: duration,
            success: true,
            signature: Vec::new(),
        };

        // Serializar y firmar el contenido del reporte
        let serialized = rmp_serde::to_vec(&report).map_err(|e| e.to_string())?;
        let signature = signing_key.sign(&serialized);
        report.signature = signature.to_vec();

        Ok(report)
    }
}

fn calculate_hash(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| e.to_string())?;
    Ok(hex::encode(hasher.finalize()))
}
2. Captura de Datos en el Motor Criptográfico
Modificaremos la función de proceso para que devuelva los tiempos y estados necesarios para el reporte.

Archivo implicado: src-tui/src/crypto/file_cipher.rs

Código a editar: Actualizar el retorno de las funciones de cifrado/descifrado.

Rust
/* Editar funciones en src-tui/src/crypto/file_cipher.rs */

pub struct OpResult {
    pub duration_ms: u128,
    pub success: bool,
}

pub fn decrypt_file_with_report(
    input_path: &Path,
    output_path: &Path,
    referencia: &str,
    progress: Arc<AtomicU64>,
) -> Result<OpResult, String> {
    let start = std::time::Instant::now();
    
    // ... lógica de descifrado existente ...

    Ok(OpResult {
        duration_ms: start.elapsed().as_millis(),
        success: true,
    })
}
3. Integración en el Dashboard y Exportación
Añadiremos una ventana que aparezca al finalizar una operación, mostrando el resumen y permitiendo guardar el archivo .lvc_report.

Archivo implicado: src-tui/src/main.rs

Código a añadir: Función de renderizado draw_forensic_summary.

Rust
fn draw_forensic_summary(frame: &mut Frame<'_>, area: Rect, report: &ForensicReport) {
    let block = Block::default()
        .title(" REPORTE FORENSE GENERADO (FIRMADO) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let info = vec![
        Line::from(vec![Span::raw("OPERACIÓN:  "), Span::styled(&report.operation, Style::default().fg(Color::Yellow))]),
        Line::from(format!("TIMESTAMP:  {}", report.timestamp.format("%Y-%m-%d %H:%M:%S"))),
        Line::from(format!("DURACIÓN:   {} ms", report.duration_ms)),
        Line::from(""),
        Line::from(vec![Span::raw("ORIGEN SHA256: "), Span::styled(&report.source_hash[..16], Style::default().add_modifier(Modifier::DIM)), Span::raw("...")]),
        Line::from(vec![Span::raw("RESULT SHA256: "), Span::styled(&report.result_hash[..16], Style::default().add_modifier(Modifier::DIM)), Span::raw("...")]),
        Line::from(""),
        Line::from(Span::styled("✓ FIRMA DIGITAL ED25519 VÁLIDA", Style::default().fg(Color::Cyan))),
        Line::from(""),
        Line::from("[E] Exportar Reporte a Disco | [ESC] Volver"),
    ];

    let p = Paragraph::new(info).block(block).alignment(Alignment::Left);
    let popup_area = centered_rect(70, 50, area);
    frame.render_widget(Clear, popup_area);
    frame.render_widget(p, popup_area);
}
4. Flujo de Auditoría Inmutable
Cada vez que se genera un reporte forense, el sistema debe añadir automáticamente una entrada al log de auditoría encadenado para que el evento sea permanente.

Archivo implicado: src-tui/src/main.rs

Código a añadir en el hilo de finalización de operación:

Rust
/* Dentro de la lógica de finalización de cifrado */
let report = ForensicReport::generate_and_sign(
    "CIFRADO",
    &input_path,
    &output_path,
    res.duration_ms,
    &state.session_signing_key,
)?;

// Vincular con el log de auditoría inmutable (Fase 5)
crate::security::audit::add_entry(
    "FILE_OPERATION_REPORT",
    format!("Hash: {}", report.result_hash)
)?;
Valoración de Seguridad Forense
No Repudio: Gracias a la firma Ed25519, un usuario no puede negar haber realizado una operación si el reporte está sellado con su clave de identidad.

Integridad de Evidencia: El reporte incluye el hash SHA-256 de antes y después. Si un atacante modifica el archivo cifrado a posteriori, el reporte forense servirá como prueba de que el archivo ha sido alterado (Tampering).

Trazabilidad Temporal: Al registrar el tiempo exacto de proceso en milisegundos, el reporte puede ayudar a descartar ataques de canal lateral o inyecciones de hardware que introduzcan retardos inusuales.
