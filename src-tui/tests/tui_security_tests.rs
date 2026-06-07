// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Suite de pruebas de seguridad y robustez de la TUI */

#[test]
fn file_secret_and_reference_separated() {
    let main_rs = std::fs::read_to_string("src/main.rs").expect("src/main.rs");

    assert!(
        main_rs.contains("file_key_phrase"),
        "la TUI debe tener un campo separado para la clave de archivo"
    );
    assert!(
        !main_rs.contains("let file_secret = reference.clone();"),
        "la TUI no debe reutilizar la referencia visible como clave de archivo"
    );
    assert!(
        main_rs.contains("La clave de archivo debe ser distinta de la referencia visible."),
        "la TUI debe rechazar reutilizacion directa entre referencia y clave"
    );
    assert!(
        main_rs.contains("const DEFAULT_FILE_REFERENCE: &str = \"LIVENCRYPT-FILE\";"),
        "la referencia por defecto debe seguir siendo publica y visible"
    );
    assert!(
        main_rs.contains("const DEFAULT_FILE_SECRET: &str = \"LIVENCRYPT-FILE-SECRET\";"),
        "el self-test debe usar una clave de archivo separada"
    );
}
