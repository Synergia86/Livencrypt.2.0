// SPDX-License-Identifier: GPL-3.0-or-later

/// Test de integración completo para livencrypt 2.0
/// Verifica todas las funciones criptográficas implementadas

#[cfg(test)]
mod integration {
    use livencrypt_lib::crypto::file_cipher::FileCipher;
    use livencrypt_lib::crypto::positional::PositionalCipher;
    use livencrypt_lib::templates::{filelivencrypt_template, TemplateData};

    fn mini_template() -> TemplateData {
        TemplateData {
            rows: 3,
            cols: 6,
            chars: vec![
                "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p",
                "q", "␣",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }

    // ─── TEMPLATE UTILS ─────────────────────────────────────────

    #[test]
    fn test_as_grid_correct_dimensions() {
        let t = mini_template();
        let g = t.as_grid();
        assert_eq!(g.len(), 3);
        assert_eq!(g[0].len(), 6);
        assert_eq!(g[0][0], 'a');
        assert_eq!(g[2][5], '␣');
    }

    #[test]
    fn test_find_position_case_insensitive() {
        let t = mini_template();
        let g = t.as_grid();
        assert_eq!(t.find_position(&g, 'A'), Some((0, 0)));
        assert_eq!(t.find_position(&g, 'g'), Some((1, 0)));
    }

    #[test]
    fn test_get_wrapped_handles_overflow() {
        let t = mini_template();
        let g = t.as_grid();
        assert_eq!(t.get_wrapped(&g, 3, 0), 'a'); // row = 3 % 3 = 0
        assert_eq!(t.get_wrapped(&g, 0, 6), 'a'); // col = 6 % 6 = 0
        assert_eq!(t.get_wrapped(&g, -1, -1), '␣'); // (-1)%3=2, (-1)%6=5
    }

    // ─── TEXT CIPHER (PositionalCipher) ──────────────────────────

    #[test]
    fn test_text_roundtrip_simple() {
        let c = PositionalCipher::new(mini_template());
        let enc = c.cifrar("abcdef", 1, 2, 3, 4, 0, 8);
        let dec = c.descifrar(&enc.result, 1, 2, 3, 4, 0, 8);
        assert_eq!("abcdef", dec.result);
    }

    #[test]
    fn test_text_roundtrip_with_spaces() {
        let c = PositionalCipher::new(mini_template());
        let enc = c.cifrar("a b c", 1, 2, 3, 4, 0, 8);
        let dec = c.descifrar(&enc.result, 1, 2, 3, 4, 0, 8);
        assert_eq!("a b c", dec.result);
    }

    #[test]
    fn test_text_roundtrip_mixed_case() {
        let c = PositionalCipher::new(mini_template());
        let enc = c.cifrar("AbCdEf", 5, 7, 2, 3, 0, 8);
        let dec = c.descifrar(&enc.result, 5, 7, 2, 3, 0, 8);
        assert_eq!("AbCdEf", dec.result);
    }

    #[test]
    fn test_text_control_symbols_passthrough() {
        let c = PositionalCipher::new(mini_template());
        let enc = c.cifrar("ab¢|@#~½cd", 1, 2, 3, 4, 0, 8);
        assert!(enc.result.contains('¢'));
        assert!(enc.result.contains('½'));
        let dec = c.descifrar(&enc.result, 1, 2, 3, 4, 0, 8);
        assert!(dec.result.contains('¢'));
    }

    #[test]
    fn test_text_empty_string() {
        let c = PositionalCipher::new(mini_template());
        let enc = c.cifrar("", 1, 2, 3, 4, 0, 8);
        let dec = c.descifrar(&enc.result, 1, 2, 3, 4, 0, 8);
        assert_eq!("", dec.result);
    }

    #[test]
    fn test_text_long_string() {
        let template = filelivencrypt_template();
        let c = PositionalCipher::new(template);
        let original =
            "Livencrypt 2.0 — Protocolo de soberanía física activo — Test de integración completo";
        let enc = c.cifrar(original, 7, 3, 5, 9, 0, 8);
        let dec = c.descifrar(&enc.result, 7, 3, 5, 9, 0, 8);
        assert_eq!(original, dec.result);
    }

    // ─── FILE CIPHER ────────────────────────────────────────────

    #[test]
    fn test_file_procesar_texto_archivo_roundtrip() {
        let template = filelivencrypt_template();
        let grid = template.as_grid();
        let _r = template.rows as usize;
        let _c = template.cols as usize;

        let cases = vec![
            ("0123456789abcdef", (5, 7, 2, 3, 9)),
            ("abcdef0123456789", (1, 2, 3, 4, 8)),
            ("fedcba9876543210", (9, 8, 7, 6, 5)),
        ];
        for (hex, (c1, c2, c3, c4, c5)) in cases {
            let enc = FileCipher::procesar_texto_archivo(hex, c1, c2, c3, c4, c5, "cifrar", &grid);
            let dec =
                FileCipher::procesar_texto_archivo(&enc, c1, c2, c3, c4, c5, "descifrar", &grid);
            assert_eq!(
                hex, dec,
                "Failed for hex={hex} cajas=({c1},{c2},{c3},{c4},{c5})"
            );
        }
    }

    #[test]
    fn test_file_caja5_all_patterns() {
        let template = filelivencrypt_template();
        let grid = template.as_grid();
        let _r = template.rows as usize;
        let _c = template.cols as usize;
        let hex = "abcdef0123456789abcdef";

        for c5 in 0..12 {
            let enc = FileCipher::procesar_texto_archivo(hex, 5, 7, 2, 3, c5, "cifrar", &grid);
            let dec = FileCipher::procesar_texto_archivo(&enc, 5, 7, 2, 3, c5, "descifrar", &grid);
            assert_eq!(hex, dec, "caja5={c5} failed");
        }
    }

    #[test]
    fn test_file_encrypt_decrypt_binary_full_pipeline() {
        let tmp = std::env::temp_dir();
        let orig = tmp.join("livencrypt_integration_test_orig.bin");
        let enc = tmp.join("livencrypt_integration_test_enc.txt");
        let dec = tmp.join("livencrypt_integration_test_dec.bin");

        let test_data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        std::fs::write(&orig, &test_data).unwrap();

        FileCipher::encrypt_file(
            &orig,
            &enc,
            "RefTest2026",
            &filelivencrypt_template(),
            5,
            7,
            2,
            3,
            9,
            &[0u8; 32],
        )
        .unwrap();
        assert!(enc.exists());

        FileCipher::decrypt_file(
            &enc,
            &dec,
            "RefTest2026",
            false,
            &filelivencrypt_template(),
            5,
            7,
            2,
            3,
            9,
            &[0u8; 32],
        )
        .unwrap();

        let dec_data = std::fs::read(&dec).unwrap();
        assert_eq!(test_data, dec_data, "Binary roundtrip failed");

        let _ = std::fs::remove_file(&orig);
        let _ = std::fs::remove_file(&enc);
        let _ = std::fs::remove_file(&dec);
    }

    #[test]
    fn test_file_info_returns_correct_metadata() {
        let tmp = std::env::temp_dir();
        let p = tmp.join("livencrypt_info_test.dat");
        std::fs::write(&p, &[42u8; 500]).unwrap();

        let info = FileCipher::load_file_info(&p).unwrap();
        assert_eq!(info.size_bytes, 500);
        assert!(!info.is_compressed);

        let _ = std::fs::remove_file(&p);
    }

    // ─── FILELIVENCRYPT TEMPLATE CONSISTENCY ─────────────────────

    #[test]
    fn test_filelivencrypt_template_dimensions() {
        let t = filelivencrypt_template();
        assert_eq!(t.rows, 5);
        assert_eq!(t.cols, 23);
        assert_eq!(t.chars.len(), 115);
    }

    #[test]
    fn test_filelivencrypt_no_duplicate_lowercase() {
        let t = filelivencrypt_template();
        let grid = t.as_grid();
        let mut seen = std::collections::HashSet::new();
        for row in &grid {
            for &ch in row {
                let key = ch.to_lowercase().next().unwrap_or('\0');
                assert!(
                    seen.insert(key),
                    "Duplicate lowercase char: {ch:?} ({key:?})"
                );
            }
        }
    }

    // ─── INTER-MODULE CONSISTENCY ────────────────────────────────

    #[test]
    fn test_text_and_file_cipher_are_independent() {
        // Text uses user-selected template, file uses fixed filelivencrypt
        let text_template = mini_template();
        let file_template = filelivencrypt_template();

        assert_eq!(text_template.rows, 3);
        assert_eq!(file_template.rows, 5);

        // Text cipher works with mini template
        let tc = PositionalCipher::new(text_template);
        let r = tc.cifrar("abc", 1, 2, 3, 4, 0, 8);
        assert!(!r.result.is_empty());

        // File cipher uses file template internally
        let file_grid = file_template.as_grid();
        let fr = FileCipher::procesar_texto_archivo("abc", 1, 2, 3, 4, 9, "cifrar", &file_grid);
        assert!(!fr.is_empty());

        // They produce different outputs (different templates)
        assert_ne!(r.result, fr);
    }

    // ─── EDGE CASES ──────────────────────────────────────────────

    #[test]
    fn test_caja5_edge_total_minus_one() {
        let template = filelivencrypt_template();
        let grid = template.as_grid();
        let _r = template.rows as usize;
        let _c = template.cols as usize;

        let hex = "abcde";
        let total = hex.len() as i64;
        let c5 = total - 1; // Should disable caja5

        let enc = FileCipher::procesar_texto_archivo(hex, 1, 2, 3, 4, c5, "cifrar", &grid);
        let dec = FileCipher::procesar_texto_archivo(&enc, 1, 2, 3, 4, c5, "descifrar", &grid);
        assert_eq!(hex, dec);
    }

    #[test]
    fn test_encrypt_then_decrypt_with_different_boxes_fails() {
        let c = PositionalCipher::new(mini_template());
        let enc = c.cifrar("abcdef", 5, 7, 2, 3, 0, 8);
        let dec = c.descifrar(&enc.result, 1, 2, 3, 4, 0, 8); // Different boxes!
        assert_ne!("abcdef", dec.result, "Should not decrypt with wrong boxes");
    }
}
