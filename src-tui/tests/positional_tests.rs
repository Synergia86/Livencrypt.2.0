// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Suite de pruebas para el cifrado por transposición matricial */

#[cfg(test)]
mod tests {
    use livencrypt_lib::crypto::positional::PositionalCipher;
    use livencrypt_lib::templates::TemplateData;

    fn dummy_template() -> TemplateData {
        TemplateData {
            rows: 3,
            cols: 3,
            chars: vec!["a", "b", "c", "d", "e", "f", "g", "h", "␣"]
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let template = dummy_template();
        let cipher = PositionalCipher::new(template);
        let original = "hola";
        let encrypted = cipher.cifrar(original, 5, 7, 2, 3, 0, 8);
        let decrypted = cipher.descifrar(&encrypted.result, 5, 7, 2, 3, 0, 8);
        assert_eq!(original, decrypted.result);
    }

    #[test]
    fn test_unknown_char_passthrough() {
        let template = dummy_template();
        let cipher = PositionalCipher::new(template);
        let result = cipher.cifrar("hello!", 1, 2, 3, 4, 0, 8);
        assert!(result.result.contains('!'));
    }

    #[test]
    fn test_case_preservation() {
        let template = dummy_template();
        let cipher = PositionalCipher::new(template);
        let original = "Hola";
        let encrypted = cipher.cifrar(original, 5, 7, 2, 3, 0, 8);
        let decrypted = cipher.descifrar(&encrypted.result, 5, 7, 2, 3, 0, 8);
        assert_eq!(original, decrypted.result);
    }

    #[test]
    fn test_control_symbols_passthrough() {
        let template = dummy_template();
        let cipher = PositionalCipher::new(template);
        let result = cipher.cifrar("ab¢|@#~½cd", 1, 2, 3, 4, 0, 8);
        assert!(result.result.contains('¢'));
        assert!(result.result.contains('½'));
    }

    #[test]
    fn test_custom_control_symbol_before_password() {
        let template = dummy_template();
        let cipher = PositionalCipher::new(template);
        let encrypted = cipher.cifrar_with_password_config("§abc", 1, 2, 3, 4, 0, 4, "before", "§");

        assert_eq!(encrypted.detected_password, Some("§abc".to_string()));
        assert!(encrypted.result.contains('§'));

        let decrypted = cipher.descifrar_with_password_config(
            &encrypted.result,
            1,
            2,
            3,
            4,
            0,
            4,
            "before",
            "§",
        );
        assert_eq!(decrypted.detected_password, Some("§abc".to_string()));
    }

    #[test]
    fn test_custom_control_symbol_after_password() {
        let template = dummy_template();
        let cipher = PositionalCipher::new(template);
        let encrypted = cipher.cifrar_with_password_config("abc§", 1, 2, 3, 4, 0, 4, "after", "§");

        assert_eq!(encrypted.detected_password, Some("abc§".to_string()));
        assert!(encrypted.result.contains('§'));

        let decrypted = cipher.descifrar_with_password_config(
            &encrypted.result,
            1,
            2,
            3,
            4,
            0,
            4,
            "after",
            "§",
        );
        assert_eq!(decrypted.detected_password, Some("abc§".to_string()));
    }

    #[test]
    fn test_empty_string() {
        let template = dummy_template();
        let cipher = PositionalCipher::new(template);
        let encrypted = cipher.cifrar("", 1, 2, 3, 4, 0, 8);
        let decrypted = cipher.descifrar(&encrypted.result, 1, 2, 3, 4, 0, 8);
        assert_eq!("", decrypted.result);
    }

    #[test]
    fn test_space_mapping() {
        let template = dummy_template();
        let cipher = PositionalCipher::new(template);
        let original = "a b";
        let encrypted = cipher.cifrar(original, 1, 2, 3, 4, 0, 8);
        let decrypted = cipher.descifrar(&encrypted.result, 1, 2, 3, 4, 0, 8);
        assert_eq!(original, decrypted.result);
    }

    #[test]
    fn test_different_keys_produce_different_output() {
        let template = dummy_template();
        let cipher = PositionalCipher::new(template);
        let r1 = cipher.cifrar("abc", 1, 2, 3, 4, 0, 8);
        let r2 = cipher.cifrar("abc", 9, 8, 7, 6, 0, 8);
        assert_ne!(r1.result, r2.result);
    }

    #[test]
    fn test_filelivencrypt_template() {
        let template = livencrypt_lib::templates::filelivencrypt_template();
        assert_eq!(template.rows, 5);
        assert_eq!(template.cols, 23);
        assert_eq!(template.chars.len(), 115);

        let grid = template.as_grid();
        assert_eq!(grid.len(), 5);
        assert_eq!(grid[0].len(), 23);
    }

    #[test]
    fn test_find_position_found() {
        let template = dummy_template();
        let grid = template.as_grid();
        let pos = template.find_position(&grid, 'a');
        assert_eq!(pos, Some((0, 0)));
    }

    #[test]
    fn test_find_position_not_found() {
        let template = dummy_template();
        let grid = template.as_grid();
        let pos = template.find_position(&grid, 'z');
        assert_eq!(pos, None);
    }

    #[test]
    fn test_get_wrapped() {
        let template = dummy_template();
        let grid = template.as_grid();
        let ch = template.get_wrapped(&grid, 0, 0);
        assert_eq!(ch, 'a');
    }
}
