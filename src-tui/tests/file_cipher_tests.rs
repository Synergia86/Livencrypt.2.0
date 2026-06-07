// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Suite de pruebas para el motor de cifrado de archivos */

#[cfg(test)]
mod tests {
    use livencrypt_lib::crypto::file_cipher::FileCipher;
    use livencrypt_lib::templates::{filelivencrypt_template, TemplateData};
    use std::io::Write;

    #[test]
    fn test_filelivencrypt_grid_consistency() {
        let template = filelivencrypt_template();
        let grid = template.as_grid();
        assert_eq!(grid.len(), 5);
        assert_eq!(grid[0].len(), 23);
        assert_eq!(grid[4].len(), 23);

        assert_eq!(grid[0][0], 'ճ');
        assert_eq!(grid[4][22], '厥');
    }

    #[test]
    fn test_procesar_texto_archivo_roundtrip() {
        let template = filelivencrypt_template();
        let grid = template.as_grid();
        let _rows = template.rows as usize;
        let _cols = template.cols as usize;

        let original_hex = "0123456789abcdef";
        let encrypted =
            FileCipher::procesar_texto_archivo(original_hex, 5, 7, 2, 3, 9, "cifrar", &grid);
        let decrypted =
            FileCipher::procesar_texto_archivo(&encrypted, 5, 7, 2, 3, 9, "descifrar", &grid);
        assert_eq!(original_hex, decrypted);
    }

    #[test]
    fn test_caja5_combinations_all_roundtrip() {
        let template = filelivencrypt_template();
        let grid = template.as_grid();
        let _rows = template.rows as usize;
        let _cols = template.cols as usize;

        let original_hex = "abcdef0123456789abcdef";
        for c5 in 0..10 {
            let encrypted =
                FileCipher::procesar_texto_archivo(original_hex, 5, 7, 2, 3, c5, "cifrar", &grid);
            let decrypted =
                FileCipher::procesar_texto_archivo(&encrypted, 5, 7, 2, 3, c5, "descifrar", &grid);
            assert_eq!(original_hex, decrypted, "caja5={} failed roundtrip", c5);
        }
    }

    #[test]
    fn test_encrypt_decrypt_file_binary_roundtrip() {
        let tmp_dir = std::env::temp_dir();
        let original_path = tmp_dir.join("test_original.bin");
        let encrypted_path = tmp_dir.join("test_encrypted.txt");
        let decrypted_path = tmp_dir.join("test_decrypted.bin");

        let test_data: Vec<u8> = (0..255).collect();
        std::fs::write(&original_path, &test_data).unwrap();

        FileCipher::encrypt_file(
            &original_path,
            &encrypted_path,
            "testref2024",
            &filelivencrypt_template(),
            5,
            7,
            2,
            3,
            9,
            &[0u8; 32],
        )
        .unwrap();

        assert!(encrypted_path.exists());

        FileCipher::decrypt_file(
            &encrypted_path,
            &decrypted_path,
            "testref2024",
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

        let decrypted_data = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(test_data, decrypted_data);

        let _ = std::fs::remove_file(&original_path);
        let _ = std::fs::remove_file(&encrypted_path);
        let _ = std::fs::remove_file(&decrypted_path);
    }

    #[test]
    fn test_streaming_encrypt_binary_roundtrip_without_full_hex_buffer() {
        let tmp_dir = std::env::temp_dir();
        let original_path = tmp_dir.join("test_stream_original.bin");
        let encrypted_path = tmp_dir.join("test_stream_encrypted.dat");
        let decrypted_path = tmp_dir.join("test_stream_decrypted.bin");

        let test_data: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();
        std::fs::write(&original_path, &test_data).unwrap();

        FileCipher::encrypt_file_streaming_binary_for_test(
            &original_path,
            &encrypted_path,
            "streamref2024",
            &filelivencrypt_template(),
            5,
            7,
            2,
            3,
            9,
            &[0u8; 32],
        )
        .unwrap();

        FileCipher::decrypt_file(
            &encrypted_path,
            &decrypted_path,
            "streamref2024",
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

        let decrypted_data = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(test_data, decrypted_data);

        let _ = std::fs::remove_file(&original_path);
        let _ = std::fs::remove_file(&encrypted_path);
        let _ = std::fs::remove_file(&decrypted_path);
    }

    #[test]
    fn test_streaming_decrypt_binary_roundtrip_without_full_plaintext_buffer() {
        let tmp_dir = std::env::temp_dir();
        let original_path = tmp_dir.join("test_stream_dec_original.bin");
        let encrypted_path = tmp_dir.join("test_stream_dec_encrypted.dat");
        let decrypted_path = tmp_dir.join("test_stream_dec_decrypted.bin");

        let test_data: Vec<u8> = (0..32_768).map(|i| ((i * 17) % 251) as u8).collect();
        std::fs::write(&original_path, &test_data).unwrap();

        FileCipher::encrypt_file_streaming_binary_for_test(
            &original_path,
            &encrypted_path,
            "streamdecref2024",
            &filelivencrypt_template(),
            5,
            7,
            2,
            3,
            9,
            &[0u8; 32],
        )
        .unwrap();

        FileCipher::decrypt_file_streaming_for_test(
            &encrypted_path,
            &decrypted_path,
            "streamdecref2024",
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

        let decrypted_data = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(test_data, decrypted_data);

        let _ = std::fs::remove_file(&original_path);
        let _ = std::fs::remove_file(&encrypted_path);
        let _ = std::fs::remove_file(&decrypted_path);
    }

    #[test]
    fn test_streaming_decrypt_removes_partial_output_on_error() {
        let tmp_dir = std::env::temp_dir();
        let original_path = tmp_dir.join("test_stream_dec_error_original.bin");
        let encrypted_path = tmp_dir.join("test_stream_dec_error_encrypted.dat");
        let decrypted_path = tmp_dir.join("test_stream_dec_error_decrypted.bin");
        let temp_path = decrypted_path.with_extension("bin.tmp");
        let invalid_template = TemplateData {
            rows: 1,
            cols: 1,
            chars: vec!["x".into()],
        };

        let _ = std::fs::remove_file(&decrypted_path);
        let _ = std::fs::remove_file(&temp_path);
        std::fs::write(&original_path, [0u8; 32]).unwrap();
        FileCipher::encrypt_file_streaming_binary_for_test(
            &original_path,
            &encrypted_path,
            "streamdecerr2024",
            &filelivencrypt_template(),
            5,
            7,
            2,
            3,
            9,
            &[0u8; 32],
        )
        .unwrap();

        let err = FileCipher::decrypt_file_streaming_for_test(
            &encrypted_path,
            &decrypted_path,
            "streamdecerr2024",
            false,
            &invalid_template,
            5,
            7,
            2,
            3,
            9,
            &[0u8; 32],
        )
        .unwrap_err();

        assert!(err.contains("caracter fuera de grid"));
        assert!(!decrypted_path.exists(), "no debe quedar salida parcial");
        assert!(!temp_path.exists(), "no debe quedar temporal parcial");

        let _ = std::fs::remove_file(&original_path);
        let _ = std::fs::remove_file(&encrypted_path);
    }

    #[test]
    fn test_streaming_encrypt_removes_partial_output_on_error() {
        let tmp_dir = std::env::temp_dir();
        let original_path = tmp_dir.join("test_stream_error_original.bin");
        let encrypted_path = tmp_dir.join("test_stream_error_encrypted.dat");
        let temp_path = encrypted_path.with_extension("dat.tmp");
        let invalid_template = TemplateData {
            rows: 1,
            cols: 1,
            chars: vec!["x".into()],
        };

        let _ = std::fs::remove_file(&encrypted_path);
        let _ = std::fs::remove_file(&temp_path);
        std::fs::write(&original_path, [0u8; 32]).unwrap();

        let err = FileCipher::encrypt_file_streaming_binary_for_test(
            &original_path,
            &encrypted_path,
            "streamref2024",
            &invalid_template,
            5,
            7,
            2,
            3,
            9,
            &[0u8; 32],
        )
        .unwrap_err();

        assert!(err.contains("caracter fuera de grid"));
        assert!(!encrypted_path.exists(), "no debe quedar salida parcial");
        assert!(!temp_path.exists(), "no debe quedar temporal parcial");

        let _ = std::fs::remove_file(&original_path);
    }

    #[test]
    fn test_file_info() {
        let tmp_dir = std::env::temp_dir();
        let test_path = tmp_dir.join("test_info.bin");
        {
            let mut f = std::fs::File::create(&test_path).unwrap();
            f.write_all(&[0u8; 1024]).unwrap();
        }

        let info = FileCipher::load_file_info(&test_path).unwrap();
        assert_eq!(info.size_bytes, 1024);
        assert!(!info.is_compressed);

        let _ = std::fs::remove_file(&test_path);
    }

    #[test]
    fn test_caja5_edge_case_equals_total_minus_one() {
        let template = filelivencrypt_template();
        let grid = template.as_grid();
        let _rows = template.rows as usize;
        let _cols = template.cols as usize;

        let original_hex = "abcde";
        let total = original_hex.len();
        let c5 = (total as i64) - 1;

        let encrypted =
            FileCipher::procesar_texto_archivo(original_hex, 1, 2, 3, 4, c5, "cifrar", &grid);
        let decrypted =
            FileCipher::procesar_texto_archivo(&encrypted, 1, 2, 3, 4, c5, "descifrar", &grid);
        assert_eq!(original_hex, decrypted);
    }

    #[test]
    fn test_caja5_even_indices_use_mirrored_l_movement() {
        let total = 16;

        assert_eq!(
            FileCipher::get_caja5_movements_test(1, 0, total),
            vec![(2, 0), (0, 1)],
            "odd indices must keep the original 1.1 L movement"
        );
        assert_eq!(
            FileCipher::get_caja5_movements_test(0, 0, total),
            vec![(-2, 0), (0, -1)],
            "even indices must use the inverted mirror movement"
        );
    }

    #[test]
    fn file_aead_tamper_rejected() {
        let tmp_dir = std::env::temp_dir();
        let original_path = tmp_dir.join("test_aead_tamper_original.bin");
        let encrypted_path = tmp_dir.join("test_aead_tamper_encrypted.lvc");
        let decrypted_path = tmp_dir.join("test_aead_tamper_decrypted.bin");
        let secret = "clave archivo segura 2026";
        let reference = "referencia segura 2026";
        let cajas = [5, 7, 2, 3, 9];

        std::fs::write(&original_path, b"payload autenticado").unwrap();
        FileCipher::encrypt_file_authenticated(
            &original_path,
            &encrypted_path,
            reference,
            &filelivencrypt_template(),
            cajas,
            secret,
        )
        .unwrap();
        let mut bytes = std::fs::read(&encrypted_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x55;
        std::fs::write(&encrypted_path, bytes).unwrap();

        let err = FileCipher::decrypt_file_authenticated(
            &encrypted_path,
            &decrypted_path,
            reference,
            false,
            &filelivencrypt_template(),
            cajas,
            secret,
        )
        .unwrap_err();
        assert!(err.contains("AEAD") || err.contains("invalido"));

        let _ = std::fs::remove_file(&original_path);
        let _ = std::fs::remove_file(&encrypted_path);
        let _ = std::fs::remove_file(&decrypted_path);
    }

    #[test]
    fn file_aead_text_roundtrip_with_inner_seed() {
        let tmp_dir = std::env::temp_dir();
        let original_path = tmp_dir.join("test_aead_text_seed_original.txt");
        let encrypted_path = tmp_dir.join("test_aead_text_seed_encrypted.lvc");
        let decrypted_path = tmp_dir.join("test_aead_text_seed_decrypted.txt");
        let secret = "clave archivo independiente 2026";
        let reference = "referencia visible 2026";
        let cajas = [1, 2, 3, 4, 5];
        let plain = b"texto livencrypt autenticado con semilla interna";

        std::fs::write(&original_path, plain).unwrap();
        FileCipher::encrypt_file_authenticated(
            &original_path,
            &encrypted_path,
            reference,
            &filelivencrypt_template(),
            cajas,
            secret,
        )
        .unwrap();
        FileCipher::decrypt_file_authenticated(
            &encrypted_path,
            &decrypted_path,
            reference,
            true,
            &filelivencrypt_template(),
            cajas,
            secret,
        )
        .unwrap();

        assert_eq!(std::fs::read(&decrypted_path).unwrap(), plain);

        let _ = std::fs::remove_file(&original_path);
        let _ = std::fs::remove_file(&encrypted_path);
        let _ = std::fs::remove_file(&decrypted_path);
    }

    #[test]
    fn file_aead_wrong_secret_rejected() {
        let tmp_dir = std::env::temp_dir();
        let original_path = tmp_dir.join("test_aead_secret_original.bin");
        let encrypted_path = tmp_dir.join("test_aead_secret_encrypted.lvc");
        let decrypted_path = tmp_dir.join("test_aead_secret_decrypted.bin");
        let reference = "referencia segura 2026";
        let cajas = [5, 7, 2, 3, 9];

        std::fs::write(&original_path, b"payload autenticado").unwrap();
        FileCipher::encrypt_file_authenticated(
            &original_path,
            &encrypted_path,
            reference,
            &filelivencrypt_template(),
            cajas,
            "clave archivo correcta 2026",
        )
        .unwrap();

        let err = FileCipher::decrypt_file_authenticated(
            &encrypted_path,
            &decrypted_path,
            reference,
            false,
            &filelivencrypt_template(),
            cajas,
            "clave archivo erronea 2026",
        )
        .unwrap_err();
        assert!(err.contains("AEAD") || err.contains("clave incorrecta"));

        let _ = std::fs::remove_file(&original_path);
        let _ = std::fs::remove_file(&encrypted_path);
        let _ = std::fs::remove_file(&decrypted_path);
    }

    #[test]
    fn file_aead_wrong_template_boxes_reference_rejected() {
        let tmp_dir = std::env::temp_dir();
        let original_path = tmp_dir.join("test_aead_meta_original.bin");
        let encrypted_path = tmp_dir.join("test_aead_meta_encrypted.lvc");
        let decrypted_path = tmp_dir.join("test_aead_meta_decrypted.bin");
        let secret = "clave archivo segura 2026";
        let reference = "referencia segura 2026";
        let cajas = [5, 7, 2, 3, 9];
        let wrong_template = TemplateData {
            rows: 5,
            cols: 23,
            chars: filelivencrypt_template().chars.into_iter().rev().collect(),
        };

        std::fs::write(&original_path, b"payload autenticado").unwrap();
        FileCipher::encrypt_file_authenticated(
            &original_path,
            &encrypted_path,
            reference,
            &filelivencrypt_template(),
            cajas,
            secret,
        )
        .unwrap();

        assert!(FileCipher::decrypt_file_authenticated(
            &encrypted_path,
            &decrypted_path,
            reference,
            false,
            &wrong_template,
            cajas,
            secret,
        )
        .unwrap_err()
        .contains("plantilla"));

        assert!(FileCipher::decrypt_file_authenticated(
            &encrypted_path,
            &decrypted_path,
            reference,
            false,
            &filelivencrypt_template(),
            [5, 7, 2, 3, 8],
            secret,
        )
        .unwrap_err()
        .contains("cajas"));

        assert!(FileCipher::decrypt_file_authenticated(
            &encrypted_path,
            &decrypted_path,
            "otra referencia segura 2026",
            false,
            &filelivencrypt_template(),
            cajas,
            secret,
        )
        .unwrap_err()
        .contains("referencia"));

        let _ = std::fs::remove_file(&original_path);
        let _ = std::fs::remove_file(&encrypted_path);
        let _ = std::fs::remove_file(&decrypted_path);
    }
}
