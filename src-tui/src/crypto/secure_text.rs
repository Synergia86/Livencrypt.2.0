// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: cifrado autenticado de texto con Argon2id y XChaCha20Poly1305 */

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"LVCT";
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;

fn argon2id() -> Result<Argon2<'static>, String> {
    let params = Params::new(131_072, 3, 1, Some(32))
        .map_err(|error| format!("parametros Argon2id invalidos: {}", error))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn derive_key(secret: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    // Normalizacion NFC: dos cadenas visualmente identicas con distinta composicion
    // Unicode deben derivar la misma clave. Sin validacion de longitud minima: el
    // motor Argon2id acepta cualquier tamano sin filtrar para no exponer canal lateral.
    let mut normalized: String = secret.nfc().collect();
    let mut key = [0u8; 32];
    let result = argon2id()?.hash_password_into(normalized.as_bytes(), salt, &mut key);
    normalized.zeroize();
    result.map_err(|error| format!("no se pudo derivar la clave de texto: {}", error))?;
    Ok(key)
}

pub fn encrypt_text(plaintext: &str, secret: &str) -> Result<String, String> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut header = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let mut key = derive_key(secret, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher.encrypt(
        XNonce::from_slice(&nonce),
        Payload {
            msg: plaintext.as_bytes(),
            aad: &header,
        },
    );
    key.zeroize();
    let ciphertext = ciphertext.map_err(|_| "fallo AEAD al cifrar texto".to_string())?;

    let mut envelope = header;
    envelope.extend_from_slice(&ciphertext);
    Ok(hex::encode(envelope))
}

pub fn decrypt_text(token: &str, secret: &str) -> Result<String, String> {
    let raw = hex::decode(token.trim())
        .map_err(|_| "texto cifrado Livencrypt invalido (no es hexadecimal)".to_string())?;
    let header_len = MAGIC.len() + SALT_LEN + NONCE_LEN;
    if raw.len() <= header_len || &raw[..MAGIC.len()] != MAGIC {
        return Err("texto cifrado Livencrypt no reconocido".to_string());
    }
    let salt = &raw[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce = &raw[MAGIC.len() + SALT_LEN..header_len];
    let ciphertext = &raw[header_len..];

    let mut key = derive_key(secret, salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher.decrypt(
        XNonce::from_slice(nonce),
        Payload {
            msg: ciphertext,
            aad: &raw[..header_len],
        },
    );
    key.zeroize();
    let plaintext = plaintext
        .map_err(|_| "autenticacion AEAD fallida: texto manipulado o clave incorrecta".to_string())?;

    String::from_utf8(plaintext).map_err(|_| "el texto descifrado no es UTF-8 valido".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_text_roundtrip() {
        let secret = "clave de texto segura 2026";
        let token = encrypt_text("mensaje confidencial", secret).expect("cifrar");
        assert_eq!(decrypt_text(&token, secret).expect("descifrar"), "mensaje confidencial");
    }

    #[test]
    fn secure_text_wrong_secret_fails() {
        let token = encrypt_text("mensaje", "clave correcta 2026").expect("cifrar");
        assert!(decrypt_text(&token, "clave erronea 2026xx").is_err());
    }

    #[test]
    fn secure_text_is_not_deterministic() {
        let secret = "clave de texto segura 2026";
        let a = encrypt_text("mismo mensaje", secret).unwrap();
        let b = encrypt_text("mismo mensaje", secret).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn secure_text_accepts_any_secret_length() {
        let token = encrypt_text("dato", "ab").expect("cifrar clave corta");
        assert_eq!(decrypt_text(&token, "ab").expect("descifrar"), "dato");
    }
}
