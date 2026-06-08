// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: verificación pre-arranque y sellado ChaCha20Poly1305 de la configuración de initramfs */

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"LVCBOOT1";
const NONCE_LEN: usize = 12;

pub struct BootKey {
    key: [u8; 32],
}

impl Drop for BootKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl BootKey {
    pub fn from_hex(hex_key: &str) -> Result<Self, String> {
        let raw = hex::decode(hex_key.trim())
            .map_err(|_| "clave de Boot Shield invalida (hexadecimal)".to_string())?;
        if raw.len() != 32 {
            return Err("la clave de Boot Shield debe ser de 32 bytes (64 hex)".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        Ok(Self { key })
    }

    pub fn from_passphrase(passphrase: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"LIVENCRYPT-BOOT-SHIELD-KDF-V1");
        hasher.update(passphrase.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&hasher.finalize());
        Self { key }
    }
}

pub fn seal_config(key: &BootKey, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: MAGIC,
            },
        )
        .map_err(|_| "fallo ChaCha20Poly1305 al sellar la configuracion de arranque".to_string())?;

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open_config(key: &BootKey, sealed: &[u8]) -> Result<Vec<u8>, String> {
    let header = MAGIC.len() + NONCE_LEN;
    if sealed.len() <= header || &sealed[..MAGIC.len()] != MAGIC {
        return Err("contenedor de arranque no reconocido".into());
    }
    let nonce = &sealed[MAGIC.len()..header];
    let ciphertext = &sealed[header..];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: MAGIC,
            },
        )
        .map_err(|_| {
            "verificacion de arranque fallida: configuracion manipulada o clave incorrecta"
                .to_string()
        })
}

pub fn verify_config(key: &BootKey, sealed: &[u8]) -> bool {
    open_config(key, sealed).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_shield_seal_open_roundtrip() {
        let key = BootKey::from_passphrase("frase de arranque del sistema");
        let sealed = seal_config(&key, b"configuracion critica").expect("sellar");
        assert_eq!(
            open_config(&key, &sealed).expect("abrir"),
            b"configuracion critica"
        );
        assert!(verify_config(&key, &sealed));
    }

    #[test]
    fn boot_shield_rejects_tampered_container() {
        let key = BootKey::from_passphrase("frase de arranque del sistema");
        let mut sealed = seal_config(&key, b"configuracion critica").expect("sellar");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x55;
        assert!(!verify_config(&key, &sealed));
    }

    #[test]
    fn boot_shield_rejects_wrong_key() {
        let key = BootKey::from_passphrase("frase correcta");
        let sealed = seal_config(&key, b"config").expect("sellar");
        let other = BootKey::from_passphrase("frase incorrecta");
        assert!(!verify_config(&other, &sealed));
    }
}
