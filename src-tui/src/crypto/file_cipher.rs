// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Motor de cifrado multihilo adaptativo de archivos en disco */

#![allow(clippy::too_many_arguments, clippy::needless_return)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{Rng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use zeroize::Zeroize;

/// Tareas paralelas ideales para procesar chunks — detectado en startup según CPU
static IDEAL_CHUNK_TASKS: AtomicUsize = AtomicUsize::new(24);
const STREAMING_BINARY_THRESHOLD_BYTES: u64 = 64 * 1024 * 1024;
const FILE_IO_BUFFER_BYTES: usize = 1024 * 1024;
const FILE_V2_MAGIC: [u8; 8] = *b"LVCF2\0\0\0";

#[derive(Serialize, Deserialize, Clone)]
struct FileKdfParams {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl Default for FileKdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id-v19".to_string(),
            memory_kib: 128 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct FileV2Header {
    magic: [u8; 8],
    version: u16,
    kdf: FileKdfParams,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    template_sha256: Vec<u8>,
    cajas_sha256: Vec<u8>,
    referencia_sha256: Vec<u8>,
    is_txt_output_hint: bool,
}

#[derive(Serialize, Deserialize)]
struct FileV2Envelope {
    header: FileV2Header,
    ciphertext: Vec<u8>,
}

/// Calcular chunk_size adaptativo continuo según tamaño × CPU.
/// Retorna None si el archivo es tan pequeño que conviene secuencial.
#[inline]
fn adaptive_chunk_size(total_chars: usize) -> Option<usize> {
    let tasks = IDEAL_CHUNK_TASKS.load(Ordering::Relaxed);
    let chars_per_task = 2_000_000; // punto de inflexión: 1 tarea más = vale la pena
    let min_parallel = 500_000; // por debajo de esto: secuencial

    // Cuántos chunks ideales: crece con el archivo hasta saturar los cores
    let ideal = (total_chars / chars_per_task).clamp(1, tasks);
    let size = total_chars / ideal;

    if size < min_parallel {
        None
    } else {
        Some(size.clamp(min_parallel, 20_000_000))
    }
}

/// Detectar núcleos CPU una vez al iniciar — llama desde lib.rs::run()
pub fn configure_chunk_tasks() {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let tasks = (cpus * 3).clamp(8, 48);
    IDEAL_CHUNK_TASKS.store(tasks, Ordering::Relaxed);
    println!(
        "[config] {} núcleos CPU → {} tareas paralelas por archivo",
        cpus, tasks
    );
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

fn write_file_synced(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(data).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    sync_parent_dir(path);
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn template_sha256(template: &crate::templates::TemplateData) -> Result<Vec<u8>, String> {
    let encoded = rmp_serde::to_vec(template)
        .map_err(|error| format!("No se pudo serializar plantilla para hash: {}", error))?;
    Ok(sha256_bytes(&encoded))
}

fn cajas_sha256(cajas: [i64; 5]) -> Vec<u8> {
    let mut material = Vec::new();
    for caja in cajas {
        material.extend_from_slice(&caja.to_le_bytes());
    }
    let out = sha256_bytes(&material);
    material.zeroize();
    out
}

fn derive_file_key(
    file_secret: &str,
    referencia: &str,
    cajas: [i64; 5],
    salt: &[u8],
    params: &FileKdfParams,
) -> Result<[u8; 32], String> {
    if params.algorithm != "argon2id-v19" {
        return Err(format!("KDF de archivo no soportado: {}", params.algorithm));
    }
    if file_secret.trim().chars().count() < 12 {
        return Err("La clave/frase de archivo debe tener al menos 12 caracteres.".to_string());
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|error| format!("Parametros Argon2 invalidos: {}", error))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut material = Vec::new();
    material.extend_from_slice(b"LIVENCRYPT-FILE-V2|");
    material.extend_from_slice(referencia.as_bytes());
    material.push(b'|');
    for caja in cajas {
        material.extend_from_slice(&caja.to_le_bytes());
    }
    material.push(b'|');
    material.extend_from_slice(file_secret.as_bytes());

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(&material, salt, &mut key)
        .map_err(|error| format!("No se pudo derivar clave de archivo: {}", error))?;
    material.zeroize();
    Ok(key)
}

fn derive_xor_seed(file_secret: &str, referencia: &str, cajas: [i64; 5]) -> [u8; 32] {
    // CWE-1204/CWE-329: una semilla o IV fijo permite correlacionar mensajes y
    // facilita ataques de diccionario. Esta semilla interna se deriva del secreto
    // de archivo y metadatos; el contenedor AEAD usa nonce aleatorio por cifrado.
    let mut material = Vec::new();
    material.extend_from_slice(b"LIVENCRYPT-FILE-INNER-SEED-V1|");
    material.extend_from_slice(file_secret.as_bytes());
    material.push(b'|');
    material.extend_from_slice(referencia.as_bytes());
    material.push(b'|');
    for caja in cajas {
        material.extend_from_slice(&caja.to_le_bytes());
    }

    let hash = Sha256::digest(&material);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash[..32]);
    material.zeroize();
    seed
}

fn seal_v2(
    plaintext: &[u8],
    header: FileV2Header,
    key: &[u8; 32],
) -> Result<FileV2Envelope, String> {
    if header.nonce.len() != 24 {
        return Err("Nonce AEAD invalido.".to_string());
    }
    let aad = rmp_serde::to_vec(&header)
        .map_err(|error| format!("No se pudo serializar AAD: {}", error))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(&header.nonce);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "Fallo AEAD al cifrar archivo.".to_string())?;
    Ok(FileV2Envelope { header, ciphertext })
}

fn open_v2(envelope: &FileV2Envelope, key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if envelope.header.magic != FILE_V2_MAGIC || envelope.header.version != 2 {
        return Err("Formato Livencrypt de archivo no soportado.".to_string());
    }
    if envelope.header.nonce.len() != 24 {
        return Err("Nonce AEAD invalido.".to_string());
    }
    let aad = rmp_serde::to_vec(&envelope.header)
        .map_err(|error| format!("No se pudo serializar AAD: {}", error))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(&envelope.header.nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: envelope.ciphertext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| {
            "Autenticacion AEAD fallida: archivo manipulado o clave incorrecta.".to_string()
        })
}

fn verify_file_readable(path: &Path) -> Result<(), String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        buffer[..read].zeroize();
    }
    Ok(())
}

fn promote_temp_file(temp_path: &Path, output_path: &Path) -> Result<(), String> {
    verify_file_readable(temp_path)?;
    std::fs::rename(temp_path, output_path).map_err(|error| error.to_string())?;
    sync_parent_dir(output_path);
    Ok(())
}

fn overwrite_and_remove_file(path: &Path) -> Result<(), String> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };

    if !metadata.is_file() {
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    let mut remaining = metadata.len().max(1);
    while remaining > 0 {
        let chunk_len = remaining.min(64 * 1024) as usize;
        file.write_all(&random_bytes(chunk_len))
            .map_err(|error| error.to_string())?;
        remaining = remaining.saturating_sub(chunk_len as u64);
    }
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    std::fs::remove_file(path).map_err(|error| error.to_string())?;
    sync_parent_dir(path);
    Ok(())
}

fn cleanup_temp_file(path: &Path) {
    let _ = overwrite_and_remove_file(path);
}

pub struct FileCipher;

impl FileCipher {
    pub fn encrypt_file_authenticated(
        input_path: &Path,
        output_path: &Path,
        referencia: &str,
        template: &crate::templates::TemplateData,
        cajas: [i64; 5],
        file_secret: &str,
    ) -> Result<(), String> {
        let inner_path = temp_inner_path(output_path);
        cleanup_temp_file(&inner_path);

        let mut xor_seed = derive_xor_seed(file_secret, referencia, cajas);
        let inner_result = Self::encrypt_file(
            input_path,
            &inner_path,
            referencia,
            template,
            cajas[0],
            cajas[1],
            cajas[2],
            cajas[3],
            cajas[4],
            &xor_seed,
        );
        xor_seed.zeroize();
        if let Err(error) = inner_result {
            cleanup_temp_file(&inner_path);
            return Err(error);
        }

        let mut inner = std::fs::read(&inner_path)
            .map_err(|error| format!("No se pudo leer payload interno: {}", error))?;
        cleanup_temp_file(&inner_path);

        let kdf = FileKdfParams::default();
        let salt = random_bytes(32);
        let nonce = random_bytes(24);
        // El nonce AEAD debe ser unico e impredecible por archivo; reutilizarlo
        // con la misma clave comprometeria la confidencialidad del ciphertext.
        let mut key = derive_file_key(file_secret, referencia, cajas, &salt, &kdf)?;

        let header = FileV2Header {
            magic: FILE_V2_MAGIC,
            version: 2,
            kdf,
            salt,
            nonce,
            template_sha256: template_sha256(template)?,
            // CWE-916: NO publicar SHA-256 sin sal de valores de baja entropía.
            // Las cajas y la referencia ya entran en la clave Argon2id+AEAD, así que
            // estos hashes eran redundantes y permitían fuerza bruta offline (recuperar
            // cajas/referencia sin pagar el coste del KDF). Se dejan vacíos; el AEAD es
            // la única autoridad. Los archivos antiguos siguen verificándose (ver decrypt).
            cajas_sha256: Vec::new(),
            referencia_sha256: Vec::new(),
            is_txt_output_hint: false,
        };

        let envelope = seal_v2(&inner, header, &key);
        inner.zeroize();
        key.zeroize();

        let envelope = envelope?;
        let encoded = rmp_serde::to_vec(&envelope)
            .map_err(|error| format!("No se pudo serializar archivo LVC v2: {}", error))?;
        write_file_synced(output_path, &encoded)
    }

    pub fn decrypt_file_authenticated(
        input_path: &Path,
        output_path: &Path,
        referencia: &str,
        is_txt_output: bool,
        template: &crate::templates::TemplateData,
        cajas: [i64; 5],
        file_secret: &str,
    ) -> Result<(), String> {
        let bytes = std::fs::read(input_path)
            .map_err(|error| format!("No se pudo leer archivo cifrado: {}", error))?;
        let envelope: FileV2Envelope = rmp_serde::from_slice(&bytes)
            .map_err(|error| format!("Archivo LVC v2 invalido: {}", error))?;

        if envelope.header.template_sha256 != template_sha256(template)? {
            return Err("La plantilla no coincide con la usada al cifrar.".to_string());
        }
        // Compatibilidad: archivos antiguos llevaban estos hashes; si están presentes
        // se siguen verificando. Los archivos nuevos los omiten y delegan en el AEAD
        // (cajas/referencia incorrectas -> fallo de autenticación AEAD igualmente).
        if !envelope.header.cajas_sha256.is_empty()
            && envelope.header.cajas_sha256 != cajas_sha256(cajas)
        {
            return Err("Las cajas no coinciden con las usadas al cifrar.".to_string());
        }
        if !envelope.header.referencia_sha256.is_empty()
            && envelope.header.referencia_sha256 != sha256_bytes(referencia.as_bytes())
        {
            return Err("La referencia no coincide con la usada al cifrar.".to_string());
        }

        let mut key = derive_file_key(
            file_secret,
            referencia,
            cajas,
            &envelope.header.salt,
            &envelope.header.kdf,
        )?;
        let mut inner = open_v2(&envelope, &key)?;
        key.zeroize();

        let inner_path = temp_inner_path(output_path);
        cleanup_temp_file(&inner_path);
        write_file_synced(&inner_path, &inner)?;
        inner.zeroize();

        let mut xor_seed = derive_xor_seed(file_secret, referencia, cajas);
        let result = Self::decrypt_file(
            &inner_path,
            output_path,
            referencia,
            is_txt_output,
            template,
            cajas[0],
            cajas[1],
            cajas[2],
            cajas[3],
            cajas[4],
            &xor_seed,
        );
        xor_seed.zeroize();
        cleanup_temp_file(&inner_path);
        result
    }

    pub fn encrypt_file(
        input_path: &Path,
        output_path: &Path,
        referencia: &str,
        template: &crate::templates::TemplateData,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        seed: &[u8; 32],
    ) -> Result<(), String> {
        let t_start = Instant::now();
        let metadata = std::fs::metadata(input_path).map_err(|e| e.to_string())?;
        let is_txt_input = input_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase() == "txt")
            .unwrap_or(false);

        if !is_txt_input && metadata.len() >= STREAMING_BINARY_THRESHOLD_BYTES {
            return Self::encrypt_file_streaming_binary(
                input_path,
                output_path,
                referencia,
                template,
                caja1,
                caja2,
                caja3,
                caja4,
                caja5,
                seed,
                t_start,
            );
        }

        let mut data = std::fs::read(input_path).map_err(|e| e.to_string())?;
        let mut payload = if is_txt_input {
            let compressed = Self::compress(&data)?;
            data.zeroize();
            compressed
        } else {
            std::mem::take(&mut data)
        };

        // Capa adicional sobre el payload interno serializado a hex.
        // Si seed = [0;32], el XOR es identidad para compatibilidad legacy.
        if seed.iter().any(|&b| b != 0) {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= seed[i % 32];
            }
        }

        let hex_string = hex::encode(&payload);
        payload.zeroize();

        let grid = template.as_grid();
        let rows = template.rows as usize;
        let cols = template.cols as usize;
        let is_filelivencrypt = rows == 5 && cols == 23;

        let encrypted_hex = if is_filelivencrypt {
            Self::procesar_texto_archivo(
                &hex_string,
                caja1,
                caja2,
                caja3,
                caja4,
                caja5,
                "cifrar",
                &grid,
            )
        } else {
            procesar_texto_archivo_variable(
                &hex_string,
                caja1,
                caja2,
                caja3,
                caja4,
                caja5,
                "cifrar",
                &grid,
                rows,
                cols,
            )
        };

        let sealed = if !referencia.is_empty() {
            Self::insertar_referencia_aleatoria(&encrypted_hex, referencia)
        } else {
            encrypted_hex
        };

        let compressed = Self::compress(sealed.as_bytes())?;
        write_file_synced(output_path, &compressed)?;
        let elapsed = t_start.elapsed().as_millis();
        println!(
            "[cipher] CIFRADO+COMPRESO {} → {} ({}ms, {} hex chars, {}×{})",
            input_path.file_name().unwrap_or_default().to_string_lossy(),
            output_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            elapsed,
            sealed.len(),
            rows,
            cols
        );
        Ok(())
    }

    pub fn decrypt_file(
        input_path: &Path,
        output_path: &Path,
        referencia: &str,
        is_txt_output: bool,
        template: &crate::templates::TemplateData,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        seed: &[u8; 32],
    ) -> Result<(), String> {
        let t_start = Instant::now();
        Self::decrypt_file_streaming(
            input_path,
            output_path,
            referencia,
            is_txt_output,
            template,
            caja1,
            caja2,
            caja3,
            caja4,
            caja5,
            seed,
            t_start,
        )
    }

    pub fn load_file_info(path: &Path) -> Result<FileInfo, String> {
        let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let size_bytes = metadata.len();

        let is_text = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase() == "txt")
            .unwrap_or(false);

        let hex_chars = if is_text {
            let data = std::fs::read(path).map_err(|e| e.to_string())?;
            let compressed = Self::compress(&data)?;
            (compressed.len() * 2) as u64
        } else {
            size_bytes * 2
        };

        Ok(FileInfo {
            name,
            size_bytes,
            hex_chars,
            is_compressed: is_text,
        })
    }

    fn encrypt_file_streaming_binary(
        input_path: &Path,
        output_path: &Path,
        referencia: &str,
        template: &crate::templates::TemplateData,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        seed: &[u8; 32],
        t_start: Instant,
    ) -> Result<(), String> {
        let input_len = std::fs::metadata(input_path)
            .map_err(|e| e.to_string())?
            .len();
        let total_chars_u64 = input_len
            .checked_mul(2)
            .ok_or("Archivo demasiado grande para indexado hex")?;
        let total_chars = usize::try_from(total_chars_u64)
            .map_err(|_| "Archivo demasiado grande para esta arquitectura")?;

        let grid = template.as_grid();
        let rows = template.rows as usize;
        let cols = template.cols as usize;
        if rows == 0 || cols == 0 {
            return Err("Plantilla de archivo vacia".into());
        }
        let char_map = build_char_map(&grid);
        let ref_pos = if referencia.is_empty() {
            None
        } else {
            Some(rand::thread_rng().gen_range(0..=total_chars))
        };

        let temp_path = temp_output_path(output_path);
        cleanup_temp_file(&temp_path);
        let write_result = (|| -> Result<(), String> {
            let input = File::open(input_path).map_err(|e| e.to_string())?;
            let output = File::create(&temp_path).map_err(|e| e.to_string())?;
            let mut reader = BufReader::with_capacity(FILE_IO_BUFFER_BYTES, input);
            let writer = BufWriter::with_capacity(FILE_IO_BUFFER_BYTES, output);
            let mut encoder =
                zstd::stream::write::Encoder::new(writer, 3).map_err(|e| e.to_string())?;

            let mut buffer = vec![0u8; FILE_IO_BUFFER_BYTES];
            let mut byte_offset = 0usize;
            let mut char_index = 0usize;
            let use_seed = seed.iter().any(|&b| b != 0);
            const HEX: &[u8; 16] = b"0123456789abcdef";

            loop {
                let n = reader.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                for (local_i, &raw) in buffer[..n].iter().enumerate() {
                    let absolute_byte = byte_offset + local_i;
                    let byte = if use_seed {
                        raw ^ seed[absolute_byte % 32]
                    } else {
                        raw
                    };
                    for nibble in [byte >> 4, byte & 0x0f] {
                        if ref_pos == Some(char_index) {
                            encoder
                                .write_all(referencia.as_bytes())
                                .map_err(|e| e.to_string())?;
                        }
                        let hex_char = HEX[nibble as usize] as char;
                        let encrypted = transform_file_char(
                            hex_char,
                            char_index,
                            total_chars,
                            caja1,
                            caja2,
                            caja3,
                            caja4,
                            caja5,
                            true,
                            &grid,
                            &char_map,
                            rows,
                            cols,
                        )?;
                        let mut out = [0u8; 4];
                        encoder
                            .write_all(encrypted.encode_utf8(&mut out).as_bytes())
                            .map_err(|e| e.to_string())?;
                        char_index += 1;
                    }
                }
                byte_offset += n;
                buffer[..n].zeroize();
            }

            if ref_pos == Some(total_chars) {
                encoder
                    .write_all(referencia.as_bytes())
                    .map_err(|e| e.to_string())?;
            }
            let mut writer = encoder.finish().map_err(|e| e.to_string())?;
            writer.flush().map_err(|e| e.to_string())?;
            writer.get_ref().sync_all().map_err(|e| e.to_string())?;
            Ok(())
        })();

        if let Err(e) = write_result {
            cleanup_temp_file(&temp_path);
            return Err(e);
        }

        if let Err(e) = promote_temp_file(&temp_path, output_path) {
            cleanup_temp_file(&temp_path);
            return Err(e);
        }

        let elapsed = t_start.elapsed().as_millis();
        println!(
            "[cipher] CIFRADO+COMPRESO streaming {} → {} ({}ms, {} hex chars, {}×{})",
            input_path.file_name().unwrap_or_default().to_string_lossy(),
            output_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            elapsed,
            total_chars,
            rows,
            cols
        );
        Ok(())
    }

    fn decrypt_file_streaming(
        input_path: &Path,
        output_path: &Path,
        referencia: &str,
        is_txt_output: bool,
        template: &crate::templates::TemplateData,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        seed: &[u8; 32],
        t_start: Instant,
    ) -> Result<(), String> {
        let grid = template.as_grid();
        let rows = template.rows as usize;
        let cols = template.cols as usize;
        if rows == 0 || cols == 0 {
            return Err("Plantilla de archivo vacia".into());
        }
        let char_map = build_char_map(&grid);
        let total_chars = count_clean_encrypted_chars(input_path, referencia)?;
        if total_chars % 2 != 0 {
            return Err("Hex descifrado con longitud impar".into());
        }

        let temp_path = temp_output_path(output_path);
        let decoded_temp_path = temp_path.with_extension("decoded.tmp");
        cleanup_temp_file(&temp_path);
        cleanup_temp_file(&decoded_temp_path);

        let write_result = (|| -> Result<(), String> {
            let decoded_output = File::create(&decoded_temp_path).map_err(|e| e.to_string())?;
            let mut decoded_writer = BufWriter::with_capacity(FILE_IO_BUFFER_BYTES, decoded_output);
            let use_seed = seed.iter().any(|&b| b != 0);
            let mut char_index = 0usize;
            let mut byte_index = 0usize;
            let mut high_nibble: Option<u8> = None;

            process_clean_encrypted_chars(input_path, referencia, |encrypted| {
                let hex_char = transform_file_char(
                    encrypted,
                    char_index,
                    total_chars,
                    caja1,
                    caja2,
                    caja3,
                    caja4,
                    caja5,
                    false,
                    &grid,
                    &char_map,
                    rows,
                    cols,
                )?;
                let nibble = hex_char
                    .to_digit(16)
                    .ok_or_else(|| format!("Hex invalido tras descifrar: {}", hex_char))?
                    as u8;
                if let Some(high) = high_nibble.take() {
                    let mut byte = (high << 4) | nibble;
                    if use_seed {
                        byte ^= seed[byte_index % 32];
                    }
                    decoded_writer
                        .write_all(&[byte])
                        .map_err(|e| e.to_string())?;
                    byte.zeroize();
                    byte_index += 1;
                } else {
                    high_nibble = Some(nibble);
                }
                char_index += 1;
                Ok(())
            })?;

            if high_nibble.is_some() {
                return Err("Hex descifrado con longitud impar".into());
            }
            decoded_writer.flush().map_err(|e| e.to_string())?;
            decoded_writer
                .get_ref()
                .sync_all()
                .map_err(|e| e.to_string())?;

            if is_txt_output {
                let decoded_input = File::open(&decoded_temp_path).map_err(|e| e.to_string())?;
                let mut temp_output = File::create(&temp_path).map_err(|e| e.to_string())?;
                match zstd::stream::copy_decode(decoded_input, &mut temp_output) {
                    Ok(_) => {
                        temp_output.sync_all().map_err(|e| e.to_string())?;
                        drop(temp_output);
                    }
                    Err(_) => {
                        drop(temp_output);
                        let mut decoded =
                            std::fs::read(&decoded_temp_path).map_err(|e| e.to_string())?;
                        write_file_synced(&temp_path, &decoded)?;
                        decoded.zeroize();
                    }
                }
                verify_file_readable(&temp_path)?;
            } else {
                promote_temp_file(&decoded_temp_path, &temp_path)?;
            }
            Ok(())
        })();

        if let Err(e) = write_result {
            cleanup_temp_file(&decoded_temp_path);
            cleanup_temp_file(&temp_path);
            return Err(e);
        }

        if let Err(e) = promote_temp_file(&temp_path, output_path) {
            cleanup_temp_file(&decoded_temp_path);
            cleanup_temp_file(&temp_path);
            return Err(e);
        }
        cleanup_temp_file(&decoded_temp_path);

        let elapsed = t_start.elapsed().as_millis();
        println!(
            "[cipher] DESCOMPRESO+DESCIFRADO streaming {} → {} ({}ms, {}×{})",
            input_path.file_name().unwrap_or_default().to_string_lossy(),
            output_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            elapsed,
            rows,
            cols
        );
        Ok(())
    }

    pub fn save_result(temp_path: &Path, save_path: &Path) -> Result<(), String> {
        std::fs::copy(temp_path, save_path).map_err(|e| e.to_string())?;
        overwrite_and_remove_file(temp_path)?;
        Ok(())
    }
}

#[derive(Serialize, Clone)]
pub struct FileInfo {
    pub name: String,
    pub size_bytes: u64,
    pub hex_chars: u64,
    pub is_compressed: bool,
}

impl FileCipher {
    // SAFETY: from_utf8_unchecked es seguro porque los bytes provienen de
    // char::encode_utf8() sobre chars de la grid, todos Unicode válidos.
    #[allow(unsafe_code)]
    pub fn procesar_texto_archivo(
        hex_text: &str,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        mode: &str,
        grid: &[Vec<char>],
    ) -> String {
        let chars: Vec<char> = hex_text.chars().collect();
        let total_chars = chars.len();
        let char_map = build_char_map(grid);

        // filelivencrypt grid is always 5 rows × 23 cols — constants enable LLVM strength reduction
        let is_cifrar = mode == "cifrar";

        // Decidir secuencial vs paralelo con chunk_size adaptativo continuo
        match adaptive_chunk_size(total_chars) {
            None => {
                // Secuencial: archivo demasiado pequeño para justificar rayon
                let mut out = Vec::with_capacity(total_chars + total_chars / 4);
                for (i, &c) in chars.iter().enumerate() {
                    if let Some(&(mut fila, mut columna)) = char_map.get(c) {
                        let indice: i64 = if is_cifrar {
                            (total_chars - i) as i64
                        } else {
                            (i + 1) as i64
                        };
                        let mut fc = columna as i64;
                        let mut fr = fila as i64;
                        if is_cifrar {
                            fc = (fc + caja1 - indice).rem_euclid(23);
                            fr = (fr + caja2 - indice).rem_euclid(5);
                            fc = (fc - caja3 + indice).rem_euclid(23);
                            fr = (fr - caja4 + indice).rem_euclid(5);
                        } else {
                            fr = (fr + caja4 - indice).rem_euclid(5);
                            fc = (fc + caja3 - indice).rem_euclid(23);
                            fr = (fr - caja2 + indice).rem_euclid(5);
                            fc = (fc - caja1 + indice).rem_euclid(23);
                        }
                        fila = fr as usize;
                        columna = fc as usize;
                        let movs = get_caja5_movements_inline(i as i64, caja5, total_chars);
                        for (mov_fila, mov_columna) in movs {
                            if is_cifrar {
                                fila = (fila as i64 + mov_fila).rem_euclid(5) as usize;
                                columna = (columna as i64 + mov_columna).rem_euclid(23) as usize;
                            } else {
                                fila = (fila as i64 - mov_fila).rem_euclid(5) as usize;
                                columna = (columna as i64 - mov_columna).rem_euclid(23) as usize;
                            }
                        }
                        let mut buf = [0u8; 4];
                        let encoded = grid[fila][columna].encode_utf8(&mut buf);
                        out.extend_from_slice(encoded.as_bytes());
                    }
                }
                // SAFETY: out contiene bytes de char::encode_utf8() sobre chars
                // de la grid, todos Unicode válidos. La concatenación de segmentos
                // UTF-8 válidos preserva UTF-8.
                return unsafe { String::from_utf8_unchecked(out) };
            }
            Some(chunk_size) => {
                // Paralelo con rayon: map produce Vec<u8> por chunk, merge secuencial al final
                let chunks: Vec<Vec<u8>> = chars
                    .par_chunks(chunk_size)
                    .enumerate()
                    .map(|(chunk_idx, chunk)| {
                        let offset = chunk_idx * chunk_size;
                        let mut out = Vec::with_capacity(chunk.len() + chunk.len() / 4);
                        for (local_i, &c) in chunk.iter().enumerate() {
                            let i = offset + local_i;
                            if let Some(&(mut fila, mut columna)) = char_map.get(c) {
                                let indice: i64 = if is_cifrar {
                                    (total_chars - i) as i64
                                } else {
                                    (i + 1) as i64
                                };
                                let mut fc = columna as i64;
                                let mut fr = fila as i64;

                                if is_cifrar {
                                    fc = (fc + caja1 - indice).rem_euclid(23);
                                    fr = (fr + caja2 - indice).rem_euclid(5);
                                    fc = (fc - caja3 + indice).rem_euclid(23);
                                    fr = (fr - caja4 + indice).rem_euclid(5);
                                } else {
                                    fr = (fr + caja4 - indice).rem_euclid(5);
                                    fc = (fc + caja3 - indice).rem_euclid(23);
                                    fr = (fr - caja2 + indice).rem_euclid(5);
                                    fc = (fc - caja1 + indice).rem_euclid(23);
                                }

                                fila = fr as usize;
                                columna = fc as usize;

                                let movs = get_caja5_movements_inline(i as i64, caja5, total_chars);
                                for (mov_fila, mov_columna) in movs {
                                    if is_cifrar {
                                        fila = (fila as i64 + mov_fila).rem_euclid(5) as usize;
                                        columna =
                                            (columna as i64 + mov_columna).rem_euclid(23) as usize;
                                    } else {
                                        fila = (fila as i64 - mov_fila).rem_euclid(5) as usize;
                                        columna =
                                            (columna as i64 - mov_columna).rem_euclid(23) as usize;
                                    }
                                }

                                let mut buf = [0u8; 4];
                                let encoded = grid[fila][columna].encode_utf8(&mut buf);
                                out.extend_from_slice(encoded.as_bytes());
                            }
                        }
                        out
                    })
                    .collect();

                // Merge secuencial — una sola pasada, sin merges en árbol binario
                let total_bytes: usize = chunks.iter().map(|v| v.len()).sum();
                let mut resultado = Vec::with_capacity(total_bytes);
                for chunk in chunks {
                    resultado.extend_from_slice(&chunk);
                }
                // SAFETY: cada chunk contiene solo bytes de encode_utf8(),
                // la concatenación preserva UTF-8.
                unsafe { String::from_utf8_unchecked(resultado) }
            }
        }
    }
}

/// Dual-lookup: array[128] para ASCII (1ns, sin hashing) + HashMap para Unicode
struct CharLookup {
    ascii: [Option<(usize, usize)>; 128],
    unicode: HashMap<char, (usize, usize)>,
}

impl CharLookup {
    #[inline]
    fn get(&self, c: char) -> Option<&(usize, usize)> {
        let byte = c as u32;
        if byte < 128 {
            self.ascii[byte as usize].as_ref()
        } else {
            self.unicode.get(&c)
        }
    }
}

/// Build dual lookup: array (ASCII hex) + HashMap (Unicode grid chars)
fn build_char_map(grid: &[Vec<char>]) -> CharLookup {
    let mut ascii: [Option<(usize, usize)>; 128] = [None; 128];
    let mut unicode = HashMap::with_capacity(grid.iter().map(|r| r.len()).sum());

    for (r, row) in grid.iter().enumerate() {
        for (c, &cell) in row.iter().enumerate() {
            let lower = cell.to_lowercase().next().unwrap_or(cell);
            let upper = cell.to_uppercase().next().unwrap_or(cell);

            // ASCII chars → array (fast path)
            for &ch in &[lower, upper] {
                let byte = ch as u32;
                if byte < 128 {
                    ascii[byte as usize] = Some((r, c));
                } else {
                    unicode.entry(ch).or_insert((r, c));
                }
            }
        }
    }
    CharLookup { ascii, unicode }
}

fn temp_output_path(output_path: &Path) -> PathBuf {
    let extension = output_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!("{}.tmp", ext))
        .unwrap_or_else(|| "tmp".to_string());
    output_path.with_extension(extension)
}

fn temp_inner_path(output_path: &Path) -> PathBuf {
    output_path.with_extension(format!("inner-{}.tmp", std::process::id()))
}

fn count_clean_encrypted_chars(input_path: &Path, referencia: &str) -> Result<usize, String> {
    let mut count = 0usize;
    process_clean_encrypted_chars(input_path, referencia, |_| {
        count = count.saturating_add(1);
        Ok(())
    })?;
    Ok(count)
}

fn process_clean_encrypted_chars<F>(
    input_path: &Path,
    referencia: &str,
    mut on_char: F,
) -> Result<(), String>
where
    F: FnMut(char) -> Result<(), String>,
{
    let input = File::open(input_path).map_err(|e| e.to_string())?;
    let mut decoder = zstd::stream::read::Decoder::new(input).map_err(|e| e.to_string())?;
    let reference: Vec<char> = referencia.chars().collect();
    let has_reference = !reference.is_empty();
    let mut matcher = ReferenceSkipper::new(reference);
    let mut bytes = vec![0u8; FILE_IO_BUFFER_BYTES];
    let mut pending = Vec::<u8>::new();

    loop {
        let n = decoder.read(&mut bytes).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        pending.extend_from_slice(&bytes[..n]);
        consume_valid_utf8_prefix(&mut pending, |ch| {
            if !has_reference && (ch == '\n' || ch == ' ') {
                return Ok(());
            }
            matcher.push(ch, &mut on_char)
        })?;
    }

    if !pending.is_empty() {
        consume_valid_utf8_prefix(&mut pending, |ch| {
            if !has_reference && (ch == '\n' || ch == ' ') {
                return Ok(());
            }
            matcher.push(ch, &mut on_char)
        })?;
        if !pending.is_empty() {
            return Err("Datos cifrados corruptos: UTF-8 truncado".into());
        }
    }
    matcher.finish(&mut on_char)
}

fn consume_valid_utf8_prefix<F>(bytes: &mut Vec<u8>, mut on_char: F) -> Result<(), String>
where
    F: FnMut(char) -> Result<(), String>,
{
    let valid_len = match std::str::from_utf8(bytes) {
        Ok(text) => {
            for ch in text.chars() {
                on_char(ch)?;
            }
            bytes.clear();
            return Ok(());
        }
        Err(e) => {
            if e.error_len().is_some() {
                return Err("Datos cifrados corruptos: UTF-8 invalido".into());
            }
            e.valid_up_to()
        }
    };

    if valid_len > 0 {
        let text = std::str::from_utf8(&bytes[..valid_len])
            .map_err(|_| "Datos cifrados corruptos: UTF-8 invalido".to_string())?;
        for ch in text.chars() {
            on_char(ch)?;
        }
        bytes.drain(..valid_len);
    }
    Ok(())
}

struct ReferenceSkipper {
    reference: Vec<char>,
    pending: Vec<char>,
    skipped: bool,
}

impl ReferenceSkipper {
    fn new(reference: Vec<char>) -> Self {
        Self {
            reference,
            pending: Vec::new(),
            skipped: false,
        }
    }

    fn push<F>(&mut self, ch: char, emit: &mut F) -> Result<(), String>
    where
        F: FnMut(char) -> Result<(), String>,
    {
        if self.skipped || self.reference.is_empty() {
            return emit(ch);
        }

        self.pending.push(ch);
        loop {
            if self.pending == self.reference {
                self.pending.clear();
                self.skipped = true;
                return Ok(());
            }
            if self.reference.starts_with(&self.pending) {
                return Ok(());
            }
            let first = self.pending.remove(0);
            emit(first)?;
            if self.pending.is_empty() {
                return Ok(());
            }
        }
    }

    fn finish<F>(&mut self, emit: &mut F) -> Result<(), String>
    where
        F: FnMut(char) -> Result<(), String>,
    {
        for ch in self.pending.drain(..) {
            emit(ch)?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn transform_file_char(
    c: char,
    i: usize,
    total_chars: usize,
    caja1: i64,
    caja2: i64,
    caja3: i64,
    caja4: i64,
    caja5: i64,
    is_cifrar: bool,
    grid: &[Vec<char>],
    char_map: &CharLookup,
    rows: usize,
    cols: usize,
) -> Result<char, String> {
    let Some(&(mut fila, mut columna)) = char_map.get(c) else {
        return Err(format!(
            "caracter fuera de grid para cifrado de archivo: {}",
            c
        ));
    };
    let rows_i = rows as i64;
    let cols_i = cols as i64;
    let indice: i64 = if is_cifrar {
        (total_chars - i) as i64
    } else {
        (i + 1) as i64
    };
    let mut fc = columna as i64;
    let mut fr = fila as i64;
    if is_cifrar {
        fc = (fc + caja1 - indice).rem_euclid(cols_i);
        fr = (fr + caja2 - indice).rem_euclid(rows_i);
        fc = (fc - caja3 + indice).rem_euclid(cols_i);
        fr = (fr - caja4 + indice).rem_euclid(rows_i);
    } else {
        fr = (fr + caja4 - indice).rem_euclid(rows_i);
        fc = (fc + caja3 - indice).rem_euclid(cols_i);
        fr = (fr - caja2 + indice).rem_euclid(rows_i);
        fc = (fc - caja1 + indice).rem_euclid(cols_i);
    }
    fila = fr as usize;
    columna = fc as usize;
    let movs = get_caja5_movements_inline(i as i64, caja5, total_chars);
    for (mov_fila, mov_columna) in movs {
        if is_cifrar {
            fila = (fila as i64 + mov_fila).rem_euclid(rows_i) as usize;
            columna = (columna as i64 + mov_columna).rem_euclid(cols_i) as usize;
        } else {
            fila = (fila as i64 - mov_fila).rem_euclid(rows_i) as usize;
            columna = (columna as i64 - mov_columna).rem_euclid(cols_i) as usize;
        }
    }
    Ok(grid[fila][columna])
}

/// Variable path: cualquier plantilla personalizada (N×M) — sin optimización LLVM
#[allow(unsafe_code)]
fn procesar_texto_archivo_variable(
    hex_text: &str,
    caja1: i64,
    caja2: i64,
    caja3: i64,
    caja4: i64,
    caja5: i64,
    mode: &str,
    grid: &[Vec<char>],
    rows: usize,
    cols: usize,
) -> String {
    let chars: Vec<char> = hex_text.chars().collect();
    let total_chars = chars.len();
    let char_map = build_char_map(grid);

    let rows_i = rows as i64;
    let cols_i = cols as i64;
    let is_cifrar = mode == "cifrar";

    match adaptive_chunk_size(total_chars) {
        None => {
            let mut out = Vec::with_capacity(total_chars + total_chars / 4);
            for (i, &c) in chars.iter().enumerate() {
                if let Some(&(mut fila, mut columna)) = char_map.get(c) {
                    let indice: i64 = if is_cifrar {
                        (total_chars - i) as i64
                    } else {
                        (i + 1) as i64
                    };
                    let mut fc = columna as i64;
                    let mut fr = fila as i64;
                    if is_cifrar {
                        fc = (fc + caja1 - indice).rem_euclid(cols_i);
                        fr = (fr + caja2 - indice).rem_euclid(rows_i);
                        fc = (fc - caja3 + indice).rem_euclid(cols_i);
                        fr = (fr - caja4 + indice).rem_euclid(rows_i);
                    } else {
                        fr = (fr + caja4 - indice).rem_euclid(rows_i);
                        fc = (fc + caja3 - indice).rem_euclid(cols_i);
                        fr = (fr - caja2 + indice).rem_euclid(rows_i);
                        fc = (fc - caja1 + indice).rem_euclid(cols_i);
                    }
                    fila = fr as usize;
                    columna = fc as usize;
                    let movs = get_caja5_movements_inline(i as i64, caja5, total_chars);
                    for (mov_fila, mov_columna) in movs {
                        if is_cifrar {
                            fila = (fila as i64 + mov_fila).rem_euclid(rows_i) as usize;
                            columna = (columna as i64 + mov_columna).rem_euclid(cols_i) as usize;
                        } else {
                            fila = (fila as i64 - mov_fila).rem_euclid(rows_i) as usize;
                            columna = (columna as i64 - mov_columna).rem_euclid(cols_i) as usize;
                        }
                    }
                    let mut buf = [0u8; 4];
                    let encoded = grid[fila][columna].encode_utf8(&mut buf);
                    out.extend_from_slice(encoded.as_bytes());
                }
            }
            // SAFETY: out contiene bytes de encode_utf8() de chars de grid.
            // Cada carácter Unicode codificado en UTF-8 es válido.
            return unsafe { String::from_utf8_unchecked(out) };
        }
        Some(chunk_size) => {
            let chunks: Vec<Vec<u8>> = chars
                .par_chunks(chunk_size)
                .enumerate()
                .map(|(chunk_idx, chunk)| {
                    let offset = chunk_idx * chunk_size;
                    let mut out = Vec::with_capacity(chunk.len() + chunk.len() / 4);
                    for (local_i, &c) in chunk.iter().enumerate() {
                        let i = offset + local_i;
                        if let Some(&(mut fila, mut columna)) = char_map.get(c) {
                            let indice: i64 = if is_cifrar {
                                (total_chars - i) as i64
                            } else {
                                (i + 1) as i64
                            };
                            let mut fc = columna as i64;
                            let mut fr = fila as i64;
                            if is_cifrar {
                                fc = (fc + caja1 - indice).rem_euclid(cols_i);
                                fr = (fr + caja2 - indice).rem_euclid(rows_i);
                                fc = (fc - caja3 + indice).rem_euclid(cols_i);
                                fr = (fr - caja4 + indice).rem_euclid(rows_i);
                            } else {
                                fr = (fr + caja4 - indice).rem_euclid(rows_i);
                                fc = (fc + caja3 - indice).rem_euclid(cols_i);
                                fr = (fr - caja2 + indice).rem_euclid(rows_i);
                                fc = (fc - caja1 + indice).rem_euclid(cols_i);
                            }
                            fila = fr as usize;
                            columna = fc as usize;
                            let movs = get_caja5_movements_inline(i as i64, caja5, total_chars);
                            for (mov_fila, mov_columna) in movs {
                                if is_cifrar {
                                    fila = (fila as i64 + mov_fila).rem_euclid(rows_i) as usize;
                                    columna =
                                        (columna as i64 + mov_columna).rem_euclid(cols_i) as usize;
                                } else {
                                    fila = (fila as i64 - mov_fila).rem_euclid(rows_i) as usize;
                                    columna =
                                        (columna as i64 - mov_columna).rem_euclid(cols_i) as usize;
                                }
                            }
                            let mut buf = [0u8; 4];
                            let encoded = grid[fila][columna].encode_utf8(&mut buf);
                            out.extend_from_slice(encoded.as_bytes());
                        }
                    }
                    out
                })
                .collect();
            let total_bytes: usize = chunks.iter().map(|v| v.len()).sum();
            let mut resultado = Vec::with_capacity(total_bytes);
            for chunk in chunks {
                resultado.extend_from_slice(&chunk);
            }
            // SAFETY: chunks generados con encode_utf8() → concatenación UTF-8 válida.
            unsafe { String::from_utf8_unchecked(resultado) }
        }
    }
}

/// Inline caja5 movements — odd indices keep Livencrypt 1.1, even indices use the 2.0 mirror.
#[inline(always)]
fn get_caja5_movements_inline(i: i64, caja5: i64, total_chars: usize) -> &'static [(i64, i64)] {
    if caja5 == (total_chars as i64) - 1 {
        return &[];
    }

    match (i.rem_euclid(2), caja5.rem_euclid(4)) {
        (1, 0) => &[(2, 0), (0, 1)],
        (1, 1) => &[(0, 2), (1, 0)],
        (1, 2) => &[(-2, 0), (0, -1)],
        (1, _) => &[(0, -2), (-1, 0)],
        (0, 0) => &[(-2, 0), (0, -1)],
        (0, 1) => &[(0, -2), (-1, 0)],
        (0, 2) => &[(2, 0), (0, 1)],
        _ => &[(0, 2), (1, 0)],
    }
}

#[doc(hidden)]
impl FileCipher {
    pub fn get_caja5_movements_test(i: i64, caja5: i64, total_chars: usize) -> Vec<(i64, i64)> {
        get_caja5_movements_inline(i, caja5, total_chars).to_vec()
    }

    #[doc(hidden)]
    pub fn encrypt_file_streaming_binary_for_test(
        input_path: &Path,
        output_path: &Path,
        referencia: &str,
        template: &crate::templates::TemplateData,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        seed: &[u8; 32],
    ) -> Result<(), String> {
        Self::encrypt_file_streaming_binary(
            input_path,
            output_path,
            referencia,
            template,
            caja1,
            caja2,
            caja3,
            caja4,
            caja5,
            seed,
            Instant::now(),
        )
    }

    #[doc(hidden)]
    pub fn decrypt_file_streaming_for_test(
        input_path: &Path,
        output_path: &Path,
        referencia: &str,
        is_txt_output: bool,
        template: &crate::templates::TemplateData,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        seed: &[u8; 32],
    ) -> Result<(), String> {
        Self::decrypt_file_streaming(
            input_path,
            output_path,
            referencia,
            is_txt_output,
            template,
            caja1,
            caja2,
            caja3,
            caja4,
            caja5,
            seed,
            Instant::now(),
        )
    }

    fn insertar_referencia_aleatoria(content: &str, referencia: &str) -> String {
        let mut rng = rand::thread_rng();
        let char_count = content.chars().count();
        let char_pos = rng.gen_range(0..=char_count);
        let byte_pos = content
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(content.len()))
            .nth(char_pos)
            .unwrap_or(0);
        let mut result = String::with_capacity(content.len() + referencia.len());
        result.push_str(&content[..byte_pos]);
        result.push_str(referencia);
        result.push_str(&content[byte_pos..]);
        result
    }

    fn compress(data: &[u8]) -> Result<Vec<u8>, String> {
        zstd::encode_all(data, 3).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod authenticated_inner_seed_tests {
    use super::derive_xor_seed;

    #[test]
    fn xor_seed_changes_with_secret() {
        let cajas = [1, 2, 3, 4, 5];
        let referencia = "referencia archivo visible";
        let seed_a = derive_xor_seed("clave archivo independiente A", referencia, cajas);
        let seed_b = derive_xor_seed("clave archivo independiente B", referencia, cajas);

        assert_ne!(seed_a, seed_b);
    }

    #[test]
    fn encrypt_file_inner_not_zero_seed() {
        let seed = derive_xor_seed(
            "clave archivo independiente",
            "referencia archivo visible",
            [1, 2, 3, 4, 5],
        );

        assert_ne!(seed, [0u8; 32]);
    }
}
