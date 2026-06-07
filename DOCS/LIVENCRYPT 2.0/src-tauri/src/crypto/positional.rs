// SPDX-License-Identifier: GPL-3.0-or-later

use crate::templates::TemplateData;
use serde::Serialize;

pub struct PositionalCipher {
    pub grid: Vec<Vec<char>>,
    pub template: TemplateData,
}

#[derive(Serialize, Clone)]
pub struct CipherResult {
    pub result: String,
    pub detected_password: Option<String>,
}

pub const DEFAULT_CONTROL_SYMBOLS: &str = "¢|@#~½¶←↓→ˀ|¢ª─¬";
pub const PASSWORD_DIRECTION_AFTER: &str = "after";
pub const PASSWORD_DIRECTION_BEFORE: &str = "before";

pub fn normalize_control_symbols(symbols: &str) -> String {
    let mut normalized = String::new();
    for symbol in symbols.chars().filter(|symbol| !symbol.is_whitespace()) {
        if !normalized.contains(symbol) {
            normalized.push(symbol);
        }
    }

    if normalized.is_empty() {
        DEFAULT_CONTROL_SYMBOLS.to_string()
    } else {
        normalized
    }
}

pub fn normalize_password_direction(direction: &str) -> String {
    match direction {
        PASSWORD_DIRECTION_AFTER => PASSWORD_DIRECTION_AFTER.to_string(),
        _ => PASSWORD_DIRECTION_BEFORE.to_string(),
    }
}

impl PositionalCipher {
    pub fn new(template: TemplateData) -> Self {
        let grid = template.as_grid();
        Self { grid, template }
    }

    pub fn cifrar(
        &self,
        texto: &str,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        password_len: usize,
    ) -> CipherResult {
        self.cifrar_with_password_config(
            texto,
            caja1,
            caja2,
            caja3,
            caja4,
            caja5,
            password_len,
            PASSWORD_DIRECTION_BEFORE,
            DEFAULT_CONTROL_SYMBOLS,
        )
    }

    pub fn cifrar_with_password_config(
        &self,
        texto: &str,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        password_len: usize,
        password_direction: &str,
        control_symbols: &str,
    ) -> CipherResult {
        let control_symbols = normalize_control_symbols(control_symbols);
        let password_direction = normalize_password_direction(password_direction);
        let result = self.ocultar_palabra_with_control_symbols(
            texto,
            caja1,
            caja2,
            caja3,
            caja4,
            caja5,
            "cifrar",
            &control_symbols,
        );
        let password = Self::extract_control_password(
            texto,
            password_len,
            &password_direction,
            &control_symbols,
        );
        CipherResult {
            result,
            detected_password: password,
        }
    }

    pub fn cifrar_raw(
        &self,
        texto: &str,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
    ) -> String {
        self.ocultar_palabra_internal(
            texto,
            caja1,
            caja2,
            caja3,
            caja4,
            caja5,
            "cifrar",
            false,
            false,
            DEFAULT_CONTROL_SYMBOLS,
        )
    }

    pub fn descifrar(
        &self,
        texto: &str,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        password_len: usize,
    ) -> CipherResult {
        self.descifrar_with_password_config(
            texto,
            caja1,
            caja2,
            caja3,
            caja4,
            caja5,
            password_len,
            PASSWORD_DIRECTION_BEFORE,
            DEFAULT_CONTROL_SYMBOLS,
        )
    }

    pub fn descifrar_with_password_config(
        &self,
        texto: &str,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        password_len: usize,
        password_direction: &str,
        control_symbols: &str,
    ) -> CipherResult {
        let control_symbols = normalize_control_symbols(control_symbols);
        let password_direction = normalize_password_direction(password_direction);
        let result = self.ocultar_palabra_with_control_symbols(
            texto,
            -caja1,
            -caja2,
            -caja3,
            -caja4,
            caja5,
            "descifrar",
            &control_symbols,
        );
        let password = Self::intercept_and_decipher_control(
            texto,
            caja1,
            caja2,
            caja3,
            caja4,
            caja5,
            password_len,
            &password_direction,
            &control_symbols,
            &self,
        );
        CipherResult {
            result,
            detected_password: password,
        }
    }

    pub fn descifrar_raw(
        &self,
        texto: &str,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
    ) -> String {
        self.ocultar_palabra_internal(
            texto,
            -caja1,
            -caja2,
            -caja3,
            -caja4,
            caja5,
            "descifrar",
            false,
            false,
            DEFAULT_CONTROL_SYMBOLS,
        )
    }

    fn extract_control_password(
        text: &str,
        len: usize,
        password_direction: &str,
        control_symbols: &str,
    ) -> Option<String> {
        if len == 0 {
            return None;
        }
        let chars: Vec<char> = text.chars().collect();
        let plen = len.max(2);
        Self::extract_control_segment(&chars, plen, password_direction, control_symbols)
    }

    fn intercept_and_decipher_control(
        text: &str,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        len: usize,
        password_direction: &str,
        control_symbols: &str,
        cipher: &Self,
    ) -> Option<String> {
        if len == 0 {
            return None;
        }
        let chars: Vec<char> = text.chars().collect();
        let plen = len.max(2);
        let segment =
            Self::extract_control_segment(&chars, plen, password_direction, control_symbols)?;
        let deciphered = cipher.ocultar_palabra_with_control_symbols(
            &segment,
            -caja1,
            -caja2,
            -caja3,
            -caja4,
            caja5,
            "descifrar",
            control_symbols,
        );
        Some(deciphered)
    }

    fn extract_control_segment(
        chars: &[char],
        plen: usize,
        password_direction: &str,
        control_symbols: &str,
    ) -> Option<String> {
        for (index, char_value) in chars.iter().enumerate() {
            if !control_symbols.contains(*char_value) {
                continue;
            }

            if password_direction == PASSWORD_DIRECTION_AFTER {
                if index + 1 >= plen {
                    return Some(chars[index + 1 - plen..index + 1].iter().collect());
                }
            } else if index + plen <= chars.len() {
                return Some(chars[index..index + plen].iter().collect());
            }
        }

        None
    }

    pub fn ocultar_palabra(
        &self,
        palabra: &str,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        modo: &str,
    ) -> String {
        self.ocultar_palabra_with_control_symbols(
            palabra,
            caja1,
            caja2,
            caja3,
            caja4,
            caja5,
            modo,
            DEFAULT_CONTROL_SYMBOLS,
        )
    }

    fn ocultar_palabra_with_control_symbols(
        &self,
        palabra: &str,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        modo: &str,
        control_symbols: &str,
    ) -> String {
        self.ocultar_palabra_internal(
            palabra,
            caja1,
            caja2,
            caja3,
            caja4,
            caja5,
            modo,
            true,
            true,
            control_symbols,
        )
    }

    fn ocultar_palabra_internal(
        &self,
        palabra: &str,
        caja1: i64,
        caja2: i64,
        caja3: i64,
        caja4: i64,
        caja5: i64,
        modo: &str,
        preserve_case: bool,
        preserve_control_symbols: bool,
        control_symbols: &str,
    ) -> String {
        let mut resultado = String::with_capacity(palabra.len());
        let espacio_en_plantilla = self.template.space_in_template(&self.grid);
        let total_chars = palabra.chars().count();
        let indice = total_chars as i64;

        for (i, caracter) in palabra.chars().enumerate() {
            if preserve_control_symbols && control_symbols.contains(caracter) {
                resultado.push(caracter);
                continue;
            }

            let caracter_busqueda = if caracter == ' ' { '␣' } else { caracter };
            let pos = self.template.find_position(&self.grid, caracter_busqueda);

            if let Some((fila, columna)) = pos {
                let mut c = columna as i64;
                let mut f = fila as i64;

                c += caja1 - indice;
                f += caja2 - indice;
                c -= caja3 - indice;
                f -= caja4 - indice;

                let nr = f.rem_euclid(self.template.rows as i64) as usize;
                let nc = c.rem_euclid(self.template.cols as i64) as usize;

                // ── caja5 — idéntico a Python 1.1 obtener_movimientos_caja5 ──
                let mut fr = nr as i64;
                let mut fc = nc as i64;
                for (mf, mc) in caja5_movements(i as i64, caja5, total_chars) {
                    if modo == "cifrar" {
                        fr += mf;
                        fc += mc;
                    } else {
                        fr -= mf;
                        fc -= mc;
                    }
                }
                let nr_final = fr.rem_euclid(self.template.rows as i64) as usize;
                let nc_final = fc.rem_euclid(self.template.cols as i64) as usize;

                let mut nuevo_caracter = self.grid[nr_final][nc_final];
                if modo == "descifrar" && nuevo_caracter == '␣' {
                    nuevo_caracter = ' ';
                }
                if preserve_case && caracter.is_uppercase() {
                    nuevo_caracter = nuevo_caracter
                        .to_uppercase()
                        .next()
                        .unwrap_or(nuevo_caracter);
                }
                resultado.push(nuevo_caracter);
            } else if caracter == ' ' && !espacio_en_plantilla {
                resultado.push(' ');
            } else {
                resultado.push(caracter);
            }
        }

        resultado
    }
}

/// caja5 2.0: patrón L original (1.1) en impares + espejo L⁻¹ en pares.
static CAJA5_PATTERNS: [[(i64, i64); 2]; 8] = [
    [(2, 0), (0, 1)],   // 0: impares, caja5%4=0 (↓↓→)
    [(-2, 0), (0, -1)], // 1: pares,   caja5%4=0 espejo (↑↑←)
    [(0, 2), (1, 0)],   // 2: impares, caja5%4=1 (→→↓)
    [(0, -2), (-1, 0)], // 3: pares,   caja5%4=1 espejo (←←↑)
    [(-2, 0), (0, -1)], // 4: impares, caja5%4=2 (↑↑←)
    [(2, 0), (0, 1)],   // 5: pares,   caja5%4=2 espejo (↓↓→)
    [(0, -2), (-1, 0)], // 6: impares, caja5%4=3 (←←↑)
    [(0, 2), (1, 0)],   // 7: pares,   caja5%4=3 espejo (→→↓)
];

/// Centinela: caja5 == total_chars-1 desactiva completamente.
#[inline(always)]
fn caja5_movements(i: i64, caja5: i64, total_chars: usize) -> &'static [(i64, i64); 2] {
    if caja5 == (total_chars as i64) - 1 {
        return &[(0, 0), (0, 0)]; // sin efecto (el for suma 0)
    }
    let base = (caja5.rem_euclid(4) * 2) as usize;
    let idx = if i % 2 == 1 { base } else { base + 1 }; // impar→original, par→espejo
    &CAJA5_PATTERNS[idx]
}
