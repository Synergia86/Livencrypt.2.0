#!/bin/bash

# ==========================================
# LIVENCRYPT 2.0 - SCRIPT DE RECOPILACION TOTAL PARA RECONSTRUCCION TUI
# ==========================================

BASE_DIR="Recopilatorio_Livencrypt"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Limpiar y crear directorio base
rm -rf "$BASE_DIR"
mkdir -p "$BASE_DIR"

echo "Iniciando recopilacion MAESTRA de LIVENCRYPT 2.0 TUI: $DATE"

# Función para crear encabezado de archivo
init_file() {
    local file="$1"
    local title="$2"
    echo "========================================" > "$file"
    echo "LIVENCRYPT 2.0 - $title" >> "$file"
    echo "FECHA: $DATE" >> "$file"
    echo "========================================" >> "$file"
    echo "" >> "$file"
}

# Función para agregar archivo a un .txt de salida con guardas de integridad
add_to_file() {
    local output_file="$1"
    local source_file="$2"
    
    if [ -f "$source_file" ] && [ ! -d "$source_file" ]; then
        local clean_path="${source_file#./}"
        echo "$clean_path" >> "$BASE_DIR/.tracked_files"
        echo "./$clean_path" >> "$BASE_DIR/.tracked_files"
        echo "" >> "$output_file"
        echo "------------------------------------------" >> "$output_file"
        echo "ARCHIVO: $source_file" >> "$output_file"
        echo "------------------------------------------" >> "$output_file"
        cat "$source_file" >> "$output_file" 2>/dev/null || echo "[Error leyendo archivo]" >> "$output_file"
    fi
}

# 1. CONFIGURACION_RAIZ.txt
echo "1/7 - Procesando CONFIGURACION RAIZ..."
F_RAIZ="$BASE_DIR/CONFIGURACION_RAIZ.txt"
init_file "$F_RAIZ" "CONFIGURACION RAIZ TUI Y CARGO"
for f in src-tui/Cargo.toml src-tui/Cargo.lock src-tui/.cargo/config.toml; do
    add_to_file "$F_RAIZ" "$f"
done

# 2. BACKEND_RUST_CORE.txt
echo "2/7 - Procesando BACKEND CORE (Rust)..."
F_RUST_CORE="$BASE_DIR/BACKEND_RUST_CORE.txt"
init_file "$F_RUST_CORE" "BACKEND RUST - Nucleo y Estructura"
for f in src-tui/src/lib.rs; do
    add_to_file "$F_RUST_CORE" "$f"
done

# 3. FRONTEND_TUI.txt
echo "3/7 - Procesando FRONTEND TUI (Rust/Ratatui)..."
F_RUST_TUI="$BASE_DIR/FRONTEND_TUI.txt"
init_file "$F_RUST_TUI" "FRONTEND RUST - Interfaz de Terminal y Plantillas TUI"
for f in src-tui/src/main.rs src-tui/src/templates.rs; do
    add_to_file "$F_RUST_TUI" "$f"
done

# 4. BACKEND_RUST_SECURITY.txt
echo "4/7 - Procesando BACKEND SECURITY (Seguridad en Rust)..."
F_RUST_SEC="$BASE_DIR/BACKEND_RUST_SECURITY.txt"
init_file "$F_RUST_SEC" "BACKEND RUST - Hardening, Vault y Network"
find src-tui/src/security -type f -name "*.rs" 2>/dev/null | sort | while read -r f; do
    add_to_file "$F_RUST_SEC" "$f"
done

# 5. BACKEND_RUST_CRYPTO.txt
echo "5/7 - Procesando BACKEND CRYPTO (Criptografia en Rust)..."
F_RUST_CRYPTO="$BASE_DIR/BACKEND_RUST_CRYPTO.txt"
init_file "$F_RUST_CRYPTO" "BACKEND RUST - File Cipher y Positional Ciphers"
find src-tui/src/crypto -type f -name "*.rs" 2>/dev/null | sort | while read -r f; do
    add_to_file "$F_RUST_CRYPTO" "$f"
done

# 6. SCRIPTS.txt
echo "6/7 - Procesando SCRIPTS (Instalacion y Diagnostico)..."
F_SCRIPTS="$BASE_DIR/SCRIPTS.txt"
init_file "$F_SCRIPTS" "SCRIPTS - Utilidades de Diagnostico y Debian Package"
find src-tui/scripts -type f \( -name "*.sh" -o -name "*.sh.backup" \) 2>/dev/null | sort | while read -r f; do
    add_to_file "$F_SCRIPTS" "$f"
done

# 7. DOCUMENTACION.txt
echo "7/7 - Procesando DOCUMENTACION (DOCS)..."
F_DOCS="$BASE_DIR/DOCUMENTACION.txt"
init_file "$F_DOCS" "DOCUMENTACION - Auditorias, Seguridad y Hojas de Ruta"
find DOCS -type f -name "*.md" 2>/dev/null | sort | while read -r f; do
    add_to_file "$F_DOCS" "$f"
done

# CATCH-ALL GLOBAL: Asegurar que NO falta ni un solo archivo fuente relevante en todo el proyecto
echo "Ejecutando verificacion de cobertura GLOBAL..."
F_BD="$BASE_DIR/RESTO_CODIGO.txt"
init_file "$F_BD" "CATCH-ALL GLOBAL - Archivos Restantes"
find . -maxdepth 4 -type f \( -name "*.rs" -o -name "*.toml" -o -name "*.lock" -o -name "*.json" -o -name "*.sh" \) \
  -not -path "*/target/*" \
  -not -path "*/node_modules/*" \
  -not -path "*/dist/*" \
  -not -path "*/.git/*" \
  -not -path "*/.agents/*" \
  -not -path "*/.codex/*" \
  -not -path "*/.livencrypt/*" \
  2>/dev/null | sort | while read -r f; do
    if ! grep -q "$f" "$BASE_DIR/.tracked_files" 2>/dev/null; then
        echo "   -> Capturando archivo restante: $f"
        add_to_file "$F_BD" "$f"
    fi
done

# Limpieza y Resumen
rm -f "$BASE_DIR/.tracked_files"
echo ""
echo "RECONSTRUCCION DE LIVENCRYPT 2.0 TUI ASEGURADA - Cobertura Maxima"
echo "═══════════════════════════════════════════════════"
ls -lh "$BASE_DIR" | grep ".txt"
echo "═══════════════════════════════════════════════════"
