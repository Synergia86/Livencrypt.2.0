#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="${LIVENCRYPT_INITRAMFS_TARGET:-x86_64-unknown-linux-musl}"
OUT_DIR="$ROOT_DIR/target/initramfs"

command -v rustup >/dev/null 2>&1 || {
  echo "Livencrypt PBA: rustup no esta disponible." >&2
  exit 1
}

rustup target add "$TARGET"
cargo build --release --locked --target "$TARGET" --manifest-path "$ROOT_DIR/Cargo.toml"

install -d -m 0755 "$OUT_DIR"
install -m 0755 \
  "$ROOT_DIR/target/$TARGET/release/livencrypt-core" \
  "$OUT_DIR/livencrypt-core"

cat > "$OUT_DIR/livencrypt_hook" <<EOF
#!/bin/sh
PREREQ=""

prereqs() {
  echo "\$PREREQ"
}

case "\$1" in
  prereqs)
    prereqs
    exit 0
    ;;
esac

. /usr/share/initramfs-tools/hook-functions
copy_exec /usr/bin/livencrypt-core /bin/livencrypt-core
EOF

chmod 0755 "$OUT_DIR/livencrypt_hook"

echo "Livencrypt PBA: artefactos generados en $OUT_DIR."
echo "Livencrypt PBA: no se ha instalado ningun hook de arranque."
