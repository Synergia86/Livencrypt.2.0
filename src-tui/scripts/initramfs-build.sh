#!/bin/sh
set -eu

WORK_DIR="${LIVENCRYPT_INITRAMFS_WORKDIR:-/tmp/livencrypt-initramfs}"
HOOK_PATH="$WORK_DIR/livencrypt_hook"
INSTALLED_BIN="${LIVENCRYPT_INITRAMFS_BIN:-/usr/bin/livencrypt-core}"

if [ ! -x "$INSTALLED_BIN" ]; then
  SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
  ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
  if [ -x "$ROOT_DIR/target/release/livencrypt-core" ]; then
    INSTALLED_BIN="$ROOT_DIR/target/release/livencrypt-core"
  else
    echo "Livencrypt: no se encontro binario ejecutable para incluir en initramfs." >&2
    echo "Compile primero o instale el paquete .deb." >&2
    exit 1
  fi
fi

install -d -m 0755 "$WORK_DIR"

cat > "$HOOK_PATH" <<EOF
#!/bin/sh
PREREQ=""
prereqs() { echo "\$PREREQ"; }
case "\${1:-}" in
  prereqs) prereqs; exit 0 ;;
esac

. /usr/share/initramfs-tools/hook-functions
copy_exec "$INSTALLED_BIN" /bin/livencrypt-core
EOF

chmod 0755 "$HOOK_PATH"

cat > "$WORK_DIR/README.rollback" <<EOF
Livencrypt initramfs/PBA
=======================

Hook preparado:
  $HOOK_PATH

Instalacion manual:
  sudo LIVENCRYPT_CONFIRM_INITRAMFS="INSTALAR PBA" /usr/share/livencrypt/scripts/initramfs-install.sh "$HOOK_PATH"

Rollback:
  sudo rm -f /etc/initramfs-tools/hooks/livencrypt
  sudo update-initramfs -u

Recomendacion:
  pruebe siempre en equipo no critico antes de activar PBA.
EOF

echo "$HOOK_PATH"
