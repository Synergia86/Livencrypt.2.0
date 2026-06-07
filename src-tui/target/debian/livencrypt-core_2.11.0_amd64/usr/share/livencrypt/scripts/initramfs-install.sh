#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
HOOK_SRC="$ROOT_DIR/target/initramfs/livencrypt_hook"
HOOK_DST="/etc/initramfs-tools/hooks/livencrypt-core"
BACKUP_DIR="/var/backups/livencrypt-initramfs"

if [ "$(id -u)" -ne 0 ]; then
  echo "Livencrypt PBA: ejecute este script como root." >&2
  exit 1
fi

if [ "${LIVENCRYPT_ENABLE_PBA:-0}" != "1" ]; then
  echo "Livencrypt PBA: instalacion bloqueada." >&2
  echo "Defina LIVENCRYPT_ENABLE_PBA=1 solo tras backup y prueba en equipo no critico." >&2
  exit 1
fi

if [ ! -f "$HOOK_SRC" ]; then
  echo "Livencrypt PBA: falta $HOOK_SRC. Ejecute scripts/initramfs-build.sh primero." >&2
  exit 1
fi

command -v update-initramfs >/dev/null 2>&1 || {
  echo "Livencrypt PBA: update-initramfs no esta disponible." >&2
  exit 1
}

install -d -m 0700 "$BACKUP_DIR"
if [ -d /boot ]; then
  tar -C /boot -czf "$BACKUP_DIR/boot-initramfs-$(date +%Y%m%d%H%M%S).tar.gz" .
fi

install -m 0755 "$HOOK_SRC" "$HOOK_DST"
update-initramfs -u

echo "Livencrypt PBA: hook instalado en $HOOK_DST."
echo "Livencrypt PBA: backup creado en $BACKUP_DIR."
