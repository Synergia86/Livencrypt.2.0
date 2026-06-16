#!/bin/sh
set -eu

CONFIRM="${LIVENCRYPT_CONFIRM_INITRAMFS:-}"
HOOK_SRC="${1:-/tmp/livencrypt-initramfs/livencrypt_hook}"
HOOK_DST="/etc/initramfs-tools/hooks/livencrypt"
BACKUP_DIR="/var/backups/livencrypt-initramfs"

if [ "$(id -u)" -ne 0 ]; then
  echo "Livencrypt: initramfs-install requiere permisos de administrador." >&2
  exit 1
fi

if [ "$CONFIRM" != "INSTALAR PBA" ]; then
  echo "Livencrypt: instalacion PBA cancelada." >&2
  echo "Para instalar: LIVENCRYPT_CONFIRM_INITRAMFS=\"INSTALAR PBA\" $0 $HOOK_SRC" >&2
  exit 2
fi

if [ ! -f "$HOOK_SRC" ]; then
  echo "Livencrypt: hook no encontrado: $HOOK_SRC" >&2
  echo "Ejecute primero initramfs-build.sh." >&2
  exit 1
fi

if [ ! -d /etc/initramfs-tools/hooks ]; then
  echo "Livencrypt: initramfs-tools no esta disponible en este sistema." >&2
  exit 1
fi

if ! command -v update-initramfs >/dev/null 2>&1; then
  echo "Livencrypt: update-initramfs no esta disponible." >&2
  exit 1
fi

install -d -m 0755 "$BACKUP_DIR"
if [ -f "$HOOK_DST" ]; then
  cp -a "$HOOK_DST" "$BACKUP_DIR/livencrypt.$(date +%Y%m%d%H%M%S).bak"
fi

install -m 0755 "$HOOK_SRC" "$HOOK_DST"
update-initramfs -u

cat >&2 <<EOF
Livencrypt: hook PBA instalado en $HOOK_DST.
Rollback:
  sudo rm -f "$HOOK_DST"
  sudo update-initramfs -u
EOF
