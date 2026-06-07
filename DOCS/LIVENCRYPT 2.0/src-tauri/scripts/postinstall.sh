#!/bin/sh
set -eu

if [ "${1:-}" != "configure" ]; then
  exit 0
fi

binary_path="/usr/bin/livencrypt-core"
integrity_dir="/etc/livencrypt"
integrity_file="$integrity_dir/expected.sha256"

if [ ! -x "$binary_path" ]; then
  echo "Livencrypt: no se encontro el binario instalado en $binary_path." >&2
  exit 1
fi

if ! command -v setcap >/dev/null 2>&1; then
  echo "Livencrypt: setcap no esta disponible. Instale libcap2-bin para habilitar CAP_IPC_LOCK." >&2
  exit 1
fi

setcap cap_ipc_lock=ep "$binary_path"

if command -v getcap >/dev/null 2>&1; then
  if ! getcap "$binary_path" | grep -q "cap_ipc_lock"; then
    echo "Livencrypt: CAP_IPC_LOCK no quedo aplicado sobre $binary_path." >&2
    exit 1
  fi
fi

if ! command -v sha256sum >/dev/null 2>&1; then
  echo "Livencrypt: sha256sum no esta disponible; no se puede registrar hash de integridad." >&2
  exit 1
fi

install -d -m 0755 "$integrity_dir"
sha256sum "$binary_path" | awk '{print $1}' > "$integrity_file"
chmod 0644 "$integrity_file"

echo "Livencrypt: CAP_IPC_LOCK aplicado a $binary_path para mlockall real."
echo "Livencrypt: SHA-256 esperado registrado en $integrity_file."
exit 0
