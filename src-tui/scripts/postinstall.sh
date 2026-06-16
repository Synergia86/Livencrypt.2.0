#!/bin/sh
set -eu

if [ "${1:-}" != "configure" ]; then
  exit 0
fi

binary_path="/usr/bin/livencrypt-core"
integrity_dir="/etc/livencrypt"
integrity_file="$integrity_dir/expected.sha256"
install_profile="${LIVENCRYPT_INSTALL_PROFILE:-expu}"
apparmor_src="/usr/share/livencrypt/apparmor/livencrypt-core"
apparmor_dst="/etc/apparmor.d/usr.bin.livencrypt-core"
native_manifest_src="/usr/share/livencrypt/native-messaging/com.livencrypt.gateway.json"
native_manifest_name="com.livencrypt.gateway.json"

detect_os() {
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "${ID:-unknown}:${ID_LIKE:-}"
  else
    uname -s
  fi
}

configure_memlock_limits() {
  if [ -d /etc/security/limits.d ]; then
    cat > /etc/security/limits.d/99-livencrypt.conf <<EOF
* soft memlock unlimited
* hard memlock unlimited
root soft memlock unlimited
root hard memlock unlimited
EOF
    chmod 0644 /etc/security/limits.d/99-livencrypt.conf
  fi
}

configure_expected_hash() {
  if ! command -v sha256sum >/dev/null 2>&1; then
    echo "Livencrypt: sha256sum no esta disponible; no se puede registrar hash de integridad." >&2
    exit 1
  fi

  install -d -m 0755 "$integrity_dir"
  sha256sum "$binary_path" | awk '{print $1}' > "$integrity_file"
  chmod 0644 "$integrity_file"
}

configure_profile() {
  install -d -m 0755 "$integrity_dir"
  case "$install_profile" in
    standard|isolated|expu|pba) ;;
    *)
      echo "Livencrypt: perfil '$install_profile' no valido; usando expu." >&2
      install_profile="expu"
      ;;
  esac
  printf "%s\n" "$install_profile" > "$integrity_dir/install_profile.conf"
  chmod 0644 "$integrity_dir/install_profile.conf"
}

configure_sandbox_profile() {
  install -d -m 0755 "$integrity_dir/sandbox"
  cat > "$integrity_dir/sandbox/profile.conf" <<EOF
network=isolated
mount=private
cpu_seconds=120
memory_mb=512
file_size_mb=64
EOF
  chmod 0644 "$integrity_dir/sandbox/profile.conf"
}

configure_apparmor_profile() {
  if [ ! -f "$apparmor_src" ]; then
    return 0
  fi

  if ! command -v apparmor_parser >/dev/null 2>&1 || [ ! -d /etc/apparmor.d ]; then
    echo "Livencrypt: AppArmor no disponible; perfil expu no cargado." >&2
    return 0
  fi

  install -m 0644 "$apparmor_src" "$apparmor_dst"
  if ! apparmor_parser -r "$apparmor_dst"; then
    echo "Livencrypt: aviso, no se pudo cargar el perfil AppArmor." >&2
  fi
}

register_desktop_entry() {
  if command -v update-desktop-database >/dev/null 2>&1 && [ -d /usr/share/applications ]; then
    update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
  fi
}

register_native_messaging_host() {
  if [ ! -f "$native_manifest_src" ]; then
    echo "Livencrypt: manifiesto de mensajeria nativa no encontrado en $native_manifest_src." >&2
    return 0
  fi

  for manifest_dir in \
    /etc/opt/chrome/native-messaging-hosts \
    /etc/chromium/native-messaging-hosts \
    /etc/brave/native-messaging-hosts \
    /etc/opt/brave.com/brave/native-messaging-hosts
  do
    install -d -m 0755 "$manifest_dir"
    install -m 0644 "$native_manifest_src" "$manifest_dir/$native_manifest_name"
  done
}

if [ ! -x "$binary_path" ]; then
  echo "Livencrypt: no se encontro el binario instalado en $binary_path." >&2
  exit 1
fi

os_id="$(detect_os)"
configure_profile

if ! command -v setcap >/dev/null 2>&1; then
  echo "Livencrypt: setcap no esta disponible. Instale libcap2-bin para habilitar CAP_IPC_LOCK." >&2
  exit 1
fi

setcap cap_ipc_lock=ep "$binary_path" || {
  echo "Livencrypt: ERROR no se pudieron asignar capacidades al binario." >&2
  echo "Livencrypt: verifique que el sistema de archivos permita setcap y no este montado con nosuid." >&2
  exit 1
}

if command -v getcap >/dev/null 2>&1; then
  if ! getcap "$binary_path" | grep -q "cap_ipc_lock"; then
    echo "Livencrypt: CRITICO CAP_IPC_LOCK no quedo aplicado sobre $binary_path." >&2
    echo "Livencrypt: mlockall real puede fallar sin esta capacidad." >&2
    exit 1
  fi
fi

memlock_limit="$(ulimit -l 2>/dev/null || echo 0)"
case "$memlock_limit" in
  unlimited) ;;
  ''|*[!0-9]*)
    echo "Livencrypt: AVISO no se pudo interpretar el limite memlock: $memlock_limit" >&2
    ;;
  *)
    if [ "$memlock_limit" -lt 65536 ]; then
      echo "Livencrypt: AVISO el limite memlock es bajo (${memlock_limit} KB)." >&2
      echo "Livencrypt: considere elevarlo en /etc/security/limits.conf si MLOCKALL aparece como FALLO." >&2
    fi
    ;;
esac

case "$os_id" in
  *debian*|*ubuntu*|*linuxmint*|debian:*|ubuntu:*|linuxmint:*)
    configure_memlock_limits
    configure_sandbox_profile
    ;;
  *fedora*|*rhel*|*centos*)
    configure_sandbox_profile
    echo "Livencrypt: SELinux detectado o probable; politica especifica pendiente." >&2
    ;;
  *)
    configure_sandbox_profile
    echo "Livencrypt: SO detectado '$os_id'; aplicando hardening Linux disponible." >&2
    ;;
esac

configure_expected_hash
register_desktop_entry
register_native_messaging_host

echo "Livencrypt: CAP_IPC_LOCK aplicado a $binary_path para mlockall real."
echo "Livencrypt: SHA-256 esperado registrado en $integrity_file."
echo "Livencrypt: perfil expu instalado: $install_profile."
echo "Livencrypt: perfil sandbox local configurado en $integrity_dir/sandbox/profile.conf."
echo "Livencrypt: host de mensajeria nativa registrado como /usr/bin/livencrypt-bridge."
echo "Livencrypt: extension Web3 disponible en /usr/share/livencrypt/extension/livencrypt-web3."
echo "Livencrypt: carguela manualmente como extension desempaquetada en Chromium/Brave."
echo "Livencrypt: AppArmor queda disponible, pero NO se activa automaticamente. Activelo desde Configuracion."
if [ "$install_profile" = "pba" ]; then
  echo "Livencrypt: PBA seleccionado, pero initramfs NO se activa automaticamente. Use script dedicado y rollback." >&2
fi
exit 0
