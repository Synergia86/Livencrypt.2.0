#!/bin/sh
set -eu

if [ "${1:-}" != "purge" ]; then
  exit 0
fi

rm -f /etc/livencrypt/expected.sha256
rm -f /etc/livencrypt/install_profile.conf
rm -f /etc/livencrypt/sandbox/profile.conf
rmdir /etc/livencrypt/sandbox 2>/dev/null || true
rmdir /etc/livencrypt 2>/dev/null || true
rm -f /etc/security/limits.d/99-livencrypt.conf
rm -f /etc/opt/chrome/native-messaging-hosts/com.livencrypt.gateway.json
rm -f /etc/chromium/native-messaging-hosts/com.livencrypt.gateway.json
rm -f /etc/brave/native-messaging-hosts/com.livencrypt.gateway.json
rm -f /etc/opt/brave.com/brave/native-messaging-hosts/com.livencrypt.gateway.json

if [ -f /etc/apparmor.d/usr.bin.livencrypt-core ]; then
  if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -R /etc/apparmor.d/usr.bin.livencrypt-core 2>/dev/null || true
  fi
  rm -f /etc/apparmor.d/usr.bin.livencrypt-core
fi

if command -v update-desktop-database >/dev/null 2>&1 && [ -d /usr/share/applications ]; then
  update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
fi

echo "Livencrypt: purge completado. Los datos de usuario/vaults no se eliminan automaticamente."
echo "Livencrypt: para borrar datos personales, elimine manualmente ~/.local/share/livencrypt tras hacer copia de seguridad."

exit 0
