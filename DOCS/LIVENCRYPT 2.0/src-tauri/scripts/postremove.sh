#!/bin/sh
set -eu

if [ "${1:-}" != "purge" ]; then
  exit 0
fi

rm -f /etc/livencrypt/expected.sha256
rmdir /etc/livencrypt 2>/dev/null || true

for home_dir in /home/* /root; do
  [ -d "$home_dir" ] || continue

  data_dir="$home_dir/.local/share/livencrypt"
  route_backup="$data_dir/.livencrypt/secure/default_routes.backup"

  [ -d "$data_dir" ] || continue

  if [ -f "$route_backup" ]; then
    echo "Livencrypt: se conserva $data_dir porque existe backup de rutas de red."
    continue
  fi

  rm -rf "$data_dir"
done

exit 0
