#!/bin/sh
set -eu

APP_BIN="/usr/bin/livencrypt-core"
APP_TITLE="Livencrypt 2.0"

run_app() {
  exec "$APP_BIN" "$@"
}

if [ -t 0 ] && [ -t 1 ]; then
  run_app "$@"
fi

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

if [ -n "${TERMINAL:-}" ] && command_exists "$TERMINAL"; then
  exec "$TERMINAL" -e sh -lc "exec '$APP_BIN'"
fi

if command_exists x-terminal-emulator; then
  exec x-terminal-emulator -T "$APP_TITLE" -e sh -lc "exec '$APP_BIN'"
fi

if command_exists gnome-terminal; then
  exec gnome-terminal --title="$APP_TITLE" -- sh -lc "exec '$APP_BIN'"
fi

if command_exists konsole; then
  exec konsole --title "$APP_TITLE" -e sh -lc "exec '$APP_BIN'"
fi

if command_exists xfce4-terminal; then
  exec xfce4-terminal --title="$APP_TITLE" --command "sh -lc \"exec '$APP_BIN'\""
fi

if command_exists mate-terminal; then
  exec mate-terminal --title="$APP_TITLE" -- sh -lc "exec '$APP_BIN'"
fi

if command_exists lxterminal; then
  exec lxterminal --title="$APP_TITLE" -e sh -lc "exec '$APP_BIN'"
fi

if command_exists kitty; then
  exec kitty --title "$APP_TITLE" sh -lc "exec '$APP_BIN'"
fi

if command_exists alacritty; then
  exec alacritty --title "$APP_TITLE" -e sh -lc "exec '$APP_BIN'"
fi

if command_exists xterm; then
  exec xterm -T "$APP_TITLE" -e sh -lc "exec '$APP_BIN'"
fi

echo "Livencrypt: no se encontro un emulador de terminal compatible." >&2
echo "Ejecute manualmente: $APP_BIN" >&2
exit 127
