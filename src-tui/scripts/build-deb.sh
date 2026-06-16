#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT_DIR/Cargo.toml" | head -n 1)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
PACKAGE_NAME="livencrypt-core"
DEBIAN_WORK_DIR="$TARGET_DIR/debian"
DIST_DIR="$ROOT_DIR/dist"

detect_deb_arch() {
  if command -v dpkg >/dev/null 2>&1; then
    dpkg --print-architecture
    return
  fi

  case "$(uname -m)" in
    x86_64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7*) echo "armhf" ;;
    i386|i686) echo "i386" ;;
    *)
      echo "amd64" >&2
      echo "Livencrypt: arquitectura no reconocida; usando amd64 por defecto." >&2
      ;;
  esac
}

ARCH="$(detect_deb_arch)"
BUILD_ROOT="$TARGET_DIR/debian/${PACKAGE_NAME}_${VERSION}_${ARCH}"
DEB_PATH="$DIST_DIR/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"

CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release --locked --manifest-path "$ROOT_DIR/Cargo.toml"

rm -rf "$BUILD_ROOT"
mkdir -p "$DIST_DIR"
mkdir -p "$BUILD_ROOT/DEBIAN"
mkdir -p "$BUILD_ROOT/usr/bin"
mkdir -p "$BUILD_ROOT/usr/share/doc/$PACKAGE_NAME"
mkdir -p "$BUILD_ROOT/usr/share/applications"
mkdir -p "$BUILD_ROOT/usr/share/icons/hicolor/128x128/apps"
mkdir -p "$BUILD_ROOT/usr/share/livencrypt/apparmor"
mkdir -p "$BUILD_ROOT/usr/share/livencrypt/extension"
mkdir -p "$BUILD_ROOT/usr/share/livencrypt/native-messaging"
mkdir -p "$BUILD_ROOT/usr/share/livencrypt/scripts"

install -m 0755 "$TARGET_DIR/release/livencrypt-core" "$BUILD_ROOT/usr/bin/livencrypt-core"
install -m 0755 "$TARGET_DIR/release/livencrypt-bridge" "$BUILD_ROOT/usr/bin/livencrypt-bridge"
install -m 0755 "$ROOT_DIR/scripts/livencrypt-core-window.sh" "$BUILD_ROOT/usr/bin/livencrypt-core-window"
install -m 0755 "$ROOT_DIR/scripts/postinstall.sh" "$BUILD_ROOT/DEBIAN/postinst"
install -m 0755 "$ROOT_DIR/scripts/postremove.sh" "$BUILD_ROOT/DEBIAN/postrm"
install -m 0644 "$ROOT_DIR/packaging/desktop/livencrypt-core.desktop" "$BUILD_ROOT/usr/share/applications/livencrypt-core.desktop"
install -m 0644 "$ROOT_DIR/icons/livencrypt2.0_logo.png" "$BUILD_ROOT/usr/share/icons/hicolor/128x128/apps/livencrypt-core.png"
install -m 0644 "$ROOT_DIR/packaging/apparmor/livencrypt-core" "$BUILD_ROOT/usr/share/livencrypt/apparmor/livencrypt-core"
install -m 0644 "$ROOT_DIR/scripts/com.livencrypt.gateway.json" "$BUILD_ROOT/usr/share/livencrypt/native-messaging/com.livencrypt.gateway.json"
cp -R "$ROOT_DIR/extension/livencrypt-web3" "$BUILD_ROOT/usr/share/livencrypt/extension/livencrypt-web3"
install -m 0755 "$ROOT_DIR/scripts/initramfs-build.sh" "$BUILD_ROOT/usr/share/livencrypt/scripts/initramfs-build.sh"
install -m 0755 "$ROOT_DIR/scripts/initramfs-install.sh" "$BUILD_ROOT/usr/share/livencrypt/scripts/initramfs-install.sh"

cat > "$BUILD_ROOT/DEBIAN/control" <<EOF
Package: $PACKAGE_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: Synergia86
Depends: libc6, libcap2-bin
Description: Livencrypt 2.0 - TUI segura para texto, archivo y plantillas
 Interfaz de terminal para Livencrypt 2.0 sin WebView ni frontend web.
 Incluye hardening de proceso, Boot Shield y nucleo criptografico local.
EOF

cat > "$BUILD_ROOT/usr/share/doc/$PACKAGE_NAME/README.Debian" <<EOF
Livencrypt 2.0 TUI
==================

Ejecute desde terminal:

  livencrypt-core

Diagnostico de hardening:

  livencrypt-core --hardening-check
EOF

if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --build "$BUILD_ROOT" "$DEB_PATH"
else
  command -v ar >/dev/null 2>&1 || {
    echo "Livencrypt: falta 'dpkg-deb' o 'ar' para generar el paquete .deb." >&2
    echo "Instale dpkg, dpkg-dev o binutils segun su distribucion." >&2
    exit 1
  }
  command -v tar >/dev/null 2>&1 || {
    echo "Livencrypt: falta 'tar' para generar el paquete .deb." >&2
    exit 1
  }

  PKG_WORK="$DEBIAN_WORK_DIR/.${PACKAGE_NAME}_${VERSION}_${ARCH}.deb-work"
  rm -rf "$PKG_WORK"
  mkdir -p "$PKG_WORK"

  printf "2.0\n" > "$PKG_WORK/debian-binary"
  (cd "$BUILD_ROOT/DEBIAN" && tar --sort=name --owner=0 --group=0 --numeric-owner -czf "$PKG_WORK/control.tar.gz" .)
  (cd "$BUILD_ROOT" && tar --sort=name --owner=0 --group=0 --numeric-owner --exclude=./DEBIAN -czf "$PKG_WORK/data.tar.gz" .)

  rm -f "$DEB_PATH"
  (cd "$PKG_WORK" && ar rcs "$DEB_PATH" debian-binary control.tar.gz data.tar.gz)
  rm -rf "$PKG_WORK"
fi
echo "$DEB_PATH"
