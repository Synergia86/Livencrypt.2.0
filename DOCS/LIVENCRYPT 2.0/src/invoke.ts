// SPDX-License-Identifier: GPL-3.0-or-later
// Bridge centralizado para comandos Tauri
const invoke = (window as any).__TAURI_INTERNALS__?.invoke ||
  (window as any).__TAURI__?.core?.invoke ||
  (window as any).__TAURI__?.tauri?.invoke;

export default invoke;
