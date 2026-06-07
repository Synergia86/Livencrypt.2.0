// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Suite de pruebas para los canales de comunicación IPC */

#[test]
fn ipc_socket_never_uses_tmp() {
    let worker = std::fs::read_to_string("src/crypto/blockchain/worker.rs").expect("worker.rs");
    let bridge = std::fs::read_to_string("src/bin/livencrypt-bridge.rs").expect("bridge");

    assert!(!worker.contains("/tmp/livencrypt.sock"));
    assert!(!bridge.contains("/tmp/livencrypt.sock"));
    assert!(worker.contains("XDG_RUNTIME_DIR"));
    assert!(bridge.contains("XDG_RUNTIME_DIR"));
    assert!(worker.contains("join(\"livencrypt\")"));
    assert!(bridge.contains("join(\"livencrypt\")"));
}
