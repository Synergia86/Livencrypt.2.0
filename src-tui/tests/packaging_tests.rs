// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>
/* rol: Suite de pruebas para el empaquetado e instalación de perfiles */

#[test]
fn postremove_does_not_delete_user_data() {
    let script = std::fs::read_to_string("scripts/postremove.sh").expect("postremove.sh");
    assert!(!script.contains("for home_dir in /home/* /root"));
    assert!(!script.contains("rm -rf \"$data_dir\""));
    assert!(script.contains("Los datos de usuario/vaults no se eliminan automaticamente."));
}
