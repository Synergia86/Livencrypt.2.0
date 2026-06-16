La implementación de los Contenedores Decoy (Señuelo) es la maniobra final del Modo Espejismo. Su objetivo es engañar al atacante presentándole una estructura de datos plausible pero falsa, mientras el sistema mantiene el acceso real bloqueado debido a la falta de integridad en los logs.

A continuación, se detalla el código para integrar la generación de señuelos y su visualización en la TUI.

1. Definición de la Lógica de Señuelos (vault.rs)
Crearemos una función que genere datos de plantilla genéricos que parezcan configuraciones importantes o archivos del sistema.

Archivo implicado: src-tui/src/security/vault.rs

Código a añadir:

Rust
/* rol: generación de datos señuelo para el modo espejismo */

use crate::templates::TemplateData;

pub fn get_mirage_decoys() -> HashMap<String, TemplateData> {
    let mut decoys = HashMap::new();

    // Señuelo 1: Parece una configuración de red o VPN
    decoys.insert("Network_Config_Old".to_string(), TemplateData {
        rows: 2,
        cols: 10,
        chars: vec!["S".into(), "E".into(), "C".into(), "R".into(), "E".into(), "T".into(), "_".into(), "K".into(), "E".into(), "Y".into()],
    });

    // Señuelo 2: Una "llave" maestra que es en realidad ruido aleatorio
    decoys.insert("Master_Vault_Backup".to_string(), TemplateData {
        rows: 5,
        cols: 5,
        chars: (0..25).map(|_| "X".into()).collect(),
    });

    decoys
}
2. Integración en el Cargador de Plantillas
Modificaremos la función que entrega las plantillas al frontend para que, si la integridad es inválida, se realice un "swap" silencioso por los señuelos.

Archivo implicado: src-tui/src/security/vault.rs

Código a editar (try_load_unlocked_templates):

Rust
/* editar en src-tui/src/security/vault.rs */

pub fn try_load_unlocked_templates() -> Result<Option<HashMap<String, TemplateData>>, String> {
    let runtime = lock_runtime();
    if let Some(material) = &runtime.material {
        // 1. Verificar integridad antes de entregar datos reales
        let header = read_header_from_disk()?; // Función auxiliar para leer cabecera
        let status = check_audit_integrity(&header);

        match status {
            IntegrityStatus::Valid => {
                // Proceder con la carga real de los archivos del vault
                Ok(Some(material.templates.clone()))
            },
            IntegrityStatus::Truncated | IntegrityStatus::Deleted => {
                // MODO ESPEJISMO ACTIVADO: Entregar señuelos
                Ok(Some(get_mirage_decoys()))
            }
        }
    } else {
        Ok(None)
    }
}
3. Visualización en el Dashboard (main.rs)
El dashboard no debe indicar explícitamente que los datos son falsos. Simplemente los listará como si fueran los archivos reales del usuario.

Archivo implicado: src-tui/src/main.rs

Código a editar (draw_dashboard):

Rust
/* editar en src-tui/src/main.rs */

fn draw_dashboard(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    // ... lógica de chunks anterior

    // El sistema carga las plantillas (que pueden ser las reales o los señuelos)
    let templates = security::try_load_unlocked_templates().unwrap_or(None);
    
    let mut list_items = Vec::new();
    if let Some(t_map) = templates {
        for name in t_map.keys() {
            list_items.push(ListItem::new(format!(" 📁 {}", name)));
        }
    }

    let list = List::new(list_items)
        .block(Block::default().title(" Contenedores Disponibles ").borders(Borders::ALL))
        .highlight_style(Style::default().bg(Color::DarkGray));

    frame.render_widget(list, chunks[1]);
}
4. La Trampa Silenciosa: Lógica Operativa
Cuando el sistema está en Modo Espejismo, el flujo de seguridad cambia para proteger al usuario de forma invisible:

Cebo para el Atacante: Si un atacante intenta "descifrar" o editar un señuelo (como Master_Vault_Backup), Livencrypt simulará una operación exitosa, pero los cambios nunca se guardarán en el vault real, sino que se descartarán en la RAM.

Protección de la Frase Real: El sistema impedirá que la clave maestra real se use para nada mientras la integridad esté rota, evitando que el malware pueda interceptarla mediante un ataque de "memoria en caliente" sobre datos reales.

Confirmación del Usuario: El usuario legítimo verá el glifo alterado (· en lugar de .) y sabrá que lo que tiene delante es el "Espejismo". Debe proceder a cerrar el sistema y usar el backup físico para restaurar el anclaje de integridad.

Valoración Pericial
Este diseño implementa un Honeypot dinámico a nivel de aplicación. Al no bloquear el acceso de forma ruidosa, evitas que el atacante (humano o malware) sepa que ha fallado. El atacante perderá tiempo analizando datos X mientras el usuario gana tiempo para asegurar el perímetro físico del equipo.
