# Detección de Comportamiento con IA Local y eBPF

Este módulo describe la propuesta para integrar un sensor de núcleo (eBPF) y un motor de Inteligencia Artificial local (SLM) de inferencia en tiempo real, capaz de detectar y frenar ataques del software aislado basándose en su intención de comportamiento.

---

## 1. Diseño y Principios Técnicos

A diferencia de las reglas estáticas del sandbox (que solo bloquean accesos prohibidos), este módulo añade un análisis cognitivo local sobre la secuencia de acciones para predecir si el software está intentando realizar una intrusión compleja (como inyección de código o cifrado tipo ransomware).

```
[ Software en Cuarentena ]
          │ (Syscalls)
          ▼
   [ Sensor eBPF ] ──► Captura secuencias de eventos
          │
          ▼
   [ Motor IA (SLM) ] ──► Inferencia Local (Burn / ONNX)
          │
          ▼
   [ Risk Scoring ]
   ├── >85%: Alerta Silenciosa TUI
   └── >99%: Congelación del Proceso (SIGSTOP)
```

### A. Sensor eBPF (Extended Berkeley Packet Filter)
* **Monitorización No Invasiva**: eBPF permite inyectar programas en el núcleo de Linux para registrar llamadas al sistema (*syscalls*) de forma extremadamente rápida y segura, sin alterar el binario en cuarentena ni causar lag visible.
* **Correlación Temporal**: El sensor captura la secuencia de llamadas en el tiempo. Por ejemplo: `abrir_archivo` $\rightarrow$ `medir_entropía` $\rightarrow$ `crear_socket` $\rightarrow$ `sobrescribir_bloque`. De forma aislada son operaciones legítimas; juntas, indican la preparación de un secuestro de archivos (Ransomware) o exfiltración.

### B. Motor de Inferencia de IA Local (SLM)
* **Privacidad Absoluta**: Siguiendo las directrices de Livencrypt, está prohibida cualquier conexión de red externa para analizar datos (prohibido usar OpenAI u APIs en la nube). La IA debe ser local y offline.
* **Modelo Ligero (SLM)**: Se utiliza un modelo de lenguaje pequeño o red neuronal recurrente (LSTM o Transformer ligero) optimizado para CPU y bajo consumo de memoria.
* **Encapsulado**: El modelo reside cifrado dentro de la base de datos del vault. Solo se descifra y se monta en la RAM física protegida (`mlockall`) cuando se inicia un proceso en cuarentena.

### C. Análisis de Patrones Críticos
* **Detección de Beaconing**: Identifica si un troyano intenta contactar silenciosamente con un servidor de Comando y Control (C2) utilizando ráfagas de paquetes con intervalos de tiempo matemáticos, incluso si la IP del host no está en una lista de bloqueo previa.
* **Heurística de Cifrado**: Identifica si el programa lee archivos secuencialmente y los sobrescribe rápidamente con datos de alta entropía (encriptados), congelando el proceso antes de que se pierda información vital.
* **Inyección en Memoria**: Detecta si el proceso en cuarentena intenta ejecutar llamadas de mapeo de memoria sobre otros IDs de procesos para inyectar payloads.

### D. Respuesta Predictiva (Freno de Emergencia)
El motor de IA actualiza una puntuación de riesgo (*Risk Scoring*) en tiempo real por cada acción del sandbox:
* **Alerta Temprana (>85%)**: Se notifica discretamente al usuario mediante la alerta silenciosa esteganográfica en la TUI.
* **Congelación de Ejecución (>99%)**: Livencrypt envía la señal `SIGSTOP` al kernel de Linux para pausar inmediatamente la ejecución del proceso. La RAM del sandbox queda congelada exactamente en su estado actual, permitiendo al usuario decidir si destruye el sandbox, realiza un análisis forense de la memoria en claro, o reanuda la ejecución.

---

## 2. Archivos Implicados en el Proyecto

* **`src-tui/src/security/ebpf_sensor.rs`** *(Módulo propuesto)*: Cargará el programa eBPF en el núcleo utilizando bibliotecas como `aya` (un framework de eBPF puro en Rust) y consumirá el *Ring Buffer* de eventos de syscalls.
* **`src-tui/src/security/ia_monitor.rs`** *(Módulo propuesto)*: Implementará el motor de inferencia local utilizando la biblioteca de deep learning en Rust **Burn** o la biblioteca **onnxruntime-rs** para cargar y ejecutar un archivo `.onnx` ligero.
* **[Cargo.toml](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/Cargo.toml)**: Requiere la adición de dependencias de deep learning y eBPF (ej. `burn`, `onnxruntime`, `aya`).

---

## 3. Estado de la Integración

### ¿Qué está YA integrado?
* [x] **Nada**: No hay soporte en el código para sensores eBPF ni bibliotecas de inferencia de IA.

### ¿Qué falta por integrar?
* [ ] **Entrenamiento del Modelo**: Crear y entrenar un clasificador de series temporales de syscalls de malware que pueda guardarse en menos de 10-20 MB.
* [ ] **Bibliotecas de Inferencia**: Integrar `burn` u `onnxruntime` en el build pipeline de Rust-TUI.
* [ ] **Cargador eBPF con Aya**: Escribir el código en C (o Rust-eBPF) para capturar las trazas de llamadas y cargarlas desde la TUI.
* [ ] **Lógica de Señales de Control**: Implementar la llamada para enviar `SIGSTOP` al proceso problemático del sandbox.
* [ ] **Monitoreo TUI**: Integrar un medidor visual de porcentaje de riesgo del sandbox activo en la pestaña "Monitor de Sistema".

---

## Enlaces Relacionados
* Volver al [[00_indice|Índice General]].
* Ver la arquitectura del búnker de ejecución: [[06_cuarentena_memoria_y_aislamiento_sandbox|Cuarentena de Memoria y Aislamiento (Zero-Trust Sandbox)]].

## Código a integrar
1. Actualización de Dependencias (Cargo.toml)
Necesitamos integrar Aya para el manejo de eBPF en Rust puro y Burn para la inferencia de la IA local (SLM).

Archivo implicado: src-tui/Cargo.toml

Código a añadir:

Ini, TOML
[dependencies]
# ...
aya = "0.11"
aya-log = "0.1"
burn = { version = "0.13", features = ["train", "wgpu"] } # Motor de IA local
libc = "0.2"
2. Cargador eBPF con Aya (src-tui/src/security/ebpf_loader.rs)
Este módulo carga el programa eBPF en el kernel para interceptar las syscalls del sandbox sin penalización de rendimiento.

Archivo implicado: src-tui/src/security/ebpf_loader.rs (NUEVO)

Rust
// SPDX-License-Identifier: GPL-3.0-or-later
use aya::{programs::TracePoint, Bpf};
use aya_log::BpfLogger;
use std::sync::Arc;
use tokio::sync::Mutex;

/* Rol: Sensor eBPF para recolección de telemetría de syscalls */

pub struct EbpfMonitor {
    bpf: Bpf,
}

impl EbpfMonitor {
    pub fn load() -> Result<Self, String> {
        // Carga el bytecode de eBPF (compilado aparte)
        let bpf = Bpf::load(include_bytes!("../../../target/bpfel-unknown-none/release/livencrypt-ebpf"))
            .map_err(|e| e.to_string())?;
        
        // Adjuntar a los puntos de traza de syscalls
        let program: &mut TracePoint = bpf.program_mut("sys_enter").unwrap().try_into().unwrap();
        program.load().map_err(|e| e.to_string())?;
        program.attach("raw_syscalls", "sys_enter").map_err(|e| e.to_string())?;

        Ok(Self { bpf })
    }
}
3. Motor de Inferencia de IA Local (src-tui/src/security/ai_monitor.rs)
Aquí implementamos la lógica que carga el modelo (SLM < 20MB) y evalúa las secuencias de syscalls recibidas del sensor.

Archivo implicado: src-tui/src/security/ai_monitor.rs (NUEVO)

Rust
/* Rol: Clasificador de series temporales de malware (SLM) */

use burn::prelude::*;

pub fn evaluate_behavior_risk(syscall_sequence: &[u32]) -> f32 {
    // 1. Preprocesamiento de la secuencia (normalización)
    // 2. Inferencia usando el modelo entrenado (ej. GRU o Transformer pequeño)
    
    // Simulación de salida de la red neuronal:
    // Retorna un valor de 0.0 (seguro) a 1.0 (amenaza crítica)
    let risk_score = calculate_neural_inference(syscall_sequence);
    
    risk_score
}

fn calculate_neural_inference(input: &[u32]) -> f32 {
    // Lógica interna del modelo Burn
    0.15 // Ejemplo de riesgo bajo
}
4. Lógica de Señales de Control (src-tui/src/security/loader.rs)
Actualizamos el cargador para que pueda suspender procesos si la IA detecta un patrón de ataque inminente.

Archivo implicado: src-tui/src/security/loader.rs

Código a añadir:

Rust
/* Añadir a la lógica de monitor_sandbox */

fn process_ai_verdict(pid: i32, risk: f32) {
    if risk > 0.85 {
        // ENVIAR SIGSTOP: Congelar el proceso inmediatamente para inspección
        unsafe { libc::kill(pid, libc::SIGSTOP) };
        
        // Notificar a la TUI y registrar evento
        let _ = crate::security::audit::register_tombstone(&format!("AI_HALT: Riesgo detectado {}", risk));
    }
}
5. Monitoreo TUI: Medidor de Riesgo (src-tui/src/main.rs)
Integramos el medidor visual en la pestaña de Monitor de Sistema.

Archivo implicado: src-tui/src/main.rs

Código a editar: Actualizar draw_system_monitor.

Rust
/* Editar en src-tui/src/main.rs */

use ratatui::widgets::Gauge;

fn draw_system_monitor(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40), // Auditoría
            Constraint::Length(3),      // NUEVO: Medidor de Riesgo IA
            Constraint::Percentage(50), // Firmware
        ])
        .split(area);

    // ... (dibujo de auditoría previo)

    // NUEVO: Medidor de Riesgo de IA Local
    let risk_pct = (state.active_sandbox_risk * 100.0) as u16;
    let gauge_color = if risk_pct > 80 { Color::Red } else if risk_pct > 50 { Color::Yellow } else { Color::Green };
    
    let risk_gauge = Gauge::default()
        .block(Block::default().title(" Nivel de Riesgo IA (Heurística Local) ").borders(Borders::ALL))
        .gauge_style(Style::default().fg(gauge_color).bg(Color::Black).add_modifier(Modifier::ITALIC))
        .percent(risk_pct);
    
    frame.render_widget(risk_gauge, chunks[1]);

    // ... (dibujo de firmware previo en chunks[2])
}
Valoración Pericial Forense
Inferencia Fileless: El modelo de IA reside dentro del vault cifrado y se carga en la RAM protegida. No hay archivos de "firmas de virus" visibles en el sistema operativo.

Monitorización Silenciosa: Gracias a eBPF, el software en cuarentena no sabe que está siendo analizado por una IA; no puede detectar el sensor para intentar evadirlo .

Prevención de Daño: El uso de SIGSTOP permite que el sistema reaccione en microsegundos ante un patrón de cifrado masivo (Ransomware), deteniendo la CPU del proceso antes de que se pierda la integridad del primer archivo.
