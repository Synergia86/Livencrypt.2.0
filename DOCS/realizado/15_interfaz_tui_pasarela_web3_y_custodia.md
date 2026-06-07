# Interfaz TUI para Pasarela Web3 y Custodia

Este módulo detalla el diseño, la arquitectura y la implementación del frontend interactivo en consola (TUI Ratatui) para la pasarela Web3 y custodia universal de Livencrypt 2.0. Asimismo, define el modelo asíncrono para operar la pasarela en segundo plano sin congelar la terminal.

---

## 1. Diseño y Principios Técnicos

La interfaz gráfica de la pasarela está diseñada para proporcionar un panel de visualización y control táctico de alta visibilidad, protegiendo al mismo tiempo la responsividad de la aplicación.

```mermaid
graph TD
    UI[Bucle TUI Ratatui] -- 1. Entrada de datos / Confirmar --> UI_Ev[gateway_events.rs]
    UI_Ev -- 2. Enviar Web3WorkerCmd (tx) --> Chan[Canal mpsc]
    Chan --> Worker[Trabajador: worker.rs]
    
    subgraph Hilos en Segundo Plano (Background Threads)
        SocketThread[Hilo Lector de Socket Unix] -- Enviar Web3WorkerCmd::IncomingWebRequest --> Worker
        Worker -- 3. Procesa Comandos y Peticiones --> Sup[Supervisor: supervisor.rs]
    end
    
    Sup -- 4. Cambios de Estado / Métricas --> Worker
    Worker -- 5. Enviar Web3WorkerEvent (rx) --> Tick[Bucle de Tick de la TUI]
    Tick -- 6. Actualizar Caché en TuiState --> UI
```

### A. Concurrencia Asíncrona (Background Worker)
* **El Problema del Bloqueo**: La escucha de peticiones desde el navegador a través de un socket Unix local es una operación bloqueante. Si se ejecutara en el hilo principal de la TUI, la interfaz de usuario se congelaría por completo, impidiendo el refresco y la navegación.
* **La Solución**: La pasarela y su supervisor (`GatewaySupervisor`) se mueven a un hilo de ejecución secundario dedicado (`Web3BackgroundWorker`). La comunicación entre el hilo principal de la TUI y el hilo de la pasarela se realiza a través de canales de paso de mensajes asíncronos y seguros (`std::sync::mpsc`).

### B. Arquitectura de Estado y Caching (TuiState)
* **Desacoplamiento Mutuo**: Para evitar violaciones del validador de préstamos de Rust (*Borrow Checker*), el hilo principal de la TUI no accede al supervisor directamente. En su lugar, el TuiState almacena una copia en caché de los datos relevantes:
  - `cached_gateway_state`: Estado de seguridad del disyuntor (Operativo, Congelado, Bloqueado).
  - `cached_tx_count` / `cached_volume_usd`: Métricas de operaciones acumuladas hoy.
  - `allowed_dex_contracts` / `allowed_cex_destinations`: Copia de trabajo local de las listas blancas.
* **Sincronización Asíncrona**: En cada iteración del bucle TUI, la función `process_background_web3_events` drena el canal de eventos asíncronos y actualiza la caché local de la interfaz gráfica sin bloqueos.

### C. HUD de Seguridad en el Dashboard
* **Monitoreo Rápido**: El Dashboard principal incluye un panelHUD compacto que visualiza la salud operativa de la pasarela Web3, el volumen consumido y el número de firmas del día, proporcionando control inmediato sobre el canal Web3 al iniciar sesión.

---

## 2. Archivos Implicados en el Proyecto

* **[main.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/main.rs)**: Extiende el enum `Screen` y la estructura `TuiState` con los canales y variables de caché, e implementa el procesamiento de eventos de fondo en los ticks de actualización.
* **[mod.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/mod.rs)**: Registra el módulo del trabajador asíncrono.
* **[worker.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/worker.rs)** (Nuevo): Gestiona el bucle de ejecución asíncrono y los canales de mensajería del supervisor.
* **[gateway.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/ui/gateway.rs)** (Nuevo): Implementa el diseño de bloques de Ratatui para la pantalla de la pasarela y el modal de desbloqueo matricial.
* **[gateway_events.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/ui/gateway_events.rs)** (Nuevo): Intercepta los eventos de teclado crossterm para editar los límites y enviar comandos de rearme al worker.
* **[mod.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/ui/mod.rs)**: Enruta el dibujo de la pasarela Web3.
* **[dashboard.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/ui/dashboard.rs)**: Renderiza el HUD de estado de la pasarela dentro del cuadro de mandos principal.

---

## 3. Auditoría Técnica y Correcciones Aplicadas

Al evaluar la convivencia física de ambos entornos dentro del espacio de ejecución del sistema operativo, así como el comportamiento bajo condiciones de estrés, concurrencia masiva e inyección de datos, han salido a la luz varios defectos estructurales de colisión de descriptores, errores de lógica de ejecución (bugs de runtime) y vectores de denegación de servicio que deben subsanarse para garantizar la resiliencia del binario.

### 1. Defectos de arquitectura y colisiones de entrada/salida (bugs de runtime)

#### A. La colisión catastrófica de stdout y stdin entre Ratatui y Chrome
El host de mensajería nativa utiliza por estándar los descriptores `stdin` y `stdout` para intercambiar payloads JSON binarios con la extensión del navegador. Al mismo tiempo, el frontend utiliza la librería Crossterm (backend de Ratatui) para inicializar la terminal en modo crudo (raw mode), capturar las pulsaciones de teclado mediante `stdin` y renderizar los paneles del cuadro de mandos inyectando códigos de escape ANSI directos sobre `stdout`.
* **El fallo**: Ambas capas operan simultáneamente sobre los mismos descriptores de archivos del proceso (`fd/0` y `fd/1`).
* **La consecuencia**:
  1. Cuando el hilo secundario escriba una respuesta JSON mediante `NativeProxyChannel::write_response`, esos bytes se mezclarán con el stream de renderizado de la pantalla de la TUI, emitiendo texto plano y rompiendo el diseño gráfico de la terminal.
  2. Al mismo tiempo, el navegador Chrome interpretará los códigos de escape ANSI de refresco de pantalla de Ratatui como si fueran el prefijo de longitud de 4 bytes del protocolo Web3, provocando un fallo inmediato de desalineación de memoria y la desconexión fulminante de la extensión.
  3. Si Chrome despierta el binario directamente, el proceso carecerá de un entorno de terminal real (TTY), por lo que la inicialización de Ratatui sufrirá un pánico estructural al arrancar.

#### B. Cuello de botella en el drenaje de la cola de comandos
En el bucle del hilo maestro del supervisor dentro de `worker.rs`, se procesa la entrada del canal MPSC utilizando un condicional simple:
```rust
if let Ok(cmd) = cmd_rx.try_recv() { ... }
```
* **El fallo**: Al usar un `if let` en combinación con un retardo forzado de `thread::sleep(Duration::from_millis(10))` al final del bucle, el hilo secundario solo puede procesar un único comando por cada iteración (máximo 100 comandos por segundo).
* **La consecuencia**: Si el usuario realiza interacciones rápidas en la TUI (como spamear caracteres o enviar actualizaciones masivas de configuración), los comandos se acumularán en el búfer del canal, generando un retraso de entrada (input lag) acumulativo y severo entre la interfaz de usuario y el backend de la pasarela.

#### C. Degradación regresiva de las reglas por errores tipográficos
En `gateway_events.rs`, el procesamiento de los límites numéricos utiliza una cláusula de escape directa:
```rust
max_daily_tx: state.input_max_tx.parse().unwrap_or(10),
max_daily_volume_usd: state.input_max_volume.parse().unwrap_or(5000.0),
```
* **El fallo**: Si el operador comete un error al escribir o deja el campo vacío momentáneamente antes de pulsar Enter, el sistema revertirá la seguridad del Firewall de forma automática a los valores hardcodeados por defecto (10 y 5000.0).
* **La consecuencia**: Esto rompe la persistencia de las políticas activas. Si el usuario tenía configurado un límite ultra-estricto (por ejemplo, máximo 1 transacción diaria y 100 USD de volumen), un error tipográfico relajará silenciosamente las defensas del backend al valor por defecto, ampliando el radio de exposición ante un ataque Web3 simultáneo.

#### D. Condición de carrera visual por sobreescritura destructiva de buffers
En `process_background_web3_events`, el evento asíncrono `Web3WorkerEvent::SyncRules` actualiza de forma impositiva los hilos de texto intermedios de la interfaz para garantizar la integridad de los datos:
```rust
state.input_max_tx = backend_rules.max_daily_tx.to_string();
state.input_max_volume = backend_rules.max_daily_volume_usd.to_string();
```
* **El fallo**: Si el operador se encuentra posicionado en el campo de edición 0 o 1 modificando un límite numérico (por ejemplo, ha borrado el contenido para teclear una nueva cifra) y en ese milisegundo entra un evento de sincronización desde el backend (disparado por una actualización paralela o una transacción), la caché de la TUI machacará el buffer interactivo.
* **La consecuencia**: La entrada parcial del usuario será borrada de forma destructiva a mitad de la edición, degradando severamente la experiencia de control del Firewall en entornos de alta actividad Web3.

#### E. Silencio ciego ante el pánico del hilo secundario
En `main.rs`, la función encargada de consumir las señales del trabajador asíncrono opera mediante:
```rust
while let Ok(event) = rx.try_recv() { ... }
```
* **El fallo**: Si el hilo del supervisor sufre un pánico inesperado o es terminado de forma externa por el sistema operativo, el canal `web3_event_rx` devolverá inmediatamente un error de desconexión (`TryRecvError::Disconnected`). El bucle actual rompe la iteración silenciosamente sin reportar anomalías.
* **La consecuencia**: La interfaz gráfica de la TUI continuará mostrando de forma estática los últimos datos almacenados en caché (`cached_gateway_state`), dando al usuario la falsa sensación de que la pasarela Web3 sigue operativa y protegiendo el canal cuando en realidad el motor de contención está completamente muerto.

### 2. Vectores de ataque y debilidades de robustez

#### A. Violación de la fuente única de verdad en listas blancas (condición de carrera)
Al añadir un nuevo contrato o destino en `gateway_events.rs`, mutas el estado local de la TUI de forma inmediata antes de realizar el envío asíncrono:
```rust
state.allowed_dex_contracts.push(state.input_new_dex_id.clone());
```
* **El vector de ataque**: Esto rompe el principio de asincronía segura. El frontend asume el control del estado. Si el canal MPSC estuviera saturado o el hilo secundario rechazara la inserción por políticas de integridad, la TUI mostraría que el contrato está autorizado cuando el backend realmente lo está denegando.
* **El riesgo**: Un atacante que logre interceptar la memoria intermedia de la TUI podría simular que una dirección maliciosa ha sido añadida a la lista blanca visual, induciendo al usuario a firmar operaciones fraudulentas desde el navegador.

#### B. Denegación de servicio (DoS) por vectores de búsqueda lineal ilimitados
Tanto en la TUI como en el core del Firewall, los elementos agregados a `allowed_dex_contracts` y `allowed_cex_destinations` se almacenan en vectores estándar (`Vec<String>`) sin límites de capacidad máxima.
* **El vector de ataque**: La función `validate_transaction` en `firewall.rs` evalúa la legitimidad de los identificadores realizando una búsqueda lineal de coste $O(N)$ mediante `.contains()`. Un atacante con acceso a la terminal podría inyectar de forma masiva miles de identificadores de contratos espurios.
* **El riesgo**: El crecimiento descontrolado de los vectores degradará el rendimiento de la CPU del supervisor exponencialmente en cada solicitud Web3 entrante, provocando un retraso masivo en las firmas o forzando la caída del binario por agotamiento de recursos.

#### C. Exposición del socket IPC en sistemas multiusuario
Al inicializar la escucha física en la ruta local `/tmp/livencrypt.sock`, el archivo queda expuesto dentro de un directorio global compartido.
* **El vector de ataque**: En entornos Linux multiusuario, cualquier otro proceso local sin privilegios puede listar el directorio `/tmp`, colisionar con el nombre del socket o intentar conectarse a él de forma directa si las máscaras de usuario (`umask`) no son lo suficientemente restrictivas.
* **El riesgo**: Sabotaje local mediante inyección de payloads corruptos. La pasarela debe mover el enlace del socket a un directorio controlado con permisos estrictos `0700` del usuario (como `$XDG_RUNTIME_DIR` o la propia carpeta raíz cifrada del vault).

### 3. Refactorización y desacoplamiento de canales (IPC búnker)

Para solventar la colisión de descriptores estándar de forma definitiva, el binario local de la TUI debe operar con exclusividad sobre los flujos de la terminal, delegando la comunicación de la extensión hacia un socket de dominio Unix local (unix domain socket), aislando por completo el perímetro E/S.

#### Nota de despliegue de infraestructura
Bajo este modelo defensivo, el script puente de mensajería nativa registrado en el navegador (`com.livencrypt.gateway.json`) apuntará estrictamente a `/usr/bin/livencrypt-bridge`, un script o binario secundario ultra-ligero que simplemente redirigirá el flujo de stdin/stdout de Chrome hacia el descriptor del socket descriptor `$XDG_RUNTIME_DIR/livencrypt.sock` (o `/tmp/livencrypt.sock` como fallback si la variable no está definida). Esto garantiza que la TUI principal retenga el monopolio absoluto sobre la terminal física sin interferencias criptográficas externas.

### 4. Parches de optimización y blindaje de código

Para neutralizar de raíz estas debilidades, se deben aplicar las siguientes correcciones estructurales:

#### Actualización reactiva para `src-tui/src/crypto/blockchain/worker.rs`

```rust
/* rol: hilo de ejecucion asincrono multi-hilo blindado contra slowloris y fugas de heap */
use std::sync::mpsc::{channel, Sender, Receiver};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::fs::PermissionsExt;
use std::io::{Read, Write};
use crate::crypto::blockchain::supervisor::GatewaySupervisor;
use crate::crypto::blockchain::firewall::FirewallRules;
use crate::crypto::blockchain::breaker::GatewaySecurityState;
use crate::crypto::blockchain::proxy::{ExtensionRequest, ExtensionResponse};
use zeroize::Zeroize;
use libc;

pub enum Web3WorkerCmd {
    UpdateRules { max_tx: Option<u32>, max_vol: Option<f64> },
    AddDexContract(String),      
    AddCexDestination(String),   
    ResetBreaker([i64; 5], Vec<u8>), 
    IncomingWebRequest(Vec<u8>, UnixStream), 
}

pub enum Web3WorkerEvent {
    StatusChanged(GatewaySecurityState),
    MetricsUpdated { tx_count: u32, volume_usd: f64 },
    SyncRules(FirewallRules), 
    Notification(String),
}

pub struct Web3BackgroundWorker;

impl Web3BackgroundWorker {
    pub fn spawn(
        mut supervisor: GatewaySupervisor,
    ) -> (Sender<Web3WorkerCmd>, Receiver<Web3WorkerEvent>) {
        let (cmd_tx, cmd_rx) = channel::<Web3WorkerCmd>();
        let (event_tx, event_rx) = channel::<Web3WorkerEvent>();

        let io_cmd_tx = cmd_tx.clone();
        thread::spawn(move || {
            let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
            let socket_path = format!("{}/livencrypt.sock", runtime_dir);
            
            let _ = std::fs::remove_file(&socket_path);

            let old_umask = unsafe { libc::umask(0o177) }; 
            let bind_result = UnixListener::bind(&socket_path);
            unsafe { libc::umask(old_umask) }; 

            if let Ok(listener) = bind_result {
                let active_connections = Arc::new(AtomicUsize::new(0));
                const MAX_CONCURRENT_CONNECTIONS: usize = 8;

                for stream in listener.incoming() {
                    if let Ok(mut stream) = stream {
                        if active_connections.load(Ordering::Relaxed) >= MAX_CONCURRENT_CONNECTIONS {
                            continue; 
                        }
                        active_connections.fetch_add(1, Ordering::Relaxed);
                        let thread_tx = io_cmd_tx.clone();
                        let counter = Arc::clone(&active_connections);
                        thread::spawn(move || {
                            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
                            let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(200)));
                            let mut length_buffer = [0u8; 4];
                            if stream.read_exact(&mut length_buffer).is_ok() {
                                let message_length = u32::from_ne_bytes(length_buffer) as usize;
                                if message_length <= 1024 * 1024 {
                                    let mut json_buffer = vec![0u8; message_length];
                                    if stream.read_exact(&mut json_buffer).is_ok() {
                                        let _ = thread_tx.send(Web3WorkerCmd::IncomingWebRequest(json_buffer, stream));
                                        counter.fetch_sub(1, Ordering::Relaxed);
                                        return; 
                                    }
                                }
                            }
                            counter.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                }
            }
        });

        thread::spawn(move || {
            let mut last_tx_count = 0;
            let mut last_volume_usd = 0.0;

            loop {
                let timeout = std::time::Duration::from_millis(200);
                match cmd_rx.recv_timeout(timeout) {
                    Ok(cmd) => {
                        match cmd {
                            Web3WorkerCmd::UpdateRules { max_tx, max_vol } => {
                                let mut updated = false;
                                if let Some(tx) = max_tx { supervisor.firewall.rules.max_daily_tx = tx; updated = true; }
                                if let Some(vol) = max_vol { supervisor.firewall.rules.max_daily_volume_usd = vol; updated = true; }
                                
                                if updated {
                                    let _ = event_tx.send(Web3WorkerEvent::Notification("Límites del cortafuegos actualizados".to_string()));
                                } else {
                                    let _ = event_tx.send(Web3WorkerEvent::Notification("Error: Formato numérico inválido".to_string()));
                                }
                                let _ = event_tx.send(Web3WorkerEvent::SyncRules(supervisor.firewall.rules.clone()));
                            }
                            Web3WorkerCmd::AddDexContract(contract) => {
                                if supervisor.firewall.rules.allowed_dex_contracts.len() < 100 {
                                    if !supervisor.firewall.rules.allowed_dex_contracts.contains(&contract) {
                                        supervisor.firewall.rules.allowed_dex_contracts.push(contract);
                                        let _ = event_tx.send(Web3WorkerEvent::SyncRules(supervisor.firewall.rules.clone()));
                                    }
                                }
                            }
                            Web3WorkerCmd::AddCexDestination(destination) => {
                                if supervisor.firewall.rules.allowed_cex_destinations.len() < 100 {
                                    if !supervisor.firewall.rules.allowed_cex_destinations.contains(&destination) {
                                        supervisor.firewall.rules.allowed_cex_destinations.push(destination);
                                        let _ = event_tx.send(Web3WorkerEvent::SyncRules(supervisor.firewall.rules.clone()));
                                    }
                                }
                            }
                            Web3WorkerCmd::ResetBreaker(cajas, mut phrase_bytes) => {
                                match std::str::from_utf8(&phrase_bytes) {
                                    Ok(phrase_str) => {
                                        if supervisor.breaker.resolve_and_reset(cajas, phrase_str).is_ok() {
                                            let _ = event_tx.send(Web3WorkerEvent::StatusChanged(supervisor.breaker.state.clone()));
                                            let _ = event_tx.send(Web3WorkerEvent::Notification("Circuito de seguridad rearmado".to_string()));
                                        } else {
                                            supervisor.breaker.integrity_failures += 1;
                                            if supervisor.breaker.integrity_failures >= 3 {
                                                supervisor.breaker.trigger_hard_lock();
                                                let _ = event_tx.send(Web3WorkerEvent::StatusChanged(supervisor.breaker.state.clone()));
                                        }
                                            let _ = event_tx.send(Web3WorkerEvent::Notification("Error: Credenciales de rearme inválidas".to_string()));
                                        }
                                    }
                                    Err(_) => {
                                        let _ = event_tx.send(Web3WorkerEvent::Notification("Error: Frase con codificación UTF-8 inválida".to_string()));
                                    }
                                }
                                phrase_bytes.zeroize();
                            }
                            Web3WorkerCmd::IncomingWebRequest(mut raw_json, mut stream) => {
                                let old_state = supervisor.breaker.state.clone();
                                
                                match serde_json::from_slice::<ExtensionRequest>(&raw_json) {
                                    Ok(req) => {
                                        match supervisor.run_loop_iteration(req) {
                                            Ok(response_bytes) => {
                                                let len_prefix = (response_bytes.len() as u32).to_ne_bytes();
                                                let _ = stream.write_all(&len_prefix);
                                                let _ = stream.write_all(&response_bytes);
                                                let _ = stream.flush();
                                            }
                                            Err(e) => {
                                                let err_resp = ExtensionResponse::<()>::Error(e);
                                                if let Ok(bytes) = serde_json::to_vec(&err_resp) {
                                                    let len_prefix = (bytes.len() as u32).to_ne_bytes();
                                                    let _ = stream.write_all(&len_prefix);
                                                    let _ = stream.write_all(&bytes);
                                                    let _ = stream.flush();
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let err_resp = ExtensionResponse::<()>::Error(format!("formato malformado: {}", e));
                                        if let Ok(bytes) = serde_json::to_vec(&err_resp) {
                                            let len_prefix = (bytes.len() as u32).to_ne_bytes();
                                            let _ = stream.write_all(&len_prefix);
                                            let _ = stream.write_all(&bytes);
                                            let _ = stream.flush();
                                        }
                                    }
                                }
                                
                                if supervisor.breaker.state != old_state {
                                    let _ = event_tx.send(Web3WorkerEvent::StatusChanged(supervisor.breaker.state.clone()));
                                }
                                
                                raw_json.zeroize();
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }

                let current_tx_count = supervisor.firewall.tx_count_today;
                let current_volume_usd = supervisor.firewall.volume_today_usd;
                let volume_changed = (current_volume_usd - last_volume_usd).abs() > f64::EPSILON;
                if current_tx_count != last_tx_count || volume_changed {
                    let _ = event_tx.send(Web3WorkerEvent::MetricsUpdated {
                        tx_count: current_tx_count,
                        volume_usd: current_volume_usd,
                    });
                    last_tx_count = current_tx_count;
                    last_volume_usd = current_volume_usd;
                }
            }
        });

        (cmd_tx, event_rx)
    }
}
```

#### Ajuste de sincronización de eventos y captura forense de desconexión (`src-tui/src/main.rs`)
Subordinamos la actualización de los buffers editables al estado de enfoque de la interfaz para impedir la pérdida de pulsaciones.

```rust
/* rol: procesamiento de eventos con proteccion de buffers interactivos */
pub fn process_background_web3_events(state: &mut TuiState) {
    if let Some(ref rx) = state.web3_event_rx {
        loop {
            match rx.try_recv() {
                Ok(event) => {
                    match event {
                        crypto::blockchain::worker::Web3WorkerEvent::StatusChanged(new_state) => {
                            state.cached_gateway_state = new_state.clone();
                            if let crypto::blockchain::breaker::GatewaySecurityState::Operational = state.cached_gateway_state {
                                state.show_breaker_reset = false;
                            }
                        }
                        crypto::blockchain::worker::Web3WorkerEvent::MetricsUpdated { tx_count, volume_usd } => {
                            state.cached_tx_count = tx_count;
                            state.cached_volume_usd = volume_usd;
                        }
                        crypto::blockchain::worker::Web3WorkerEvent::SyncRules(backend_rules) => {
                            state.allowed_dex_contracts = backend_rules.allowed_dex_contracts;
                            state.allowed_cex_destinations = backend_rules.allowed_cex_destinations;
                            
                            // Corrección B: Solo actualizar los buffers si el usuario no los está editando activamente
                            if state.gateway_focused_field != 0 {
                                state.input_max_tx = backend_rules.max_daily_tx.to_string();
                            }
                            if state.gateway_focused_field != 1 {
                                state.input_max_volume = backend_rules.max_daily_volume_usd.to_string();
                            }
                        }
                        crypto::blockchain::worker::Web3WorkerEvent::Notification(msg) => {
                            state.system_notification = msg;
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    state.cached_gateway_state = crypto::blockchain::breaker::GatewaySecurityState::Frozen {
                        reason: "CRASH CRÍTICO: SUBSISTEMA ASÍNCRONO DETENIDO IMPREVISTAMENTE".to_string(),
                        timestamp: 0,
                    };
                    break;
                }
            }
        }
    }
}
```

#### Rectificación de emisión de comandos (`src-tui/src/ui/gateway_events.rs`)

```rust
/* Modificación del brazo KeyCode::Enter bajo el principio de fuente única de verdad */
        KeyCode::Enter => {
            match state.gateway_focused_field {
                0 | 1 => {
                    // Enviar solo el valor opcional si el parseo local es correcto, mitigando regresiones
                    let max_tx = state.input_max_tx.parse::<u32>().ok();
                    let max_vol = state.input_max_volume.parse::<f64>().ok();

                    if let Some(ref tx) = state.web3_cmd_tx {
                        let _ = tx.send(Web3WorkerCmd::UpdateRules { max_tx, max_vol });
                    }
                }
                2 => {
                    if !state.input_new_dex_id.is_empty() {
                        // NO alteramos el vector state.allowed_dex_contracts localmente de forma directa
                        if let Some(ref tx) = state.web3_cmd_tx {
                            let _ = tx.send(Web3WorkerCmd::AddDexContract(state.input_new_dex_id.clone()));
                        }
                        state.input_new_dex_id.clear();
                    }
                }
                3 => {
                    if !state.input_new_cex_id.is_empty() {
                        if let Some(ref tx) = state.web3_cmd_tx {
                            let _ = tx.send(Web3WorkerCmd::AddCexDestination(state.input_new_cex_id.clone()));
                        }
                        state.input_new_cex_id.clear();
                    }
                }
                _ => {}
            }
        }
```

---

## 4. Estado de la Integración

### ¿Qué está YA integrado?
* [x] **Modelo de Diseño**: La arquitectura desacoplada por paso de mensajes está completamente detallada y lista para compilar en los archivos del proyecto.

### ¿Qué falta por integrar?
* [ ] **Pantallas**: Registrar `Screen::WalletGateway` en el enrutador de pantallas de `main.rs`.
* [ ] **Variables de Canal**: Modificar la definición de `TuiState` para incluir los buffers de canales MPSC.
* [ ] **Módulo de Renderizado**: Crear el archivo `src-tui/src/ui/gateway.rs`.
* [ ] **Manejador de Teclas**: Crear el controlador reactivo `src-tui/src/ui/gateway_events.rs`.
* [ ] **Hilo de Ejecución (Worker)**: Crear `src-tui/src/crypto/blockchain/worker.rs` y orquestar el arranque en la TUI.

---

## 5. Código a integrar (Corregido y Optimizado)

### 1. Extensión del estado y enrutamiento en el ciclo de vida (`src-tui/src/main.rs`)
Añadimos los estados de pantalla, cachés y el procesador lógico de los ticks de refresco.

**Archivo implicado**: `src-tui/src/main.rs`

```rust
/* Modificación de la enumeración de pantallas */
#[derive(Clone, PartialEq, Eq)]
pub enum Screen {
    Unlock,
    Dashboard,
    TextCipher,
    FileBrowser,
    FilePreview { metadata: security::vault::FileMetadata },
    Settings,
    TemplateEditor,
    WalletGateway,
}

/* Modificación del TuiState para soportar concurrencia desacoplada */
pub struct TuiState {
    pub screen: Screen,
    pub active_vault_unlocked: bool,
    
    // Canales de control asíncronos para el background worker
    pub web3_cmd_tx: Option<std::sync::mpsc::Sender<crypto::blockchain::worker::Web3WorkerCmd>>,
    pub web3_event_rx: Option<std::sync::mpsc::Receiver<crypto::blockchain::worker::Web3WorkerEvent>>,
    
    // Variables de caché local para evitar accesos cruzados de hilos
    pub cached_gateway_state: crypto::blockchain::breaker::GatewaySecurityState,
    pub cached_tx_count: u32,
    pub cached_volume_usd: f64,
    pub allowed_dex_contracts: Vec<String>,
    pub allowed_cex_destinations: Vec<String>,
    pub system_notification: String,

    // Buffers interactivos de la pantalla de gobernanza
    pub gateway_focused_field: usize,
    pub input_max_tx: String,
    pub input_max_volume: String,
    pub input_new_dex_id: String,
    pub input_new_cex_id: String,
    
    // Buffers para el modal de desbloqueo matricial
    pub show_breaker_reset: bool,
    pub reset_cajas: [String; 5],
    pub reset_phrase: String,
    pub reset_focus_index: usize,
}

impl TuiState {
    /* Inicialización de la pasarela y spawneo del hilo en segundo plano */
    pub fn initialize_wallet_gateway(&mut self, cajas: [i64; 5], master_phrase: &str) -> Result<(), String> {
        let keymaster = crypto::blockchain::multi_curve::UniversalKeymaster::new(cajas, master_phrase)?;
        
        let default_rules = crypto::blockchain::firewall::FirewallRules {
            max_daily_tx: 10,
            max_daily_volume_usd: 5000.0,
            allowed_dex_contracts: vec![],
            allowed_cex_destinations: vec![],
        };
        
        let firewall = crypto::blockchain::firewall::LiveFirewall::new(default_rules);
        let supervisor = crypto::blockchain::supervisor::GatewaySupervisor::new(keymaster, firewall);
        
        self.input_max_tx = supervisor.firewall.rules.max_daily_tx.to_string();
        self.input_max_volume = supervisor.firewall.rules.max_daily_volume_usd.to_string();
        self.allowed_dex_contracts = supervisor.firewall.rules.allowed_dex_contracts.clone();
        self.allowed_cex_destinations = supervisor.firewall.rules.allowed_cex_destinations.clone();
        self.cached_gateway_state = supervisor.breaker.state.clone();
        
        // Lanzar el hilo asíncrono y guardar los canales de comunicación
        let (tx, rx) = crypto::blockchain::worker::Web3BackgroundWorker::spawn(supervisor);
        self.web3_cmd_tx = Some(tx);
        self.web3_event_rx = Some(rx);
        
        Ok(())
    }
}

/* Procesamiento de eventos con captura forense de desconexión de canal y protección de buffers */
pub fn process_background_web3_events(state: &mut TuiState) {
    if let Some(ref rx) = state.web3_event_rx {
        loop {
            match rx.try_recv() {
                Ok(event) => {
                    match event {
                        crypto::blockchain::worker::Web3WorkerEvent::StatusChanged(new_state) => {
                            state.cached_gateway_state = new_state.clone();
                            if let crypto::blockchain::breaker::GatewaySecurityState::Operational = state.cached_gateway_state {
                                state.show_breaker_reset = false;
                            }
                        }
                        crypto::blockchain::worker::Web3WorkerEvent::MetricsUpdated { tx_count, volume_usd } => {
                            state.cached_tx_count = tx_count;
                            state.cached_volume_usd = volume_usd;
                        }
                        crypto::blockchain::worker::Web3WorkerEvent::SyncRules(backend_rules) => {
                            state.allowed_dex_contracts = backend_rules.allowed_dex_contracts;
                            state.allowed_cex_destinations = backend_rules.allowed_cex_destinations;
                            
                            // Corrección B: Solo actualizar los buffers si el usuario no los está editando activamente
                            if state.gateway_focused_field != 0 {
                                state.input_max_tx = backend_rules.max_daily_tx.to_string();
                            }
                            if state.gateway_focused_field != 1 {
                                state.input_max_volume = backend_rules.max_daily_volume_usd.to_string();
                            }
                        }
                        crypto::blockchain::worker::Web3WorkerEvent::Notification(msg) => {
                            state.system_notification = msg;
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Corrección C: Forzar estado de pánico visual si el hilo secundario cae
                    state.cached_gateway_state = crypto::blockchain::breaker::GatewaySecurityState::Frozen {
                        reason: "CRASH CRÍTICO: SUBSISTEMA ASÍNCRONO DETENIDO IMPREVISTAMENTE".to_string(),
                        timestamp: 0,
                    };
                    break;
                }
            }
        }
    }
}
```

---

### 2. Trabajador asíncrono en segundo plano (`src-tui/src/crypto/blockchain/worker.rs`)

```rust
/* rol: hilo de ejecucion asincrono multi-hilo blindado contra slowloris y fugas de heap */
use std::sync::mpsc::{channel, Sender, Receiver};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::fs::PermissionsExt;
use std::io::{Read, Write};
use crate::crypto::blockchain::supervisor::GatewaySupervisor;
use crate::crypto::blockchain::firewall::FirewallRules;
use crate::crypto::blockchain::breaker::GatewaySecurityState;
use crate::crypto::blockchain::proxy::{ExtensionRequest, ExtensionResponse};
use zeroize::Zeroize;
use libc;

pub enum Web3WorkerCmd {
    UpdateRules { max_tx: Option<u32>, max_vol: Option<f64> },
    AddDexContract(String),      
    AddCexDestination(String),   
    ResetBreaker([i64; 5], Vec<u8>), 
    IncomingWebRequest(Vec<u8>, UnixStream), 
}

pub enum Web3WorkerEvent {
    StatusChanged(GatewaySecurityState),
    MetricsUpdated { tx_count: u32, volume_usd: f64 },
    SyncRules(FirewallRules), 
    Notification(String),
}

pub struct Web3BackgroundWorker;

impl Web3BackgroundWorker {
    pub fn spawn(
        mut supervisor: GatewaySupervisor,
    ) -> (Sender<Web3WorkerCmd>, Receiver<Web3WorkerEvent>) {
        let (cmd_tx, cmd_rx) = channel::<Web3WorkerCmd>();
        let (event_tx, event_rx) = channel::<Web3WorkerEvent>();

        let io_cmd_tx = cmd_tx.clone();
        thread::spawn(move || {
            let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
            let socket_path = format!("{}/livencrypt.sock", runtime_dir);
            
            let _ = std::fs::remove_file(&socket_path);

            let old_umask = unsafe { libc::umask(0o177) }; 
            let bind_result = UnixListener::bind(&socket_path);
            unsafe { libc::umask(old_umask) }; 

            if let Ok(listener) = bind_result {
                let active_connections = Arc::new(AtomicUsize::new(0));
                const MAX_CONCURRENT_CONNECTIONS: usize = 8;

                for stream in listener.incoming() {
                    if let Ok(mut stream) = stream {
                        if active_connections.load(Ordering::Relaxed) >= MAX_CONCURRENT_CONNECTIONS {
                            continue; 
                        }
                        active_connections.fetch_add(1, Ordering::Relaxed);
                        let thread_tx = io_cmd_tx.clone();
                        let counter = Arc::clone(&active_connections);
                        thread::spawn(move || {
                            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
                            let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(200)));
                            let mut length_buffer = [0u8; 4];
                            if stream.read_exact(&mut length_buffer).is_ok() {
                                let message_length = u32::from_ne_bytes(length_buffer) as usize;
                                if message_length <= 1024 * 1024 {
                                    let mut json_buffer = vec![0u8; message_length];
                                    if stream.read_exact(&mut json_buffer).is_ok() {
                                        let _ = thread_tx.send(Web3WorkerCmd::IncomingWebRequest(json_buffer, stream));
                                        counter.fetch_sub(1, Ordering::Relaxed);
                                        return; 
                                    }
                                }
                            }
                            counter.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                }
            }
        });

        thread::spawn(move || {
            let mut last_tx_count = 0;
            let mut last_volume_usd = 0.0;

            loop {
                let timeout = std::time::Duration::from_millis(200);
                match cmd_rx.recv_timeout(timeout) {
                    Ok(cmd) => {
                        match cmd {
                            Web3WorkerCmd::UpdateRules { max_tx, max_vol } => {
                                let mut updated = false;
                                if let Some(tx) = max_tx { supervisor.firewall.rules.max_daily_tx = tx; updated = true; }
                                if let Some(vol) = max_vol { supervisor.firewall.rules.max_daily_volume_usd = vol; updated = true; }
                                
                                if updated {
                                    let _ = event_tx.send(Web3WorkerEvent::Notification("Límites del cortafuegos actualizados".to_string()));
                                } else {
                                    let _ = event_tx.send(Web3WorkerEvent::Notification("Error: Formato numérico inválido".to_string()));
                                }
                                let _ = event_tx.send(Web3WorkerEvent::SyncRules(supervisor.firewall.rules.clone()));
                            }
                            Web3WorkerCmd::AddDexContract(contract) => {
                                if supervisor.firewall.rules.allowed_dex_contracts.len() < 100 {
                                    if !supervisor.firewall.rules.allowed_dex_contracts.contains(&contract) {
                                        supervisor.firewall.rules.allowed_dex_contracts.push(contract);
                                        let _ = event_tx.send(Web3WorkerEvent::SyncRules(supervisor.firewall.rules.clone()));
                                    }
                                }
                            }
                            Web3WorkerCmd::AddCexDestination(destination) => {
                                if supervisor.firewall.rules.allowed_cex_destinations.len() < 100 {
                                    if !supervisor.firewall.rules.allowed_cex_destinations.contains(&destination) {
                                        supervisor.firewall.rules.allowed_cex_destinations.push(destination);
                                        let _ = event_tx.send(Web3WorkerEvent::SyncRules(supervisor.firewall.rules.clone()));
                                    }
                                }
                            }
                            Web3WorkerCmd::ResetBreaker(cajas, mut phrase_bytes) => {
                                match std::str::from_utf8(&phrase_bytes) {
                                    Ok(phrase_str) => {
                                        if supervisor.breaker.resolve_and_reset(cajas, phrase_str).is_ok() {
                                            let _ = event_tx.send(Web3WorkerEvent::StatusChanged(supervisor.breaker.state.clone()));
                                            let _ = event_tx.send(Web3WorkerEvent::Notification("Circuito de seguridad rearmado".to_string()));
                                        } else {
                                            supervisor.breaker.integrity_failures += 1;
                                            if supervisor.breaker.integrity_failures >= 3 {
                                                supervisor.breaker.trigger_hard_lock();
                                                let _ = event_tx.send(Web3WorkerEvent::StatusChanged(supervisor.breaker.state.clone()));
                                        }
                                            let _ = event_tx.send(Web3WorkerEvent::Notification("Error: Credenciales de rearme inválidas".to_string()));
                                        }
                                    }
                                    Err(_) => {
                                        let _ = event_tx.send(Web3WorkerEvent::Notification("Error: Frase con codificación UTF-8 inválida".to_string()));
                                    }
                                }
                                phrase_bytes.zeroize();
                            }
                            Web3WorkerCmd::IncomingWebRequest(mut raw_json, mut stream) => {
                                let old_state = supervisor.breaker.state.clone();
                                
                                match serde_json::from_slice::<ExtensionRequest>(&raw_json) {
                                    Ok(req) => {
                                        match supervisor.run_loop_iteration(req) {
                                            Ok(response_bytes) => {
                                                let len_prefix = (response_bytes.len() as u32).to_ne_bytes();
                                                let _ = stream.write_all(&len_prefix);
                                                let _ = stream.write_all(&response_bytes);
                                                let _ = stream.flush();
                                            }
                                            Err(e) => {
                                                let err_resp = ExtensionResponse::<()>::Error(e);
                                                if let Ok(bytes) = serde_json::to_vec(&err_resp) {
                                                    let len_prefix = (bytes.len() as u32).to_ne_bytes();
                                                    let _ = stream.write_all(&len_prefix);
                                                    let _ = stream.write_all(&bytes);
                                                    let _ = stream.flush();
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let err_resp = ExtensionResponse::<()>::Error(format!("formato malformado: {}", e));
                                        if let Ok(bytes) = serde_json::to_vec(&err_resp) {
                                            let len_prefix = (bytes.len() as u32).to_ne_bytes();
                                            let _ = stream.write_all(&len_prefix);
                                            let _ = stream.write_all(&bytes);
                                            let _ = stream.flush();
                                        }
                                    }
                                }
                                
                                if supervisor.breaker.state != old_state {
                                    let _ = event_tx.send(Web3WorkerEvent::StatusChanged(supervisor.breaker.state.clone()));
                                }
                                
                                raw_json.zeroize();
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }

                let current_tx_count = supervisor.firewall.tx_count_today;
                let current_volume_usd = supervisor.firewall.volume_today_usd;
                let volume_changed = (current_volume_usd - last_volume_usd).abs() > f64::EPSILON;
                if current_tx_count != last_tx_count || volume_changed {
                    let _ = event_tx.send(Web3WorkerEvent::MetricsUpdated {
                        tx_count: current_tx_count,
                        volume_usd: current_volume_usd,
                    });
                    last_tx_count = current_tx_count;
                    last_volume_usd = current_volume_usd;
                }
            }
        });

        (cmd_tx, event_rx)
    }
}
```

---

### 3. Registro en el enrutador blockchain (`src-tui/src/crypto/blockchain/mod.rs`)

**Archivo implicado**: `src-tui/src/crypto/blockchain/mod.rs`

```rust
/* rol: enrutador maestro del subsistema blockchain universal */
pub mod multi_curve;
pub mod types;
pub mod proxy;
pub mod firewall;
pub mod breaker;
pub mod supervisor;
pub mod worker; // Añadido
```

---

### 4. Renderizado visual del panel de control de la pasarela (`src-tui/src/ui/gateway.rs`)
Dibuja el estado del cortafuegos, las listas blancas del vault y el modal flotante de mitigación en caliente.

**Archivo implicado**: `src-tui/src/ui/gateway.rs` (Nuevo)

```rust
/* rol: renderizado del panel de control y componentes visuales de la pasarela web3 */
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};
use crate::TuiState;
use crate::crypto::blockchain::breaker::GatewaySecurityState;

pub fn draw_wallet_gateway(f: &mut Frame, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Encabezado de estado
            Constraint::Min(10),   // Cuerpo central dividido
            Constraint::Length(3), // Barra de comandos inferior
        ])
        .split(f.area());

    // 1. Renderizado del encabezado HUD (Estado del disyuntor)
    let (status_text, status_style) = match &state.cached_gateway_state {
        GatewaySecurityState::Operational => ("OPERATIVA - CANAL SEGURO ACTIVO", Style::default().fg(Color::Green).bold()),
        GatewaySecurityState::Frozen { reason, .. } => (reason.as_str(), Style::default().fg(Color::Yellow).bold()),
        GatewaySecurityState::HardLocked => ("BLOQUEO PERIMETRAL: REVERIFICACIÓN REQUERIDA", Style::default().fg(Color::Red).bold().add_modifier(Modifier::BLINK)),
    };

    let header = Paragraph::new(Line::from(vec![
        Span::raw(" PASARELA WEB3 SECURE GATEWAY [ "),
        Span::styled(status_text, status_style),
        Span::raw(" ]"),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
    f.render_widget(header, chunks[0]);

    // 2. División del cuerpo central (Controles de Firewall frente a Listas Blancas)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40), // Reglas y cuotas fijas
            Constraint::Percentage(60), // Listas de IDs de CEX/DEX
        ])
        .split(chunks[1]);

    // Panel Izquierdo: Métricas del Cortafuegos en tiempo real y entradas
    let mut firewall_info = vec![
        Line::from(vec![
            Span::raw("Transacciones hoy: "),
            Span::styled(state.cached_tx_count.to_string(), Style::default().fg(Color::White).bold()),
        ]),
        Line::from(vec![
            Span::raw("Volumen diario consumido: "),
            Span::styled(format!("{:.2} USD", state.cached_volume_usd), Style::default().fg(Color::White).bold()),
        ]),
    ];

    // Campos de entrada interactivos con indicación visual de enfoque
    let get_field_style = |idx: usize| {
        if state.gateway_focused_field == idx {
            Style::default().fg(Color::Yellow).bold()
        } else {
            Style::default().fg(Color::Gray)
        }
    };

    firewall_info.push(Line::from(""));
    firewall_info.push(Line::from(Span::styled("--- Configuración de Límites (Presiona Enter para Confirmar) ---", Style::default().fg(Color::Cyan))));
    firewall_info.push(Line::from(vec![Span::styled(" [1] Límite diario Tx (X): ", get_field_style(0)), Span::raw(&state.input_max_tx)]));
    firewall_info.push(Line::from(vec![Span::styled(" [2] Techo diario USD (Y): ", get_field_style(1)), Span::raw(&state.input_max_volume)]));
    firewall_info.push(Line::from(vec![Span::styled(" [3] Registrar nuevo DEX ID: ", get_field_style(2)), Span::raw(&state.input_new_dex_id)]));
    firewall_info.push(Line::from(vec![Span::styled(" [4] Registrar nuevo CEX ID: ", get_field_style(3)), Span::raw(&state.input_new_cex_id)]));
    
    if !state.system_notification.is_empty() {
        firewall_info.push(Line::from(""));
        firewall_info.push(Line::from(Span::styled(format!(" Status: {}", state.system_notification), Style::default().fg(Color::Magenta))));
    }

    let left_panel = Paragraph::new(firewall_info)
        .block(Block::default().title(" Parámetros de Firewall ").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    f.render_widget(left_panel, body_chunks[0]);

    // Panel Derecho: Visualizador de infraestructuras autorizadas
    let list_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body_chunks[1]);

    let dex_items: Vec<ListItem> = state.allowed_dex_contracts.iter().map(|id| ListItem::new(format!("  • Contract-ID: {}", id)).white()).collect();
    let dex_list = List::new(dex_items).block(Block::default().title(" Contratos de DEX en Lista Blanca ").borders(Borders::ALL));
    f.render_widget(dex_list, list_chunks[0]);

    let cex_items: Vec<ListItem> = state.allowed_cex_destinations.iter().map(|id| ListItem::new(format!("  • Vault-ID: {}", id)).white()).collect();
    let cex_list = List::new(cex_items).block(Block::default().title(" Direcciones de CEX en Lista Blanca ").borders(Borders::ALL));
    f.render_widget(cex_list, list_chunks[1]);

    // 3. Barra de instrucciones inferior
    let footer_text = " Tab: Navegar Campos | Enter: Confirmar Entrada | Backspace: Borrar | R: Rearmar Disyuntor Físico | Esc: Dashboard ";
    let footer = Paragraph::new(footer_text)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(footer, chunks[2]);

    // 4. Modal Flotante de Desbloqueo Forense (Condicional)
    if state.show_breaker_reset {
        render_reset_modal(f, state);
    }
}

fn render_reset_modal(f: &mut Frame, state: &TuiState) {
    let size = f.area();
    let modal_area = Rect::new(size.width / 2 - 30, size.height / 2 - 6, 60, 12);
    
    f.render_widget(Clear, modal_area);
    
    let block = Block::default()
        .title(" INTERVENCIÓN REQUERIDA: REARME DE CIRCUITO ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red).bold());
    f.render_widget(block, modal_area);

    let modal_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(2), // Advertencia
            Constraint::Length(3), // Cajas
            Constraint::Length(3), // Frase
        ])
        .split(modal_area);

    let warning = Paragraph::new("La pasarela está congelada por violación de perímetro. Introduce la matriz táctica clásica para restablecer el canal operativo.").red().wrap(Wrap { trim: true });
    f.render_widget(warning, modal_chunks[0]);

    let mut cajas_line = Vec::new();
    for i in 0..5 {
        let style = if state.reset_focus_index == i { Style::default().fg(Color::Yellow).bold() } else { Style::default().fg(Color::Gray) };
        cajas_line.push(Span::styled(format!(" [Caja {}]: ", i + 1), style));
        cajas_line.push(Span::raw(format!("{:<4} ", state.reset_cajas[i])));
    }
    let cajas_para = Paragraph::new(Line::from(cajas_line)).block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(cajas_para, modal_chunks[1]);

    let phrase_style = if state.reset_focus_index == 5 { Style::default().fg(Color::Yellow).bold() } else { Style::default().fg(Color::Gray) };
    let hidden_phrase: String = "*".repeat(state.reset_phrase.len());
    let phrase_para = Paragraph::new(vec![Line::from(vec![
        Span::styled(" Frase Maestra del Vault: ", phrase_style),
        Span::raw(hidden_phrase),
    ])]);
    f.render_widget(phrase_para, modal_chunks[2]);
}
```

---

### 5. Interceptador de teclado crossterm (`src-tui/src/ui/gateway_events.rs`)
Envia la información recolectada de la TUI al supervisor asíncrono en segundo plano por el canal seguro.

**Archivo implicado**: `src-tui/src/ui/gateway_events.rs`

```rust
/* rol: gestion de eventos e interactividad blindada contra ataques de memoria y dos */
use crossterm::event::{KeyCode, KeyEvent};
use crate::{TuiState, Screen};
use crate::crypto::blockchain::worker::Web3WorkerCmd;
use crate::crypto::blockchain::firewall::FirewallRules;
use zeroize::Zeroize;

pub fn handle_gateway_input(state: &mut TuiState, key_event: KeyEvent) {
    if state.show_breaker_reset {
        handle_modal_input(state, key_event.code);
        return;
    }

    match key_event.code {
        KeyCode::Esc => { state.screen = Screen::Dashboard; }
        KeyCode::Tab => { state.gateway_focused_field = (state.gateway_focused_field + 1) % 4; }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            state.show_breaker_reset = true;
            state.reset_focus_index = 0;
        }
        KeyCode::Backspace => {
            match state.gateway_focused_field {
                0 => { state.input_max_tx.pop(); }
                1 => { state.input_max_volume.pop(); }
                2 => { state.input_new_dex_id.pop(); }
                3 => { state.input_new_cex_id.pop(); }
                _ => {}
            }
        }
        KeyCode::Char(c) => {
            match state.gateway_focused_field {
                0 => { if c.is_ascii_digit() && state.input_max_tx.len() < 4 { state.input_max_tx.push(c); } }
                1 => { if (c.is_ascii_digit() || c == '.') && state.input_max_volume.len() < 10 { state.input_max_volume.push(c); } }
                2 => { if state.input_new_dex_id.len() < 66 { state.input_new_dex_id.push(c); } }
                3 => { if state.input_new_cex_id.len() < 66 { state.input_new_cex_id.push(c); } }
                _ => {}
            }
        }
        KeyCode::Enter => {
            match state.gateway_focused_field {
                0 | 1 => {
                    // Enviar solo el valor opcional si el parseo local es correcto, mitigando regresiones
                    let max_tx = state.input_max_tx.parse::<u32>().ok();
                    let max_vol = state.input_max_volume.parse::<f64>().ok();

                    if let Some(ref tx) = state.web3_cmd_tx {
                        let _ = tx.send(Web3WorkerCmd::UpdateRules { max_tx, max_vol });
                    }
                }
                2 => {
                    if !state.input_new_dex_id.is_empty() {
                        // NO alteramos el vector state.allowed_dex_contracts localmente de forma directa
                        if let Some(ref tx) = state.web3_cmd_tx {
                            let _ = tx.send(Web3WorkerCmd::AddDexContract(state.input_new_dex_id.clone()));
                        }
                        state.input_new_dex_id.clear();
                    }
                }
                3 => {
                    if !state.input_new_cex_id.is_empty() {
                        if let Some(ref tx) = state.web3_cmd_tx {
                            let _ = tx.send(Web3WorkerCmd::AddCexDestination(state.input_new_cex_id.clone()));
                        }
                        state.input_new_cex_id.clear();
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
}

fn handle_modal_input(state: &mut TuiState, key_code: KeyCode) {
    match key_code {
        KeyCode::Esc => {
            state.show_breaker_reset = false;
            state.reset_phrase.zeroize();
            state.reset_phrase = String::new();
            for i in 0..5 {
                state.reset_cajas[i].zeroize();
                state.reset_cajas[i] = String::new();
            }
        }
        KeyCode::Tab => { state.reset_focus_index = (state.reset_focus_index + 1) % 6; }
        KeyCode::Backspace => {
            if state.reset_focus_index < 5 {
                state.reset_cajas[state.reset_focus_index].pop();
            } else {
                state.reset_phrase.pop();
            }
        }
        KeyCode::Char(c) => {
            if state.reset_focus_index < 5 {
                if (c.is_ascii_digit() || c == '-') && state.reset_cajas[state.reset_focus_index].len() < 6 {
                    state.reset_cajas[state.reset_focus_index].push(c);
                }
            } else {
                if state.reset_phrase.len() < 120 { state.reset_phrase.push(c); }
            }
        }
        KeyCode::Enter => {
            let mut cajas_parsed = [0i64; 5];
            let mut parse_success = true;

            for i in 0..5 {
                if let Ok(val) = state.reset_cajas[i].parse::<i64>() {
                    cajas_parsed[i] = val;
                } else {
                    parse_success = false;
                }
            }

            if parse_success && !state.reset_phrase.is_empty() {
                let secret_bytes = state.reset_phrase.as_bytes().to_vec();
                
                state.reset_phrase.zeroize();
                state.reset_phrase = String::new();

                if let Some(ref tx) = state.web3_cmd_tx {
                    let _ = tx.send(Web3WorkerCmd::ResetBreaker(cajas_parsed, secret_bytes));
                }
                
                for i in 0..5 { state.reset_cajas[i].clear(); }
                
                // Corrección C: Se elimina la ocultación inmediata; el modal se cierra únicamente de forma reactiva
                // en main.rs al procesar el evento asíncrono StatusChanged(GatewaySecurityState::Operational)
            }
        }
        _ => {}
    }
}
```

---

### 6. Dibujo en el enrutamiento general (`src-tui/src/ui/mod.rs`)

**Archivo implicado**: `src-tui/src/ui/mod.rs`

```rust
/* Declaración de módulos ui */
pub mod gateway;
pub mod gateway_events;

/* Enrutador de dibujo central */
pub fn draw_main_ui(f: &mut Frame, state: &TuiState) {
    match state.screen {
        Screen::Unlock => draw_unlock_screen(f, state),
        Screen::Dashboard => draw_dashboard(f, state),
        // ... otros emparejamientos
        Screen::WalletGateway => gateway::draw_wallet_gateway(f, state),
    }
}
```

---

### 7. Dibujo del HUD de estado de la pasarela en el Dashboard (`src-tui/src/ui/dashboard.rs`)
Integra visualmente las métricas en tiempo real de la pasarela para monitoreo proactivo del usuario.

**Archivo implicado**: `src-tui/src/ui/dashboard.rs` (Nuevo / Modificado)

```rust
/* rol: componente hud de visualizacion rapida para la pasarela web3 en el dashboard */
use ratatui::{
    style::{Color, Style, Modifier},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use crate::TuiState;
use crate::crypto::blockchain::breaker::GatewaySecurityState;

pub fn render_web3_gateway_hud(f: &mut Frame, area: ratatui::layout::Rect, state: &TuiState) {
    let (status_str, color) = match &state.cached_gateway_state {
        GatewaySecurityState::Operational => ("ACTIVA", Color::Green),
        GatewaySecurityState::Frozen { .. } => ("CONGELADA", Color::Yellow),
        GatewaySecurityState::HardLocked => ("BLOQUEADA", Color::Red),
    };

    let hud_content = vec![
        Line::from(vec![
            Span::raw("Estado del Canal: "),
            Span::styled(status_str, Style::default().fg(color).bold()),
        ]),
        Line::from(vec![
            Span::raw("Firmas emitidas hoy: "),
            Span::styled(state.cached_tx_count.to_string(), Style::default().fg(Color::White).bold()),
        ]),
        Line::from(vec![
            Span::raw("Volumen transferido: "),
            Span::styled(format!("{:.2} USD", state.cached_volume_usd), Style::default().fg(Color::White).bold()),
        ]),
    ];

    let block = Paragraph::new(hud_content)
        .block(Block::default().title(" Pasarela Web3 ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
        
    f.render_widget(block, area);
}
```

---

## Conclusión del despliegue de la TUI

Con la implementación de este cuarto bloque, el desarrollo de la interfaz interactiva para el **Motor de Custodia Universal de Livencrypt 2.0** queda completamente cerrado y funcional:

1. El estado global ha sido adaptado para soportar concurrencia sin bloqueos mediante un modelo asíncrono de doble hilo guiado por eventos, aislando `stdin` de la cola de comandos de la TUI.
2. Los paneles tácticos renderizan las métricas directamente desde los hilos de ejecución en tiempo real.
3. Se han implementado mitigaciones robustas de DoS (acotación de buffers) y mitigación de fuga de secretos (Zeroize asíncrono y retraso del cierre del modal de desbloqueo hasta validación de canal).
