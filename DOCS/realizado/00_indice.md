# Índice de Módulos de Seguridad y Funciones Pendientes - LIVENCRYPT 2.0

Este directorio contiene la documentación técnica pericial de las funciones y módulos de seguridad de **Livencrypt 2.0**, detallando su diseño, los archivos implicados en el código de Rust-TUI, lo que ya está integrado y lo que queda pendiente por integrar.

Esta estructura está optimizada para su uso y visualización en **Obsidian**, interconectando los diferentes componentes mediante enlaces bidireccionales.

---

## Módulos y Hojas de Ruta de Seguridad

### 1. [[01_proteccion_ingenieria_inversa_y_hardening_memoria|Protección contra Ingeniería Inversa y Hardening de Memoria]]
* **Temas**: Blindaje de RAM física (`mlockall`), Zeroize implacable de secretos, eliminación del puente IPC y del heap compartido (migración a Rust-TUI puro), claves de coacción y auto-wipe.

### 2. [[02_configuracion_inmutable_del_kernel_y_actualizaciones|Configuración Inmutable del Kernel y Actualizaciones Seguras]]
* **Temas**: Configuración del sistema como un Vault cerrado, actualizaciones con payloads pre-cifrados desde fábrica, "handover" (traspaso) de claves mediante cifrado efímero en tránsito y firmas digitales Ed25519 en origen.

### 3. [[03_staging_vfs_y_registro_auditoria_criptografica|Staging VFS y Registro de Auditoría Cifrado]]
* **Temas**: Área de descompresión criptográfica de actualizaciones en el sistema de archivos virtual, estructura de logs encadenados localmente mediante hash chains (SHA-256) con firmas Poly1305, y gestión del Registro de Tumbas (*Tombstone Log*) en accesos fallidos.

### 4. [[04_alerta_silenciosa_y_modo_espejismo|Alerta Silenciosa de Manipulación y Modo Espejismo]]
* **Temas**: Anclaje de continuidad criptográfica en el encabezado del vault, esteganografía visual en la TUI (alteración sutil de caracteres/colores y micro-retrasos artificiales) y aislamiento de claves en entorno señuelo (*Modo Espejismo*).

### 5. [[05_cargador_sobre_digital_y_bit_de_suicidio|Cargador (Crypter/Loader) y Bit de Suicidio]]
* **Temas**: Aislamiento "sobre digital" para binarios externos, descifrado y ejecución *fileless* directamente en la RAM protegida (`memfd_create`), y el "bit de suicidio" permanente en el encabezado del vault.

### 6. [[06_cuarentena_memoria_y_aislamiento_sandbox|Cuarentena de Memoria y Aislamiento (Zero-Trust Sandbox)]]
* **Temas**: Contenedor de ejecución efímera con Namespaces de Linux (PID, Net, Mount), control de recursos por CGroups v2, políticas restrictivas AppArmor y filtrado de llamadas de sistema con Seccomp, socket Unix cifrado y alertas de sandbox en la TUI.

### 7. [[07_ia_local_y_deteccion_ebpf|Detección de Comportamiento con IA Local y eBPF]]
* **Temas**: Sensores no invasivos eBPF en el núcleo para recolección de telemetría de syscalls, motor de inferencia proactivo (SLM local ligero con Burn u ONNX Runtime) para detectar intenciones maliciosas y respuesta predictiva (congelación de procesos con `SIGSTOP`).

### 8. [[08_pre_boot_authentication_y_teclado_aleatorio|Pre-Boot Authentication (PBA) y Teclado Aleatorio]]
* **Temas**: Protección del kernel frente a privilegios de Root (cold boot, DMA, keyloggers), integración de la TUI en el Initramfs previa al arranque del sistema operativo, y la aleatorización de la carga de cajas e interfaces de entrada con teclado virtual aleatorio.

### 9. [[09_integración_frontend_en_dashboard|Integración Frontend en Dashboard]]
* **Temas**: Navegación avanzada del Dashboard TUI (Monitor de Auditoría, Firmware Staging, Sandbox), visualización de telemetría eBPF y de medidores de riesgo de la IA, y visualización sutil esteganográfica de integridad del sistema (glifo `.` / `·`).

### 10. [[10_teclado|Teclado Blindado (Posiciones Aleatorias)]]
* **Temas**: Teclado virtual TUI con barajado dinámico (`teclado_shuffled`), interacción y navegación por flechas de dirección y tecla Enter, mitigación de keyloggers de nivel de kernel y de observación visual/física (*shoulder surfing*).

### 11. [[11_Contenedores_Decoy_(Señuelo)_para_el_Modo_Espejismo|Contenedores Decoy (Señuelo) para el Modo Espejismo]]
* **Temas**: Generación de plantillas señuelo (`get_mirage_decoys`), sustitución silenciosa de plantillas reales por cebos ante pérdidas de integridad, descartado de escrituras simuladas exitosas, e inmunidad forense del espacio de claves reales.

### 12. [[12_archivo_recuperación|Archivo de Recuperación de Emergencia]]
* **Temas**: Verificación de firmas asimétricas Ed25519 en payloads `.lvc_recovery`, actualización atómica de anclajes de integridad en el encabezado del vault, rotación de claves criptográficas y flujos forenses post-compromiso/formateo.

### 13. [[13_comparativa_frontend_tauri_a_tui|Comparativa de Frontend: Migración de Tauri a TUI]]
* **Temas**: Mapeo estructural detallado de funciones, tablas, textos y componentes de UI desde el frontend Tauri (React/TS) a la actual versión nativa de consola (Rust/Ratatui).

### 14. [[14_motor_custodia_universal_y_pasarela_web3|Motor de Custodia Universal y Pasarela Web3 de Confianza Cero]]
* **Temas**: Derivación multiecurva (secp256k1, ed25519-dalek), canal de mensajería nativa stateless (stdio JSON), cortafuegos de políticas y límites diarios (Límites X e Y) con listas blancas de DEX/CEX, disyuntor táctico de congelación forense y supervisor de bucle.

### 15. [[15_interfaz_tui_pasarela_web3_y_custodia|Interfaz TUI para Pasarela Web3 y Custodia]]
* **Temas**: Navegación de interfaz interactiva Ratatui, concurrencia asíncrona mediante hilo trabajador en segundo plano (MPSC), caché local en TuiState, eventos de teclado contextuales y modal de rearme matricial.

---

> [!NOTE]
> Todos los documentos enlazados contienen un análisis pericial forense del estado actual de integración en el código del proyecto ubicado en [src-tui](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui).
