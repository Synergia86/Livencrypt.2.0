Livencrypt 2.0

Livencrypt 2.0 es una suite criptográfica avanzada de confianza cero (zero-trust) y pasarela de custodia universal diseñada en Rust para operar de manera local y descentralizada a través de una interfaz interactiva de terminal (TUI). El sistema proporciona un entorno fortificado para el cifrado posicional de datos, la gestión de almacenamiento criptográfico blindado en memoria volátil y la intermediación segura de operaciones Web3 con navegadores web mediante canales de comunicación aislados (IPC).

1. Arquitectura y modelo de confianza cero
La suite está estructurada bajo una filosofía de diseño compartimentado para mitigar de raíz la persistencia de secretos en entornos inseguros (como el espacio de memoria de un navegador de internet).

                                  [ENTORNO INSEGURO]
                           +------------------------------+
                           | Extensión web stateless (JS) |
                           +--------------+---------------+
                                          |
                        Mensajería nativa (Payloads JSON)
                                          |
                                  [CORTAFUEGOS IPC]
                           +--------------v---------------+
                           |  Host puente de mensajería   |
                           |    (livencrypt-bridge)       |
                           +--------------+---------------+
                                          |
                              Socket Unix (Permisos 0600)
                                          |
                               [NÚCLEO SEGURO (RUST)]
     +------------------------------------+------------------------------------+
     |                      Hilo asíncrono secundario                          |
     |  +-------------------------------------------------------------------+  |
     |  |                         Web3BackgroundWorker                      |  |
     |  |                                                                   |  |
     |  |   +--------------------+     +--------------------------------+   |  |
     |  |   |   LiveFirewall     |---->|       GatewaySupervisor        |   |  |
     |  |   | (Cuotas / Límites) |     | (run_loop_iteration / Sockets) |   |  |
     |  |   +--------------------+     +---------------+----------------+   |  |
     |  +----------------------------------------------|--------------------+  |
     |                                                 |                       |
     |                                     Canal asíncrono MPSC                |
     |                                                 |                       |
     |                      Hilo maestro interactivo   v                       |
     |  +-------------------------------------------------------------------+  |
     |  |                          Bucle TUI Ratatui                        |  |
     |  |               (Gestión gráfica / Caching de TuiState)             |  |
     |  +-------------------------------------------------------------------+  |
     +-------------------------------------------------------------------------+
El núcleo de la aplicación se divide en tres capas asíncronas concurrentes libres de bloqueos físicos:

1 Hilo maestro interactivo (TUI): Gobierna el renderizado gráfico mediante Ratatui y Crossterm. Consume de manera reactiva las alertas de red de los canales MPSC y manipula una caché interna local (TuiState) para evitar colisiones de préstamos de memoria (borrow checker).

2 Hilo perimetral de lectura Unix (Socket Reader): Escucha peticiones externas a través de un descriptor de socket local seguro con un límite estricto de hilos concurrentes para neutralizar ataques de denegación de servicio (DoS).

3 Hilo maestro del supervisor (Background Worker): Orquesta de forma asíncrona la validación en caliente del cortafuegos de políticas y coordina la ejecución del llavero multiecurva en memoria blindada.

2. Características principales y lógica de control
A. Cifrado posicional de texto y archivos autenticados
· Agnosticismo de datos: El motor dinámico PositionalCipher utiliza matrices de sustitución y permutación complejas basadas en plantillas lingüísticas estructuradas. Procesa caracteres internacionales (tablas nativas de chino, coreano, katakana, árabe, entre otras) eliminando codificaciones Unicode corruptas.

· Cifrado de archivos con doble factor de secreto: El subsistema FileCipher implementa un flujo de cifrado autenticado de archivos que separa de manera estricta la referencia pública visualizada en el HUD de la frase mnemónica real del archivo. Bloquea de forma impositiva cualquier regresión de código o reutilización accidental de metadatos visibles como material de clave criptográfica.

B. Pasarela Web3 asíncrona y custodia universal
· Llavero multiecurva volátil: La clase UniversalKeymaster almacena una master_seed de 64 bytes calculada mediante funciones KDF combinadas sobre la matriz de 5 cajas lógicas y la frase mnemónica del operador. Deriva claves deterministas bajo el estándar BIP-32/BIP-44 y SLIP-0044 para los principales ecosistemas criptográficos:

· Curva secp256k1: Firma transacciones ECDSA compactas para Bitcoin y Ethereum. En la red Ethereum, trunca de manera exacta el prefijo de control geométrico de 1 byte (0x04) para devolver la estructura nativa de 64 bytes requerida por las APIs del navegador.

· Curva ed25519: Genera llaves y firmas de Edwards nativas sobre la carga útil completa del payload para la red Solana.

· Aislamiento perimetral: Las solicitudes dirigidas a redes que requieren criptografía especializada de firmas en anillo (como Monero) se rechazan de manera determinista en el backend para preservar la seguridad de la clave.

C. Cortafuegos de políticas activo (Firewall)
· Cada solicitud de firma enviada desde el navegador web debe superar una evaluación lineal antes de que el núcleo exponga el material criptográfico:

· Límite de frecuencia (Límite X): Controla la cuota diaria acumulada de transacciones autorizadas (max_daily_tx) para impedir la automatización maliciosa de drenajes de fondos.

· Límite de volumen monetario (Límite Y): Evalúa el impacto financiero estimado en dólares de la transacción (max_daily_volume_usd) frente al acumulado diario consumido.

· Validación criptográfica de infraestructuras: Exige de forma obligatoria un identificador inmutable de destino (target_dex_cex_id). Contrasta el ID en tiempo real mediante búsquedas acotadas contra listas blancas estrictas de contratos autorizados de DEX (ej. exchanges descentralizados) y billeteras de depósito de CEX.

· Asentamiento diferido de cuotas: El cortafuegos aprueba la inspección perimetral de forma preliminar, pero solo asienta e incrementa las cuotas diarias consumidas (commit_transaction) si el motor multiecurva logra firmar la transacción de manera exitosa, evitando denegaciones de servicio artificiales por fallos de red externos.

D. Disyuntor táctico de seguridad (Circuit Breaker)
· Congelación forense inmediata: Si el cortafuegos detecta una solicitud hacia un destino no autorizado o una violación de cuotas, invoca el método trip_breaker, mutando instantáneamente el estado operativo a Frozen y bloqueando el acceso al llavero de Rust.

· Bloqueo terminal de integridad: Si se acumulan 3 fallos consecutivos en el perímetro, el disyuntor salta a HardLocked, un estado de aislamiento permanente e irrecuperable en caliente que suspende la comunicación y requiere el reinicio físico del binario completo.

· Rearme físico local por matriz: Para restablecer una pasarela congelada (Frozen), el operador debe acudir físicamente a la consola local y teclear las credenciales exactas de desbloqueo (combinación de las 5 cajas de la matriz y la frase maestra). Los bytes secretos se evalúan directamente sobre la referencia de memoria (std::str::from_utf8), aplicando un borrado destructivo atómico mediante el trait Zeroize en cuanto finaliza la rutina.

E. Blindaje del sistema operativo y protección de memoria
· Process Hardening: La rutina de inicialización aplica directivas estrictas del kernel Linux mediante llamadas libc::prctl para inhabilitar de forma permanente los volcados de memoria (PR_SET_DUMPABLE = 0), restringe el radio de traza de ptrace y reduce el límite del recurso RLIMIT_CORE a cero absoluto.

· Boot Shield (Aislamiento de arranque): Mecanismo de contención que encripta de manera hermética las plantillas críticas del sistema en reposo utilizando el cifrado simétrico ChaCha20Poly1305. Durante el arranque, monta las estructuras en un directorio temporal aislado en RAM y destruye las trazas originales mediante ganchos avanzados sincronizados con initramfs.

· Monitor heurístico integrado: Evalúa de manera proactiva las llamadas al sistema (syscalls) realizadas por el proceso, asignando puntuaciones de riesgo ante comportamientos anómalos que sugieran inyecciones de código, montajes corruptos o intentos de monitorización por depuradores locales.

3. Estructura del proyecto
El árbol del repositorio divide las responsabilidades del sistema de la siguiente manera:

├── Cargo.toml                      # Declaración de dependencias criptográficas y empaquetado
├── DOCS/                           # Documentación técnica y especificaciones de Tauri
├── src-tui/
│   ├── scripts/
│   │   ├── com.livencrypt.gateway.json # Manifiesto de mensajería nativa para navegadores web
│   │   ├── build-deb.sh            # Script de compilación del paquete de distribución Debian
│   │   ├── postinstall.sh          # Configuración post-instalación de AppArmor y límites
│   │   └── postremove.sh           # Purga segura de archivos temporales del host
│   └── src/
│       ├── lib.rs                  # Inicializador del núcleo y endurecimiento de procesos
│       ├── main.rs                 # Punto de entrada de la TUI y bucle de pintado reactivo
│       ├── crypto/
│       │   ├── file_cipher.rs      # Flujo de cifrado autenticado de archivos
│       │   ├── positional.rs       # Motor de álgebra posicional multilingüe
│       │   └── blockchain/         # Subsistema de pasarela Web3 y gobernanza criptográfica
│       │       ├── breaker.rs      # Estado del disyuntor táctico de contención
│       │       ├── firewall.rs     # Validación de cuotas de volumen e identificadores
│       │       ├── multi_curve.rs  # Derivación BIP-32/44 en curvas secp256k1 y ed25519
│       │       ├── proxy.rs        # Canal seguro de mensajería nativa stateless
│       │       ├── supervisor.rs   # Orquestador y servidor de sockets Unix de contingencia
│       │       └── worker.rs       # Hilo asíncrono secundario y control anti-slowloris
│       └── security/
│           ├── ai_monitor.rs       # Puntuación heurística de riesgo de syscalls
│           ├── apparmor.rs         # Generación dinámica de perfiles MAC del kernel
│           └── boot_shield.rs      # Orquestador de initramfs y ChaCha20Poly1305
4. Requisitos del sistema e instalación
Requisitos previos
· Sistema operativo Linux (kernel fortificado con soporte AppArmor activo recomendado).

· Rustc y Cargo (edición de compilación 2021 o superior).

· Navegador web compatible con mensajería nativa (Brave, Google Chrome o Chromium).

Compilación y empaquetado Debian nativo
La suite cuenta con utilidades automatizadas para generar paquetes de distribución nativa de arquitectura cruzada (amd64, arm64, etc.). Para compilar y empaquetar el binario, ejecuta:

# Otorgar permisos de ejecución al script de empaquetado
chmod +x src-tui/scripts/build-deb.sh

# Compilar e inicializar la infraestructura de empaquetado
./src-tui/scripts/build-deb.sh
El script compilará el binario optimizado en modo de producción (--release), creará la estructura de directorios y generará el archivo ejecutable listo para su despliegue. Instala el paquete resultante haciendo uso del gestor de tu sistema:

sudo dpkg -i target/debian/livencrypt-core_2.11.0_amd64.deb
Despliegue automático de políticas de seguridad
Al instalar el paquete Debian, las utilidades de diagnóstico configuran de manera atómica el host:

1 Límites del sistema (99-livencrypt.conf): Configura directivas estrictas en los límites del sistema operativo del operador, deshabilitando de forma permanente la escritura de archivos de volcado de memoria (core 0) y bloqueando la memoria física en RAM para evitar intercambios a disco duro (swap swapping).

2 Confinamiento AppArmor: Genera y carga el perfil MAC (usr.bin.livencrypt-core) en el espacio de ejecución del kernel para restringir los accesos físicos del ejecutable exclusivamente a sus dependencias operativas.

3 Registro de mensajería nativa: Copia de forma simétrica el manifiesto JSON (com.livencrypt.gateway.json) en las rutas globales de configuración de Chrome, Chromium y Brave, permitiendo que la extensión local localice la pasarela de desvío asíncrona.

5. Instrucciones de uso básico
Inicialización de la TUI
Para arrancar el panel interactivo de terminal con los mecanismos de protección de procesos activos, invoca el núcleo:

livencrypt-core
Al iniciar la sesión por primera vez, el sistema ejecutará el análisis heurístico preventivo de llamadas al sistema y te solicitará configurar la matriz táctica de 5 cajas numéricas y la frase maestra para instanciar el llavero volátil en RAM.

Controles de navegación interactiva
· Tab: Permite conmutar el enfoque de edición entre los campos numéricos de límites diarios del cortafuegos y los registros de las listas blancas.

· Enter: Procesa y valida el texto introducido en el campo activo. Si se introducen límites numéricos, los transmite de forma asíncrona al worker secundario para su actualización en caliente.

· Char 'R' / 'r': Abre de manera forzada el modal flotante de emergencia para el rearme físico del disyuntor de seguridad en caso de congelación por alertas Web3.

· Esc: Regresa de manera segura al cuadro de mandos principal (Dashboard).

6. Licencia y derechos de autor
Este programa es software libre: puedes redistribuirlo y/o modificarlo bajo los términos de la GNU General Public License v3.0 tal como está publicada por la Free Software Foundation.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 Synergia86 <livencrypt1@gmail.com>

El código fuente de este proyecto incluye las cabeceras digitales de validación estática de licencias exigidas por los indexadores de software de código abierto. Consulta el archivo LICENSE adjunto en la raíz del repositorio para leer el texto legal íntegro y las garantías de exención de responsabilidad correspondientes.
