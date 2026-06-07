# Utilidad de dependencias y salida de compilacion

Este documento explica que se instala y que significa la salida de compilacion de la version final de **Livencrypt 2.0**, limitada a:

| Funcion | Codigo relacionado |
|---|---|
| TRANSMUTADOR DE TEXTO | Cifrado y descifrado posicional de texto, contrasena y plantillas locales. |
| TRANSMUTADOR DE ARCHIVO | Cifrado y descifrado de archivos con plantilla seleccionada. |
| PLANTILLAS | Crear, editar, validar y cargar plantillas MessagePack con caracteres UTF-8 reales. |

## Lectura correcta de `Building [601/602]`

La linea:

`Building [=======================> ] 601/602: livencrypt-core(bin)`

no es un error. Es una linea normal de progreso de Cargo/Rust.

Significa:

- Cargo esta compilando unidades internas del proyecto y sus dependencias.
- `601/602` indica que esta casi al final de la compilacion.
- `livencrypt-core(bin)` es el binario final de Tauri, generado desde `src-tauri/src/main.rs`.
- `livencrypt-core` es el paquete Rust definido en `src-tauri/Cargo.toml`.
- `livencrypt_lib` es la libreria interna definida en el mismo `Cargo.toml`, usada por el binario Tauri.

## Error real detectado

El error real que aparecio durante `cargo test` fue:

`No space left on device (os error 28)`

Esto significa que no quedaba espacio suficiente para escribir archivos generados en `src-tauri/target`.

No indica fallo en:

- `TRANSMUTADOR DE TEXTO`
- `TRANSMUTADOR DE ARCHIVO`
- `PLANTILLAS`
- Rust
- React
- Tauri
- MessagePack

La validacion importante previa fue:

- `cargo check`: correcto.
- Busqueda de codigo retirado `ROUTER-SECURITY|tun0|node_manager|cluster|quarantine|telemetry|dpdk`: sin coincidencias.

Para repetir `cargo test`, libera espacio o usa una carpeta de compilacion con espacio:

`CARGO_TARGET_DIR=/tmp/livencrypt-target cargo test`

## Dependencias Rust activas

Estas dependencias estan en `src-tauri/Cargo.toml` y son necesarias para compilar la aplicacion Tauri y las tres funciones finales.

| Dependencia | Utilidad en la version final |
|---|---|
| `tauri` | Framework principal de escritorio. Crea ventanas, registra comandos IPC y ejecuta la aplicacion nativa. |
| `tauri-build` | Herramienta de build de Tauri usada por `build.rs` para preparar recursos y configuracion de compilacion. |
| `tauri-plugin-dialog` | Permite abrir dialogos nativos para seleccionar o guardar archivos en el transmutador de archivo. |
| `tauri-plugin-opener` | Permite abrir rutas o carpetas desde la aplicacion. |
| `opener` | Utilidad Rust usada por el comando `open_folder` para abrir la carpeta del resultado. |
| `serde` | Serializacion y deserializacion de estructuras entre Rust, MessagePack y Tauri IPC. |
| `rmp-serde` | Lectura y escritura de plantillas en formato MessagePack. Es clave para `PLANTILLAS`. |
| `rand` | Generacion de valores aleatorios usados por el cifrado posicional y operaciones auxiliares. |
| `hex` | Codificacion/decodificacion hexadecimal para valores internos de cifrado o representacion de datos. |
| `flate2` | Compresion/descompresion usada por el cifrado de archivos. |
| `zstd` | Compresion Zstandard usada para procesar datos de archivo de forma eficiente. |
| `rayon` | Paralelismo en operaciones intensivas, especialmente procesamiento de archivos. |
| `url` | Construccion y validacion de URLs internas para abrir ventanas Tauri en modo desarrollo. |

## Dependencias frontend activas

Estas dependencias estan en `package.json` y son necesarias para la interfaz React/Vite.

| Dependencia | Utilidad en la version final |
|---|---|
| `react` | Motor de componentes del frontend. Renderiza launcher y ventanas de texto, archivo y plantillas. |
| `react-dom` | Conecta React con el DOM del WebView de Tauri. |
| `@tauri-apps/api` | API JavaScript para comunicarse con comandos nativos Tauri. |
| `@tauri-apps/plugin-dialog` | API frontend para abrir dialogos nativos de seleccion/guardado de archivos. |
| `@tauri-apps/plugin-opener` | API frontend asociada a apertura de rutas o recursos. |
| `tailwindcss` | Sistema de estilos utility-first usado por la UI. |
| `@tailwindcss/vite` | Integracion de Tailwind con Vite. |
| `@fontsource/jetbrains-mono` | Fuente monoespaciada usada por el HUD/launcher. |
| `framer-motion` | Animaciones en dialogos y teclado HUD. |
| `lucide-react` | Iconos usados en dialogos y controles. |

## Dependencias de desarrollo frontend

| Dependencia | Utilidad |
|---|---|
| `@tauri-apps/cli` | Comando `npx tauri dev` y build de la aplicacion Tauri. |
| `vite` | Servidor de desarrollo y empaquetador frontend. |
| `typescript` | Compilacion y validacion de tipos TypeScript. |
| `@vitejs/plugin-react` | Integracion de React con Vite. |
| `@types/react` | Tipos TypeScript para React. |
| `@types/react-dom` | Tipos TypeScript para React DOM. |

## Archivos fuente principales

| Archivo | Utilidad |
|---|---|
| `src/main.tsx` | Launcher principal con tres columnas: texto, archivo y plantillas. |
| `src/pages/TextCipherWindow.tsx` | Ventana del transmutador de texto. |
| `src/pages/FileCipherWindow.tsx` | Ventana del transmutador de archivo. |
| `src/pages/TemplateEditorWindow.tsx` | Ventana de plantillas y alfabetos. |
| `src/invoke.ts` | Puente IPC del frontend hacia Rust/Tauri. |
| `src-tauri/src/main.rs` | Entrada del binario Tauri. |
| `src-tauri/src/lib.rs` | Registro de comandos Tauri y apertura de ventanas permitidas. |
| `src-tauri/src/templates.rs` | Plantillas MessagePack, idiomas, alfabetos y normalizacion UTF-8. |
| `src-tauri/src/crypto/positional.rs` | Cifrado y descifrado posicional de texto. |
| `src-tauri/src/crypto/file_cipher.rs` | Cifrado y descifrado de archivos. |
| `templates/*.msgpack` | Plantillas locales usadas por texto, archivo y editor de plantillas. |

## Componentes que no deben volver a entrar

La version final no debe recuperar codigo de:

- router
- nodo
- `tun0`
- DPDK
- cluster
- telemetria
- dashboard anterior
- cuarentena
- firewall
- sincronizacion con router

Comando de control:

`rg -n "ROUTER-SECURITY|tun0|node_manager|cluster|fetch_dashboard_snapshot|quarantine|telemetry|dpdk" src src-tauri`

El resultado esperado es no encontrar coincidencias.

## Comandos recomendados

Desde `/home/Divad/Escritorio/LIVENCRYPT 2.0`:

`npm install`

`npx tsc --noEmit`

`npx vite build`

`cd src-tauri && cargo check`

Si hay espacio suficiente:

`cd src-tauri && cargo test`

Si no hay espacio suficiente:

`cd src-tauri && CARGO_TARGET_DIR=/tmp/livencrypt-target cargo test`

## Conclusion

La salida `Building [601/602]: livencrypt-core(bin)` indica que Cargo esta construyendo el binario final de la aplicacion. No es un error.

El fallo observado fue falta de espacio en disco durante `cargo test`. La solucion no es integrar codigo nuevo, sino liberar espacio o cambiar `CARGO_TARGET_DIR` a una ruta con espacio disponible.
