# Informe de Auditoria de Seguridad: Acceso Auto-Cifrado / Livencrypt Boot Shield

## 1. Resumen ejecutivo

El documento `DOCS/SEGURIDAD_ACCESO_AUTO_CIFRADO.md` describe una funcion util para Livencrypt 2.0: proteger en reposo las plantillas locales y configuraciones sensibles frente a extraccion forense offline. La idea es valida si se implementa como un contenedor cifrado en disco desbloqueado al inicio de sesion.

Sin embargo, la arquitectura descrita no debe implementarse literalmente en su forma actual. Presenta afirmaciones criptograficas demasiado fuertes, mezcla controles reales con controles operativos peligrosos, y confia en "el propio algoritmo de la aplicacion" para proteger datos persistentes. Para seguridad en reposo, Livencrypt debe usar criptografia autenticada estandar con derivacion de clave robusta, y reservar su algoritmo posicional para su funcion principal de cifrado/transmutacion, no para proteger secretos de configuracion.

Ademas, el codigo actual ya contiene una aproximacion de Boot Shield en `src/main.tsx`, pero guarda `boot_cajas` y `boot_frase` en `localStorage`. Esto invalida el objetivo de seguridad: un atacante con acceso al perfil de la aplicacion puede leer la frase y la secuencia directamente, sin romper ningun cifrado.

Conclusion: el modulo es de utilidad para Livencrypt, pero debe redisenarse antes de considerarlo una defensa real.

## 2. Alcance revisado

Archivos revisados:

- `DOCS/SEGURIDAD_ACCESO_AUTO_CIFRADO.md`
- `DOCS/INFORME_PERICIAL_SEGURIDAD_MEMORIA.md`
- `src/main.tsx`
- `src-tauri/src/lib.rs`
- `src-tauri/src/templates.rs`
- `src-tauri/src/crypto/file_cipher.rs`
- `src-tauri/capabilities/default.json`

La auditoria se centra en:

- Seguridad de plantillas y configuracion en reposo.
- Riesgo de fuga de credenciales.
- Resistencia frente a clonacion de disco.
- Coherencia entre el documento y la implementacion actual.
- Recomendaciones de arquitectura para una implementacion segura.

No constituye una prueba criptografica formal del algoritmo posicional de Livencrypt.

## 3. Utilidad real para Livencrypt 2.0

El Boot Shield si aporta valor si se limita a un objetivo claro:

> Evitar que una copia offline del disco revele plantillas personalizadas, configuracion sensible y metadatos de uso de Livencrypt.

Este objetivo es relevante porque las plantillas `.msgpack` pueden contener alfabetos personalizados. Si un atacante obtiene esas plantillas junto con textos cifrados, puede reducir el coste de analisis y reconstruccion de mensajes. Cifrar las plantillas en reposo mejora la seguridad operacional.

Lo que no puede prometer el modulo:

- No protege frente a malware activo en la sesion desbloqueada.
- No protege frente a un atacante con control de root mientras la app esta abierta.
- No garantiza borrado fisico completo de DRAM tras apagado o crash.
- No convierte el algoritmo posicional en un sistema de cifrado de almacenamiento moderno.
- No sustituye cifrado completo de disco cuando el equipo entero debe estar protegido.

## 4. Hallazgos criticos

### CRITICO 1: Las credenciales del Boot Shield se almacenan en `localStorage`

En `src/main.tsx`, la configuracion actual guarda:

- `boot_cajas`
- `boot_frase`
- `boot_shield_active`

Tambien las lee para desbloquear la interfaz. Esto significa que la frase maestra y las cajas quedan persistidas en texto claro dentro del almacenamiento web del WebView. En un ataque offline contra el perfil de la aplicacion, el atacante no necesita fuerza bruta: extrae `localStorage` y obtiene las credenciales.

Impacto:

- Rompe completamente el modelo de amenaza del documento.
- Hace que el bloqueo sea un control de interfaz, no un control criptografico.
- Un usuario puede creer que las plantillas estan cifradas cuando no lo estan.

Recomendacion:

- Eliminar almacenamiento de frases y cajas en frontend.
- Guardar solo un encabezado cifrado con `salt`, `nonce`, parametros KDF y verificador autenticado.
- La frase debe introducirse en cada arranque y enviarse a Rust solo para derivar una clave en memoria.
- Nunca persistir la frase ni la clave derivada.

### CRITICO 2: El documento propone cifrar almacenamiento con el propio algoritmo de Livencrypt

El texto indica que las plantillas se cifraran "utilizando el propio algoritmo de la aplicacion". Para proteccion en reposo, esto es una debilidad de diseno. El cifrado posicional de Livencrypt puede ser parte del producto, pero no debe usarse como primitiva de almacenamiento de secretos.

Riesgo:

- No hay autenticacion criptografica fuerte del ciphertext.
- No hay KDF estandar para convertir frase de usuario en clave resistente a GPU.
- No hay formato de vault con versionado, salt y nonce por objeto.
- Si el algoritmo posicional filtra estructura, las plantillas podrian ser recuperables con analisis.

Recomendacion:

- Usar `Argon2id` para derivar clave desde frase.
- Usar `XChaCha20-Poly1305` o `AES-256-GCM` para cifrado autenticado.
- Usar nonces aleatorios por archivo u objeto.
- Usar `blake3` o SHA-256 solo para integridad no secreta, nunca como sustituto de AEAD.

### CRITICO 3: No existe cifrado real de plantillas en la implementacion actual

El codigo actual mantiene funciones `load_templates` y `save_template` que leen y escriben `.msgpack` desde el directorio de plantillas. No hay vault cifrado ni descifrado real asociado al Boot Shield. El texto de la UI dice que "toda la aplicacion, incluida las plantillas, estaran cifradas", pero la implementacion actual solo controla el acceso visual mediante `localStorage`.

Impacto:

- Las plantillas siguen recuperables desde disco.
- El estado de bloqueo no impide lectura directa de los `.msgpack`.
- Hay divergencia entre promesa de seguridad y comportamiento real.

Recomendacion:

- No mostrar la funcion como "cifrado" hasta que el backend cifre realmente las plantillas.
- Crear comandos Rust especificos: `boot_shield_enable`, `boot_shield_unlock`, `boot_shield_lock`, `boot_shield_disable`.
- Hacer que `load_templates` lea desde el vault desbloqueado si Boot Shield esta activo.

## 5. Hallazgos altos

### ALTO 1: `panic_wipe_and_exit` no sanitiza memoria

En `src-tauri/src/lib.rs`, `panic_wipe_and_exit` ejecuta `std::process::exit(0)`. Esto finaliza el proceso, pero no aplica borrado de buffers sensibles ni garantiza limpieza de memoria. La funcion se presenta como boton de panico, pero en su estado actual equivale a cierre inmediato.

Recomendacion:

- Renombrar temporalmente la funcion a "cierre rapido" si no se implementa sanitizacion real.
- Si se implementa sanitizacion: usar `zeroize`, estructuras `SecretString`/`SecretVec`, limpiar cache de plantillas y cerrar ventanas.
- Deshabilitar core dumps al inicio del proceso.
- Evaluar `mlock`/`mlockall` en Linux con manejo de errores y limites de memoria.

### ALTO 2: El control de red ejecuta `nmcli networking off`

`toggle_network` llama directamente a `nmcli networking off/on`. El documento ya advierte que esto puede dejar equipos remotos inaccesibles. Como control de seguridad, es peligroso por defecto y no esta relacionado directamente con cifrado de plantillas.

Riesgo:

- Denegacion de servicio accidental.
- Requiere permisos del sistema.
- Puede cortar sesiones remotas de administracion.
- Mezcla una accion operacional destructiva con una funcion de seguridad de almacenamiento.

Recomendacion:

- Mantenerlo en modo simulacion por defecto.
- Exigir confirmacion explicita y persistente para habilitar modo real.
- Separar perfiles: `mock`, `drop-default-route`, `nmcli-off`.
- Registrar claramente que no es parte del cifrado en reposo.

### ALTO 3: No hay verificacion autenticada ni control anti-manipulacion definido

El documento menciona "checksum criptografico" y `boot.conf`, pero un checksum sin MAC o AEAD no evita manipulacion. Un atacante puede reemplazar archivos, modificar marcadores o provocar rollback.

Recomendacion:

- Usar AEAD con Associated Data que incluya:
  - magic bytes
  - version de formato
  - identificador de algoritmo
  - parametros KDF
  - lista de objetos cifrados
  - contador de version del vault
- Detectar rollback con un contador monotono local cuando sea viable.
- Hacer que `boot.conf` sea solo un encabezado publico, nunca un verificador secreto.

## 6. Hallazgos medios

### MEDIO 1: Las afirmaciones sobre DRAM son demasiado absolutas

El documento afirma que al cerrar el proceso "los datos legibles desaparecen inmediatamente de la DRAM fisica". Operativamente no es garantizable. El sistema operativo libera paginas, pero los bytes pueden permanecer hasta que sean reutilizados. Tambien pueden existir copias en allocator, logs, buffers del WebView, GPU, portapapeles, swap o core dumps.

Recomendacion:

- Cambiar la redaccion a "reduce la persistencia en disco" y "limpieza best-effort".
- No prometer neutralizacion completa frente a cold boot o root.

### MEDIO 2: Falta modelo de amenazas

El documento mezcla amenazas offline, acceso fisico, forense, red, memoria viva y administracion remota. Sin separar amenazas, el diseno queda ambiguo.

Recomendacion:

Definir explicitamente:

- Protege contra: robo o clonacion de disco con app cerrada.
- Reduce impacto de: perdida del equipo sin sesion desbloqueada.
- No protege contra: malware, root, debugger, keylogger, memoria viva, usuario autenticado malicioso.

### MEDIO 3: Falta plan de recuperacion

Si el vault queda corrupto o el usuario olvida la frase, las plantillas pueden perderse. Esto es aceptable si se comunica, pero debe diseniarse.

Recomendacion:

- Crear exportacion cifrada de recuperacion.
- Crear backup atomico antes de migrar plantillas a vault.
- Confirmar frase dos veces al habilitar.
- Mostrar una advertencia irreversible: "sin frase no hay recuperacion".

### MEDIO 4: Riesgo de logs con secretos o metadatos sensibles

La pantalla actual registra intentos y secuencia de cajas rechazada. Aunque no registra la frase, exponer cajas intentadas puede ayudar a analisis local.

Recomendacion:

- No registrar cajas ni fragmentos de credenciales.
- Limitar mensajes de error a "credenciales invalidas".
- Aplicar retardo progresivo y contador de intentos.

## 7. Arquitectura recomendada

### 7.1 Formato de vault

Crear un archivo unico o directorio de objetos cifrados:

- `.livencrypt/secure/vault.lvcvault`
- `.livencrypt/secure/vault.meta`

Cabecera publica propuesta:

```text
magic: LVCVAULT
version: 1
kdf: argon2id
kdf_memory_kib: configurable
kdf_iterations: configurable
kdf_parallelism: configurable
salt: 16-32 bytes aleatorios
aead: xchacha20poly1305
nonce: 24 bytes aleatorios por objeto
created_at: timestamp
```

Contenido cifrado:

- Plantillas `.msgpack`.
- Preferencias sensibles.
- Estado de configuracion del Boot Shield.

No cifrar dentro del vault:

- `salt`
- parametros KDF
- version de formato
- indicador publico de que el vault existe

Nunca guardar:

- frase de acceso
- cajas en claro
- clave derivada
- verificador derivado reutilizable sin proteccion AEAD

### 7.2 Flujo para habilitar

1. Usuario introduce frase y cajas.
2. UI envia credenciales al comando Rust `boot_shield_enable`.
3. Rust valida longitud y calidad minima.
4. Rust deriva clave con `Argon2id`.
5. Rust serializa plantillas existentes.
6. Rust cifra con AEAD.
7. Rust escribe vault temporal.
8. Rust hace `fsync` y rename atomico.
9. Rust conserva backup hasta verificar apertura.
10. Rust elimina o migra `.msgpack` en claro solo tras validacion.

### 7.3 Flujo de arranque

1. Rust detecta vault antes de cargar plantillas.
2. Frontend muestra pantalla bloqueada.
3. Usuario introduce frase y cajas.
4. Frontend invoca `boot_shield_unlock`.
5. Rust deriva clave y prueba AEAD.
6. Si falla, no revela si fallo frase, cajas o vault.
7. Si pasa, Rust monta plantillas en memoria dentro de un `VaultState`.
8. `load_templates` devuelve datos desde `VaultState`, no desde disco.

### 7.4 Flujo para guardar plantillas con vault activo

1. `save_template` actualiza el estado en memoria.
2. Rust reserializa y re-cifra el vault.
3. Escritura atomica con archivo temporal.
4. Nunca escribir `.msgpack` en claro si el vault esta activo.

### 7.5 Desbloqueo y memoria

Usar:

- `zeroize` para secretos.
- `secrecy` o wrapper equivalente para frases.
- `mlock` para claves y buffers pequenos si el sistema lo permite.
- `setrlimit(RLIMIT_CORE, 0)` al inicio.
- Limpieza de cache al bloquear o cerrar.

Evitar:

- guardar secretos en React state mas tiempo del necesario;
- guardar secretos en `localStorage`;
- registrar secretos;
- copiar plantillas descifradas a multiples caches.

## 8. Cambios recomendados en codigo

### Frontend

- Eliminar `localStorage.setItem("boot_frase", ...)`.
- Eliminar `localStorage.setItem("boot_cajas", ...)`.
- `localStorage` solo puede guardar `boot_shield_seen=true` o preferencias no sensibles.
- La pantalla de desbloqueo debe llamar a Rust y esperar resultado.
- Borrar campos de frase tras cada intento.
- No mostrar cajas intentadas en logs.

### Backend Rust

Crear modulos:

- `src-tauri/src/security/mod.rs`
- `src-tauri/src/security/vault.rs`
- `src-tauri/src/security/kdf.rs`
- `src-tauri/src/security/memory.rs`

Dependencias sugeridas:

- `argon2`
- `chacha20poly1305`
- `rand_core`
- `zeroize`
- `secrecy`
- `blake3` opcional para hashes no secretos
- `libc` opcional para `setrlimit` y `mlock`

Comandos Tauri:

- `boot_shield_status()`
- `boot_shield_enable(cajas, frase)`
- `boot_shield_unlock(cajas, frase)`
- `boot_shield_lock()`
- `boot_shield_disable(cajas, frase)`
- `boot_shield_change_secret(old, new)`

### Plantillas

Modificar `load_templates`, `save_template`, `delete_template`:

- Si vault activo y desbloqueado: operar sobre vault en memoria.
- Si vault activo y bloqueado: devolver error controlado.
- Si vault inactivo: operar como hoy.

## 9. Pruebas necesarias

### Unitarias

- Derivacion KDF con parametros esperados.
- AEAD falla si se modifica un byte.
- AEAD falla con frase incorrecta.
- AEAD falla con cajas incorrectas si las cajas forman parte de la derivacion.
- `zeroize` limpia estructuras al salir de ambito.

### Integracion

- Habilitar vault desde plantillas existentes.
- Verificar que no quedan `.msgpack` en claro tras migracion.
- Reiniciar app y desbloquear correctamente.
- Guardar una plantilla con vault activo y verificar que el disco solo contiene ciphertext.
- Intentar abrir con credenciales incorrectas.
- Recuperar desde backup si falla escritura atomica.

### Seguridad operacional

- Verificar que `localStorage` no contiene frase, cajas ni claves.
- Verificar que logs no contienen secretos.
- Verificar que `toggle_network` no ejecuta `nmcli` salvo perfil real habilitado.
- Verificar que `panic_wipe_and_exit` no promete wipe si solo hace `exit`.

## 10. Redaccion recomendada para corregir el documento original

Reemplazar afirmaciones absolutas como:

- "neutralizar cualquier vector de extraccion forense"
- "100% blindado"
- "matematicamente inviable" sin especificar KDF/AEAD
- "datos legibles desaparecen inmediatamente de la DRAM"

Por formulaciones auditables:

- "protege plantillas en reposo frente a copia offline del disco"
- "usa cifrado autenticado estandar con clave derivada de frase"
- "reduce exposicion en memoria mediante limpieza best-effort"
- "no protege frente a sistema operativo comprometido ni sesion desbloqueada"

## 11. Veredicto

El concepto de Boot Shield es util para Livencrypt 2.0, pero solo si se implementa como vault cifrado real en Rust. En su estado actual, el documento debe considerarse una propuesta de alto nivel, no una especificacion segura.

Prioridad recomendada:

1. Retirar almacenamiento de frase y cajas en `localStorage`.
2. Cambiar el discurso de UI para no afirmar cifrado real hasta implementarlo.
3. Implementar vault AEAD + Argon2id en backend.
4. Integrar `load_templates` y `save_template` con el vault.
5. Endurecer memoria y errores.
6. Dejar acciones de red en simulacion por defecto.

Estado final recomendado para produccion:

- Plantillas en disco cifradas con AEAD.
- Frase nunca persistida.
- Clave derivada solo en memoria.
- Integridad autenticada.
- Escrituras atomicas.
- Backups cifrados.
- Pruebas automatizadas de ausencia de plaintext y ausencia de secretos en `localStorage`.
