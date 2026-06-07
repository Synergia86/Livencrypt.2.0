# Hoja de Ruta de Integracion: Livencrypt Boot Shield

## 1. Objetivo

Integrar un sistema real de proteccion de arranque para Livencrypt 2.0 que cifre plantillas y configuracion sensible en reposo, elimine el uso inseguro de `localStorage` para credenciales y convierta el actual bloqueo visual en un mecanismo criptografico verificable.

Esta hoja de ruta parte del informe:

- `DOCS/INFORME_AUDITORIA_SEGURIDAD_ACCESO_AUTO_CIFRADO.md`

Objetivo de seguridad aceptado:

- Proteger plantillas y configuracion sensible frente a copia offline del disco con Livencrypt cerrado.
- Evitar persistencia de frase, cajas o claves derivadas.
- Integrar un vault cifrado en Rust.
- Mantener acciones de red configurables para no dejar equipos remotos inaccesibles.

Fuera de alcance como garantia absoluta:

- Proteccion frente a malware activo.
- Proteccion frente a atacante con `root` durante sesion desbloqueada.
- Eliminacion fisica perfecta de datos en DRAM.
- Sustitucion del cifrado completo de disco del sistema operativo.

## 2. Decision criptografica: secuencia segura Argon2id + Livencrypt + AEAD

Pregunta: se puede usar `Argon2id` + algoritmo de cifrado/descifrado Livencrypt?

Respuesta tecnica:

Si. La decision de integracion es que Livencrypt forme parte del sistema de cifrado del vault, siempre dentro de una secuencia segura que anada derivacion de clave robusta y autenticacion criptografica.

Condicion de seguridad: Livencrypt participa como capa propia de transmutacion/cifrado, pero no queda solo. El vault final debe cerrarse con cifrado autenticado estandar para detectar manipulacion, corrupcion o intentos de apertura con valores incorrectos.

Diseno recomendado:

1. `Argon2id` deriva una clave fuerte desde:
   - frase maestra;
   - secuencia `caja1..caja5`;
   - `salt` aleatorio del vault;
   - parametros KDF versionados.
2. Livencrypt se aplica como capa interna obligatoria de transmutacion/cifrado sobre el payload serializado, usando la secuencia de cajas validada.
3. El resultado producido por Livencrypt se cifra y autentica con AEAD:
   - preferente: `XChaCha20-Poly1305`;
   - alternativa: `AES-256-GCM`, si se decide depender de AES.
4. La integridad y autenticidad del archivo final se confian al AEAD. Livencrypt aporta la capa propia del producto, y AEAD aporta verificacion criptografica fuerte del vault.

Orden recomendado:

```text
plantillas msgpack/configuracion
        |
        v
serializacion canonica del vault
        |
        v
capa Livencrypt obligatoria, usando cajas verificadas
        |
        v
XChaCha20-Poly1305 con clave derivada por Argon2id
        |
        v
vault cifrado en disco
```

Orden de desbloqueo:

```text
vault cifrado en disco
        |
        v
Argon2id(frase + cajas + salt)
        |
        v
XChaCha20-Poly1305 decrypt + verificacion AEAD
        |
        v
reversion Livencrypt obligatoria
        |
        v
plantillas/configuracion montadas en memoria
```

Motivo:

- `Argon2id` protege contra fuerza bruta acelerada por GPU.
- `XChaCha20-Poly1305` aporta confidencialidad e integridad autenticada.
- Livencrypt aporta la capa de transmutacion propia del producto y hace que las 5 cajas sigan siendo parte material del desbloqueo.
- AEAD no sustituye a Livencrypt; lo envuelve para garantizar autenticidad, integridad y fallo seguro ante manipulacion del archivo.

Regla de seguridad:

> Secuencia aprobada: `Argon2id(frase + cajas + salt)` -> `Livencrypt(payload, cajas)` -> `XChaCha20-Poly1305`. Si se elimina AEAD, el diseno no debe considerarse seguro para almacenamiento en reposo. Si se elimina Livencrypt, el diseno deja de cumplir la identidad criptografica definida para Boot Shield.

## 3. Fase 0: Congelar el comportamiento inseguro actual

Prioridad: inmediata.

Objetivo:

- Evitar que la interfaz siga prometiendo cifrado real mientras solo existe bloqueo visual.

Cambios:

- Cambiar textos de UI de Boot Shield para indicar "modo pendiente de vault criptografico" si todavia no esta implementado.
- Desactivar la opcion de activacion real hasta que exista backend.
- Mantener solo modo demostracion si es necesario.

Criterio de aceptacion:

- La aplicacion no debe afirmar que cifra plantillas en disco si no existe vault activo en Rust.

## 4. Fase 1: Eliminar credenciales de `localStorage`

Prioridad: critica.

Estado actual inseguro:

- `boot_cajas`
- `boot_frase`
- `boot_shield_active`

Accion:

- Eliminar almacenamiento de `boot_cajas`.
- Eliminar almacenamiento de `boot_frase`.
- Permitir persistir solo estado no secreto, por ejemplo:
  - `boot_shield_configured=true`;
  - preferencias visuales no sensibles;
  - perfil de red seleccionado, sin contrasenas.

Nuevo flujo:

1. Al arrancar, frontend pregunta a Rust `boot_shield_status`.
2. Si no hay vault, se carga Launcher normal.
3. Si hay vault bloqueado, se muestra pantalla de desbloqueo.
4. Usuario introduce frase y cajas.
5. Frontend invoca `boot_shield_unlock`.
6. Rust valida y monta en memoria.
7. Frontend borra campos inmediatamente tras el intento.

No permitido:

- Guardar frase.
- Guardar cajas.
- Guardar clave derivada.
- Guardar hash reutilizable de frase en frontend.
- Registrar cajas en logs.

Criterios de aceptacion:

- Buscar `boot_frase` en todo el repositorio no debe encontrar persistencia en `localStorage`.
- Inspeccionar `localStorage` tras configurar Boot Shield no debe revelar credenciales.
- Reiniciar la app debe exigir frase y cajas de nuevo.

## 5. Fase 2: Crear backend Rust para Boot Shield

Prioridad: critica.

Nuevos modulos propuestos:

```text
src-tauri/src/security/mod.rs
src-tauri/src/security/vault.rs
src-tauri/src/security/kdf.rs
src-tauri/src/security/memory.rs
src-tauri/src/security/network_profile.rs
```

Dependencias Rust sugeridas:

```toml
argon2 = "0.5"
chacha20poly1305 = { version = "0.10", features = ["std"] }
rand_core = "0.6"
zeroize = { version = "1", features = ["derive"] }
secrecy = "0.8"
blake3 = "1"
libc = "0.2"
```

Comandos Tauri:

```text
boot_shield_status()
boot_shield_enable(cajas, frase)
boot_shield_unlock(cajas, frase)
boot_shield_lock()
boot_shield_disable(cajas, frase)
boot_shield_change_secret(old_cajas, old_frase, new_cajas, new_frase)
boot_shield_export_recovery(cajas, frase, output_path)
boot_shield_import_recovery(cajas, frase, input_path)
```

Reglas:

- Los comandos reciben secretos solo como parametros transitorios.
- Rust convierte frase y cajas a estructuras `zeroize`.
- El estado desbloqueado vive en memoria Rust, no en React.
- React solo recibe si el vault esta `locked`, `unlocked` o `not_configured`.

## 6. Fase 3: Formato de vault autenticado

Prioridad: critica.

Ruta propuesta:

```text
.livencrypt/secure/vault.lvcvault
.livencrypt/secure/vault.backup.lvcvault
```

Cabecera publica:

```text
magic: LVCVAULT
format_version: 1
kdf: argon2id
kdf_memory_kib: 65536 o superior configurable
kdf_iterations: 3 o superior configurable
kdf_parallelism: segun CPU
salt: 32 bytes aleatorios
aead: xchacha20poly1305
nonce: 24 bytes aleatorios
created_at: timestamp
vault_counter: u64
```

Associated Data AEAD:

```text
magic
format_version
kdf
kdf_parameters
aead
vault_counter
lista de objetos
```

Payload cifrado:

```text
templates: Record<string, TemplateData>
settings: configuracion sensible
network_profile: perfil seleccionado sin contrasenas
metadata: version interna
```

Integracion obligatoria de Livencrypt:

- Antes de AEAD, serializar payload y aplicar transmutacion/cifrado Livencrypt con la secuencia de cajas validada.
- El AEAD siempre envuelve el resultado final.
- Si la capa Livencrypt falla o cambia, el formato debe versionarse.

Criterios de aceptacion:

- Modificar un byte del vault debe impedir desbloqueo.
- Cambiar `salt`, `nonce`, cabecera o payload debe impedir desbloqueo.
- Frase correcta + cajas incorrectas debe fallar.
- Cajas correctas + frase incorrecta debe fallar.

## 7. Fase 4: Integrar plantillas con el vault

Prioridad: critica.

Funciones afectadas:

- `load_templates`
- `save_template`
- `delete_template`
- `initialize_defaults`
- `list_templates`

Comportamiento con vault inactivo:

- Igual que hoy: usar `.msgpack`.

Comportamiento con vault activo y bloqueado:

- `load_templates` devuelve error controlado o lista vacia segura.
- No se leen `.msgpack` en claro como fallback silencioso.

Comportamiento con vault activo y desbloqueado:

- `load_templates` lee del estado en memoria del vault.
- `save_template` actualiza memoria y reescribe vault cifrado atomicamente.
- `delete_template` borra de memoria y reescribe vault cifrado.

Migracion al habilitar:

1. Leer plantillas actuales.
2. Crear backup temporal.
3. Crear vault cifrado.
4. Verificar apertura del vault.
5. Mover `.msgpack` en claro a backup seguro o eliminarlos segun politica.
6. Registrar evento no sensible.

Criterios de aceptacion:

- Tras habilitar Boot Shield, no deben quedar plantillas personalizadas en claro.
- Las plantillas por defecto pueden regenerarse, pero no deben filtrar plantillas de usuario.
- Guardar una plantilla nueva con vault activo no debe crear `.msgpack` en claro.

## 8. Fase 5: Boton de panico y memoria

Prioridad: alta.

Estado actual:

- `panic_wipe_and_exit` solo ejecuta `exit(0)`.

Implementacion por etapas:

### Etapa 5.1: Renombrado honesto

Mientras no exista limpieza real:

- UI: "CIERRE RAPIDO"
- Tooltip: "Finaliza la aplicacion; no garantiza borrado seguro de memoria."

### Etapa 5.2: Sanitizacion best-effort

Integrar:

- `zeroize` para secretos.
- Limpieza del estado `VaultState`.
- Cierre de ventanas secundarias.
- Borrado de buffers temporales.
- `setrlimit(RLIMIT_CORE, 0)` al inicio.

### Etapa 5.3: Memoria bloqueada

Evaluar:

- `mlock` para clave derivada y buffers pequenos.
- Manejo de error si el sistema no permite bloquear memoria.
- No fallar el arranque por falta de `mlock`; degradar con advertencia.

Criterios de aceptacion:

- No prometer limpieza absoluta de DRAM.
- Documentar como "best-effort".
- `panic_wipe_and_exit` debe limpiar estado sensible antes de salir si el vault esta desbloqueado.

## 9. Fase 6: Control de red configurable en primera ejecucion

Prioridad: alta.

Decision solicitada:

- En primera ejecucion y configuracion, informar y solicitar autorizacion para acciones de red.
- Si no se autoriza, aconsejar ejecucion manual.
- El boton debe ser configurable segun el equipo para evitar aislamiento total accidental.

Perfiles:

```text
mock
  No ejecuta comandos del sistema.
  Solo registra evento.
  Perfil por defecto.

drop-default-route
  Elimina ruta por defecto.
  Mantiene LAN local.
  Requiere confirmacion explicita.

nmcli-off
  Ejecuta nmcli networking off.
  Puede cortar SSH/Remmina.
  Requiere confirmacion fuerte y advertencia.

manual
  No ejecuta nada.
  Muestra instrucciones para que el operador lo haga fuera de Livencrypt.
```

Primera ejecucion:

1. Mostrar pantalla de perfil de red.
2. Explicar riesgos por perfil.
3. Recomendar `mock` o `manual`.
4. Si se elige perfil real, solicitar confirmacion textual:
   - ejemplo: `ENTENDIDO`
5. Guardar solo el perfil, no contrasenas.

Privilegios:

- No guardar contrasenas administrativas.
- Si un comando requiere permisos, pedir al usuario configurar permisos externos.
- Documentar alternativa manual:
  - apagar Wi-Fi desde sistema;
  - eliminar ruta por defecto manualmente;
  - usar firewall del sistema;
  - ejecutar en entorno air-gapped.

Criterios de aceptacion:

- Primera ejecucion nunca debe cortar la red sin consentimiento.
- Perfil por defecto debe ser `mock`.
- El UI debe mostrar claramente el perfil activo.

## 10. Fase 7: Verificacion autenticada y anti-manipulacion

Prioridad: alta.

Implementar:

- AEAD obligatorio.
- Associated Data con cabecera.
- Contador de version del vault.
- Escrituras atomicas.
- Backup cifrado.

Rollback:

- Mantener `vault_counter`.
- Detectar downgrade si existe metadata local mas reciente.
- Si no se puede garantizar contador monotono por limitacion local, documentar riesgo.

Criterios de aceptacion:

- Copiar un vault antiguo encima de uno nuevo debe detectarse cuando haya contador local disponible.
- Manipular cabecera debe fallar.
- Manipular ciphertext debe fallar.

## 11. Fase 8: Modelo de amenazas y redaccion de producto

Prioridad: media.

Actualizar documentacion y UI:

Protege contra:

- robo de disco;
- copia offline del perfil de Livencrypt;
- lectura de plantillas con app cerrada;
- perdida de equipo sin sesion desbloqueada.

No protege contra:

- malware activo;
- usuario root;
- depurador adjunto;
- keylogger;
- lectura de memoria durante sesion desbloqueada;
- capturas de pantalla;
- portapapeles;
- sistema operativo comprometido.

Cambiar lenguaje:

- Evitar "100% blindado".
- Evitar "desaparece inmediatamente de DRAM".
- Usar "proteccion en reposo" y "limpieza best-effort".

## 12. Fase 9: Recuperacion y backup

Prioridad: media.

Implementar:

- Confirmacion doble de frase al habilitar.
- Exportacion cifrada de recuperacion.
- Backup atomico antes de migrar.
- Advertencia irreversible:
  - "Sin frase y cajas no se puede recuperar el vault."

Politica propuesta:

- Backup local cifrado automatico: `vault.backup.lvcvault`.
- Exportacion manual cifrada a ruta elegida.
- No permitir exportacion en claro si Boot Shield esta activo.

Criterios de aceptacion:

- Simular fallo a mitad de migracion no debe destruir plantillas.
- Recuperacion desde backup cifrado debe restaurar plantillas.
- Frase olvidada no debe tener bypass.

## 13. Fase 10: Logs seguros e intentos fallidos

Prioridad: media.

Cambios:

- No registrar cajas.
- No registrar frase.
- No diferenciar si fallo frase, cajas o vault.
- Mensaje unico: `Credenciales invalidas o vault corrupto`.
- Retardo progresivo:
  - 1 intento: sin retardo;
  - 2-3 intentos: 1-2 segundos;
  - 4+ intentos: retardo mayor configurable.

Criterios de aceptacion:

- Logs no contienen secretos.
- Capturas de consola no exponen cajas intentadas.
- Fallos repetidos no permiten fuerza bruta rapida desde UI.

## 14. Orden recomendado de implementacion

1. Desactivar promesas de cifrado real en UI hasta que exista vault.
2. Eliminar `boot_frase` y `boot_cajas` de `localStorage`.
3. Crear modulos Rust de seguridad.
4. Implementar `Argon2id` + AEAD.
5. Definir formato `LVCVAULT`.
6. Implementar comandos `boot_shield_*`.
7. Integrar `load_templates/save_template/delete_template` con vault.
8. Implementar migracion atomica desde `.msgpack`.
9. Implementar desbloqueo real al arrancar.
10. Implementar red configurable de primera ejecucion.
11. Implementar panic best-effort con `zeroize`.
12. Implementar backup/exportacion cifrada.
13. Agregar pruebas automatizadas.
14. Actualizar documentacion de usuario.

## 15. Pruebas obligatorias

### Seguridad de credenciales

- `localStorage` no contiene frase.
- `localStorage` no contiene cajas.
- Reinicio obliga a introducir credenciales.
- Logs no contienen secretos.

### Vault

- Unlock correcto con frase+cajas correctas.
- Unlock falla con frase incorrecta.
- Unlock falla con cajas incorrectas.
- Manipular un byte del vault falla.
- Manipular cabecera falla.
- Nonce distinto por escritura.
- Salt aleatorio por vault.

### Plantillas

- Habilitar Boot Shield migra plantillas existentes.
- No quedan `.msgpack` personalizados en claro.
- Guardar plantilla con vault activo no escribe claro.
- Eliminar plantilla con vault activo actualiza vault cifrado.

### Recuperacion

- Backup cifrado se crea antes de migrar.
- Recuperacion desde backup funciona.
- Vault corrupto no destruye backup valido.

### Red

- Primera ejecucion usa perfil `mock`.
- Perfil `nmcli-off` exige confirmacion fuerte.
- Perfil `manual` muestra instrucciones y no ejecuta comandos.

### Memoria y cierre

- `panic_wipe_and_exit` limpia `VaultState`.
- Core dumps deshabilitados si el sistema lo permite.
- Fallos de `mlock` generan advertencia, no crash.

## 16. Criterio de finalizacion

La integracion se considera completa cuando:

- No existen credenciales persistidas en frontend.
- Las plantillas protegidas no existen en claro en disco.
- El desbloqueo depende de Rust y del vault autenticado.
- El vault usa la secuencia segura `Argon2id` + `Livencrypt` + AEAD.
- Livencrypt esta integrado como capa interna obligatoria, envuelta por AEAD para autenticidad e integridad.
- La UI no promete garantias absolutas.
- La red es configurable y segura por defecto.
- Hay pruebas automatizadas de vault, migracion, logs y recuperacion.

## 17. Decision final de arquitectura

Arquitectura aprobada para integracion:

```text
Frase + cajas
    |
    v
Argon2id + salt
    |
    v
Clave de vault en memoria Rust
    |
    v
Payload serializado
    |
    v
Livencrypt obligatorio como capa interna de transmutacion/cifrado
    |
    v
XChaCha20-Poly1305 obligatorio para autenticidad e integridad
    |
    v
Vault cifrado en disco
```

La seguridad en reposo se construye con la composicion completa: `Argon2id` endurece la frase y las cajas frente a fuerza bruta, Livencrypt ejecuta la capa propia de cifrado/transmutacion del producto, y `XChaCha20-Poly1305` autentica y protege el vault final contra manipulacion. Livencrypt queda integrado en el sistema de encriptacion del archivo, pero el archivo final no se acepta como valido hasta superar la verificacion AEAD.
