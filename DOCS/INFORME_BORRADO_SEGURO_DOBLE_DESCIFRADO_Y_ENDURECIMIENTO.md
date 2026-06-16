# Informe de Seguridad: Borrado Seguro, Bloqueo de Captura, Anti-Malware y Doble Descifrado Boot Shield

## 1. Objetivo

Responder tecnicamente a las siguientes propuestas para Livencrypt 2.0:

- Antes de borrar archivos sensibles, escribir datos erroneos y despues borrarlos para que una restauracion del archivo sea inaccesible.
- Aplicar esa misma logica al cerrar la aplicacion.
- Bloquear `copy/paste` durante la ejecucion.
- Bloquear capturas de pantalla.
- Integrar medidas para neutralizar malware.
- Aclarar que secuencia de cajas se usa actualmente en el inicio de sesion Boot Shield.
- Evaluar un doble descifrado: primera secuencia `5 cajas + frase`, seguida de segunda secuencia `5 cajas + frase`; con un solo error no debe existir acceso al dashboard.

Este documento no modifica codigo. Define criterios de diseno y limites forenses.

## 2. Resumen ejecutivo

1. Segun el codigo actual, Boot Shield usa una secuencia mas parecida al cifrado de archivo que al cifrado de texto libre: el payload del vault se serializa, se convierte a hexadecimal, se transforma con Livencrypt usando `filelivencrypt_template()` y las 5 cajas, y finalmente se cifra/autentica con `XChaCha20-Poly1305`.
2. Sobrescribir un archivo con basura y borrarlo puede ayudar contra recuperacion simple en HDD, pero no debe considerarse fiable en SSD, sistemas con journaling, snapshots, copias COW o backups.
3. En SSD/NVMe, la medida fuerte no es "sobrescribir y borrar", sino cifrar desde el inicio y destruir claves, porque el controlador puede no sobrescribir las mismas celdas fisicas.
4. Al cerrar la aplicacion no debe destruirse el vault activo normal, porque se perderia el acceso en el siguiente arranque. Lo que debe limpiarse son temporales, plantillas en claro residuales, caches y memoria sensible.
5. Si existe un modo "panico destructivo", entonces si puede corromperse el vault y borrarse, pero debe ser irreversible y separado del cierre normal.
6. Bloquear portapapeles y capturas es una defensa best-effort. Ayuda contra fugas accidentales y herramientas normales, pero no neutraliza malware con permisos del usuario, root, compositor o acceso grafico.
7. Una aplicacion no puede neutralizar malware ya presente en el sistema. Puede reducir superficie, dificultar captura y detectar condiciones sospechosas, pero no garantizar limpieza del equipo.
8. El doble descifrado propuesto es valido si se integra criptograficamente en el vault. Si se implementa como segunda pantalla visual, es debil y parcheable.

## 3. Estado actual de la secuencia Boot Shield

### 3.1. Secuencia actual observada

El flujo actual del vault es:

```text
frase + caja1..caja5
        |
        v
Argon2id(salt, 64 MiB, 3 iteraciones, p=1)
        |
        v
clave AEAD 256 bits
```

Payload:

```text
plantillas + configuracion sensible + metadatos
        |
        v
MessagePack
        |
        v
hex
        |
        v
Livencrypt usando filelivencrypt_template() + caja1..caja5
        |
        v
XChaCha20-Poly1305 con clave derivada por Argon2id
        |
        v
vault.lvcvault
```

### 3.2. Es estilo cifrado texto o estilo cifrado archivo?

La secuencia Boot Shield no usa una plantilla de texto seleccionada por el usuario. Usa internamente `filelivencrypt_template()`.

Por tanto, conceptualmente es mas cercana al estilo de cifrado de archivo:

- trabaja sobre payload serializado/hexadecimal;
- usa plantilla fija `filelivencrypt`;
- no depende de una plantilla textual editable;
- las 5 cajas participan en la capa Livencrypt y en la derivacion `Argon2id`;
- no usa el mecanismo de "password_length" del cifrado de texto.

Resumen:

```text
Boot Shield actual = Argon2id + Livencrypt estilo filelivencrypt + AEAD
```

## 4. Sobre escribir datos erroneos antes de borrar

### 4.1. La idea

La propuesta es:

```text
archivo sensible
  -> sobrescribir con datos erroneos/aleatorios
  -> flush/sync
  -> borrar archivo
```

Objetivo:

```text
Si alguien restaura el archivo borrado, recupera basura y no el contenido original.
```

### 4.2. Es util?

Si, pero solo como medida best-effort y con alcance limitado.

Puede ayudar en:

- HDD clasico sin snapshots;
- archivos temporales pequenos;
- recuperacion simple de archivos borrados;
- casos donde el sistema de archivos realmente sobrescribe los mismos bloques;
- reduccion de exposicion accidental.

No es suficiente en:

- SSD/NVMe con wear leveling;
- sistemas de archivos con journaling;
- Btrfs/ZFS/APFS o mecanismos copy-on-write;
- snapshots;
- backups;
- caches;
- indexadores;
- papelera;
- sistemas con TRIM diferido;
- copias ya realizadas;
- imagenes forenses previas;
- almacenamiento remoto/sincronizado.

NIST SP 800-88 trata la sanitizacion como un proceso formal y diferencia niveles como Clear, Purge y Destroy. En flash/SSD, la sobrescritura logica puede no tocar las mismas celdas fisicas por wear leveling y sobreaprovisionamiento. Para SSD, la defensa robusta suele ser borrado criptografico, comandos de sanitizacion del dispositivo o destruccion fisica, segun el nivel de riesgo.

### 4.3. Riesgo especifico en SSD

En un SSD, cuando el sistema operativo escribe sobre una ruta logica, el controlador puede guardar los nuevos datos en otra ubicacion fisica. Los datos antiguos pueden quedar en bloques no mapeados, bloques reasignados o areas de sobreaprovisionamiento.

Por tanto:

```text
sobrescribir archivo != sobrescribir necesariamente las celdas fisicas antiguas
```

Conclusion:

```text
La sobrescritura previa al borrado reduce riesgo, pero no debe venderse como borrado forense garantizado.
```

## 5. Recomendacion para Livencrypt: borrado seguro por tipo de dato

### 5.1. Vault cifrado activo

El vault activo `vault.lvcvault` no debe sobrescribirse y borrarse al cierre normal.

Motivo:

- el vault es necesario para el siguiente arranque;
- si se destruye, las plantillas se pierden;
- el cierre normal debe bloquear y limpiar memoria, no eliminar el almacenamiento persistente cifrado.

Accion correcta al cierre normal:

```text
persistir vault valido si hay cambios
limpiar claves en memoria
limpiar payload en memoria
limpiar caches temporales
cerrar proceso
```

### 5.2. Plantillas `.msgpack` en claro residuales

Estas si deben tratarse agresivamente cuando Boot Shield esta activo.

Secuencia recomendada:

```text
1. detectar archivos .msgpack en directorio de plantillas
2. renombrar a nombre temporal aleatorio para evitar uso concurrente
3. sobrescribir con bytes aleatorios del mismo tamano o mayor
4. flush del archivo
5. fsync del directorio cuando sea posible
6. borrar archivo
7. registrar solo evento generico, nunca contenido
```

Advertencia:

```text
Esto no garantiza sanitizacion en SSD, pero evita que una restauracion simple del archivo borrado recupere el .msgpack original.
```

### 5.3. Temporales de cifrado/descifrado

Todo archivo temporal que contenga:

- texto claro;
- plantilla;
- fragmentos de payload;
- salida intermedia;
- backups previos;
- datos descifrados;

debe seguir la misma politica:

```text
sobrescritura best-effort -> flush -> borrado -> limpieza de memoria asociada
```

Mejor aun:

```text
evitar crear temporales en claro
usar streams
usar directorio privado 0700
usar nombres aleatorios
marcar temporales como no indexables cuando sea viable
```

### 5.4. Backups del vault

Los backups del vault estan cifrados. No deben borrarse automaticamente si sirven para recuperacion.

Si se rotan backups:

```text
backup antiguo cifrado
  -> opcional: sobrescribir best-effort
  -> borrar
```

Si existe riesgo de rollback, se necesita contador monotono o vinculacion TPM/secret local. Borrar backups no elimina snapshots externos.

## 6. Cierre normal de la aplicacion

### 6.1. Lo que debe hacer

Al cerrar Livencrypt:

```text
1. bloquear runtime Boot Shield
2. zeroize de claves Argon2id/AEAD
3. zeroize de cajas y frases en memoria Rust
4. limpiar payload de plantillas en memoria
5. limpiar campos frontend
6. limpiar buffers de texto si existen
7. limpiar resultados temporales si no deben persistir
8. purgar .msgpack residuales si Boot Shield esta activo
9. borrar temporales con sobrescritura best-effort
10. cerrar proceso
```

### 6.2. Lo que no debe hacer

No debe:

- sobrescribir y borrar el vault activo normal;
- destruir backups cifrados utiles sin confirmacion;
- borrar rutas de recuperacion;
- cortar red automaticamente;
- prometer borrado perfecto de DRAM;
- prometer proteccion contra root/malware.

### 6.3. Cierre destructivo opcional

Puede existir un modo separado:

```text
PANICO DESTRUCTIVO
```

Accion:

```text
1. pedir confirmacion fuerte
2. cerrar ventanas
3. limpiar memoria
4. sobrescribir vault con datos aleatorios
5. fsync
6. borrar vault
7. borrar backups de vault
8. borrar plantillas locales
9. cerrar proceso
```

Texto obligatorio:

```text
Esta accion puede hacer irrecuperables las plantillas. No es un cierre normal.
```

## 7. Que pasa si se restaura un archivo borrado?

### 7.1. Si se restaura un `.msgpack` previamente sobrescrito

Resultado esperado:

```text
archivo restaurado = basura aleatoria
plantilla inaccesible
```

Pero no garantizado si:

- el sistema restauro una version previa desde snapshot;
- la sobrescritura no alcanzo el bloque fisico antiguo;
- habia copia en journal;
- habia backup externo;
- habia cache de indexacion;
- el fichero ya fue copiado antes.

### 7.2. Si se restaura el vault cifrado valido

Si se restaura un `vault.lvcvault` valido:

- seguira siendo atacable por fuerza bruta offline;
- seguira siendo desbloqueable con frase + cajas correctas;
- no queda inutilizado por haber borrado una copia posterior.

Para impedir rollback/restauracion de vault antiguo se necesita:

- contador monotono local;
- secreto local no exportado;
- TPM;
- registro de version fuera del vault restaurable;
- politica de rechazo de vault antiguo.

### 7.3. Si se restaura un vault sobrescrito y borrado

Si realmente se sobrescribio el mismo contenido y se restauro esa version corrupta:

```text
XChaCha20-Poly1305 falla
vault inaccesible
```

Pero en SSD/snapshots puede restaurarse una version anterior valida.

## 8. Bloqueo de copy/paste

### 8.1. Medidas recomendadas

En ventanas sensibles:

```text
preventDefault en copy/cut/paste
preventDefault en contextmenu
preventDefault en dragstart/drop
deshabilitar seleccion de texto donde no sea necesaria
limpiar portapapeles al bloquear/cerrar
evitar botones "copiar" para secretos
no usar clipboard para frase/cajas
```

### 8.2. Alcance real

Bloquear copy/paste reduce:

- fugas accidentales;
- pegado de secretos en campos equivocados;
- exfiltracion por usuario no tecnico;
- robo mediante historial de portapapeles.

No detiene:

- malware con acceso al proceso;
- herramientas de accesibilidad maliciosas;
- capturas OCR;
- keyloggers;
- lectura directa del DOM/WebView;
- root;
- usuario que transcribe manualmente.

Conclusion:

```text
copy/paste blocking = control higienico, no defensa criptografica.
```

## 9. Bloqueo de capturas de pantalla

### 9.1. Medida tecnica disponible

Tauri v2 expone la opcion de ventana:

```text
contentProtected: true
```

La documentacion de Tauri describe esta opcion como un mecanismo para impedir que el contenido de la ventana sea capturado por otras aplicaciones.

Tambien puede aplicarse desde API de ventana si la plataforma lo soporta.

### 9.2. Limitaciones

No hay garantia universal.

Limitaciones:

- depende del sistema operativo;
- depende del compositor grafico;
- en Linux puede variar entre Wayland/X11/escritorio;
- no bloquea una camara externa;
- no bloquea malware con permisos suficientes;
- no bloquea captura a nivel driver/GPU;
- no bloquea lectura de memoria;
- no bloquea OCR sobre imagen capturada por otro canal.

### 9.3. Medidas complementarias

```text
contentProtected en todas las ventanas sensibles
modo pantalla completa opcional
marca de agua con usuario/equipo/hora
ocultar datos sensibles por defecto
revelar secretos solo mientras se mantiene pulsado
auto-bloqueo por inactividad
limpiar pantalla al perder foco
minimizar/ocultar al detectar blur si el modo estricto esta activo
```

Conclusion:

```text
screen capture blocking = defensa best-effort contra captura normal, no neutralizacion de malware.
```

## 10. Medidas para neutralizar malware

### 10.1. Dictamen tecnico

Una aplicacion de usuario no puede neutralizar malware ya instalado en el mismo sistema, especialmente si el malware corre como el mismo usuario o con privilegios superiores.

Si el malware puede:

- leer teclado;
- inyectar codigo;
- inspeccionar memoria;
- modificar binario;
- capturar pantalla;
- interceptar WebView;
- actuar como root;

entonces puede robar frase, cajas o plantillas una vez desbloqueadas.

### 10.2. Que si puede hacer Livencrypt

Puede reducir exposicion:

```text
no guardar frase/cajas
zeroize de memoria sensible
deshabilitar core dumps
mlock/mlockall best-effort en Linux
evitar logs con secretos
integridad del binario
firma de releases
verificacion de hash en actualizaciones
modo contentProtected
bloqueo de clipboard
auto-bloqueo por inactividad
limpiar al perder foco
minimizar superficie IPC Tauri
permisos minimos
detectar debugging de forma best-effort
avisar si se ejecuta como root
avisar si hay LD_PRELOAD sospechoso
avisar si el binario fue modificado
```

### 10.3. Que no debe prometer

No debe prometer:

```text
neutralizacion total de malware
invisibilidad frente a root
proteccion frente a keylogger activo
proteccion frente a memoria viva comprometida
proteccion frente a binario alterado por atacante local
```

Frase recomendada:

```text
Livencrypt reduce exposicion frente a fugas locales, pero no puede garantizar seguridad en un sistema infectado. Use Boot Shield con sistema operativo limpio, cifrado de disco y binarios verificados.
```

## 11. Doble descifrado propuesto

### 11.1. Propuesta del usuario

Secuencia:

```text
1. validar/descifrar con primera secuencia:
   cajas A + frase A

2. acto seguido descifrar con segunda secuencia:
   cajas B + frase B

3. si hay un solo error:
   no se accede al dashboard
```

Objetivo:

```text
un fallo en cualquiera de las dos credenciales bloquea completamente el acceso
```

### 11.2. Evaluacion

La propuesta es correcta si ambas credenciales son necesarias para descifrar material criptografico real.

No debe implementarse como:

```text
descifrar vault con A
mostrar pantalla visual de B
si B es correcto mostrar dashboard
```

Eso seria debil porque:

- el vault ya estaria abierto tras A;
- las plantillas podrian estar en memoria;
- la pantalla B podria parchearse;
- el atacante podria saltar el bloqueo de interfaz.

Debe implementarse como:

```text
A y B son necesarias para obtener la clave final del vault
sin A y B no hay payload descifrado en memoria
```

## 12. Diseno recomendado para doble credencial

### 12.1. Opcion recomendada: combinacion antes de una unica apertura AEAD

```text
K1 = Argon2id(frase A + cajas A + salt A)
K2 = Argon2id(frase B + cajas B + salt B)

Kfinal = HKDF-SHA256(K1 || K2, contexto Boot Shield, salt final)

payload
  -> Livencrypt capa A/B
  -> XChaCha20-Poly1305(Kfinal)
```

Desbloqueo:

```text
usuario introduce A y B
derivar K1
derivar K2
derivar Kfinal
intentar AEAD decrypt
si falla: error generico
si valida: cargar dashboard
```

Ventaja:

- no hay validacion independiente de A;
- no hay validacion independiente de B;
- el atacante debe acertar combinacion completa;
- un solo error impide descifrar el vault;
- el dashboard nunca se monta si falta cualquiera de las dos.

### 12.2. Como incorporar Livencrypt

Dos opciones:

#### Opcion A: una capa Livencrypt con cajas combinadas

Derivar cajas internas:

```text
caja_final_i = funcion(cajaA_i, cajaB_i, salt, version)
```

Luego:

```text
payload -> Livencrypt(payload, caja_final_1..5) -> AEAD(Kfinal)
```

Ventaja:

- formato simple;
- una sola capa Livencrypt;
- no hay apertura intermedia.

#### Opcion B: doble capa Livencrypt interna sin verificacion intermedia

```text
payload
  -> Livencrypt(payload, cajas B)
  -> Livencrypt(resultado, cajas A)
  -> AEAD(Kfinal)
```

Desbloqueo:

```text
AEAD(Kfinal) debe validar primero
despues revertir Livencrypt A
despues revertir Livencrypt B
```

Ventaja:

- respeta literalmente la idea de doble descifrado;
- ambas cajas influyen en Kfinal y en transformacion Livencrypt.

Requisito:

- no exponer errores separados tipo "fallo primera clave" o "fallo segunda clave";
- solo mostrar "credenciales invalidas o vault manipulado".

## 13. Diseno no recomendado: capas verificables por separado

Flujo no recomendado si el objetivo es maximizar coste de fuerza bruta:

```text
vault exterior = AEAD(K1, vault interior)
vault interior = AEAD(K2, payload)
```

Este diseno exige A y B para abrir, pero permite ataque por fases:

```text
1. romper A hasta abrir vault exterior
2. romper B hasta abrir vault interior
```

Coste aproximado:

```text
T_total ~= T_A + T_B
```

Si A y B tienen fuerza similar:

```text
mejora aproximada = x2
equivalente criptografico = +1 bit
```

No es inutil, pero no multiplica exponencialmente si cada capa se puede verificar por separado.

## 14. Diseno recomendado de interfaz para doble credencial

Pantalla Boot Shield:

```text
Bloque 1: Secuencia principal
  caja A1 A2 A3 A4 A5
  frase A

Bloque 2: Secuencia secundaria
  caja B1 B2 B3 B4 B5
  frase B

Boton:
  DESBLOQUEAR VAULT
```

Reglas:

- limpiar todos los campos tras cada intento;
- mismo mensaje de error para cualquier fallo;
- retardo progresivo en UI;
- contador de intentos solo local y no secreto;
- nunca guardar A ni B;
- nunca registrar cajas;
- nunca indicar cual de las dos secuencias fallo.

Texto de error:

```text
CREDENCIALES INVALIDAS O VAULT MANIPULADO
```

## 15. Coste de la doble credencial

Si se usa combinacion previa a una unica verificacion AEAD:

```text
E_total = E_A + E_B
```

Ejemplo:

```text
A = 5 cajas 0-999 + frase aleatoria fuerte
B = 5 cajas 0-999 + frase aleatoria fuerte
```

El atacante debe acertar ambas combinaciones antes de validar.

Si cada credencial tiene 70 bits efectivos:

```text
E_total ~= 140 bits
```

Esto queda fuera de fuerza bruta realista.

Si se usa doble capa verificable por separado:

```text
E efectiva practica ~= max(E_A, E_B) + 1 bit si ambas son parecidas
```

Por eso se recomienda combinar antes de verificar.

## 16. Secuencia integral recomendada para Livencrypt

Activacion:

```text
1. usuario introduce A y confirma A
2. usuario introduce B y confirma B
3. generar salt A, salt B y salt final
4. K1 = Argon2id(A)
5. K2 = Argon2id(B)
6. Kfinal = HKDF(K1 || K2)
7. serializar payload
8. aplicar Livencrypt interno con cajas combinadas o doble capa A/B
9. cifrar/autenticar con XChaCha20-Poly1305(Kfinal)
10. escribir vault
11. leer vault
12. verificar roundtrip con A+B
13. si correcto: limpiar .msgpack residuales con sobrescritura best-effort y borrar
14. limpiar memoria
15. cerrar aplicacion
```

Desbloqueo:

```text
1. usuario introduce A+B
2. derivar K1, K2, Kfinal
3. AEAD decrypt
4. si falla: limpiar campos y error generico
5. si valida: revertir Livencrypt
6. montar plantillas en memoria
7. cargar dashboard
```

Cierre normal:

```text
1. persistir cambios en vault cifrado valido
2. limpiar claves y payload en memoria
3. limpiar frontend
4. purgar temporales/residuos en claro
5. cerrar
```

Cierre destructivo:

```text
solo bajo confirmacion explicita
corromper vault + borrar + limpiar backups + limpiar memoria
```

## 17. Priorizacion de medidas

### Criticas

1. Doble credencial combinada antes de AEAD si se decide integrar doble descifrado.
2. No crear temporales en claro.
3. Limpiar `.msgpack` residuales con sobrescritura best-effort y borrado.
4. `zeroize` de claves, frases, cajas y payload.
5. `contentProtected` en ventanas sensibles.
6. Desactivar copy/paste en campos sensibles.
7. No registrar secretos.

### Altas

1. Deshabilitar core dumps.
2. `mlock/mlockall` best-effort.
3. Auto-bloqueo por inactividad.
4. Limpiar al perder foco.
5. Verificacion de integridad del binario.
6. Firma de builds.
7. Advertencia si se ejecuta como root.

### Medias

1. Marca de agua visual.
2. Deteccion best-effort de debugger.
3. Deteccion de variables de entorno sospechosas.
4. Deteccion de directorios sincronizados.
5. Aviso si existen snapshots/backups conocidos.

## 18. Dictamen final

La propuesta de escribir datos erroneos antes de borrar es razonable como endurecimiento, pero no debe considerarse borrado forense garantizado, especialmente en SSD. Debe aplicarse a residuos en claro, temporales y `.msgpack` migrados, no al vault activo en un cierre normal.

El cierre normal debe bloquear, persistir vault cifrado valido y limpiar memoria. La destruccion del vault debe existir solo como modo separado e irreversible.

Bloquear portapapeles y capturas reduce fugas accidentales, pero no neutraliza malware. Livencrypt puede endurecerse contra exposicion, pero no puede garantizar seguridad en un sistema comprometido.

La secuencia Boot Shield actual usa `filelivencrypt_template()`, por lo que se aproxima mas al estilo de cifrado de archivo que al cifrado de texto por plantilla seleccionada.

El doble descifrado propuesto es una mejora fuerte solo si ambas credenciales se combinan criptograficamente antes de abrir el vault. La regla correcta es:

```text
sin A + B correctos, no hay clave final;
sin clave final, AEAD no valida;
sin AEAD valido, no hay payload;
sin payload, no hay dashboard.
```

## 19. Referencias

- NIST SP 800-88 Rev. 2, Guidelines for Media Sanitization:
  https://csrc.nist.gov/pubs/sp/800/88/r2/final

- OWASP MASWE-0055, Sensitive Data Leaked via Screenshots or Screen Recordings:
  https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0055/

- OWASP Cornucopia / MASVS, riesgo de datos sensibles en portapapeles:
  https://cornucopia.owasp.org/cards/NS3

- Tauri v2 WindowOptions `contentProtected`:
  https://v2.tauri.app/reference/javascript/api/namespacewindow/

- OWASP Cryptographic Storage Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
