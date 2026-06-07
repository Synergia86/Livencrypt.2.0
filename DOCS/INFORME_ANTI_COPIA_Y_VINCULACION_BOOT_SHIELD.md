# Informe de Seguridad: Anti-Copia, Fuerza Bruta y Vinculacion del Boot Shield

## 1. Objetivo

Analizar si un atacante puede copiar el archivo de configuracion/vault de Livencrypt Boot Shield a otro equipo y explotarlo por fuerza bruta para acceder al dashboard, y definir medidas para reducir la portabilidad del vault sin provocar perdida accidental de acceso para el usuario legitimo.

Este documento no modifica codigo. Define el caso de seguridad y una hoja tecnica de diseno para una futura integracion.

## 2. Respuesta directa

### Si se copia el archivo de configuracion a otro equipo, se puede acceder al dashboard?

No de forma directa. Si Boot Shield esta correctamente activado, el archivo util no deberia ser una configuracion en claro sino un vault cifrado. Para acceder al dashboard, el atacante necesita desbloquear ese vault con:

- la frase correcta;
- la secuencia correcta de las 5 cajas;
- el formato y parametros del vault;
- la verificacion autenticada del ciphertext.

Si no conoce la frase y cajas, no deberia poder abrir el dashboard. Lo que si puede hacer es intentar un ataque offline de fuerza bruta contra una copia del vault.

### Puede hacer fuerza bruta offline?

Si. Cualquier sistema que permita copiar el vault cifrado permite intentos offline si el atacante tiene el archivo. La defensa no es impedir matematicamente todos los intentos, sino hacerlos costosos:

- `Argon2id` debe consumir memoria y tiempo por intento.
- La frase debe tener suficiente entropia.
- Las 5 cajas deben formar parte de la derivacion de clave.
- El vault debe usar cifrado autenticado para que cada intento incorrecto falle sin revelar datos utiles.

El retardo progresivo de la interfaz no sirve contra fuerza bruta offline, porque el atacante no usa la aplicacion original; usa su propio programa contra el archivo copiado.

### Al proteger con clave de acceso, tambien se cifran las plantillas?

Ese debe ser el objetivo obligatorio de Boot Shield. El estado seguro es:

```text
Boot Shield desactivado:
  plantillas .msgpack pueden existir en disco en claro

Boot Shield activado:
  plantillas migradas dentro del vault cifrado
  .msgpack en claro eliminados
  carga de plantillas solo desde vault desbloqueado en memoria
```

Si quedan plantillas `.msgpack` en claro despues de activar Boot Shield, la proteccion es incompleta. La pantalla de bloqueo solo seria una barrera visual, no una proteccion criptografica de las plantillas.

## 3. Modelo de amenaza

### Protege contra

- Copia del vault con la aplicacion cerrada.
- Robo o clonacion parcial del perfil de usuario donde esta el vault.
- Lectura directa de plantillas en disco, siempre que las plantillas se hayan migrado al vault.
- Manipulacion simple del vault, si se usa AEAD con datos asociados.

### Reduce, pero no elimina

- Fuerza bruta offline sobre frases debiles.
- Ataques con GPU, si `Argon2id` esta configurado con memoria suficiente.
- Copia del vault a otro equipo, si se anade vinculacion local al dispositivo.

### No protege contra

- Malware o keylogger ejecutandose mientras el usuario introduce la frase.
- Atacante con `root` durante una sesion desbloqueada.
- Debugger o volcado de memoria con Livencrypt abierto.
- Usuario legitimo malicioso con acceso ya concedido.
- Copia completa del disco mas copia de cualquier secreto local si ese secreto tambien vive dentro del disco.

## 4. Por que los IDs de hardware no son suficientes

Se puede pensar en indexar el vault a:

- ID del SSD.
- ID del procesador.
- ID de RAM.
- ID del usuario.
- ID del sistema operativo.
- `machine-id` del sistema.

Estos valores pueden ser utiles como senales auxiliares, pero no deben tratarse como secretos.

Problemas:

- Muchos identificadores son legibles por software local.
- Algunos no existen, cambian con firmware o no son estables entre fabricantes.
- En maquinas virtuales pueden ser falsificados.
- En una imagen completa del disco, IDs del sistema como `/etc/machine-id`, usuario, UID y configuraciones viajan con la imagen.
- Si el valor se puede leer para derivar la clave, un atacante que pueda ejecutar codigo en otro entorno puede intentar reproducirlo o parchear la comprobacion.
- Si el hardware cambia por reparacion, ampliacion de RAM o cambio de disco, el usuario legitimo puede perder acceso.

Conclusion:

> Un ID de hardware no es una clave. Sirve como dato asociado o condicion de politica, pero no como frontera criptografica fuerte.

## 5. Diseno correcto para evitar copia util del vault

Para que una copia del vault no sea valida en otro equipo, la clave efectiva debe depender de al menos un secreto que no viaje con el archivo copiado.

Secuencia recomendada:

```text
frase + cajas
    |
    v
Argon2id con salt del vault
    |
    v
clave del usuario

secreto local del equipo, no exportable si es posible
    |
    v
clave de vinculacion del dispositivo

clave del usuario + clave de vinculacion
    |
    v
HKDF / combinacion KDF
    |
    v
clave final AEAD del vault
```

El secreto local puede estar en:

- TPM 2.0, idealmente con clave sellada al equipo.
- Almacen seguro del sistema operativo.
- Secret Service/libsecret en Linux, si esta disponible.
- Archivo secreto local generado al activar Boot Shield, con permisos estrictos, como solucion intermedia.

La diferencia importante:

- IDs de hardware: normalmente no secretos.
- Secreto local generado: puede ser secreto si no se copia.
- TPM: mejor opcion si la clave no es exportable y las operaciones criptograficas ocurren dentro del modulo o mediante sellado.

## 6. Niveles de vinculacion propuestos

### Nivel 0: Portable seguro

El vault depende solo de:

- frase;
- cajas;
- salt;
- parametros `Argon2id`;
- Livencrypt;
- AEAD.

Ventajas:

- Es portable.
- Permite restaurar backup en otro equipo.
- Menor riesgo de dejar al usuario sin acceso.

Desventajas:

- Si el vault se copia, permite fuerza bruta offline en cualquier equipo.

Uso recomendado:

- Modo por defecto si se prioriza recuperacion.

### Nivel 1: Vinculacion blanda a instalacion

El vault incorpora como Associated Data:

- identificador de instalacion generado por Livencrypt;
- usuario local;
- `machine-id`;
- version de formato;
- identificador de app.

Ventajas:

- Detecta copias simples y cambios accidentales.
- Facil de implementar.
- No rompe criptografia si se disena con migracion.

Desventajas:

- No detiene a un atacante que copie tambien esos metadatos.
- No impide fuerza bruta si el secreto necesario esta en el mismo disco.

Uso recomendado:

- Deteccion y advertencia, no seguridad fuerte.

### Nivel 2: Vinculacion con secreto local

Al activar Boot Shield se genera un secreto aleatorio local:

```text
~/.local/share/livencrypt/.livencrypt/secure/device.key
```

Ese secreto:

- no se guarda dentro del vault;
- se protege con permisos `0600`;
- se combina con frase + cajas para derivar la clave final;
- puede exportarse solo mediante una funcion de backup cifrado.

Ventajas:

- Copiar solo el vault ya no basta.
- Una desinstalacion que borre datos locales invalida el vault.
- Reduce ataques offline contra vault suelto.

Desventajas:

- Si el atacante clona todo el perfil de usuario, tambien puede clonar `device.key`.
- Si se pierde `device.key`, el vault queda inaccesible salvo backup.

Uso recomendado:

- Buen equilibrio para Livencrypt si se comunica claramente el riesgo.

### Nivel 3: Vinculacion fuerte con TPM

El vault depende de una clave protegida por TPM 2.0:

- clave no exportable o secreto sellado al TPM;
- opcionalmente sellado a PCRs concretos del arranque;
- desbloqueo requiere frase + cajas + operacion local del TPM.

Ventajas:

- Una imagen del disco no contiene el secreto TPM.
- Copiar el vault a otro equipo no permite abrirlo aunque se conozca el archivo completo.
- Aumenta mucho el coste de clonacion.

Desventajas:

- No todos los equipos tienen TPM utilizable.
- Puede fallar al cambiar firmware, Secure Boot, kernel o parametros PCR si se sella de forma agresiva.
- Requiere flujo de recuperacion.
- Mas complejidad de soporte en Linux.

Uso recomendado:

- Modo avanzado "vincular a este equipo".
- Nunca activarlo sin backup de recuperacion.

## 7. Sobre imagen completa de disco

Si el atacante hace una imagen completa del disco, hay tres casos:

### Caso A: vault sin vinculacion local

La imagen contiene el vault. El atacante puede intentar fuerza bruta offline en otro equipo.

### Caso B: vault + secreto local en archivo

La imagen puede contener tambien el secreto local. Si el atacante copia todo, la proteccion adicional baja. Aun asi, si el usuario exporta solo el vault o solo se filtra el archivo de configuracion, la copia no sirve.

### Caso C: vault + TPM

La imagen contiene el vault, pero no contiene la clave privada interna del TPM. En otro equipo, el vault no deberia desbloquearse. En el mismo equipo original, podria seguir siendo valido si el estado TPM/PCR coincide.

Conclusion:

> Para que una imagen de disco no sea suficiente, el diseno necesita un factor que no este dentro de la imagen. El candidato realista es TPM o un servicio externo. Los IDs del sistema copiados dentro de la imagen no bastan.

## 8. Recomendacion para Livencrypt

Implementar tres modos seleccionables:

### Modo 1: Recuperable

Nombre de UI:

```text
Boot Shield portable
```

Propiedades:

- frase + cajas;
- Argon2id + Livencrypt + AEAD;
- permite restaurar vault en otro equipo con las mismas credenciales.

Advertencia:

```text
Si alguien copia el vault, podra intentar fuerza bruta offline.
```

### Modo 2: Instalacion local

Nombre de UI:

```text
Boot Shield vinculado a esta instalacion
```

Propiedades:

- frase + cajas;
- secreto local aleatorio `device.key`;
- datos de equipo como Associated Data;
- backup cifrado obligatorio para recuperar.

Advertencia:

```text
Si se borra la configuracion local o se reinstala sin backup, las plantillas pueden perderse.
```

### Modo 3: Equipo fisico

Nombre de UI:

```text
Boot Shield vinculado a TPM
```

Propiedades:

- frase + cajas;
- secreto sellado en TPM;
- el vault no debe abrir en otro equipo aunque se copie el disco.

Advertencia:

```text
Cambios de firmware, TPM, placa base o politica de arranque pueden bloquear el acceso. Requiere backup de recuperacion.
```

## 9. Formato de vault recomendado

Cabecera publica:

```text
magic = LVCVAULT
format_version
kdf = Argon2id
kdf_params
salt
aead = XChaCha20-Poly1305
nonce
binding_mode = portable | local_secret | tpm
binding_id_public
device_policy_version
object_names
vault_counter
```

No guardar en la cabecera:

- frase;
- cajas;
- clave derivada;
- secreto local;
- clave TPM;
- hash reutilizable que permita verificar contrasena sin AEAD.

Datos asociados AEAD:

- `magic`;
- version;
- algoritmo;
- parametros KDF;
- modo de vinculacion;
- identificador publico de instalacion;
- lista de objetos;
- contador de vault.

Payload cifrado:

- plantillas;
- configuracion sensible;
- metadatos internos;
- estado de migracion;
- historial minimo necesario.

## 10. Flujo de activacion recomendado

1. Usuario selecciona activar Boot Shield.
2. Usuario elige modo:
   - portable;
   - vinculado a instalacion;
   - vinculado a TPM.
3. Usuario introduce cajas + frase.
4. Usuario confirma frase dos veces.
5. Si elige vinculacion:
   - generar secreto local o TPM;
   - crear backup cifrado de recuperacion;
   - mostrar advertencia irreversible.
6. Migrar plantillas al vault.
7. Verificar roundtrip:
   - escribir vault;
   - leer vault;
   - descifrar con las mismas credenciales;
   - comprobar integridad AEAD.
8. Solo si la verificacion funciona:
   - borrar plantillas en claro;
   - cerrar aplicacion;
   - exigir desbloqueo en el siguiente arranque.

## 11. Flujo de recuperacion

Debe existir antes de activar vinculacion fuerte.

Opciones:

- Exportar paquete de recuperacion cifrado con una frase independiente.
- Generar codigo de recuperacion de alta entropia.
- Permitir convertir vault vinculado a vault portable mientras esta desbloqueado.
- Permitir rotar `device.key` o TPM si el vault esta desbloqueado.

No recomendado:

- Permitir "reset" que preserve plantillas sin credenciales.
- Guardar copia de la frase.
- Guardar clave maestra en el frontend.

## 12. Riesgo de bloqueo del usuario legitimo

Vincular a hardware aumenta seguridad, pero tambien aumenta riesgo operacional.

Eventos que pueden romper acceso:

- cambio de disco;
- cambio de placa base;
- limpieza de `$HOME`;
- reinstalacion del sistema;
- cambio de usuario;
- cambio de TPM;
- restauracion de backup en otro equipo;
- purga del paquete si borra datos locales;
- perdida del backup de recuperacion.

Por eso el modo vinculado no debe activarse silenciosamente. Debe requerir confirmacion explicita:

```text
ENTIENDO QUE SIN ESTE EQUIPO O SIN BACKUP DE RECUPERACION PUEDO PERDER MIS PLANTILLAS
```

## 13. Decision tecnica recomendada

Para Livencrypt 2.0, la mejor ruta es:

1. Mantener Boot Shield actual como modo portable seguro.
2. Anadir modo "vinculado a instalacion" con secreto local aleatorio.
3. Disenar modo TPM como opcion avanzada, no como requisito.
4. Usar IDs de hardware solo como datos asociados y senales de advertencia, no como claves.
5. No prometer que SSD/CPU/RAM impiden copia si no hay secreto no exportable.
6. No borrar datos de usuario en desinstalacion normal; borrar solo en `purge` o restablecimiento confirmado.

## 14. Frase de seguridad para documentacion de usuario

Texto recomendado:

```text
Boot Shield cifra las plantillas en reposo. Si se copia el vault, un atacante no puede abrirlo sin la frase y las cajas, pero puede intentar fuerza bruta offline. Para impedir que el vault sea util en otro equipo, active la vinculacion local o TPM y guarde un backup de recuperacion.
```

## 15. Referencias tecnicas

- OWASP Cryptographic Storage Cheat Sheet: recomienda disenar almacenamiento criptografico con algoritmos publicos, gestion correcta de claves y autenticacion/integridad del dato cifrado.
  https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

- OWASP Key Management Cheat Sheet: trata la gestion de claves, proteccion en almacenamiento y uso de modulos o servicios de gestion de secretos cuando el riesgo lo justifica.
  https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html

- OWASP Password Storage Cheat Sheet: recomienda KDFs resistentes como `Argon2id` para secretos derivados de contrasenas.
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

- NIST SP 800-63B: define criterios sobre autenticadores, clonacion/exportacion de claves y el uso de criptografia aprobada para operaciones de autenticacion.
  https://pages.nist.gov/800-63-4/sp800-63b.html
