# Hoja de Ruta: Livencrypt en Equipo Aislado y Endurecimiento Boot Shield

## 1. Objetivo

Definir una hoja de ruta para endurecer Livencrypt 2.0 descartando Docker como via principal y priorizando el escenario operativo natural de la aplicacion:

- equipo aislado;
- tarjeta de red desactivada o sin conectividad;
- reinicio para limpiar estado temporal;
- ejecucion local portable;
- adaptacion futura a otras plataformas;
- Boot Shield como proteccion criptografica de plantillas y configuracion.

El documento tambien fija la integracion futura de:

- selector de plantilla al activar `AUTO-CIFRADO DE ARRANQUE`;
- limpieza agresiva de `.msgpack` residuales;
- limpieza de temporales;
- cierre normal endurecido;
- cierre destructivo opcional;
- reduccion de exposicion frente a malware;
- doble credencial combinada antes de AEAD.

Este documento no modifica codigo. Sirve como guia de integracion.

## 2. Principio de seguridad operativo

Livencrypt debe asumir como escenario preferente:

```text
equipo sin red o con red desactivada
uso local
plantillas cifradas en reposo
credenciales no persistidas
minima exposicion de memoria y temporales
reinicio tras uso sensible cuando el riesgo lo justifique
```

Docker queda descartado como estrategia principal. El aislamiento operativo debe venir de:

- equipo dedicado;
- red desconectada;
- sistema limpio;
- cifrado en reposo;
- cierre y reinicio;
- minimizacion de datos temporales;
- control estricto de plantillas.

## 3. Modelo de uso recomendado

### 3.1. Uso normal seguro

```text
1. iniciar equipo aislado o sin red
2. abrir Livencrypt
3. desbloquear Boot Shield
4. trabajar con texto/archivo/plantillas
5. cerrar Livencrypt
6. Livencrypt limpia memoria, temporales y residuos
7. opcional: reiniciar equipo para reducir persistencia de memoria
```

### 3.2. Uso de maxima sensibilidad

```text
1. equipo dedicado
2. sin red fisica o tarjeta desactivada
3. sin sincronizacion cloud
4. sin portapapeles compartido
5. sin capturas
6. sin servicios innecesarios
7. Boot Shield con doble credencial
8. cierre normal endurecido
9. reinicio despues de operar
```

### 3.3. Uso portable multiplataforma

Livencrypt ocupa poco y puede adaptarse a dispositivos donde pueda ejecutarse el runtime necesario.

La hoja de ruta debe separar:

- nucleo criptografico Rust;
- interfaz Tauri;
- almacenamiento local;
- integraciones especificas de sistema operativo;
- medidas de red/captura/clipboard por plataforma.

## 4. Configuracion del sistema: selector de plantilla al activar Boot Shield

### 4.1. Requisito

En `CONFIGURACION DEL SISTEMA`, al activar:

```text
AUTO-CIFRADO DE ARRANQUE
```

debe añadirse una funcion:

```text
Seleccionar plantilla Boot Shield
```

Objetivo:

- permitir elegir la plantilla Livencrypt usada como capa interna del vault;
- no depender necesariamente de `filelivencrypt_template()`;
- permitir que el usuario use una plantilla propia para la capa Livencrypt del Boot Shield;
- registrar en la cabecera publica solo el identificador/version de plantilla, nunca la plantilla en claro si forma parte del secreto.

### 4.2. Opciones de diseño

#### Opcion A: plantilla fija de sistema [no aplicar]

```text
Boot Shield siempre usa Livencrypt/filelivencrypt
```

Ventajas:

- mas simple;
- menos riesgo de bloquear al usuario;
- mas facil migracion.

Desventajas:

- menor personalizacion;
- no aprovecha plantillas propias como factor adicional.

#### Opcion B: selector de plantilla antes de cifrar el vault 

```text
usuario elige plantilla
plantilla se usa para Livencrypt interno
plantilla queda guardada cifrada dentro del vault
```

Ventajas:

- mas fuerte frente a conocimiento del formato interno;
- coherente con identidad Livencrypt;
- permite plantillas personalizadas como capa operacional.

Riesgos:

- si la plantilla elegida se pierde o cambia, puede romper desbloqueo;
- si el identificador no es suficiente para reconstruirla, se necesita guardar snapshot cifrado;
- mayor complejidad de migracion.

#### Opcion C: plantilla combinada para doble credencial 

```text
plantilla final = funcion(plantilla seleccionada + cajas A + cajas B + salt)
```

Ventajas:

- mas integracion con doble credencial;
- evita una plantilla interna estatica.

Riesgos:

- complejidad alta;
- requiere pruebas formales de migracion y recuperacion.

### 4.3. Decision recomendada

Fase inicial:

```text
implementar selector de plantilla Boot Shield con snapshot cifrado dentro del vault
```

Reglas:

- mostrar lista de plantillas disponibles; habilitar la opción de acceder a EDITAR PLANTILLAS y así crear nuevas plantillas para poder seleccionar en el inicio.
- por defecto seleccionar `Livencrypt`;
- guardar dentro del vault una copia cifrada de la plantilla usada para Boot Shield;
- no permitir borrar la plantilla Boot Shield activa sin migracion previa;
- permitir cambiar plantilla Boot Shield solo con vault desbloqueado y re-cifrado completo;
- verificar roundtrip antes de eliminar residuos.

## 5. Plantillas `.msgpack` en claro residuales

Estas deben tratarse agresivamente cuando Boot Shield esta activo.

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

### 5.1. Alcance

Debe aplicarse a:

- migracion inicial a Boot Shield;
- cierre normal si Boot Shield esta activo;
- limpieza manual desde configuracion;
- reset de instalacion;
- rotacion de vault;
- cambio de plantilla Boot Shield.

### 5.2. Limitaciones

Debe documentarse que:

- en SSD no garantiza borrado fisico;
- snapshots/backups pueden conservar versiones anteriores;
- la defensa fuerte es no crear texto claro y cifrar desde el inicio;
- la sobrescritura es best-effort.

## 6. Temporales de cifrado/descifrado

Todo archivo temporal que contenga:

- texto claro;
- plantilla;
- fragmentos de payload;
- salida intermedia;
- backups previos;
- datos descifrados;

debe seguir la politica:

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

### 6.1. Reglas de implementacion

- Crear directorio temporal privado por sesion.
- Permisos `0700` en Linux.
- Nombres aleatorios criptograficos.
- No reutilizar nombres.
- No escribir plaintext si se puede procesar en streaming.
- No registrar rutas sensibles salvo modo diagnostico.
- Limpiar temporales al cerrar, bloquear o fallar.

## 7. Cierre normal de la aplicacion

### 7.1. Lo que debe hacer

Al cerrar Livencrypt:

```text
1. persistir cambios en vault cifrado valido
2. bloquear runtime Boot Shield
3. zeroize de claves Argon2id/AEAD
4. zeroize de cajas y frases en memoria Rust
5. limpiar payload de plantillas en memoria
6. limpiar campos frontend
7. limpiar buffers de texto si existen
8. limpiar resultados temporales si no deben persistir
9. purgar .msgpack residuales si Boot Shield esta activo
10. borrar temporales con sobrescritura best-effort
11. cerrar proceso
```

### 7.2. Lo que no debe hacer

El cierre normal no debe:

- destruir el vault activo;
- borrar backups cifrados utiles sin confirmacion;
- cortar red del host de forma automatica;
- prometer borrado completo de DRAM;
- dejar la aplicacion bloqueada sin persistir cambios.

### 7.3. Reinicio del equipo

Para operaciones sensibles, tras cerrar Livencrypt se recomienda:

```text
reiniciar equipo
```

Objetivo:

- reducir persistencia de memoria;
- cerrar handles abiertos;
- limpiar estado de procesos;
- reducir exposicion accidental post-uso.

Limite:

- no garantiza defensa frente a cold boot;
- no limpia backups ni snapshots;
- no corrige malware persistente.

## 8. Cierre destructivo opcional

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
9. borrar temporales
10. cerrar proceso
```

Texto obligatorio:

```text
Esta accion puede hacer irrecuperables las plantillas. No es un cierre normal.
```

### 8.1. Confirmacion recomendada

```text
DESTRUIR VAULT Y PLANTILLAS
```

La confirmacion debe ser exacta y no depender de botones ambiguos.

## 9. Red y equipo aislado

### 9.1. Enfoque recomendado

La estrategia preferente no debe ser manipular agresivamente la red del host desde Livencrypt, sino:

- equipo sin red;
- adaptador desconectado;
- Wi-Fi desactivado por sistema;
- perfil de red manual;
- reinicio tras uso sensible;
- modo `mock` por defecto para evitar aislar equipos remotos.

### 9.2. Perfiles de red en Livencrypt

Mantener perfiles:

- `mock`: simulacion segura;
- `manual`: instrucciones al usuario;
- `drop-default-route`: avanzado;
- `nmcli-off`: destructivo/administrativo.

Regla:

```text
Por defecto, Livencrypt no debe cortar la red del sistema.
```

### 9.3. Recomendacion de uso

Para seguridad alta:

```text
apagar Wi-Fi/Bluetooth
desconectar cable Ethernet
evitar servicios de sincronizacion
usar equipo dedicado
reiniciar despues de cerrar
```

## 10. Medidas para reducir exposicion

Livencrypt puede reducir exposicion con:

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

### 10.1. Medidas criticas

- No persistir credenciales.
- Limpiar campos tras intento.
- No registrar cajas.
- No mostrar si fallo A o B.
- No dejar `.msgpack` en claro.
- No crear temporales en claro.
- Proteger ventanas sensibles.

### 10.2. Limite frente a malware

Una aplicacion no puede neutralizar malware ya presente.

Debe indicarse:

```text
Livencrypt reduce exposicion, pero un sistema infectado puede capturar credenciales durante el uso.
```

## 11. Doble credencial Boot Shield

### 11.1. Objetivo

Integrar una proteccion en la que el usuario tenga que introducir:

```text
Credencial A = 5 cajas A + frase A
Credencial B = 5 cajas B + frase B
```

Regla:

```text
un solo error en A o B impide acceso al dashboard
```

No debe existir apertura parcial.

## 12. Diseño recomendado para doble credencial

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

### 12.3. Decision recomendada

Para Livencrypt:

```text
usar Opcion B si se quiere respetar la semantica literal de doble descifrado;
usar Opcion A si se prioriza formato simple y mantenimiento;
en ambos casos, Kfinal debe depender de A+B antes de AEAD.
```

## 13. Interfaz para doble credencial

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

## 14. Coste de la doble credencial

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

## 15. Secuencia integral recomendada para Livencrypt

### 15.1. Activacion

```text
1. usuario selecciona plantilla Boot Shield
2. usuario introduce A y confirma A
3. usuario introduce B y confirma B
4. generar salt A, salt B y salt final
5. K1 = Argon2id(A)
6. K2 = Argon2id(B)
7. Kfinal = HKDF(K1 || K2)
8. serializar payload
9. aplicar Livencrypt interno con cajas combinadas o doble capa A/B
10. cifrar/autenticar con XChaCha20-Poly1305(Kfinal)
11. escribir vault
12. leer vault
13. verificar roundtrip con A+B
14. si correcto: limpiar .msgpack residuales con sobrescritura best-effort y borrar
15. limpiar memoria
16. cerrar aplicacion
```

### 15.2. Desbloqueo

```text
1. usuario introduce A+B
2. derivar K1, K2, Kfinal
3. AEAD decrypt
4. si falla: limpiar campos y error generico
5. si valida: revertir Livencrypt
6. montar plantillas en memoria
7. cargar dashboard
```

### 15.3. Cierre normal

```text
1. persistir cambios en vault cifrado valido
2. limpiar claves y payload en memoria
3. limpiar frontend
4. purgar temporales/residuos en claro
5. cerrar
```

### 15.4. Cierre destructivo

```text
solo bajo confirmacion explicita
corromper vault + borrar + limpiar backups + limpiar memoria
```

## 16. Priorizacion de medidas

### Criticas

1. Doble credencial combinada antes de AEAD si se decide integrar doble descifrado.
2. Selector de plantilla Boot Shield en `CONFIGURACION DEL SISTEMA`.
3. No crear temporales en claro.
4. Limpiar `.msgpack` residuales con sobrescritura best-effort y borrado.
5. `zeroize` de claves, frases, cajas y payload.
6. `contentProtected` en ventanas sensibles.
7. Desactivar copy/paste en campos sensibles.
8. No registrar secretos.

### Altas

1. Deshabilitar core dumps.
2. `mlock/mlockall` best-effort.
3. Auto-bloqueo por inactividad.
4. Limpiar al perder foco.
5. Verificacion de integridad del binario.
6. Firma de builds.
7. Advertencia si se ejecuta como root.
8. Red desactivada por sistema o equipo aislado.

### Medias

1. Marca de agua visual.
2. Deteccion best-effort de debugger.
3. Deteccion de variables de entorno sospechosas.
4. Deteccion de directorios sincronizados.
5. Aviso si existen snapshots/backups conocidos.
6. Documentacion de reinicio recomendado tras uso sensible.

## 17. Adaptacion a otras plataformas

Livencrypt debe separar el nucleo comun de las integraciones por plataforma.

### 17.1. Comun

- Rust core criptografico.
- Vault Boot Shield.
- Argon2id/HKDF/AEAD.
- Livencrypt interno.
- serializacion.
- limpieza de temporales.

### 17.2. Linux

- `mlock/mlockall` best-effort.
- deshabilitar core dumps.
- permisos `0700/0600`.
- fsync de directorios.
- perfiles de red opcionales.
- content protection segun soporte del compositor.

### 17.3. Windows

- DPAPI opcional para secreto local.
- proteccion de ventana segun API disponible.
- limpieza de temporales.
- bloqueo de clipboard.
- integridad de binario firmada.

### 17.4. macOS

- Keychain opcional para secreto local.
- proteccion de captura segun API disponible.
- sandboxing si procede.
- firma y notarizacion.

### 17.5. Dispositivos de baja potencia

- calibrar Argon2id.
- permitir perfil KDF ajustado.
- evitar temporales en disco.
- interfaz ligera.
- mantener compatibilidad de formato.

## 18. Criterios de aceptacion

### Boot Shield

- Activar Boot Shield permite seleccionar plantilla.
- Las credenciales A+B no se guardan.
- El vault solo abre si A+B son correctas.
- No se informa si fallo A o B.
- El dashboard no se monta hasta que AEAD valida.
- `.msgpack` residuales se limpian.

### Cierre

- Cierre normal preserva vault valido.
- Cierre normal limpia memoria y temporales.
- Panico destructivo exige confirmacion especifica.
- Panico destructivo puede hacer irrecuperables las plantillas.

### Red

- Modo por defecto no toca la red.
- Perfil real exige confirmacion.
- La documentacion recomienda equipo aislado antes que cortar red por software.

### Portabilidad

- El vault mantiene formato versionado.
- Las integraciones especificas no rompen el core.
- La plantilla Boot Shield queda versionada o cifrada dentro del vault.

## 19. Dictamen final

La estrategia principal para Livencrypt no debe ser Docker. El escenario coherente es una aplicacion local, ligera, ejecutada en equipo aislado o con red desactivada, con Boot Shield protegiendo plantillas y configuracion en reposo.

La hoja de ruta debe priorizar:

```text
selector de plantilla Boot Shield
doble credencial combinada antes de AEAD
limpieza agresiva de residuos
cierre normal endurecido
panico destructivo separado
reduccion de exposicion de memoria/clipboard/captura
documentacion de uso en equipo aislado
portabilidad multiplataforma
```

El reinicio del equipo despues de uso sensible no sustituye las medidas criptograficas, pero reduce exposicion operacional y encaja con un entorno aislado.
