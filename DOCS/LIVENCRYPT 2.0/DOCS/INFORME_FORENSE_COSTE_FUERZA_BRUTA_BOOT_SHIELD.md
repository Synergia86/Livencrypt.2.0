# Informe Forense Criptografico: Coste de Fuerza Bruta contra Livencrypt Boot Shield

## 1. Objetivo

Evaluar, segun el codigo actual de Livencrypt 2.0, si las plantillas quedan cifradas al activar Boot Shield y estimar el coste computacional de un ataque de fuerza bruta offline contra el vault.

Tambien se analiza el efecto de anadir un segundo descifrado basado en otra secuencia de `5 cajas + frase` para acceder al dashboard.

Este documento no modifica codigo. Es un informe tecnico-forense basado en la implementacion actual observada en:

- `src-tauri/src/security/vault.rs`
- `src-tauri/src/templates.rs`
- `src/main.tsx`

## 2. Conclusiones ejecutivas

### 2.1. Las plantillas si quedan cifradas al activar Boot Shield?

Segun el codigo actual, si `boot_shield_enable` termina correctamente, las plantillas existentes en el directorio local de plantillas se migran al vault cifrado.

Flujo real observado:

1. `boot_shield_enable` comprueba que no exista un vault previo.
2. Normaliza frase y cajas.
3. Deriva una clave con `Argon2id`.
4. Lee las plantillas `.msgpack` desde disco mediante `read_templates_from_disk`.
5. Construye un `VaultPayload` que contiene:
   - plantillas;
   - configuracion sensible;
   - perfil de red;
   - metadatos.
6. Serializa el payload.
7. Aplica una capa interna Livencrypt al payload serializado.
8. Cifra y autentica el resultado con `XChaCha20-Poly1305`.
9. Escribe `vault.lvcvault`.
10. Vuelve a leer el vault escrito y lo descifra con las mismas credenciales para verificar roundtrip.
11. Solo despues de esa verificacion elimina los `.msgpack` en claro mediante `purge_plaintext_templates_from_disk`.

Por tanto:

```text
Boot Shield activado correctamente:
  plantillas dentro de vault.lvcvault cifrado
  .msgpack locales eliminados del directorio de plantillas
```

### 2.2. Limitaciones de esa afirmacion

La afirmacion anterior solo cubre el directorio de plantillas que gestiona la aplicacion.

No cubre automaticamente:

- copias manuales de `.msgpack` realizadas por el usuario;
- backups del sistema;
- snapshots;
- copias en papelera;
- copias en otro directorio;
- volcados de memoria;
- indexadores del sistema operativo;
- copias de seguridad externas;
- imagenes antiguas del disco;
- datos que estuvieran ya filtrados antes de activar Boot Shield.

Si la activacion falla antes de borrar los `.msgpack`, el codigo conserva las plantillas en claro. Esto es preferible desde el punto de vista de disponibilidad, porque evita perder plantillas si el vault no se ha creado correctamente.

## 3. Arquitectura criptografica actual del vault

### 3.1. Parametros observados

En `KdfParams::default()`:

```text
KDF: Argon2id
memory_kib: 65_536 KiB
iterations: 3
parallelism: 1
salida: 32 bytes
```

Equivalencia:

```text
65_536 KiB = 64 MiB
3 iteraciones
1 lane/hilo de paralelismo
clave derivada = 256 bits
```

Esta configuracion esta por encima del minimo recomendado por OWASP para Argon2id y coincide en memoria/iteraciones con el perfil de 64 MiB y 3 pasadas descrito por RFC 9106 para entornos con menos memoria, aunque el RFC menciona `p=4` en ese perfil y el codigo actual usa `p=1`.

### 3.2. Material de entrada de la KDF

El material usado para derivar clave se construye asi:

```text
frase:caja1:caja2:caja3:caja4:caja5
```

Consecuencia:

- la frase y las 5 cajas forman una sola credencial combinada;
- no se puede comprobar una caja de forma aislada;
- no se puede comprobar la frase sin las cajas;
- cada intento de fuerza bruta requiere ejecutar `Argon2id` con el candidato completo.

### 3.3. Secuencia de cifrado

La secuencia efectiva es:

```text
VaultPayload
  -> MessagePack
  -> hex
  -> Livencrypt(payload_hex, cajas)
  -> XChaCha20-Poly1305(key Argon2id, nonce, AAD)
  -> vault.lvcvault
```

La secuencia de desbloqueo es:

```text
vault.lvcvault
  -> Argon2id(frase + cajas + salt)
  -> XChaCha20-Poly1305 decrypt + autenticacion
  -> Livencrypt decode con cajas
  -> hex decode
  -> MessagePack
  -> plantillas en memoria
```

### 3.4. Verificacion de intento correcto

El atacante tiene una forma clara de saber si una credencial candidata es correcta:

- si `XChaCha20-Poly1305` autentica correctamente, el candidato probablemente es correcto;
- si falla la autenticacion AEAD, la frase/cajas son incorrectas o el vault fue manipulado.

Esto es normal en vaults cifrados: el atacante no obtiene texto claro, pero puede probar candidatos offline.

## 4. Modelo de ataque forense offline

Escenario:

1. El atacante copia `vault.lvcvault`.
2. Tambien obtiene la cabecera publica del vault:
   - salt;
   - nonce;
   - parametros Argon2id;
   - nombres de objetos;
   - contador;
   - version.
3. No conoce la frase ni las cajas.
4. Ejecuta un programa propio para probar candidatos.

Por cada candidato:

```text
1. construir "frase:c1:c2:c3:c4:c5"
2. ejecutar Argon2id con 64 MiB, 3 iteraciones, p=1
3. probar XChaCha20-Poly1305 con la clave derivada
4. si AEAD falla, descartar candidato
5. si AEAD valida, aplicar Livencrypt decode y deserializar payload
```

Coste minimo por intento:

```text
Argon2id: 64 MiB * 3 pasadas ~= 192 MiB de trabajo de memoria por candidato
AEAD: coste bajo comparado con Argon2id
Livencrypt decode: normalmente solo se ejecuta si AEAD valida
```

La parte dominante del ataque es `Argon2id`.

## 5. Formula de coste

Definiciones:

```text
D_cajas = numero de posibilidades por caja
E_frase = entropia efectiva de la frase en bits
S_cajas = D_cajas^5
S_frase = 2^E_frase
S_total = S_cajas * S_frase
E_total = log2(S_total)
R = intentos por segundo del atacante
```

Tiempo esperado medio:

```text
T_medio = S_total / (2 * R)
```

Tiempo peor caso:

```text
T_peor = S_total / R
```

Trabajo minimo de memoria esperado:

```text
Memoria_medio = (S_total / 2) * 192 MiB
```

Ancho de banda minimo para una tasa de ataque:

```text
BW_minimo = R * 192 MiB/s
```

Ejemplos:

```text
R = 1 intento/s      -> ~192 MiB/s de trabajo de memoria
R = 10 intentos/s    -> ~1.875 GiB/s
R = 100 intentos/s   -> ~18.75 GiB/s
R = 1.000 intentos/s -> ~187.5 GiB/s
R = 10.000 intentos/s -> ~1.875 TiB/s
```

Estos valores son minimos teoricos simplificados. Una implementacion real tiene sobrecostes de memoria, planificacion, transferencias, paralelizacion y lectura de candidatos.

## 6. Entropia de las cajas

El codigo actual acepta `i64` como cajas en backend. En la interfaz se usan entradas numericas. Para un calculo realista hay que fijar el rango que el usuario usa en la practica.

### 6.1. Cajas de 0 a 9

```text
D_cajas = 10
S_cajas = 10^5 = 100.000
E_cajas ~= 16.61 bits
```

Esto es debil si la frase tambien es debil.

### 6.2. Cajas de 0 a 999

```text
D_cajas = 1.000
S_cajas = 1.000^5 = 10^15
E_cajas ~= 49.83 bits
```

Esto ya aporta una resistencia considerable si el atacante no conoce patrones de uso.

### 6.3. Cajas predecibles

Si el usuario usa valores como:

```text
1,1,1,1,1
0,0,0,0,0
1,2,3,4,5
5,7,2,3,0
```

la entropia real de las cajas puede caer casi a cero, porque el atacante probaria primero listas pequenas de patrones probables.

La seguridad no depende del rango teorico, sino de la entropia efectiva.

## 7. Estimaciones de fuerza bruta del diseno actual

Las siguientes tablas son estimaciones forenses. No sustituyen un benchmark real sobre el hardware atacante, pero muestran el orden de magnitud.

Hipotesis comunes:

```text
KDF: Argon2id
memoria: 64 MiB
iteraciones: 3
coste minimo por candidato: ~192 MiB de trabajo de memoria
tiempo mostrado: tiempo medio esperado = mitad del espacio
```

### 7.1. Caso A: cajas 0-9 + frase de 6 digitos

```text
Cajas: 10^5 posibilidades
Frase: 10^6 posibilidades
Espacio total: 10^11
Entropia: ~36.5 bits
```

| Ritmo de ataque | Tiempo medio estimado |
|---:|---:|
| 1 intento/s | ~1.58e3 anos |
| 10 intentos/s | ~158 anos |
| 100 intentos/s | ~15.8 anos |
| 1.000 intentos/s | ~1.58 anos |

Lectura:

- Si las cajas son de un digito y la frase es un PIN numerico de 6 digitos, el sistema no es suficiente contra un adversario serio con ataque offline.
- La proteccion depende demasiado de que el atacante no alcance ritmos altos o no conozca el patron.

### 7.2. Caso B: cajas 0-999 + frase de 6 digitos

```text
Cajas: 10^15 posibilidades
Frase: 10^6 posibilidades
Espacio total: 10^21
Entropia: ~69.8 bits
```

| Ritmo de ataque | Tiempo medio estimado |
|---:|---:|
| 1 intento/s | ~1.58e13 anos |
| 10 intentos/s | ~1.58e12 anos |
| 100 intentos/s | ~1.58e11 anos |
| 1.000 intentos/s | ~1.58e10 anos |

Lectura:

- Incluso con una frase numerica pobre, si las cajas tienen realmente 1.000 posibilidades cada una y no son predecibles, el coste se vuelve astronomico.
- El riesgo practico aqui es que los usuarios no elijan cajas aleatorias uniformes.

### 7.3. Caso C: cajas 0-999 + frase de 4 palabras aleatorias tipo Diceware

```text
Cajas: 10^15 posibilidades
Frase: 7.776^4 posibilidades
Entropia frase: ~51.7 bits
Entropia total: ~101.5 bits
```

| Ritmo de ataque | Tiempo medio estimado |
|---:|---:|
| 1 intento/s | ~5.79e22 anos |
| 10 intentos/s | ~5.79e21 anos |
| 100 intentos/s | ~5.79e20 anos |
| 1.000 intentos/s | ~5.79e19 anos |

Lectura:

- Este nivel es forensemente robusto frente a fuerza bruta offline si las palabras se eligieron de forma aleatoria real.
- No aplica si la frase son palabras personales, fechas, nombres o una frase comun.

### 7.4. Caso D: cajas 0-999 + frase de 5 palabras aleatorias tipo Diceware

```text
Entropia frase: ~64.6 bits
Entropia total: ~114.5 bits
```

| Ritmo de ataque | Tiempo medio estimado |
|---:|---:|
| 1 intento/s | ~4.50e26 anos |
| 10 intentos/s | ~4.50e25 anos |
| 100 intentos/s | ~4.50e24 anos |
| 1.000 intentos/s | ~4.50e23 anos |

Lectura:

- Este escenario esta muy por encima de lo explotable por fuerza bruta convencional.
- La amenaza real se desplaza a malware, captura de credenciales, copia de memoria, error de implementacion o mala gestion de backups.

### 7.5. Caso E: cajas 0-999 + 16 caracteres aleatorios base 94

```text
Entropia frase: ~104.9 bits
Entropia total: ~154.7 bits
```

| Ritmo de ataque | Tiempo medio estimado |
|---:|---:|
| 1 intento/s | ~5.89e38 anos |
| 10 intentos/s | ~5.89e37 anos |
| 100 intentos/s | ~5.89e36 anos |
| 1.000 intentos/s | ~5.89e35 anos |

Lectura:

- La fuerza bruta deja de ser el vector razonable.
- El atacante buscaria atajos: keylogger, memoria viva, robo de frase, sustitucion de binario, captura de pantalla, manipulacion de interfaz o acceso cuando el vault este abierto.

## 8. Coste economico estimado

No se debe dar una cifra unica en euros sin benchmark real, porque el coste depende de:

- hardware exacto;
- implementacion de Argon2id;
- paralelismo;
- energia;
- refrigeracion;
- alquiler cloud;
- coste de desarrollo del cracker;
- calidad del diccionario;
- si el atacante ya conoce parte de la frase o cajas.

Formula:

```text
Coste = horas_de_ataque * coste_por_hora_del_cluster
```

Ejemplo ilustrativo con `R = 1.000 intentos/s` y cluster hipotetico de `10 EUR/h`:

| Caso | Tiempo medio | Coste aproximado |
|---|---:|---:|
| Cajas 0-9 + frase 6 digitos | ~1.58 anos | ~138.000 EUR |
| Cajas 0-999 + frase 6 digitos | ~1.58e10 anos | ~1.38e15 EUR |
| Cajas 0-999 + 4 palabras aleatorias | ~5.79e19 anos | ~5.07e24 EUR |
| Cajas 0-999 + 5 palabras aleatorias | ~4.50e23 anos | ~3.94e28 EUR |

Advertencia:

- El primer caso podria ser reducible si el atacante conoce patrones de cajas o de frase.
- El coste real puede bajar mucho con diccionarios inteligentes si la frase es humana y predecible.
- El coste real puede subir mucho si las credenciales son aleatorias y no hay patrones.

## 9. Ataques mas probables que la fuerza bruta

Si el usuario usa frase fuerte y cajas no predecibles, la fuerza bruta no es el camino principal.

Vectores mas realistas:

- capturar la frase con malware;
- leer memoria durante la sesion desbloqueada;
- modificar el binario para registrar cajas/frase;
- capturar teclado o portapapeles;
- obtener plantillas antes de activar Boot Shield;
- explotar backups o snapshots;
- engañar al usuario para introducir credenciales en una version manipulada;
- acceder al equipo ya desbloqueado.

Conclusion forense:

> Con credenciales fuertes, el coste de fuerza bruta supera el coste de comprometer el entorno de ejecucion. La defensa debe centrarse tambien en integridad del binario, memoria, backups y sistema operativo.

## 10. Analisis de un segundo descifrado para acceder al dashboard

Se analiza la propuesta:

```text
Primera secuencia: 5 cajas + frase
Segunda secuencia: 5 cajas + frase
```

El impacto depende completamente de como se integre.

## 11. Escenario 1: segunda pantalla visual despues de desbloquear

Flujo:

```text
Vault se descifra con credencial A
Dashboard queda bloqueado por una segunda pantalla con credencial B
```

Evaluacion:

- No aumenta la proteccion del vault frente a fuerza bruta offline.
- Si las plantillas ya estan en memoria despues de la credencial A, un atacante con control local puede parchear o saltar la segunda pantalla.
- Si la segunda validacion no descifra material imprescindible, es un control de interfaz.

Conclusion:

```text
Seguridad criptografica adicional: practicamente nula.
Valor: solo control operacional/UI.
```

No recomendado como defensa forense.

## 12. Escenario 2: segunda capa cifrada independiente y verificable

Flujo:

```text
Vault exterior:
  Argon2id(frase A + cajas A)
  XChaCha20-Poly1305

Vault interior:
  Argon2id(frase B + cajas B)
  XChaCha20-Poly1305
```

El atacante puede atacar por fases:

1. Probar candidatos de A hasta abrir el vault exterior.
2. Una vez abierto, probar candidatos de B contra el vault interior.

Si cada capa tiene su propia autenticacion AEAD, cada capa ofrece un oraculo de verificacion independiente.

Coste esperado:

```text
T_total ~= S_A / (2R) + S_B / (2R)
```

Si A y B tienen la misma fuerza:

```text
T_total ~= 2 * T_una_capa
```

Eso equivale aproximadamente a sumar solo 1 bit de resistencia efectiva, no a duplicar la entropia.

Ejemplo:

```text
Una capa de 69.8 bits:
  tiempo medio a 1.000 intentos/s ~= 1.58e10 anos

Dos capas independientes verificables de 69.8 bits:
  tiempo medio ~= 3.16e10 anos
  mejora: x2
  mejora en bits: +1 bit
```

Conclusion:

```text
Util si se busca defensa en profundidad.
No multiplica el espacio de busqueda si cada capa se puede verificar por separado.
```

## 13. Escenario 3: credenciales combinadas en una unica derivacion

Flujo:

```text
Credencial A = frase A + cajas A
Credencial B = frase B + cajas B

clave = KDF(credencial A || credencial B || salt)
vault = AEAD(clave)
```

En este caso no hay una verificacion intermedia de A o B por separado.

El atacante tiene que probar pares:

```text
S_total = S_A * S_B
E_total = E_A + E_B
```

Si cada credencial tiene 69.8 bits:

```text
E_total ~= 139.6 bits
```

Tiempo medio a 1.000 intentos/s:

```text
~1.58e31 anos
```

Este si multiplica el espacio de busqueda.

Problemas:

- Muy mala usabilidad.
- Mayor riesgo de perdida permanente.
- Si una de las dos frases es debil, aporta poco.
- No protege contra malware que capture ambas durante el desbloqueo.
- No resuelve ataques de memoria viva.

## 14. Calculo comparativo de segunda credencial

### 14.1. Segunda capa verificable por separado

Supongamos dos credenciales iguales.

| Caso por credencial | Entropia por capa | Una capa a 1.000/s | Dos capas verificables |
|---|---:|---:|---:|
| cajas 0-9 + frase 6 digitos | 36.5 bits | ~1.58 anos | ~3.16 anos |
| cajas 0-999 + frase 6 digitos | 69.8 bits | ~1.58e10 anos | ~3.16e10 anos |
| cajas 0-999 + 4 palabras | 101.5 bits | ~5.79e19 anos | ~1.16e20 anos |
| cajas 0-999 + 5 palabras | 114.5 bits | ~4.50e23 anos | ~9.00e23 anos |

Conclusion:

```text
La mejora es lineal: aproximadamente x2 si ambas capas tienen fuerza equivalente.
```

### 14.2. Dos credenciales combinadas en una sola KDF

Supongamos dos credenciales independientes con igual entropia.

| Caso por credencial | Entropia combinada | Tiempo medio a 1.000/s |
|---|---:|---:|
| cajas 0-9 + frase 6 digitos | ~73.1 bits | ~1.58e11 anos |
| cajas 0-999 + frase 6 digitos | ~139.5 bits | ~1.58e31 anos |
| cajas 0-999 + 4 palabras | ~203.1 bits | ~2.12e50 anos |
| cajas 0-999 + 5 palabras | ~228.9 bits | ~1.28e58 anos |

Conclusion:

```text
La mejora es exponencial solo si no existe verificacion intermedia y el atacante debe probar combinaciones A+B.
```

## 15. Evaluacion profesional

### 15.1. Estado actual

El diseno actual es razonable frente a copia offline si se cumplen estas condiciones:

- frase no trivial;
- cajas no predecibles;
- plantillas migradas y `.msgpack` eliminados;
- no existen backups en claro;
- no hay malware ni acceso en vivo;
- el usuario no introduce credenciales en una version manipulada.

La pieza mas importante es `Argon2id`, no Livencrypt por si solo. Livencrypt aporta identidad del producto y mezcla dependiente de cajas, pero la resistencia forense frente a fuerza bruta la proporciona principalmente:

- entropia de frase+cajas;
- coste memoria/tiempo de Argon2id;
- autenticacion AEAD.

### 15.2. Riesgo principal

El riesgo principal no es que `XChaCha20-Poly1305` sea roto por criptoanalisis. El riesgo real es:

- frase debil;
- cajas predecibles;
- copia de plantillas antes de activar Boot Shield;
- copia de seguridad en claro;
- malware;
- binario alterado;
- recuperacion forense de memoria;
- errores de implementacion.

### 15.3. Sobre la frase "todas las medidas acaban siendo inutiles"

Forensemente, la afirmacion es demasiado absoluta.

Lo correcto es:

```text
Las medidas criptograficas son inutiles si el atacante obtiene la credencial o actua durante la sesion desbloqueada.
Pero son muy eficaces contra copia offline del vault si las credenciales tienen entropia alta y la KDF esta bien parametrizada.
```

La seguridad no es binaria. Cada control desplaza el coste del atacante.

## 16. Recomendaciones

### 16.1. Recomendaciones de uso inmediato

- Usar cajas no triviales y no secuenciales.
- Evitar cajas de un solo digito si se busca resistencia forense.
- Usar una frase aleatoria larga:
  - minimo recomendado: 4 palabras aleatorias reales;
  - preferible: 5 o mas palabras aleatorias;
  - alternativa: 16+ caracteres aleatorios.
- No usar datos personales.
- No usar frases famosas.
- No usar fechas.
- No guardar capturas ni notas con las cajas.
- Verificar que no quedan `.msgpack` en claro tras activar Boot Shield.
- Hacer backup cifrado si se decide vincular a equipo.

### 16.2. Recomendaciones de diseno

1. Mantener `Argon2id + Livencrypt + XChaCha20-Poly1305`.
2. Anadir benchmark de calibracion para ajustar Argon2id al equipo.
3. Considerar aumentar memoria si el equipo objetivo lo permite.
4. Anadir modo avanzado con secreto local o TPM.
5. Evitar una segunda pantalla puramente visual.
6. Si se quiere segundo factor criptografico real, combinar ambas credenciales antes de una unica verificacion AEAD.
7. Implementar comprobacion de no existencia de `.msgpack` en claro tras activar Boot Shield.
8. Documentar que backups/snapshots pueden conservar plantillas antiguas.

### 16.3. Recomendacion sobre doble descifrado

La mejor opcion no es:

```text
abrir vault A -> mostrar segunda pantalla -> abrir dashboard
```

La opcion criptograficamente fuerte seria:

```text
clave = KDF(frase A + cajas A + frase B + cajas B + salt)
AEAD decrypt del vault con clave final
```

O bien:

```text
K1 = Argon2id(frase A + cajas A + salt A)
K2 = Argon2id(frase B + cajas B + salt B)
clave_final = HKDF(K1 || K2 || contexto)
AEAD decrypt del vault con clave_final
```

Con esta forma, el atacante no puede validar A y B por separado. Debe acertar la combinacion.

## 17. Dictamen final

1. Segun el codigo actual, Boot Shield si cifra las plantillas gestionadas por Livencrypt cuando la activacion finaliza correctamente.
2. El vault actual permite ataques offline si se copia el archivo, como cualquier vault local basado en frase.
3. La fuerza bruta es inviable si la frase y cajas tienen entropia suficiente.
4. La fuerza bruta puede ser viable si el usuario usa cajas obvias y frase debil.
5. Un segundo descifrado solo aporta seguridad fuerte si se integra criptograficamente, no como pantalla adicional.
6. Dos capas verificables por separado duplican el tiempo, pero no duplican la entropia efectiva.
7. Dos credenciales combinadas antes de una unica verificacion si suman entropia y pueden elevar el coste de forma exponencial.
8. Las defensas mas importantes despues de esto son proteccion contra malware, integridad del binario, control de backups y posible vinculacion a TPM/secreto local.

## 18. Referencias

- RFC 9106, Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications:
  https://www.rfc-editor.org/rfc/rfc9106

- OWASP Password Storage Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

- OWASP Cryptographic Storage Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

- OWASP Key Management Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
