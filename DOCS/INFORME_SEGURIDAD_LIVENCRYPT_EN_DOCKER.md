# Informe de Seguridad: Ejecucion de Livencrypt 2.0 dentro de Docker

## 1. Objetivo

Analizar como cambiaria la seguridad de Livencrypt 2.0 si se ejecutase dentro de Docker, con especial atencion a:

- aislamiento frente al sistema anfitrion;
- proteccion del vault Boot Shield;
- proteccion de plantillas;
- bloqueo de red;
- copy/paste y capturas;
- malware;
- riesgos especificos de ejecutar una aplicacion grafica Tauri dentro de un contenedor;
- configuracion recomendada para endurecimiento.

Este documento no modifica codigo. Es un analisis tecnico de arquitectura.

## 2. Resumen ejecutivo

Ejecutar Livencrypt 2.0 dentro de Docker puede mejorar la compartimentacion del proceso y reducir el impacto de algunos errores de la aplicacion, pero no convierte la ejecucion en un entorno plenamente confiable.

Docker ayuda a:

- limitar acceso al sistema de archivos del host;
- aislar procesos;
- limitar red;
- ejecutar con usuario no root;
- aplicar `seccomp`, AppArmor/SELinux y capacidades reducidas;
- crear un entorno reproducible.

Docker no soluciona por si solo:

- malware en el host;
- keyloggers o capturas de pantalla del host;
- lectura de datos si se monta el directorio del usuario;
- fuerza bruta offline contra el vault copiado;
- robo de credenciales si se introducen en un entorno grafico comprometido;
- fuga por X11 si se usa el servidor grafico del host de forma insegura;
- riesgo de montar `/var/run/docker.sock`;
- riesgo de ejecutar contenedor con `--privileged`.

Dictamen:

```text
Docker puede ser util como capa de aislamiento operacional, pero no debe considerarse sustituto de Boot Shield, cifrado de disco, TPM, integridad del binario ni sistema operativo limpio.
```

## 3. Modelo de ejecucion posible

Livencrypt 2.0 es una aplicacion Tauri con interfaz grafica. Dentro de Docker hay varias formas de ejecutarla:

### 3.1. GUI directa usando X11/Wayland del host

Ejemplo conceptual:

```text
contenedor Livencrypt -> socket X11/Wayland -> escritorio del host
```

Ventaja:

- experiencia similar a una app nativa;
- menor complejidad que VNC.

Riesgo:

- X11 historicamente permite que clientes lean eventos de otros clientes si no se aisla correctamente;
- el contenedor puede necesitar acceso a sockets graficos;
- el host puede capturar teclado, pantalla y portapapeles;
- el contenedor no protege frente a malware del host.

### 3.2. GUI por VNC/noVNC dentro del contenedor

Ejemplo conceptual:

```text
contenedor -> escritorio virtual interno -> VNC/noVNC -> navegador del usuario
```

Ventaja:

- no se expone directamente el socket grafico real;
- mejor separacion de escritorio;
- se puede aislar copy/paste del escritorio host.

Riesgo:

- aumenta superficie de ataque por VNC/web;
- hay que proteger contrasena y puerto;
- si se expone por red, se crea una nueva entrada de ataque;
- sigue sin impedir capturas del host.

### 3.3. Docker + VM

Ejemplo:

```text
host -> maquina virtual Linux dedicada -> Docker -> Livencrypt
```

Ventaja:

- mejor aislamiento que Docker solo;
- el kernel queda separado del host;
- menos riesgo de escape directo al host.

Riesgo:

- mayor complejidad;
- peor integracion de archivos;
- requiere politica clara de transferencia de datos.

Dictamen:

```text
Para seguridad alta, Docker dentro de una VM dedicada es mas fuerte que Docker directamente sobre el host.
```

## 4. Impacto sobre Boot Shield y plantillas

### 4.1. Si el vault vive dentro del contenedor

Si `~/.local/share/livencrypt` queda dentro del filesystem del contenedor:

Ventajas:

- el host no ve directamente el directorio de datos salvo accediendo a capas Docker;
- al borrar el contenedor se puede eliminar el estado;
- se reduce exposicion accidental del vault en el `$HOME` del host.

Desventajas:

- si se elimina el contenedor sin backup, se pierde el vault;
- si se exporta la imagen/capa, puede viajar el vault;
- Docker no cifra por defecto las capas de imagen/volumen;
- snapshots de Docker pueden conservar datos antiguos.

### 4.2. Si el vault vive en un volumen Docker

Ejemplo:

```text
volume: livencrypt-data -> /home/livencrypt/.local/share/livencrypt
```

Ventajas:

- persistencia controlada;
- facil backup;
- separa binario y datos;
- permite borrar/recrear contenedor sin perder vault.

Desventajas:

- el volumen puede copiarse y atacarse offline;
- si el host esta comprometido, puede leer el volumen;
- no sustituye Boot Shield.

### 4.3. Si se monta un directorio del host

Ejemplo:

```text
-v $HOME/.local/share/livencrypt:/home/livencrypt/.local/share/livencrypt
```

Ventaja:

- persistencia sencilla.

Riesgo:

- Docker ya no aisla esos datos del host;
- malware del host puede leer/copiar el vault;
- errores de permisos pueden exponer archivos;
- se pierde parte del beneficio de aislamiento.

Recomendacion:

```text
Usar volumen Docker dedicado o directorio minimo dedicado, nunca montar todo $HOME.
```

## 5. Impacto frente a fuerza bruta offline

Docker no cambia el coste criptografico del vault.

Si un atacante obtiene `vault.lvcvault`, el ataque sigue siendo:

```text
frase + 5 cajas -> Argon2id -> AEAD verify
```

Por tanto:

- Docker no aumenta la entropia de la frase;
- Docker no aumenta la entropia de las cajas;
- Docker no impide fuerza bruta offline si el vault se copia;
- Docker puede dificultar encontrar el vault si no se montan rutas obvias, pero no debe considerarse una defensa criptografica.

La defensa real sigue siendo:

- frase fuerte;
- cajas no predecibles;
- `Argon2id`;
- `XChaCha20-Poly1305`;
- no dejar `.msgpack` en claro;
- opcionalmente TPM/secreto local;
- cifrado de disco del host o de la VM.

## 6. Impacto frente a malware

### 6.1. Malware dentro del contenedor

Docker puede limitar el dano si Livencrypt o una dependencia se compromete:

- limitar acceso a archivos del host;
- quitar capacidades Linux;
- bloquear syscalls con `seccomp`;
- hacer filesystem de solo lectura;
- impedir escalada con `no-new-privileges`;
- aislar red;
- ejecutar como usuario no root.

### 6.2. Malware en el host

Docker no protege de forma fuerte contra malware del host.

Si el host esta comprometido, el atacante puede:

- capturar teclado antes de entrar al contenedor;
- capturar pantalla;
- leer portapapeles;
- inspeccionar procesos Docker;
- copiar volumenes;
- modificar imagenes;
- sustituir binario;
- manipular sockets graficos;
- leer memoria si tiene privilegios suficientes;
- registrar las credenciales cuando se introducen.

Dictamen:

```text
Docker protege al host frente al contenedor mejor de lo que protege al contenedor frente al host.
```

## 7. Riesgos especificos de Docker

### 7.1. Docker daemon con privilegios root

Docker Engine tradicional usa un daemon con privilegios elevados. Quien controla Docker en el host suele poder obtener acceso muy amplio al sistema.

Riesgo critico:

```text
Montar /var/run/docker.sock dentro del contenedor equivale practicamente a dar control del host.
```

Prohibicion recomendada:

```text
No montar /var/run/docker.sock
```

### 7.2. `--privileged`

No usar:

```bash
--privileged
```

Riesgo:

- desactiva gran parte del aislamiento;
- amplia capacidades;
- expone dispositivos;
- puede permitir acciones peligrosas en el host.

### 7.3. Montajes amplios

No montar:

```text
/
/home
/var/run
/dev
/proc
/sys
```

salvo necesidad justificada y de solo lectura cuando sea posible.

### 7.4. X11

X11 es especialmente delicado para seguridad.

Riesgos:

- lectura de eventos de teclado;
- inyeccion de eventos;
- captura de ventanas;
- interaccion entre clientes graficos.

Si se usa X11, debe considerarse de menor seguridad que un escritorio virtual aislado.

### 7.5. Wayland

Wayland mejora aislamiento grafico frente a X11, pero el resultado depende del compositor, portal, permisos y configuracion.

No debe asumirse proteccion perfecta.

## 8. Configuracion Docker recomendada

### 8.1. Principios

Ejecutar con:

```text
usuario no root
rootless Docker si es viable
sin privilegios
capabilities reducidas
no-new-privileges
seccomp activo
AppArmor/SELinux activo
filesystem read-only
tmpfs para temporales
volumen dedicado para vault
red deshabilitada por defecto
sin docker.sock
sin montaje amplio del host
```

### 8.2. Ejemplo conceptual de `docker run`

Este ejemplo es orientativo. Una app Tauri GUI puede requerir ajustes especificos para WebKitGTK, GPU, Wayland/X11 o VNC.

```bash
docker run --rm \
  --name livencrypt \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
  --tmpfs /run:rw,noexec,nosuid,nodev,size=64m \
  --cap-drop=ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=default \
  --network=none \
  --mount type=volume,src=livencrypt-data,dst=/home/livencrypt/.local/share/livencrypt \
  livencrypt:2.0
```

Notas:

- `--network=none` es coherente con una herramienta criptografica offline.
- Si se necesita red para actualizaciones, debe habilitarse temporalmente o en un contenedor separado.
- `--read-only` obliga a declarar explicitamente donde puede escribir.
- `--tmpfs` evita persistencia de temporales en disco del contenedor.
- `--cap-drop=ALL` reduce superficie.

### 8.3. Si se necesita GUI

Preferencia de seguridad:

```text
1. VM dedicada + Docker + escritorio virtual interno
2. Docker + VNC/noVNC local solo en 127.0.0.1
3. Docker + Wayland controlado
4. Docker + X11 directo
```

Para VNC/noVNC:

```text
exponer solo 127.0.0.1
contrasena fuerte
sin acceso remoto por defecto
sin clipboard compartido
sin carpetas compartidas amplias
```

## 9. Red en Docker

Docker permite una medida muy clara:

```bash
--network=none
```

Ventajas:

- Livencrypt queda sin conectividad de red desde el contenedor;
- no hace falta ejecutar `nmcli networking off`;
- no corta la red del host;
- evita aislar un equipo remoto por accidente.

Esto puede sustituir parcialmente los perfiles de red peligrosos cuando Livencrypt se ejecuta dentro de Docker.

Comparacion:

| Perfil | Riesgo host | Aislamiento |
|---|---:|---:|
| `mock` | ninguno | ninguno real |
| `drop-default-route` en host | medio | corta salida del host |
| `nmcli-off` en host | alto | puede aislar equipo |
| Docker `--network=none` | bajo | corta red solo del contenedor |

Recomendacion:

```text
Si Livencrypt corre en Docker, preferir --network=none antes que manipular la red del host.
```

## 10. Copy/paste y capturas dentro de Docker

### 10.1. Copy/paste

Docker no bloquea automaticamente el portapapeles.

Depende de:

- X11/Wayland;
- VNC;
- navegador si se usa noVNC;
- configuracion del escritorio;
- integracion del host.

Recomendacion:

```text
deshabilitar clipboard compartido en VNC/noVNC
bloquear eventos copy/paste en la app
no montar portales de clipboard si no son necesarios
limpiar clipboard al bloquear/cerrar
```

### 10.2. Capturas

Docker no impide capturas de pantalla realizadas por el host.

Incluso si Tauri usa `contentProtected`, el comportamiento depende del sistema y no bloquea:

- captura externa;
- malware del host;
- captura del escritorio VNC;
- captura a nivel compositor/controlador.

Conclusion:

```text
Docker no es una solucion anticaputra. Solo permite aislar mejor el escritorio si se usa una sesion grafica virtual dedicada.
```

## 11. Borrado y persistencia en Docker

### 11.1. Capas del contenedor

No guardar datos sensibles en capas de imagen.

Riesgo:

- una imagen puede exportarse;
- una capa puede conservar archivos borrados en capas anteriores;
- `docker commit` puede congelar estado sensible.

Regla:

```text
El vault y datos de usuario deben vivir en volumen dedicado, no en la imagen.
```

### 11.2. Volumen persistente

El volumen debe tratarse como disco sensible:

- puede copiarse;
- puede incluir vault;
- puede incluir temporales si se configuran mal;
- requiere backup cifrado;
- requiere eliminacion controlada.

### 11.3. Temporales

Usar `tmpfs` para:

- `/tmp`;
- `/run`;
- caches no persistentes;
- temporales de descifrado.

Ventaja:

```text
los temporales desaparecen al parar el contenedor
```

Limitacion:

```text
no impide memoria/swap del host si el host esta configurado de forma insegura
```

## 12. Docker Rootless

Rootless Docker reduce el riesgo de que el daemon y los contenedores operen como root real del host.

Ventajas:

- menor impacto de ciertas vulnerabilidades;
- mejor separacion usuario-host;
- coherente con una aplicacion de escritorio sensible.

Limitaciones:

- no es compatible con todas las configuraciones;
- puede requerir ajustes de AppArmor/user namespaces;
- no sustituye AppArmor/seccomp;
- no protege frente a malware del mismo usuario en el host.

Recomendacion:

```text
Usar rootless Docker o Podman rootless cuando sea viable.
```

## 13. Docker Desktop vs Docker Engine en Linux

Para Linux Mint u otro Linux:

- Docker Engine nativo suele ser mas directo.
- Docker Desktop introduce una VM/control plane adicional.
- Docker Desktop tiene funciones empresariales como Enhanced Container Isolation en ciertos escenarios/licencias.

Para seguridad local de Livencrypt:

```text
Linux Engine/Podman rootless + contenedor restringido suele ser preferible a un Docker Desktop con integraciones amplias.
```

## 14. Comparacion con maquina virtual

Docker comparte kernel con el host. Una VM tiene kernel separado.

| Caracteristica | Docker | VM |
|---|---:|---:|
| Aislamiento de kernel | comparte host | separado |
| Rendimiento | alto | menor |
| Facilidad GUI | variable | buena |
| Proteccion frente a escape | menor que VM | mayor |
| Portabilidad | alta | media |
| Seguridad para datos sensibles | buena si endurecido | mejor si bien configurada |

Dictamen:

```text
Para maxima seguridad, VM dedicada cifrada + Docker dentro + red desactivada es mas fuerte que Docker solo.
```

## 15. Arquitectura recomendada para Livencrypt en Docker

### 15.1. Modo seguro local

```text
Host Linux limpio
  -> Docker/Podman rootless
  -> contenedor Livencrypt sin red
  -> volumen dedicado cifrado por Boot Shield
  -> tmpfs para temporales
  -> usuario no root
  -> seccomp/AppArmor
```

### 15.2. Modo de maxima seguridad

```text
Host
  -> VM Linux cifrada
      -> Docker/Podman rootless
          -> Livencrypt sin red
          -> escritorio virtual interno
          -> sin clipboard compartido
          -> vault en volumen dedicado
```

### 15.3. Modo no recomendado

```text
docker run --privileged
montando /home completo
montando docker.sock
usando X11 directo
con red activa
como root
sin seccomp/AppArmor
```

Este modo podria ser menos seguro que ejecutar la app nativa, porque aumenta superficie sin aislamiento real.

## 16. Impacto sobre funciones actuales de Livencrypt

### 16.1. Boot Shield

Sigue siendo necesario.

Docker no sustituye:

- `Argon2id`;
- Livencrypt interno;
- `XChaCha20-Poly1305`;
- borrado de `.msgpack`;
- doble credencial si se integra;
- vinculacion a TPM/secreto local.

### 16.2. Control de red

Dentro de Docker, deberia preferirse:

```text
--network=none
```

antes que `nmcli-off`, porque:

- no corta la red del host;
- no requiere permisos de administrador dentro de la app;
- evita dejar remoto inaccesible;
- es facil de auditar.

### 16.3. Plantillas

Las plantillas deben:

- vivir dentro del vault;
- no quedar como `.msgpack` en el volumen;
- no copiarse en capas de imagen;
- no guardarse en logs;
- no exportarse sin cifrado.

### 16.4. Actualizaciones

Si el contenedor no tiene red:

- las actualizaciones deben hacerse reconstruyendo imagen;
- verificar hash/firma de imagen;
- no actualizar desde dentro de la app.

## 17. Amenazas residuales

Incluso con Docker endurecido, siguen existiendo:

- fuerza bruta offline si se copia el vault;
- captura por host comprometido;
- keylogger del host;
- capturas fisicas externas;
- vulnerabilidades del kernel;
- vulnerabilidades de Docker/runtime;
- malas configuraciones de volumen;
- backups inseguros;
- robo de frase/cajas por ingenieria social;
- acceso cuando el vault ya esta desbloqueado.

## 18. Recomendaciones practicas

1. No montar `/var/run/docker.sock`.
2. No usar `--privileged`.
3. No montar `$HOME` completo.
4. Usar `--network=none` por defecto.
5. Usar usuario no root.
6. Usar rootless Docker o Podman rootless si es viable.
7. Usar volumen dedicado para `~/.local/share/livencrypt`.
8. Usar `tmpfs` para temporales.
9. Usar `--read-only` y declarar solo rutas necesarias de escritura.
10. Aplicar `--cap-drop=ALL`.
11. Aplicar `--security-opt no-new-privileges:true`.
12. Mantener seccomp/AppArmor/SELinux activos.
13. Evitar X11 directo si se busca seguridad alta.
14. Preferir escritorio virtual interno sin clipboard compartido.
15. Mantener Boot Shield activo aunque se use Docker.
16. Cifrar disco del host o de la VM.
17. Firmar/verificar imagen de Livencrypt.
18. No guardar vault en imagen Docker.

## 19. Dictamen final

Ejecutar Livencrypt 2.0 dentro de Docker puede ser positivo si se usa como contenedor restringido, sin red, sin privilegios, sin montajes amplios y con volumen dedicado. En ese caso, Docker anade una capa util de compartimentacion.

Pero Docker mal configurado puede empeorar la seguridad. Un contenedor con `--privileged`, acceso a Docker socket, red activa, X11 directo y `$HOME` montado no ofrece una frontera fiable para una aplicacion criptografica.

La recomendacion profesional es:

```text
Docker endurecido = capa adicional util.
Docker sin endurecer = falsa sensacion de seguridad.
Docker no sustituye Boot Shield.
VM dedicada + Docker rootless + sin red = opcion mas fuerte.
```

## 20. Referencias

- Docker Engine security:
  https://docs.docker.com/engine/security/

- Docker seccomp security profiles:
  https://docs.docker.com/engine/security/seccomp/

- Docker user namespace remap:
  https://docs.docker.com/engine/security/userns-remap/

- Docker rootless mode:
  https://docs.docker.com/engine/security/rootless/

- Docker container run reference:
  https://docs.docker.com/reference/cli/docker/container/run/

- Docker Enhanced Container Isolation:
  https://docs.docker.com/enterprise/security/hardened-desktop/enhanced-container-isolation/

- OWASP Docker Security Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
