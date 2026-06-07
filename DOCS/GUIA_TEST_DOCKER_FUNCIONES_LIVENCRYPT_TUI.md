# Guia de test Docker para funciones Livencrypt 2.0 TUI

## Objetivo

Ejecutar pruebas funcionales de Livencrypt 2.0 en un contenedor aislado para no tocar el sistema anfitrion.

El test Docker valida:

```text
plantillas: cargar, guardar, eliminar
cifrado de texto: cifrar y descifrar
cifrado de archivo: info, cifrar y descifrar
Boot Shield: crear vault, bloquear, desbloquear, settings cifrados
```

Quedan excluidos:

```text
funciones de red
nmcli
ip route
AppArmor del host
mlockall
prctl
setrlimit
namespaces/sandbox real del host
PBA/initramfs
```

## Archivos

```text
src-tui/Dockerfile.selftest
src-tui/scripts/docker-self-test.sh
```

## Comando

```bash
cd "/home/Divad/Escritorio/LIVENCRYPT 2.0/src-tui"
chmod +x scripts/docker-self-test.sh
./scripts/docker-self-test.sh
```

## Ejecucion manual equivalente

```bash
cd "/home/Divad/Escritorio/LIVENCRYPT 2.0/src-tui"
docker build -f Dockerfile.selftest -t livencrypt-core:selftest .
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=256m \
  --tmpfs /var/tmp:rw,exec,nosuid,size=64m \
  --tmpfs /home/livencrypt/.local/share:rw,exec,nosuid,size=256m \
  livencrypt-core:selftest
```

## Resultado correcto

```text
LIVENCRYPT SELF-TEST SEGURO
OK plantillas: cargar/guardar/eliminar.
OK texto: cifrar/descifrar.
OK archivo: info/cifrar/descifrar.
OK Boot Shield: crear/bloquear/desbloquear/settings.
SELF-TEST OK
```

## Interpretacion

Si Docker pasa y el binario instalado falla en el host, el problema esta en:

```text
perfil AppArmor
permisos de directorios del usuario
permisos del terminal
postinst del paquete .deb
configuracion del sistema anfitrion
```

Si Docker falla, el problema esta en el codigo funcional de Livencrypt.
