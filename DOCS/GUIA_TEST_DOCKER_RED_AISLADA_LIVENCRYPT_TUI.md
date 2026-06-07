# Guia de test Docker de red aislada para Livencrypt 2.0 TUI

## Objetivo

Ejecutar pruebas de funciones de red de Livencrypt dentro de Docker sin modificar la red del equipo anfitrion.

Docker no es una maquina virtual completa: comparte kernel con el host. Por eso el contenedor se ejecuta con restricciones estrictas.

## Garantias del script

El script:

```text
no usa --network host
no usa --privileged
no monta directorios del host
elimina todas las capabilities
solo anade CAP_NET_ADMIN dentro del contenedor
usa root filesystem read-only
usa tmpfs aislados para datos temporales
limita procesos, memoria y CPU
```

Archivo:

```text
src-tui/scripts/docker-network-self-test.sh
```

Dockerfile:

```text
src-tui/Dockerfile.networktest
```

## Funciones probadas

```text
perfil mock
perfil drop-default-route
perfil nmcli-off mediante shim interno del contenedor
```

## Importante

`drop-default-route` modifica rutas reales, pero solo dentro del namespace de red del contenedor.

`nmcli-off` se ejecuta contra un shim interno `/usr/local/bin/nmcli`, porque un contenedor normal no ejecuta NetworkManager real. Esto permite validar que Livencrypt invoca la funcion correcta sin tocar el host.

## Guard de seguridad en el binario

El modo:

```bash
livencrypt-core --network-self-test-container-only
```

rechaza ejecutarse si:

```text
no existe LIVENCRYPT_CONTAINER_NETWORK_TEST=1
no se detecta contenedor Docker
```

## Comando

```bash
cd "/home/Divad/Escritorio/LIVENCRYPT 2.0/src-tui"
chmod +x scripts/docker-network-self-test.sh
./scripts/docker-network-self-test.sh
```

## Resultado correcto

```text
LIVENCRYPT NETWORK SELF-TEST CONTAINER-ONLY
OK red mock: no modifica rutas.
OK red drop-default-route: rutas por defecto eliminadas dentro del contenedor.
OK red drop-default-route: rutas restauradas dentro del contenedor.
OK red nmcli-off: ejecutado contra shim aislado dentro del contenedor.
NETWORK SELF-TEST CONTAINER-ONLY OK
```

## Verificacion de que no toca el host

Antes y despues del test en el host:

```bash
ip route show default
nmcli networking connectivity
```

La ruta por defecto del host no debe cambiar.

## Que no cubre

```text
NetworkManager real del host
permisos pkexec reales del host
AppArmor del host
systemd del host
PBA/initramfs
```

Para esas pruebas se recomienda una VM o equipo no critico.
