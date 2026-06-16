# Diseño de Arquitectura Forense: Control de Acceso mediante Auto-Cifrado (Livencrypt Boot Shield)

Este documento detalla la especificación de diseño para el módulo **"Acceso Protegido por Auto-Cifrado" (Livencrypt Boot Shield)**. Esta medida de seguridad avanzada cifra el entorno persistente del software utilizando su propio motor de cifrado para neutralizar cualquier vector de extracción forense fuera de línea (*offline*).

---

## 1. Concepto y Utilidad del Sistema de Cierre

El almacenamiento de plantillas locales (`.msgpack`) en el disco duro expone la estructura interna de los alfabetos personalizados del usuario. Si un atacante con acceso físico clona el disco duro, puede extraer estos diccionarios para intentar realizar análisis de frecuencias o ingeniería inversa sobre los textos cifrados capturados.

El módulo **Livencrypt Boot Shield** soluciona esto cifrando en disco toda la base de datos de plantillas y configuraciones utilizando el propio algoritmo de la aplicación.

### Flujo de Funcionamiento:
1. **En Reposo (Cerrado)**: Todas las plantillas y configuraciones del disco están cifradas con la secuencia de cajas y la frase de paso del usuario. No existe ninguna clave de descifrado almacenada en disco.
2. **Al Arrancar**: La aplicación muestra exclusivamente una pantalla de bloqueo con campos para la secuencia de cajas (`caja1` a `caja5`) y la Frase de Acceso.
3. **En Ejecución (Montado)**: Al introducir los valores correctos, el backend en Rust descifra las plantillas al vuelo en la **DRAM**, montando el entorno operativo sin escribir nunca los datos en texto plano en el disco.

---

## 2. Especificación de la Ventana "Configuración" ──► "Acceso"

En el encabezado del panel de control se integra un botón de **Configuración** que despliega un panel flotante con la sección **Acceso**:

### Interfaz del Panel de Acceso:
- **Selector de Activación**: Interruptor (*toggle*) para activar o desactivar la protección "Livencrypt Boot Shield".
- **Campos de Credenciales**:
  - **Secuencia de Cajas**: Cinco campos numéricos independientes para `caja1`, `caja2`, `caja3`, `caja4` y `caja5`.
  - **Frase de Acceso (Password)**: Campo de texto oculto para la contraseña maestra de derivación.
- **Acción "Habilitar Cierre"**:
  - Lee todas las plantillas locales del directorio del usuario.
  - Genera una cabecera de verificación (checksum criptográfico).
  - Cifra cada archivo `.msgpack` con los parámetros proporcionados utilizando el algoritmo de transmutación posicional.
  - Guarda una firma o marcador `boot.conf` indicando que el sistema está blindado.

---

## 3. Protocolo de Ejecución y Montaje en DRAM

Cuando la aplicación inicia con la protección habilitada, se ejecuta el siguiente protocolo pericial de seguridad:

```
                  [Inicio de Livencrypt 2.0]
                              │
                              ▼
                 ¿`boot.conf` está activo?
                 ├── NO ──► Cargar Dashboard normal
                 │
                 └── SÍ
                      ▼
        [Bloqueo: Livencrypt Boot Shield]
        Solicita: Secuencia Cajas + Frase
                              │
                              ▼
         [Cómputo en Registro de CPU (DRAM)]
      Descifra cabecera y archivos de plantilla
                              │
                              ▼
                 ¿Deserialización Correcta?
                 ├── NO ──► Credenciales Inválidas (Error)
                 │
                 └── SÍ
                      ▼
         [Montar Entorno de Trabajo en DRAM]
         Acceso concedido al panel y herramientas
```

### Medidas de Seguridad Integradas en este Protocolo:

1. **Aislamiento en DRAM**: Las plantillas descifradas y la estructura en texto plano solo existen en variables en memoria RAM dinámica del proceso mientras esté abierto.
2. **Autodestrucción en Caídas**: Si el proceso es cerrado de golpe, finalizado mediante el **Botón de Pánico** o el equipo pierde energía, los datos legibles desaparecen inmediatamente de la DRAM física, volviendo el disco a su estado 100% blindado.
3. **Resistencia a Extracción Forense**: Sin la secuencia exacta de 5 enteros y la contraseña, es matemáticamente inviable descifrar las plantillas almacenadas en disco mediante fuerza bruta debido al espacio de claves tridimensional generado por las coordenadas de las cajas y la rotación dinámica de `caja5`.

---

## 4. Guía de Configuración Inicial (Onboarding Wizard)

Para evitar incidentes operacionales críticos al ejecutar el software en sistemas con configuraciones extremas o sin acceso a teclado local (como servidores *headless* o mini PCs administrados de forma remota), Livencrypt implementa un **Asistente de Configuración Inicial** en su primera ejecución.

Este asistente obliga al usuario a definir de manera consciente qué acciones físicas debe y no debe desencadenar la aplicación al interactuar con los botones de seguridad.

### Perfiles de Acción para el Botón de Red (`🌐 RED`)

El usuario puede elegir entre tres modos de comportamiento durante la configuración inicial para ajustar el nivel de restricción a su infraestructura:

| Perfil de Red | Comando Asociado | Descripción Operativa | Riesgo Asociado |
|---|---|---|---|
| **A: Aislamiento Total** (Air-Gap) | `nmcli networking off` | Apaga globalmente todas las conexiones cableadas (Ethernet) e inalámbricas (Wi-Fi) del dispositivo. | **Crítico**: Desconecta inmediatamente las sesiones locales SSH y Remmina, dejando el equipo inaccesible sin teclado físico. |
| **B: Aislamiento de Internet** (LAN Local) | `ip route del default` | Elimina la puerta de enlace predeterminada. El tráfico hacia Internet exterior se bloquea, pero se preservan intactas las conexiones dentro de la red local. | **Bajo**: Permite mantener el control local por SSH y Remmina de forma segura mientras se cifra/descifra. |
| **C: Simulación / Desactivado** | Ninguno (Mock/Filtro) | Registra el evento de seguridad en la bitácora interna, pero no realiza ninguna llamada al sistema que altere el hardware de red. | **Nulo**: Para entornos de desarrollo o pruebas. |

### Perfiles de Acción para el Botón de Pánico (`⚠️ PÁNICO`)

| Perfil de Pánico | Acción Asociada | Descripción Operativa |
|---|---|---|
| **A: Destrucción Volátil Completa** | Sanitización y Cierre | Realiza la rutina de borrado seguro multipaso (ruido aleatorio + puesta a cero + barrido de LLVM) en DRAM y sale de inmediato (`exit(0)`). |
| **B: Congelación Temporal** | Bloqueo Estático | Aplica un filtro difuminado en la interfaz y oculta los caracteres de texto plano en memoria, solicitando de nuevo la contraseña maestra para reanudar la sesión. |
| **C: Cierre Estándar** | Terminación Directa | Finaliza el proceso de la aplicación de inmediato delegando la liberación de recursos en el sistema operativo. |

---

## 5. Directiva de Seguridad y Pruebas del Operador

> [!WARNING]
> ### PROHIBICIÓN EXPRESA DE COMPORTAMIENTO (TESTEO DE RED)
>
> **Queda estrictamente prohibido probar o ejecutar de forma activa la función de Aislamiento Total (Apagado de Red - `nmcli networking off`) en este dispositivo anfitrión (GeekomA6).**
>
> Dado que este equipo está configurado para la administración remota, la desactivación de la interfaz de red interrumpirá inmediatamente la sesión actual de SSH y la conexión por Remmina de forma irreversible, obligando a realizar una intervención física en el hardware para restaurar la conectividad. Las pruebas del botón en este entorno se deben realizar limitadas estrictamente al **Perfil C (Modo Simulación)**.
