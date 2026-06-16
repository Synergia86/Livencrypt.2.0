# Informe Pericial de Seguridad: Persistencia y Sanitización de Datos en Memoria (RAM/DRAM) y Disco

Este documento constituye un análisis forense de seguridad sobre la gestión de memoria y el almacenamiento de datos durante la ejecución de las funciones de cifrado y descifrado de texto y archivos en la aplicación **Livencrypt 2.0**. Además, detalla un esquema de contramedidas avanzadas para mitigar la fuga de información mediante ofuscación y borrado seguro multipaso.

---

## 1. Análisis de Almacenamiento y Persistencia de la Secuencia de Cajas

Durante la ejecución del cifrado o descifrado posicional (tanto de texto como de archivos), el sistema procesa dos elementos clave: la **plantilla de caracteres** (la matriz física de transposición) y las **claves de desplazamiento** (las variables numéricas llamadas `caja1` a `caja5`).

### A. Almacenamiento en Memoria Volátil (RAM / DRAM)
- **Estructuras activas**: En el momento en que se invoca `PositionalCipher::cifrar` o `PositionalCipher::descifrar`, la estructura `PositionalCipher` (que contiene la cuadrícula en `Vec<Vec<char>>` y la plantilla en `TemplateData`), el texto plano y las claves `caja1..caja5` se almacenan en la memoria dinámica (**DRAM**) asignada al proceso de la aplicación.
- **Riesgo asociado**: Estos datos residen en la pila (*stack*) y en el montón (*heap*) del proceso en formato binario legible. Cualquier atacante con privilegios suficientes en el sistema operativo puede realizar un volcado de memoria física o inspeccionar la memoria del proceso (por ejemplo, leyendo `/proc/self/mem` o adjuntando un depurador como `gdb`).

### B. Almacenamiento en Disco (Persistencia Física)
Las claves de las cajas y el texto plano en sí **no** se graban directamente en disco por diseño del algoritmo criptográfico. Sin embargo, existen tres vectores críticos de fuga indirecta hacia el almacenamiento físico (SSD/HDD):

1. **Memoria de Intercambio (Swap Space)**:
   Si el sistema operativo Linux experimenta una alta demanda de memoria, el gestor de memoria virtual del núcleo (*kernel*) puede mover páginas de memoria física del proceso de Livencrypt hacia la partición o archivo de intercambio (*swap*) en el disco duro. Esto almacena de manera persistente en el disco las variables del texto plano, la cuadrícula de caracteres y las claves numéricas.
2. **Volcados de Núcleo (Core Dumps)**:
   Si la aplicación sufre una caída inesperada (*crash*) debido a un fallo crítico, el sistema operativo genera por defecto un archivo de volcado de memoria en el disco (`core.*`). Este archivo contiene una copia exacta de la DRAM asignada al proceso al momento del fallo, exponiendo la clave de las cajas y los datos tratados.
3. **Archivos Temporales**:
   En el cifrado de archivos de gran tamaño, la segmentación y procesamiento por bloques requiere en ocasiones el uso de archivos temporales en disco. Si estos archivos temporales no se destruyen mediante algoritmos de trituración física (*shredding*), los metadatos y sectores de datos permanecen en los bloques libres del sistema de archivos.

---

## 2. Medidas de Seguridad Proponibles para la Ofuscación en RAM/DRAM

Para evitar que herramientas de análisis forense extraigan las claves y secuencias en texto plano directamente de la DRAM del proceso activo, se pueden integrar las siguientes medidas de ofuscación:

### A. Ofuscación por Enmascaramiento Dinámico (XOR Masking)
En lugar de almacenar las claves `caja1` a `caja5` como enteros planos (`i64`) en memoria, se debe implementar un mecanismo de enmascaramiento:
- Al arrancar la aplicación, se genera una clave de máscara criptográfica aleatoria de un solo uso (*ephemeral mask*).
- Las claves se guardan en memoria combinadas mediante una operación XOR con la máscara:
  $$\text{caja\_enmascarada} = \text{caja\_real} \oplus \text{mascara}$$
- La clave real solo se recupera aplicando la operación inversa en los registros de la CPU durante la fracción de milisegundo en la que se ejecuta el cálculo de coordenadas, y el registro se limpia inmediatamente después.

### B. Cifrado Interno del Heap (ChaCha20 Ephemeral Storage)
Para la cuadrícula de caracteres (`Vec<Vec<char>>`) de la plantilla, que es masiva y estructurada, se puede emplear un almacenamiento cifrado en memoria:
- La plantilla se almacena en el *heap* cifrada con un algoritmo de cifrado de flujo simétrico ultrarrápido (como ChaCha20).
- La clave simétrica de descifrado es efímera, reside estrictamente en registros de CPU y se rota periódicamente.
- Las filas de la cuadrícula solo se descifran bajo demanda bloque por bloque y se eliminan inmediatamente tras su uso.

---

## 3. Llenado con Datos Aleatorios y Sanitización de la DRAM (Borrado Multipaso)

El simple hecho de liberar la memoria (mediante `drop` en Rust o `free` en C) no destruye los datos físicos en los chips de DRAM. Debido al fenómeno de **remanencia de datos**, las cargas eléctricas de los condensadores de la memoria DRAM tardan desde varios segundos hasta minutos en disiparse (y pueden persistir indefinidamente si la placa es enfriada, permitiendo un *Cold Boot Attack*).

Para neutralizar este riesgo, se propone un protocolo de sanitización activa en la DRAM de **cuatro fases (Borrado Seguro Multipaso)**, implementado inmediatamente después de finalizar cada operación de cifrado o descifrado.

### Flujo del Protocolo de Sanitización Activa en DRAM

```
[Fin de Cifrado/Descifrado]
           │
           ▼
┌──────────────────────────────────────┐
│  Paso 1: Sobrescritura con Ruido     │ ──► Llena el buffer con bytes aleatorios de alta entropía.
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│  Paso 2: Puesta a Cero (Zeroing)     │ ──► Sobrescribe con bytes de valor 0x00.
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│  Paso 3: Ciclo Complementario        │ ──► Sobrescribe con el complemento de bits del primer ruido.
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│  Paso 4: Sanitización Final y Liberar │ ──► Segundo llenado a 0x00 aplicando barreras de compilador.
└──────────────────────────────────────┘
```

### Detalle Técnico de los Pasos:

1. **Paso 1: Sobrescritura con Ruido Criptográfico**:
   Antes de liberar los vectores de texto plano, texto cifrado y coordenadas, el bloque de memoria física se sobrescribe por completo con bytes generados de manera pseudoaleatoria criptográficamente segura (PRNG). Esto fuerza la alternancia caótica de los condensadores de la DRAM, destruyendo la firma eléctrica del dato original.
2. **Paso 2: Puesta a Cero (Zeroing)**:
   Se realiza un barrido completo del buffer sobrescribiendo cada posición de memoria con el byte neutro `0x00`.
3. **Paso 3: Ciclo de Llenado Complementario**:
   Se genera un nuevo ciclo de ruido aleatorio de alta entropía diferente al primero o, en su defecto, se escribe el complemento a nivel de bits de la primera secuencia de ruido, garantizando la inversión del estado físico de cada celda de memoria.
4. **Paso 4: Limpieza Final y Liberación de Memoria**:
   Se vuelve a realizar una escritura masiva de bytes `0x00` en todo el bloque y se procede a desasignar la memoria a nivel de sistema operativo.

---

## 4. Aseguramiento contra la Optimización del Compilador

> [!CAUTION]
> Los compiladores modernos (como LLVM utilizado por `rustc` en modo de optimización `--release`) detectan las escrituras de limpieza en buffers que están a punto de ser liberados como **código muerto** (*dead store elimination*) y las eliminan por completo del binario final. Como resultado, el código de limpieza nunca se ejecuta en producción.

Para garantizar que el protocolo de borrado seguro multipaso no sea optimizado ni eliminado por el compilador, se deben implementar las siguientes técnicas en Rust:

### A. Escrituras Volátiles (`write_volatile`)
Utilizar la función de la biblioteca estándar `std::ptr::write_volatile`. Esto indica formalmente al compilador que la operación de escritura tiene efectos secundarios en el hardware y no debe ser eliminada bajo ninguna circunstancia.

### B. Uso de Barreras de Memoria (`black_box`)
Utilizar `std::hint::black_box` para obligar al optimizador a tratar el puntero de memoria como una entrada/salida opaca, impidiendo que deduzca que la asignación es redundante.

### C. Implementación del Trait `Drop` con la Crate `Zeroize`
La forma recomendada e industrial en la comunidad de Rust para asegurar la destrucción de datos sensibles es implementar el *crate* auditado `zeroize`. Este realiza escrituras seguras a nivel de ensamblador.

#### Ejemplo de Código Rust Recomendado para Integrar en `PositionalCipher`:

```rust
use zeroize::Zeroize;

// Definición de estructura con borrado automático al salir de ámbito
#[derive(Zeroize)]
#[zeroize(drop)] // Fuerza el borrado seguro automático al invocar drop()
pub struct SensitiveBuffer {
    pub plaintext: String,
    pub keys: Vec<i64>,
}

// Ejemplo de rutina de sanitización manual multipaso
pub fn secure_scrub_memory(buffer: &mut [u8]) {
    use rand::{RngCore, thread_rng};

    let len = buffer.len();

    // Paso 1: Escritura de datos aleatorios
    thread_rng().fill_bytes(buffer);
    std::hint::black_box(&buffer);

    // Paso 2: Puesta a cero
    buffer.fill(0);
    std::hint::black_box(&buffer);

    // Paso 3: Segundo ciclo de datos aleatorios
    thread_rng().fill_bytes(buffer);
    std::hint::black_box(&buffer);

    // Paso 4: Puesta a cero final volatile
    for byte_ptr in buffer.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte_ptr, 0x00);
        }
    }
}
```

---

## 5. Medidas de Endurecimiento a Nivel de Sistema Operativo

Adicionalmente al código de la aplicación, el entorno de ejecución de Livencrypt debe endurecerse mediante llamadas al sistema del kernel de Linux:

1. **Evitar la Paginación a Swap con `mlock`**:
   Invocar la llamada del sistema `mlock` (o `mlockall` de POSIX) sobre los segmentos de memoria donde residen las claves y el transmutador. Esto prohíbe explícitamente al sistema operativo paginar esa memoria a disco duro, garantizando que permanezca estrictamente en la DRAM física.
2. **Desactivar Volcados de Núcleo (Core Dumps)**:
   Configurar el límite de recursos en el arranque de la ventana principal Tauri para deshabilitar la generación de volcados de memoria en caso de colisión del proceso:
   ```rust
   // En main.rs / lib.rs nativo de Tauri
   unsafe {
       libc::setrlimit(
           libc::RLIMIT_CORE,
           &libc::rlimit {
               rlim_cur: 0,
               rlim_max: 0,
           },
       );
   }
   ```
3. **Uso de Sistemas de Archivos en Memoria para Temporales**:
   Si la aplicación de cifrado de archivos genera buffers temporales en disco, estos deben guardarse exclusivamente en carpetas montadas como `tmpfs` (por ejemplo, `/dev/shm` o carpetas en memoria RAM administradas por Linux), evitando cualquier tipo de desgaste físico u opción de recuperación forense en el almacenamiento flash o magnético del dispositivo.
