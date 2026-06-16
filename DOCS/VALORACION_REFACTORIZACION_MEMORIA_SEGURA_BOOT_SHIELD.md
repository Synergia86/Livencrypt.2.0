# Valoracion de refactorizacion de memoria segura en Boot Shield

## 1. Objetivo

Este documento valora e integra la refactorizacion propuesta para reducir exposicion de secretos en memoria durante el desbloqueo de Livencrypt Boot Shield.

Alcance del cambio:

```text
1. sustituir frase String por SecretString
2. construir el material canonico con SecretVec<u8>
3. eliminar format! en la derivacion Argon2id
4. reducir clones de frase durante verificacion de vault
5. recuperar el runtime si el Mutex queda envenenado
```

No se han ejecutado pruebas de funcionamiento ni funciones de red para esta valoracion.

## 2. Situacion anterior

El vault ya tenia varias medidas correctas:

```text
BootMaterial limpia key y cajas con zeroize
BootShieldRuntime desmonta payload/material/header en Drop
la frase de Boot Shield se limpiaba manualmente con zeroize
el vault se abre con Argon2id + capa Livencrypt + XChaCha20-Poly1305
```

Debilidades detectadas:

```text
la frase vivia como String normal
derive_key construia material con format!
format! podia crear buffers intermedios no controlados
la verificacion interna clonaba frases
el Mutex del runtime devolvia error si quedaba poisoned
```

## 3. Cambios aplicados en codigo

Archivo principal:

```text
src-tauri/src/security/vault.rs
```

Dependencia anadida:

```toml
secrecy = "0.8"
```

### 3.1. AccessSecret con SecretString

Se reemplaza la estructura interna anterior por:

```rust
pub struct AccessSecret {
    cajas: [i64; 5],
    frase: SecretString,
}

impl Drop for AccessSecret {
    fn drop(&mut self) {
        self.cajas.zeroize();
    }
}
```

Valoracion:

```text
Mejora real:
  la frase queda envuelta por secrecy
  SecretString aplica zeroize al liberar
  el acceso explicito exige expose_secret()

Limitacion:
  la frase entra desde Tauri como String
  durante la frontera IPC/WebView puede existir copia previa
  no neutraliza malware, root, debugger ni memoria viva
```

### 3.2. Normalizacion de secreto

La normalizacion ahora convierte la frase recibida a `SecretString` y limpia el `String` original:

```rust
fn normalize_secret(cajas: [i64; 5], mut frase: String) -> Result<AccessSecret, String> {
    if frase.trim().is_empty() {
        frase.zeroize();
        return Err("La frase de Boot Shield no puede estar vacia.".into());
    }

    let normalized_frase = SecretString::new(frase.trim().to_string());
    frase.zeroize();

    Ok(AccessSecret {
        cajas,
        frase: normalized_frase,
    })
}
```

Valoracion:

```text
Correcto:
  evita conservar el String de entrada mas tiempo del necesario
  rechaza frase vacia
  mantiene cajas en memoria controlada por AccessSecret

Riesgo residual:
  trim().to_string() crea la copia final protegida
  no borra copias que WebView/Tauri hayan creado antes de Rust
```

### 3.3. Canonical secret con SecretVec

La funcion de derivacion ya no usa `format!`:

```rust
fn canonical_secret(secret: &AccessSecret) -> SecretVec<u8> {
    let mut buffer = Vec::with_capacity(128);
    buffer.extend_from_slice(b"LIVENCRYPT-ACCESS-V1|");

    for caja in &secret.cajas {
        let mut caja_str = caja.to_string();
        buffer.extend_from_slice(caja_str.as_bytes());
        buffer.push(b'|');
        caja_str.zeroize();
    }

    buffer.extend_from_slice(secret.frase.expose_secret().as_bytes());
    SecretVec::new(buffer)
}
```

Valoracion:

```text
Mejora real:
  elimina macro format! para el material completo
  reduce buffers temporales grandes con secreto completo
  el vector completo queda envuelto por SecretVec
  caja_str se limpia en cada iteracion

Limitacion:
  cada caja se convierte temporalmente a String
  Argon2id recibe una referencia expuesta mientras deriva
  SecretVec no impide lectura por proceso privilegiado
```

### 3.4. Derivacion Argon2id

Derivacion actualizada:

```rust
fn derive_key(secret: &AccessSecret, salt: &[u8], params: &KdfParams) -> Result<[u8; 32], String> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = [0u8; 32];
    let material = canonical_secret(secret);
    let result = argon.hash_password_into(material.expose_secret(), salt, &mut key);
    result.map_err(|error| format!("No se pudo derivar la clave Boot Shield: {}", error))?;
    Ok(key)
}
```

Valoracion:

```text
Correcto:
  material se libera al salir de derive_key
  SecretVec ejecuta limpieza al liberar
  key sigue siendo [u8; 32] y BootMaterial la limpia con zeroize

Pendiente recomendado:
  evitar mensajes de error demasiado especificos en rutas de login
  evaluar Argon2id con mayor memoria si el equipo aislado lo permite
```

## 4. Recuperacion de Mutex poisoned

Se anade:

```rust
fn lock_runtime() -> MutexGuard<'static, BootShieldRuntime> {
    match runtime().lock() {
        Ok(runtime) => runtime,
        Err(poisoned) => poisoned.into_inner(),
    }
}
```

Y se sustituyen los bloqueos que antes hacian:

```rust
runtime().lock().map_err(...)
```

por:

```rust
let mut runtime = lock_runtime();
```

Valoracion:

```text
Mejora:
  evita que un poisoning provoque denegacion local inmediata
  permite desmontar/montar runtime aunque un hilo anterior haya fallado
  reduce dependencia de unwrap/map_err en rutas sensibles

Riesgo:
  recuperar un Mutex poisoned no garantiza que el estado sea integro
  si el panic ocurrio durante persist_runtime puede haber estado parcial
```

Mitigacion recomendada:

```text
mantener persistencia atomica de vault
validar cabecera y contador tras recuperar
registrar evento generico de recuperacion sin secretos
si el estado en memoria no es coherente, bloquear runtime y exigir desbloqueo
```

## 5. Cambio importante: decrypt_payload por referencia

Antes, `decrypt_payload` consumia `BootSecret`. Eso obligaba a clonar frases durante:

```text
verificacion del vault en memoria
verificacion del vault escrito en disco
```

Ahora recibe:

```rust
secret: &AccessSecret
secondary_secret: Option<&AccessSecret>
```

Valoracion:

```text
Mejora real:
  elimina clones de frase
  mantiene una unica instancia controlada de AccessSecret
  permite verificar el vault dos veces sin duplicar secretos
```

## 6. Impacto en seguridad real

### 6.1. Lo que mejora

```text
menor persistencia accidental de frase en heap Rust
menos buffers intermedios con secreto completo
limpieza automatica de frase y material canonico
limpieza de cajas al liberar AccessSecret
menos riesgo de DoS local por Mutex poisoned
```

### 6.2. Lo que no soluciona

```text
no protege frente a root
no protege frente a debugger con permisos
no protege frente a malware en sesion
no borra copias internas del WebView
no borra copias internas del IPC Tauri
no evita swap si el sistema la permite
no garantiza limpieza fisica de DRAM
```

## 7. Compatibilidad y riesgo tecnico

Riesgos de compatibilidad:

```text
se anade dependencia nueva secrecy
la API exacta depende de secrecy 0.8
cargo check debe confirmar resolucion de dependencia
```

Riesgos funcionales:

```text
si SecretVec cambia API en version futura puede requerir ajuste
si se recupera Mutex poisoned con estado incoherente puede montarse estado parcial
```

Medida recomendada en siguiente iteracion:

```text
tras lock_runtime poisoned, validar invariantes:
  payload/material/header presentes juntos
  boot_template_name y boot_template presentes juntos
  header.magic y header.aead validos
si falla, desmontar runtime y devolver estado locked
```

## 8. Valoracion profesional

La refactorizacion es util y recomendable para Livencrypt porque reduce exposicion de secretos en memoria Rust y elimina duplicaciones innecesarias de la frase durante operaciones criticas.

No convierte el sistema en proteccion absoluta de memoria. Su funcion correcta es endurecimiento defensivo:

```text
mejor disciplina de secretos
menos copias accidentales
limpieza automatica mas fiable
menor superficie de DoS local
```

La medida tiene sentido dentro del modelo de amenaza de Livencrypt:

```text
equipo aislado
vault cifrado en reposo
frase no persistida
plantillas montadas solo tras desbloqueo
limpieza best-effort al cerrar
```

## 9. Prioridad de siguientes mejoras

```text
1. validar invariantes tras recuperar Mutex poisoned
2. envolver tambien buffers de plaintext de payload cuando sea viable
3. evitar mensajes tecnicos en rutas de desbloqueo expuestas a usuario
4. revisar copias frontend de frase y cajas
5. aplicar autolimpieza de campos WebView tras desbloqueo/fallo
6. confirmar cargo check en entorno controlado
```

## 10. Conclusion

Los cambios son positivos y coherentes con Boot Shield. La mejora mas importante no es solo usar `SecretString`, sino eliminar el `format!` del material completo y dejar de clonar frases para verificar el vault.

La seguridad resultante sigue dependiendo de:

```text
fortaleza de frase
parametros Argon2id
integridad del vault AEAD
ausencia de malware/root durante ejecucion
limpieza de runtime al cierre
```

Por tanto, esta refactorizacion debe considerarse una mejora de memoria y robustez, no una defensa completa frente a compromiso del sistema en caliente.
