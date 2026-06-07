# Guia de integracion de acceso Livencrypt con 5 cajas + frase

## 1. Objetivo

Este documento describe como integrar Livencrypt 2.0 como sistema de acceso criptografico para una aplicacion, portal web, base de datos o modulo interno.

El objetivo no es ocultar la interfaz con una pantalla de login. El objetivo correcto es que los datos necesarios para ejecutar la aplicacion esten cifrados y solo puedan montarse en memoria cuando el usuario introduce:

```text
5 cajas numericas + frase exacta
```

Si una caja o la frase son incorrectas:

```text
no se obtiene clave valida
no se autentica el vault
no se descifra la capa Livencrypt
no se cargan plantillas
no se monta el dashboard
```

El mensaje de error debe ser siempre generico:

```text
CREDENCIALES INVALIDAS O VAULT MANIPULADO
```

## 2. Principio de seguridad

La secuencia de 5 cajas + frase no debe guardarse nunca en claro. Tampoco debe guardarse en `localStorage`, cookies, ficheros de configuracion, logs ni parametros de arranque.

La secuencia debe usarse solo para derivar una clave en memoria:

```text
material_usuario = cajas[0..4] + frase
K = Argon2id(material_usuario, salt, parametros)
```

Despues se usa `K` para abrir un vault autenticado.

Formato recomendado:

```text
payload real
  -> capa Livencrypt con plantilla seleccionada
  -> XChaCha20-Poly1305 con clave derivada por Argon2id
  -> vault.msgpack
```

La capa Livencrypt aporta la transformacion posicional propia del producto. La capa AEAD aporta confidencialidad autenticada, deteccion de manipulacion y verificacion criptografica fuerte.

## 3. Componentes minimos

Una integracion completa necesita:

```text
1. editor de plantillas
2. plantilla Boot Shield seleccionable
3. derivacion Argon2id
4. cifrado autenticado XChaCha20-Poly1305
5. capa Livencrypt interna
6. vault versionado
7. pantalla de desbloqueo
8. runtime desbloqueado en memoria
9. limpieza de memoria y cierre seguro
```

## 4. Estructura de datos

### 4.1. Plantilla Livencrypt

La plantilla define la matriz de caracteres usada por el cifrado posicional.

```rust
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TemplateData {
    pub rows: u32,
    pub cols: u32,
    pub chars: Vec<String>,
}
```

Requisitos:

```text
rows * cols == chars.len()
no debe haber caracteres vacios
no debe haber duplicados
para vault Boot Shield debe contener 0-9 y a-f
```

### 4.2. Encabezado publico del vault

El encabezado puede guardarse en claro porque no contiene secretos.

```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct VaultHeader {
    pub magic: [u8; 8],
    pub format_version: u16,
    pub kdf_algorithm: String,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub livencrypt_layer: String,
    pub template_name: String,
    pub object_names: Vec<String>,
}
```

### 4.3. Payload cifrado

El payload contiene lo que la aplicacion necesita para ejecutarse.

```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct VaultPayload {
    pub templates: std::collections::HashMap<String, TemplateData>,
    pub app_config: AppConfig,
    pub protected_objects: Vec<ProtectedObject>,
}
```

Ejemplos de `protected_objects`:

```text
plantillas
credenciales de base de datos
tokens de API
configuracion privada
rutas internas
datos iniciales de dashboard
clave de descifrado de otro modulo
```

## 5. Derivacion desde 5 cajas + frase

### 5.1. Normalizacion

Las cajas pueden introducirse con numeros localizados. Antes de derivar se deben normalizar a enteros.

```rust
pub struct AccessSecret {
    pub cajas: [i64; 5],
    pub frase: String,
}

pub fn canonical_secret(secret: &AccessSecret) -> Vec<u8> {
    format!(
        "LIVENCRYPT-ACCESS-V1|{}|{}|{}|{}|{}|{}",
        secret.cajas[0],
        secret.cajas[1],
        secret.cajas[2],
        secret.cajas[3],
        secret.cajas[4],
        secret.frase
    )
    .into_bytes()
}
```

### 5.2. Argon2id

```rust
use argon2::{Algorithm, Argon2, Params, Version};

pub fn derive_key(secret: &AccessSecret, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(
        256 * 1024,
        4,
        1,
        Some(32),
    ).map_err(|e| e.to_string())?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(&canonical_secret(secret), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}
```

Los parametros exactos deben ajustarse al equipo objetivo. En escritorio aislado se puede subir memoria y tiempo. En portal web multiusuario se debe equilibrar resistencia y disponibilidad.

## 6. Capa Livencrypt interna

La capa Livencrypt transforma el payload serializado antes del AEAD.

```rust
pub fn livencrypt_encode_payload(
    payload_bytes: &[u8],
    cajas: [i64; 5],
    template: &TemplateData,
) -> Result<Vec<u8>, String> {
    let cipher = PositionalCipher::new(template.clone());
    cipher.encrypt_bytes(payload_bytes, cajas)
}

pub fn livencrypt_decode_payload(
    encoded: &[u8],
    cajas: [i64; 5],
    template: &TemplateData,
) -> Result<Vec<u8>, String> {
    let cipher = PositionalCipher::new(template.clone());
    cipher.decrypt_bytes(encoded, cajas)
}
```

En una integracion externa, si el proyecto no expone `encrypt_bytes` y `decrypt_bytes`, se debe crear una API equivalente que aplique la misma transformacion posicional usada por Livencrypt 2.0.

## 7. Cifrado del vault

### 7.1. Crear vault

```rust
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};

pub fn create_vault(
    payload: &VaultPayload,
    secret: &AccessSecret,
    boot_template_name: &str,
    boot_template: &TemplateData,
) -> Result<VaultEnvelope, String> {
    let salt = random_bytes(32);
    let nonce = random_bytes(24);
    let key = derive_key(secret, &salt)?;

    let payload_bytes = rmp_serde::to_vec(payload)
        .map_err(|e| format!("No se pudo serializar payload: {e}"))?;

    let livencrypt_payload = livencrypt_encode_payload(
        &payload_bytes,
        secret.cajas,
        boot_template,
    )?;

    let header = VaultHeader {
        magic: *b"LVCBOOT1",
        format_version: 1,
        kdf_algorithm: "argon2id".to_string(),
        kdf_memory_kib: 256 * 1024,
        kdf_iterations: 4,
        kdf_parallelism: 1,
        salt,
        nonce,
        livencrypt_layer: "livencrypt-positional-v1".to_string(),
        template_name: boot_template_name.to_string(),
        object_names: payload.protected_object_names(),
    };

    let aad = rmp_serde::to_vec(&header)
        .map_err(|e| format!("No se pudo serializar AAD: {e}"))?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&header.nonce),
            chacha20poly1305::aead::Payload {
                msg: &livencrypt_payload,
                aad: &aad,
            },
        )
        .map_err(|_| "No se pudo cifrar vault".to_string())?;

    zeroize_key(key);
    Ok(VaultEnvelope { header, ciphertext })
}
```

### 7.2. Desbloquear vault

```rust
pub fn unlock_vault(
    envelope: &VaultEnvelope,
    secret: &AccessSecret,
    boot_template: &TemplateData,
) -> Result<VaultPayload, String> {
    if envelope.header.magic != *b"LVCBOOT1" {
        return Err("CREDENCIALES INVALIDAS O VAULT MANIPULADO".into());
    }

    let key = derive_key(secret, &envelope.header.salt)?;
    let aad = rmp_serde::to_vec(&envelope.header)
        .map_err(|_| "CREDENCIALES INVALIDAS O VAULT MANIPULADO".to_string())?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let livencrypt_payload = cipher
        .decrypt(
            XNonce::from_slice(&envelope.header.nonce),
            chacha20poly1305::aead::Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| "CREDENCIALES INVALIDAS O VAULT MANIPULADO".to_string())?;

    let payload_bytes = livencrypt_decode_payload(
        &livencrypt_payload,
        secret.cajas,
        boot_template,
    ).map_err(|_| "CREDENCIALES INVALIDAS O VAULT MANIPULADO".to_string())?;

    let payload = rmp_serde::from_slice::<VaultPayload>(&payload_bytes)
        .map_err(|_| "CREDENCIALES INVALIDAS O VAULT MANIPULADO".to_string())?;

    zeroize_key(key);
    Ok(payload)
}
```

La aplicacion solo debe montar el dashboard despues de que `unlock_vault` devuelva `Ok(payload)`.

## 8. Integracion en una aplicacion Tauri

### 8.1. Comandos Rust

```rust
#[tauri::command]
pub async fn access_enable(
    cajas: [i64; 5],
    frase: String,
    boot_template_name: String,
) -> Result<AccessStatus, String> {
    let templates = load_templates_from_editor()?;
    let boot_template = templates
        .get(&boot_template_name)
        .ok_or("Plantilla Boot Shield no encontrada")?;

    validate_template_for_scheduling(boot_template)?;

    let payload = VaultPayload {
        templates,
        app_config: load_private_config()?,
        protected_objects: load_protected_objects()?,
    };

    let secret = AccessSecret { cajas, frase };
    let envelope = create_vault(&payload, &secret, &boot_template_name, boot_template)?;
    write_atomic_vault(&envelope)?;
    purge_plaintext_templates_best_effort()?;
    clear_secret(secret);

    Ok(AccessStatus::Locked)
}

#[tauri::command]
pub async fn access_unlock(
    cajas: [i64; 5],
    frase: String,
) -> Result<AccessStatus, String> {
    let envelope = read_vault()?;
    let boot_template = resolve_boot_template_from_envelope(&envelope)?;
    let secret = AccessSecret { cajas, frase };

    let payload = unlock_vault(&envelope, &secret, &boot_template)?;
    RUNTIME.write().unwrap().mount(payload);
    clear_secret(secret);

    Ok(AccessStatus::Unlocked)
}

#[tauri::command]
pub fn access_lock() -> Result<AccessStatus, String> {
    RUNTIME.write().unwrap().zeroize_and_unmount();
    Ok(AccessStatus::Locked)
}
```

### 8.2. Frontend de desbloqueo

```tsx
function BootUnlock() {
  const [cajas, setCajas] = useState(["", "", "", "", ""]);
  const [frase, setFrase] = useState("");
  const [error, setError] = useState("");

  async function unlock() {
    try {
      setError("");
      const parsed = cajas.map(parseLocalizedInteger);
      if (parsed.length !== 5 || parsed.some((n) => n === null)) {
        setError("CREDENCIALES INVALIDAS O VAULT MANIPULADO");
        return;
      }

      await invoke("access_unlock", {
        cajas: parsed,
        frase,
      });

      setCajas(["", "", "", "", ""]);
      setFrase("");
      mountDashboard();
    } catch {
      setCajas(["", "", "", "", ""]);
      setFrase("");
      setError("CREDENCIALES INVALIDAS O VAULT MANIPULADO");
    }
  }

  return (
    <section>
      <input value={cajas[0]} onChange={...} />
      <input value={cajas[1]} onChange={...} />
      <input value={cajas[2]} onChange={...} />
      <input value={cajas[3]} onChange={...} />
      <input value={cajas[4]} onChange={...} />
      <input type="password" value={frase} onChange={(e) => setFrase(e.target.value)} />
      <button onClick={unlock}>DESBLOQUEAR</button>
      {error && <p>{error}</p>}
    </section>
  );
}
```

Reglas frontend:

```text
no guardar cajas
no guardar frase
limpiar campos tras cada intento
no indicar que caja fallo
no registrar valores introducidos
traducir numeros localizados a enteros antes de invocar Rust
```

## 9. Editor de plantillas

El editor de plantillas debe formar parte del sistema, no ser un modulo externo sin proteger.

### 9.1. Crear plantilla

```rust
#[tauri::command]
pub fn save_template(name: String, data: TemplateData) -> Result<(), String> {
    let data = normalize_template_data(data);
    validate_template_for_scheduling(&data)?;

    if let Some(runtime) = unlocked_runtime() {
        runtime.payload.templates.insert(name, data);
        persist_runtime_vault()?;
        return Ok(());
    }

    write_plain_template_msgpack(name, data)
}
```

### 9.2. Leer plantillas

```rust
#[tauri::command]
pub fn load_templates() -> Result<HashMap<String, TemplateData>, String> {
    if let Some(runtime) = unlocked_runtime() {
        return Ok(runtime.payload.templates.clone());
    }

    read_plain_templates_msgpack()
}
```

Cuando Boot Shield esta activo y desbloqueado:

```text
load_templates lee desde runtime cifrado montado
save_template actualiza el payload en memoria
persist_runtime_vault recifra el vault
no deben escribirse .msgpack en claro
```

Cuando Boot Shield no esta activo:

```text
las plantillas pueden existir como .msgpack locales
al activar Boot Shield se migran al vault
despues se purgan las .msgpack residuales
```

## 10. Integracion en portal web

Para un portal web, la secuencia no debe validarse solo en JavaScript. El navegador debe enviar las cajas y frase al backend sobre TLS, y el backend debe intentar abrir un vault del servidor o del usuario.

Flujo:

```text
1. usuario introduce 5 cajas + frase
2. frontend envia la secuencia al backend
3. backend deriva Argon2id
4. backend intenta abrir vault AEAD + Livencrypt
5. si valida, crea sesion de corta duracion
6. si falla, devuelve error generico
```

Ejemplo:

```rust
#[post("/login-livencrypt")]
async fn login_livencrypt(request: Json<LoginRequest>) -> Result<Json<LoginResponse>, Error> {
    let secret = AccessSecret {
        cajas: request.cajas,
        frase: request.frase.clone(),
    };

    let envelope = read_user_vault(request.user_id)?;
    let boot_template = read_user_boot_template(request.user_id)?;
    let payload = unlock_vault(&envelope, &secret, &boot_template)
        .map_err(|_| Error::InvalidCredentials)?;

    let session_id = create_short_session(request.user_id, payload.permissions)?;
    clear_secret(secret);

    Ok(Json(LoginResponse { session_id }))
}
```

En web, el vault puede proteger:

```text
permisos del usuario
configuracion privada
claves de acceso a base de datos
secretos de API
tokens de integracion
```

## 11. Integracion con base de datos

La base de datos no debe guardar la frase ni la clave derivada.

Modelo recomendado:

```text
tabla users
  id
  vault_header
  vault_ciphertext
  boot_template_ciphertext o referencia protegida

tabla sessions
  id
  user_id
  expires_at
  permisos ya descifrados
```

Para abrir acceso a datos:

```rust
pub fn open_database_access(user_id: UserId, secret: AccessSecret) -> Result<DbAccess, String> {
    let envelope = db_read_vault(user_id)?;
    let boot_template = db_read_boot_template(user_id)?;
    let payload = unlock_vault(&envelope, &secret, &boot_template)?;

    let db_key = payload
        .protected_objects
        .find_secret("database-key")
        .ok_or("CREDENCIALES INVALIDAS O VAULT MANIPULADO")?;

    Ok(DbAccess::new(db_key))
}
```

## 12. Doble credencial opcional

Si se requiere doble descifrado:

```text
A = 5 cajas + frase principal
B = 5 cajas + frase secundaria
```

No se debe validar A por separado y despues B. Se recomienda combinar antes de una unica verificacion:

```text
K1 = Argon2id(A, salt_a)
K2 = Argon2id(B, salt_b)
Kfinal = HKDF-SHA256(K1 || K2, contexto, salt_final)
```

Despues:

```text
payload
  -> Livencrypt con cajas B
  -> Livencrypt con cajas A
  -> XChaCha20-Poly1305(Kfinal)
```

Un solo error en A o B debe impedir abrir el AEAD. No se debe informar cual de las dos secuencias fallo.

## 13. Cierre y limpieza

Al cerrar la aplicacion:

```text
1. persistir cambios en vault cifrado
2. zeroize de claves derivadas
3. zeroize de frases y cajas
4. desmontar plantillas en memoria
5. limpiar buffers frontend
6. purgar temporales en claro
7. cerrar proceso
```

Si se usa modo destructivo:

```text
sobrescribir best-effort vault
fsync cuando sea viable
borrar vault
borrar backups
borrar plantillas residuales
cerrar proceso
```

## 14. Errores que no deben cometerse

```text
guardar frase en localStorage
guardar cajas en localStorage
usar solo una pantalla visual de bloqueo
guardar plantillas .msgpack en claro con Boot Shield activo
mostrar errores separados por caja o frase
usar hash como sustituto de cifrado autenticado
validar la secuencia en frontend como unica proteccion
registrar valores introducidos por el usuario
```

## 15. Resultado esperado

Una aplicacion integrada correctamente con Livencrypt debe comportarse asi:

```text
sin vault desbloqueado:
  no dashboard
  no plantillas
  no secretos
  no conexion a datos protegidos

con secuencia correcta:
  Argon2id deriva clave
  AEAD autentica vault
  Livencrypt revierte payload
  plantillas se montan en memoria
  dashboard se carga

con secuencia incorrecta:
  AEAD falla o payload no revierte
  no se monta nada
  se limpian campos
  se muestra error generico
```

Esta es la diferencia critica entre un login visual y un acceso cifrado real: la aplicacion no se ejecuta correctamente porque se haya pulsado un boton, sino porque los datos necesarios para ejecutarla solo existen despues de descifrar el vault.
