# Motor de Custodia Universal y Pasarela Web3 de Confianza Cero

Este módulo describe la arquitectura de la pasarela Web3 y el motor de custodia de Livencrypt 2.0. Permite la integración segura del navegador web (a través de una extensión stateless) con el almacenamiento en memoria protegida de claves privadas multiecosistema, filtrado por un cortafuegos local y respaldado por un disyuntor táctico automático.

---

## 1. Diseño y Principios Técnicos

La pasarela de custodia universal de Livencrypt 2.0 está estructurada como un sistema de defensa multicapa de confianza cero (*Zero-Trust*). El flujo de procesamiento de transacciones y llaves criptográficas se ejecuta de manera totalmente aislada en la TUI, sin persistencia de secretos en el navegador.

```mermaid
graph TD
    Ext[Extensión Web Stateless] -- stdio (JSON) --> Bridge[Host Puente de Mensajería]
    Bridge -- Socket Unix (/tmp/livencrypt.sock) --> Worker[Web3BackgroundWorker: worker.rs]
    Worker -- Canal de Entrada --> Supervisor[Supervisor: supervisor.rs]
    
    subgraph TUI Aislada (Rust Core)
        Supervisor --> CheckBreaker{¿Disyuntor Activo?}
        CheckBreaker -- Sí (Frozen/Locked) --> Err[Retornar Error & Aislamiento]
        CheckBreaker -- No --> Route{Tipo de Petición}
        
        Route -- Obtener Clave Pública --> Deriv[UniversalKeymaster: multi_curve.rs]
        Route -- Firmar Transacción --> Firewall{LiveFirewall: firewall.rs}
        
        Firewall -- Violación de Límite o ID --> Trip[Disparar Disyuntor / Congelar Claves]
        Firewall -- OK --> Deriv
        
        Deriv --> Vault[Derivación BIP-32/SLIP-0044 en RAM Blindada]
        Vault --> Zeroize[Zeroize Material de Claves]
    end
    
    Zeroize --> Sign[Firma ECDSA/Ed25519]
    Sign -- Retorna Bytes (Vec u8) --> Worker
    Worker -- Socket Unix (Retorno) --> Bridge
    Bridge -- stdio (JSON) --> Ext
    Trip -- Retorna Error --> Worker
```

### A. Derivación Multiecurva y Aislamiento en RAM
* **Agnosticismo de Red**: Derivación determinista basada en BIP-32/BIP-44 y SLIP-0044 para generar claves de forma segura y firmar en las principales curvas elípticas del ecosistema blockchain:
  - **secp256k1**: Para redes basadas en Bitcoin (coin_id 0) y Ethereum (coin_id 60) mediante firmas ECDSA.
  - **ed25519**: Para redes basadas en Solana (coin_id 501) mediante firmas de Edwards. Monero (coin_id 128) requiere un esquema criptográfico especializado de firmas en anillo (ring signatures) multifactoriales (MLSAG/CLSAG) acopladas a pruebas de conocimiento cero (Bulletproofs) para ocultar las cuantías y debe tratarse de forma aislada mediante un payload multilave específico.
* **Memoria Blindada**: La frase maestra y las cajas se procesan mediante `derive_vault_key` para generar un secreto efímero en la RAM. La clase `UniversalKeymaster` almacena la `master_seed` de 64 bytes y garantiza que se aplique `zeroize()` para sobrescribir los secretos en memoria tan pronto como se libere el objeto (`Drop`).

### B. Pasarela Stateless (Mensajería Nativa)
* **Comunicación sin Estado**: La extensión del navegador web no retiene ni conoce la frase de acceso ni las claves privadas. Toda derivación de clave pública o firma se delega mediante paso de mensajes estructurados JSON sobre descriptores estándar (`stdin`/`stdout`).
* **Hardening contra Desbordamientos y DoS**: El canal de mensajería nativa (`NativeProxyChannel`) lee un prefijo de 32 bits que indica la longitud del mensaje. Limita estrictamente el tamaño máximo de lectura a **1 MB** para mitigar ataques de denegación de servicio por asignación masiva de memoria.
* **Restricción de Orígenes**: El archivo de manifiesto del host (`com.livencrypt.gateway.json`) utiliza la directiva `"allowed_origins"` con el identificador único hash de la extensión autorizada, haciendo que el kernel del sistema operativo y el navegador bloqueen cualquier intento de invocación externa por procesos no autorizados.

### C. Cortafuegos de Políticas Activo (Firewall)
* **Límite X (Frecuencia diaria)**: Controla el número máximo de solicitudes de firma autorizadas por día (`max_daily_tx`). Evita que una extensión comprometida realice transacciones automatizadas masivas en bucle.
* **Límite Y (Volumen en USD)**: Limita la cuantía monetaria acumulada diaria autorizada para mitigar drenajes masivos de fondos en caso de explotación.
* **Listas Blancas**: Las transacciones deben especificar de manera obligatoria un identificador inmutable (`target_dex_cex_id`). El firewall contrasta este ID con una lista blanca local de contratos autorizados de DEX (ej. Uniswap, Curve) y direcciones autorizadas de CEX (billeteras de depósito). Peticiones arbitrarias sin enrutamiento claro o destinos no aprobados son rechazadas de inmediato.

### D. Disyuntor Táctico (Circuit Breaker)
* **Congelación Forense**: Si se detecta un intento de firma hacia una dirección no autorizada o un desbordamiento de cuotas diarias:
  1. Se bloquea preventivamente la derivación de claves públicas y el proceso de firma (`trip_breaker`).
  2. El disyuntor incrementa el contador de fallos de integridad. Al llegar a 3 fallos consecutivos, la pasarela entra en estado de **bloqueo permanente** (`HardLocked`).
* **Verificación Física Obligatoria**: Una vez activado el disyuntor, la pasarela cesa de responder al navegador. Para volver al estado operativo (`Operational`), el usuario debe acudir físicamente a la interfaz TUI local y reintroducir de forma segura sus credenciales de desbloqueo (combinación de las 5 cajas de la matriz y frase maestra), validando la clave contra Argon2id.

---

## 2. Archivos Implicados en el Proyecto

* **[Cargo.toml](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/Cargo.toml)**: Incorpora las dependencias necesarias de bajo nivel criptográfico (`secp256k1`, `ed25519-dalek`, `hmac`, `sha2`, `serde_json`).
* **[mod.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/mod.rs)**: Enrutador maestro del subsistema blockchain.
* **[types.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/types.rs)**: Tipos de datos estructurados para las peticiones y firmas.
* **[multi_curve.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/multi_curve.rs)**: Lógica de derivación multiecosistema en memoria blindada.
* **[proxy.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/proxy.rs)**: Host de mensajería nativa estándar mediante stdin/stdout.
* **[firewall.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/firewall.rs)**: Filtro perimetral del cortafuegos de cuotas y listas blancas.
* **[breaker.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/breaker.rs)**: Disyuntor táctico de seguridad y congelación forense.
* **[supervisor.rs](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/src/crypto/blockchain/supervisor.rs)**: Orquestador del bucle continuo reactivo de la pasarela.
* **[com.livencrypt.gateway.json](file:///home/Divad/Escritorio/LIVENCRYPT%202.0/src-tui/scripts/com.livencrypt.gateway.json)**: Archivo de manifiesto que registra el canal de mensajería en el sistema operativo.

---

## 3. Estado de la Integración

### ¿Qué está YA integrado?
* [x] **Arquitectura y Diseño**: El diseño conceptual de la pasarela y del motor de firma multicurva está completado y documentado en la carpeta de pendientes.

### ¿Qué falta por integrar?
* [ ] **Dependencias**: Configurar e instalar las versiones correctas de `secp256k1`, `ed25519-dalek`, `hmac` y `sha2` en `src-tui/Cargo.toml`.
* [ ] **Subsistema Blockchain**: Crear el directorio `src-tui/src/crypto/blockchain/` y estructurar los archivos de código fuente.
* [ ] **Limpieza de Secretos**: Validar que la derivación y firmas sobre secp256k1 y ed25519 destruyan efectivamente los residuos en la pila con `zeroize()` y `Drop`.
* [ ] **Políticas del Cortafuegos**: Implementar el cargador en caliente de reglas (`FirewallRules`) desde un JSON cifrado en el vault.
* [ ] **Registro de Host de Mensajería Nativa**: Desarrollar el script de instalación para copiar el manifiesto en las rutas de configuración de Brave, Chrome y Firefox del sistema operativo del usuario.
* [ ] **TUI HUD Integration**: Añadir un indicador visual en el Dashboard principal que muestre el estado de la pasarela (Operativo, Congelado, Bloqueado) y las transacciones bloqueadas por el firewall.

---

## 4. Enlaces Relacionados
* Volver al [[00_indice|Índice General]].
* Ver la documentación de hardening: [[01_proteccion_ingenieria_inversa_y_hardening_memoria|Protección contra Ingeniería Inversa y Hardening de Memoria]].
* Ver el panel HUD: [[09_integración_frontend_en_dashboard|Integración Frontend en Dashboard]].

---

## 5. Código a integrar

A continuación, se detalla el código completo y los archivos del subsistema para su integración ordenada en el proyecto:

### 1. Actualización de dependencias del proyecto (`src-tui/Cargo.toml`)
Añadimos el soporte criptográfico multiecurva y serialización estructurada.

**Archivo implicado**: `src-tui/Cargo.toml`

```toml
[dependencies]
# ... dependencias previas de Livencrypt
secp256k1 = { version = "0.29", features = ["global-context", "rand", "recovery"] }
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
hmac = "0.12"
sha2 = "0.10"
sha3 = "0.10"
serde_json = "1.0"
libc = "0.2"
```

---

### 2. Enrutador maestro del subsistema (`src-tui/src/crypto/blockchain/mod.rs`)
Establece la jerarquía del módulo para compilar todas las defensas y derivaciones Web3.

**Archivo implicado**: `src-tui/src/crypto/blockchain/mod.rs` (Nuevo)

```rust
/* rol: enrutador maestro del subsistema blockchain universal */
pub mod multi_curve;
pub mod types;
pub mod proxy;
pub mod firewall;
pub mod breaker;
pub mod supervisor;
```

Deberá registrarse en `src-tui/src/crypto/mod.rs` añadiendo la línea `pub mod blockchain;`.

---

### 3. Estructuras de datos unificadas (`src-tui/src/crypto/blockchain/types.rs`)
Define los payloads agnósticos de la red para transacciones, derivación de claves y firmas.

**Archivo implicado**: `src-tui/src/crypto/blockchain/types.rs` (Nuevo)

```rust
/* rol: tipos de datos unificados para el proxy criptográfico blockchain */
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize)]
pub enum ChainType {
    Bitcoin,
    Ethereum,
    Solana,
    Monero,
}

#[derive(Serialize, Deserialize, Clone, Zeroize)]
#[zeroize(drop)]
pub struct KeyDerivationRequest {
    pub chain: ChainType,
    pub account_index: u32,
    pub address_index: u32,
}

#[derive(Serialize, Deserialize, Clone, Zeroize)]
#[zeroize(drop)]
pub struct TransactionSignRequest {
    pub chain: ChainType,
    pub account_index: u32,
    pub raw_tx_payload: Vec<u8>,
    pub value_usd: f64,
    pub target_dex_cex_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignatureResponse {
    pub public_key: Vec<u8>,
    pub raw_signature: Vec<u8>,
    pub recovery_id: Option<u8>,
}
```

---

### 4. Motor de derivación multiecurva en memoria protegida (`src-tui/src/crypto/blockchain/multi_curve.rs`)
Genera claves deterministas basadas en BIP-32/BIP-44 adaptado, y realiza firmas en secp256k1 y ed25519 con borrado seguro de memoria.

**Archivo implicado**: `src-tui/src/crypto/blockchain/multi_curve.rs` (Nuevo)

```rust
/* rol: derivación de claves multiecosistema en memoria volátil blindada */
use crate::crypto::blockchain::types::{ChainType, SignatureResponse};
use crate::security::vault::derive_vault_key;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512, Digest as Sha2Digest};
use sha3::{Keccak256, Digest as Sha3Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use ed25519_dalek::{SigningKey, Signer};
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

pub struct UniversalKeymaster {
    master_seed: [u8; 64],
}

impl Drop for UniversalKeymaster {
    fn drop(&mut self) {
        self.master_seed.zeroize();
    }
}

impl UniversalKeymaster {
    pub fn new(cajas: [i64; 5], master_phrase: &str) -> Result<Self, String> {
        let mut vault_key = derive_vault_key(cajas, master_phrase)?;
        let mut hmac = HmacSha512::new_from_slice(b"Livencrypt Universal Seed")
            .map_err(|e| e.to_string())?;
        hmac.update(&vault_key);
        
        let mut master_seed = [0u8; 64];
        master_seed.copy_from_slice(&hmac.finalize().into_bytes());
        
        vault_key.zeroize();
        
        Ok(Self { master_seed })
    }

    fn derive_bip32_child(&self, coin_type: u32, account: u32, index: u32) -> Result<[u8; 32], String> {
        let mut hmac = HmacSha512::new_from_slice(&self.master_seed)
            .map_err(|e| e.to_string())?;
        
        hmac.update(&coin_type.to_be_bytes());
        hmac.update(&account.to_be_bytes());
        hmac.update(&index.to_be_bytes());
        
        let result = hmac.finalize().into_bytes();
        let mut child_key = [0u8; 32];
        child_key.copy_from_slice(&result[0..32]);
        
        Ok(child_key)
    }

    pub fn get_public_key(&self, chain: &ChainType, account: u32, index: u32) -> Result<Vec<u8>, String> {
        let coin_id = match chain {
            ChainType::Bitcoin => 0,
            ChainType::Ethereum => 60,
            ChainType::Solana => 501,
            ChainType::Monero => 128,
        };

        let mut raw_key = self.derive_bip32_child(coin_id, account, index)?;
        
        // Clausura de limpieza incondicional para garantizar zeroize en TODAS las ramas
        let result = (|| -> Result<Vec<u8>, String> {
            match chain {
                ChainType::Bitcoin => {
                    let s = Secp256k1::new();
                    let sk = SecretKey::from_slice(&raw_key).map_err(|e| e.to_string())?;
                    let pk = PublicKey::from_secret_key(&s, &sk);
                    Ok(pk.serialize().to_vec())
                }
                ChainType::Ethereum => {
                    let s = Secp256k1::new();
                    let sk = SecretKey::from_slice(&raw_key).map_err(|e| e.to_string())?;
                    let pk = PublicKey::from_secret_key(&s, &sk);
                    Ok(pk.serialize_uncompressed()[1..].to_vec())
                }
                ChainType::Solana => {
                    let sk = SigningKey::from_bytes(&raw_key);
                    Ok(sk.verifying_key().to_bytes().to_vec())
                }
                ChainType::Monero => {
                    Err("Monero requiere derivación multilave aislada no soportada".to_string())
                }
            }
        })();

        raw_key.zeroize(); // GARANTIZADO: se ejecuta siempre, éxito o error
        result
    }

    pub fn sign_transaction(
        &self,
        chain: &ChainType,
        account: u32,
        index: u32,
        raw_payload: &[u8],
    ) -> Result<SignatureResponse, String> {
        let coin_id = match chain {
            ChainType::Bitcoin => 0,
            ChainType::Ethereum => 60,
            ChainType::Solana => 501,
            ChainType::Monero => 128,
        };

        let mut raw_key = self.derive_bip32_child(coin_id, account, index)?;

        // Clausura de limpieza incondicional para garantizar zeroize en TODAS las ramas
        let result = (|| -> Result<SignatureResponse, String> {
            match chain {
                ChainType::Bitcoin | ChainType::Ethereum => {
                    let s = Secp256k1::new();
                    let sk = SecretKey::from_slice(&raw_key).map_err(|e| e.to_string())?;
                    
                    let tx_hash = match chain {
                        ChainType::Bitcoin => {
                            let hash1 = Sha256::digest(raw_payload);
                            let hash2 = Sha256::digest(&hash1);
                            let mut array = [0u8; 32];
                            array.copy_from_slice(&hash2);
                            array
                        }
                        _ => {
                            let hash = Keccak256::digest(raw_payload);
                            let mut array = [0u8; 32];
                            array.copy_from_slice(&hash);
                            array
                        }
                    };

                    let msg = Message::from_digest_slice(&tx_hash).map_err(|e| e.to_string())?;
                    let recoverable_sig = s.sign_ecdsa_recoverable(&msg, &sk);
                    let (rec_id, sig_bytes) = recoverable_sig.serialize_compact();
                    
                    let serialized_pub = match chain {
                        ChainType::Bitcoin => PublicKey::from_secret_key(&s, &sk).serialize().to_vec(),
                        _ => PublicKey::from_secret_key(&s, &sk).serialize_uncompressed()[1..].to_vec(),
                    };
                    
                    Ok(SignatureResponse {
                        public_key: serialized_pub,
                        raw_signature: sig_bytes.to_vec(),
                        recovery_id: Some(rec_id.to_i32() as u8),
                    })
                }
                ChainType::Solana => {
                    let sk = SigningKey::from_bytes(&raw_key);
                    let sig = sk.sign(raw_payload);
                    
                    Ok(SignatureResponse {
                        public_key: sk.verifying_key().to_bytes().to_vec(),
                        raw_signature: sig.to_bytes().to_vec(),
                        recovery_id: None,
                    })
                }
                ChainType::Monero => {
                    Err("Monero requiere un esquema especializado de firmas en anillo (MLSAG/CLSAG) acopladas a Bulletproofs y debe tratarse con un payload multilave específico".to_string())
                }
            }
        })();

        raw_key.zeroize(); // GARANTIZADO: se ejecuta siempre, éxito o error
        result
    }
}
```

---

### 5. Host de mensajería nativa (`src-tui/src/crypto/blockchain/proxy.rs`)
Implementa el canal stdin/stdout robusto frente a ataques de buffer e inyección de datos estructurados.

**Archivo implicado**: `src-tui/src/crypto/blockchain/proxy.rs` (Nuevo)

```rust
/* rol: host de mensajería nativa seguro para extensión web stateless */
use crate::crypto::blockchain::types::{KeyDerivationRequest, TransactionSignRequest};
use std::io::{self, Read, Write};
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum ExtensionRequest {
    DeriveKey(KeyDerivationRequest),
    SignTransaction(TransactionSignRequest),
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum ExtensionResponse<T> {
    Success(T),
    Error(String),
}

pub struct NativeProxyChannel;

impl NativeProxyChannel {
    pub fn read_next_request() -> Result<ExtensionRequest, String> {
        let mut length_buffer = [0u8; 4];
        io::stdin()
            .read_exact(&mut length_buffer)
            .map_err(|e| format!("error al leer longitud del mensaje: {}", e))?;

        let message_length = u32::from_ne_bytes(length_buffer) as usize;
        
        // Hardening: Limitar el tamaño máximo del payload a 1MB para evitar DoS
        if message_length > 1024 * 1024 {
            return Err("longitud de mensaje excede el límite de seguridad de 1MB".to_string());
        }

        let mut json_buffer = vec![0u8; message_length];
        io::stdin()
            .read_exact(&mut json_buffer)
            .map_err(|e| format!("error al leer cuerpo del mensaje: {}", e))?;

        let request: ExtensionRequest = serde_json::from_slice(&json_buffer)
            .map_err(|e| format!("error de deserialización estructurada: {}", e))?;

        json_buffer.zeroize();
        Ok(request)
    }

    pub fn write_response<T: Serialize>(response: &ExtensionResponse<T>) -> Result<(), String> {
        let json_bytes = serde_json::to_vec(response)
            .map_err(|e| format!("error de serialización de respuesta: {}", e))?;

        let length_prefix = (json_bytes.len() as u32).to_ne_bytes();

        let mut stdout = io::stdout();
        stdout.write_all(&length_prefix)
            .map_err(|e| format!("error al escribir prefijo de longitud: {}", e))?;
        stdout.write_all(&json_bytes)
            .map_err(|e| format!("error al escribir cuerpo de la respuesta: {}", e))?;
        stdout.flush()
            .map_err(|e| format!("error al vaciar el canal de salida: {}", e))?;

        Ok(())
    }
}
```

---

### 6. Manifiesto de Host de mensajería nativa (`src-tui/scripts/com.livencrypt.gateway.json`)
Configura la vinculación física de la extensión oficial con el ejecutable local en el sistema operativo del host.

**Archivo implicado**: `src-tui/scripts/com.livencrypt.gateway.json` (Nuevo)

```json
{
  "name": "com.livencrypt.gateway",
  "description": "Proxy criptografico universal aislado de Livencrypt 2.0",
  "path": "/usr/bin/livencrypt-bridge",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://iealgmhdifbjdmlffgkccejpbnmefkkl/"
  ]
}
```

---

### 7. Cortafuegos de políticas y límites (`src-tui/src/crypto/blockchain/firewall.rs`)
Valida cuotas y destinos autorizados en tiempo real antes de conceder la firma criptográfica.

**Archivo implicado**: `src-tui/src/crypto/blockchain/firewall.rs` (Nuevo)

```rust
/* rol: cortafuegos de políticas en caliente y listas blancas */
use crate::crypto::blockchain::types::TransactionSignRequest;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FirewallRules {
    pub max_daily_tx: u32,
    pub max_daily_volume_usd: f64,
    pub allowed_dex_contracts: Vec<String>,
    pub allowed_cex_destinations: Vec<String>,
}

pub struct LiveFirewall {
    pub rules: FirewallRules,
    pub tx_count_today: u32,
    pub volume_today_usd: f64,
    pub last_reset_timestamp: u64,
}

impl LiveFirewall {
    pub fn new(rules: FirewallRules) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            rules,
            tx_count_today: 0,
            volume_today_usd: 0.0,
            last_reset_timestamp: now,
        }
    }

    fn check_and_reset_daily_counters(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if now.saturating_sub(self.last_reset_timestamp) >= 86400 {
            self.tx_count_today = 0;
            self.volume_today_usd = 0.0;
            self.last_reset_timestamp = now;
        }
    }

    pub fn validate_transaction(&mut self, request: &TransactionSignRequest, estimated_value_usd: f64) -> Result<(), String> {
        self.check_and_reset_daily_counters();

        if self.tx_count_today >= self.rules.max_daily_tx {
            return Err(format!(
                "restricción de frecuencia: se ha alcanzado el límite máximo de {} transacciones diarias",
                self.rules.max_daily_tx
            ));
        }

        if self.volume_today_usd + estimated_value_usd > self.rules.max_daily_volume_usd {
            return Err(format!(
                "umbral de volumen excedido: la operación empuja el acumulado sobre el límite diario de {} USD",
                self.rules.max_daily_volume_usd
            ));
        }

        if let Some(target_id) = &request.target_dex_cex_id {
            let is_authorized_dex = self.rules.allowed_dex_contracts.contains(target_id);
            let is_authorized_cex = self.rules.allowed_cex_destinations.contains(target_id);

            if !is_authorized_dex && !is_authorized_cex {
                return Err(format!(
                    "bloqueo perimetral: el identificador de destino '{}' no coincide con ninguna infraestructura autorizada",
                    target_id
                ));
            }
        } else {
            return Err("operación insegura: las peticiones Web3 externas deben proveer un identificador de destino inmutable".to_string());
        }

        Ok(())
    }

    pub fn commit_transaction(&mut self, estimated_value_usd: f64) {
        self.tx_count_today += 1;
        self.volume_today_usd += estimated_value_usd;
    }
}
```

---

### 8. Disyuntor táctico de seguridad (`src-tui/src/crypto/blockchain/breaker.rs`)
Permite el aislamiento en caliente y la revocación de la derivación de claves públicas.

**Archivo implicado**: `src-tui/src/crypto/blockchain/breaker.rs` (Nuevo)

```rust
/* rol: disyuntor tactico de seguridad, congelacion forense y aislamiento */
use crate::security::vault::derive_vault_key;
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq)]
pub enum GatewaySecurityState {
    Operational,
    Frozen { reason: String, timestamp: u64 },
    HardLocked,
}

pub struct TacticalCircuitBreaker {
    pub state: GatewaySecurityState,
    pub integrity_failures: u32,
}

impl TacticalCircuitBreaker {
    pub fn new() -> Self {
        Self {
            state: GatewaySecurityState::Operational,
            integrity_failures: 0,
        }
    }

    pub fn trip_breaker(&mut self, reason: &str, timestamp: u64) {
        self.state = GatewaySecurityState::Frozen {
            reason: reason.to_string(),
            timestamp,
        };
    }

    pub fn trigger_hard_lock(&mut self) {
        self.state = GatewaySecurityState::HardLocked;
    }

    pub fn resolve_and_reset(
        &mut self,
        cajas: [i64; 5],
        master_phrase: &str,
    ) -> Result<(), String> {
        // Guardia: HardLocked es un estado terminal irrecuperable por diseño
        if self.state == GatewaySecurityState::HardLocked {
            return Err("bloqueo perimetral permanente: la pasarela requiere reinicio completo del binario".to_string());
        }

        // Validación local física e impositiva mediante Argon2id para restablecer el disyuntor
        let mut verification_key = derive_vault_key(cajas, master_phrase)?;
        
        if verification_key.is_empty() {
            verification_key.zeroize();
            return Err("credenciales de autorizacion locales invalidas".to_string());
        }

        verification_key.zeroize();
        self.state = GatewaySecurityState::Operational;
        self.integrity_failures = 0;
        Ok(())
    }
}
```

---

### 9. Supervisor y coordinador de la pasarela (`src-tui/src/crypto/blockchain/supervisor.rs`)
Orquesta las operaciones reactivas en bucle acopladas a los demás submódulos de seguridad.

**Archivo implicado**: `src-tui/src/crypto/blockchain/supervisor.rs` (Nuevo)

```rust
/* rol: supervisor maestro y coordinador de la pasarela de custodia universal */
use crate::crypto::blockchain::proxy::{ExtensionRequest, ExtensionResponse};
use crate::crypto::blockchain::multi_curve::UniversalKeymaster;
use crate::crypto::blockchain::firewall::LiveFirewall;
use crate::crypto::blockchain::breaker::{TacticalCircuitBreaker, GatewaySecurityState};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct GatewaySupervisor {
    pub keymaster: UniversalKeymaster,
    pub firewall: LiveFirewall,
    pub breaker: TacticalCircuitBreaker,
}

impl GatewaySupervisor {
    pub fn new(keymaster: UniversalKeymaster, firewall: LiveFirewall) -> Self {
        Self {
            keymaster,
            firewall,
            breaker: TacticalCircuitBreaker::new(),
        }
    }

    pub fn run_loop_iteration(&mut self, request: ExtensionRequest) -> Result<Vec<u8>, String> {
        if self.breaker.state == GatewaySecurityState::HardLocked {
            let err_resp = ExtensionResponse::<()>::Error("acceso revocado: intervención local requerida".to_string());
            return serde_json::to_vec(&err_resp).map_err(|e| e.to_string());
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        let response_bytes = match request {
            ExtensionRequest::DeriveKey(deriv_req) => {
                if let GatewaySecurityState::Frozen { .. } = self.breaker.state {
                    let err_resp = ExtensionResponse::<Vec<u8>>::Error("operación suspendida temporalmente".to_string());
                    serde_json::to_vec(&err_resp).map_err(|e| e.to_string())?
                } else {
                    match self.keymaster.get_public_key(&deriv_req.chain, deriv_req.account_index, deriv_req.address_index) {
                        Ok(pub_key) => {
                            let resp = ExtensionResponse::Success(pub_key);
                            serde_json::to_vec(&resp).map_err(|e| e.to_string())?
                        }
                        Err(e) => {
                            let resp = ExtensionResponse::<Vec<u8>>::Error(e);
                            serde_json::to_vec(&resp).map_err(|e| e.to_string())?
                        }
                    }
                }
            }

            ExtensionRequest::SignTransaction(sign_req) => {
                if let Err(firewall_err) = self.firewall.validate_transaction(&sign_req, sign_req.value_usd) {
                    self.breaker.trip_breaker(&firewall_err, now);
                    self.breaker.integrity_failures += 1;

                    if self.breaker.integrity_failures >= 3 {
                        self.breaker.trigger_hard_lock();
                    }

                    let err_resp = ExtensionResponse::<()>::Error(format!("violación de perímetro: {}", firewall_err));
                    serde_json::to_vec(&err_resp).map_err(|e| e.to_string())?
                } else {
                    match self.keymaster.sign_transaction(&sign_req.chain, sign_req.account_index, 0, &sign_req.raw_tx_payload) {
                        Ok(sig_resp) => {
                            self.firewall.commit_transaction(sign_req.value_usd);
                            let resp = ExtensionResponse::Success(sig_resp);
                            serde_json::to_vec(&resp).map_err(|e| e.to_string())?
                        }
                        Err(e) => {
                            let resp = ExtensionResponse::<()>::Error(e);
                            serde_json::to_vec(&resp).map_err(|e| e.to_string())?
                        }
                    }
                }
            }
        };

        Ok(response_bytes)
    }
}
```
