# Hoja de ruta frontend TUI pendiente: Pasarela Web3, politicas por cuenta y precios

## 1. Objetivo

Este documento detalla lo que falta por integrar en el frontend TUI para completar la interfaz de:

- politicas Web3 por cuenta;
- reglas programadas;
- oraculo de precios offline/firmado/RPC;
- auditor multicadena con datos extendidos;
- gestion visual de cuentas, destinos, contratos y tokens;
- pantallas especificas para saldos, nonce, fees e historial cuando el perfil permita RPC.

El backend ya dispone de estructuras base para:

```text
AccountPolicy
ScheduledPolicy
PriceBook
PriceQuote
Web3ConnectivityProfile
NodeEndpointPolicy
BroadcastTransactionRequest
ChainRpcAdapter
```

El frontend actual muestra datos globales y permite editar limites basicos, pero todavia falta una interfaz completa para administrar politicas por cuenta y reglas programadas.

## 2. Archivos implicados

Frontend principal:

```text
src-tui/src/main.rs
```

Backend ya disponible:

```text
src-tui/src/crypto/blockchain/types.rs
src-tui/src/crypto/blockchain/firewall.rs
src-tui/src/crypto/blockchain/worker.rs
src-tui/src/crypto/blockchain/nodes.rs
src-tui/src/crypto/blockchain/rpc.rs
src-tui/src/crypto/blockchain/supervisor.rs
```

## 3. Pantallas TUI pendientes

Agregar nuevas variantes a `enum Screen`:

```rust
enum Screen {
    // existentes
    WalletGateway,
    WalletAuditor,
    NodesManager,

    // nuevas
    Web3AccountPolicies,
    Web3ScheduledRules,
    Web3PriceOracle,
    Web3RpcInspector,
    Web3AccountEditor,
}
```

Uso:

```text
P -> Politicas por cuenta
S -> Reglas programadas
$ -> Precios / oraculo
I -> Inspector RPC
E -> Editor de cuenta Web3
```

## 4. Estado nuevo en `TuiState`

Agregar campos especificos para el frontend Web3:

```rust
struct TuiState {
    // existentes
    account_policies: Vec<AccountPolicy>,
    price_quotes: Vec<PriceQuote>,

    // seleccion de cuenta/politica
    web3_policy_selected: usize,
    web3_policy_focus: usize,
    web3_policy_chain_index: usize,
    web3_policy_account_index: String,
    web3_policy_address_index: String,
    web3_policy_label: String,
    web3_policy_max_tx: String,
    web3_policy_max_crypto: String,
    web3_policy_max_fiat: String,
    web3_policy_fiat_currency: String,
    web3_policy_require_confirmation: bool,

    // listas por politica
    web3_policy_destination_input: String,
    web3_policy_contract_input: String,
    web3_policy_asset_input: String,
    web3_policy_asset_limit_input: String,

    // reglas programadas
    web3_schedule_selected: usize,
    web3_schedule_focus: usize,
    web3_schedule_name: String,
    web3_schedule_asset: String,
    web3_schedule_destination: String,
    web3_schedule_max_tx: String,
    web3_schedule_max_asset: String,
    web3_schedule_max_fiat: String,
    web3_schedule_currency: String,
    web3_schedule_window: String,
    web3_schedule_expires_unix: String,

    // oraculo de precios
    web3_price_focus: usize,
    web3_price_selected: usize,
    web3_price_asset: String,
    web3_price_fiat: String,
    web3_price_value: String,
    web3_price_source: String,
    web3_price_max_age_seconds: String,

    // inspector RPC lectura
    web3_rpc_focus: usize,
    web3_rpc_chain_index: usize,
    web3_rpc_address: String,
    web3_rpc_asset: String,
    web3_rpc_status: String,
    web3_rpc_balance: String,
    web3_rpc_nonce: String,
    web3_rpc_fee: String,
    web3_rpc_tx_status: String,
}
```

Inicializacion recomendada:

```rust
web3_policy_selected: 0,
web3_policy_focus: 0,
web3_policy_chain_index: 0,
web3_policy_account_index: "0".to_string(),
web3_policy_address_index: "0".to_string(),
web3_policy_label: "Operativa".to_string(),
web3_policy_max_tx: "10".to_string(),
web3_policy_max_crypto: String::new(),
web3_policy_max_fiat: "5000".to_string(),
web3_policy_fiat_currency: "USD".to_string(),
web3_policy_require_confirmation: true,
web3_policy_destination_input: String::new(),
web3_policy_contract_input: String::new(),
web3_policy_asset_input: String::new(),
web3_policy_asset_limit_input: String::new(),
web3_schedule_selected: 0,
web3_schedule_focus: 0,
web3_schedule_name: String::new(),
web3_schedule_asset: "USDT".to_string(),
web3_schedule_destination: String::new(),
web3_schedule_max_tx: "4".to_string(),
web3_schedule_max_asset: String::new(),
web3_schedule_max_fiat: String::new(),
web3_schedule_currency: "USD".to_string(),
web3_schedule_window: "diario".to_string(),
web3_schedule_expires_unix: String::new(),
web3_price_focus: 0,
web3_price_selected: 0,
web3_price_asset: "BTC".to_string(),
web3_price_fiat: "USD".to_string(),
web3_price_value: String::new(),
web3_price_source: "manual-local".to_string(),
web3_price_max_age_seconds: "86400".to_string(),
web3_rpc_focus: 0,
web3_rpc_chain_index: 0,
web3_rpc_address: String::new(),
web3_rpc_asset: "native".to_string(),
web3_rpc_status: "RPC no consultado.".to_string(),
web3_rpc_balance: String::new(),
web3_rpc_nonce: String::new(),
web3_rpc_fee: String::new(),
web3_rpc_tx_status: String::new(),
```

## 5. Comandos nuevos del worker

Ampliar `Web3WorkerCmd` para que el frontend pueda guardar politicas, reglas y precios:

```rust
pub enum Web3WorkerCmd {
    // existentes
    UpdateRules {
        max_tx: Option<u32>,
        max_vol: Option<Decimal>,
        max_fiat: Option<Decimal>,
        fiat_currency: Option<String>,
    },
    SetManualPrice {
        asset: String,
        fiat: String,
        value: Decimal,
    },

    // nuevos
    UpsertAccountPolicy(AccountPolicy),
    RemoveAccountPolicy {
        chain: ChainType,
        account_index: u32,
        address_index: Option<u32>,
    },
    AddScheduledPolicy {
        chain: ChainType,
        account_index: u32,
        address_index: Option<u32>,
        rule: ScheduledPolicy,
    },
    RemoveScheduledPolicy {
        chain: ChainType,
        account_index: u32,
        address_index: Option<u32>,
        name: String,
    },
    ImportSignedPriceFile {
        path: PathBuf,
    },
    RpcReadBalance {
        chain: String,
        address: String,
        asset: String,
    },
    RpcReadNonce {
        chain: String,
        address: String,
    },
    RpcEstimateFee {
        chain: String,
        raw_payload: Vec<u8>,
    },
    RpcReadTxStatus {
        chain: String,
        txid: String,
    },
}
```

Eventos asociados:

```rust
pub enum Web3WorkerEvent {
    // existentes
    SyncRules(FirewallRules),
    Notification(String),

    // nuevos
    AccountPoliciesUpdated(Vec<AccountPolicy),
    PriceBookUpdated(PriceBook),
    RpcInspectorResult {
        label: String,
        result: Result<String, String>,
    },
}
```

## 6. Backend requerido para politicas por cuenta

Agregar metodos en `LiveFirewall`:

```rust
impl LiveFirewall {
    pub fn upsert_account_policy(&mut self, policy: AccountPolicy) {
        self.rules.account_policies.retain(|existing| {
            !(existing.chain == policy.chain
                && existing.account_index == policy.account_index
                && existing.address_index == policy.address_index)
        });
        self.rules.account_policies.push(policy);
    }

    pub fn remove_account_policy(
        &mut self,
        chain: &ChainType,
        account_index: u32,
        address_index: Option<u32>,
    ) -> bool {
        let before = self.rules.account_policies.len();
        self.rules.account_policies.retain(|policy| {
            !(policy.chain == *chain
                && policy.account_index == account_index
                && policy.address_index == address_index)
        });
        self.rules.account_policies.len() != before
    }

    pub fn add_scheduled_policy(
        &mut self,
        chain: &ChainType,
        account_index: u32,
        address_index: Option<u32>,
        rule: ScheduledPolicy,
    ) -> Result<(), String> {
        let policy = self
            .rules
            .account_policies
            .iter_mut()
            .find(|policy| {
                policy.chain == *chain
                    && policy.account_index == account_index
                    && policy.address_index == address_index
            })
            .ok_or_else(|| "politica de cuenta no encontrada".to_string())?;

        policy.scheduled_rules.retain(|existing| existing.name != rule.name);
        policy.scheduled_rules.push(rule);
        Ok(())
    }
}
```

## 7. Pantalla `Web3AccountPolicies`

Objetivo:

```text
POLITICAS POR CUENTA

Izquierda:
  Bitcoin cuenta 0 indice *
  Ethereum cuenta 1 indice *
  Solana cuenta 2 indice 0

Centro:
  Red
  Cuenta
  Indice
  Etiqueta
  Max TX
  Max cripto/token
  Max FIAT
  Moneda FIAT
  Confirmacion local

Derecha:
  Destinos permitidos
  Contratos permitidos
  Limites por activo
```

Funciones:

```text
Enter: guardar politica
Delete: eliminar politica
Tab: cambiar campo
Flechas: seleccionar politica
D: agregar destino
C: agregar contrato
A: agregar activo/limite
S: abrir reglas programadas
Esc: volver
```

Handler recomendado:

```rust
fn handle_web3_account_policies_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => state.screen = Screen::WalletGateway,
        KeyCode::Tab => state.web3_policy_focus = (state.web3_policy_focus + 1) % 12,
        KeyCode::BackTab => {
            state.web3_policy_focus = state.web3_policy_focus.saturating_sub(1);
        }
        KeyCode::Up => {
            state.web3_policy_selected = state.web3_policy_selected.saturating_sub(1);
            load_selected_policy_into_form(state);
        }
        KeyCode::Down => {
            if state.web3_policy_selected + 1 < state.account_policies.len() {
                state.web3_policy_selected += 1;
                load_selected_policy_into_form(state);
            }
        }
        KeyCode::Enter => submit_web3_account_policy(state),
        KeyCode::Delete => remove_selected_web3_account_policy(state),
        KeyCode::Char('S') | KeyCode::Char('s') => {
            state.screen = Screen::Web3ScheduledRules;
        }
        KeyCode::Backspace => edit_policy_field_backspace(state),
        KeyCode::Char(value) => edit_policy_field_char(state, value),
        _ => {}
    }
}
```

Constructor de politica:

```rust
fn build_account_policy_from_state(state: &TuiState) -> Result<AccountPolicy, String> {
    let chain = selected_policy_chain(state);
    let account_index = state
        .web3_policy_account_index
        .trim()
        .parse::<u32>()
        .map_err(|_| "cuenta invalida".to_string())?;
    let address_index = parse_optional_u32(&state.web3_policy_address_index)?;
    let max_tx = state
        .web3_policy_max_tx
        .trim()
        .parse::<u32>()
        .map_err(|_| "max TX invalido".to_string())?;
    let max_native_amount = parse_optional_decimal(&state.web3_policy_max_crypto)?;
    let max_fiat_value = parse_optional_decimal(&state.web3_policy_max_fiat)?;

    Ok(AccountPolicy {
        chain,
        account_index,
        address_index,
        label: state.web3_policy_label.trim().to_string(),
        max_tx_per_window: max_tx,
        max_native_amount,
        max_asset_amounts: HashMap::new(),
        max_fiat_value,
        max_fiat_value_per_tx: None,
        fiat_currency: state.web3_policy_fiat_currency.trim().to_uppercase(),
        allowed_destinations: Vec::new(),
        allowed_contracts: Vec::new(),
        scheduled_rules: Vec::new(),
        require_local_confirmation: state.web3_policy_require_confirmation,
    })
}
```

Envio al worker:

```rust
fn submit_web3_account_policy(state: &mut TuiState) {
    match build_account_policy_from_state(state) {
        Ok(policy) => {
            if let Some(tx) = &state.web3_cmd_tx {
                let _ = tx.send(Web3WorkerCmd::UpsertAccountPolicy(policy));
            }
        }
        Err(error) => state.system_notification = error,
    }
}
```

## 8. Pantalla `Web3ScheduledRules`

Objetivo:

```text
REGLAS PROGRAMADAS

Cuenta: Ethereum / cuenta 1 / indice *

Nombre: Pago proveedor A
Activo: USDT
Destino: 0x...
Ventana: diario/semanal/mensual/custom
Max TX: 4
Max activo: 1000
Max FIAT: 1000 USD
Caduca UNIX: opcional
Confirmacion local: si/no
```

Reglas:

- una regla programada nunca firma automaticamente;
- solo autoriza que una operacion concreta pueda pasar la prevalidacion;
- si cambia destino, contrato, activo o ventana, debe requerir revalidacion local;
- el error mostrado debe ser generico para no filtrar detalles excesivos.

Constructor:

```rust
fn build_scheduled_policy_from_state(
    state: &TuiState,
    chain: ChainType,
    account_index: u32,
    address_index: Option<u32>,
) -> Result<ScheduledPolicy, String> {
    Ok(ScheduledPolicy {
        name: state.web3_schedule_name.trim().to_string(),
        enabled: true,
        chain,
        account_index,
        address_index,
        asset: state.web3_schedule_asset.trim().to_uppercase(),
        destination: state.web3_schedule_destination.trim().to_string(),
        max_tx: state.web3_schedule_max_tx.trim().parse::<u32>().unwrap_or(1),
        max_asset_amount: parse_optional_decimal(&state.web3_schedule_max_asset)?,
        max_fiat_value: parse_optional_decimal(&state.web3_schedule_max_fiat)?,
        fiat_currency: state.web3_schedule_currency.trim().to_uppercase(),
        window: parse_policy_window(&state.web3_schedule_window),
        expires_unix: parse_optional_u64(&state.web3_schedule_expires_unix)?,
        require_local_confirmation: true,
    })
}
```

## 9. Pantalla `Web3PriceOracle`

Objetivo:

```text
ORACULO DE PRECIOS

Modo: OFFLINE MANUAL / FICHERO FIRMADO / RPC ONLINE
Fiat principal: USD/EUR
Max antiguedad: 86400s

Precios:
  BTC/USD = 105000 manual-local
  ETH/USD = 3800 manual-local
  USDT/USD = 1 manual-local

Acciones:
  Enter: guardar precio manual
  I: importar fichero firmado
  Delete: eliminar precio
  Esc: volver
```

Integracion inicial:

```rust
fn handle_web3_price_oracle_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => state.screen = Screen::WalletGateway,
        KeyCode::Tab => state.web3_price_focus = (state.web3_price_focus + 1) % 4,
        KeyCode::Enter => submit_manual_price(state),
        KeyCode::Char('I') | KeyCode::Char('i') => {
            state.status = "Importacion de fichero firmado pendiente de selector de archivo.".to_string();
        }
        KeyCode::Backspace => edit_price_field_backspace(state),
        KeyCode::Char(value) => edit_price_field_char(state, value),
        _ => {}
    }
}

fn submit_manual_price(state: &mut TuiState) {
    let Some(tx) = &state.web3_cmd_tx else {
        state.system_notification = "Web3 no inicializado.".to_string();
        return;
    };
    let Ok(value) = state.web3_price_value.trim().parse::<Decimal>() else {
        state.system_notification = "Precio invalido.".to_string();
        return;
    };
    let _ = tx.send(Web3WorkerCmd::SetManualPrice {
        asset: state.web3_price_asset.trim().to_uppercase(),
        fiat: state.web3_price_fiat.trim().to_uppercase(),
        value,
    });
}
```

## 10. Importador de fichero firmado `.lvcprices`

Formato recomendado:

```json
{
  "version": 1,
  "created_unix": 1781280000,
  "source": "mesa-operaciones",
  "quotes": [
    {"asset": "BTC", "fiat": "USD", "value": "105000"},
    {"asset": "ETH", "fiat": "USD", "value": "3800"}
  ],
  "public_key": "hex-ed25519",
  "signature": "hex-ed25519"
}
```

Funcion backend:

```rust
pub fn import_signed_price_file(path: &Path) -> Result<PriceBook, String> {
    let raw = std::fs::read(path)
        .map_err(|error| format!("no se pudo leer fichero de precios: {}", error))?;
    if raw.len() > 1024 * 1024 {
        return Err("fichero de precios demasiado grande".into());
    }

    let envelope: SignedPriceEnvelope = serde_json::from_slice(&raw)
        .map_err(|error| format!("fichero de precios invalido: {}", error))?;

    verify_price_signature(&envelope)?;
    envelope.to_price_book()
}
```

La clave publica de firma debe configurarse previamente y guardarse dentro del vault cifrado si Boot Shield esta activo.

## 11. Pantalla `Web3RpcInspector`

Objetivo:

```text
INSPECTOR RPC

Perfil: OFFLINE / RPC LECTURA / RPC OPERATIVO
Red: Ethereum
Direccion: 0x...
Activo: ETH/USDT/native

Lecturas:
  Balance
  Nonce
  Fee estimado
  Estado TX

Estado:
  OFFLINE: consultas desactivadas
  RPC LECTURA: consultas permitidas, broadcast bloqueado
  RPC OPERATIVO: consultas permitidas, broadcast solo con politica
```

Reglas:

- si perfil `OFFLINE`, no llamar adaptadores RPC;
- si perfil `RPC LECTURA`, permitir solo lecturas;
- si perfil `RPC OPERATIVO`, permitir lecturas y preparacion, pero no firma automatica;
- nunca transmitir transacciones desde esta pantalla sin confirmacion local.

Handler:

```rust
fn handle_web3_rpc_inspector_key(state: &mut TuiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => state.screen = Screen::WalletGateway,
        KeyCode::Tab => state.web3_rpc_focus = (state.web3_rpc_focus + 1) % 4,
        KeyCode::Char('B') | KeyCode::Char('b') => request_rpc_balance(state),
        KeyCode::Char('N') | KeyCode::Char('n') => request_rpc_nonce(state),
        KeyCode::Char('F') | KeyCode::Char('f') => request_rpc_fee(state),
        KeyCode::Backspace => edit_rpc_field_backspace(state),
        KeyCode::Char(value) => edit_rpc_field_char(state, value),
        _ => {}
    }
}
```

## 12. Navegacion desde `WalletGateway`

Actualizar footer:

```text
P politicas | S reglas | $ precios | I inspector RPC | N nodos | M perfil | R rearme | Esc
```

Actualizar handler:

```rust
match key.code {
    KeyCode::Char('P') | KeyCode::Char('p') => {
        state.screen = Screen::Web3AccountPolicies;
    }
    KeyCode::Char('S') | KeyCode::Char('s') => {
        state.screen = Screen::Web3ScheduledRules;
    }
    KeyCode::Char('$') => {
        state.screen = Screen::Web3PriceOracle;
    }
    KeyCode::Char('I') | KeyCode::Char('i') => {
        state.screen = Screen::Web3RpcInspector;
    }
    KeyCode::Char('N') | KeyCode::Char('n') => {
        state.screen = Screen::NodesManager;
    }
    _ => {}
}
```

## 13. Renderizado minimo de politicas

```rust
fn draw_web3_account_policies(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Percentage(40),
            Constraint::Percentage(30),
        ])
        .split(area);

    let items = if state.account_policies.is_empty() {
        vec![ListItem::new("Sin politicas por cuenta.")]
    } else {
        state.account_policies
            .iter()
            .enumerate()
            .map(|(idx, policy)| {
                let marker = if idx == state.web3_policy_selected { ">" } else { " " };
                ListItem::new(format!(
                    "{} {:?} cuenta {} indice {:?} - {}",
                    marker,
                    policy.chain,
                    policy.account_index,
                    policy.address_index,
                    policy.label
                ))
            })
            .collect()
    };

    frame.render_widget(
        List::new(items).block(Block::default().title(" Politicas ").borders(Borders::ALL)),
        chunks[0],
    );

    let form = Paragraph::new(vec![
        Line::from(format!("Etiqueta: {}", state.web3_policy_label)),
        Line::from(format!("Cuenta: {}", state.web3_policy_account_index)),
        Line::from(format!("Indice: {}", state.web3_policy_address_index)),
        Line::from(format!("Max TX: {}", state.web3_policy_max_tx)),
        Line::from(format!("Max cripto/token: {}", state.web3_policy_max_crypto)),
        Line::from(format!("Max FIAT: {} {}", state.web3_policy_max_fiat, state.web3_policy_fiat_currency)),
        Line::from(format!("Confirmacion local: {}", if state.web3_policy_require_confirmation { "si" } else { "no" })),
    ])
    .block(Block::default().title(" Editor ").borders(Borders::ALL));
    frame.render_widget(form, chunks[1]);

    let side = Paragraph::new(vec![
        Line::from("Destinos permitidos"),
        Line::from(&state.web3_policy_destination_input),
        Line::from(""),
        Line::from("Contratos permitidos"),
        Line::from(&state.web3_policy_contract_input),
        Line::from(""),
        Line::from("Activo/limite"),
        Line::from(format!("{} {}", state.web3_policy_asset_input, state.web3_policy_asset_limit_input)),
    ])
    .block(Block::default().title(" Listas ").borders(Borders::ALL));
    frame.render_widget(side, chunks[2]);
}
```

## 14. Persistencia

Actualmente `FirewallRules` se sincroniza en memoria desde el worker. Para que las politicas sobrevivan reinicios:

1. Si Boot Shield esta activo:
   - guardar `FirewallRules`, `PriceBook`, perfil Web3 y politicas dentro del vault cifrado.
   - no escribir politicas sensibles en claro.

2. Si Boot Shield no esta activo:
   - guardar en archivo local con permisos `0600`.
   - avisar que la configuracion no esta protegida por vault.

Ruta sugerida en modo no vault:

```text
~/.local/share/livencrypt/.livencrypt/web3_policies.toml
```

## 15. Validaciones de seguridad frontend

Toda pantalla debe aplicar:

- errores genericos para rechazos de firma;
- no registrar frases, claves privadas ni payloads completos;
- truncar direcciones largas en listas;
- confirmar antes de borrar politicas;
- confirmar antes de activar `RPC OPERATIVO`;
- mostrar claramente cuando una cadena esta en:

```text
auditoria
firma experimental
firma soportada
solo lectura
no soportada
```

## 16. Prioridad de implementacion

### Primera pasada

1. `Web3AccountPolicies`
2. `UpsertAccountPolicy`
3. `RemoveAccountPolicy`
4. renderizado y edicion basica de politicas
5. persistencia en vault o archivo local protegido

### Segunda pasada

1. `Web3ScheduledRules`
2. `AddScheduledPolicy`
3. `RemoveScheduledPolicy`
4. validacion visual por ventana temporal

### Tercera pasada

1. `Web3PriceOracle`
2. importador `.lvcprices`
3. verificacion Ed25519
4. cache cifrada de precios

### Cuarta pasada

1. `Web3RpcInspector`
2. adaptadores RPC reales por cadena
3. health de nodos
4. balance/nonce/fees/status
5. reloj verificado por consenso de nodos

## 17. Resultado esperado

Al terminar la integracion, el frontend TUI debe permitir operar sin editar archivos manualmente:

```text
1. crear cuenta logica;
2. asignar red/cuenta/indice;
3. nombrarla;
4. definir limites TX/cripto/FIAT;
5. agregar destinos y contratos permitidos;
6. crear reglas programadas;
7. cargar precios manuales o firmados;
8. revisar saldos/nonce/fees solo si el perfil lo permite;
9. confirmar firmas bajo politica local;
10. bloquear broadcast salvo RPC OPERATIVO auditado.
```

