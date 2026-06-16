"use strict";

const HOST = "com.livencrypt.gateway";
const DEFAULT_CHAIN = "Ethereum";
const DEFAULT_ACCOUNT = 0;
const DEFAULT_INDEX = 0;
const PERMISSION_TTL_MS = 24 * 60 * 60 * 1000;
const PASSIVE_METHODS = new Set(["eth_chainId", "net_version"]);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.scope !== "livencrypt-web3") {
    return false;
  }

  handleProviderRequest(message.request, message.origin || sender.origin || "")
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => {
      const normalized = normalizeLivencryptError(error);
      sendResponse({
        ok: false,
        error: {
          code: normalized.code,
          message: normalized.message,
          data: normalized.data
        }
      });
    });

  return true;
});

async function handleProviderRequest(request, origin) {
  if (!request || typeof request.method !== "string") {
    throw new Error("Solicitud Web3 invalida");
  }

  switch (request.method) {
    case "eth_requestAccounts":
      await requireAllowedOrigin(origin, request.method);
      return requestAccounts(origin);
    case "eth_accounts":
      if (!(await isOriginAllowed(origin))) return [];
      return cachedAccounts(origin);
    case "eth_chainId":
      return "0x1";
    case "net_version":
      return "1";
    case "livencrypt_status":
      return status();
    case "eth_getBalance":
    case "eth_getTransactionCount":
    case "eth_gasPrice":
      await requireAllowedOrigin(origin, request.method);
      return handleReadMethod(request);
    case "eth_estimateGas":
      await requireAllowedOrigin(origin, request.method);
      throw new Error("eth_estimateGas requiere simulacion EVM auditada pendiente");
    case "livencrypt_prepareTransaction":
      await requireAllowedOrigin(origin, request.method);
      return prepareTransaction(request.params, origin);
    case "eth_sendTransaction":
      await requireAllowedOrigin(origin, request.method);
      return signTransaction(request.params, origin);
    case "personal_sign":
    case "eth_signTypedData_v4":
      await requireAllowedOrigin(origin, request.method);
      throw new Error(`${request.method} pendiente de politica de firma de mensajes`);
    case "wallet_switchEthereumChain":
    case "wallet_addEthereumChain":
      await requireAllowedOrigin(origin, request.method);
      return null;
    default:
      throw new Error(`Metodo no soportado por Livencrypt: ${request.method}`);
  }
}

async function getPermissions() {
  return chrome.storage.local.get({
    allowedOrigins: {},
    pendingOrigins: {}
  });
}

async function setOriginPending(origin, method) {
  const data = await getPermissions();
  data.pendingOrigins[origin] = {
    origin,
    method,
    requested_at: Date.now()
  };
  await chrome.storage.local.set({ pendingOrigins: data.pendingOrigins });
}

async function isOriginAllowed(origin) {
  return isOriginAllowedForMethod(origin, null);
}

async function isOriginAllowedForMethod(origin, method) {
  if (!origin || origin === "null") return false;
  let parsed;
  try {
    parsed = new URL(origin);
  } catch (_) {
    return false;
  }

  const isHttps = parsed.protocol === "https:";
  const isLocal = parsed.protocol === "http:" &&
    (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1");
  if (!isHttps && !isLocal) return false;

  const data = await getPermissions();
  const entry = data.allowedOrigins[origin];
  if (!entry) return false;

  if (Date.now() - Number(entry.approved_at || 0) > PERMISSION_TTL_MS) {
    delete data.allowedOrigins[origin];
    await chrome.storage.local.set({ allowedOrigins: data.allowedOrigins });
    return false;
  }

  if (method && !PASSIVE_METHODS.has(method)) {
    const methods = Array.isArray(entry.methods) ? entry.methods : [];
    if (!methods.includes(method)) return false;
  }

  return true;
}

async function requireAllowedOrigin(origin, method) {
  if (await isOriginAllowedForMethod(origin, method)) return;
  await setOriginPending(origin, method);
  throw providerError(4100, `Origen no autorizado para ${method}. Apruebe el dominio en la extension Livencrypt.`);
}

async function requestAccounts(origin) {
  const response = await sendNative({
    type: "Web3Account",
    payload: {
      chain: DEFAULT_CHAIN,
      account_index: DEFAULT_ACCOUNT,
      address_index: DEFAULT_INDEX,
      origin
    }
  });
  const account = unwrapSuccess(response);
  await chrome.storage.session.set({
    [`account:${origin}`]: account
  });
  return [account.address];
}

async function cachedAccounts(origin) {
  const key = `account:${origin}`;
  const stored = await chrome.storage.session.get(key);
  const account = stored[key];
  return account?.address ? [account.address] : [];
}

async function handleReadMethod(request) {
  switch (request.method) {
    case "eth_getBalance":
      return readBalance(request.params);
    case "eth_getTransactionCount":
      return readNonce(request.params);
    case "eth_gasPrice":
      return readGasPrice();
    default:
      throw new Error(`Metodo de lectura no soportado: ${request.method}`);
  }
}

async function readBalance(params) {
  const address = String(params?.[0] || "");
  if (!isEthAddress(address)) {
    throw new Error("Direccion Ethereum invalida");
  }
  const response = await sendNative({
    type: "Web3ReadBalance",
    payload: {
      chain: "ethereum",
      address,
      asset: "ETH"
    }
  });
  return unwrapSuccess(response).raw_amount || "0x0";
}

async function readNonce(params) {
  const address = String(params?.[0] || "");
  if (!isEthAddress(address)) {
    throw new Error("Direccion Ethereum invalida");
  }
  const response = await sendNative({
    type: "Web3ReadNonce",
    payload: {
      chain: "ethereum",
      address
    }
  });
  return unwrapSuccess(response).nonce || "0x0";
}

async function readGasPrice() {
  const response = await sendNative({
    type: "Web3EstimateFee",
    payload: {
      chain: "ethereum",
      raw_payload: []
    }
  });
  return unwrapSuccess(response).raw_fee || "0x0";
}

async function status() {
  const response = await sendNative({
    type: "Web3Status"
  });
  return unwrapSuccess(response);
}

async function signTransaction(params, origin) {
  const tx = params?.[0];
  if (!tx || typeof tx !== "object") {
    throw new Error("Transaccion Ethereum invalida");
  }

  const raw = tx.raw_tx_payload || tx.rawTxPayload;
  if (!raw) {
    const response = await sendNative({
      type: "EthereumSignTransaction",
      payload: buildEthereumPreparePayload(params, origin)
    });
    return unwrapSuccess(response).raw_tx_hex;
  }

  const response = await sendNative({
    type: "SignTransaction",
    payload: {
      chain: "Ethereum",
      account_index: DEFAULT_ACCOUNT,
      address_index: DEFAULT_INDEX,
      raw_tx_payload: hexToBytes(String(raw)),
      value_usd: 0,
      target_dex_cex_id: tx.to || null,
      origin
    }
  });
  return unwrapSuccess(response);
}

async function prepareTransaction(params, origin) {
  const response = await sendNative({
    type: "EthereumPrepareTransaction",
    payload: buildEthereumPreparePayload(params, origin)
  });
  return unwrapSuccess(response);
}

function buildEthereumPreparePayload(params, origin) {
  const tx = params?.[0];
  if (!tx || typeof tx !== "object") {
    throw new Error("Transaccion Ethereum invalida");
  }
  const from = String(tx.from || "");
  if (!isEthAddress(from)) {
    throw new Error("Campo from Ethereum invalido");
  }
  const to = tx.to == null || tx.to === "" ? null : String(tx.to);
  if (to !== null && !isEthAddress(to)) {
    throw new Error("Campo to Ethereum invalido");
  }

  const kind = tx.maxFeePerGas || tx.maxPriorityFeePerGas
    ? "Eip1559"
    : tx.accessList
      ? "Eip2930"
      : "Legacy";

  return {
    origin,
    account_index: DEFAULT_ACCOUNT,
    address_index: DEFAULT_INDEX,
    tx: {
      chain_id: parseChainId(tx.chainId || "0x1"),
      from,
      to,
      nonce: parseHexQuantity(tx.nonce, "nonce"),
      value: String(tx.value || "0x0"),
      data: String(tx.data || "0x"),
      gas_limit: parseHexQuantity(tx.gas || tx.gasLimit, "gas"),
      gas_price: tx.gasPrice ? String(tx.gasPrice) : null,
      max_fee_per_gas: tx.maxFeePerGas ? String(tx.maxFeePerGas) : null,
      max_priority_fee_per_gas: tx.maxPriorityFeePerGas ? String(tx.maxPriorityFeePerGas) : null,
      kind
    }
  };
}

function sendNative(payload) {
  return new Promise((resolve, reject) => {
    const port = chrome.runtime.connectNative(HOST);
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try {
          port.disconnect();
        } catch (_) {}
        reject(new Error("Timeout de mensajeria nativa Livencrypt"));
      }
    }, 300000);

    port.onMessage.addListener((message) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(message);
      port.disconnect();
    });

    port.onDisconnect.addListener(() => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error(chrome.runtime.lastError?.message || "Livencrypt desconectado"));
      }
    });

    port.postMessage(payload);
  });
}

function unwrapSuccess(message) {
  if (message?.status === "Success") {
    return message.data;
  }
  throw normalizeLivencryptError(message?.data || "Livencrypt rechazo la solicitud");
}

function providerError(code, message, data = undefined) {
  const error = new Error(message);
  error.code = code;
  if (data !== undefined) error.data = data;
  return error;
}

function normalizeLivencryptError(error) {
  if (error?.code !== undefined) return error;
  const message = String(error?.message || error);
  const lower = message.toLowerCase();
  if (lower.includes("no autorizado") || lower.includes("no permitid")) {
    return providerError(4100, message);
  }
  if (lower.includes("rechazad") || lower.includes("cancelad")) {
    return providerError(4001, message);
  }
  if (lower.includes("no soportado") || lower.includes("pendiente")) {
    return providerError(4200, message);
  }
  if (lower.includes("desconectado") || lower.includes("sin respuesta")) {
    return providerError(4900, message);
  }
  return providerError(-32603, message);
}

function isEthAddress(value) {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

function hexToBytes(value) {
  const normalized = value.startsWith("0x") ? value.slice(2) : value;
  if (normalized.length % 2 !== 0 || /[^0-9a-fA-F]/.test(normalized)) {
    throw new Error("Payload hexadecimal invalido");
  }
  const out = [];
  for (let i = 0; i < normalized.length; i += 2) {
    out.push(parseInt(normalized.slice(i, i + 2), 16));
  }
  return out;
}

function parseChainId(value) {
  if (typeof value === "number") return value;
  return parseHexQuantity(String(value || "0x1"), "chainId");
}

function parseHexQuantity(value, field) {
  if (value === undefined || value === null || value === "") {
    throw new Error(`Campo ${field} obligatorio ausente`);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`Campo ${field} invalido`);
    }
    return value;
  }
  const text = String(value);
  if (!/^0x[0-9a-fA-F]+$/.test(text)) {
    throw new Error(`Campo ${field} debe ser cantidad hexadecimal`);
  }
  const parsed = Number.parseInt(text.slice(2), 16);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`Campo ${field} excede entero seguro JS`);
  }
  return parsed;
}
