"use strict";

(function installLivencryptProvider() {
  const REQUEST_TYPE = "LIVENCRYPT_WEB3_REQUEST";
  const RESPONSE_TYPE = "LIVENCRYPT_WEB3_RESPONSE";
  let sequence = 1;
  const pending = new Map();

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const message = event.data;
    if (!message || message.type !== RESPONSE_TYPE || !message.id) return;
    const entry = pending.get(message.id);
    if (!entry) return;
    pending.delete(message.id);

    if (message.response?.ok) {
      entry.resolve(message.response.result);
    } else {
      const payload = message.response?.error;
      const error = new Error(
        typeof payload === "object" && payload?.message
          ? payload.message
          : payload || "Error Livencrypt Web3"
      );
      if (typeof payload === "object") {
        if (payload.code !== undefined) error.code = payload.code;
        if (payload.data !== undefined) error.data = payload.data;
      }
      entry.reject(error);
    }
  });

  class LivencryptProvider {
    constructor() {
      this.isLivencrypt = true;
      this.selectedAddress = null;
      this.chainId = "0x1";
      this._listeners = new Map();
    }

    request(args) {
      if (!args || typeof args.method !== "string") {
        return Promise.reject(new Error("Solicitud EIP-1193 invalida"));
      }

      const id = `livencrypt-${Date.now()}-${sequence++}`;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        window.postMessage({ type: REQUEST_TYPE, id, request: args }, window.location.origin);

        window.setTimeout(() => {
          if (pending.has(id)) {
            pending.delete(id);
            reject(new Error("Tiempo de espera agotado esperando a Livencrypt"));
          }
        }, 300000);
      }).then((result) => {
        if ((args.method === "eth_requestAccounts" || args.method === "eth_accounts") && result?.[0]) {
          this.selectedAddress = result[0];
          this._emit("accountsChanged", result);
        }
        if (args.method === "eth_chainId" && typeof result === "string") {
          this.chainId = result;
        }
        return result;
      });
    }

    on(event, callback) {
      if (typeof callback !== "function") return;
      const listeners = this._listeners.get(event) || new Set();
      listeners.add(callback);
      this._listeners.set(event, listeners);
    }

    removeListener(event, callback) {
      this._listeners.get(event)?.delete(callback);
    }

    _emit(event, value) {
      for (const callback of this._listeners.get(event) || []) {
        try {
          callback(value);
        } catch (_) {
          // La pagina controla sus propios callbacks; la extension no debe fallar por ellos.
        }
      }
    }
  }

  const provider = new LivencryptProvider();
  Object.defineProperty(window, "livencrypt", {
    value: provider,
    writable: false,
    configurable: false
  });

  if (!window.ethereum) {
    Object.defineProperty(window, "ethereum", {
      value: provider,
      writable: false,
      configurable: true
    });
  }

  window.dispatchEvent(new CustomEvent("livencrypt#initialized"));
})();
