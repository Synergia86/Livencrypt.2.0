"use strict";

const REQUEST_TYPE = "LIVENCRYPT_WEB3_REQUEST";
const RESPONSE_TYPE = "LIVENCRYPT_WEB3_RESPONSE";

if (window.top !== window) {
  console.warn("Livencrypt Web3: iframe bloqueado");
} else {
  injectProvider();
}

window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const message = event.data;
  if (!message || message.type !== REQUEST_TYPE || !message.id) return;

  chrome.runtime.sendMessage(
    {
      scope: "livencrypt-web3",
      id: message.id,
      origin: window.location.origin,
      request: message.request
    },
    (response) => {
      const lastError = chrome.runtime.lastError?.message;
      window.postMessage(
        {
          type: RESPONSE_TYPE,
          id: message.id,
          response: response || {
            ok: false,
            error: {
              code: 4900,
              message: lastError || "Livencrypt Web3 sin respuesta"
            }
          }
        },
        window.location.origin
      );
    }
  );
});

function injectProvider() {
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("inject.js");
  script.async = false;
  script.onload = () => script.remove();
  (document.documentElement || document.head).prepend(script);
}
