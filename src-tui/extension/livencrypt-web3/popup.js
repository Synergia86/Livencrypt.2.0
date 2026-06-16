"use strict";

async function loadState() {
  const data = await chrome.storage.local.get({
    allowedOrigins: {},
    pendingOrigins: {}
  });
  renderList("pending", Object.values(data.pendingOrigins), true);
  renderList("allowed", Object.values(data.allowedOrigins), false);
  document.getElementById("status").textContent = "listo";
}

function renderList(targetId, entries, pending) {
  const target = document.getElementById(targetId);
  target.textContent = "";

  if (entries.length === 0) {
    target.textContent = "Sin registros.";
    return;
  }

  for (const entry of entries) {
    const origin = typeof entry === "string" ? entry : entry.origin;
    const row = document.createElement("div");
    row.className = "row";

    const label = document.createElement("span");
    label.textContent = pending && entry.method ? `${origin} · ${entry.method}` : origin;
    row.appendChild(label);

    if (pending) {
      row.appendChild(button("Aprobar", () => approveOrigin(origin)));
      row.appendChild(button("Rechazar", () => rejectOrigin(origin)));
    } else {
      row.appendChild(button("Revocar", () => revokeOrigin(origin)));
    }

    target.appendChild(row);
  }
}

function button(text, fn) {
  const element = document.createElement("button");
  element.textContent = text;
  element.addEventListener("click", fn);
  return element;
}

async function approveOrigin(origin) {
  const data = await chrome.storage.local.get({
    allowedOrigins: {},
    pendingOrigins: {}
  });
  data.allowedOrigins[origin] = {
    origin,
    approved_at: Date.now(),
    methods: methodsForApproval(data.pendingOrigins[origin]?.method),
    account_index: 0,
    address_index: 0,
    mode: "method-scoped"
  };
  delete data.pendingOrigins[origin];
  await chrome.storage.local.set(data);
  await loadState();
}

function methodsForApproval(method) {
  const methods = new Set(["eth_accounts", "eth_chainId", "net_version"]);
  if (method) methods.add(method);
  if (method === "eth_sendTransaction") {
    methods.add("livencrypt_prepareTransaction");
  }
  if (method === "livencrypt_prepareTransaction") {
    methods.add("eth_sendTransaction");
  }
  return Array.from(methods).sort();
}

async function rejectOrigin(origin) {
  const data = await chrome.storage.local.get({ pendingOrigins: {} });
  delete data.pendingOrigins[origin];
  await chrome.storage.local.set({ pendingOrigins: data.pendingOrigins });
  await loadState();
}

async function revokeOrigin(origin) {
  const data = await chrome.storage.local.get({ allowedOrigins: {} });
  delete data.allowedOrigins[origin];
  await chrome.storage.local.set({ allowedOrigins: data.allowedOrigins });
  await loadState();
}

loadState();
