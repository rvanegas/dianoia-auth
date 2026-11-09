// Passkeys at dianoia-auth (passkeys.py): signing in with one on /login, adding
// one when offered after a code sign-in, and on /account. The page says which
// it is, and what this needs, on <body data-passkeys data-request data-csrf
// data-next>. Without WebAuthn in the browser, nothing here is shown, and an
// offer page goes straight on to where the sign-in was going.

"use strict";

const page = document.body.dataset;
const supported = typeof window.PublicKeyCredential === "function";

const b64 = {
  enc(buffer) {
    let s = "";
    for (const byte of new Uint8Array(buffer)) s += String.fromCharCode(byte);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  dec(text) {
    const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
  },
};

function encoded(credential) {
  const r = credential.response;
  const response = { clientDataJSON: b64.enc(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = b64.enc(r.attestationObject);
    response.transports = r.getTransports ? r.getTransports() : [];
  }
  if (r.authenticatorData) {
    response.authenticatorData = b64.enc(r.authenticatorData);
    response.signature = b64.enc(r.signature);
    if (r.userHandle) response.userHandle = b64.enc(r.userHandle);
  }
  return {
    id: credential.id, rawId: b64.enc(credential.rawId), type: credential.type, response,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
  };
}

async function post(url, body) {
  const response = await fetch(url, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF": page.csrf || "" },
    body: JSON.stringify(body),
  });
  const answer = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(answer.detail || "Something went wrong; try again.");
  return answer;
}

function say(text) {
  const where = document.getElementById("passkey-error");
  if (where) where.textContent = text;
}

// --- signing in --------------------------------------------------------------

let waiting = null;  // the autofill's pending request, which a press replaces

async function signIn(autofill) {
  if (waiting) waiting.abort();
  const controller = new AbortController();
  if (autofill) waiting = controller;
  const options = await post("/passkeys/sign-in/options", { request: page.request });
  options.challenge = b64.dec(options.challenge);
  (options.allowCredentials || []).forEach((c) => { c.id = b64.dec(c.id); });
  const credential = await navigator.credentials.get({
    publicKey: options, signal: controller.signal, ...(autofill ? { mediation: "conditional" } : {}),
  });
  const done = await post("/passkeys/sign-in", { request: page.request, credential: encoded(credential) });
  location.assign(done.redirect);
}

// --- adding one --------------------------------------------------------------

async function add() {
  const options = await post("/passkeys/options", {});
  options.challenge = b64.dec(options.challenge);
  options.user.id = b64.dec(options.user.id);
  (options.excludeCredentials || []).forEach((c) => { c.id = b64.dec(c.id); });
  const credential = await navigator.credentials.create({ publicKey: options });
  await post("/passkeys", { credential: encoded(credential) });
}

function failed(error) {
  if (error && error.name === "AbortError") return;
  if (error && error.name === "NotAllowedError") return say("Cancelled.");
  say(error && error.message ? error.message : String(error));
}

if (!supported) {
  document.querySelectorAll(".passkey").forEach((node) => { node.hidden = true; });
  if (page.passkeys === "offer") location.replace(page.next);
} else if (page.passkeys === "login") {
  const button = document.getElementById("passkey-sign-in");
  if (button) button.addEventListener("click", () => signIn(false).catch(failed));
  if (PublicKeyCredential.isConditionalMediationAvailable) {
    PublicKeyCredential.isConditionalMediationAvailable().then((yes) => {
      if (yes) signIn(true).catch(failed);
    });
  }
} else if (page.passkeys === "offer") {
  document.getElementById("passkey-add").addEventListener("click", () =>
    add().then(() => location.assign(page.next)).catch(failed));
} else if (page.passkeys === "account") {
  document.getElementById("passkey-add").addEventListener("click", () =>
    add().then(() => location.reload()).catch(failed));
}
