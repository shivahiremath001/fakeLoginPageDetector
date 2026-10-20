/**
 * content.js — Tier 2 form and credential destination inspector.
 *
 * Runs at document_idle (~100ms).
 * Only triggers if the page contains a password input field.
 */

(function initTier2() {
  const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));
  if (passwordInputs.length === 0) {
    // No password field on page — silent exit, zero network or background overhead
    return;
  }

  // Extract all form actions on the page and resolve to absolute URLs
  const formActions = [];
  const forms = Array.from(document.querySelectorAll("form"));

  forms.forEach((form) => {
    const rawAction = form.getAttribute("action") || "";
    try {
      const resolved = new URL(rawAction, window.location.href).href;
      formActions.push(resolved);
    } catch {
      if (rawAction) formActions.push(rawAction);
    }
  });

  // If password input exists without a form element, note current URL as submission target
  if (formActions.length === 0) {
    formActions.push(window.location.href);
  }

  // Notify the service worker (Tier 2 / Tier 3 verification)
  chrome.runtime.sendMessage({
    type: "LOGIN_FORM_DETECTED",
    url: window.location.href,
    hasPassword: true,
    formActions: Array.from(new Set(formActions)),
  }).catch(() => {
    // Service worker might be waking up; ignore send failure
  });

  // Listen for overlay commands from background worker
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "SHOW_VERIFY_OVERLAY") {
      showVerifyOverlay();
    } else if (message.type === "HIDE_VERIFY_OVERLAY") {
      hideVerifyOverlay();
    }
  });

  function showVerifyOverlay() {
    if (document.getElementById("fld-verify-banner")) return;

    // Lock password fields during scan
    passwordInputs.forEach((input) => input.classList.add("fld-temporarily-locked"));

    const banner = document.createElement("div");
    banner.id = "fld-verify-banner";
    banner.innerHTML = `
      <div class="fld-spinner" aria-hidden="true"></div>
      <span>Verifying this login page...</span>
    `;
    document.body.appendChild(banner);
  }

  function hideVerifyOverlay() {
    const banner = document.getElementById("fld-verify-banner");
    if (banner) {
      banner.classList.add("fld-fade-out");
      setTimeout(() => banner.remove(), 300);
    }
    // Unlock password inputs
    passwordInputs.forEach((input) => input.classList.remove("fld-temporarily-locked"));
  }
})();
