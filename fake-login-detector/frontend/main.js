import { scanUrl } from "./api.js";
import { renderGauge } from "./gauge.js";
import { renderCompare } from "./compare.js";
import { renderReasons } from "./reasons.js";
import { renderBreakdown } from "./breakdown.js";
import { renderDomain } from "./domainHighlight.js";
import { renderReportButtons, wireReportButtons } from "./report.js";

const input = document.getElementById("url-input");
const genuineInput = document.getElementById("genuine-url-input");
const button = document.getElementById("scan-btn");
const results = document.getElementById("results");
const verdictBox = document.getElementById("verdict-box");
const compareBox = document.getElementById("compare-box");
const reasonsBox = document.getElementById("reasons-box");
const breakdownBox = document.getElementById("breakdown-box");

const domainBox = document.createElement("div");
domainBox.id = "domain-box";
verdictBox.after(domainBox);

const attackBox = document.createElement("div");
attackBox.id = "attack-box";
domainBox.after(attackBox);

const reportBox = document.createElement("div");
reportBox.id = "report-box";
breakdownBox.after(reportBox);

function escapeHtml(value) {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character],
  );
}

function showMessage(message, heading = "Scan could not be completed") {
  verdictBox.innerHTML = `
    <div class="card">
      <h2>${escapeHtml(heading)}</h2>
      <p>${escapeHtml(message)}</p>
    </div>
  `;
}

function getVerdictLabel(verdict) {
  const labels = {
    genuine: "Genuine",
    low_risk: "Low Risk",
    suspicious: "Suspicious",
    likely_clone: "Likely Clone",
    unrelated: "Unrelated",
  };

  return labels[verdict] || "Result unavailable";
}

function isOwnDetectorHomepage(url) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    return (
      (hostname === "localhost" || hostname === "127.0.0.1") &&
      (parsed.port === "8080" || parsed.port === "8000") &&
      (parsed.pathname === "/" || parsed.pathname === "")
    );
  } catch {
    return false;
  }
}

function clearResultSections() {
  domainBox.innerHTML = "";
  attackBox.innerHTML = "";
  compareBox.innerHTML = "";
  reasonsBox.innerHTML = "";
  breakdownBox.innerHTML = "";
  reportBox.innerHTML = "";
}

function renderDetectorHomepageMessage(scannedUrl) {
  verdictBox.innerHTML = `
    <div class="card verdict-card">
      <div class="verdict-heading">
        <span class="verdict-eyebrow">SECURITY SCAN REPORT</span>
        <h2>Detector Homepage</h2>
      </div>

      <p>
        This is the Fake Login Page Detector interface, not a login page
        being evaluated for impersonation.
      </p>

      <p class="domain-note">
        Login-page clone comparison is not applicable to this page.
        This is not a safety verdict.
      </p>

      <p class="domain-note">
        URL scanned: ${escapeHtml(scannedUrl)}
      </p>
    </div>
  `;
}

function renderInsufficientEvidence(data, url) {
  showMessage(
    data.summary ||
    "The scan did not collect enough reliable evidence. This does not mean the page is safe.",
    "No reliable safety verdict",
  );

  // Retain the URL so the user knows what was scanned.
  const scannedUrl = data.suspect_url || url;

  verdictBox.insertAdjacentHTML(
    "beforeend",
    `<p class="domain-note">URL scanned: ${escapeHtml(scannedUrl)}</p>`,
  );
}

function renderNormalVerdict(data, url, isPartial) {
  verdictBox.innerHTML = `
    <div class="card verdict-card verdict-${escapeHtml(data.verdict)}">
      <div class="verdict-heading">
        <span class="verdict-eyebrow">SECURITY SCAN REPORT</span>
        <h2>${escapeHtml(getVerdictLabel(data.verdict))}</h2>
      </div>

      ${renderGauge(data.score, data.verdict)}

      <p>${escapeHtml(data.summary || "No additional summary is available.")}</p>

      ${isPartial
      ? `<p class="domain-note">
               Warning: This scan was incomplete. Treat the result as uncertain.
             </p>`
      : ""
    }

      <p class="domain-note">
        URL scanned: ${escapeHtml(data.suspect_url || url)}
      </p>
    </div>
  `;
}

function renderDomainSection(data, url) {
  const suspectUrl = data.suspect_url || url;
  const genuineUrl = data.genuine_url || "";

  let genuineHost = "";
  let suspectHost = "";

  try {
    genuineHost = genuineUrl ? new URL(genuineUrl).host : "";
  } catch {
    genuineHost = "";
  }

  try {
    suspectHost = new URL(suspectUrl).host;
  } catch {
    suspectHost = suspectUrl;
  }

  if (genuineHost && suspectHost) {
    domainBox.innerHTML = renderDomain(genuineHost, suspectHost);
    return;
  }

  domainBox.innerHTML = `
    <div class="card">
      <h3>Web address check</h3>
      <p>${genuineUrl
      ? "The genuine reference page could not be captured."
      : "No genuine reference page was available for comparison."
    }</p>
      <p class="domain fake">
        ${escapeHtml(suspectHost)}
      </p>
    </div>
  `;
}

function renderFormSection(data) {
  const form = data.form_comparison;

  if (form && (form.suspect_action || form.genuine_action)) {
    attackBox.innerHTML = `
      <div class="card">
        <h3>Login form destination</h3>

        <p><strong>Scanned page sends to:</strong></p>
        <p>${escapeHtml(form.suspect_action || "Not detected")}</p>

        <p><strong>Reference page sends to:</strong></p>
        <p>${escapeHtml(form.genuine_action || "Not available")}</p>
${form.suspect_action &&
        form.genuine_action &&
        (() => {
          try {
            const suspectOrigin = new URL(form.suspect_action).origin;
            const genuineOrigin = new URL(form.genuine_action).origin;

            return suspectOrigin !== genuineOrigin;
          } catch {
            return false;
          }
        })()
        ? `<p class="domain-note">
         Warning: The scanned page's form submits to a different origin
         than the reference page's form.
       </p>`
        : !form.genuine_action && form.is_cross_origin
          ? `<p class="domain-note">
           Warning: The scanned page's form submits to a different origin
           than the page itself.
         </p>`
          : ""
      }
      </div>
    `;
  } else {
    attackBox.innerHTML = `
      <div class="card">
        <h3>Login form destination</h3>
        <p>No form-action comparison was available for this scan.</p>
      </div>
    `;
  }
}

function renderEvidenceSections(data) {
  compareBox.innerHTML = renderCompare(data.images);

  if (Array.isArray(data.reasons) && data.reasons.length > 0) {
    reasonsBox.innerHTML = renderReasons(data.reasons);
  } else {
    reasonsBox.innerHTML = `
      <div class="card">
        <h3>Evidence</h3>
        <p>No specific evidence items were returned by the analyzers.</p>
      </div>
    `;
  }

  if (Array.isArray(data.signals) && data.signals.length > 0) {
    breakdownBox.innerHTML = renderBreakdown(data.signals);
  } else {
    breakdownBox.innerHTML = `
      <div class="card">
        <h3>Score breakdown</h3>
        <p>No analyzer breakdown is available.</p>
      </div>
    `;
  }

  reportBox.innerHTML = renderReportButtons();
  wireReportButtons(data);
}

button.addEventListener("click", async () => {
  const url = input.value.trim();

  if (!url) {
    alert("Please paste a URL first.");
    input.focus();
    return;
  }

  button.disabled = true;
  button.textContent = "Scanning...";
  results.classList.remove("hidden");

  verdictBox.innerHTML = `
    <div class="card">
      <h2>Scanning page...</h2>
      <p>Analyzing the URL and collecting available evidence. Please wait.</p>
    </div>
  `;

  clearResultSections();

  try {
    const data = await scanUrl(url, genuineInput?.value || "");

    if (!data || typeof data.score !== "number" || !data.verdict) {
      throw new Error("The backend returned an invalid scan result.");
    }

    const scannedUrl = data.suspect_url || url;
    const isPartial = data.partial === true;
    const isDetectorHomepage = isOwnDetectorHomepage(scannedUrl);
    const isFailure = data.verdict === "unrelated" && isPartial;

    // Special case: the detector homepage is not a phishing-login candidate.
    if (isDetectorHomepage) {
      renderDetectorHomepageMessage(scannedUrl);
      clearResultSections();
      return;
    }

    // Incomplete unrelated scans should not be presented as reliable verdicts.
    if (isFailure) {
      renderInsufficientEvidence(data, url);
    } else {
      renderNormalVerdict(data, url, isPartial);
    }

    // Render detailed results only for normal website scans.
    renderDomainSection(data, url);
    renderFormSection(data);
    renderEvidenceSections(data);
  } catch (error) {
    console.error("Scan error:", error);

    clearResultSections();

    showMessage(
      error instanceof Error
        ? error.message
        : "An unexpected error occurred. Check the backend terminal.",
    );
  } finally {
    button.disabled = false;
    button.textContent = "Scan";
  }
});

// Auto-populate inputs and trigger scan if query parameters are present (?url=... or ?target=...)
function initFromUrlParams() {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || params.get("target");
  const genuineUrl = params.get("genuine") || params.get("genuine_url");

  if (targetUrl && input) {
    input.value = targetUrl;
    if (genuineUrl && genuineInput) {
      genuineInput.value = genuineUrl;
    }
    setTimeout(() => {
      if (button && !button.disabled) {
        button.click();
      }
    }, 150);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initFromUrlParams);
} else {
  initFromUrlParams();
}

