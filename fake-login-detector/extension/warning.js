/**
 * warning.js — Interactive logic for the warning interstitial page.
 */
import { charDiff, parseUrl, registrableDomain } from "./lib/localCheck.js";

document.addEventListener("DOMContentLoaded", async () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("target") || "";
  const brandName = params.get("brand") || "a protected brand";
  const score = parseInt(params.get("score") || "85", 10);
  const genuineUrl = params.get("genuine") || "";
  let reasons = [];

  try {
    const rawReasons = params.get("reasons");
    if (rawReasons) {
      reasons = JSON.parse(rawReasons);
    }
  } catch {
    reasons = [
      {
        title: "Suspected Phishing Clone",
        detail: "The site matches characteristics of a fraudulent replica portal.",
      },
    ];
  }

  // Populate brand details
  const brandNameEl = document.getElementById("brand-name");
  const targetBrandEl = document.getElementById("target-brand");
  if (brandNameEl) brandNameEl.textContent = brandName;
  if (targetBrandEl) targetBrandEl.textContent = brandName;

  // Populate risk score
  const scoreEl = document.getElementById("risk-score");
  if (scoreEl) {
    scoreEl.textContent = `${score} / 100`;
  }

  // Populate domain diff highlight
  const parsedTarget = parseUrl(targetUrl);
  const parsedGenuine = parseUrl(genuineUrl);

  const genuineDomainEl = document.getElementById("genuine-domain");
  const diffContainerEl = document.getElementById("domain-diff-highlight");

  const suspectHost = parsedTarget?.hostname || targetUrl;
  const genuineHost = parsedGenuine?.hostname || (brandName.toLowerCase().includes("college") ? "portal.college.edu" : "genuine-portal.com");

  if (genuineDomainEl) genuineDomainEl.textContent = genuineHost;

  if (diffContainerEl) {
    const suspectLabel = registrableDomain(suspectHost).split(".")[0];
    const genuineLabel = registrableDomain(genuineHost).split(".")[0];
    const diff = charDiff(suspectLabel, genuineLabel);

    if (diff.length > 0) {
      diffContainerEl.innerHTML = "";
      diff.forEach((item) => {
        const span = document.createElement("span");
        span.className = `diff-char ${item.status}`;
        span.textContent = item.char;
        if (item.status === "substituted" && item.expected) {
          span.title = `Impersonating: '${item.expected}'`;
        }
        diffContainerEl.appendChild(span);
      });
      // Append remaining host suffix
      const suffix = suspectHost.replace(suspectLabel, "");
      const suffixSpan = document.createElement("span");
      suffixSpan.className = "diff-char match";
      suffixSpan.textContent = suffix;
      diffContainerEl.appendChild(suffixSpan);
    } else {
      diffContainerEl.textContent = suspectHost;
    }
  }

  // Populate Top Reasons (max 3)
  const reasonsListEl = document.getElementById("reasons-list");
  if (reasonsListEl) {
    reasonsListEl.innerHTML = "";
    const topReasons = reasons.slice(0, 3);
    topReasons.forEach((r) => {
      const li = document.createElement("li");
      li.className = "reason-item";
      li.innerHTML = `
        <span class="reason-icon">⚠️</span>
        <div>
          <strong>${escapeHtml(r.title || "Detected Signal")}</strong>:
          ${escapeHtml(r.detail || "")}
        </div>
      `;
      reasonsListEl.appendChild(li);
    });
  }

  // Wire "View Full Analysis" button
  const reportBtn = document.getElementById("btn-full-report");
  if (reportBtn) {
    const fullAnalysisUrl = `http://localhost:8000/?url=${encodeURIComponent(targetUrl)}${genuineUrl ? `&genuine=${encodeURIComponent(genuineUrl)}` : ""}`;
    reportBtn.href = fullAnalysisUrl;
    reportBtn.addEventListener("click", (e) => {
      e.preventDefault();
      if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url: fullAnalysisUrl });
      } else {
        window.open(fullAnalysisUrl, "_blank", "noopener,noreferrer");
      }
    });
  }

  // Wire "Go Back to Safety"
  const safetyBtn = document.getElementById("btn-safety");
  if (safetyBtn) {
    safetyBtn.addEventListener("click", () => {
      if (genuineUrl) {
        window.location.href = genuineUrl;
      } else if (window.history.length > 1) {
        window.history.back();
      } else {
        window.close();
      }
    });
  }

  // Wire "Proceed anyway" with 2nd step confirmation
  const proceedBtn = document.getElementById("btn-proceed");
  const confirmBox = document.getElementById("proceed-confirm");
  const cancelProceedBtn = document.getElementById("btn-cancel-proceed");
  const confirmProceedBtn = document.getElementById("btn-confirm-proceed");

  if (proceedBtn && confirmBox) {
    proceedBtn.addEventListener("click", () => {
      confirmBox.classList.remove("hidden");
      proceedBtn.classList.add("hidden");
    });
  }

  if (cancelProceedBtn && confirmBox && proceedBtn) {
    cancelProceedBtn.addEventListener("click", () => {
      confirmBox.classList.add("hidden");
      proceedBtn.classList.remove("hidden");
    });
  }

  if (confirmProceedBtn && targetUrl) {
    confirmProceedBtn.addEventListener("click", async () => {
      try {
        const origin = new URL(targetUrl).origin;
        // Store 10-minute temporary bypass in session storage
        const key = `bypass_${origin}`;
        await chrome.storage.session.set({
          [key]: Date.now() + 10 * 60 * 1000,
        });
      } catch (err) {
        console.warn("Storage session not available:", err);
      }
      // Redirect to the suspect target
      window.location.href = targetUrl;
    });
  }
});

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text || "";
  return div.innerHTML;
}
