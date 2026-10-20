/**
 * background.js — Service worker orchestrating Tier 1, Tier 2, and Tier 3 protection.
 */
import { checkDomain, originKey, parseUrl } from "./lib/localCheck.js";

const BACKEND_URL = "http://localhost:8000";
const VERIFY_TIMEOUT_MS = 8000;
const SESSION_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

let brandsRegistry = [];

// ── Startup & Brand Registry Loader ──────────────────────────────────────────

async function loadBrands() {
  try {
    const url = chrome.runtime.getURL("data/brands.json");
    const response = await fetch(url);
    const data = await response.json();
    brandsRegistry = data.brands || [];
    console.log(`[FLD] Loaded ${brandsRegistry.length} local brands.`);
  } catch (err) {
    console.error("[FLD] Failed to load local brands:", err);
  }

  // Attempt live sync from backend
  try {
    const res = await fetch(`${BACKEND_URL}/api/brands`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      const serverBrands = await res.json();
      if (Array.isArray(serverBrands) && serverBrands.length > 0) {
        brandsRegistry = serverBrands;
        console.log(`[FLD] Synced ${serverBrands.length} brands from backend.`);
      }
    }
  } catch {
    // Backend offline; local brands continue working seamlessly
  }
}

chrome.runtime.onInstalled.addListener(loadBrands);
chrome.runtime.onStartup.addListener(loadBrands);
loadBrands();

// ── Helpers ──────────────────────────────────────────────────────────────────

async function isOriginBypassed(url) {
  try {
    const origin = new URL(url).origin;
    const key = `bypass_${origin}`;
    const result = await chrome.storage.session.get(key);
    if (result && result[key] && result[key] > Date.now()) {
      return true;
    }
  } catch {
    // Storage session unavailable
  }
  return false;
}

async function getCachedVerdict(origin) {
  try {
    const key = `verdict_${origin}`;
    const result = await chrome.storage.session.get(key);
    if (result && result[key] && result[key].expiresAt > Date.now()) {
      return result[key];
    }
  } catch {
    // ignore
  }
  return null;
}

async function setCachedVerdict(origin, verdict, score) {
  try {
    const key = `verdict_${origin}`;
    await chrome.storage.session.set({
      [key]: {
        verdict,
        score,
        expiresAt: Date.now() + SESSION_CACHE_TTL_MS,
      },
    });
  } catch {
    // ignore
  }
}

function buildWarningUrl(targetUrl, result) {
  const genuineUrl = result.brand?.genuine_urls?.[0] || "";
  const params = new URLSearchParams({
    target: targetUrl,
    brand: result.brand?.name || "Genuine Portal",
    score: String(result.score || 85),
    genuine: genuineUrl,
    reasons: JSON.stringify(result.reasons || []),
  });
  return chrome.runtime.getURL(`warning.html?${params.toString()}`);
}

// ── Tier 1: Instant Local Pre-Navigation Guard ────────────────────────────────

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Main frame only
  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http://") && !details.url.startsWith("https://")) return;

  // Don't intercept the warning page itself or backend API
  if (details.url.includes("warning.html") || details.url.startsWith(BACKEND_URL)) return;

  // Check 10-minute user bypass
  if (await isOriginBypassed(details.url)) return;

  // Check session cache
  const origin = originKey(details.url);
  const cached = await getCachedVerdict(origin);
  if (cached && (cached.verdict === "genuine" || cached.verdict === "low_risk" || cached.verdict === "unrelated")) {
    return;
  }

  // Run Tier 1 heuristics
  const check = checkDomain(details.url, brandsRegistry);

  if (!check.isSafe && check.score >= 60) {
    console.warn(`[FLD Tier 1] Lookalike domain detected: ${details.url} (Score: ${check.score})`);
    const warnUrl = buildWarningUrl(details.url, check);
    chrome.tabs.update(details.tabId, { url: warnUrl });
  }
});

// ── Tier 2 & Tier 3: Form Inspection & Backend Verification ───────────────────

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.type !== "LOGIN_FORM_DETECTED") return;

  const tabId = sender.tab?.id;
  const pageUrl = message.url;
  const formActions = message.formActions || [];

  handleLoginDetected(tabId, pageUrl, formActions);
});

async function handleLoginDetected(tabId, pageUrl, formActions) {
  if (!pageUrl || !tabId) return;

  // 1. Check bypass
  if (await isOriginBypassed(pageUrl)) return;

  const pageOrigin = originKey(pageUrl);

  // 2. Check if page is known genuine origin
  for (const b of brandsRegistry) {
    const all = [...(b.origins || []), ...(b.trusted_related_origins || [])];
    if (all.some((o) => o.toLowerCase() === pageOrigin)) {
      // Verified brand site — allow immediately
      return;
    }
  }

  // 3. Tier 2: Foreign Form Action Instant Heuristic
  const foreignActions = formActions.filter((act) => {
    const actOrigin = originKey(act);
    return actOrigin && actOrigin !== pageOrigin;
  });

  const domainCheck = checkDomain(pageUrl, brandsRegistry);

  if (foreignActions.length > 0) {
    const firstForeign = foreignActions[0];
    const isLocalhostPair = pageOrigin.startsWith("localhost") && firstForeign.includes("localhost");

    // Foreign action with password input on non-registered site
    console.warn(`[FLD Tier 2] Foreign-origin password action detected: ${firstForeign}`);
    const reasons = [
      {
        code: "FORM_FOREIGN_ACTION",
        title: "Password sent to external server",
        detail: `The login form sends credentials to '${firstForeign}' rather than '${pageOrigin}'.`,
        severity: "critical",
      },
      ...domainCheck.reasons,
    ];

    const warningResult = {
      score: Math.max(90, domainCheck.score),
      brand: domainCheck.brand || { name: "Protected Organization", genuine_urls: ["http://localhost:5001/login"] },
      reasons,
    };

    const warnUrl = buildWarningUrl(pageUrl, warningResult);
    chrome.tabs.update(tabId, { url: warnUrl });
    return;
  }

  // 4. Tier 3: Backend Verification
  // Show non-intrusive overlay banner and disable password inputs while verifying
  chrome.tabs.sendMessage(tabId, { type: "SHOW_VERIFY_OVERLAY" }).catch(() => {});

  let backendSuccess = false;

  try {
    // Call POST /api/quick-check with 8 second timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), VERIFY_TIMEOUT_MS);

    const res = await fetch(`${BACKEND_URL}/api/quick-check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: pageUrl,
        form_actions: formActions,
        has_password: true,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      backendSuccess = true;
      const data = await res.json();

      if (data.verdict === "likely_clone" || (data.verdict === "suspicious" && data.score >= 60)) {
        console.warn(`[FLD Tier 3] Backend confirmed suspicious clone: ${pageUrl} (Score: ${data.score})`);
        const warnUrl = buildWarningUrl(pageUrl, {
          score: data.score,
          brand: data.brand ? { name: data.brand } : domainCheck.brand,
          reasons: data.reasons || domainCheck.reasons,
        });
        chrome.tabs.update(tabId, { url: warnUrl });
        return;
      } else {
        // Safe / Unrelated verdict
        await setCachedVerdict(pageOrigin, data.verdict, data.score);
      }
    }
  } catch (err) {
    console.warn("[FLD Tier 3] Backend quick-check unreachable or timed out:", err.message);
  } finally {
    // Hide overlay banner and re-enable password input
    chrome.tabs.sendMessage(tabId, { type: "HIDE_VERIFY_OVERLAY" }).catch(() => {});
  }

  // Optional: Trigger full scan in background for dashboard/artifacts without blocking UI
  if (backendSuccess) {
    fetch(`${BACKEND_URL}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: pageUrl, mode: "fast" }),
    }).catch(() => {});
  }
}
