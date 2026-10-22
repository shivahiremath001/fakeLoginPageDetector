/**
 * localCheck.js — Domain lookalike and URL heuristic analysis for the extension.
 *
 * Implements Tier 1 client-side protection: instant, offline, deterministic.
 * Parity guaranteed against backend/app/analyzers/domain.py and
 * backend/app/utils/confusables.py via shared/domain_test_vectors.json.
 */

// ── Digit-to-letter substitutions (leet-speak) ───────────────────────────────
export const DIGIT_SUBS = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "6": "g",
  "7": "t",
  "8": "b",
};

// ── Cyrillic, Greek, and Fullwidth Unicode lookalikes ─────────────────────────
export const UNICODE_LOOKALIKES = {
  // Cyrillic
  "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
  "\u0445": "x", "\u0455": "s", "\u0456": "i", "\u0454": "e", "\u0405": "s",
  "\u0406": "i", "\u0410": "a", "\u0412": "b", "\u0415": "e", "\u041a": "k",
  "\u041c": "m", "\u041d": "h", "\u041e": "o", "\u0420": "p", "\u0421": "c",
  "\u0422": "t", "\u0425": "x",
  // Greek
  "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b7": "n", "\u03b9": "i",
  "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c5": "u", "\u03c7": "x",
  "\u0391": "a", "\u0392": "b", "\u0395": "e", "\u0396": "z", "\u0397": "h",
  "\u0399": "i", "\u039a": "k", "\u039c": "m", "\u039d": "n", "\u039f": "o",
  "\u03a1": "p", "\u03a4": "t", "\u03a5": "y", "\u03a7": "x",
};

// Add fullwidth ASCII (0xFF01-0xFF5E → 0x21-0x7E)
for (let i = 0; i < 94; i++) {
  UNICODE_LOOKALIKES[String.fromCharCode(0xff01 + i)] = String.fromCharCode(0x21 + i);
}

// ── Multi-character substitutions ───────────────────────────────────────────
export const MULTI_CHAR_SUBS = [
  ["rn", "m"],
  ["vv", "w"],
  ["cl", "d"],
  ["li", "h"],
];

// ── Default lists ───────────────────────────────────────────────────────────
export const PHISHING_KEYWORDS = [
  "login", "secure", "verify", "account", "portal", "update", "signin",
];

export const RISKY_TLDS = new Set([
  "xyz", "tk", "top", "pw", "cc", "club", "live", "work", "click", "link", "zip",
]);

/**
 * Reduce a domain label or brand name to a canonical ASCII skeleton.
 */
export function skeleton(label) {
  if (!label || typeof label !== "string") return "";

  try {
    let s = label.toLowerCase().trim();

    // Per-character substitutions
    let substituted = "";
    for (const ch of s) {
      let mapped = UNICODE_LOOKALIKES[ch] || ch;
      mapped = DIGIT_SUBS[mapped] || mapped;
      substituted += mapped;
    }
    s = substituted;

    // Multi-character substitutions
    for (const [pattern, replacement] of MULTI_CHAR_SUBS) {
      s = s.replaceAll(pattern, replacement);
    }

    // Strip everything that is not a-z
    let clean = "";
    for (let i = 0; i < s.length; i++) {
      const code = s.charCodeAt(i);
      if (code >= 97 && code <= 122) { // a-z
        clean += s[i];
      }
    }
    return clean;
  } catch {
    return (label || "").toLowerCase();
  }
}

/**
 * Calculate Levenshtein distance between two strings.
 */
export function levenshteinDistance(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  const matrix = Array.from({ length: a.length + 1 }, () => new Int32Array(b.length + 1));
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[a.length][b.length];
}

/**
 * Normalized Levenshtein similarity ratio between 0.0 and 1.0.
 */
export function levenshteinSimilarity(a, b) {
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1.0;
  const dist = levenshteinDistance(a, b);
  return 1.0 - dist / maxLen;
}

/**
 * Safely parse a URL string into components without throwing.
 */
export function parseUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return null;
  try {
    const url = new URL(rawUrl.includes("://") ? rawUrl.trim() : `http://${rawUrl.trim()}`);
    return url;
  } catch {
    return null;
  }
}

/**
 * Return normalized origin key (e.g. "localhost:5001" or "example.com").
 */
export function originKey(rawUrl) {
  const parsed = parseUrl(rawUrl);
  if (!parsed) return "";
  const host = parsed.hostname.toLowerCase();
  const port = parsed.port;
  const scheme = parsed.protocol.replace(":", "");
  const isDefaultPort = (scheme === "http" && port === "80") || (scheme === "https" && port === "443") || !port;
  return isDefaultPort ? host : `${host}:${port}`;
}

/**
 * Check if a host is an IPv4 or IPv6 address.
 */
export function isIpAddress(host) {
  if (!host) return false;
  // IPv4
  const ipv4Match = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  if (ipv4Match) {
    const parts = host.split(".").map(Number);
    return parts.every(p => p >= 0 && p <= 255);
  }
  // IPv6
  return host.includes(":") && !host.includes(".");
}

/**
 * Character-level diff between suspect label and brand label.
 */
export function charDiff(suspectLabel, brandLabel) {
  if (!suspectLabel || !brandLabel) return [];
  const s = suspectLabel.toLowerCase();
  const b = brandLabel.toLowerCase();
  const diff = [];

  const maxLen = Math.max(s.length, b.length);
  for (let i = 0; i < maxLen; i++) {
    const sc = s[i];
    const bc = b[i];
    if (sc === undefined) {
      diff.push({ char: bc, status: "missing" });
    } else if (bc === undefined) {
      diff.push({ char: sc, status: "extra" });
    } else if (sc === bc) {
      diff.push({ char: sc, status: "match" });
    } else {
      diff.push({ char: sc, status: "substituted", expected: bc });
    }
  }
  return diff;
}

/**
 * Extract the registrable domain (best-effort offline without public suffix list download).
 */
export function registrableDomain(host) {
  if (!host || isIpAddress(host) || host === "localhost" || host.endsWith(".localhost")) {
    return host;
  }
  const parts = host.split(".");
  if (parts.length <= 2) return host;

  const twoPartSuffixes = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.in", "firm.in", "net.in", "org.in",
    "com.br", "com.cn", "co.jp",
  ]);

  const suffix = parts.slice(-2).join(".");
  if (twoPartSuffixes.has(suffix) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

/**
 * Check if a brand label is maliciously embedded in a subdomain.
 * For example: college.edu.evil.com (trick) vs portal.college.edu (not a trick).
 */
export function isBrandInSubdomain(host, brandLabel) {
  if (!host || !brandLabel) return false;
  const regDomain = registrableDomain(host);
  const regParts = regDomain.split(".");
  const hostParts = host.split(".");
  const subdomains = hostParts.slice(0, hostParts.length - regParts.length);

  if (subdomains.length === 0) return false;

  // Generic service subdomains on legitimate domains are not brand phishing tricks
  const commonServicePrefixes = new Set(["www", "portal", "login", "mail", "webmail", "auth", "sso", "app", "secure"]);
  if (commonServicePrefixes.has(brandLabel.toLowerCase()) && subdomains.length <= 1) {
    return false;
  }

  return subdomains.some(sub => sub.toLowerCase() === brandLabel.toLowerCase() || sub.toLowerCase().includes(brandLabel.toLowerCase()));
}

/**
 * Tier 1 analysis: runs on beforeNavigate against data/brands.json.
 *
 * @param {string} targetUrl - URL to evaluate
 * @param {Array<Object>} brands - Registry of brands from brands.json
 * @returns {Object} { isSafe, score, brand, reasons, diff }
 */
export function checkDomain(targetUrl, brands = []) {
  const parsed = parseUrl(targetUrl);
  if (!parsed) {
    return { isSafe: true, score: 0, brand: null, reasons: [], diff: [] };
  }

  const targetOrigin = originKey(targetUrl);
  const host = parsed.hostname.toLowerCase();
  const rawUrl = targetUrl.toLowerCase();

  // 1. Same-origin check against all known brands
  for (const b of brands) {
    const allOrigins = [...(b.origins || []), ...(b.trusted_related_origins || [])];
    if (allOrigins.some(o => o.toLowerCase() === targetOrigin)) {
      return {
        isSafe: true,
        score: 0,
        brand: b,
        reasons: [{
          code: "SAME_ORIGIN",
          title: "Genuine Origin",
          detail: `Origin matches verified genuine brand: ${b.name}`,
          severity: "info",
        }],
        diff: [],
      };
    }
  }

  let totalScore = 0.0;
  const reasons = [];
  let matchedBrand = null;
  let bestDiff = [];

  // 2. Misleading Userinfo (@ trick)
  if (parsed.username || parsed.password) {
    totalScore = Math.max(totalScore, 0.65);
    reasons.push({
      code: "DOMAIN_USERINFO_TRICK",
      title: "Misleading URL credentials",
      detail: "The URL contains text before the @ symbol that could be mistaken for the actual website hostname.",
      severity: "high",
    });
  }

  // 3. IP address host
  if (isIpAddress(host)) {
    totalScore = Math.max(totalScore, 0.50);
    reasons.push({
      code: "DOMAIN_IP_ADDRESS",
      title: "IP address used as hostname",
      detail: "The website is addressed directly by an IP address rather than a domain name.",
      severity: "medium",
    });
  }

  const labels = host.split(".");
  const regDomain = registrableDomain(host);
  const suspectLabel = regDomain.split(".")[0];
  const suspectSkeleton = skeleton(suspectLabel);

  // 4. Punycode (xn--)
  if (labels.some(l => l.startsWith("xn--"))) {
    totalScore = Math.max(totalScore, 0.55);
    reasons.push({
      code: "DOMAIN_PUNYCODE",
      title: "Encoded hostname label",
      detail: "The hostname contains an IDN punycode label which can disguise lookalike characters.",
      severity: "medium",
    });
  }

  // 5. Risky TLD
  const tld = labels[labels.length - 1];
  if (tld && RISKY_TLDS.has(tld)) {
    totalScore += 0.15;
    reasons.push({
      code: "DOMAIN_RISKY_TLD",
      title: "Configured high-risk domain ending",
      detail: `The hostname uses a high-risk TLD (.${tld}).`,
      severity: "low",
    });
  }

  // 6. Phishing keywords
  const matchedKeywords = PHISHING_KEYWORDS.filter(kw => host.includes(kw));
  if (matchedKeywords.length > 0) {
    totalScore += 0.20;
    reasons.push({
      code: "DOMAIN_SUSPICIOUS_KEYWORD",
      title: "Security-related hostname wording",
      detail: `The hostname contains common phishing keywords: ${matchedKeywords.join(", ")}`,
      severity: "low",
    });
  }

  // 7. Double hyphen or excessive subdomains
  if (host.includes("--")) {
    totalScore += 0.10;
    reasons.push({
      code: "DOMAIN_DOUBLE_HYPHEN",
      title: "Consecutive hyphens in hostname",
      detail: "The hostname contains consecutive hyphens frequently seen in phishing domains.",
      severity: "low",
    });
  }
  if (labels.length >= 5) {
    totalScore += 0.10;
    reasons.push({
      code: "DOMAIN_MANY_SUBDOMAINS",
      title: "Unusually deep subdomain structure",
      detail: `Hostname contains ${labels.length} levels of subdomains.`,
      severity: "low",
    });
  }

  // 8. Brand Lookalike Evaluation
  for (const b of brands) {
    // Check aliases for testing
    if ((b.aliases_for_local_testing || []).some(a => a.toLowerCase() === host)) {
      matchedBrand = b;
      totalScore = Math.max(totalScore, 0.85);
      reasons.push({
        code: "DOMAIN_ALIAS_MATCH",
        title: "Test lookalike hostname alias",
        detail: `Hostname matches configured lookalike alias for ${b.name}.`,
        severity: "critical",
      });
      break;
    }

    // Check protected lookalike labels
    const brandLabels = b.lookalike_labels || [];
    for (const bl of brandLabels) {
      const blSkel = skeleton(bl);
      if (!blSkel) continue;

      // Skeleton exact match
      if (suspectSkeleton === blSkel && suspectLabel.toLowerCase() !== bl.toLowerCase()) {
        totalScore = Math.max(totalScore, 0.85);
        matchedBrand = b;
        bestDiff = charDiff(suspectLabel, bl);
        reasons.push({
          code: "DOMAIN_CONFUSABLE_BRAND",
          title: "Lookalike brand domain",
          detail: `The domain '${suspectLabel}' is a visual lookalike for protected brand '${b.name}' (${bl}).`,
          severity: "critical",
        });
        break;
      }

      // Levenshtein close match
      const sim = levenshteinSimilarity(suspectSkeleton, blSkel);
      if (sim >= 0.80 && suspectLabel.toLowerCase() !== bl.toLowerCase() && suspectLabel.length >= 4) {
        totalScore = Math.max(totalScore, 0.70);
        matchedBrand = b;
        bestDiff = charDiff(suspectLabel, bl);
        reasons.push({
          code: "DOMAIN_SIMILAR_BRAND",
          title: "Domain resembles a known brand",
          detail: `The domain '${suspectLabel}' is very similar to protected brand label '${bl}'.`,
          severity: "high",
        });
        break;
      }

      // Brand label in subdomain of another registered domain (e.g. college.edu.evil.com)
      if (host.includes(bl) && regDomain !== bl && !regDomain.startsWith(bl + ".")) {
        totalScore = Math.max(totalScore, 0.60);
        matchedBrand = b;
        reasons.push({
          code: "DOMAIN_BRAND_IN_OTHER_DOMAIN",
          title: "Brand label embedded in another domain",
          detail: `The brand name '${bl}' appears inside a foreign domain (${regDomain}).`,
          severity: "high",
        });
        break;
      }
    }
  }

  const finalScore = Math.min(1.0, Math.max(0.0, totalScore));
  const isSafe = finalScore < 0.60;

  return {
    isSafe,
    score: Math.round(finalScore * 100),
    brand: matchedBrand,
    reasons,
    diff: bestDiff,
  };
}
