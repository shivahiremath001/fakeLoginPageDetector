/**
 * test_vectors.js — Node.js parity test runner for shared/domain_test_vectors.json
 *
 * Verifies that extension/lib/localCheck.js behaves identically to Python backend.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import {
  skeleton,
  levenshteinSimilarity,
  isIpAddress,
  originKey,
  parseUrl,
  registrableDomain,
  isBrandInSubdomain,
  PHISHING_KEYWORDS,
  RISKY_TLDS,
} from "../lib/localCheck.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const vectorsPath = path.resolve(__dirname, "../../shared/domain_test_vectors.json");
const data = JSON.parse(fs.readFileSync(vectorsPath, "utf-8"));

let passed = 0;
let failed = 0;

for (const vec of data.vectors) {
  try {
    if ("expect_skeleton_match" in vec) {
      const s1 = skeleton(vec.label);
      const s2 = skeleton(vec.brand);
      const matches = s1 === s2 && s1.length > 0;
      if (matches !== vec.expect_skeleton_match) {
        throw new Error(
          `skeleton match mismatch: label='${vec.label}' -> '${s1}', brand='${vec.brand}' -> '${s2}', expected ${vec.expect_skeleton_match}`
        );
      }
    }

    if ("expect_brand_in_subdomain" in vec) {
      const isTrick = isBrandInSubdomain(vec.brand_in_subdomain, vec.brand);
      if (isTrick !== vec.expect_brand_in_subdomain) {
        throw new Error(`brand_in_subdomain expected ${vec.expect_brand_in_subdomain}, got ${isTrick}`);
      }
    }

    if ("is_ip" in vec) {
      const parsed = parseUrl(vec.url);
      const ip = isIpAddress(parsed?.hostname);
      if (ip !== vec.is_ip) {
        throw new Error(`is_ip expected ${vec.is_ip}, got ${ip}`);
      }
    }

    if ("has_userinfo" in vec) {
      const parsed = parseUrl(vec.url);
      const userinfo = Boolean(parsed?.username || parsed?.password);
      if (userinfo !== vec.has_userinfo) {
        throw new Error(`has_userinfo expected ${vec.has_userinfo}, got ${userinfo}`);
      }
    }

    if ("has_phishing_keyword" in vec) {
      const hasKw = PHISHING_KEYWORDS.some((kw) => vec.host.includes(kw));
      if (hasKw !== vec.has_phishing_keyword) {
        throw new Error(`has_phishing_keyword expected ${vec.has_phishing_keyword}, got ${hasKw}`);
      }
    }

    if ("risky_tld" in vec) {
      const tld = vec.host.split(".").pop();
      const isRisky = RISKY_TLDS.has(tld);
      if (isRisky !== vec.risky_tld) {
        throw new Error(`risky_tld expected ${vec.risky_tld}, got ${isRisky}`);
      }
    }

    if ("excessive_subdomains" in vec) {
      const isExcessive = vec.host.split(".").length >= 5;
      if (isExcessive !== vec.excessive_subdomains) {
        throw new Error(`excessive_subdomains expected ${vec.excessive_subdomains}, got ${isExcessive}`);
      }
    }

    if ("double_hyphen" in vec) {
      const hasDouble = vec.host.includes("--");
      if (hasDouble !== vec.double_hyphen) {
        throw new Error(`double_hyphen expected ${vec.double_hyphen}, got ${hasDouble}`);
      }
    }

    if ("expect_different_origin" in vec) {
      const o1 = originKey(vec.url);
      const isDiff = o1 !== vec.genuine_origin;
      if (isDiff !== vec.expect_different_origin) {
        throw new Error(`expect_different_origin expected ${vec.expect_different_origin}, got ${isDiff} (${o1} vs ${vec.genuine_origin})`);
      }
    }

    if ("expect_levenshtein_close" in vec) {
      const sim = levenshteinSimilarity(skeleton(vec.label), skeleton(vec.brand));
      const isClose = sim >= 0.70;
      if (isClose !== vec.expect_levenshtein_close) {
        throw new Error(`expect_levenshtein_close expected ${vec.expect_levenshtein_close}, got sim=${sim}`);
      }
    }

    passed++;
  } catch (err) {
    failed++;
    console.error(`❌ Vector [${vec.id}] FAILED:`, err.message);
  }
}

console.log(`\nDomain Test Vectors Parity Results:`);
console.log(`Total: ${data.vectors.length}`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log(`✅ All vectors passed with 100% parity!`);
}
