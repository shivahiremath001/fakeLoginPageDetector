# Fake Login Page Detector (Comprehensive Technical Specification & Architecture Manual)

> **Document Version:** 1.0.0  
> **System Name:** Fake Login Page Detector (FLPD) / PhishGuard Deep Analyzer  
> **Core Objective:** Real-time, deterministic, multi-modal detection and explainable forensics of credential-harvesting phishing portals and deceptive lookalike websites.  
> **Primary Technology Stack:** Python 3.13, FastAPI, Playwright (Headless Chromium), PIL (Pillow), ImageHash, OpenCV / scikit-image SSIM, Vanilla JS (ES Modules), W3C WebExtensions Manifest V3.

---

## Table of Contents

1. [Executive Summary & Problem Statement](#1-executive-summary--problem-statement)
2. [High-Level Architecture & End-to-End Workflow](#2-high-level-architecture--end-to-end-workflow)
3. [Repository Topology & Directory Breakdown](#3-repository-topology--directory-breakdown)
4. [The 5 Multi-Modal Detection Analyzers](#4-the-5-multi-modal-detection-analyzers)
   - 4.1 [Domain & Hostname Analyzer (domain.py)](#41-domain--hostname-analyzer-domainpy)
   - 4.2 [Form & Action Analyzer (orm.py)](#42-form--action-analyzer-formpy)
   - 4.3 [DOM & Structural Analyzer (dom.py)](#43-dom--structural-analyzer-dompy)
   - 4.4 [Visual & Perceptual Analyzer (isual.py)](#44-visual--perceptual-analyzer-visualpy)
   - 4.5 [Asset & Network Request Analyzer (ssets.py)](#45-asset--network-request-analyzer-assetspy)
5. [Scoring Engine, Weighted Contribution & Overrides](#5-scoring-engine-weighted-contribution--overrides)
   - 5.1 [Base Weighted Formula](#51-base-weighted-formula)
   - 5.2 [Dynamic Missing-Signal Normalization](#52-dynamic-missing-signal-normalization)
   - 5.3 [Deterministic Hard Override Rules (R1 - R4)](#53-deterministic-hard-override-rules-r1---r4)
   - 5.4 [Verdicts & Qualitative Thresholds](#54-verdicts--qualitative-thresholds)
6. [Backend Core Architecture (FastAPI & Playwright Engine)](#6-backend-core-architecture-fastapi--playwright-engine)
   - 6.1 [Application Lifespan & Concurrency Control (main.py)](#61-application-lifespan--concurrency-control-mainpy)
   - 6.2 [Robust Browser Lifecycle & Anti-Cloaking (etcher.py)](#62-robust-browser-lifecycle--anti-cloaking-fetcherpy)
   - 6.3 [Orchestrator & Execution Pipeline (orchestrator.py)](#63-orchestrator--execution-pipeline-orchestratorpy)
   - 6.4 [Pydantic Data Contracts & Schemas (models.py)](#64-pydantic-data-contracts--schemas-modelspy)
   - 6.5 [Brand Registry & Origin Management (
egistry.py)](#65-brand-registry--origin-management-registrypy)
   - 6.6 [Evidence Assembly & Explainability (evidence.py)](#66-evidence-assembly--explainability-evidencepy)
   - 6.7 [Report Generation (
eport.py)](#67-report-generation-reportpy)
   - 6.8 [Utility Subsystems (confusables.py, urls.py, imaging.py)](#68-utility-subsystems-confusablespy-urlspy-imagingpy)
7. [REST API Documentation & Data Contracts](#7-rest-api-documentation--data-contracts)
   - 7.1 [Meta & Health Endpoints](#71-meta--health-endpoints)
   - 7.2 [Admin Brand Governance Endpoints](#72-admin-brand-governance-endpoints)
   - 7.3 [Full Scan Endpoints (/api/scan, /api/scan/{id}, /progress)](#73-full-scan-endpoints-apiscan-apiscanid-progress)
   - 7.4 [Fast-Path Quick Check (/api/quick-check)](#74-fast-path-quick-check-apiquick-check)
   - 7.5 [Forensic Report Export Endpoints (.json, .pdf)](#75-forensic-report-export-endpoints-json-pdf)
8. [Browser Extension Deep Dive (Manifest V3)](#8-browser-extension-deep-dive-manifest-v3)
   - 8.1 [Manifest Configuration & Architecture](#81-manifest-configuration--architecture)
   - 8.2 [Service Worker & Navigation Watcher (ackground.js)](#82-service-worker--navigation-watcher-backgroundjs)
   - 8.3 [Content Script & DOM Inspection (content.js)](#83-content-script--dom-inspection-contentjs)
   - 8.4 [Client-Side Fast Filter Engine (localCheck.js)](#84-client-side-fast-filter-engine-localcheckjs)
   - 8.5 [Full-Screen Warning Interstitial (warning.html, warning.js)](#85-full-screen-warning-interstitial-warninghtml-warningjs)
9. [Frontend Forensic Dashboard](#9-frontend-forensic-dashboard)
   - 9.1 [UI Layout & Structural Elements (index.html)](#91-ui-layout--structural-elements-indexhtml)
   - 9.2 [Design Philosophy & Cyber Forensic Aesthetics (Styles.css)](#92-design-philosophy--cyber-forensic-aesthetics-stylescss)
   - 9.3 [State Machine & Asynchronous Orchestration (main.js, pi.js)](#93-state-machine--asynchronous-orchestration-mainjs-apijs)
   - 9.4 [Visual Gauge & Metric Visualizations (gauge.js, reakdown.js)](#94-visual-gauge--metric-visualizations-gaugejs-breakdownjs)
   - 9.5 [Interactive Comparative Inspection (compare.js, domainHighlight.js, ttackPath.js)](#95-interactive-comparative-inspection-comparejs-domainhighlightjs-attackpathjs)
10. [Test Matrix & Local Demonstration Testbed (	estpages/serve_all.py)](#10-test-matrix--local-demonstration-testbed-testpagesserve_allpy)
    - 10.1 [The 13 Test Scenarios & Multi-Port Server](#101-the-13-test-scenarios--multi-port-server)
    - 10.2 [Automated Test Vectors (domain_test_vectors.json)](#102-automated-test-vectors-domain_test_vectorsjson)
11. [Installation, Configuration & Deployment Guide](#11-installation-configuration--deployment-guide)
    - 11.1 [Prerequisites & Environment Matrix](#111-prerequisites--environment-matrix)
    - 11.2 [Backend Setup & Playwright Initialization](#112-backend-setup--playwright-initialization)
    - 11.3 [Extension Sideloading in Chromium Browsers](#113-extension-sideloading-in-chromium-browsers)
    - 11.4 [Configuration Reference & Environment Variables](#114-configuration-reference--environment-variables)
12. [Security Considerations & Threat Modeling](#12-security-considerations--threat-modeling)
13. [Future Enhancements & Scalability Roadmap](#13-future-enhancements--scalability-roadmap)

---

## 1. Executive Summary & Problem Statement

Phishing attacks and malicious credential-harvesting landing pages remain the predominant initial vector for data breaches, corporate espionage, ransomware deployments, and account takeovers globally. Traditional anti-phishing countermeasures largely depend upon:
1. **Static Blocklists (e.g., Google Safe Browsing, PhishTank, Spamhaus):** While highly accurate once verified, static lists exhibit an intolerable detection latency window ranging from hours to days. Modern spear-phishing campaigns exploit this latency window by cycling through burner domains, ephemeral Cloudflare tunnels, or dynamic bulletproof hosting before a URL is submitted, reviewed, and published to global lists.
2. **Generic Heuristic / Keyword Filters:** Traditional browser scanners look for basic keywords like login or password in URLs or inspect raw HTML text. These produce massive false-positive rates on benign sites or fail completely when attackers deploy obfuscated scripts or image-only pages.
3. **Black-box AI / Machine Learning Classifiers:** Deep neural networks trained on broad web pages often suffer from catastrophic false-positive spikes, offer zero explainability to incident responders, and can be trivially bypassed using adversarial visual tweaks or DOM perturbation.

The **Fake Login Page Detector (FLPD)** introduces a radically differentiated, forensic-grade detection paradigm: **Multi-Modal Comparative Differential Analysis with Explainable Deterministic Governance**.

Instead of guessing whether an isolated web page is malicious in a vacuum, FLPD performs the following key functions:
- Identifies the institutional brand or organization identity being targeted (e.g., university portals, corporate SSO, financial institutions, enterprise webmail).
- Automatically retrieves and simultaneously renders the authoritative **genuine page** alongside the **suspect page** inside synchronized, sandboxed Playwright headless browser viewports.
- Applies five parallel, specialized detection engines covering Domain Lexicography, Form Exfiltration Dynamics, DOM Tree Topology, Perceptual/Visual Geometry, and Network Asset Distribution.
- Synthesizes findings using a normalized weighted scoring algorithm governed by strict, mathematically verifiable **hard overrides (R1–R4)** that emulate the decision tree of a senior cyber forensic analyst.
- Delivers granular, interactive evidence cards with side-by-side screenshot diffing, structural tree heatmaps, and downloadable forensic audit reports in JSON and PDF.

By coupling a high-speed Chromium Manifest V3 browser extension for proactive endpoint protection with a high-throughput FastAPI forensic scanning backend, FLPD provides an impenetrable security perimeter against zero-day login cloning campaigns.

---

## 2. High-Level Architecture & End-to-End Workflow

The system operates across three primary tiers:
1. **Client Tier (Proactive Defense):** The Manifest V3 Browser Extension monitors navigation events, evaluates candidate login portals via client-side heuristics, and triggers immediate warnings or escalates deep scan requests.
2. **Analysis Tier (FastAPI & Playwright Cluster):** An asynchronous Python backend orchestrates dual-head headless Chromium rendering, dynamic DOM extraction, screenshot perceptual comparison, and analyzer pipeline execution.
3. **Presentation & Forensic Tier:** A web-based forensic dashboard and export engine presenting visual diffing sliders, DOM structure breakdowns, form exfiltration traces, and forensic reports.

`
+----------------------------------------------------------------------------------------------------+
|                                    CLIENT BROWSER / USER INTERACTION                              |
+----------------------------------------------------------------------------------------------------+
       |                                                                            |
       | 1. Navigation Event                                                        | 1b. Direct URL Scan
       v                                                                            v
+-----------------------------+                                            +------------------------+
| Manifest V3 Extension       |                                            | Web Forensic Dashboard |
| - background.js (Worker)    |                                            | - index.html / main.js |
| - content.js (DOM extract)  |                                            | - Interactive Gauge    |
| - localCheck.js (Tier 1/2)  |                                            | - Visual Diff Slider   |
+-----------------------------+                                            +------------------------+
       |                                                                            |
       | 2. Tier 3 Fast Query: POST /api/quick-check                                | 2b. Full Scan Request:
       |    or Deep Scan: POST /api/scan                                            |     POST /api/scan
       v                                                                            v
+----------------------------------------------------------------------------------------------------+
|                                      FASTAPI BACKEND RUNTIME                                       |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [main.py Lifespan Management]                                                                     |
|   - Initializes Brand Registry (registry.py)                                                       |
|   - Launches Playwright Engine Singleton (fetcher.py)                                              |
|   - Manages TTL Result Caching (cache.py)                                                          |
|                                                                                                    |
|  [Orchestrator Pipeline (orchestrator.py)]                                                         |
|   - Concurrency Semaphore Throttle (max_concurrent_scans)                                          |
|   - Brand Identification (registry.match_brand)                                                    |
|                                                                                                    |
|        +--------------------------------------------------------------------------+                |
|        |                DUAL HEADLESS BROWSER RENDERING (fetcher.py)              |                |
|        +--------------------------------------------------------------------------+                |
|        |  Suspect Page Context (1366x768)     |  Genuine Page Context (1366x768)  |                |
|        |  - Render & Wait Idle                |  - Render & Wait Idle             |                |
|        |  - Extract Full DOM & Text           |  - Extract Full DOM & Text        |                |
|        |  - Intercept Network Requests        |  - Intercept Network Requests     |                |
|        |  - Capture Viewport PNG              |  - Capture Viewport PNG           |                |
|        |  - Crop Form & Logo Bounding Boxes   |  - Crop Form & Logo Bounding Boxes|                |
|        +--------------------------------------------------------------------------+                |
|                                                                                                    |
|        +--------------------------------------------------------------------------+                |
|        |                  PARALLEL MULTI-MODAL ANALYZER SUITE                     |                |
|        +--------------------------------------------------------------------------+                |
|        | 1. Domain Analyzer (domain.py)     - Homoglyphs, TLDs, Entropy, Levenshtein             |
|        | 2. Form Analyzer (orm.py)         - Cross-Origin Actions, Cleartext, Exfiltration JS   |
|        | 3. DOM Analyzer (dom.py)           - Tag Distribution, Cosine Sim, Structural Diff      |
|        | 4. Visual Analyzer (isual.py)     - SSIM Pixel Diff, pHash, Layout Bounding Boxes      |
|        | 5. Assets Analyzer (ssets.py)     - Cross-Site Hotlinking, Favicon & CSS Theft         |
|        +--------------------------------------------------------------------------+                |
|                                                                                                    |
|  [Scoring Engine & Rule Evaluator (scoring.py)]                                                    |
|   - Normalizes available weights                                                                   |
|   - Evaluates Hard Rule Overrides:                                                                 |
|     * R1: Same Origin / Trusted Domain -> Forced Verdict: GENUINE (Score: 0)                      |
|     * R2: Foreign Credential Action + Visual Match -> Forced Verdict: LIKELY_CLONE (Score >= 88)  |
|     * R3: Homoglyph/Skeleton Match + Structural Match -> Forced Verdict: LIKELY_CLONE (Score >= 65)|
|     * R4: Low Similarity (< 0.20) + Clean Indicators -> Forced Verdict: UNRELATED (Score <= 10)    |
|                                                                                                    |
|  [Evidence Assembly & Artifacts (evidence.py, report.py)]                                          |
|   - Computes Visual Highlight Overlays (diff.png, suspect_overlay.png, genuine_overlay.png)        |
|   - Compiles Attack Path Forensics & Risk Breakdown                                                |
|   - Generates Downloadable JSON and Forensic PDF Reports                                           |
+----------------------------------------------------------------------------------------------------+
`

---

## 3. Repository Topology & Directory Breakdown

The codebase is organized into cleanly decoupled directories separating backend analysis, frontend presentation, client browser extensions, shared schemas, and isolated test mock environments:

`
fakeLoginPageDetector/
├── backend/                              # Core Python Forensic Engine & API Server
│   ├── app/
│   │   ├── analyzers/                    # Multi-modal detection modules
│   │   │   ├── __init__.py               # Analyzer package declarations
│   │   │   ├── base.py                   # Abstract Analyzer base class & run_analyzer wrapper
│   │   │   ├── domain.py                 # Homoglyphs, TLD risk, Levenshtein, entropy
│   │   │   ├── form.py                   # Form actions, password credential exfiltration
│   │   │   ├── dom.py                    # Structural tag frequency, cosine similarity, Jaccard
│   │   │   ├── visual.py                 # Viewport SSIM, perceptual hashing, crop comparisons
│   │   │   └── assets.py                 # Cross-origin script/CSS hotlinking, favicon matching
│   │   ├── utils/                        # Low-level cryptographic and image helpers
│   │   │   ├── __init__.py
│   │   │   ├── confusables.py            # Unicode confusable skeletons & Punycode decoding
│   │   │   ├── imaging.py                # PIL difference rendering, heatmaps, perceptual hashing
│   │   │   └── urls.py                   # Strict URL normalization, origin keys, action resolvers
│   │   ├── cache.py                      # Thread-safe in-memory TTL caching for scan sessions
│   │   ├── config.py                     # Pydantic BaseSettings loading environment configuration
│   │   ├── evidence.py                   # Generation of bounding-box visual comparison artifacts
│   │   ├── fetcher.py                    # Playwright Chromium lifecycle, page capture & cloaking defense
│   │   ├── main.py                       # FastAPI application factory, lifespan, routing, static mounts
│   │   ├── models.py                     # Universal Pydantic v2 data models, schemas, and enums
│   │   ├── orchestrator.py               # Asynchronous scan coordination and pipeline scheduler
│   │   ├── registry.py                   # Brand database persistence, origin matching, and lookup
│   │   ├── report.py                     # ReportLab PDF report generation and serialization
│   │   └── scoring.py                    # Weighted normalization, rule overrides, verdict logic
│   ├── config/
│   │   ├── brands.json                   # Seed database of protected brand profiles and origins
│   │   └── scoring.json                  # Dynamic weight coefficients and classification thresholds
│   ├── tests/                            # Unit and integration test suites
│   │   ├── unit/                         # Unit tests for analyzers, confusables, scoring, fetcher
│   │   └── conftest.py                   # Pytest fixtures and environment initialization
│   ├── requirements.txt                  # Production Python dependencies
│   └── pyproject.toml                    # Modern Python package metadata and tool configuration
├── extension/                            # Chromium Manifest V3 Real-Time Protection Extension
│   ├── data/
│   │   └── brands.json                   # Offline brand registry for zero-latency client checking
│   ├── lib/
│   │   └── localCheck.js                 # Fast client-side classification and rule matching
│   ├── tests/
│   │   └── test_vectors.js               # Extension-specific unit tests for domain extraction
│   ├── background.js                     # Manifest V3 service worker managing web navigation hooks
│   ├── content.js                        # Isolated content script extracting form and DOM state
│   ├── manifest.json                     # WebExtension Manifest V3 declaration
│   ├── overlay.css                       # Styles for in-page non-intrusive warning badges
│   ├── warning.css                       # Cyber-themed styling for full-page warning blocking interstitial
│   ├── warning.html                      # Blocking interstitial UI shown when phishing clones are detected
│   └── warning.js                        # Interstitial button interactions (proceed/turn back)
├── frontend/                             # Single-Page Forensic Dashboard & Web GUI
│   ├── images/                           # System badges, brand icons, forensic UI graphics
│   ├── Styles.css                        # Modern forensic UI styling (custom properties, dark aesthetic)
│   ├── api.js                            # Backend API communication and polling client
│   ├── attackPath.js                     # Attack path exfiltration visualization generator
│   ├── breakdown.js                      # Weighted signal contribution chart renderer
│   ├── compare.js                        # Interactive side-by-side screenshot diff slider
│   ├── domainHighlight.js                # Color-coded domain and homoglyph syntax highlighter
│   ├── favicon.svg                       # Application security shield vector icon
│   ├── gauge.js                          # Canvas/SVG circular risk score gauge animator
│   ├── index.html                        # Semantic HTML5 application entry point
│   ├── main.js                           # UI controller, event delegation, state management
│   ├── reasons.js                        # Forensic evidence card generator with severity tags
│   └── report.js                         # JSON and PDF export handlers
├── shared/                               # Cross-Component Data Standards
│   └── domain_test_vectors.json          # Standardized test vectors for homoglyphs and typosquatting
└── testpages/                            # Standalone Multi-Port Testbed Server
    └── serve_all.py                      # Multi-threaded HTTP server providing 13 test scenarios

## 4. The 5 Multi-Modal Detection Analyzers

The core detection intelligence of FLPD resides in its five decoupled analyzer modules located within `backend/app/analyzers/`. Every analyzer inherits from the abstract base class `Analyzer` (`base.py`) and implements the asynchronous `analyze(self, ctx: ScanContext) -> SignalResult` contract.

```python
class Analyzer(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique machine-readable name of the analyzer."""
        ...

    @abstractmethod
    async def analyze(self, ctx: ScanContext) -> SignalResult:
        """Evaluate the scan context and return a SignalResult."""
        ...
```

The execution of each analyzer is wrapped by `run_analyzer(analyzer, ctx, timeout=8.0)`. If an analyzer encounters an unexpected exception, unhandled edge-case, or exceeds its execution budget, it degrades gracefully by returning a `SignalResult(name=analyzer.name, score=0.0, available=False, unavailable_reason=str(exc))`. This ensures that a failure in one complex module (e.g., visual pixel processing) never crashes the scan pipeline.

---

### 4.1 Domain & Hostname Analyzer (`domain.py`)

The **Domain Analyzer** evaluates the lexical, structural, and cryptographic properties of the suspect hostname against the genuine brand domain and global indicators of malicious infrastructure.

#### Key Detection Mechanisms:
1. **Unicode Confusable & Homoglyph Detection:**
   Attackers frequently utilize Internationalized Domain Names (IDN) and Punycode (`xn--`) to register lookalike domains where Latin characters are substituted with visually identical Cyrillic, Greek, or Unicode characters (e.g., Cyrillic 'a' `\u0430` substituted for Latin 'a' `\u0061`).
   The analyzer leverages `app.utils.confusables.skeleton()` to compute the Unicode confusable skeleton of the suspect host and compares it to registered brand aliases.
   - Code: `DOMAIN_CONFUSABLE_BRAND` (Severity: `critical`, adds `+0.90` risk score).
   - Punycode detection: Flags any `xn--` prefix with explicit confusable character breakdowns.

2. **Levenshtein Edit Distance & Typosquatting:**
   Computes the normalized edit distance between the suspect registrable domain (SLD) and genuine brand SLDs:
   - Distance Ratio = 1.0 - Levenshtein(suspect_domain, genuine_domain) / max(len(suspect_domain), len(genuine_domain))
   - If distance is 1 (single character swap, deletion, or addition), triggers `DOMAIN_TYPOSQUAT_DISTANCE_1` (Severity: `high`, adds `+0.75` risk).
   - If distance is 2, triggers `DOMAIN_TYPOSQUAT_DISTANCE_2` (Severity: `medium`, adds `+0.45` risk).

3. **Subdomain Prepending & Brand Impersonation:**
   Detects instances where the legitimate brand name is embedded into an arbitrary third-party domain's subdomain hierarchy (e.g., `login.microsoft.com.attacker-infrastructure.org`).
   - If the brand identifier exists in the subdomain but the registrable root domain belongs to an unknown registrant: triggers `DOMAIN_BRAND_IN_SUBDOMAIN` (Severity: `high`, adds `+0.70` risk).

4. **High-Risk & Suspicious Top-Level Domains (TLDs):**
   Maintains a configurable catalog of low-cost, abuse-prone TLDs frequently utilized in automated phishing campaigns (e.g., `.xyz`, `.tk`, `.ml`, `.ga`, `.cf`, `.top`, `.click`, `.link`).
   - Triggers `DOMAIN_RISKY_TLD` (Severity: `medium`, adds `+0.35` risk).

5. **IP Address & Raw Hostname Formats:**
   Detects login pages hosted directly on raw IPv4 or IPv6 addresses (e.g., `http://192.168.1.50/login` or `http://45.33.32.156/`), which legitimate enterprise authentication services almost never employ.
   - Triggers `DOMAIN_IP_ADDRESS_USED` (Severity: `high`, adds `+0.60` risk).

6. **Excessive Hostname Shannon Entropy:**
   Calculates the Shannon information entropy of the hostname string:
   - High entropy (H > 4.2) strongly correlates with Algorithmically Generated Domains (DGA) or randomized cloud staging subdomains.
   - Triggers `DOMAIN_HIGH_ENTROPY` (Severity: `low`, adds `+0.20` risk).

7. **Extensive Hyphenation & Subdomain Nesting:**
   Counts hyphens and subdomain levels. Phishing sites frequently string together trust keywords (e.g., `secure-login-account-update-portal.com`).
   - Triggers `DOMAIN_EXCESSIVE_HYPHENS` or `DOMAIN_DEEP_SUBDOMAINS`.

8. **Same-Origin Whitelist Short-Circuit:**
   If the suspect domain exactly matches an authorized brand origin or designated trusted partner origin:
   - Returns score `0.0` with reason `SAME_ORIGIN` (Severity: `info`).

---

### 4.2 Form & Action Analyzer (`form.py`)

Phishing landing pages exist for one primary objective: to intercept and steal user credentials (passwords, session tokens, MFA codes, credit cards). The **Form & Action Analyzer** inspects the underlying data submission pathways of every form on the page.

#### Key Detection Mechanisms:
1. **Foreign Action Submission (`FORM_PASSWORD_FOREIGN_ACTION` / `FORM_FOREIGN_ACTION`):**
   When a form containing a password input (`<input type="password">`) submits its `action` attribute to an origin distinct from the current page origin and outside the brand's trusted infrastructure, this is the definitive hallmark of credential harvesting.
   - If `form.has_password` is True and `is_cross_origin` is True: triggers `FORM_PASSWORD_FOREIGN_ACTION` (Severity: `critical`, sets score contribution to `1.0`).
   - If generic form submits to foreign host: triggers `FORM_FOREIGN_ACTION` (Severity: `high`, sets score contribution to `0.80`).

2. **JavaScript Exfiltration & Asynchronous Stealing (`FORM_EXFILTRATION_JS`):**
   Modern phishing kits increasingly omit the HTML `action` attribute or set it to `action="#"` or `action="javascript:void(0)"`, instead intercepting the form's `submit` event or button click via JavaScript `fetch()` or `XMLHttpRequest()` calls to an external exfiltration endpoint.
   The analyzer scans the page's inline and loaded JavaScript code for asynchronous POST/PUT requests directed to foreign origins when password inputs are present.
   - Triggers `FORM_EXFILTRATION_JS` (Severity: `critical`, sets score contribution to `0.95`).

3. **Insecure Cleartext Submissions (`FORM_CLEARTEXT_SUBMISSION`):**
   Identifies password forms that submit credentials over unencrypted plain `http://` protocols instead of `https://`.
   - Triggers `FORM_CLEARTEXT_SUBMISSION` (Severity: `critical`, adds `+0.70` risk).

4. **Credential Field Harvesting Analysis:**
   Inspects input field distributions. A page featuring both username/email inputs and password fields outside of an authorized origin triggers:
   - `FORM_PASSWORD_FIELD_FOUND` (Severity: `medium`, adds `+0.30` risk).

5. **Hidden Form Fields & Fingerprinting:**
   Examines `<input type="hidden">` tags. Attackers often embed campaign trackers, victim affiliate IDs, or telegram bot routing keys into hidden fields.

---

### 4.3 DOM & Structural Analyzer (`dom.py`)

Even when attackers attempt to modify classes or styles to evade static string matches, the underlying HTML Document Object Model (DOM) tree structure often closely mirrors the genuine target portal. The **DOM Analyzer** extracts deep structural and linguistic signatures.

#### Key Detection Mechanisms:
1. **DOM Tag Distribution & Structural Cosine Similarity:**
   Builds a high-dimensional vector representing the frequency of all HTML elements (e.g., `div`, `form`, `input`, `button`, `label`, `header`, `svg`, `a`).
   Computes the Cosine Similarity metric against the genuine portal's vector:
   - Cosine Sim = dot_product(A, B) / (norm(A) * norm(B))
   - If Cosine Similarity >= 0.92, triggers `DOM_STRUCTURAL_SIMILARITY_VERY_HIGH` (Severity: `high`, adds `+0.80` to similarity index).
   - If Cosine Similarity >= 0.80, triggers `DOM_STRUCTURAL_SIMILARITY_HIGH` (Severity: `medium`, adds `+0.55`).

2. **Text Content & Vocabulary Jaccard Similarity:**
   Tokenizes the extracted visible text (`document.body.innerText`), filters stopwords, and calculates the Jaccard similarity coefficient:
   - Jaccard = count(words_suspect INTERSECT words_genuine) / count(words_suspect UNION words_genuine)
   - Identifies identical wording, privacy disclosures, button labels ("Sign In", "Keep me logged in"), or institutional copyright notices copied verbatim.

3. **Input Field Signature Matching:**
   Extracts the ordered sequence of input names, types, IDs, and placeholder attributes:
   - Signature sequence: [(type1, name1), (type2, name2), ...]
   - An identical input layout on an untrusted origin confirms structural clone attempt.
   - Triggers `DOM_INPUT_SIGNATURE_MATCH` (Severity: `high`).

4. **Image-Only Clone Detection (`DOM_IMAGE_ONLY_CLONE`):**
   Detects evasive phishing pages where the entire interface is a static background screenshot of the real login page, with transparent `<input>` tags overlaid on top to capture keystrokes.
   - Identified when HTML body contains zero or minimal text (< 50 characters) but contains an oversized full-viewport `<img>` or background graphic and interactive input fields.
   - Triggers `DOM_IMAGE_ONLY_CLONE` (Severity: `critical`, adds `+0.90` risk).

---

### 4.4 Visual & Perceptual Analyzer (`visual.py`)

Phishing pages are specifically engineered to deceive human vision. While backend code may differ, the rendered pixel output must appear visually authentic to trick the victim. The **Visual Analyzer** performs computer vision and perceptual image processing on high-resolution viewport screenshots captured by Playwright.

#### Key Detection Mechanisms:
1. **Structural Similarity Index Measure (SSIM):**
   Using OpenCV and `scikit-image`, computes full-viewport luminance, contrast, and structural comparison between suspect and genuine renderings:
   - SSIM evaluates visual degradation and structural perception rather than raw pixel-by-pixel equality, rendering it resilient against minor anti-aliasing variations or rendering engine differences.
   - If SSIM >= 0.90: triggers `VISUAL_SIMILARITY_CRITICAL` (Severity: `critical`, signal score `0.95`).
   - If SSIM >= 0.75: triggers `VISUAL_SIMILARITY_HIGH` (Severity: `high`, signal score `0.75`).

2. **Perceptual Hashing (pHash):**
   Computes a 64-bit discrete cosine transform (DCT) perceptual hash (`imagehash.phash()`) of both renderings and calculates the Hamming distance:
   - Hamming Distance = sum(bit_xor(hash1, hash2))
   - A Hamming distance <= 8 indicates visually indistinguishable layouts.
   - Triggers `VISUAL_PHASH_MATCH` (Severity: `high`).

3. **Form & Element Bounding Box Layout Alignment:**
   Extracts the geometric coordinates (x, y, width, height) of the primary authentication container, username field, password field, and submit button.
   Calculates the spatial overlap and Intersection over Union (IoU):
   - IoU = Area of Overlap / Area of Union
   - Close spatial alignment on an untrusted origin confirms layout copying.

4. **Visual Difference Heatmap Generation:**
   Generates a composite diff image highlighting pixel discrepancies in red overlaid on a desaturated grayscale background (saved to `artifacts/{scan_id}/diff.png`).

---

### 4.5 Asset & Network Request Analyzer (`assets.py`)

Phishing creators are notoriously lazy; rather than downloading, re-hosting, and updating all brand logos, fonts, and stylesheets, they frequently **hotlink** assets directly from the genuine organization's live servers or content delivery networks (CDNs).

#### Key Detection Mechanisms:
1. **Cross-Origin Asset Hotlinking (`ASSETS_HOTLINKED_FROM_GENUINE`):**
   Analyzes all outbound network requests captured during the Playwright rendering phase.
   Identifies requests for `.css`, `.woff2`, `.svg`, and `.png` files directed to the genuine brand's origins originating from the suspect host.
   - If suspect page loads assets directly from genuine origin: triggers `ASSETS_HOTLINKED_FROM_GENUINE` (Severity: `critical`, sets signal score >= 0.85).

2. **Perceptual Logo & Favicon Theft:**
   Extracts the suspect page's favicon and candidate logo images, computes their perceptual hash (`pHash`), and compares against the brand's verified logo hash stored in `brands.json`.
   - If favicon or logo matches the official brand asset while hosted on an untrusted domain: triggers `ASSETS_LOGO_MATCH_EXTERNAL` (Severity: `high`, adds `+0.70`).

3. **External Suspicious Script Injections:**
   Inspects the destination of third-party `<script>` tags, flagging scripts loaded from known paste sites, raw GitHub gists, or free hosting domains.
   - Triggers `ASSETS_SUSPICIOUS_SCRIPT_SOURCE` (Severity: `high`).

## 5. Scoring Engine, Weighted Contribution & Overrides

The scoring engine (`backend/app/scoring.py`) synthesizes findings from all active analyzers into a unified **Clone-Likelihood Risk Score (0–100)** and a qualitative **Verdict**. It bridges statistical machine classification with rigid forensic rules.

### 5.1 Base Weighted Formula

In default standard operation, each of the five analyzers produces a normalized signal score $S_i \in [0.0, 1.0]$. The base composite risk score is computed as:

$$\text{Raw Score} = 100 \times \sum_{i \in \text{Available}} S_i \times W_i^{\text{norm}}$$

The configured default baseline weights defined in `backend/config/scoring.json` are:

| Analyzer Module | Configuration Key | Default Weight ($W_i$) | Percentage Contribution | Forensic Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **Visual Analyzer** | `weight_visual` | `0.30` | 30% | Visual imitation is the primary deceptive mechanism targeting human victims. |
| **DOM Analyzer** | `weight_dom` | `0.25` | 25% | Structural tag distribution and identical input topologies reveal copied code. |
| **Form Analyzer** | `weight_form` | `0.20` | 20% | Clear indicators of credential exfiltration pipelines and cross-origin POST targets. |
| **Domain Analyzer** | `weight_domain` | `0.15` | 15% | Typosquatting, homoglyphs, and brand subdomain prepending. |
| **Assets Analyzer** | `weight_assets` | `0.10` | 10% | Hotlinked stylesheets, stolen favicons, and cross-site script loading. |
| **Total** | | `1.00` | 100% | |

---

### 5.2 Dynamic Missing-Signal Normalization

In production, certain analyzers may become unavailable:
- Fast Scan mode skips the heavy headless browser rendering, omitting `visual` and `dom`.
- The genuine portal may be temporarily unreachable or protected by Cloudflare CAPTCHAs, preventing live visual capture.
- Network timeouts or missing system dependencies (e.g., OpenCV) may cause an analyzer to report `available=False`.

Rather than failing or arbitrarily defaulting unavailable scores to zero (which would falsely deflate the risk score), FLPD dynamically normalizes the active weights:

$$W_i^{\text{norm}} = \frac{W_i}{\sum_{j \in \text{Available}} W_j}$$

$$\text{Contribution}_i = S_i \times W_i^{\text{norm}} \times 100$$

Every `SignalResult` returned in `ScanResult.signals` contains both `weight_used` (the normalized fraction) and `contribution` (points added to the 0–100 total), providing mathematical transparency.

---

### 5.3 Deterministic Hard Override Rules (R1 - R4)

Weighted linear sums are susceptible to edge-case anomalies:
- A page might look visually identical to a university login page because it *is* the university login page.
- An attacker might completely redesign the login form with unique CSS (low visual similarity), but submit user passwords to `evil-hacker.com/steal.php`.

To prevent catastrophic false positives and false negatives, the scoring engine enforces **Four Deterministic Override Rules (R1 through R4)** that supersede the linear weighted score:

```
+---------------------------------------------------------------------------------------------------+
|                                     SCORING OVERRIDE FLOWCHART                                    |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
                     +---------------------------------------------------------+
                     | Is suspect host identical to Genuine Origin or Trusted? |
                     +---------------------------------------------------------+
                                    |                         |
                               (YES)|                         |(NO)
                                    v                         v
                       +-----------------------+   +---------------------------------------+
                       | [R1] Force Score = 0  |   | Has Foreign Password Form Action?     |
                       | Verdict = GENUINE     |   | (FORM_PASSWORD_FOREIGN_ACTION)        |
                       +-----------------------+   +---------------------------------------+
                                                                  |                 |
                                                             (YES)|                 |(NO)
                                                                  v                 v
                                +-----------------------------------+   +-----------------------+
                                | Is Visual/DOM Similarity >= 0.60? |   | Has Domain Skeleton / |
                                | (or Fast Mode with No Render)     |   | Confusable Homoglyph? |
                                +-----------------------------------+   +-----------------------+
                                              |                 |                   |        |
                                         (YES)|                 |(NO)          (YES)|        |(NO)
                                              v                 v                   v        v
                                +-----------------------+       |       +---------------+  Standard
                                | [R2] Force Score >= 88|       |       | Similarity    |  Weighted
                                | Verdict = LIKELY_CLONE|       |       | >= 0.50?      |  Score
                                +-----------------------+       |       +---------------+
                                                                |         |           |
                                                                |    (YES)|           |(NO)
                                                                |         v           v
                                                                |   +-----------+  Standard
                                                                |   | [R3]      |  Score
                                                                |   | Score>=65 |
                                                                |   | LIKELY    |
                                                                |   | CLONE     |
                                                                |   +-----------+
                                                                v
                                    +-----------------------------------------------+
                                    | [R4] Similarity < 0.20 AND No Risk Indicators |
                                    | AND Base Score <= 20?                         |
                                    +-----------------------------------------------+
                                                      |
                                                 (YES)|
                                                      v
                                        +-----------------------+
                                        | Force Score <= 10     |
                                        | Verdict = UNRELATED   |
                                        +-----------------------+
```

#### Detailed Rule Specifications:

1. **Rule R1: Same Origin / Whitelisted Origin Match (The Authority Override)**
   - **Condition:** The suspect page URL origin matches any origin in the target brand's `origins` or `trusted_related_origins` array.
   - **Action:**
     - Force Final Score = `0`.
     - Force Verdict = `Verdict.genuine`.
     - Record override: `"R1: Same origin or trusted related origin"`.
   - **Forensic Guarantee:** Eliminates false positives when authorized corporate subdomains authenticate users.

2. **Rule R2: Foreign Credential Harvesting Action (The Exfiltration Override)**
   - **Condition:** The page contains a form requesting passwords submitting to a foreign host (`FORM_PASSWORD_FOREIGN_ACTION`, `FORM_FOREIGN_ACTION`, or `FORM_EXFILTRATION_JS`), AND the visual/DOM similarity index is $\ge 0.60$ (or running in fast mode without visual comparison).
   - **Action:**
     - Force Final Score = $\max(\text{score}, 88)$.
     - Force Verdict = `Verdict.likely_clone`.
     - Record override: `"R2: Foreign form action stealing credentials"`.
   - **Forensic Guarantee:** Even if an attacker uses obfuscated styling or incomplete DOM cloning, credential exfiltration guarantees immediate high-severity classification.

3. **Rule R3: Homoglyph / Skeleton Impersonation with Structural Alignment**
   - **Condition:** Suspect domain exhibits an exact confusable skeleton or typosquat match against the brand (`DOMAIN_CONFUSABLE_BRAND` or `DOMAIN_ALIAS_MATCH`), AND structural/visual similarity index is $\ge 0.50$.
   - **Action:**
     - Force Final Score = $\max(\text{score}, 65)$.
     - Force Verdict = `Verdict.likely_clone`.
     - Record override: `"R3: Domain skeleton match with high similarity"`.
   - **Forensic Guarantee:** Catches sophisticated spear-phishing sites operating under lookalike Cyrillic or Greek IDN domains before user submission occurs.

4. **Rule R4: Low Similarity with Clean Indicators (The Irrelevant Portal Override)**
   - **Condition:** Similarity index $< 0.20$, no domain skeleton match, no foreign form action, and base score $\le 20$.
   - **Action:**
     - Force Final Score = $\min(\text{score}, 10)$.
     - Force Verdict = `Verdict.unrelated`.
     - Record override: `"R4: Low similarity and no risk indicators"`.
   - **Forensic Guarantee:** Prevents benign generic web services (e.g., an unrelated personal blog or municipal login) from being incorrectly labeled as clones simply because they contain generic `<input>` fields.

---

### 5.4 Verdicts & Qualitative Thresholds

When no hard overrides trigger, the score maps to standardized forensic categories defined in `backend/config/scoring.json`:

| Score Range | Verdict (`Verdict` Enum) | System Classification | UI Visual Treatment | Actionable User Guidance |
| :---: | :---: | :---: | :---: | :--- |
| `0` (Exact Match) | `genuine` | Verified Authentic Portal | Vibrant Emerald Green | **Safe to Authenticate:** Origin verified against organization database. |
| `0` - `19` | `unrelated` / `low_risk` | Benign / Low Correlation | Neutral Steel Blue | **Normal Caution:** Limited or no indicators of brand impersonation detected. |
| `20` - `69` | `suspicious` | Suspicious Indicators Present | Cautionary Amber Orange | **Exercise High Caution:** Structural or domain anomalies detected. Do not submit sensitive data without secondary verification. |
| `70` - `100` | `likely_clone` | Deceptive Phishing Clone | Threat Crimson Red | **CRITICAL THREAT: Phishing Clone.** Do not enter passwords or session credentials. High-fidelity clone designed to steal authentication tokens. |

## 6. Backend Core Architecture (FastAPI & Playwright Engine)

The backend is built as a high-concurrency, asynchronous microservice utilizing FastAPI, Uvicorn, and Playwright for Python.

---

### 6.1 Application Lifespan & Concurrency Control (`main.py`)

FastAPI handles API requests and lifecycle events via the modern `lifespan` context manager:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup Phase
    logger.info("Loading brand registry...")
    load_brands()

    logger.info("Starting Playwright browser...")
    await fetcher.startup()

    logger.info("Fake Login Detector ready on %s:%d", settings.host, settings.port)
    yield

    # Shutdown Phase
    logger.info("Shutting down Playwright browser...")
    await fetcher.shutdown()
    logger.info("Shutdown complete.")
```

#### Key Architecture Features:
- **Windows Proactor Event Loop:** Automatically forces `asyncio.WindowsProactorEventLoopPolicy()` when running on Windows platforms, preventing subprocess connection resets with the Playwright Chromium child process.
- **TTL Cache Layer (`app.cache.TTLCache`):** Employs an in-memory thread-safe cache with a configurable time-to-live (`ttl_seconds=3600`, 1 hour). Scanned results are keyed by a UUID `scan_id`, allowing instantaneous retrieval of historical reports without re-running heavy browser captures.
- **Static Artifacts & UI Mounts:** Mounts `/artifacts` to serve generated screenshot diffs and PDF documents directly, and mounts `/` to serve the static frontend SPA directly on the same port (`8000`), eliminating CORS configuration hurdles during local deployment.

---

### 6.2 Robust Browser Lifecycle & Anti-Cloaking (`fetcher.py`)

Capturing untrusted, adversarial web pages presents severe security and stability risks. `PageFetcher` (`fetcher.py`) is a hardened browser driver wrapper designed for forensic isolation.

#### Hardened Browser Configuration:
1. **Sandboxed Single-Instance Management:**
   Launches a shared Playwright Chromium instance during server startup (`fetcher.startup()`) using hardened flags:
   - `--disable-dev-shm-usage` (prevents shared-memory exhaustion in Docker/Linux environments)
   - `--no-sandbox` & `--disable-setuid-sandbox`
   - Viewport initialized to standard desktop resolution: `1366x768`.

2. **Per-Scan Ephemeral Contexts:**
   Every page scan runs inside an isolated, newly instantiated `BrowserContext`:
   ```python
   context = await self._browser.new_context(
       viewport={"width": 1366, "height": 768},
       user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
       ignore_https_errors=True,
   )
   ```
   Cookies, storage tokens, and session state are entirely segregated and destroyed immediately upon scan termination.

3. **Anti-Cloaking & Anti-Bot Evasion:**
   Phishing kits often inspect `navigator.webdriver` or evaluate user-agent strings. If they detect an automated headless crawler or security scanner, they serve benign decoy content (e.g., redirecting to Google or showing a 404 page).
   `fetcher.py` injects stealth evaluation scripts into every page before scripts run:
   ```javascript
   Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
   window.chrome = { runtime: {} };
   ```

4. **Network Request Interception:**
   Attaches listeners to `page.on("request")` and `page.on("response")` to capture:
   - Outbound network requests (method, target URL, resource type, payload existence).
   - Full HTTP redirect chains (`response.request.redirected_from`).
   - Third-party script calls and asynchronous AJAX/WebSocket connections.

5. **DOM Extraction & Bounding Box Coordinates:**
   Executes in-page JavaScript queries to resolve:
   - Full rendered HTML (`await page.content()`), capped at `max_html_bytes` (10 MB).
   - Clean visible text (`await page.evaluate("() => document.body.innerText")`).
   - Exact client bounding boxes (`getBoundingClientRect()`) for all `<form>`, `<input>`, `<button>`, and `<img>` tags.
   - High-resolution viewport screenshot saved to `artifacts/{scan_id}/suspect.png`.

---

### 6.3 Orchestrator & Execution Pipeline (`orchestrator.py`)

The `Orchestrator` coordinates the entire multi-stage analysis pipeline and enforces strict concurrency budgets:

```python
class Orchestrator:
    def __init__(self):
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
        self._analyzers = [
            DomainAnalyzer(),
            FormAnalyzer(),
            DomAnalyzer(),
            VisualAnalyzer(),
            AssetsAnalyzer(),
        ]
```

#### Pipeline Stages & State Machine:
1. **Queued:** Request received and waiting on `self._semaphore`.
2. **Brand Identification:** Queries `registry.match_brand(suspect_url)` to find candidate targets. If genuine URL is supplied in request, uses direct pairing.
3. **Dual Page Fetching (`asyncio.gather`):**
   - Renders suspect page via `fetcher.fetch_page()`.
   - Simultaneously renders genuine page via `fetcher.fetch_page()` (cached if previously visited).
4. **Context Construction:** Assembles immutable `ScanContext(suspect, genuine, brand, settings)`.
5. **Parallel Analysis (`asyncio.gather`):**
   - Dispatches all 5 analyzers simultaneously via `run_analyzer(timeout=8.0)`.
6. **Score Synthesis:** Evaluates `scoring.compute_score(signals, settings)`.
7. **Forensic Evidence Assembly:** Calls `evidence.build_evidence(ctx, scored_result)`.
8. **Artifact Persistence:** Writes visual diff overlays and prepares download links.

---

### 6.4 Pydantic Data Contracts & Schemas (`models.py`)

All cross-module communication is strictly enforced via Pydantic v2 schemas. Key structures include:

- **`Severity` (Enum):** `info`, `low`, `medium`, `high`, `critical`.
- **`Verdict` (Enum):** `genuine`, `low_risk`, `suspicious`, `likely_clone`, `unrelated`.
- **`Reason` (Model):** Represents an atomic, explainable forensic finding:
  ```python
  class Reason(BaseModel):
      code: str               # e.g., "FORM_PASSWORD_FOREIGN_ACTION"
      title: str              # e.g., "Foreign Form Submission Target"
      detail: str             # Non-expert plain English explanation
      severity: Severity
      signal: str             # Originating analyzer ("form", "domain", etc.)
      evidence: dict[str, Any]# Supporting parameters (URLs, distances, etc.)
  ```
- **`SignalResult` (Model):** Contains analyzer score `[0.0, 1.0]`, metric dictionaries, and normalized contribution weights.
- **`ScanResult` (Model):** Complete scan entity returned to API consumers containing scan ID, verdict, numeric score, reasons, image URLs, and performance timings.

---

### 6.5 Brand Registry & Origin Management (`registry.py`)

Maintains the authoritative catalog of protected organizational portals (`backend/config/brands.json`).

#### Brand Model Schema:
```json
{
  "id": "sample_college",
  "name": "State University Portal",
  "genuine_urls": ["https://portal.university.edu/login"],
  "origins": ["https://portal.university.edu"],
  "trusted_related_origins": [
    "https://auth.university.edu",
    "https://identity.university.edu"
  ],
  "title_keywords": ["portal", "university", "student", "webmail"],
  "lookalike_labels": ["univ-portal", "student-login"],
  "logo_phash": "a7c3b9d1e4f20815",
  "aliases_for_local_testing": ["localhost:5001"],
  "organization_type": "Education",
  "verification_status": "verified"
}
```

#### Verification Lifecycle:
- New organizations can be submitted via the admin API in `pending` status.
- Once verified by security personnel, status is marked `verified`, activating automatic matching and whitelist protection across both backend and extension.

---

### 6.6 Evidence Assembly & Explainability (`evidence.py`)

To ensure that findings are completely explainable to human incident responders, `evidence.py` generates visual artifacts demonstrating the attack:
- **`diff.png`:** Visual pixel diff highlighting altered or cloned regions in bright red.
- **`suspect_overlay.png`:** Suspect page screenshot annotated with bounding-box rectangles highlighting foreign forms in crimson red.
- **`genuine_overlay.png`:** Genuine page screenshot annotated with genuine form boxes in emerald green.

---

### 6.7 Report Generation (`report.py`)

Generates courtroom-ready forensic audit reports in PDF format using Python's `reportlab` library:
- **Header:** Scan UUID, execution timestamp, target URL, and final verdict badge.
- **Executive Summary:** Plain-English summary explaining why the site was flagged.
- **Risk Score Breakdown Table:** Signal names, raw scores, assigned weights, and final point contributions.
- **Evidence Ledger:** Categorized list of all detected reasons sorted by severity (`CRITICAL`, `HIGH`, `MEDIUM`).
- **Form Action Trace:** Explicit comparison showing user credentials submitting to an unauthorized endpoint.

---

### 6.8 Utility Subsystems (`confusables.py`, `urls.py`, `imaging.py`)

- **`confusables.py`:** Implements Unicode TR39 confusable character normalization. Normalizes lookalike characters across Latin, Cyrillic, Greek, and Hebrew alphabets to their canonical Latin base characters.
- **`urls.py`:** Implements strict URL parsing, normalization, scheme validation, and action URL resolution (resolving relative paths like `action="../post.php"` into absolute URLs based on page base).
- **`imaging.py`:** Handles image decoding, PIL format conversions, perceptual hash calculation (`imagehash.phash`), and visual diff rendering.

## 7. REST API Documentation & Data Contracts

The backend exposes an OpenAPI-compliant REST API documented via interactive Swagger UI at `http://localhost:8000/docs` and Redoc at `http://localhost:8000/redoc`.

---

### 7.1 Meta & Health Endpoints

#### `GET /api/health`
Liveness and readiness health check probe used by container orchestrators and monitoring tools.
- **Request:** None
- **Response (200 OK):**
  ```json
  {
    "status": "ok",
    "version": "0.1.0"
  }
  ```

#### `GET /api/brands`
Returns the public list of verified protected brands. Used by the browser extension to synchronize offline protection lists.
- **Request:** None
- **Response (200 OK):**
  ```json
  [
    {
      "id": "sample_college",
      "name": "State University Portal",
      "genuine_urls": ["https://portal.university.edu/login"],
      "origins": ["https://portal.university.edu"],
      "trusted_related_origins": ["https://auth.university.edu"],
      "organization_type": "Education",
      "verification_status": "verified"
    }
  ]
  ```

---

### 7.2 Admin Brand Governance Endpoints

Administrative brand endpoints require the header `X-Admin-Token: <SECRET_TOKEN>` configured via `REGISTRY_ADMIN_TOKEN`.

#### `GET /api/admin/brands`
Lists all registered brands, including pending and unverified organizations.

#### `POST /api/admin/brands`
Submits a new institution or website for monitoring and protection.
- **Request Body (`BrandRegistrationRequest`):**
  ```json
  {
    "name": "City Municipal Bank",
    "official_url": "https://online.citybank.com/signin",
    "organization_type": "Financial"
  }
  ```
- **Response (201 Created):**
  ```json
  {
    "id": "city_municipal_bank",
    "name": "City Municipal Bank",
    "official_url": "https://online.citybank.com/signin",
    "organization_type": "Financial",
    "verification_status": "pending",
    "message": "Registration saved. Verify the official website before trusting it."
  }
  ```

#### `POST /api/admin/brands/{brand_id}/verify`
Elevates a brand registration from `pending` to `verified`.

#### `DELETE /api/admin/brands/{brand_id}`
Removes an organization from the active registry.

---

### 7.3 Full Scan Endpoints (`/api/scan`, `/api/scan/{id}`, `/progress`)

#### `POST /api/scan`
Initiates a comprehensive forensic scan of a target URL.
- **Request Body (`ScanRequest`):**
  ```json
  {
    "url": "http://localhost:5002/login",
    "genuine_url": "http://localhost:5001/login",
    "mode": "full"
  }
  ```
  *(Note: `genuine_url` is optional; if omitted, the system automatically detects the brand).*

- **Response (200 OK - Synchronous Completion):**
  ```json
  {
    "scan_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "created_at": "2026-10-22T12:00:00Z",
    "duration_ms": 3420,
    "suspect_url": "http://localhost:5002/login",
    "genuine_url": "http://localhost:5001/login",
    "brand": "State University Portal",
    "score": 92,
    "verdict": "likely_clone",
    "summary": "Strong similarity or other risk indicators suggest this page may be a phishing clone. Review the evidence before interacting with it.",
    "signals": {
      "visual": {
        "name": "visual",
        "score": 0.95,
        "available": true,
        "weight_used": 0.30,
        "contribution": 28.5,
        "metrics": { "ssim": 0.98, "phash_distance": 2 }
      },
      "form": {
        "name": "form",
        "score": 1.0,
        "available": true,
        "weight_used": 0.20,
        "contribution": 20.0,
        "metrics": { "is_cross_origin": true }
      }
    },
    "reasons": [
      {
        "code": "FORM_PASSWORD_FOREIGN_ACTION",
        "title": "Password Submits to Foreign Destination",
        "detail": "This login form sends your password to an external website not owned by State University Portal.",
        "severity": "critical",
        "signal": "form",
        "evidence": {
          "action_url": "http://localhost:5006/submit",
          "action_host": "localhost:5006"
        }
      }
    ],
    "images": {
      "suspect": "/artifacts/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d/suspect.png",
      "genuine": "/artifacts/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d/genuine.png",
      "diff": "/artifacts/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d/diff.png"
    },
    "overrides_applied": ["R2: Foreign form action stealing credentials"]
  }
  ```

#### `GET /api/scan/{scan_id}`
Retrieves a previously computed scan result by UUID.

#### `GET /api/scan/{scan_id}/progress`
Returns the real-time execution stage of an in-flight scan for frontend progress bars:
```json
{
  "scan_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "stage": "analyzers",
  "done": false,
  "error": null
}
```

---

### 7.4 Fast-Path Quick Check (`/api/quick-check`)

Designed for the Chrome extension to query verdicts in under 50 milliseconds without invoking headless browser rendering.

- **Request Body (`QuickCheckRequest`):**
  ```json
  {
    "url": "http://evil-clone.com/login.html",
    "form_actions": ["http://data-collector.com/harvest.php"],
    "has_password": true
  }
  ```

- **Response (200 OK - `QuickCheckResult`):**
  ```json
  {
    "verdict": "likely_clone",
    "score": 90,
    "brand": "State University Portal",
    "reasons": [
      {
        "code": "FORM_PASSWORD_FOREIGN_ACTION",
        "title": "Password Submits to Foreign Destination",
        "detail": "This login form sends your password to an external website.",
        "severity": "critical",
        "signal": "form"
      }
    ]
  }
  ```

---

### 7.5 Forensic Report Export Endpoints (`.json`, `.pdf`)

- **`GET /api/report/{scan_id}.json`:** Triggers browser download of raw forensic audit JSON data (`Content-Disposition: attachment; filename="scan_{id}.json"`).
- **`GET /api/report/{scan_id}.pdf`:** Generates and returns a formatted multi-page PDF forensic report complete with visual diff figures, score tables, and chain of custody metadata.

## 8. Browser Extension Deep Dive (Manifest V3)

The FLPD Browser Extension (`fake-login-detector/extension/`) provides proactive, zero-latency protection directly inside Chromium-based browsers (Google Chrome, Microsoft Edge, Brave, Opera) adhering to the strict security constraints of Google Chrome Manifest V3.

---

### 8.1 Manifest Configuration & Architecture

The extension is declared in `extension/manifest.json`:
- **Manifest Version:** `3`
- **Background Context:** Service Worker (`background.js`, `type: module`)
- **Permissions:**
  - `webNavigation`: Listens to committed navigation events before content renders.
  - `storage`: Caches verified brand rules and user override decisions in `chrome.storage.local`.
  - `tabs`: Queries tab metadata and handles interstitial redirects.
  - `scripting`: Dynamically executes isolated analysis routines when needed.
- **Host Permissions:** Allows communication with `http://localhost:8000/*` (backend API) and HTTP/HTTPS page endpoints.
- **Content Security Policy:** Compliant with MV3 restrictions (no inline eval, strict remote code bans).

---

### 8.2 Service Worker & Navigation Watcher (`background.js`)

The background service worker orchestrates the 3-Tier progressive inspection pipeline whenever a user navigates to a new web resource:

```javascript
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only inspect top-level window
  await handleNavigation(details.tabId, details.url);
});
```

#### The 3-Tier Progressive Detection Funnel:
1. **Tier 1 (Instant Whitelist Filter - 0ms):**
   Checks the destination URL against the local offline brand cache stored in `extension/data/brands.json`.
   - If the URL matches an official origin or trusted partner origin: marks the page as **SAFE** immediately. Zero network requests, zero overhead.

2. **Tier 2 (Client Heuristic Filter - < 10ms):**
   Injected `content.js` inspects the page for presence of `<input type="password">` elements.
   - If no password input exists, the page is deemed not an authentication portal and inspection completes quietly.
   - If a password field exists: extracts form action URLs, method, and page title.
   - Runs `localCheck.js` to evaluate cross-origin submission targets.

3. **Tier 3 (Backend Escalation - < 50ms):**
   If Tier 2 detects a suspicious form action or lookalike domain, `background.js` dispatches an asynchronous call to the backend:
   ```javascript
   const res = await fetch("http://localhost:8000/api/quick-check", {
     method: "POST",
     headers: { "Content-Type": "application/json" },
     body: JSON.stringify({ url, form_actions, has_password: true })
   });
   ```
   - If verdict is `likely_clone`: immediately halts navigation and redirects the active tab to `warning.html`!

---

### 8.3 Content Script & DOM Inspection (`content.js`)

`content.js` runs in an isolated world at `document_idle`. It passively inspects the DOM for login forms without interfering with legitimate website functionality:
- Scans `document.querySelectorAll("form")`.
- Identifies any input matching `input[type="password"]` or common username identifiers (`name="username"`, `name="email"`, `name="login"`).
- Resolves relative form actions using `new URL(form.action, window.location.href).href`.
- Detects inline submit handlers that cancel form submission to route through JavaScript fetch callers.
- Sends payload to background worker via `chrome.runtime.sendMessage()`.

---

### 8.4 Client-Side Fast Filter Engine (`localCheck.js`)

`localCheck.js` encapsulates domain and form checking logic directly in pure JavaScript. It enables offline detection even when the backend API server is momentarily unreachable:
- Implements hostname stripping and domain label tokenization.
- Matches candidate hostnames against offline brand lookalikes.
- Detects obvious cross-origin submissions (e.g., page at `my-university.tk` submitting to `collect-passwords.org`).

---

### 8.5 Full-Screen Warning Interstitial (`warning.html`, `warning.js`)

When a high-confidence clone is detected, the user is shielded by a full-screen red warning interstitial preventing credential entry.

#### Features of `warning.html`:
- **Threat Indicator Banner:** Flashing warning badge with detected brand name (e.g., *"Deceptive State University Portal Clone Detected"*).
- **Clear Explanation:** Plain-English summary: *"This website is attempting to steal your login credentials by mimicking an official portal. Passwords entered here will be captured by unauthorized third parties."*
- **Action Buttons:**
  - **"Take Me Back to Safety" (Primary):** Redirects the browser to the official genuine URL stored in the brand registry.
  - **"View Forensic Evidence":** Opens the FLPD dashboard to view side-by-side screenshot diffs and audit logs.
  - **"Proceed Anyway (Unsafe)":** Allows advanced security researchers to bypass the warning and view the clone.

## 9. Frontend Forensic Dashboard

The Frontend Dashboard (`fake-login-detector/frontend/`) is a high-performance Single Page Application (SPA) built using modern Vanilla JavaScript (ES Modules), semantic HTML5, and bespoke cyber forensic CSS without heavy third-party framework dependencies.

---

### 9.1 UI Layout & Structural Elements (`index.html`)

The dashboard layout is designed specifically for forensic triage:
1. **Command Navigation Header:** Application title, status indicator, connection state badge, and direct links to API documentation.
2. **Scan Input Console:**
   - Suspect URL input field with validation and auto-clearing.
   - Genuine URL input field (optional; auto-populates upon brand detection).
   - Mode Toggle: Full Multi-Modal Scan vs. Fast Inspection.
   - Quick-Load Demonstration Buttons: One-click buttons to load local test scenarios (Genuine, Clone, Rewritten, Screenshot, Hotlinked, etc.).
3. **Primary Verdict Stage:**
   - Animated Circular Risk Gauge showing calculated score (0 to 100).
   - Color-coded Verdict Banner (`GENUINE`, `LOW RISK`, `SUSPICIOUS`, `LIKELY CLONE`).
   - Plain-English Executive Summary text card.
4. **Interactive Forensic Inspection Deck:**
   - Side-by-Side Viewport Visual Diffing Slider.
   - Attack Path Exfiltration Graph.
   - Weighted Signal Contribution Radar / Bar Breakdown.
   - Structured Evidence Cards ordered by severity.
   - Raw Technical Metrics Inspector (SSIM scores, pHash distance, DOM similarity percentages, form action hosts).

---

### 9.2 Design Philosophy & Cyber Forensic Aesthetics (`Styles.css`)

`Styles.css` implements a bespoke, high-contrast dark theme engineered to evoke a specialized cybersecurity operations center:
- **Color Palette:**
  - Background: Deep slate obsidian (`#0b0f19`, `#111827`).
  - Panels & Cards: Elevated glassmorphism surfaces (`rgba(30, 41, 59, 0.7)` with `backdrop-filter: blur(12px)`).
  - Accents: Neon cyan (`#06b6d4`), electric violet (`#8b5cf6`), alert amber (`#f59e0b`), threat crimson (`#ef4444`), safe emerald (`#10b981`).
- **Typography:** Clean geometric sans-serif (Inter / System UI) with monospace fonts (Fira Code / JetBrains Mono) for domains, hashes, and raw URLs.
- **Fluid Micro-Animations:** Smooth bezier transitions on hover, pulsing threat indicator glows, and fluid gauge sweeps.

---

### 9.3 State Machine & Asynchronous Orchestration (`main.js`, `api.js`)

`main.js` acts as the central UI controller:
- Manages scan lifecycle state (`idle` -> `scanning` -> `polling` -> `rendered` -> `error`).
- Submits scan payloads via `api.js` and streams progress updates using `/api/scan/{id}/progress`.
- Dispatches data packets to visualization components (`gauge.js`, `compare.js`, `breakdown.js`, `reasons.js`).

---

### 9.4 Visual Gauge & Metric Visualizations (`gauge.js`, `breakdown.js`)

- **`gauge.js`:** Renders an animated SVG arc gauge. Calculates color interpolation smoothly across green (0) -> yellow (40) -> orange (65) -> red (85+). Features an animated numeric odometer counting up to the final risk score.
- **`breakdown.js`:** Renders a horizontal bar chart displaying each analyzer's individual contribution. Demonstrates exactly how many points out of 100 were added by Visual, DOM, Form, Domain, and Assets analyzers.

---

### 9.5 Interactive Comparative Inspection (`compare.js`, `domainHighlight.js`, `attackPath.js`)

- **`compare.js`:** Implements an interactive split-screen image slider. Users can drag a vertical dividing divider back and forth across the suspect and genuine page screenshots to spot subtle visual discrepancies, font mismatches, or counterfeit logos.
- **`domainHighlight.js`:** Breaks down URLs into structured components (scheme, subdomain, second-level domain, public suffix, path). Highlights deceptive homoglyphs, confusable Cyrillic letters, or suspicious TLDs with bright neon warning outlines.
- **`attackPath.js`:** Generates an intuitive visual diagram illustrating the exfiltration route:
  `[Victim Browser]` -> `[Suspect Clone Interface]` -> `[Unauthorized Exfiltration Server]`.

## 10. Test Matrix & Local Demonstration Testbed (`testpages/serve_all.py`)

Testing phishing detection tools against live malicious domains in the wild presents severe security and ethical risks (exposure to active malware, ephemeral domain lifespans, network monitoring triggers). To solve this, FLPD includes a self-contained, multi-port local mock environment (`testpages/serve_all.py`) providing 13 fully functional test scenarios covering realistic phishing techniques.

---

### 10.1 The 13 Test Scenarios & Multi-Port Server

Running `python testpages/serve_all.py` spawns a cluster of lightweight, multi-threaded HTTP servers across dedicated local ports:

| Port | Target Description & Technique | Expected Verdict | Expected Score | Primary Triggered Signals & Reasons |
| :---: | :--- | :---: | :---: | :--- |
| `5001` | **Genuine College Portal:** Authentic baseline institutional authentication page. | `genuine` | `0` | `SAME_ORIGIN`, `GENUINE_ORIGIN` (Rule R1 fired). |
| `5002` | **Exact Copy with Foreign Action:** High-fidelity clone sending credentials to Port 5006. | `likely_clone` | `90 - 100` | `FORM_PASSWORD_FOREIGN_ACTION`, `VISUAL_SIMILARITY_CRITICAL` (Rule R2 fired). |
| `5003` | **Visual Clone with Rewritten DOM:** Visually identical UI, but CSS classes and HTML tags completely refactored. | `likely_clone` | `85 - 95` | `VISUAL_SIMILARITY_CRITICAL`, `FORM_FOREIGN_ACTION` (Defeats pure DOM filters). |
| `5004` | **Screenshot-Only Overlay Clone:** Background is a static image of the portal; transparent inputs overlaid. | `likely_clone` | `90 - 100` | `DOM_IMAGE_ONLY_CLONE`, `VISUAL_SIMILARITY_CRITICAL`. |
| `5005` | **Asset Hotlinked Clone:** Cloned portal that links CSS stylesheets and logo SVG directly from Port 5001. | `likely_clone` | `90 - 100` | `ASSETS_HOTLINKED_FROM_GENUINE`, `FORM_FOREIGN_ACTION`. |
| `5006` | **Genuine Webmail & Exfiltration Sink:** Authentic email login & form submission endpoint. | `genuine` | `0` | Verified authentic brand secondary service. |
| `5007` | **Webmail Phishing Clone:** Malicious clone of the university webmail service. | `likely_clone` | `88 - 98` | `FORM_PASSWORD_FOREIGN_ACTION`, `ASSETS_LOGO_MATCH_EXTERNAL`. |
| `5008` | **Legitimate Department Portal:** Physics dept login with unique layout; legitimate sub-service. | `low_risk` | `< 20` | Benign internal variation; low similarity. |
| `5009` | **Unrelated Generic Login:** Completely different corporate login (blue theme, different fields). | `unrelated` | `< 10` | Low visual similarity, low DOM similarity (Rule R4 fired). |
| `5010` | **JavaScript Fetch Exfiltration:** Cloned page without `<form action>`; submits via AJAX `fetch()`. | `likely_clone` | `85 - 95` | `FORM_EXFILTRATION_JS`, `VISUAL_SIMILARITY_CRITICAL`. |
| `5011` | **Slow Rendering Server:** Simulates slow network latency with a 3-second sleep delay. | Dynamic | Dynamic | Validates Playwright wait-until-idle and timeout thresholds. |
| `5012` | **Broken Server (HTTP 500):** Emulates downstream web server crashes and internal errors. | Error Handled | `0` | Validates error degradation and network failure resilience. |
| `5013` | **Iframe Embedded Login:** Tests credential harvesting inside nested embedded iframes. | `likely_clone` | `80 - 90` | Validates iframe traversal and nested input extraction. |

---

### 10.2 Automated Test Vectors (`domain_test_vectors.json`)

Located in `shared/domain_test_vectors.json`, this suite supplies 50+ standardized domain pairs used in automated CI/CD unit testing (`backend/tests/unit/test_utils_confusables.py` and `extension/tests/test_vectors.js`):
- **Cyrillic Homoglyphs:** `gооgle.com` (`о`), `pаypal.com` (`а`), `microsоft.com`.
- **Greek Homoglyphs:** `аррle.com` (`ο`, `ρ`).
- **Punycode Transforms:** `xn--pple-43d.com`, `xn--e1awd7f.xn--p1ai`.
- **Hyphen & Subdomain Squatting:** `login-microsoft-auth.com`, `paypal.verification-portal.net`.

---

## 11. Installation, Configuration & Deployment Guide

---

### 11.1 Prerequisites & Environment Matrix

- **Operating System:** Windows 10/11, macOS (Apple Silicon / Intel), or Ubuntu Linux 22.04 LTS.
- **Python Runtime:** Python 3.11, 3.12, or 3.13 (Python 3.13 64-bit recommended).
- **Web Browser (for Extension):** Chromium-based browser supporting Manifest V3 (Chrome 110+, Edge 110+, Brave).
- **Node.js (Optional):** Node.js 18+ if running standalone frontend dev servers.

---

### 11.2 Backend Setup & Playwright Initialization

Follow these exact steps from an administrative shell or terminal:

#### 1. Clone the repository
```bash
git clone https://github.com/shivahiremath001/fakeLoginPageDetector.git
cd fakeLoginPageDetector/fake-login-detector
```

#### 2. Create and Activate Virtual Environment
**On Windows (PowerShell / Command Prompt):**
```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
```

**On Linux / macOS:**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
```

#### 3. Install Python Dependencies
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### 4. Install Playwright Chromium Browser
The backend requires Playwright's headless Chromium binaries:
```bash
python -m playwright install chromium
```

#### 5. Launch the Backend Server
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
The server will initialize the brand database, launch the headless Chromium instance, and serve:
- REST API: `http://127.0.0.1:8000/api`
- Interactive API Docs: `http://127.0.0.1:8000/docs`
- Web Dashboard: `http://127.0.0.1:8000`

#### 6. Start the Local Test Scenario Server (Separate Terminal)
```bash
cd fake-login-detector
python testpages/serve_all.py
```

#### 7. Execute the Test Suite
```bash
cd backend
python -m pytest tests/unit -v
```
All unit tests will execute and validate: **143 passed**.

---

### 11.3 Extension Sideloading in Chromium Browsers

To load the real-time protection extension in Google Chrome or Microsoft Edge:
1. Open your browser and navigate to `chrome://extensions/` (or `edge://extensions/`).
2. Toggle the **Developer mode** switch in the top-right corner to **ON**.
3. Click the **Load unpacked** button in the top-left toolbar.
4. Browse to and select the `fake-login-detector/extension` directory.
5. The **Fake Login Page Detector** extension is now active!
6. Visit `http://localhost:5002/login` in your browser. The extension will intercept the navigation and render the threat warning screen!

---

### 11.4 Configuration Reference & Environment Variables

All settings can be customized via environment variables or a `.env` file placed inside `backend/`:

| Environment Variable | Default Value | Description |
| :--- | :---: | :--- |
| `HOST` | `127.0.0.1` | Network interface IP binding for FastAPI. |
| `PORT` | `8000` | HTTP port for the backend server. |
| `LOG_LEVEL` | `info` | Logging verbosity (`debug`, `info`, `warning`, `error`). |
| `MAX_CONCURRENT_SCANS` | `3` | Maximum concurrent Playwright browser tabs. |
| `PAGE_TIMEOUT_MS` | `15000` | Playwright page navigation timeout in milliseconds. |
| `REGISTRY_ADMIN_TOKEN` | `""` | Secret token required for admin brand registration APIs. |
| `WEIGHT_VISUAL` | `0.30` | Baseline weight for the Visual Perceptual Analyzer. |
| `WEIGHT_DOM` | `0.25` | Baseline weight for the DOM Structural Analyzer. |
| `WEIGHT_FORM` | `0.20` | Baseline weight for the Form Action Analyzer. |
| `WEIGHT_DOMAIN` | `0.15` | Baseline weight for the Domain Hostname Analyzer. |
| `WEIGHT_ASSETS` | `0.10` | Baseline weight for the Assets & Hotlinking Analyzer. |
| `THRESHOLD_LOW_RISK` | `20` | Score cutoff dividing low risk from suspicious portals. |
| `THRESHOLD_SUSPICIOUS` | `70` | Score cutoff dividing suspicious from high-risk clones. |

---

## 12. Security Considerations & Threat Modeling

### Sandboxing & SSRF Mitigation
- **Server-Side Request Forgery (SSRF):** The backend renders arbitrary, user-supplied URLs. To prevent attackers from using the scanner to inspect internal cloud metadata services (`http://169.254.169.254`) or local network services, the fetcher enforces strict URL protocol whitelisting (`http://` and `https://` only) and can be configured with `ALLOW_PRIVATE_HOSTS=False` in production environments.
- **Headless Browser Exploitation:** Playwright runs inside isolated Chromium contexts with disabled file system access and restricted permissions.

### Admin Token Security
- All brand registration and verification endpoints use constant-time string comparisons (`hmac.compare_digest`) to prevent timing attack enumeration.

### Privacy & Data Sanitization
- The system never stores entered passwords. The fetcher only extracts input element metadata and form target destinations; no credential values are ever cached or written to disk.

---

## 13. Future Enhancements & Scalability Roadmap

1. **Distributed Celery / Redis Task Queue:** Evolve from local asyncio semaphores to a distributed Redis/Celery worker cluster for enterprise-scale processing handling thousands of concurrent URL scans.
2. **Deep Learning Visual Transformer (ViT) Embeddings:** Supplement SSIM and pHash with fine-tuned Vision Transformers to detect visually transformed, responsive, or mobile-optimized clones.
3. **WHOIS & Passive DNS Age Integration:** Query live WHOIS APIs to dynamically score newly registered domains (< 14 days old).
4. **Certificate Transparency Log Ingestion:** Automatically monitor CT logs in real-time to detect TLS certificates issued for lookalike brand hostnames before attacks launch.
5. **Multi-Browser Extension Marketplace Deployment:** Package and sign extensions for official publication on the Chrome Web Store and Firefox Add-ons repository.

---

*Authored by the Fake Login Page Detector Engineering & Security Team.*
