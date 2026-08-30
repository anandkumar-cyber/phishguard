# 🛡️ PhishGuard — Threat Analysis Workspace & Security Workbench

[![Tests](https://img.shields.io/badge/tests-114%20passed%20%7C%20100%25-10B981?style=flat-square)](tests/testRunner.js)
[![Benchmark](https://img.shields.io/badge/benchmark-~0.039ms%20%2F%20artifact-06B6D4?style=flat-square)](tests/benchmark.js)
[![Architecture](https://img.shields.io/badge/architecture-Dual--Core%20Hybrid-3B82F6?style=flat-square)](#-dual-core-threat-engine-architecture)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Zero-Secrets](https://img.shields.io/badge/security-Zero--Secrets%20%7C%20BYOK-10B981?style=flat-square)](#-security--privacy-architecture)

> **PhishGuard** is an intelligent cybersecurity threat analysis workbench and triage workspace that combines **100% offline deterministic security heuristics** with **optional AI-augmented threat matrix synthesis** (Google Gemini 2.5 Flash) to evaluate suspicious URLs, SMS messages, phishing emails, and Android APK package identifiers.

---

## 🎯 Problem Statement & Solution

Phishing, smishing, credential harvesting, and trojanized payloads remain the primary entry point for modern cyberattacks. Traditional detection tools either require heavy server infrastructure, rely on sluggish cloud lookups, or output opaque binary verdicts ("Phishing Detected") without explainability.

**PhishGuard delivers a transparent, explainable triage model:**
1. **Immediate Client-Side Deterministic Heuristics:** Algorithmic URL decomposition, Shannon entropy scoring, Levenshtein distance brand typosquatting, Punycode homoglyph detection, and NLP urgency tokenizers operating locally in your browser with sub-millisecond execution (~0.039ms average triage time).
2. **AI Threat Matrix Synthesis:** Contextual reasoning and threat actor intent classification powered by Google Gemini 2.5 Flash Structured Outputs (optional BYOK model).
3. **SOC-Grade Explainability:** Provides immediate clarity on **What We Found**, **Why It Matters ("Why?" section)**, **Multi-Vector Threat Matrix breakdown**, and a **Recommended Action Protocol**.

---

## 🧠 Dual-Core Threat Engine Architecture

```
                               ┌────────────────────────────────────────┐
                               │             USER INPUT                 │
                               │  (URL, Message/SMS, Email, APK Name)   │
                               └──────────────────┬─────────────────────┘
                                                  │
                                                  ▼
                               ┌────────────────────────────────────────┐
                               │   INPUT SANITIZER & NORMALIZER         │
                               │   - Scheme normalization & decoding    │
                               │   - Unicode / Punycode conversion      │
                               │   - Lexical tokenization               │
                               └──────────────────┬─────────────────────┘
                                                  │
                                                  ▼
                        ┌──────────────────────────────────────────────────────┐
                        │        PHISHGUARD DUAL-CORE THREAT ENGINE            │
                        ├──────────────────────────┬───────────────────────────┤
                        │                          │                           │
                        ▼                          ▼                           ▼
       ┌───────────────────────────────┐ ┌───────────────────┐ ┌───────────────────────────────┐
       │   DETERMINISTIC HEURISTICS    │ │  IOC EXTRACTION   │ │    AI THREAT MATRIX SYNTHESIS  │
       │   - Shannon Entropy (DGA)     │ │  - Elevated TLDs  │ │    - Gemini 2.5 Flash (BYOK)   │
       │   - Levenshtein Brand Matrix  │ │  - Credential tags│ │    - Structured Output Schema  │
       │   - Punycode IDN Homoglyphs   │ │  - Urgency triggers│ │    - Contextual Reasoning      │
       │   - IP as Host / Obfuscation  │ │  - Suffix checks  │ │    - SOC Action Protocol       │
       │   - Authority Auth Masquerade │ │  - Brand shadowing│ │    (Optional Augmentation)     │
       │   (100% Offline & Instant)    │ └─────────┬─────────┘ └───────────────┬───────────────┘
       └───────────────┬───────────────┘           │                           │
                       │                           │                           │
                       └───────────────────────────┼───────────────────────────┘
                                                   │
                                                   ▼
                               ┌────────────────────────────────────────┐
                               │       THREAT SCORE MATRIX ENGINE       │
                               │  - Weighted composite risk calculation │
                               │  - Multi-factor severity assignment    │
                               │  - Transparent explainability mapping  │
                               └──────────────────┬─────────────────────┘
                                                  │
                                                  ▼
                               ┌────────────────────────────────────────┐
                               │          SOC WORKBENCH HUD             │
                               │  - Live Threat Verdict & Matrix Table  │
                               │  - Real-Time Session Telemetry         │
                               │  - Searchable Investigation History    │
                               │  - Interactive Live URL Inspector      │
                               │  - JSON / Markdown Report Exporter     │
                               └────────────────────────────────────────┘
```

---

## 🔬 Detection Modules & Mathematical Formulations

See [`DETECTION_METHODOLOGY.md`](DETECTION_METHODOLOGY.md) for full algorithmic specifications.

### 1. Shannon Domain Entropy (DGA Detection)
Quantifies domain unpredictability to detect algorithmically generated domains (DGA):
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
* *High Entropy ($\ge 3.85\text{ bits/char}$):* Identifies randomized alphanumeric strings frequently used in disposable phishing domains.

### 2. Levenshtein Distance & Brand Combosquatting
Computes edit distance against a centralized database of 100+ targeted enterprise brands (`src/engine/data/brands.js`):
$$\text{lev}(a, b) = \begin{cases} |a| & \text{if } |b| = 0, \\ |b| & \text{if } |a| = 0, \\ \text{lev}(\text{tail}(a), \text{tail}(b)) & \text{if } a[0] = b[0], \\ 1 + \min(\text{lev}(\text{tail}(a), b), \text{lev}(a, \text{tail}(b)), \text{lev}(\text{tail}(a), \text{tail}(b))) & \text{otherwise.} \end{cases}$$
* Identifies character lookalikes (`paypa1.com`), combosquatting (`paypal-security-verify.com`), and subdomain shadowing (`paypal.com.account-auth.ru`).

### 3. Internationalized Domain Names (IDN) & Homoglyphs
* Detects Punycode (`xn--`) domain indicators.
* Cross-references characters against Cyrillic and Greek Unicode confusable tables (e.g. Cyrillic `а` U+0430 imitating Latin `a` U+0061).

### 4. Structural & Lexical Vector Analysis
* **IP Address as Host:** Detects direct IPv4/IPv6 socket connections.
* **Authority Auth Masquerade:** Detects deceptive user info and `@` masquerading in URL authority.
* **Subdomain Nesting:** Flags deep subdomain chains ($\ge 4$) designed to truncate visible URLs on mobile screens.
* **Top-Level Domain (TLD) Risk Profiling:** Evaluates statistical registrar abuse rates from curated metadata (`src/engine/data/tldMetadata.js`).

### 5. Social Engineering & Urgency Tokenizers (SMS & Email)
* Linguistic evaluation of artificial deadline pressure ("within 24 hours"), fear/coercion ("legal action", "arrest warrant"), OTP harvesting, and prize lures.
* Contextual negation filters prevent false alarms on legitimate security advisories ("Never share your OTP").
* Header anomaly detection identifying Display Name spoofing (e.g., `From: "PayPal Support" <alert98@gmail.com>`).

### 6. Android APK Namespace Heuristics
* Structural reverse-DNS validation, brand shadowing (`com.whatsapp.update.free`), fake OS service masquerades (`com.android.system.patch`), and trojanized mod suffixes.

---

## 🔒 Security & Privacy Architecture

See [`SECURITY_MODEL.md`](SECURITY_MODEL.md) for full threat modeling.

* **Zero Compromised Secrets:** No hardcoded API keys exist in the codebase.
* **Bring-Your-Own-Key (BYOK) Model:** Users can optionally supply their personal Gemini API key. Keys are saved strictly in origin-scoped `localStorage` and sent only to Google's official Gemini endpoint.
* **No Blind URL Fetching (SSRF Protection):** Decomposes URL strings algorithmically without executing uncontrolled background HTTP requests to suspicious domains.
* **XSS Sanitization:** All untrusted user inputs, IOCs, and AI responses are contextually escaped prior to DOM rendering.
* **Local Data Wipe:** One-click purge of all stored investigation records, session telemetry, and stored keys.

---

## ⚡ Performance Benchmarking

Measured over 1,000 sequential triage analyses using the included benchmark suite (`tests/benchmark.js`):

| Metric | Measured Value |
|---|---|
| **Average Triage Latency** | **0.0392 ms / artifact** (~39 microseconds) |
| **Minimum Latency** | **0.0050 ms** |
| **Maximum Latency** | **2.1002 ms** |
| **Throughput** | **~25,300+ analyses / second** |
| **Test Suite Coverage** | **114/114 Passed (100% Precision across curated vectors)** |

---

## 🚀 Running Locally & Testing

### 1. Clone & Run (No Build Tools Required)
```bash
# Clone the repository
git clone https://github.com/lucifer12049/phishguard.git
cd phishguard

# Start a local static HTTP server
python3 -m http.server 8000
# OR
npx serve .
```
Navigate to `http://localhost:8000` in any modern web browser.

### 2. Execute Automated Unit Tests
```bash
node tests/testRunner.js
```

### 3. Run Performance Benchmark
```bash
node tests/benchmark.js
```

---

## 📋 Honest Capabilities & Explicit Disclosures

* ✅ **What PhishGuard Does:** Real-time client-side deterministic heuristic analysis (RFC 3986 URL parsing, Shannon entropy, Levenshtein brand distance, Punycode detection, lexical and social engineering tokenizing) combined with optional LLM threat synthesis.
* ⚠️ **What PhishGuard Does Not Do:** It does not perform active external DNS resolution, WHOIS queries, SSL certificate chain inspection, dynamic sandbox detonation, or compiled Android DEX bytecode reverse-engineering in the browser.

---

## 💼 Portfolio Highlights & Resume Bullets

* **Architected an offline-first Cyber Threat Intelligence Workbench** in modular ES6 that decomposes URLs, SMS messages, and emails across 50+ heuristic vectors with sub-millisecond execution (~0.039ms average triage time).
* **Integrated Google Gemini 2.5 Flash via native Structured Outputs (JSON Schema)** as an optional BYOK augmentation layer, delivering hybrid threat scoring with authoritative deterministic fallback.
* **Engineered an enterprise-inspired SOC design system and interactive workbench** featuring live Threat Matrix HUDs, explainable "Why?" key factors, real-time session telemetry, and incident report generation (JSON/Markdown/Print).
* **Hardened client-side security architecture** eliminating hardcoded credentials, mitigating XSS/SSRF vectors, and achieving 100% pass rates across 114 automated unit test cases.

---

## 👨‍💻 Author

**Anand Kumar**  
B.Tech in Artificial Intelligence & Data Science  
[GitHub Profile](https://github.com/lucifer12049) &middot; [Live Demo](https://lucifer12049.github.io/phishguard/)
