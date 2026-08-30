# 🛡️ PhishGuard — Security Architecture & Threat Model

**Document Classification:** Technical Architecture & Security Specification  
**Version:** 3.0.0  
**Target Platform:** Modern Web Browsers (ECMAScript 2022+ Native ES Modules)

---

## 1. Threat Model & System Boundaries

PhishGuard is designed to operate primarily as an **isolated client-side triage environment**. Its fundamental security objective is to allow security analysts and end users to inspect potentially malicious digital artifacts (URLs, email headers, SMS lures, Android package identifiers) **without exposing the client endpoint to compromise**.

```
┌────────────────────────────────────────────────────────────────────────┐
│ BROWSER SANDBOX BOUNDARY (Client Endpoint)                             │
│                                                                        │
│  ┌───────────────────────┐          ┌───────────────────────────────┐  │
│  │ Untrusted User Input  │ ───────► │ Sanitizer & Contextual Escaper│  │
│  │ (URLs, SMS, APK, etc.)│          │ (XSS Neutralization Layer)    │  │
│  └───────────────────────┘          └──────────────┬────────────────┘  │
│                                                    │                   │
│                                                    ▼                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ 100% OFFLINE DETERMINISTIC HEURISTIC ENGINE (Authoritative Score)│  │
│  │ - RFC 3986 Lexical Parser        - Shannon Entropy Engine        │  │
│  │ - Levenshtein Brand Matrix       - Punycode / Homoglyph Scanner  │  │
│  │ - TLD Registrar Metadata         - Android Namespace Validator   │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
│                                     │                                  │
│                 ┌───────────────────┴───────────────────┐              │
│                 ▼                                       ▼              │
│  ┌──────────────────────────────┐     ┌─────────────────────────────┐  │
│  │ Local Storage Sandbox        │     │ Optional BYOK AI Connector  │  │
│  │ (Origin-scoped localStorage) │     │ (Opt-in contextual layer)   │  │
│  └──────────────────────────────┘     └─────────────┬───────────────┘  │
└─────────────────────────────────────────────────────┼──────────────────┘
                                                      │ HTTPS REST Call
                                                      ▼ (Direct TLS 1.3)
                                        ┌─────────────────────────────┐
                                        │ Google Gemini 2.5 Endpoint  │
                                        │ (api.generativelanguage...) │
                                        └─────────────────────────────┘
```

---

## 2. Assets & Trust Boundaries

### Protected Assets:
1. **User Identity & Privacy:** Submitted artifacts may contain sensitive corporate domain names, customer emails, or private phone numbers.
2. **User API Credentials:** User-provided Gemini API keys (BYOK).
3. **Endpoint DOM Integrity:** Prevention of Cross-Site Scripting (XSS) from hostile payload strings.

### Trust Zones:
* **Untrusted Zone:** All user inputs, pasted SMS/email text, decoded URLs, and remote AI responses.
* **Semi-Trusted Zone:** Local browser `localStorage` (accessible only to scripts within the same origin).
* **Controlled External Zone:** Official Google Gemini API endpoint (`generativelanguage.googleapis.com`).

---

## 3. Vulnerability Mitigation & Defenses

### 3.1 Cross-Site Scripting (XSS) Mitigation
Attackers frequently embed script payloads within phishing URLs or message bodies (e.g. `http://malicious.com/<script>alert(1)</script>`).
* **Universal Contextual Escaping:** All user-supplied strings, extracted IOCs, and generated summaries pass through `escapeHtml()` converting special characters (`&`, `<`, `>`, `"`, `'`) into safe HTML entities before being injected into templates.
* **Safe Protocol Neutralization:** The `sanitizeUrl()` helper actively strips and neutralizes hazardous URI schemes including `javascript:`, `data:`, and `vbscript:`, replacing them with safe `#unsafe-protocol-blocked` anchors.

### 3.2 Server-Side Request Forgery (SSRF) & Blind Fetch Defense
A common flaw in naive URL checkers is making automatic background HTTP `fetch()` requests or DNS queries to untrusted targets, exposing internal network infrastructure or triggering malicious webhooks.
* **Zero Blind Requests:** PhishGuard decomposes URL syntax purely through string tokenization and regular expressions client-side. It **never performs automated network requests or socket connections to the target artifact**.

### 3.3 Bring-Your-Own-Key (BYOK) Secret Management
* **No Compromised Embedded Secrets:** The source code contains zero hardcoded API keys.
* **Origin-Scoped Persistence:** When a user configures their personal Gemini API key, it is saved exclusively in the browser's origin-scoped `localStorage`.
* **Honest Privacy Disclosure:** We explicitly disclose to users that client-side browser storage is not an encrypted hardware vault (e.g. HSM/KMS) and is accessible to any script executing under the same origin.
* **Zero Exfiltration:** API keys are injected solely into the `key=` query parameter of outbound requests directed to Google's official Gemini endpoint and are omitted from telemetry logs and exports.

---

## 4. Privacy Model: Local-First vs AI-Assisted

| Analysis Mode | Network Activity | Data Sent Outside Browser | Offline Capable |
|---|---|---|---|
| **Deterministic Mode (Default)** | **Zero** (100% client-side) | None | **Yes (100%)** |
| **Hybrid Mode (Without Key)** | **Zero** (100% client-side) | None | **Yes (100%)** |
| **Hybrid Mode (With BYOK Key)** | Encrypted HTTPS call to Google Gemini | Target payload + Heuristic tags | Requires Internet |
| **AI Only Mode** | Encrypted HTTPS call to Google Gemini | Target payload + Heuristic tags | Requires Internet |

---

## 5. Explicit Limitations

1. **No Live Sandbox Execution:** PhishGuard does not execute JavaScript inside suspicious web pages or detonate malware payloads in an isolated virtual machine.
2. **No Active DNS / WHOIS Resolving:** The tool does not perform live socket lookups to query domain registration ages or IP ASN histories directly from the browser (due to browser CORS/socket constraints).
3. **No Binary Decompilation:** APK analysis is restricted to package identifier syntax and namespace shadowing heuristics; it does not decompile DEX bytecode.

