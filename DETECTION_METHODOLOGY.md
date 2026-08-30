# 🔬 PhishGuard — Threat Detection Methodology & Heuristics

**Document Classification:** Detection Engineering Specification  
**Version:** 3.0.0

---

## 1. Overview & Detection Philosophy

PhishGuard employs a **defense-in-depth heuristic architecture** that evaluates digital artifacts across multi-dimensional indicator vectors rather than relying on a single binary rule or opaque AI verdict.

A single suspicious indicator (e.g. unencrypted HTTP or an elevated-risk TLD like `.xyz`) does not automatically equate to malice. Risk is computed through a **weighted composite index ($0–100$)** that accounts for indicator clustering and severity tiers.

---

## 2. Mathematical & Algorithmic Modules

### 2.1 Shannon Domain Entropy (Algorithmic Domain Generation)
To identify algorithmically generated domains (DGA) and randomized hex hostnames, PhishGuard calculates Shannon Entropy over the registered domain string:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where $P(x_i)$ is the empirical probability of character $x_i$ appearing across length $n$.
* **Entropy $\ge 3.85\text{ bits/char}$ ($n \ge 8$):** Flags an `ELEVATED` randomness indicator (`HIGH_DOMAIN_ENTROPY`).
* **Entropy $< 3.50\text{ bits/char}$:** Evaluated as natural human-readable orthography.

### 2.2 Brand Typosquatting & Levenshtein Matrix
PhishGuard maintains a centralized dictionary of 100+ targeted financial, tech, and enterprise brands (`src/engine/data/brands.js`).

1. **Character Substitution Normalization:** Maps visual confusables (e.g. `0` $\rightarrow$ `o`, `1` $\rightarrow$ `l`, `rn` $\rightarrow$ `m`, `vv` $\rightarrow$ `w`).
2. **Normalized Levenshtein Distance Matrix:**
$$\text{lev}(a, b) = \begin{cases} |a| & \text{if } |b| = 0, \\ |b| & \text{if } |a| = 0, \\ \text{lev}(\text{tail}(a), \text{tail}(b)) & \text{if } a[0] = b[0], \\ 1 + \min(\text{lev}(\text{tail}(a), b), \text{lev}(a, \text{tail}(b)), \text{lev}(\text{tail}(a), \text{tail}(b))) & \text{otherwise.} \end{cases}$$
3. **Subdomain Shadowing:** Flags instances where a legitimate brand name is placed in subdomains (e.g. `paypal.com.account-verify.ru`) while the true Second-Level Domain (SLD) belongs to an unassociated entity.
4. **Combosquatting:** Flags brand slugs paired with operational lure words (`paypal-security`, `chase-verify`).

### 2.3 Unicode Homoglyphs & Punycode (IDN) Spoofing
* **Punycode Scanner:** Identifies `xn--` domain prefixes indicating Internationalized Domain Names.
* **Lookalike Character Table:** Checks non-ASCII code points against known Cyrillic and Greek confusables (e.g. Cyrillic `а` U+0430 imitating Latin `a` U+0061).

### 2.4 Top-Level Domain (TLD) Risk Profiling
* Evaluates statistical registrar abuse rates from curated threat intelligence metadata (`src/engine/data/tldMetadata.js`).
* High-abuse TLDs (`.xyz`, `.top`, `.tk`, `.ru`, `.buzz`, `.click`) contribute contextual risk points ($+10$ to $+18$).
* High-trust authenticated TLDs (`.gov`, `.mil`, `.edu`, `.gov.in`) apply negative risk modifiers ($-10$ to $-20$).

### 2.5 Lexical & Structural Vectors
* **IP-as-Host:** Raw IPv4/IPv6 socket connections ($+30$ points).
* **Authority Auth Masquerade:** Deceptive `@` basic auth credentials in URL authority ($+35$ points).
* **Subdomain Nesting:** Deep chains ($\ge 4$ subdomains) hiding the root domain on mobile screens ($+15$ points).
* **Dangerous Executable Extensions:** Direct paths to `.exe`, `.scr`, `.bat`, `.apk`, `.msi` ($+35$ points).
* **Open Redirect Parameters:** Embedded `redirect=http://...` parameters ($+25$ points).

### 2.6 Social Engineering & NLP Tokenizers (SMS & Email)
* **Urgency Patterns:** Artificial deadlines ("within 24 hours"), fear triggers ("legal action", "arrest warrant"), account panic ("locked", "suspended").
* **Harvesting Lures:** Unsolicited OTP requests, password confirmation links, fake lottery wins, KYC update requirements.
* **Contextual Negation:** Educational advisories (e.g. "Never share your OTP with anyone") are recognized through negative context filters and excluded from credential-harvesting alerts.
* **Email Display Name Spoofing:** Identifies header discrepancies where display names claim trusted brand status while the envelope originates from unrelated domains.

### 2.7 Android APK Namespace Analysis
* **Reverse-DNS Validation:** Validates compliance with standard Java package naming (`com.company.app`).
* **Official App Shadowing:** Flags deceptive variants of official applications (`com.whatsapp.update.free`).
* **Fake OS Services:** Flags unauthorized packages claiming `com.android.*` or `com.google.android.*` system namespaces.
* **Mod / Crack Suffixes:** Detects high-risk suffixes (`.mod`, `.hack`, `.gems.generator`) linked to mobile banking trojans.

---

## 3. Composite Risk Scoring & Synthesis

### Verdict Thresholds:
$$\text{Verdict}(S) = \begin{cases} \text{SAFE} & 0 \le S \le 24 \\ \text{SUSPICIOUS} & 25 \le S \le 59 \\ \text{HIGH RISK} & 60 \le S \le 84 \\ \text{MALICIOUS} & 85 \le S \le 100 \end{cases}$$

### Hybrid Fusion Formula (When Gemini AI is Active):
$$S_{\text{final}} = \text{clamp}\Big(\text{round}\big(0.60 \cdot S_{\text{deterministic}} + 0.40 \cdot S_{\text{AI}}\big), 0, 100\Big)$$

* **Authoritative Local Baseline:** The deterministic score guarantees that clear-cut technical indicators (e.g. Punycode spoofing + IP host) cannot be completely silenced by LLM misinterpretation.
* **AI Contextual Value:** AI contributes nuanced semantic evaluation of novel phishing narratives and generates customized mitigation protocols.

