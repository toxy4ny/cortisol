# 🧪 cortisol — WAF Bypass & Normalization Stress Tester (for Red Teams)

> **Lab Mode Only** — Never test without explicit written permission.

`cortisol` is a lightweight, offensive security CLI tool designed to **stress-test web application firewalls (WAFs)** by exploiting inconsistencies in URL normalization logic. It helps red teams and penetration testers identify potential bypasses for common protections against **SQLi, XSS, SSRF, and Path Traversal** — especially when WAFs decode payloads **only once**, while the backend decodes them **multiple times**.

Inspired by real-world bug bounty findings like:

```
/api/v1/%2e%2e/%2e%2e/config?id=1%252bUNION%252bSELECT%252bsecrets--
```

`cortisol` automates the generation and testing of **multi-encoded payloads** to detect behavioral differences in WAF vs. application responses.

---

## 🔍 How It Works: The Normalization Bypass Theory

Many WAFs apply security rules **after a single URL-decoding step**, while web servers (e.g., Apache, Nginx, Tomcat) may **decode multiple times** before passing the request to the application.

This mismatch creates an opportunity:

| Encoding Level | WAF Sees                | Backend Decodes To      | Result                     |
|----------------|-------------------------|--------------------------|----------------------------|
| Raw            | `'`                     | `'`                      | Blocked (if WAF active)    |
| Single (%27)   | `%27`                   | `'`                      | Often blocked              |
| **Double (%2527)** | `%2527` → `%27`     | `%27` → `'`              | ✅ **WAF bypass possible!** |

Common bypass techniques include:
- Double/triple URL encoding (`%252f` → `/`)
- Mixed case (`%2f` vs `%2F`)
- Path obfuscation (`..%2f`, `....//`, `%2e%2e/`)
- UTF-8 overlong sequences (e.g., `%c0%af`)

`cortisol` systematically tests these variants and highlights responses that **differ from a benign baseline**, indicating potential bypass.

---

## 🚀 Features

- 🔍 **Auto WAF Detection** — identifies Cloudflare, AWS WAF, Sucuri, Imperva, ModSecurity, Akamai, and more via HTTP headers.
- 🧬 **Multi-Encoding Payloads** — raw, single, double, and triple URL encoding for each vector.
- 📊 **Smart Diff Analysis** — compares status codes and response sizes against a clean request.
- 🎯 **Attack Templates** — built-in payloads for:
  - SQL Injection (`sqli`)
  - Local File Inclusion (`lfi`)
  - Server-Side Request Forgery (`ssrf`)
  - Cross-Site Scripting (`xss`)
- 🖥️ **Beautiful CLI** — ASCII banner + colorized output via `rich`.
- 📁 **JSONL Logging** — machine-readable results for integration with SIEM or custom pipelines.

---

## ⚠️ Ethical Use Only

> **`cortisol` is for authorized penetration testing and bug bounty programs ONLY.**  
> Never scan systems without explicit written consent. Misuse may violate laws like the CFAA or GDPR.

This tool runs in **lab mode** by default (no consent checks), intended for controlled environments like:
- Internal red team exercises
- CTFs and training labs (e.g., `testfire.net`)
- Client engagements **with signed scope**

---

## 🛠️ Installation

```bash
git clone https://github.com/toxy4ny/cortisol.git
cd cortisol
pip install -r requirements.txt
```

Or install directly:
```bash
pip install requests click rich
```

> ✅ Works on **Parrot OS, Kali, Ubuntu 24.04, and Athena OS**.

---

## ▶️ Usage Examples

### Basic XSS Test
```bash
python3 cortisol.py -t https://target.com/search -p q -a xss
```

### SQLi Fuzzing with Output Logging
```bash
python3 cortisol.py \
  --target https://api.client.local/user \
  --param id \
  --attack sqli \
  --output ./logs/cortisol-sqli-20251225.jsonl
```

### Verbose Mode (show full URLs)
```bash
python3 cortisol.py -t https://testfire.net/index.jsp -p content -a xss -v
```

---

## 📤 Sample Output

```
WAF Bypass & Normalization Stress Tester
Lab Mode — Use only in authorized environments

Target: https://testfire.net/index.jsp
Param: content
Attack: XSS

🔍 Probing for WAF...
🛡️  Detected WAF: Unknown or No WAF Detected

┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━┳━━━━━━┳━━━━━━━┓
┃ Vector                   ┃ Encoding ┃ Status ┃ Size ┃ Diff? ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━╇━━━━━━╇━━━━━━━┩
│ <script>alert(1)</scr... │   raw    │  200   │ 6889 │  ✅   │
│ %253Cscript%253Ealert... │  double  │  200   │ 6992 │  ✅   │
└──────────────────────────┴──────────┴────────┴──────┴───────┘
```

✅ = response differs from baseline → **potential vulnerability**

---

## 📂 Output Format (JSONL)

Each line in the log file is a JSON object:

```json
{
  "timestamp": 1712345678.123,
  "target": "https://target.com/api",
  "param": "id",
  "attack": "sqli",
  "payload": "1%2527%2520UNION...",
  "encoding": "double",
  "status": 200,
  "size": 4096,
  "diff": true,
  "detected_waf": "Cloudflare"
}
```

Perfect for ingestion into **Supabase**, **Elasticsearch**, or custom analytics dashboards.

---

## 🧪 Lab Testing Tip

Use **IBM’s Testfire** (a legal, vulnerable web app) for safe practice:

```bash
python3 cortisol.py -t https://testfire.net/index.jsp -p content -a xss
```

> 💡 Note: `testfire.net` has no WAF, so all payloads reflect directly — ideal for validating tool behavior.

---

## 🔮 Future Roadmap

- [ ] Reflected XSS confirmation (HTML parsing)
- [ ] Path traversal fuzzing (`/api/%2e%2e/config`)
- [ ] Integration with **Nikki AI** for RAG-powered attack suggestions
- [ ] Consent scope validation (for production engagements)
- [ ] Dockerized version
---

## 🤝 Contribution

Bug reports, WAF signatures, and new bypass techniques welcome!  
This tool is built **by red teamers, for red teamers**.

> 🔒 Remember: With great power comes great responsibility.

---

## 📜 License

MIT — for educational and authorized security testing only.

---

> **Author**: toxy4ny / Hackteam.Red  
> **GitHub**: [github.com/toxy4ny/cortisol](https://github.com/toxy4ny/cortisol)  
> **Inspired by**: Real-world bug bounty writeups & WAFW00F logic

---

*Use wisely. Test legally. Break responsibly.*
