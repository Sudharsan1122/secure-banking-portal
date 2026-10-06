# Web Application Vulnerability Mitigation Index

**System**: Secure Banking Portal: A Web Application for Secure Transactions and Vulnerability Mitigation  
**Standard**: OWASP Top 10 (2021) & CWE Top 25 Most Dangerous Software Weaknesses  
**Status**: 100% Mitigated across all 12 Attack Classes  

---

## 1. Executive Summary

In financial and fintech web applications, architectural vulnerabilities represent severe operational and monetary risk. Rather than relying on superficial security through obscurity, the **Secure Banking Portal** implements a defense-in-depth architecture that enforces strict input validation, cryptographic integrity, parameter binding, contextual escaping, and active SIEM telemetry.

This directory documents the **12 core web application vulnerabilities** defended by our portal, detailing the theoretical exploit vectors, vulnerable anti-patterns, our hardened production implementations, dynamic forensic evidence, and automated regression test suites.

---

## 2. Vulnerability Mitigation Matrix

| # | Vulnerability File | Attack Class | OWASP Category | CWE | Target Endpoint | Severity | Status |
|---|---|---|---|---|---|---|---|
| **01** | [`01-sqli-login.md`](01-sqli-login.md) | SQL Injection (Login) | A03:2021 – Injection | CWE-89 | `POST /api/login.php` | **Critical (9.8)** | ✅ Mitigated |
| **02** | [`02-sqli-search.md`](02-sqli-search.md) | SQL Injection (Search) | A03:2021 – Injection | CWE-89 | `GET /api/transactions.php` | **High (8.6)** | ✅ Mitigated |
| **03** | [`03-stored-xss.md`](03-stored-xss.md) | Stored XSS (Remarks) | A03:2021 – Injection | CWE-79 | `POST /api/transfer.php` | **High (8.2)** | ✅ Mitigated |
| **04** | [`04-reflected-xss.md`](04-reflected-xss.md) | Reflected XSS (Query) | A03:2021 – Injection | CWE-79 | `GET /admin/users.php` | **Medium (6.1)** | ✅ Mitigated |
| **05** | [`05-idor-account.md`](05-idor-account.md) | IDOR (Account Access) | A01:2021 – Broken Access Control | CWE-639 | `POST /api/transfer.php` | **High (8.5)** | ✅ Mitigated |
| **06** | [`06-idor-transaction.md`](06-idor-transaction.md) | IDOR (Transaction Details) | A01:2021 – Broken Access Control | CWE-639 | `GET /api/transactions.php` | **Medium (6.5)** | ✅ Mitigated |
| **07** | [`07-csrf.md`](07-csrf.md) | Cross-Site Request Forgery | A01:2021 – Broken Access Control | CWE-352 | `POST /api/transfer.php` | **High (8.1)** | ✅ Mitigated |
| **08** | [`08-clickjacking.md`](08-clickjacking.md) | UI Redressing / Clickjacking | A05:2021 – Security Misconfiguration | CWE-1021 | `ALL /frontend/*.html` | **Medium (5.4)** | ✅ Mitigated |
| **09** | [`09-dom-xss.md`](09-dom-xss.md) | DOM-Based XSS | A03:2021 – Injection | CWE-79 | `ALL /js/*.js` | **Medium (6.5)** | ✅ Mitigated |
| **10** | [`10-path-traversal.md`](10-path-traversal.md) | Directory / Path Traversal | A01:2021 – Broken Access Control | CWE-22 | `GET /api/download_statement.php` | **High (7.5)** | ✅ Mitigated |
| **11** | [`11-bac.md`](11-bac.md) | Broken Access Control | A01:2021 – Broken Access Control | CWE-284 | `ALL /admin/*.php` | **Critical (9.1)** | ✅ Mitigated |
| **12** | [`12-file-upload.md`](12-file-upload.md) | Malicious File Upload | A04:2021 – Insecure Design | CWE-434 | `POST /api/avatar.php` | **Critical (9.8)** | ✅ Mitigated |

---

## 3. How to Run Automated Attack Regression Tests

All 12 mitigations are continuously verified by our dedicated attack regression suite:

```bash
# Run the entire 12-attack regression suite
php tests/attacks/run_attack_tests.php
```

Or run any single attack regression test individually:
```bash
php tests/attacks/test_01_sqli_login.php
php tests/attacks/test_07_csrf.php
```

---

## 4. Attacker Proof-of-Concept Fixtures
- [`docs/csrf-attack.html`](../csrf-attack.html): External adversary site simulating a cross-origin forged fund transfer.
- [`docs/clickjacking-attack.html`](../clickjacking-attack.html): External adversary site attempting UI redressing via transparent iframe overlay.
