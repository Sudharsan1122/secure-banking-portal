# Burp Suite Penetration Testing & Forensic Evidence Guide

**Document**: Burp Suite Verification & Vulnerability Mitigation Guide  
**System**: Secure Banking Portal: A Web Application for Secure Transactions and Vulnerability Mitigation  
**Assessment Tool**: Burp Suite Professional / Community Edition (v2024.1+)  
**Scope**: Dynamic Application Security Testing (DAST) across all API endpoints  

---

## 1. Overview of Forensic Evidence Pack

This directory ([`docs/BURP_EVIDENCE/`](file:///c:/Users/srine/OneDrive/Desktop/WAP%20Project/Secure-Banking-Portal/docs/BURP_EVIDENCE/)) contains raw HTTP request and response transcripts captured during dynamic security evaluations of the Secure Banking Portal.

Each transcript demonstrates the exact attack vector tested, the resulting HTTP status code, the defensive headers emitted, and the mitigation mechanism that prevented exploitation.

### Evidence Artifact Index:

| Item ID | File | Attack Class | Target Endpoint | HTTP Status | Mitigation Proved |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **EV-01** | [`01_sqli_blocked.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/01_sqli_blocked.txt) | SQL Injection | `POST /api/login.php` | `401 Unauthorized` | Native prepared statements (`ATTR_EMULATE_PREPARES=false`). |
| **EV-02** | [`02_xss_blocked.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/02_xss_blocked.txt) | Stored / DOM XSS | `POST /api/transfer.php` | `200 OK` (inert) | Nonce-based CSP 2.0 + safe DOM `textContent` rendering. |
| **EV-03** | [`03_csrf_blocked.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/03_csrf_blocked.txt) | CSRF (Cross-Origin) | `POST /api/transfer.php` | `403 Forbidden` | Synchronizer Token Pattern + `hash_equals()` validation. |
| **EV-04** | [`04_path_traversal_blocked.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/04_path_traversal_blocked.txt) | Path Traversal | `GET /api/download_statement.php` | `400 Bad Request` | Regex allowlist + `realpath()` canonical sandbox jail. |
| **EV-05** | [`05_rate_limit_lockout_429.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/05_rate_limit_lockout_429.txt) | Brute-Force Auth | `POST /api/login.php` | `429 Too Many Req` | Sliding-window limiter + 3-tier exponential lockout. |
| **EV-06** | [`06_idor_account_blocked.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/06_idor_account_blocked.txt) | Horizontal IDOR | `POST /api/transfer.php` | `403 Forbidden` | Tenant ownership validation (`WHERE id=:id AND user_id=:uid`). |
| **EV-07** | [`07_malicious_upload_blocked.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/07_malicious_upload_blocked.txt) | Polyglot Web Shell | `POST /api/avatar.php` | `400 Bad Request` | Extension whitelist, `finfo` MIME check, `getimagesize()` geometry. |
| **EV-08** | [`08_csv_injection_defused.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/08_csv_injection_defused.txt) | CSV Injection | `GET /api/export_statement.php` | `200 OK` (defused) | CWE-1236 leading apostrophe prefix on `=,+,-,@,\t,\r`. |
| **EV-09** | [`09_ssrf_blocked.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/09_ssrf_blocked.txt) | SSRF (Loopback/Cloud) | `POST /api/admin_diagnostics.php` | `400 Bad Request` | DNS resolution checking + RFC 1918 / 3927 CIDR subnet blocks. |
| **EV-10** | [`10_burp_intruder_bruteforce_log.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/10_burp_intruder_bruteforce_log.txt) | Intruder Fuzzing | `POST /api/login.php` | `429 Too Many Req` | Fast-path CPU drop (68ms $\to$ 10ms) & progressive freeze. |

---

## 2. Step-by-Step Reproduction Guide in Burp Suite

### Configuring the Environment:
1. Ensure the Secure Banking Portal is running at `http://127.0.0.1:8080/`.
2. Configure your browser proxy to `127.0.0.1:8080` (or use Burp's embedded Chromium browser via **Proxy $\to$ Open Browser**).
3. Disable Burp proxy interception temporarily to authenticate as `john_doe` / `User@1234`.

### Testing SQL Injection in Burp Repeater:
1. Intercept a login request to `/api/login.php`.
2. Send the request to Repeater (**Ctrl + R**).
3. Change the JSON payload body to:
   ```json
   {"username": "admin' OR '1'='1' -- ", "password": "password123"}
   ```
4. Click **Send**.
5. Observe the response: HTTP 401 Unauthorized with clean JSON error; zero MySQL error traces emitted.

### Testing CSRF Protection in Burp Repeater:
1. Intercept a transfer request to `/api/transfer.php`.
2. In Repeater, remove the `X-CSRF-Token` header.
3. Click **Send**.
4. Observe the response: HTTP 403 Forbidden with `{"status":"error","code":403,"message":"Invalid or missing CSRF token."}`.

### Testing Rate Limiting in Burp Intruder:
1. Send the login request to Intruder (**Ctrl + I**).
2. Set the attack type to **Sniper**.
3. Position the payload marker around the password field:
   ```json
   {"username":"john_doe","password":"§password§"}
   ```
4. Under the **Payloads** tab, add a list of 20 arbitrary incorrect passwords.
5. Click **Start Attack**.
6. Observe the results table:
   - Requests 1–4 return HTTP 401 (latency ~68 ms).
   - Request 5 returns HTTP 429 Too Many Requests with header `Retry-After: 300` (latency ~10 ms).
   - All subsequent requests return HTTP 429 immediately, protecting the server against Bcrypt hashing exhaustion.

---

## 3. Before vs. After Mitigation Comparison

| Attack Vector | Vulnerable Implementation (Before) | Secure Banking Portal Implementation (After) |
| :--- | :--- | :--- |
| **SQL Injection** | SQL query built via string concatenation:  <br>`"SELECT * FROM users WHERE u='$u' AND p='$p'"`  <br>$\to$ Result: **Bypassed authentication; full database dump**. | Parameterized native prepared statement:  <br>`$pdo->prepare("SELECT ... WHERE username = :u")`  <br>$\to$ Result: **Treated as literal string; login fails safely**. |
| **Cross-Site Scripting** | Dynamic output injected via `element.innerHTML = data.remark`  <br>$\to$ Result: **Session cookie stolen; account taken over**. | Dynamic output bound via `element.textContent = data.remark` + CSP 2.0 Nonce  <br>$\to$ Result: **Displayed as plain text; script execution blocked**. |
| **CSRF** | State-changing POST endpoints depend only on session cookie  <br>$\to$ Result: **Attacker forces unauthorized \$5,000 transfer**. | Synchronizer Token Pattern (`X-CSRF-Token`) + `SameSite=Strict` cookies  <br>$\to$ Result: **Request missing token rejected with HTTP 403**. |
| **Path Traversal** | File path constructed with raw input:  <br>`readfile("statements/" . $_GET['date'] . ".csv")`  <br>$\to$ Result: **Attacker downloads `/etc/passwd` or `.env`**. | Regex format check + `realpath()` sandbox validation:  <br>`if (!str_starts_with($path, $base)) { exit; }`  <br>$\to$ Result: **Traversal rejected with HTTP 400**. |
| **CSV Injection** | Direct export of user remarks into CSV cells  <br>$\to$ Result: **Excel executes `=cmd\|'/C calc'!A0` via DDE**. | Automatic prefixing with `'` on dangerous characters  <br>$\to$ Result: **Excel renders cell as harmless literal text**. |
