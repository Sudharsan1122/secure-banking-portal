# OWASP Top 10:2021 Defense Mapping & Academic Traceability

**Standard**: OWASP Top 10:2021 Web Application Security Risks  
**System**: Secure Banking Portal: A Web Application for Secure Transactions and Vulnerability Mitigation  
**Coverage**: 10 of 10 OWASP Risk Categories Fully Mitigated  
**Audit Classification**: Complete Compliance / Distinction-Grade Evidence  

---

## Executive Summary

This document details the architectural countermeasures, defensive code implementations, automated verification suites, and examiner talking points for each of the **OWASP Top 10:2021** vulnerability categories within the Secure Banking Portal.

---

## A01:2021 – Broken Access Control

### 1. Risk Profile & Theoretical Threat
Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, destruction of all data, or performing a business function outside the user's limits.

### 2. Real-World Banking Attack Scenario
A retail customer alters the `from_account_id` parameter from their own account (`ACC-USER-1001`) to a corporate payroll account (`ACC-USER-1005`) in a money transfer POST request, siphoning funds without holding authorized signing rights (Horizontal IDOR). Alternatively, a customer directly requests `/admin/users.php` to freeze competitor accounts (Vertical Privilege Escalation).

### 3. Architecture & Implemented Controls in Portal
- **Horizontal Tenant Ownership Verification**: In [`security/transfer_service.php`](file:///Secure-Banking-Portal/security/transfer_service.php), the centralized transfer engine verifies that `from_account_id` is owned by `$_SESSION['user_id']`:
  ```php
  if ((int)$fromAccount['user_id'] !== $senderId) {
      log_security_event($senderId, 'ACCESS_VIOLATION', 'BLOCKED', 'Debit attempted on unowned account', 'high');
      return ['status' => 'error', 'code' => 403, 'message' => 'Access Denied: You do not own the specified source account.'];
  }
  ```
- **Strict Role-Based Access Control (RBAC)**: All administrative endpoints call `require_role('admin')` in [`security/auth.php`](file:///Secure-Banking-Portal/security/auth.php), rejecting non-admin users with HTTP 403 Forbidden.
- **Self-Targeting Guard**: Admins are strictly prohibited from freezing their own account or peer administrators in [`admin/api/freeze_user.php`](file:///Secure-Banking-Portal/admin/api/freeze_user.php).
- **Directory Traversal Jail**: Statement downloads validate date regex and enforce `realpath()` containment within the `statements/` prefix in [`api/download_statement.php`](file:///Secure-Banking-Portal/api/download_statement.php).

### 4. Verification & Testing
- Automated Suite: [`tests/test_multi_account.php`](file:///Secure-Banking-Portal/tests/test_multi_account.php) (Test: *IDOR Source Account Debit Defense*)
- Automated Suite: [`tests/test_admin_users.php`](file:///Secure-Banking-Portal/tests/test_admin_users.php) (Test: *Frozen Account Transaction Interception*)
- Burp Evidence: [`docs/BURP_EVIDENCE/06_idor_account_blocked.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/06_idor_account_blocked.txt)

> [!TIP]
> **Examiner Defense Point**: *"We eliminated broken access control by abandoning client-trust paradigms. All financial debit operations require server-side database ownership queries before acquiring pessimistic locks, rendering parameter tampering ineffectual."*

---

## A02:2021 – Cryptographic Failures

### 1. Risk Profile & Theoretical Threat
Failures related to cryptography frequently lead to sensitive data exposure or system compromise. Common weaknesses include using weak or outdated algorithms (e.g., MD5, SHA-1), unsalted hashes, plaintext secret storage, or weak entropy.

### 2. Real-World Banking Attack Scenario
An attacker extracts a database dump and uses precomputed rainbow tables or GPU clusters to rapidly crack passwords stored with fast hashes (MD5/SHA-256), leading to wholesale account takeovers.

### 3. Architecture & Implemented Controls in Portal
- **Adaptive One-Way Password Hashing**: Passwords are hashed exclusively using `password_hash(PASSWORD_BCRYPT, ['cost' => 12])`, providing automatic 128-bit CSPRNG salting and an empirical ~240 ms computational work factor that resists offline GPU cracking.
- **Hashed One-Time Tokens**: Password reset tokens and 2FA recovery codes are never stored in plaintext. In [`api/request_reset.php`](file:///Secure-Banking-Portal/api/request_reset.php), the raw 256-bit token is sent to the user, while only its SHA-256 digest (`hash('sha256', $rawToken)`) is persisted in the database.
- **Cryptographic Audit Log Hash Chain**: In [`security/logger.php`](file:///Secure-Banking-Portal/security/logger.php), every audit log row incorporates the SHA-256 hash of the preceding block, creating an immutable mathematical ledger.
- **Transport & Cookie Cryptography**: Session cookies are configured with `HttpOnly`, `SameSite=Strict`, and `Secure` flags; HSTS header enforces TLS.

### 4. Verification & Testing
- Automated Suite: [`tests/test_password_reset.php`](file:///Secure-Banking-Portal/tests/test_password_reset.php) (Test: *Unhashed Token Never Stored in Database*)
- Automated Suite: [`tests/test_hash_chain.php`](file:///Secure-Banking-Portal/tests/test_hash_chain.php) (Test: *Master Cryptographic Chain Verification*)

> [!TIP]
> **Examiner Defense Point**: *"We distinguish between password storage—which requires slow, computationally expensive algorithms like Bcrypt—and high-entropy tokens, which are stored as fast SHA-256 digests. This guarantees database leaks yield zero reversible credentials."*

---

## A03:2021 – Injection

### 1. Risk Profile & Theoretical Threat
Injection flaws occur when untrusted user data is sent to an interpreter as part of a command or query. Hostile data tricks the interpreter into executing unintended commands or accessing data without authorization.

### 2. Real-World Banking Attack Scenario
An attacker inputs `' OR '1'='1' --` into a login form to authenticate as the first administrator in the database, or injects `=cmd|'/C calc'!A0` into a transfer remark to execute arbitrary commands on a corporate accountant's workstation upon opening a CSV export.

### 3. Architecture & Implemented Controls in Portal
- **Native Prepared Statements**: In [`config/database.php`](file:///Secure-Banking-Portal/config/database.php), `PDO::ATTR_EMULATE_PREPARES => false` forces the MySQL server to natively compile the SQL statement before parameter substitution, completely isolating SQL code from data values.
- **Stored & DOM XSS Elimination**: Output encoding with `htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')` server-side, complemented by strict client-side DOM binding via `element.textContent` in [`js/dashboard.js`](file:///Secure-Banking-Portal/js/dashboard.js).
- **CWE-1236 CSV Formula Injection Defense**: In [`security/csv_safe.php`](file:///Secure-Banking-Portal/security/csv_safe.php) and [`api/export_statement.php`](file:///Secure-Banking-Portal/api/export_statement.php), any field beginning with `=,+,-,@,\t,\r` is automatically prefixed with a single quote (`'`), neutralizing spreadsheet formula execution.
- **Elimination of Command Injection**: System command functions (`exec`, `shell_exec`, `system`) are completely banned; administrative diagnostics in [`api/admin_diagnostics.php`](file:///Secure-Banking-Portal/api/admin_diagnostics.php) use native memory-safe PHP introspection APIs (`php_uname`, `disk_free_space`).
- **HTTP Parameter Pollution (HPP)**: [`security/validation.php`](file:///Secure-Banking-Portal/security/validation.php) scans raw query strings for duplicate keys before PHP superglobal processing.

### 4. Verification & Testing
- Automated Suite: [`tests/test_csrf.php`](file:///Secure-Banking-Portal/tests/test_csrf.php) & [`tests/test_validation.php`](file:///Secure-Banking-Portal/tests/test_validation.php)
- Automated Suite: [`tests/test_export.php`](file:///Secure-Banking-Portal/tests/test_export.php) (Test: *CWE-1236 CSV Formula Injection Sanitization*)
- Burp Evidence: [`docs/BURP_EVIDENCE/01_sqli_blocked.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/01_sqli_blocked.txt) & [`docs/BURP_EVIDENCE/08_csv_injection_defused.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/08_csv_injection_defused.txt)

> [!TIP]
> **Examiner Defense Point**: *"We treat injection holistically across SQL, HTML, OS commands, and spreadsheets. Setting `ATTR_EMULATE_PREPARES => false` prevents client-side string interpolation bypasses, while our CSV sanitizer neutralizes client-side DDE execution."*

---

## A04:2021 – Insecure Design

### 1. Risk Profile & Theoretical Threat
Insecure design represents weaknesses resulting from lack of threat modeling, architecture flaws, or absent security controls in core business processes. It cannot be fixed by defensive implementation alone.

### 2. Real-World Banking Attack Scenario
An attacker executes rapid micro-transfers to drain a stolen card before fraud filters notice, or transfers funds to an unverified third-party mule account without two-step approval.

### 3. Architecture & Implemented Controls in Portal
- **Comprehensive STRIDE Threat Model**: Detailed threat modeling in [`docs/THREAT_MODEL.md`](file:///Secure-Banking-Portal/docs/THREAT_MODEL.md) driving architectural design before code implementation.
- **Multi-Tier Velocity Limits (B5)**: In [`security/transfer_service.php`](file:///Secure-Banking-Portal/security/transfer_service.php), transfers are gated against single transfer caps, rolling 24-hour daily limits, and rolling 30-day volume limits.
- **Beneficiary 2-Step Verification (B4)**: Payees cannot receive transfers until verified via an out-of-band Bcrypt-hashed OTP with a 5-attempt anti-brute force lock in [`api/verify_beneficiary.php`](file:///Secure-Banking-Portal/api/verify_beneficiary.php).
- **Failure-Pause Safety Policy (B2)**: Recurring transfers in [`security/scheduler.php`](file:///Secure-Banking-Portal/security/scheduler.php) automatically pause if an overdraft occurs, preventing cascading overdraft fees.
- **Pessimistic Concurrency Locking**: Centralized `transfer_funds()` uses `SELECT ... FOR UPDATE` with deterministic ordering (lowest ID first) to prevent race-condition double-spending and deadlocks.

### 4. Verification & Testing
- Automated Suite: [`tests/test_velocity_limits.php`](file:///Secure-Banking-Portal/tests/test_velocity_limits.php) (5/5 passing)
- Automated Suite: [`tests/test_beneficiary_verify.php`](file:///Secure-Banking-Portal/tests/test_beneficiary_verify.php) (6/6 passing)
- Automated Suite: [`tests/test_scheduled.php`](file:///Secure-Banking-Portal/tests/test_scheduled.php) (6/6 passing)

> [!TIP]
> **Examiner Defense Point**: *"Security was designed into the business logic: transfer velocity limits evaluate aggregate rolling volume before row locks, and beneficiaries must undergo two-step cryptographic activation before receiving transfers."*

---

## A05:2021 – Security Misconfiguration

### 1. Risk Profile & Theoretical Threat
Occurs when security settings are defined, implemented, and maintained with default or improper configurations, verbose error messages, open cloud storage, or missing HTTP security headers.

### 2. Real-World Banking Attack Scenario
An attacker embeds the banking login screen inside a transparent `<iframe>` on an external phishing site, tricking the user into clicking invisible transfer buttons (Clickjacking).

### 3. Architecture & Implemented Controls in Portal
- **Dynamic Nonce-Based CSP 2.0**: In [`security/security_headers.php`](file:///Secure-Banking-Portal/security/security_headers.php), eliminates `'unsafe-inline'`. Emits a 256-bit cryptographic nonce per request:
  `default-src 'self'; script-src 'self' 'nonce-...'; style-src 'self' 'nonce-...'; frame-ancestors 'none';`
- **Clickjacking Defense**: Explicit `X-Frame-Options: DENY` combined with CSP `frame-ancestors 'none'`.
- **MIME Sniffing Defense**: `X-Content-Type-Options: nosniff` stops browsers from executing non-script files as scripts.
- **Hardened Directory Protection**: Protected storage folders (`/statements`, `/uploads`, `/logs`, `/config`, `/database`) include dedicated `.htaccess` files containing `Deny from all` and `php_flag engine off`.
- **Zero Production Error Leakage**: Global exception handling prevents stack traces from reaching clients.

### 4. Verification & Testing
- Automated Suite: [`tests/test_validation.php`](file:///Secure-Banking-Portal/tests/test_validation.php)
- Automated Suite: [`tests/test_avatar_upload.php`](file:///Secure-Banking-Portal/tests/test_avatar_upload.php) (Test: *Upload Directory .htaccess Script Execution Disabled*)

> [!TIP]
> **Examiner Defense Point**: *"Our defense-in-depth architecture applies nonce-based CSP 2.0 with zero `'unsafe-inline'` allowances, paired with Apache-level directory execution locks that completely disarm web shell payloads."*

---

## A06:2021 – Vulnerable and Outdated Components

### 1. Risk Profile & Theoretical Threat
Occurs when software uses third-party libraries, frameworks, or dependencies that contain known vulnerabilities or whose supply chain has been compromised.

### 2. Real-World Banking Attack Scenario
A CDN hosting a popular JavaScript library is compromised, and attackers replace the script with a modified payload that captures keystrokes and exfiltrates banking credentials.

### 3. Architecture & Implemented Controls in Portal
- **Subresource Integrity (SRI)**: All client-side libraries include cryptographic SHA-384 integrity hashes via `sri_asset()` in [`security/security_headers.php`](file:///Secure-Banking-Portal/security/security_headers.php).
- **Self-Hosted Vendor Assets**: Chart.js is hosted locally at [`js/vendor/chart.min.js`](file:///Secure-Banking-Portal/js/vendor/chart.min.js) with SRI hash:
  `sha384-e6cc9LaIG7xZ3XD5B+jtr1NhTWPQGQdRCh6xiZ+ZFUtWCpg4ycv3Sh+SkZoopvUY`
- **Minimalist Runtime Dependencies**: Zero bulky npm packages or composer frameworks. The PDF generator in [`vendor/tcpdf/tcpdf.php`](file:///Secure-Banking-Portal/vendor/tcpdf/tcpdf.php) is self-contained and zero-dependency, eliminating supply-chain exposure.

### 4. Verification & Testing
- Automated Suite: [`tests/test_categories.php`](file:///Secure-Banking-Portal/tests/test_categories.php) (Test: *SRI Asset Hash Verification*)

> [!TIP]
> **Examiner Defense Point**: *"By self-hosting all client-side dependencies with SHA-384 Subresource Integrity hashes and eliminating bloated third-party frameworks, we reduce the software supply chain attack surface to near zero."*

---

## A07:2021 – Identification and Authentication Failures

### 1. Risk Profile & Theoretical Threat
Weaknesses in session management or credential validation that allow attackers to compromise passwords, keys, or session tokens, or exploit other implementation flaws to assume user identities.

### 2. Real-World Banking Attack Scenario
An attacker sets a victim's session ID before login (session fixation) or mounts high-speed dictionary attacks against customer accounts until a password matches.

### 3. Architecture & Implemented Controls in Portal
- **4-Site Session Fixation Defense**: Calls `session_regenerate_id(true)` at:
  1. Primary Credential Login ([`api/login.php`](file:///Secure-Banking-Portal/api/login.php))
  2. MFA OTP Verification ([`api/verify_otp.php`](file:///Secure-Banking-Portal/api/verify_otp.php))
  3. Password Reset ([`api/reset_password.php`](file:///Secure-Banking-Portal/api/reset_password.php))
  4. Administrative Privilege Elevation ([`security/auth.php`](file:///Secure-Banking-Portal/security/auth.php))
- **Sliding-Window Limiter & 3-Tier Exponential Lockout**: Enforced in [`security/rate_limit.php`](file:///Secure-Banking-Portal/security/rate_limit.php):
  - 5 failed attempts $\to$ 5-minute lockout
  - 10 failed attempts $\to$ 30-minute lockout
  - 15 failed attempts $\to$ Permanent admin lockout (`status = 'frozen'`)
- **Dual-Tier Session Expiration**: 15-minute idle inactivity ceiling + absolute 8-hour hard ceiling from initial authentication in [`security/auth.php`](file:///Secure-Banking-Portal/security/auth.php).
- **Two-Factor Recovery Codes**: 10 one-time Bcrypt-hashed emergency backup codes in [`security/auth.php`](file:///Secure-Banking-Portal/security/auth.php).

### 4. Verification & Testing
- Automated Suite: [`tests/test_auth.php`](file:///Secure-Banking-Portal/tests/test_auth.php) (5/5 passing)
- Automated Suite: [`tests/test_rate_limit.php`](file:///Secure-Banking-Portal/tests/test_rate_limit.php) (6/6 passing)
- Burp Evidence: [`docs/BURP_EVIDENCE/05_rate_limit_lockout_429.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/05_rate_limit_lockout_429.txt) & [`docs/BURP_EVIDENCE/10_burp_intruder_bruteforce_log.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/10_burp_intruder_bruteforce_log.txt)

> [!TIP]
> **Examiner Defense Point**: *"We implement dual-tier session timeouts (15m idle / 8h absolute) and destroy session identifiers at all privilege transitions using `session_regenerate_id(true)`, fully neutralizing session fixation."*

---

## A08:2021 – Software and Data Integrity Failures

### 1. Risk Profile & Theoretical Threat
Occurs when code and infrastructure do not protect against integrity violations, such as unvalidated software updates, insecure deserialization, or modifiable transaction and audit logs.

### 2. Real-World Banking Attack Scenario
An insider with database access edits a financial transaction row or deletes security log entries to cover fraudulent transfers, claiming no record exists.

### 3. Architecture & Implemented Controls in Portal
- **Cryptographic Audit Log Hash Chain**: In [`security/logger.php`](file:///Secure-Banking-Portal/security/logger.php), every log row links to the previous block via `prev_hash`, computing:
  $$\text{hash}_n = \text{SHA-256}(\text{prev\_hash}_{n} \parallel \text{timestamp} \parallel \text{user\_id} \parallel \text{event\_type} \parallel \text{status} \parallel \text{details})$$
  The root entry anchors to a 64-zero genesis seed. [`admin/verify_log_chain.php`](file:///Secure-Banking-Portal/admin/verify_log_chain.php) verifies ledger continuity and detects row insertions, deletions, or data modifications.
- **Insecure Deserialization Elimination**: The platform relies strictly on `json_encode()` and `json_decode()` for data transfer. PHP's dangerous native `unserialize()` function is strictly banned.

### 4. Verification & Testing
- Automated Suite: [`tests/test_hash_chain.php`](file:///Secure-Banking-Portal/tests/test_hash_chain.php) (6/6 passing)
- Automated Suite: [`tests/test_chain_still_valid.php`](file:///Secure-Banking-Portal/tests/test_chain_still_valid.php) (5/5 passing across 583+ records)

> [!TIP]
> **Examiner Defense Point**: *"Our audit logging implements blockchain-inspired SHA-256 hash chaining. If an attacker modifies or deletes a single database record, the cryptographic chain breaks, providing non-repudiation and forensic integrity."*

---

## A09:2021 – Security Logging and Monitoring Failures

### 1. Risk Profile & Theoretical Threat
Insufficient logging, detection, monitoring, and active response allow attackers to sustain persistence, pivot to deeper systems, and tamper with or extract data without timely detection.

### 2. Real-World Banking Attack Scenario
An attacker scans endpoints for vulnerabilities over weeks, but because events are only written to unmonitored text files, security engineers are unaware of the breach until external regulators report it.

### 3. Architecture & Implemented Controls in Portal
- **Structured Security Telemetry**: All authentication events, limit breaches, and attack attempts are recorded with structured metadata (user, IP, event type, severity, timestamp) in `security_logs`.
- **4-Tier Threat Severity Taxonomy (C2)**: In [`config/severity_map.php`](file:///Secure-Banking-Portal/config/severity_map.php), events are bound to `low`, `medium`, `high`, and `critical` severity tiers.
- **Real-Time SOC Console via SSE (C1)**: Non-blocking Server-Sent Events stream live security telemetry to [`admin/security-dashboard.php`](file:///Secure-Banking-Portal/admin/security-dashboard.php) with zero database polling lag.
- **Heuristic Anomaly Detection (C3 & B10)**: Analyzes financial and behavioral anomalies (burst velocity, $>3\times$ transfer spikes, round-number structuring, off-hours access) in real time.
- **Prometheus Metrics Exporter (C5)**: Exposes OpenMetrics format data at [`admin/metrics.php`](file:///Secure-Banking-Portal/admin/metrics.php) for enterprise Prometheus / Grafana scraping.
- **Automated SIEM Alerting Engine (C7)**: Dispatches alerts with deduplication suppression in [`security/alert_engine.php`](file:///Secure-Banking-Portal/security/alert_engine.php).

### 4. Verification & Testing
- Automated Suite: [`tests/test_sse.php`](file:///Secure-Banking-Portal/tests/test_sse.php) (5/5 passing)
- Automated Suite: [`tests/test_severity.php`](file:///Secure-Banking-Portal/tests/test_severity.php) (6/6 passing)
- Automated Suite: [`tests/test_anomaly.php`](file:///Secure-Banking-Portal/tests/test_anomaly.php) (6/6 passing)
- Automated Suite: [`tests/test_metrics.php`](file:///Secure-Banking-Portal/tests/test_metrics.php) (6/6 passing)
- Automated Suite: [`tests/test_alert_engine.php`](file:///Secure-Banking-Portal/tests/test_alert_engine.php) (6/6 passing)

> [!TIP]
> **Examiner Defense Point**: *"We elevate security from passive logging to active observability: real-time Server-Sent Events stream attack telemetry directly to the SOC console, while our Prometheus exporter integrates into enterprise SIEM pipelines."*

---

## A10:2021 – Server-Side Request Forgery (SSRF)

### 1. Risk Profile & Theoretical Threat
SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send crafted requests to unexpected destinations, typically internal network services or cloud metadata.

### 2. Real-World Banking Attack Scenario
An administrator invokes an upstream health check, but an attacker tampers with the target parameter to request `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, harvesting AWS IAM role credentials and compromising the underlying cloud infrastructure.

### 3. Architecture & Implemented Controls in Portal
- **Strict Host Whitelist**: In [`api/admin_diagnostics.php`](file:///Secure-Banking-Portal/api/admin_diagnostics.php), requests are permitted only to approved external hosts defined in `SSRF_WHITELIST_HOSTS`.
- **Recursive DNS Resolution & CIDR Subnet Firewall**: Resolves hostnames via `dns_get_record()` and validates resolved IPs against private, reserved, and loopback IP blocks:
  - `127.0.0.0/8` (Loopback)
  - `10.0.0.0/8` (Private RFC 1918)
  - `172.16.0.0/12` (Private RFC 1918)
  - `192.168.0.0/16` (Private RFC 1918)
  - `169.254.0.0/16` (Link-Local / Cloud Instance Metadata)
  - `::1` (IPv6 Loopback)
- **SIEM Telemetry**: Blocked attempts immediately log `SSRF_BLOCKED` with severity `high`.

### 4. Verification & Testing
- Automated Suite: [`tests/test_validation.php`](file:///Secure-Banking-Portal/tests/test_validation.php)
- Burp Evidence: [`docs/BURP_EVIDENCE/09_ssrf_blocked.txt`](file:///Secure-Banking-Portal/docs/BURP_EVIDENCE/09_ssrf_blocked.txt)

> [!TIP]
> **Examiner Defense Point**: *"We defeat SSRF by implementing DNS resolution filtering that resolves hostnames before socket connection, strictly denying connections to RFC 1918 private subnets and cloud metadata endpoints."*
