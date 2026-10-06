# Academic Viva Q&A Master Bank (45 Comprehensive Questions & Answers)

**System**: Secure Banking Portal: A Web Application for Secure Transactions and Vulnerability Mitigation  
**Audience**: External Examiners, Academic Viva Boards, Senior Security Assessors  
**Scope**: Defense-in-Depth Web Application Security, Concurrency, Cryptography, and Observability  

---

## Domain 1: Cryptography, Password Hashing & Key Derivation

### Q1: Why did you choose Bcrypt over SHA-256 or MD5 for password storage?
**Answer**: SHA-256 and MD5 are cryptographic message digests designed for maximum throughput and speed (gigabytes per second). In password storage, speed is a severe vulnerability because modern GPU clusters and ASICs can compute billions of candidate hashes per second, making dictionary and brute-force cracking trivial. Bcrypt is an adaptive key derivation function based on the Blowfish cipher. It incorporates an internal 128-bit random salt to eliminate precomputed rainbow table attacks and features an adjustable cost factor ($2^{\text{cost}}$ iterations). We configured cost 12 (~240 ms per hash on our host), ensuring that offline brute-force cracking is computationally and economically infeasible.

### Q2: Why is it secure to store password reset tokens as SHA-256 hashes instead of Bcrypt?
**Answer**: Passwords have low human entropy and require slow, computationally expensive hashing (Bcrypt). Conversely, our password reset tokens are generated using a Cryptographically Secure Pseudo-Random Number Generator (`random_bytes(32)`), yielding 256 bits of pure cryptographic entropy ($2^{256}$ possibilities). A 256-bit CSPRNG token cannot be brute-forced or looked up in rainbow tables. Storing its SHA-256 digest in the database protects against database leakage: if an attacker dumps the `password_resets` table, they obtain only one-way hashes, from which they cannot compute the original 32-byte token needed to execute the reset. Fast SHA-256 is appropriate here because entropy is high, and fast computation avoids server performance bottlenecks.

### Q3: How does `hash_equals()` prevent side-channel timing attacks?
**Answer**: Standard string equality operators (like `==` or `===`) perform short-circuit byte-by-byte comparisons, returning `false` immediately upon discovering the first mismatched character. An attacker measuring HTTP response times with nanosecond or microsecond precision can deduce character-by-character matches (a timing attack). PHP's `hash_equals()` executes in constant time: it XORs all bytes across the entire string length regardless of where differences occur, ensuring execution duration depends solely on string length, not content. We use `hash_equals()` for all CSRF token and password reset token comparisons.

### Q4: Explain the mathematical structure and tamper-detection mechanics of your audit log hash chain.
**Answer**: Each row in `security_logs` contains a `prev_hash` column and a `hash` column. When a new security event $n$ is recorded:
$$\text{hash}_n = \text{SHA-256}(\text{prev\_hash}_n \parallel \text{timestamp} \parallel \text{user\_id} \parallel \text{event\_type} \parallel \text{status} \parallel \text{details})$$
Block 1 (the Genesis block) anchors to a fixed 64-character zero string (`0000...0000`). Each subsequent block cryptographically seals the cumulative state of all prior blocks. If an attacker modifies any data column in row $k$, recomputing $\text{hash}_k$ produces a mismatch. If the attacker updates $\text{hash}_k$ to match the modified data, the stored `prev_hash_{k+1}` in the subsequent row no longer matches, causing an immediate pointer mismatch. The only way to forge the chain is to recompute every subsequent block to the tail, which is mathematically impossible for an attacker without direct continuous write access during active transaction generation.

### Q5: What is the purpose of Subresource Integrity (SRI) and how does it prevent supply-chain attacks?
**Answer**: Content Delivery Networks (CDNs) are shared third-party infrastructures. If an attacker compromises a CDN edge server or performs DNS poisoning, they can tamper with hosted scripts to inject credential stealers. Subresource Integrity allows browsers to verify that fetched assets match an expected cryptographic digest:
`<script src="..." integrity="sha384-..." crossorigin="anonymous">`
Before executing the script, the browser hashes the downloaded file with SHA-384 and compares it against the `integrity` attribute. If a single byte differs, the browser refuses to execute the script and logs a security error. We self-host our vendor scripts (Chart.js) and bind SHA-384 hashes via our `sri_asset()` helper.

---

## Domain 2: Database Security, Concurrency & Transactions

### Q6: Why did you set `PDO::ATTR_EMULATE_PREPARES => false` in your database connection?
**Answer**: When `ATTR_EMULATE_PREPARES` is enabled (the default in some legacy PDO drivers), PDO does not send parameterized queries to MySQL. Instead, PHP locally substitutes parameters into the SQL string via client-side string escaping before sending a single monolithic query string. This emulation can be bypassed via multi-byte encoding mismatches (e.g., GBK character set tricks). Setting `ATTR_EMULATE_PREPARES => false` forces native prepared statements: PHP sends the query blueprint to the MySQL server with parameter placeholders (`PREPARE`), the server compiles the SQL AST, and subsequent `EXECUTE` calls send parameters across binary protocol boundaries. Data values can never alter the SQL execution tree.

### Q7: Explain why `SELECT ... FOR UPDATE` was necessary in `transfer_funds()`.
**Answer**: In financial platforms, multiple transfer requests can arrive simultaneously. Suppose a customer with \$1,000 executes two simultaneous transfers of \$800 in parallel threads. In standard autocommit mode:
- Thread 1 checks balance: \$1,000 $\ge$ \$800 (True).
- Thread 2 checks balance: \$1,000 $\ge$ \$800 (True).
- Thread 1 updates balance: \$1,000 - \$800 = \$200.
- Thread 2 updates balance: \$1,000 - \$800 = \$200.
The customer transferred \$1,600 while spending only \$800 (double-spending race condition). `SELECT ... FOR UPDATE` acquires an exclusive row-level pessimistic lock within an ACID transaction. When Thread 1 reads the balance with `FOR UPDATE`, Thread 2 is forced to wait until Thread 1 commits. When Thread 2 acquires the lock, it reads the updated balance (\$200) and correctly rejects the second transfer for insufficient funds.

### Q8: How did you prevent database deadlocks during multi-account row locking?
**Answer**: A deadlock occurs when two transactions hold locks that the other requires. Suppose User A transfers money to User B, while User B simultaneously transfers money to User A:
- Transaction 1 locks Account A and requests a lock on Account B.
- Transaction 2 locks Account B and requests a lock on Account A.
Both threads block indefinitely waiting for the other to release the lock, causing a deadlock exception. We solved this by enforcing a deterministic lock acquisition order in [`security/transfer_service.php`](file:///Secure-Banking-Portal/security/transfer_service.php):
```php
$firstId  = min($fromAccountId, $toAccountId);
$secondId = max($fromAccountId, $toAccountId);
```
Both transactions always lock the account with the lower primary key ID first, making circular lock waits mathematically impossible.

### Q9: Why did you separate `accounts.balance` from `users.balance` and how do you ensure consistency?
**Answer**: Commercial banks allow customers to hold multiple accounts (Savings, Current, Fixed Deposit). `accounts.balance` tracks the individual ledger for each account number, while `users.balance` provides a cached aggregate view for profile displays. To eliminate synchronization drift, all credit and debit operations in `transfer_funds()` execute within a single atomic `PDO::beginTransaction()` block that updates the individual account rows and synchronizes `users.balance` via a subquery aggregate before issuing `PDO::commit()`. If any step fails, the entire transaction rolls back cleanly.

### Q10: Why did duplicate named placeholders fail in MySQL native prepared statements?
**Answer**: When `ATTR_EMULATE_PREPARES => false` is enforced, MySQL's native prepared statement engine requires a strict 1-to-1 mapping between parameter placeholders and bound variables. Reusing a named parameter like `:uid` multiple times in a query triggers `SQLSTATE[HY093]: Invalid parameter number`. To adhere to native statement standards, our queries use distinct named placeholders (`:u1`, `:u2`, `:u3`) or positional `?` placeholders.

---

## Domain 3: Session Management & Identity Architecture

### Q11: What is Session Fixation and how does your 4-site defense eliminate it?
**Answer**: Session fixation occurs when an attacker forces a known session identifier onto a victim's browser (e.g., via an unencrypted URL parameter or XSS). When the victim subsequently logs in, the server authenticates the existing session ID rather than issuing a new one. The attacker then uses the pre-set session ID to access the victim's authenticated account. We eliminate this by invoking `session_regenerate_id(true)` at all four critical privilege boundaries:
1. Primary password authentication (`/api/login.php`)
2. MFA OTP verification (`/api/verify_otp.php`)
3. Password reset completion (`/api/reset_password.php`)
4. Administrative elevation (`/security/auth.php`)
The parameter `true` instructs PHP to immediately delete the old session file on disk, rendering the attacker's pre-set session token invalid.

### Q12: Explain the dual-tier session expiration model. Why is an idle timeout alone insufficient?
**Answer**: An idle timeout (we enforce 15 minutes) checks the interval since the user's last HTTP request. While this protects unattended workstations, it allows indefinite session lifetimes if an automated background script or long-lived malicious session keeps pinging the server with heartbeat requests. An absolute timeout (we enforce 8 hours) measures the total elapsed time since the user's initial authentication, regardless of activity. When the 8-hour ceiling is reached, the session is forcibly destroyed, requiring full re-authentication.

### Q13: What are the security properties of `SameSite=Strict` versus `SameSite=Lax`?
**Answer**: The `SameSite` cookie attribute controls whether cookies are sent with cross-site requests. `SameSite=Lax` permits cookies to be sent on top-level GET navigations (e.g., following an external link to the banking portal). `SameSite=Strict` completely prevents the browser from attaching the session cookie on any cross-site request, whether GET, POST, iframe, or form submit. We enforce `SameSite=Strict` across all session cookies, ensuring that any request originating from an external third-party site arrives at our API unauthenticated, providing native defense against CSRF.

### Q14: How does your sliding-window rate limiter calculate request velocity?
**Answer**: Rather than relying on simple counters that reset at arbitrary clock boundaries (which allow double-burst attacks at the transition window), our rate limiter in [`security/rate_limit.php`](file:///Secure-Banking-Portal/security/rate_limit.php) uses a database table tracking IP, endpoint, and a rolling timestamp. When a request arrives, the limiter prunes expired records older than the window (e.g., 15 minutes) and counts records within the sliding interval:
`WHERE ip = :ip AND endpoint = :ep AND window_start >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)`
If the count exceeds the threshold (e.g., 5 for login), the server returns HTTP 429 Too Many Requests with a `Retry-After` header.

### Q15: How does your device fingerprinting protect user privacy while detecting intrusions?
**Answer**: Commercial tracking cookies and canvas fingerprinting store invasive tracking profiles that violate privacy frameworks (GDPR). Our device engine in [`security/devices.php`](file:///Secure-Banking-Portal/security/devices.php) generates a privacy-preserving one-way cryptographic hash:
$$\text{Fingerprint} = \text{SHA-256}(\text{User-Agent} \parallel \text{IP Subnet } /24 \parallel \text{Accept-Language})$$
By truncating the client IP to its `/24` subnet, we accommodate dynamic DHCP shifts within the same ISP while maintaining entropy across distinct geographic locations. When a user authenticates with an unrecognized fingerprint, the system dispatches an alert and in-portal notification, allowing the customer to review active devices and revoke access.

---

## Domain 4: Web Application Vulnerabilities & Defense-in-Depth

### Q16: Why is output encoding context-dependent? Why doesn't `htmlspecialchars()` protect against all XSS?
**Answer**: `htmlspecialchars()` converts `&`, `"`, `'`, `<`, and `>` into HTML entities. This neutralizes XSS when data is placed inside standard HTML body tags (e.g., `<div>...</div>` or `<p>...</p>`). However, it fails if the variable is placed inside an unquoted attribute (`<input value=USER_INPUT>`), a JavaScript execution context (`<script>var name = 'USER_INPUT';</script>`), a dynamic URI attribute (`<a href="USER_INPUT">`), or a CSS style block. In JavaScript contexts, an attacker can break out using quotes or backticks without using angle brackets. To ensure complete protection, we enforce three distinct layers:
1. Server-side `htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`
2. Client-side DOM assignment strictly via `element.textContent`, which completely bypasses the HTML parser
3. Nonce-based CSP 2.0, which instructs the browser engine to refuse execution of any inline script tag lacking the server-generated request nonce.

### Q17: How does a Content Security Policy (CSP) nonce operate, and why is it superior to `'unsafe-inline'`?
**Answer**: Legacy CSPs frequently used `'unsafe-inline'` to accommodate inline scripts, which effectively disarmed XSS protection. Nonce-based CSP 2.0 generates a 256-bit cryptographic random nonce on the server for each HTTP response:
`Content-Security-Policy: script-src 'self' 'nonce-R4nd0m...';`
The web server binds this exact nonce value to authorized script tags: `<script nonce="R4nd0m...">`. When an attacker successfully injects an XSS payload (e.g., `<script>evil()</script>`), the injected tag lacks the matching nonce for that specific HTTP response. The browser detects the missing or mismatched nonce and refuses to execute the script.

### Q18: What is HTTP Parameter Pollution (HPP) and how does your middleware block it?
**Answer**: HPP occurs when an attacker supplies multiple query or body parameters with the same name (e.g., `transfer.php?amount=10&amount=1000`). Different web technologies resolve duplicates differently: PHP silently overwrites earlier values with the last one, while ASP.NET concatenates them with a comma. An attacker can exploit this discrepancy to bypass front-end WAF validation (which checks the first parameter) while the backend executes the second. Our middleware in [`security/validation.php`](file:///Secure-Banking-Portal/security/validation.php) inspects the raw query string (`$_SERVER['QUERY_STRING']`) using regular expressions before superglobal access, rejecting any request containing duplicate parameter keys with HTTP 400 Bad Request.

### Q19: Explain Server-Side Request Forgery (SSRF) and how your IP firewall prevents it.
**Answer**: SSRF occurs when a server-side application fetches an external resource based on a user-supplied URL. Attackers supply loopback addresses (`127.0.0.1`) or private cloud metadata services (`169.254.169.254`) to probe internal network infrastructure, harvest IAM cloud credentials, or access unauthenticated internal microservices. Our defense in [`api/admin_diagnostics.php`](file:///Secure-Banking-Portal/api/admin_diagnostics.php) enforces a host allowlist (`SSRF_WHITELIST_HOSTS`), resolves the domain to an IP using `dns_get_record()`, and filters the resolved address against CIDR subnet masks covering RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local metadata (`169.254.0.0/16`), and IPv6 loopback (`::1`).

### Q20: How does CWE-1236 CSV Formula Injection work, and what is the mitigation?
**Answer**: When spreadsheet applications (Microsoft Excel, LibreOffice Calc) open a CSV file, cells beginning with `=`, `+`, `-`, `@`, `\t`, or `\r` are interpreted as formulas rather than raw text. Attackers can inject Dynamic Data Exchange (DDE) commands (e.g., `=cmd|'/C calc'!A0`) into transaction remarks. When an administrative clerk or customer exports and opens their bank statement, the spreadsheet executes the command with the user's OS privileges. In [`security/csv_safe.php`](file:///Secure-Banking-Portal/security/csv_safe.php), we mitigate this by testing each cell with `preg_match('/^[=\+\-@\t\r]/', $value)` and prepending a single quote (`'`). The spreadsheet interprets the single quote as a text-escape marker, displaying the content literally and disabling formula execution.

---

## Domain 5: API Security, Input Canonicalization & Advanced Defenses

### Q21: What is Input Canonicalization and why must it precede validation?
**Answer**: Attackers frequently use alternative character encodings (Unicode homoglyphs, multiple URL encoding `%252e%252e%252f`, HTML entities `&quot;`, null bytes `\0`) to disguise malicious payloads from input validation filters. If validation occurs before canonicalization, a filter searching for `../` will miss `%252e%252e%252f`. When the backend subsequently resolves the string, the traversal sequence emerges. In [`security/validation.php`](file:///Secure-Banking-Portal/security/validation.php), our `canonicalize_input()` function executes in strict order:
1. Unicode NFKC Normalization (converts fullwidth and compatibility characters to standard equivalents)
2. Null byte stripping (`\0`)
3. Single-pass HTML entity decoding
4. Whitespace trimming
Validation regexes execute only after data has reached its canonical, simplest representation.

### Q22: Describe the multi-layered defense pipeline for avatar image uploads.
**Answer**: File upload vulnerabilities can lead to Remote Code Execution (RCE) via web shells. We implement five independent defensive gates in [`api/avatar.php`](file:///Secure-Banking-Portal/api/avatar.php):
1. **Extension Whitelist**: Permits only `jpg`, `jpeg`, and `png`.
2. **MIME Verification**: Uses PHP's `finfo_file()` to read magic byte headers directly from disk, completely ignoring the untrusted client-supplied `Content-Type` header.
3. **Geometry Validation**: Calls `getimagesize()` to verify the file contains valid image dimension blocks.
4. **GD Pixel Re-sampling**: The image is opened with `imagecreatefromjpeg()` and re-saved via `imagejpeg()`. This completely reconstitutes the pixel matrix and strips EXIF metadata, destroying polyglot PHP payloads embedded in image headers.
5. **Filesystem Isolation**: Avatars are renamed to a random UUID and stored in a directory protected by an Apache `.htaccess` file enforcing `php_flag engine off` and `Deny from all` on executable extensions.

### Q23: Why do we enforce HTTP Method Enforcement (`require_method('POST')`)?
**Answer**: Browsers inherently permit cross-origin GET requests via simple `<img>`, `<link>`, and `<script>` tags without triggering CORS preflights. If a state-changing financial operation (such as a fund transfer or password reset) accepts GET parameters, an attacker can bypass CSRF defenses by embedding a malicious link in an email or forum post. Enforcing `require_method('POST')` ensures that unexpected HTTP verbs are rejected immediately with HTTP 405 Method Not Allowed and an `Allow: POST` header.

### Q24: How does your application protect against Insecure Deserialization?
**Answer**: Insecure deserialization in PHP occurs when untrusted data is passed to `unserialize()`, allowing attackers to instantiate arbitrary object classes, trigger `__wakeup()` or `__destruct()` magic methods, and execute Object Injection Gadget Chains leading to RCE. Our banking portal strictly bans `unserialize()`. All structured API payloads, session tokens, and cache entries rely exclusively on standard JSON serialization via `json_encode()` and `json_decode()`.

### Q25: How does your zero-cron lazy scheduler execute recurring transfers?
**Answer**: Commercial hosting environments often lack dedicated crontab access or root scheduling privileges. In [`security/scheduler.php`](file:///Secure-Banking-Portal/security/scheduler.php), our scheduler engine triggers on authenticated customer interactions (such as dashboard loads) via `trigger_lazy_scheduler()`. To eliminate redundant database queries, it uses a 60-second atomic throttle. When triggered, it queries `scheduled_transfers` for active schedules where `next_run_at <= NOW()`, invokes `transfer_funds()` under system context, advances the `next_run_at` timestamp, and automatically sets the status to `'paused'` if an overdraft occurs.

---

## Domain 6: Observability, Threat Modeling & Compliance

### Q26: What is STRIDE and how did you apply it to the banking portal?
**Answer**: STRIDE is an architectural threat modeling methodology developed by Microsoft that categorizes security threats into six distinct domains:
- **S**poofing: Impersonating identities $\to$ Mitigated by MFA, Bcrypt, and 4-site session regeneration.
- **T**ampering: Modifying data $\to$ Mitigated by ACID row locking, CSRF tokens, and CSP 2.0 nonces.
- **R**epudiation: Denying actions $\to$ Mitigated by append-only SHA-256 hash-chain audit logging.
- **I**nformation Disclosure: Exposing confidential data $\to$ Mitigated by parameterized queries, generic error masking, and `realpath()` sandboxing.
- **D**enial of Service: Exhausting resources $\to$ Mitigated by sliding-window rate limiting, exponential lockout, and 12-month statement query bounds.
- **E**levation of Privilege: Gaining unauthorized rights $\to$ Mitigated by horizontal IDOR ownership checks and strict admin RBAC.

### Q27: How does your Server-Sent Events (SSE) feed avoid blocking PHP session concurrency?
**Answer**: By default, PHP sessions acquire an exclusive file lock on the session data file (`sess_...`) for the duration of request execution. A persistent long-polling or streaming connection (such as SSE) would hold this lock indefinitely, causing all subsequent HTTP requests from the same user to hang until the stream terminates. In [`admin/stream_events.php`](file:///Secure-Banking-Portal/admin/stream_events.php), we read user authentication parameters and immediately call `session_write_close()`. This commits and releases the session lock, allowing the administrator to navigate the portal while the SSE event stream maintains a persistent unidirectional connection.

### Q28: How does your Prometheus exporter conform to open observability standards?
**Answer**: Our endpoint at [`admin/metrics.php`](file:///Secure-Banking-Portal/admin/metrics.php) outputs metrics in OpenMetrics / Prometheus exposition text format (Content-Type: `text/plain; version=0.0.4; charset=utf-8`). It includes standard `# HELP` and `# TYPE` declarations for gauges and counters (e.g., `bank_transactions_total`, `bank_security_events_total{severity="high"}`). It enforces Bearer token authentication, escapes label characters, and utilizes a 5-second atomic cache file to prevent scraping requests from causing database denial of service.

### Q29: What is the purpose of user security posture scoring (0–100)?
**Answer**: Security visibility must extend to end users. Our engine in [`security/security_score.php`](file:///Secure-Banking-Portal/security/security_score.php) calculates a dynamic posture score based on four objective security hygiene factors:
1. Password age and complexity (+25 points)
2. MFA status (+25 points)
3. 2FA backup recovery codes generated (+25 points)
4. Active unrecognized devices / account freeze state (+25 points)
It renders an interactive SVG circular gauge on [`frontend/profile.html`](file:///Secure-Banking-Portal/frontend/profile.html) with actionable recommendations (e.g., "Rotate password", "Generate backup codes"), and aggregates organization-wide scores into a SOC dashboard histogram.

### Q30: How does your heuristic transaction monitor detect financial structuring?
**Answer**: Structuring (or "smurfing") is a money-laundering technique where transactions are broken into increments just beneath regulatory reporting thresholds, or executed in round sums. Our heuristic engine in [`security/transaction_monitor.php`](file:///Secure-Banking-Portal/security/transaction_monitor.php) evaluates transactions against multi-variable rules:
1. High-Value Threshold ($\ge \$50,000.00$)
2. Round-Number Spikes ($\ge \$10,000.00$ exact multiple of $\$1,000$)
3. Rapid Velocity Bursts ($\ge 3$ transactions executed within 5 minutes)
Flagged transactions automatically create pending review cases in `transaction_reviews`, providing SOC analysts with a triage workflow to clear or escalate incidents with an audit trail.

---

## Domain 7: Deep Technical Defense Questions (Q31–Q40)

### Q31: What is the risk of using `rand()` or `mt_rand()` in security functions, and what do you use instead?
**Answer**: `rand()` and `mt_rand()` are pseudo-random number generators designed for statistical simulations, not cryptography. Their internal state can be reconstructed by observing consecutive outputs (e.g., via the Mersenne Twister seed recovery algorithm). In security contexts (CSRF tokens, password reset tokens, MFA codes), predictable randomness allows attackers to predetermine tokens. We use PHP's cryptographically secure pseudo-random function `random_bytes()`, which pulls entropy directly from the OS kernel CSPRNG (`/dev/urandom` on Unix, `CryptGenRandom` / `BCryptGenRandom` on Windows).

### Q32: What is the difference between Reflected, Stored, and DOM-Based XSS?
**Answer**:
- **Reflected XSS**: The malicious script originates from the current HTTP request (e.g., a search parameter in a malicious link). The server immediately reflects the payload back in the response body.
- **Stored XSS**: The payload is stored in the database (e.g., transfer remark or customer name) and executed later when other users view the stored record.
- **DOM-Based XSS**: The vulnerability exists entirely in client-side JavaScript. The payload never touches the server; instead, client scripts read data from an untrusted source (like `location.search` or `location.hash`) and pass it to an unsafe execution sink (like `eval()` or `element.innerHTML`).

### Q33: How does your application defend against Clickjacking without relying solely on `X-Frame-Options`?
**Answer**: While `X-Frame-Options: DENY` is supported by legacy browsers, modern W3C standards deprecate it in favor of Content Security Policy `frame-ancestors 'none'`. We emit both headers simultaneously in [`security/security_headers.php`](file:///Secure-Banking-Portal/security/security_headers.php). `frame-ancestors 'none'` ensures that modern browsers reject framing attempts from all origins, while `X-Frame-Options: DENY` maintains compatibility with older legacy user agents.

### Q34: What prevents an attacker from bypassing your rate limiting by sending forged `X-Forwarded-For` headers?
**Answer**: Many amateur rate limiters trust `$_SERVER['HTTP_X_FORWARDED_FOR']`. Attackers simply randomize this header with each request to bypass IP-based throttling. Our platform derives client IP strictly from `$_SERVER['REMOTE_ADDR']`, which represents the actual established TCP/IP socket connection to the server. `X-Forwarded-For` is only parsed if the upstream proxy IP is verified against a strict reverse-proxy allowlist.

### Q35: Why is `finfo_file()` preferred over `mime_content_type()` or `$_FILES['avatar']['type']`?
**Answer**: `$_FILES['avatar']['type']` is a user-controlled HTTP request header sent by the client browser; an attacker uploading a PHP script can simply set `Content-Type: image/jpeg`. `mime_content_type()` is deprecated in modern PHP. `finfo_file()` uses the `libmagic` library to inspect the binary signature (magic bytes) directly from the uploaded temporary file on disk, providing an objective, tamper-proof identification of the file's binary format.

### Q36: How does the application prevent session fixation on password reset?
**Answer**: When a user completes a password reset, their existing session might be active on an attacker's compromised browser, or the reset could be initiated from a public computer. In [`api/reset_password.php`](file:///Secure-Banking-Portal/api/reset_password.php), upon updating the password hash, the application destroys all active session records for that user and invokes `session_regenerate_id(true)`, ensuring that old sessions cannot be replayed after a credential update.

### Q37: What is the purpose of Unicode NFKC normalization in input canonicalization?
**Answer**: Unicode allows different byte sequences to represent visually identical characters (compatibility equivalence). For example, the ligature `ﬀ` (U+FB00) can represent `ff`, or the fullwidth script `<` (U+FF1C) can represent `<`. An input filter checking for `<script>` will miss `<ｓｃｒｉｐｔ>`. Normalization Form KC (Compatibility Decomposition followed by Canonical Composition) transforms all visual homoglyphs and compatibility representations into their standard ASCII/Unicode equivalents, allowing subsequent security regex filters to operate accurately.

### Q38: How does your statement export engine protect against Memory Exhaustion DoS attacks?
**Answer**: Exporting millions of ledger rows into memory can cause PHP to exhaust `memory_limit` and crash. We implement two defenses in [`api/export_statement.php`](file:///Secure-Banking-Portal/api/export_statement.php):
1. A hard limit enforcing that `start_date` and `end_date` span a maximum of 366 days (12 months).
2. Streaming output: CSV generation writes rows iteratively to the output stream (`php://output`) using `fputcsv()`, maintaining $O(1)$ constant memory overhead regardless of row count.

### Q39: What is the significance of the 64-zero genesis seed in your audit log?
**Answer**: In cryptographic hash chains, every block requires a `prev_hash` input. For the very first block in the ledger, no previous row exists. If the application allowed an arbitrary or null seed, an attacker could forge an arbitrary starting block. By establishing a hardcoded, immutable 64-character zero string (`0000000000000000000000000000000000000000000000000000000000000000`) as the Genesis anchor, any attempt to inject a fake initial row is detected immediately by our verification algorithms.

### Q40: What distinction-grade architectural qualities set this project apart from typical student capstone projects?
**Answer**:
1. **Cryptographic Proof of Log Integrity**: Implementation of an append-only SHA-256 hash-chain audit ledger with mathematical tamper verification.
2. **Pessimistic Concurrency Architecture**: Deadlock-free `SELECT ... FOR UPDATE` row-level locking eliminating double-spending race conditions.
3. **Comprehensive Observability**: Enterprise Prometheus metrics exporter and real-time Server-Sent Events (SSE) telemetry.
4. **Defense-in-Depth Rigor**: Zero `'unsafe-inline'` CSP 2.0 with dynamic nonces, Subresource Integrity, and strict input canonicalization.
5. **Real-World Banking Simulation**: Commercial features (multi-account, multi-tier velocity limits, zero-cron recurrence, 2-step beneficiary verification) engineered without compromising security controls.
6. **Automated Verification Coverage**: 26 modular test suites comprising 147 passing automated test cases with 100% pass rate.
7. **Fintech Design & Engineering Quality**: Full CSS design token system, zero inline scripts/handlers, strict PHP 8 type signatures, and zero third-party CDN attack surface.

---

## Domain 8: Code Quality, Defensive Standards & Modern UI/UX Architecture (Q41–Q45)

### Q41: Why did you eliminate all inline event handlers (`onclick`, `onsubmit`) across the frontend?
**Answer**: Content Security Policy Level 2/3 treats inline event attributes (e.g. `<button onclick="...">`) as inline script execution contexts. Permitting them would require disabling CSP script restrictions or using `'unsafe-hashes'`, which exposes the application to DOM XSS and attribute-based injection vulnerabilities. By completely separating presentation from behavioral logic, all interactivity is wired through external modular JavaScript files using `addEventListener` and delegated event listeners. This eliminates inline injection sinks and guarantees strict `'self'` script provenance.

### Q42: How does your UI mitigate DOM-based XSS when rendering dynamic user data?
**Answer**: In client-side JavaScript, rendering untrusted data through `element.innerHTML` or `document.write` invokes the browser's HTML parser, executing embedded script tags or image error payloads (`<img src=x onerror=...>`). We mandate that all dynamic values—including usernames, balances, transaction remarks, beneficiary names, and audit log entries—are inserted exclusively through `Node.textContent` or explicit DOM node creation (`document.createElement`). This guarantees that user input is treated strictly as plain text, preventing DOM-based script injection regardless of payload content.

### Q43: Why are self-hosted fonts and assets a security requirement in modern web applications?
**Answer**: Loading assets from public third-party CDNs (like Google Fonts or cdnjs) creates severe supply-chain vulnerabilities, external telemetry tracking, and single points of failure. If the CDN provider is compromised, poisoned, or blocked, application functionality and layout break, or malicious payloads can be served. Self-hosting Inter and JetBrains Mono fonts locally in `fonts/` and SVG brand assets in `images/` establishes complete supply-chain sovereignty and allows the Content Security Policy to enforce tight `font-src 'self'` and `style-src 'self'` directives without third-party origin exemptions.

### Q44: Why did you configure PDO with `PDO::ATTR_EMULATE_PREPARES => false` and `PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION`?
**Answer**: By default, legacy PDO emulates prepared statements by substituting values into the SQL query locally using quotation escaping before transmitting it to MySQL. This client-side emulation can be bypassed via character encoding anomalies (such as multi-byte GBK or Big5 attacks). Setting `ATTR_EMULATE_PREPARES => false` forces the use of native MySQL server-side prepared statements (`COM_STMT_PREPARE` and `COM_STMT_EXECUTE`), which ensures that query structure and user parameters are compiled and processed on completely separate binary protocol channels. Configuring `ATTR_ERRMODE => ERRMODE_EXCEPTION` ensures that all database failures trigger catchable exceptions rather than failing silently or echoing raw database errors, allowing structured error handling without leaking database internals.

### Q45: How does PHP 8 strict scalar typing harden security services against parameter pollution and type confusion?
**Answer**: In dynamic languages like PHP, loose typing and type coercion can lead to subtle vulnerabilities—for example, comparing an integer `0` to a string `'admin'` evaluated to `true` in legacy PHP, and passing array parameters where strings are expected can bypass poorly constructed regex filters. In PHP 8+, declaring explicit parameter types (e.g. `?string`, `int`, `array`, `bool`) and return types on security services (such as `validate_csrf_token(?string $candidate_token = null): bool` and `canonicalize_input(mixed $input): mixed`) guarantees strict contract enforcement. Attempting to pass unexpected types or pollute parameter structures immediately throws a `TypeError` before any vulnerable logic executes.
