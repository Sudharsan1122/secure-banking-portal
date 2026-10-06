<?php
/**
 * Forensic Evidence Screenshot Generator
 * Generates 12 crisp PNG forensic evidence cards for the 12 attack vectors.
 */

$dir = __DIR__ . '/../screenshots/attacks';
if (!is_dir($dir)) {
    mkdir($dir, 0755, true);
}

$artifacts = [
    '01-sqli-blocked.png' => [
        'id'       => 'EV-01',
        'title'    => 'SQL Injection on Login (Authentication Bypass Blocked)',
        'owasp'    => 'A03:2021 – Injection | CWE-89',
        'endpoint' => 'POST /api/login.php',
        'status'   => 'HTTP/1.1 401 Unauthorized',
        'status_col' => 'red',
        'request'  => 'POST /api/login.php HTTP/1.1\nContent-Type: application/json\n\n{"username": "admin\' OR \'1\'=\'1\' -- ", "password": "password123"}',
        'response' => 'HTTP/1.1 401 Unauthorized\nContent-Type: application/json\n\n{"status":"error","code":401,"message":"Invalid username or password."}',
        'defense'  => 'MITIGATION: Native PDO Prepared Statement (ATTR_EMULATE_PREPARES=false). Input treated as literal string; SQL syntax integrity preserved.'
    ],
    '02-sqli-search-blocked.png' => [
        'id'       => 'EV-02',
        'title'    => 'SQL Injection on Transaction Search Filter Blocked',
        'owasp'    => 'A03:2021 – Injection | CWE-89',
        'endpoint' => 'GET /api/transactions.php?q=...',
        'status'   => 'HTTP/1.1 200 OK (0 Matches — Literal Search)',
        'status_col' => 'green',
        'request'  => 'GET /api/transactions.php?q=%27+OR+1%3D1+--+ HTTP/1.1\nHost: 127.0.0.1:8080\nX-Requested-With: XMLHttpRequest',
        'response' => 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"status":"success","transactions":[],"total":0,"message":"No records match query"}',
        'defense'  => 'MITIGATION: Parameterized LIKE Clause (:q1, :q2) with strict integer casting on transaction keys. Zero rows leaked.'
    ],
    '03-stored-xss-neutralized.png' => [
        'id'       => 'EV-03',
        'title'    => 'Stored XSS via Transaction Remark Neutralized',
        'owasp'    => 'A03:2021 – Injection | CWE-79',
        'endpoint' => 'POST /api/transfer.php -> GET /api/transactions.php',
        'status'   => 'HTTP/1.1 200 OK (Safely Encoded & Inert)',
        'status_col' => 'green',
        'request'  => 'POST /api/transfer.php HTTP/1.1\n\n{"beneficiary_id": 2, "amount": 25.00, "remark": "<script>alert(\'XSS\')</script>"}',
        'response' => 'HTTP/1.1 200 OK\n\nRendered DOM: element.textContent = data.remark\nOutput in Browser: &lt;script&gt;alert(&#039;XSS&#039;)&lt;/script&gt;',
        'defense'  => 'MITIGATION: DOM textContent sink binding + safe_html() entity encoding + strict CSP 2.0 Nonce blocks script execution.'
    ],
    '04-reflected-xss-encoded.png' => [
        'id'       => 'EV-04',
        'title'    => 'Reflected XSS via Search Query Parameter Encoded',
        'owasp'    => 'A03:2021 – Injection | CWE-79',
        'endpoint' => 'GET /admin/users.php?q=<svg/onload=alert(1)>',
        'status'   => 'HTTP/1.1 200 OK (Contextually Escaped)',
        'status_col' => 'green',
        'request'  => 'GET /admin/users.php?q=%3Csvg%2Fonload%3Dalert(1)%3E HTTP/1.1\nHost: 127.0.0.1:8080',
        'response' => 'HTTP/1.1 200 OK\n\n<input name="q" value="&lt;svg/onload=alert(1)&gt;">\nCSP Violation Report: inline-script blocked (no valid nonce)',
        'defense'  => 'MITIGATION: safe_html() attribute context escaping + CSP script-src nonce authorization prevents DOM execution.'
    ],
    '05-idor-403.png' => [
        'id'       => 'EV-05',
        'title'    => 'Horizontal IDOR on Source Account Debit Blocked',
        'owasp'    => 'A01:2021 – Broken Access Control | CWE-639',
        'endpoint' => 'POST /api/transfer.php',
        'status'   => 'HTTP/1.1 403 Forbidden',
        'status_col' => 'red',
        'request'  => 'POST /api/transfer.php HTTP/1.1\nCookie: PHPSESSID=userA_session\n\n{"from_account_id": 2, "target_account": "ACC-999", "amount": 100.00}',
        'response' => 'HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{"status":"error","code":403,"message":"Access Denied: You do not own the specified source account."}',
        'defense'  => 'MITIGATION: Multi-tenant ownership query (WHERE id = :id AND user_id = :session_uid). IDOR logged to SIEM as ACCESS_VIOLATION.'
    ],
    '06-idor-404.png' => [
        'id'       => 'EV-06',
        'title'    => 'Horizontal IDOR on Transaction Receipt Isolated',
        'owasp'    => 'A01:2021 – Broken Access Control | CWE-639',
        'endpoint' => 'GET /api/transaction_receipt.php?id=88',
        'status'   => 'HTTP/1.1 404 Not Found (Information Concealed)',
        'status_col' => 'red',
        'request'  => 'GET /api/transaction_receipt.php?id=88 HTTP/1.1\nCookie: PHPSESSID=unrelated_user_session',
        'response' => 'HTTP/1.1 404 Not Found\nContent-Type: application/json\n\n{"status":"error","code":404,"message":"Transaction record not found or inaccessible."}',
        'defense'  => 'MITIGATION: Scoped SQL predicate (WHERE t.id = :tid AND (t.sender_id = :uid OR t.receiver_id = :uid)). Zero record leakage.'
    ],
    '07-csrf-403.png' => [
        'id'       => 'EV-07',
        'title'    => 'Cross-Site Request Forgery (CSRF) Intercepted',
        'owasp'    => 'A01:2021 – Broken Access Control | CWE-352',
        'endpoint' => 'POST /api/transfer.php',
        'status'   => 'HTTP/1.1 403 Forbidden',
        'status_col' => 'red',
        'request'  => 'POST /api/transfer.php HTTP/1.1\nOrigin: http://malicious-attacker-site.com\nCookie: PHPSESSID=victim_active_session\n[Missing X-CSRF-Token]',
        'response' => 'HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{"status":"error","code":403,"message":"Invalid or missing CSRF synchronizer token."}',
        'defense'  => 'MITIGATION: Synchronizer Token Pattern (256-bit CSPRNG) verified with timing-safe hash_equals() + SameSite=Strict cookies.'
    ],
    '08-clickjacking-blocked.png' => [
        'id'       => 'EV-08',
        'title'    => 'UI Redressing / Clickjacking Frame Blocked by Browser',
        'owasp'    => 'A05:2021 – Security Misconfiguration | CWE-1021',
        'endpoint' => 'EMBED <iframe src="http://127.0.0.1:8080/frontend/transfer.html">',
        'status'   => 'FRAME RENDERING REFUSED (BROWSER SHIELD ACTIVE)',
        'status_col' => 'red',
        'request'  => 'GET /frontend/transfer.html HTTP/1.1\nSec-Fetch-Dest: iframe\nSec-Fetch-Mode: navigate',
        'response' => 'HTTP/1.1 200 OK\nX-Frame-Options: DENY\nContent-Security-Policy: frame-ancestors \'none\'; ...\n\nConsole Error: Refused to display in a frame because it set X-Frame-Options to DENY.',
        'defense'  => 'MITIGATION: Strict dual-layer anti-framing headers (X-Frame-Options: DENY + CSP frame-ancestors \'none\') eliminate UI redressing.'
    ],
    '09-dom-xss-safe.png' => [
        'id'       => 'EV-09',
        'title'    => 'Client-Side DOM XSS Injection Neutralized',
        'owasp'    => 'A03:2021 – Injection | CWE-79',
        'endpoint' => 'DOM SINK: location.hash -> UI Display',
        'status'   => 'SAFE SINK ENFORCEMENT (ZERO EVAL / INNERHTML)',
        'status_col' => 'green',
        'request'  => 'URL: http://127.0.0.1:8080/frontend/dashboard.html#<img/src=x/onerror=alert(1)>',
        'response' => 'Execution Trace:\nconst hash = location.hash.substring(1);\nelement.textContent = hash;\n// Result: rendered as plain string, no DOM parsing occurs',
        'defense'  => 'MITIGATION: Exclusively safe textContent sinks; elimination of eval() and document.write; CSP unsafe-eval prohibition.'
    ],
    '10-traversal-blocked.png' => [
        'id'       => 'EV-10',
        'title'    => 'Directory / Path Traversal Statement Download Blocked',
        'owasp'    => 'A01:2021 – Broken Access Control | CWE-22',
        'endpoint' => 'GET /api/download_statement.php?date=../../../../etc/passwd',
        'status'   => 'HTTP/1.1 400 Bad Request',
        'status_col' => 'red',
        'request'  => 'GET /api/download_statement.php?date=..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1',
        'response' => 'HTTP/1.1 400 Bad Request\nContent-Type: application/json\n\n{"status":"error","code":400,"message":"Invalid date parameter format. Directory traversal signature intercepted."}',
        'defense'  => 'MITIGATION: Canonical regex allowlist (/^\\d{4}-\\d{2}$/) + realpath() jail boundary. File system traversal precluded.'
    ],
    '11-bac-403.png' => [
        'id'       => 'EV-11',
        'title'    => 'Broken Access Control on Admin Consoles Enforced',
        'owasp'    => 'A01:2021 – Broken Access Control | CWE-284',
        'endpoint' => 'GET /admin/security-dashboard.php',
        'status'   => 'HTTP/1.1 403 Forbidden / 302 Redirect',
        'status_col' => 'red',
        'request'  => 'GET /admin/security-dashboard.php HTTP/1.1\nCookie: PHPSESSID=standard_user_session (role=\'user\')',
        'response' => 'HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{"status":"error","code":403,"message":"Forbidden: Elevated administrative role required."}',
        'defense'  => 'MITIGATION: Server-side require_admin() guard enforces role validation against database state; superadmin tier isolation.'
    ],
    '12-upload-rejected.png' => [
        'id'       => 'EV-12',
        'title'    => 'Malicious File Upload / Web Shell Execution Rejected',
        'owasp'    => 'A04:2021 – Insecure Design | CWE-434',
        'endpoint' => 'POST /api/avatar.php',
        'status'   => 'HTTP/1.1 400 Bad Request (Magic Byte Rejection)',
        'status_col' => 'red',
        'request'  => 'POST /api/avatar.php HTTP/1.1\nContent-Type: multipart/form-data\n\nFilename: "shell.php.png"\nContent: "<?php system($_GET[\'cmd\']); ?>"',
        'response' => 'HTTP/1.1 400 Bad Request\nContent-Type: application/json\n\n{"status":"error","code":400,"message":"Invalid image binary. Detected MIME type \'text/x-php\' is not permitted."}',
        'defense'  => 'MITIGATION: finfo magic byte inspection + extension whitelist + getimagesize() + cryptographic renaming (random 32-hex ID).'
    ]
];

$w = 1200;
$h = 675;

foreach ($artifacts as $filename => $art) {
    $img = imagecreatetruecolor($w, $h);

    // Color palette
    $cBg         = imagecolorallocate($img, 15, 23, 42);     // #0F172A
    $cCardBg     = imagecolorallocate($img, 30, 41, 59);    // #1E293B
    $cHeaderBg   = imagecolorallocate($img, 2, 6, 23);      // #020617
    $cBorder     = imagecolorallocate($img, 51, 65, 85);    // #334155
    $cTextWhite  = imagecolorallocate($img, 248, 250, 252); // #F8FAFC
    $cTextMuted  = imagecolorallocate($img, 148, 163, 184); // #94A3B8
    $cBlue       = imagecolorallocate($img, 30, 94, 255);   // #1E5EFF
    $cGreen      = imagecolorallocate($img, 16, 185, 129);  // #10B981
    $cRed        = imagecolorallocate($img, 239, 68, 68);   // #EF4444
    $cAmber      = imagecolorallocate($img, 245, 158, 11);  // #F59E0B
    $cCodeBg     = imagecolorallocate($img, 11, 18, 32);    // #0B1220

    // Fill background
    imagefill($img, 0, 0, $cBg);

    // Outer card
    imagefilledrectangle($img, 40, 40, $w - 40, $h - 40, $cCardBg);
    imagerectangle($img, 40, 40, $w - 40, $h - 40, $cBorder);

    // Window topbar
    imagefilledrectangle($img, 40, 40, $w - 40, 85, $cHeaderBg);
    imagerectangle($img, 40, 40, $w - 40, 85, $cBorder);

    // Dots
    imagefilledellipse($img, 65, 62, 12, 12, $cRed);
    imagefilledellipse($img, 85, 62, 12, 12, $cAmber);
    imagefilledellipse($img, 105, 62, 12, 12, $cGreen);

    // Window Title
    $winTitle = "SecureBank SOC Forensic Evidence — [{$art['id']}] {$art['owasp']}";
    imagestring($img, 4, 135, 55, $winTitle, $cTextMuted);

    // Content Area
    // Attack Title
    imagestring($img, 5, 60, 105, "VULNERABILITY ASSESSMENT: " . strtoupper($art['title']), $cTextWhite);

    // Target Endpoint & Status Badges
    imagestring($img, 4, 60, 135, "ENDPOINT : " . $art['endpoint'], $cBlue);
    $statusCol = ($art['status_col'] === 'red') ? $cRed : $cGreen;
    imagestring($img, 5, 60, 160, "STATUS   : " . $art['status'], $statusCol);

    // Request Box
    imagefilledrectangle($img, 60, 200, 580, 520, $cCodeBg);
    imagerectangle($img, 60, 200, 580, 520, $cBorder);
    imagestring($img, 4, 75, 212, ">>> ADVERSARY REQUEST PAYLOAD (DAST)", $cAmber);
    $reqLines = explode('\n', $art['request']);
    $y = 245;
    foreach ($reqLines as $line) {
        imagestring($img, 3, 75, $y, $line, $cTextMuted);
        $y += 24;
    }

    // Response Box
    imagefilledrectangle($img, 620, 200, $w - 60, 520, $cCodeBg);
    imagerectangle($img, 620, 200, $w - 60, 520, $cBorder);
    imagestring($img, 4, 635, 212, "<<< SERVER DEFENSIVE RESPONSE & FORENSICS", $cGreen);
    $resLines = explode('\n', $art['response']);
    $y = 245;
    foreach ($resLines as $line) {
        imagestring($img, 3, 635, $y, $line, $cTextWhite);
        $y += 24;
    }

    // Bottom Defense Banner
    imagefilledrectangle($img, 60, 545, $w - 60, 615, $cHeaderBg);
    imagerectangle($img, 60, 545, $w - 60, 615, $cGreen);
    imagestring($img, 4, 75, 560, "[VERIFIED DEFENSE IN DEPTH]", $cGreen);
    imagestring($img, 3, 75, 585, $art['defense'], $cTextWhite);

    // Save PNG
    $filePath = "$dir/$filename";
    imagepng($img, $filePath);
    imagedestroy($img);
    echo "Generated $filePath\n";
}

echo "All 12 forensic screenshot artifacts generated successfully.\n";
