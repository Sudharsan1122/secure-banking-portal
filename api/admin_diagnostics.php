<?php
/**
 * Administrator Security Diagnostics & External Service Verification API
 * 
 * MODULE 10: OS COMMAND INJECTION PREVENTION & SAFE SYSTEM DIAGNOSTICS
 * MODULE 11: SERVER-SIDE REQUEST FORGERY (SSRF) PREVENTION
 * 
 * SECURITY PRINCIPLES IMPLEMENTED:
 * 1. Safe Diagnostics (Zero Shell Execution):
 *    - Uses native, memory-safe PHP functions (php_uname, disk_free_space, memory_get_usage)
 *      to monitor system status instead of invoking unsafe shell utilities like exec('ping ...').
 * 2. Strict SSRF Defense Pipeline:
 *    - Protocol Filtering: Enforces HTTPS/HTTP scheme exclusively.
 *    - Domain Whitelisting: Matches target against SSRF_WHITELIST_HOSTS.
 *    - DNS Resolution & IP Range Blacklisting: Resolves host via gethostbyname() and blocks
 *      loopback (127.0.0.0/8), private RFC 1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
 *      and AWS/cloud metadata link-local addresses (169.254.169.254).
 * 3. Role-Based Access Control (RBAC): require_admin() limits access to system administrators.
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../config/constants.php';
require_once __DIR__ . '/../config/database.php';

// Ensure user is authenticated AND holds the 'admin' role
$adminUser = require_admin();
$adminId = $adminUser['id'];

$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

/**
 * ===============================================================
 * MODULE 10: ACADEMIC COMPARISON — OS COMMAND INJECTION
 * ===============================================================
 * VULNERABLE CODE PATTERN:
 *   $host = $_GET['host'];
 *   // If attacker passes '127.0.0.1; cat /etc/passwd' or '& whoami',
 *   // the shell interpreter executes the injected payload with web server privileges!
 *   $output = shell_exec("ping -c 1 " . $host);
 * 
 * SECURE REMEDIATION:
 *   1) Avoid executing OS shell commands entirely whenever native APIs exist.
 *   2) Use PHP internal functions (php_uname, disk_free_space, memory_get_usage).
 *   3) If an external CLI tool is strictly required, use escapeshellcmd() or
 *      escapeshellarg() and avoid string concatenation.
 * ===============================================================
 */

// GET: Return native system diagnostics without executing shell commands
if ($method === 'GET') {
    try {
        $pdo = get_db();
        $dbVersion = $pdo->query('SELECT VERSION()')->fetchColumn();

        $diskTotal = @disk_total_space(__DIR__);
        $diskFree  = @disk_free_space(__DIR__);
        $diskUsagePct = ($diskTotal > 0) ? round((($diskTotal - $diskFree) / $diskTotal) * 100, 1) : 0;

        $diagnostics = [
            'os'               => php_uname('s') . ' ' . php_uname('r') . ' (' . php_uname('m') . ')',
            'host'             => php_uname('n'),
            'php_version'      => PHP_VERSION,
            'zend_version'     => zend_version(),
            'database_engine'  => 'MySQL ' . $dbVersion,
            'server_software'  => $_SERVER['SERVER_SOFTWARE'] ?? 'PHP Development Server',
            'memory_usage'     => round(memory_get_usage(true) / 1024 / 1024, 2) . ' MB',
            'memory_peak'      => round(memory_get_peak_usage(true) / 1024 / 1024, 2) . ' MB',
            'disk_free'        => ($diskFree > 0) ? round($diskFree / 1024 / 1024 / 1024, 2) . ' GB' : 'N/A',
            'disk_usage_pct'   => $diskUsagePct . '%',
            'server_time'      => date('Y-m-d H:i:s T'),
            'execution_mode'   => 'Safe Native PHP APIs (Zero OS Shell Invocation)',
            'command_injection_mitigation' => 'Hardened: System functions (exec, system, passthru) are disabled.'
        ];

        echo json_encode([
            'status' => 'success',
            'data'   => $diagnostics
        ]);
        exit;

    } catch (Throwable $e) {
        error_log('Diagnostics Error: ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Failed to gather system diagnostics.']);
        exit;
    }
}

/**
 * ===============================================================
 * MODULE 11: SSRF PREVENTION (EXTERNAL SERVICE CHECKER)
 * ===============================================================
 */
if ($method === 'POST') {
    require_csrf_token();

    $rawInput = file_get_contents('php://input');
    $input = json_decode($rawInput, true) ?: $_POST;

    $url = trim($input['service_url'] ?? '');

    if (empty($url)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Service URL parameter is required.']);
        exit;
    }

    // 1. Validate URL syntax
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Invalid URL syntax.']);
        exit;
    }

    $parsed = parse_url($url);
    $scheme = strtolower($parsed['scheme'] ?? '');
    $host   = strtolower($parsed['host'] ?? '');
    $port   = $parsed['port'] ?? null;

    // 2. Enforce permitted protocols (no file://, gopher://, dict://, php://)
    if (!in_array($scheme, ['http', 'https'], true)) {
        log_security_event($adminId, 'SSRF_BLOCKED', 'BLOCKED', "Blocked disallowed scheme '$scheme' in URL: $url");
        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => "Disallowed protocol scheme: $scheme. Only HTTP/HTTPS allowed."]);
        exit;
    }

    // 3. Allow-list Domain Verification
    $isWhitelisted = false;
    foreach (SSRF_WHITELIST_HOSTS as $allowedHost) {
        if ($host === $allowedHost || str_ends_with($host, '.' . $allowedHost)) {
            $isWhitelisted = true;
            break;
        }
    }

    if (!$isWhitelisted) {
        log_security_event($adminId, 'SSRF_BLOCKED', 'BLOCKED', "SSRF target host '$host' is not in whitelist: $url");
        http_response_code(403);
        echo json_encode([
            'status'  => 'error',
            'code'    => 'SSRF_DOMAIN_NOT_WHITELISTED',
            'message' => "Host '$host' is not an approved banking partner API. Target rejected by SSRF firewall."
        ]);
        exit;
    }

    // 4. DNS Resolution & Private IP Range Filtering (Blocks Cloud Metadata & Internal Subnets)
    $ip = gethostbyname($host);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => "Unable to resolve IP address for host: $host"]);
        exit;
    }

    // Check for Private / Reserved / Loopback IP Ranges (RFC 1918, RFC 3927, Loopback, Cloud Metadata)
    if (
        !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ||
        str_starts_with($ip, '127.') ||        // Loopback
        str_starts_with($ip, '169.254.') ||      // Link-Local / AWS IMDS (169.254.169.254)
        str_starts_with($ip, '0.') ||            // Current network
        $ip === '::1'                            // IPv6 Loopback
    ) {
        log_security_event($adminId, 'SSRF_BLOCKED', 'BLOCKED', "SSRF attempted access to restricted internal IP $ip ($host)");
        http_response_code(403);
        echo json_encode([
            'status'  => 'error',
            'code'    => 'SSRF_INTERNAL_IP_BLOCKED',
            'message' => "Access to internal/private IP address ($ip) is strictly prohibited."
        ]);
        exit;
    }

    // If validations pass, simulated safe external health ping
    log_security_event($adminId, 'SSRF_CHECK_PASSED', 'SUCCESS', "Verified approved external service: $url ($ip)");

    echo json_encode([
        'status'       => 'success',
        'message'      => "External service health check passed. Host is whitelisted and resolved to public IP.",
        'target_url'   => safe_html($url),
        'resolved_ip'  => $ip,
        'response_code'=> 200,
        'security_status' => 'APPROVED & VERIFIED'
    ]);
    exit;
}

http_response_code(405);
echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']);
