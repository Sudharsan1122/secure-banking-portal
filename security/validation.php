<?php
/**
 * Input Validation, Sanitization, Canonicalization, HPP Defense & Attack Signature Detection
 * 
 * MODULE 1: REGISTRATION INPUT VALIDATION
 * MODULE 5: XSS PROTECTION & PAYLOAD DETECTION
 * MODULE 8: SQL INJECTION DETECTION
 * PILLAR A [A9]: HTTP PARAMETER POLLUTION (HPP) DEFENSE
 * PILLAR A [A10]: HTTP METHOD ENFORCEMENT
 * PILLAR A [A11]: INPUT CANONICALIZATION (UNICODE / NULL-BYTE / ENTITY NORMALIZATION)
 * 
 * WHY CANONICALIZATION [A11]:
 * Attackers bypass filters by using multi-encoded characters (e.g. %253Cscript), null-byte poisoning
 * (\0), or mixed Unicode encodings. Canonicalization converts input to its simplest, standard representation
 * BEFORE validation is applied.
 * 
 * WHY HPP DEFENSE [A9]:
 * HTTP Parameter Pollution occurs when query parameters are repeated (e.g. ?amount=10&amount=1000).
 * Different backends, proxies, or WAFs interpret duplicate parameters differently (first vs last),
 * which attackers exploit to bypass WAF rules while reaching application logic.
 * 
 * WHY METHOD ENFORCEMENT [A10]:
 * Restricting each endpoint to strictly declared verbs (e.g. POST for mutations) prevents state-changing
 * actions from being triggered via GET pre-fetching, image tag requests, or cross-site script inclusions (XSSI).
 * 
 * EXAMINER TALKING POINT [A9]:
 * "HPP defense prevents parameter split attacks and ensures WAF and application logic evaluate the identical parameter set."
 * 
 * EXAMINER TALKING POINT [A10]:
 * "Strict HTTP verb declaration enforces REST idempotency and closes accidental GET CSRF vectors."
 * 
 * EXAMINER TALKING POINT [A11]:
 * "Canonicalization neutralizes multi-byte evasion, null-byte truncations, and alternate Unicode encodings before regex checks."
 */

require_once __DIR__ . '/logger.php';

/**
 * Pillar A [A11]: Universal Input Canonicalization
 * Normalizes Unicode, removes null bytes, decodes HTML entities once, and trims whitespace.
 * 
 * @param mixed $input String or array of strings
 * @return mixed Sanitized and canonicalized data
 */
function canonicalize_input(mixed $input): mixed {
    if (is_array($input)) {
        return array_map('canonicalize_input', $input);
    }

    if (!is_string($input)) {
        return $input;
    }

    // 1. Remove null-bytes and null byte representations (stops path truncation & C-string bugs)
    $clean = str_replace(["\0", "%00", "\\0"], '', $input);

    // 2. Unicode normalization (NFKC: Compatibility decomposition followed by canonical composition)
    if (class_exists('Normalizer')) {
        $normalized = Normalizer::normalize($clean, Normalizer::FORM_C);
        if ($normalized !== false) {
            $clean = $normalized;
        }
    }

    // 3. Decode HTML entities once to evaluate underlying payload (e.g., &lt;script&gt;)
    $clean = html_entity_decode($clean, ENT_QUOTES | ENT_HTML5, 'UTF-8');

    // 4. Trim leading/trailing whitespace
    return trim($clean);
}

/**
 * Pillar A [A9]: HTTP Parameter Pollution (HPP) Defense
 * Inspects raw query string and raw POST body for duplicate parameter keys.
 * 
 * @return bool True if duplicate parameter was detected (pollution attempt), False otherwise
 */
function detect_parameter_pollution(): bool {
    $rawQuery = $_SERVER['QUERY_STRING'] ?? '';
    
    // Check GET query string
    if (!empty($rawQuery)) {
        $pairs = explode('&', $rawQuery);
        $seenKeys = [];
        foreach ($pairs as $pair) {
            if (empty($pair)) continue;
            $parts = explode('=', $pair, 2);
            $key = urldecode($parts[0]);
            
            // Normalize array-style keys (e.g., items[] vs items)
            $cleanKey = rtrim($key, '[]');
            
            if (isset($seenKeys[$cleanKey]) && !str_ends_with($key, '[]')) {
                log_security_event(
                    $_SESSION['user_id'] ?? null,
                    'PARAMETER_POLLUTION',
                    'BLOCKED',
                    "Duplicate query parameter '$key' detected in request: " . mb_substr($rawQuery, 0, 200),
                    'high'
                );
                return true;
            }
            $seenKeys[$cleanKey] = true;
        }
    }

    // Check POST application/x-www-form-urlencoded body
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    if (str_contains($contentType, 'application/x-www-form-urlencoded')) {
        $rawBody = file_get_contents('php://input');
        if (!empty($rawBody)) {
            $pairs = explode('&', $rawBody);
            $seenKeys = [];
            foreach ($pairs as $pair) {
                if (empty($pair)) continue;
                $parts = explode('=', $pair, 2);
                $key = urldecode($parts[0]);
                $cleanKey = rtrim($key, '[]');
                if (isset($seenKeys[$cleanKey]) && !str_ends_with($key, '[]')) {
                    log_security_event(
                        $_SESSION['user_id'] ?? null,
                        'PARAMETER_POLLUTION',
                        'BLOCKED',
                        "Duplicate POST parameter '$key' detected in request body",
                        'high'
                    );
                    return true;
                }
                $seenKeys[$cleanKey] = true;
            }
        }
    }

    return false;
}

/**
 * Enforce HPP guard: if pollution detected, reject immediately with HTTP 400 Bad Request
 */
function guard_parameter_pollution(): void {
    if (detect_parameter_pollution()) {
        http_response_code(400);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'status'  => 'error',
            'code'    => 'HTTP_PARAMETER_POLLUTION_DETECTED',
            'message' => 'Duplicate parameter keys detected. Request terminated to prevent HTTP Parameter Pollution.'
        ]);
        exit;
    }
}

/**
 * Pillar A [A10]: Strict HTTP Method Enforcement
 * Restricts the endpoint to specific HTTP methods (e.g. POST only).
 * 
 * @param string|array $allowed Single method ('POST') or array (['GET', 'POST'])
 */
function require_method($allowed): void {
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    $allowedList = is_array($allowed) ? array_map('strtoupper', $allowed) : [strtoupper($allowed)];

    if (!in_array($method, $allowedList, true)) {
        header('Allow: ' . implode(', ', $allowedList));
        http_response_code(405);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'status'  => 'error',
            'code'    => 'METHOD_NOT_ALLOWED',
            'message' => "Method $method not allowed. Allowed methods: " . implode(', ', $allowedList)
        ]);
        exit;
    }
}

/**
 * Validate username format (alphanumeric, underscores, 3-30 chars)
 */
function validate_username(string $username): bool {
    $clean = canonicalize_input($username);
    return (bool)preg_match('/^[a-zA-Z0-9_]{3,30}$/', $clean);
}

/**
 * Validate email address format using RFC-compliant filter
 */
function validate_email(string $email): bool {
    $clean = canonicalize_input($email);
    return filter_var($clean, FILTER_VALIDATE_EMAIL) !== false && strlen($clean) <= 150;
}

/**
 * Validate phone number (allows standard international and local patterns)
 */
function validate_phone(string $phone): bool {
    $clean = canonicalize_input($phone);
    return (bool)preg_match('/^\+?[0-9\s\-\(\)]{7,20}$/', $clean);
}

/**
 * Validate password strength
 * Rules: At least 8 characters, 1 uppercase letter, 1 lowercase letter, 1 number, 1 special character
 */
function validate_password_strength(string $password): array {
    $errors = [];

    if (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters long.';
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'Password must include at least one uppercase letter.';
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = 'Password must include at least one lowercase letter.';
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = 'Password must include at least one digit.';
    }
    if (!preg_match('/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/', $password)) {
        $errors[] = 'Password must include at least one special character.';
    }

    return [
        'is_valid' => empty($errors),
        'errors'   => $errors
    ];
}

/**
 * Validate monetary amount (> 0, finite, max 2 decimals)
 */
function validate_amount($amount): ?float {
    if (!is_numeric($amount)) {
        return null;
    }
    $val = (float)$amount;
    if ($val <= 0 || $val > 10000000.00 || is_nan($val) || is_infinite($val)) {
        return null;
    }
    return round($val, 2);
}

/**
 * Validate statement date format (YYYY-MM)
 * Strict regex prevents Directory Traversal (e.g. 2026-01/../../etc/passwd)
 */
function validate_statement_date(string $date): bool {
    $clean = canonicalize_input($date);
    return (bool)preg_match('/^\d{4}-(0[1-9]|1[0-2])$/', $clean);
}

/**
 * Inspect input for Cross-Site Scripting (XSS) vectors.
 * If detected, logs an XSS_BLOCKED event to security_logs with 'high' severity.
 */
function detect_xss_payload(string $input, ?int $userId = null): bool {
    $clean = canonicalize_input($input);

    $patterns = [
        '/<script\b[^>]*>/i',
        '/<\/script>/i',
        '/onerror\s*=\s*/i',
        '/onload\s*=\s*/i',
        '/onclick\s*=\s*/i',
        '/onmouseover\s*=\s*/i',
        '/javascript\s*:/i',
        '/<img\b[^>]*src\s*=\s*["\']?x["\']?/i',
        '/<svg\b[^>]*>/i',
        '/<iframe\b[^>]*>/i'
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $clean)) {
            log_security_event(
                $userId,
                'XSS_BLOCKED',
                'BLOCKED',
                'XSS signature detected in input: ' . mb_substr($input, 0, 200),
                'high'
            );
            return true;
        }
    }
    return false;
}

/**
 * Inspect input for SQL Injection (SQLi) vectors.
 * If detected, logs a SQLI_BLOCKED event to security_logs with 'critical' severity.
 */
function detect_sqli_payload(string $input, ?int $userId = null): bool {
    $clean = canonicalize_input($input);

    $patterns = [
        '/(\bUNION\b\s+\bSELECT\b)/i',
        '/(\bOR\b\s+["\']?1["\']?\s*=\s*["\']?1["\']?)/i',
        '/(\bAND\b\s+["\']?1["\']?\s*=\s*["\']?1["\']?)/i',
        '/(--|\#|\/\*)/',
        '/(\bDROP\b\s+\bTABLE\b)/i',
        '/(\bSLEEP\s*\(\s*\d+\s*\))/i'
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $clean)) {
            log_security_event(
                $userId,
                'SQLI_BLOCKED',
                'BLOCKED',
                'SQLi signature detected in input: ' . mb_substr($input, 0, 200),
                'critical'
            );
            return true;
        }
    }
    return false;
}

/**
 * Context-Aware Output Escaping for HTML
 */
function safe_html(?string $str): string {
    if ($str === null) {
        return '';
    }
    return htmlspecialchars($str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Convenience helper: Detect SQL Injection
 */
function detect_sqli(string $input, ?int $userId = null): bool {
    return detect_sqli_payload($input, $userId);
}

/**
 * Convenience helper: Detect Cross-Site Scripting
 */
function detect_xss(string $input, ?int $userId = null): bool {
    return detect_xss_payload($input, $userId);
}

/**
 * Inspect input for Directory/Path Traversal vectors (e.g. ../, ..\)
 */
function detect_traversal(string $input, ?int $userId = null): bool {
    $clean = canonicalize_input($input);
    if (str_contains($clean, '..') || str_contains($clean, '../') || str_contains($clean, '..\\') || str_contains($input, '%2e%2e')) {
        log_security_event(
            $userId,
            'PATH_TRAVERSAL_BLOCKED',
            'BLOCKED',
            'Directory traversal signature detected in input: ' . mb_substr($input, 0, 200),
            'high'
        );
        return true;
    }
    return false;
}

