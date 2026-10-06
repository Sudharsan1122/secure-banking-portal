<?php
/**
 * Cross-Site Request Forgery (CSRF) Protection Library
 * 
 * MODULE 6: CSRF PROTECTION
 * 
 * SECURITY PRINCIPLES IMPLEMENTED:
 * 1. Synchronizer Token Pattern (STP): Generates a cryptographically strong,
 *    unpredictable pseudo-random token tied directly to the user's active session.
 * 2. Cryptographic Randomness: Uses random_bytes(32) (CSPRNG), converted to a 64-character
 *    hexadecimal string. Never uses predictable rand() or mt_rand().
 * 3. Timing-Safe Comparison: Uses hash_equals() instead of '===' to prevent
 *    side-channel timing attacks that could allow attackers to reconstruct the token byte-by-byte.
 * 4. Dual-Transport Extraction: Inspects both the custom 'X-CSRF-Token' request header
 *    (for modern asynchronous Fetch/AJAX requests) and the standard 'csrf_token' POST field.
 * 5. Automated SIEM Logging: Any token discrepancy is immediately logged to security_logs
 *    as a CSRF_FAILURE event with offending IP and user identifier.
 */

require_once __DIR__ . '/logger.php';

/**
 * Ensure a CSRF token exists in the current session; generate one if absent.
 * 
 * @return string 64-character hex CSRF token
 */
function generate_csrf_token(): string {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        // Session must be initialized before generating CSRF token
        require_once __DIR__ . '/auth.php';
        start_secure_session();
    }

    if (empty($_SESSION['csrf_token'])) {
        // Generate 32 bytes of cryptographically secure randomness = 64 hex chars
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

/**
 * Fetch the current session's CSRF token
 */
function get_csrf_token(): string {
    return generate_csrf_token();
}

/**
 * Validate an incoming CSRF token against the session token
 * 
 * @param string|null $candidate_token
 * @return bool
 */
function validate_csrf_token(?string $candidate_token = null): bool {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        require_once __DIR__ . '/auth.php';
        start_secure_session();
    }

    $session_token = $_SESSION['csrf_token'] ?? '';

    // If candidate token not explicitly passed, inspect headers and body
    if ($candidate_token === null) {
        // 1. Check custom HTTP Header (Fetch API / Axios / AJAX standard)
        $candidate_token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;

        // 2. Fallback to POST body form-data
        if (empty($candidate_token) && isset($_POST['csrf_token'])) {
            $candidate_token = (string)$_POST['csrf_token'];
        }

        // 3. Fallback to JSON payload if Content-Type is application/json
        if (empty($candidate_token)) {
            $rawInput = file_get_contents('php://input');
            if (!empty($rawInput)) {
                $decoded = json_decode($rawInput, true);
                if (is_array($decoded) && isset($decoded['csrf_token'])) {
                    $candidate_token = (string)$decoded['csrf_token'];
                }
            }
        }
    }

    // Both tokens must be non-empty strings of valid length (64 hex characters)
    if (empty($session_token) || empty($candidate_token)) {
        log_security_event(
            $_SESSION['user_id'] ?? null,
            'CSRF_FAILURE',
            'BLOCKED',
            'Missing CSRF token in state-changing request: ' . ($_SERVER['REQUEST_URI'] ?? '')
        );
        return false;
    }

    // Timing-attack resistant string comparison
    $isValid = hash_equals($session_token, $candidate_token);

    if (!$isValid) {
        log_security_event(
            $_SESSION['user_id'] ?? null,
            'CSRF_FAILURE',
            'BLOCKED',
            'Mismatched CSRF token. Expected token length ' . strlen($session_token) . ', received ' . strlen($candidate_token)
        );
    }

    return $isValid;
}

/**
 * Guard function to enforce CSRF validation on all state-changing HTTP methods
 * Terminates the request with HTTP 403 Forbidden if the token is invalid.
 */
function require_csrf_token(): void {
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    
    // Only state-changing methods require CSRF validation (POST, PUT, DELETE, PATCH)
    if (in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH'], true)) {
        if (!validate_csrf_token()) {
            http_response_code(403);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'status'  => 'error',
                'code'    => 'CSRF_VALIDATION_FAILED',
                'message' => 'Cross-Site Request Forgery (CSRF) token validation failed. Request terminated.'
            ], JSON_UNESCAPED_SLASHES);
            exit;
        }
    }
}
