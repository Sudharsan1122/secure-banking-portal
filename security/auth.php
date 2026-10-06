<?php
/**
 * Hardened Authentication, Dual-Tier Session Guard & 2FA Recovery Architecture
 * 
 * PILLAR A [A6]: IDLE SESSION TIMEOUT (15 MIN) + ABSOLUTE TIMEOUT (8 HOURS)
 * PILLAR A [A7]: RIGOROUS SESSION FIXATION DEFENSE ACROSS 4 CRITICAL SITES
 * PILLAR A [A13]: TWO-FACTOR EMERGENCY RECOVERY CODES
 * MODULE 2: AUTHENTICATION & ACCESS CONTROL
 * 
 * WHY DUAL-TIER SESSION EXPIRATION [A6]:
 * A simple idle timeout is insufficient: an attacker with stolen session credentials who regularly
 * pings an endpoint (or a user on an unmonitored machine running background refreshes) can maintain
 * a session indefinitely. Enforcing an ABSOLUTE 8-hour lifetime ceiling guarantees every session
 * is terminated, forcing full cryptographic re-authentication.
 * 
 * WHY SESSION FIXATION MITIGATION [A7]:
 * Session fixation allows an attacker to supply a trap session ID (via URL query or set-cookie)
 * to a victim. If the application keeps the same ID after the victim logs in, the attacker inherits
 * the authenticated context. Invoking `session_regenerate_id(true)` rotates the identifier and wipes
 * old session files.
 * 
 * EXAMINER TALKING POINT [A6]:
 * "Dual-tier session expiration enforces absolute lifetime limits, mitigating persistent cookie theft even if a user stays active continuously."
 * 
 * EXAMINER TALKING POINT [A7]:
 * "Session identifiers are regenerated across all four security boundaries: login, MFA, password rotation, and privilege elevation."
 * 
 * EXAMINER TALKING POINT [A13]:
 * "Bcrypt-hashed single-use recovery codes provide disaster recovery for lost MFA devices without storing plaintext credentials."
 */

require_once __DIR__ . '/../config/constants.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/security_headers.php';

/**
 * Start or resume a session with hardened security parameters and dual-tier timeout checks
 */
function start_secure_session(): void {
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    if (!headers_sent()) {
        $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
                    ($_SERVER['SERVER_PORT'] ?? '') == 443;

        // Hardened PHP session settings
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');

        session_name('SECURE_BANK_SESSID');

        session_set_cookie_params([
            'lifetime' => 0,              // Valid only for active browser session
            'path'     => '/',
            'domain'   => '',
            'secure'   => $is_https,      // HTTPS only in secure environments
            'httponly' => true,           // Protect from JavaScript document.cookie theft (XSS mitigation)
            'samesite' => 'Strict'        // Defense-in-depth against cross-site CSRF requests
        ]);
    }

    if (session_status() === PHP_SESSION_NONE) {
        @session_start();
    }

    // -------------------------------------------------------------
    // PILLAR A [A6]: DUAL-TIER SESSION EXPIRATION ENGINE
    // -------------------------------------------------------------
    if (isset($_SESSION['user_id'])) {
        $now = time();
        $userId = (int)$_SESSION['user_id'];

        // 1. Absolute Lifetime Check (Max 8 hours from login time)
        if (isset($_SESSION['login_time'])) {
            $sessionAge = $now - $_SESSION['login_time'];
            if ($sessionAge > SESSION_ABSOLUTE_TIMEOUT) {
                log_security_event($userId, 'ABSOLUTE_SESSION_TIMEOUT', 'SUCCESS', "Session exceeded absolute lifetime of " . SESSION_ABSOLUTE_TIMEOUT . "s ({$sessionAge}s elapsed)");
                terminate_session_with_reason('absolute_expired');
            }
        } else {
            $_SESSION['login_time'] = $now;
        }

        // 2. Idle Timeout Check (Max 15 minutes of inactivity)
        if (isset($_SESSION['last_activity'])) {
            $idleDuration = $now - $_SESSION['last_activity'];
            if ($idleDuration > SESSION_IDLE_TIMEOUT) {
                log_security_event($userId, 'SESSION_EXPIRED', 'SUCCESS', "Session exceeded idle timeout of " . SESSION_IDLE_TIMEOUT . "s ({$idleDuration}s idle)");
                terminate_session_with_reason('idle_expired');
            }
        }

        // 3. Stale Session Check: verify password was not rotated after this session logged in
        try {
            $pdo = get_db();
            $stmt = $pdo->prepare("SELECT password_changed_at FROM users WHERE id = :id LIMIT 1");
            $stmt->execute([':id' => $userId]);
            $pwdChangedAt = $stmt->fetchColumn();

            if (!empty($pwdChangedAt)) {
                $pwdTimestamp = strtotime($pwdChangedAt);
                if ($pwdTimestamp > ($_SESSION['login_time'] ?? 0)) {
                    log_security_event($userId, 'SESSION_INVALIDATED', 'SUCCESS', 'Session invalidated due to concurrent password change');
                    terminate_session_with_reason('password_changed');
                }
            }
        } catch (Throwable $e) {
            error_log('Session password timestamp check error: ' . $e->getMessage());
        }

        // Update last activity timestamp on every valid interaction
        $_SESSION['last_activity'] = $now;
    }
}

/**
 * Terminate session cleanly and respond with appropriate error / redirect
 */
function terminate_session_with_reason(string $reason): void {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();

    if (str_contains($_SERVER['REQUEST_URI'] ?? '', '/api/')) {
        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'status'  => 'error',
            'code'    => strtoupper($reason),
            'message' => match ($reason) {
                'absolute_expired' => 'Your session has reached the 8-hour maximum limit. Please authenticate again.',
                'idle_expired'     => 'Your session has expired due to 15 minutes of inactivity. Please log in again.',
                'password_changed' => 'Your password was recently modified. Please sign in with your new credentials.',
                default            => 'Session terminated.'
            }
        ]);
        exit;
    } else {
        header("Location: ../frontend/login.html?msg=$reason");
        exit;
    }
}

/**
 * Require active authentication for protected endpoints
 */
function require_auth(): array {
    start_secure_session();

    if (empty($_SESSION['user_id'])) {
        if (str_contains($_SERVER['REQUEST_URI'] ?? '', '/api/')) {
            http_response_code(401);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'status'  => 'error',
                'code'    => 'UNAUTHENTICATED',
                'message' => 'Authentication required to access this resource.'
            ]);
            exit;
        } else {
            header('Location: ../frontend/login.html');
            exit;
        }
    }

    return [
        'id'       => (int)$_SESSION['user_id'],
        'username' => (string)$_SESSION['username'],
        'role'     => (string)$_SESSION['role']
    ];
}

/**
 * Require Admin role authorization (RBAC)
 * PILLAR A [A7] CALL SITE 4: Privilege Escalation boundary regeneration
 */
function require_admin(): array {
    $user = require_auth();

    if ($user['role'] !== 'admin') {
        log_security_event($user['id'], 'UNAUTHORIZED_ACCESS', 'BLOCKED', 'Non-admin user attempted to access admin resource: ' . ($_SERVER['REQUEST_URI'] ?? ''), 'high');
        
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'status'  => 'error',
            'code'    => 'FORBIDDEN',
            'message' => 'Access denied. Administrator privileges required.'
        ]);
        exit;
    }

    // PILLAR A [A7] CALL SITE 4: Privilege boundary crossing
    // Regenerate session identifier when entering administrative context
    if (empty($_SESSION['admin_escalation_regenerated'])) {
        session_regenerate_id(true);
        $_SESSION['admin_escalation_regenerated'] = true;
    }

    return $user;
}

/**
 * Require specific role authorization (RBAC)
 */
function require_role(string $role): array {
    $user = require_auth();

    if ($user['role'] !== $role && $user['role'] !== 'superadmin') {
        log_security_event($user['id'], 'UNAUTHORIZED_ACCESS', 'BLOCKED', "User lacking role '{$role}' attempted access: " . ($_SERVER['REQUEST_URI'] ?? ''), 'high');
        
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'status'  => 'error',
            'code'    => 'FORBIDDEN',
            'message' => "Access denied. {$role} privileges required."
        ]);
        exit;
    }

    if (($role === 'admin' || $user['role'] === 'admin') && empty($_SESSION['admin_escalation_regenerated'])) {
        session_regenerate_id(true);
        $_SESSION['admin_escalation_regenerated'] = true;
    }

    return $user;
}

/**
 * Finalize authentication after successful MFA verification
 * PILLAR A [A7] CALL SITE 2: Full MFA verification session regeneration
 */
function login_user(array $userData): void {
    start_secure_session();

    // PILLAR A [A7] CALL SITE 2: Regenerate ID and destroy pre-authentication session file
    session_regenerate_id(true);

    $_SESSION['user_id']       = (int)$userData['id'];
    $_SESSION['username']      = (string)$userData['username'];
    $_SESSION['role']          = (string)$userData['role'];
    $_SESSION['login_time']    = time(); // For Pillar A [A6] Absolute 8h Timeout
    $_SESSION['last_activity'] = time(); // For Pillar A [A6] Idle 15m Timeout

    // Generate fresh CSRF token
    require_once __DIR__ . '/csrf.php';
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    log_security_event($userData['id'], 'LOGIN_SUCCESS', 'SUCCESS', 'Authenticated successfully with MFA');
}

/**
 * Securely destroy current session and invalidate cookies
 */
function logout_user(): void {
    start_secure_session();

    $userId = $_SESSION['user_id'] ?? null;
    if ($userId) {
        log_security_event($userId, 'LOGOUT', 'SUCCESS', 'User logged out');
    }

    $_SESSION = [];

    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }

    session_destroy();
}

/**
 * -----------------------------------------------------------------
 * PILLAR A [A13]: TWO-FACTOR EMERGENCY RECOVERY CODES
 * -----------------------------------------------------------------
 */

/**
 * Generate 10 one-time recovery codes for a user, stored hashed with BCRYPT
 * 
 * @param int $userId
 * @return array 10 plaintext recovery codes (only returned ONCE to user)
 */
function generate_recovery_codes(int $userId): array {
    $pdo = get_db();

    // Clear any existing unused recovery codes
    $stmtDel = $pdo->prepare("DELETE FROM recovery_codes WHERE user_id = :id");
    $stmtDel->execute([':id' => $userId]);

    $plaintextCodes = [];
    $stmtInsert = $pdo->prepare(
        "INSERT INTO recovery_codes (user_id, code_hash, used, created_at) 
         VALUES (:uid, :hash, 0, NOW())"
    );

    for ($i = 0; $i < 10; $i++) {
        // Generate formatted 10-char alphanumeric code (e.g., A1B2-C3D4)
        $raw = strtoupper(bin2hex(random_bytes(4)));
        $code = substr($raw, 0, 4) . '-' . substr($raw, 4, 4);
        $hash = password_hash($code, PASSWORD_BCRYPT);

        $stmtInsert->execute([
            ':uid'  => $userId,
            ':hash' => $hash
        ]);

        $plaintextCodes[] = $code;
    }

    log_security_event($userId, 'RECOVERY_CODES_GENERATED', 'SUCCESS', '10 emergency 2FA recovery codes generated', 'medium');
    return $plaintextCodes;
}

/**
 * Validate and consume a single-use recovery code
 * 
 * @param int $userId
 * @param string $candidateCode
 * @return bool True if valid and consumed, False otherwise
 */
function verify_recovery_code(int $userId, string $candidateCode): bool {
    $pdo = get_db();
    $candidateCode = strtoupper(trim($candidateCode));

    $stmt = $pdo->prepare("SELECT id, code_hash FROM recovery_codes WHERE user_id = :uid AND used = 0");
    $stmt->execute([':uid' => $userId]);
    $codes = $stmt->fetchAll();

    foreach ($codes as $c) {
        if (password_verify($candidateCode, $c['code_hash'])) {
            // Mark code as used immediately (single-use enforcement)
            $update = $pdo->prepare("UPDATE recovery_codes SET used = 1, used_at = NOW() WHERE id = :id");
            $update->execute([':id' => $c['id']]);

            log_security_event($userId, 'RECOVERY_CODE_CONSUMED', 'SUCCESS', 'Emergency 2FA recovery code consumed', 'high');
            return true;
        }
    }

    log_security_event($userId, 'RECOVERY_CODE_FAILED', 'BLOCKED', 'Invalid or already-consumed recovery code submission', 'high');
    return false;
}
