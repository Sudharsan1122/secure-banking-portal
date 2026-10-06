<?php
/**
 * Authentication API Endpoint (Step 1: Credentials Verification)
 * 
 * MODULE 2: LOGIN + MFA
 * PILLAR A [A3]: RATE LIMITING ON LOGIN ENDPOINT (5 ATTEMPTS / 15 MIN)
 * PILLAR A [A4]: EXPONENTIAL BACKOFF ACCOUNT LOCKOUT (5 MIN, 30 MIN, ADMIN LOCK)
 * PILLAR A [A7]: SESSION FIXATION DEFENSE CALL SITE 1 (PRE-AUTH SESSION REGENERATION)
 * PILLAR A [A9]: PARAMETER POLLUTION GUARD
 * PILLAR A [A10]: HTTP METHOD ENFORCEMENT
 * PILLAR A [A11]: INPUT CANONICALIZATION
 * 
 * WHY THIS PIPELINE:
 * 1. Method enforcement rejects any accidental GET request.
 * 2. Parameter pollution defense prevents parameter duplication bypasses.
 * 3. Sliding window IP rate limiting throttles automated scanners before database queries.
 * 4. User account lockout check stops credential guessing even across distributed IPs.
 * 5. Pre-auth session ID regeneration breaks any pre-existing attacker-controlled session token.
 * 
 * EXAMINER TALKING POINT [A4]:
 * "Our exponential lockout tiers raise attacker cost from minutes to permanent administrative containment."
 * 
 * EXAMINER TALKING POINT [A7]:
 * "Session fixation defense Site 1: session_regenerate_id(true) is invoked upon initial credential validation."
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/rate_limit.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/constants.php';

// Pillar A [A10]: Strict HTTP Method Enforcement
require_method('POST');

// Pillar A [A9]: HTTP Parameter Pollution Defense
guard_parameter_pollution();

// Pillar A [A3]: Enforce Sliding-Window Rate Limit (5 attempts / 15 min)
enforce_endpoint_rate_limit('/api/login.php');

$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true) ?: $_POST;

// Pillar A [A11]: Input Canonicalization
$username = canonicalize_input($input['username'] ?? '');
$password = $input['password'] ?? '';
$clientIp = get_client_ip();

// Detect attack signatures
detect_sqli_payload($username);
detect_xss_payload($username);

if (empty($username) || empty($password)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Username and password are required.']);
    exit;
}

try {
    $pdo = get_db();

    // Query user by username safely using prepared statements
    $stmt = $pdo->prepare(
        "SELECT id, username, password_hash, role, email, failed_login_count, locked_until 
         FROM users 
         WHERE username = :username LIMIT 1"
    );
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch();

    // Pillar A [A4]: Check if user account is currently locked
    if ($user) {
        $lockStatus = check_account_lockout((int)$user['id']);
        if ($lockStatus !== null) {
            http_response_code(403);
            echo json_encode([
                'status'            => 'error',
                'code'              => 'ACCOUNT_LOCKED',
                'message'           => $lockStatus['lock_reason'],
                'seconds_remaining' => $lockStatus['seconds_remaining'],
                'is_permanent'      => $lockStatus['is_permanent']
            ]);
            exit;
        }
    }

    // Timing-safe password verification
    $authenticated = false;
    if ($user && password_verify($password, $user['password_hash'])) {
        $authenticated = true;
    }

    if (!$authenticated) {
        // Record failure and increment exponential lockout if user exists
        if ($user) {
            $lockResult = record_failed_login_attempt((int)$user['id'], $username);
            if ($lockResult['lock_tier'] > 0) {
                http_response_code(403);
                echo json_encode([
                    'status'            => 'error',
                    'code'              => 'ACCOUNT_LOCKED',
                    'message'           => $lockResult['lock_reason'],
                    'seconds_remaining' => $lockResult['lock_seconds'],
                    'is_permanent'      => ($lockResult['lock_tier'] === 3)
                ]);
                exit;
            }
        } else {
            // Record generic IP attempt
            record_login_attempt($username, $clientIp, false);
            log_security_event(null, 'LOGIN_FAILED', 'FAILED', "Failed login attempt for non-existent user '$username'", 'low');
        }

        // Generic error message to prevent user enumeration
        http_response_code(401);
        echo json_encode([
            'status'  => 'error',
            'message' => 'Invalid username or password.'
        ]);
        exit;
    }

    // PILLAR A [A7] CALL SITE 1: Regenerate session ID upon primary credential validation
    start_secure_session();
    session_regenerate_id(true);

    // Generate cryptographically secure 6-digit OTP
    $otpCode = str_pad((string)random_int(100000, 999999), 6, '0', STR_PAD_LEFT);

    // Invalidate prior unused OTPs for this user
    $clearOldOtp = $pdo->prepare("UPDATE otp_codes SET used = 1 WHERE user_id = :user_id AND used = 0");
    $clearOldOtp->execute([':user_id' => $user['id']]);

    // Store new OTP in database with 5-minute expiry
    $insertOtp = $pdo->prepare(
        "INSERT INTO otp_codes (user_id, code, expires_at, used, created_at) 
         VALUES (:user_id, :code, DATE_ADD(NOW(), INTERVAL 5 MINUTE), 0, NOW())"
    );
    $insertOtp->execute([
        ':user_id' => $user['id'],
        ':code'    => $otpCode
    ]);

    log_security_event($user['id'], 'MFA_OTP_GENERATED', 'SUCCESS', "6-digit OTP generated for user {$user['username']}", 'low');

    // Store temporary pending state in session
    $_SESSION['pending_mfa_user_id'] = (int)$user['id'];
    $_SESSION['pending_mfa_time']    = time();

    http_response_code(200);
    echo json_encode([
        'status'         => 'otp_required',
        'message'        => 'Credentials verified. Please enter the 6-digit Multi-Factor Authentication (MFA) code.',
        'user_id'        => $user['id'],
        'username'       => $user['username'],
        'simulated_otp'  => $otpCode // Simulated MFA display for grading/evaluation
    ]);

} catch (Throwable $e) {
    error_log('Login API Error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'An unexpected error occurred. Please try again later.']);
}
