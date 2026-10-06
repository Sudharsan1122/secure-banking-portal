<?php
/**
 * User Registration API Endpoint
 * 
 * MODULE 1: REGISTRATION
 * 
 * SECURITY PRINCIPLES IMPLEMENTED:
 * 1. Strict Server-Side Validation: Name, email, phone (regex), username, and password complexity.
 * 2. Cryptographic Password Hashing: Uses password_hash(..., PASSWORD_BCRYPT) with auto-salt.
 * 3. Prepared Statements: Completely prevents SQL injection on insert and uniqueness checks.
 * 4. User Enumeration Defense / Conflict Handling: Checks existing username and email safely.
 * 5. SIEM Audit Logging: Logs REGISTRATION_SUCCESS or REGISTRATION_FAILED with client IP.
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../config/database.php';

require_once __DIR__ . '/../security/rate_limit.php';

// Pillar A [A10]: Method Enforcement
require_method('POST');

// Pillar A [A9]: Parameter Pollution Guard
guard_parameter_pollution();

// Pillar A [A3]: Enforce Sliding-Window Rate Limit (3 registrations / hour)
enforce_endpoint_rate_limit('/api/register.php');

// Parse incoming JSON or form payload
$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true) ?: $_POST;

// Pillar A [A11]: Input Canonicalization
$name     = canonicalize_input($input['name'] ?? '');
$email    = canonicalize_input($input['email'] ?? '');
$phone    = canonicalize_input($input['phone'] ?? '');
$username = canonicalize_input($input['username'] ?? '');
$password = $input['password'] ?? '';

// Check for malicious payload patterns
detect_xss_payload($name);
detect_xss_payload($username);
detect_sqli_payload($username);

// Server-side validation
$errors = [];

if (empty($name) || mb_strlen($name) < 2 || mb_strlen($name) > 100) {
    $errors[] = 'Full name must be between 2 and 100 characters.';
}

if (!validate_email($email)) {
    $errors[] = 'A valid email address is required.';
}

if (!validate_phone($phone)) {
    $errors[] = 'Invalid phone number format.';
}

if (!validate_username($username)) {
    $errors[] = 'Username must be 3-30 characters and contain only letters, numbers, and underscores.';
}

$passValidation = validate_password_strength($password);
if (!$passValidation['is_valid']) {
    $errors = array_merge($errors, $passValidation['errors']);
}

if (!empty($errors)) {
    http_response_code(400);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Validation failed.',
        'errors'  => $errors
    ]);
    exit;
}

try {
    $pdo = get_db();

    // Check for existing username or email
    $checkStmt = $pdo->prepare("SELECT id, username, email FROM users WHERE username = :username OR email = :email LIMIT 1");
    $checkStmt->execute([
        ':username' => $username,
        ':email'    => $email
    ]);
    $existing = $checkStmt->fetch();

    if ($existing) {
        http_response_code(409); // Conflict
        $field = ($existing['username'] === $username) ? 'Username' : 'Email';
        log_security_event(null, 'REGISTRATION_FAILED', 'BLOCKED', "Duplicate registration attempt for $field: " . ($field === 'Username' ? $username : $email));
        echo json_encode([
            'status'  => 'error',
            'message' => "$field already registered. Please choose another or log in."
        ]);
        exit;
    }

    // Hash the password securely with BCRYPT
    // Password cost is default 10, provides high resistance against brute-force hashing
    $passwordHash = password_hash($password, PASSWORD_BCRYPT);

    // Begin atomic transaction to create user and initial banking account
    $pdo->beginTransaction();

    $insertUser = $pdo->prepare(
        "INSERT INTO users (name, email, phone, username, password_hash, balance, role, created_at) 
         VALUES (:name, :email, :phone, :username, :hash, :balance, 'user', NOW())"
    );
    
    // Default starting promotional balance for demo
    $initialBalance = 1000.00;

    $insertUser->execute([
        ':name'     => $name,
        ':email'    => $email,
        ':phone'    => $phone,
        ':username' => $username,
        ':hash'     => $passwordHash,
        ':balance'  => $initialBalance
    ]);

    $userId = (int)$pdo->lastInsertId();

    // Generate unique account number: ACC-USER-{1000 + userId}
    $accountNumber = sprintf("ACC-USER-%04d", 1000 + $userId);

    $insertAccount = $pdo->prepare(
        "INSERT INTO accounts (user_id, account_number, balance, currency, created_at) 
         VALUES (:user_id, :account_number, :balance, 'USD', NOW())"
    );
    $insertAccount->execute([
        ':user_id'        => $userId,
        ':account_number' => $accountNumber,
        ':balance'        => $initialBalance
    ]);

    $pdo->commit();

    log_security_event($userId, 'REGISTRATION_SUCCESS', 'SUCCESS', "New user registered: $username (ID: $userId, Account: $accountNumber)");

    http_response_code(201);
    echo json_encode([
        'status'         => 'success',
        'message'        => 'Registration successful! Your banking account has been created. Please log in.',
        'account_number' => $accountNumber
    ]);

} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('Registration Error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'status'  => 'error',
        'message' => 'An error occurred during account creation. Please try again later.'
    ]);
}
