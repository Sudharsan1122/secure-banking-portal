<?php
/**
 * Open Additional Bank Account API Endpoint
 * 
 * PILLAR B [B6]: MULTI-ACCOUNT CREATION (SAVINGS, CURRENT, FD)
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../config/database.php';

require_method('POST');
guard_parameter_pollution();

$currentUser = require_auth();
$userId = $currentUser['id'];

require_csrf_token();

$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true) ?: $_POST;

$type = strtolower(trim($input['type'] ?? 'savings'));
$nickname = trim($input['nickname'] ?? '');
$initialDepositInput = $input['initial_deposit'] ?? 0;

$validTypes = ['savings', 'current', 'fd'];
if (!in_array($type, $validTypes, true)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => "Invalid account type. Supported types: 'savings', 'current', 'fd'."]);
    exit;
}

if (!empty($nickname)) {
    $nickname = canonicalize_input($nickname);
    detect_xss_payload($nickname, $userId);
    detect_sqli_payload($nickname, $userId);
    if (mb_strlen($nickname) > 64) {
        $nickname = mb_substr($nickname, 0, 64);
    }
} else {
    $nickname = ucfirst($type) . ' Account';
}

$initialDeposit = (float)$initialDepositInput;
if ($initialDeposit < 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Initial deposit cannot be negative.']);
    exit;
}

try {
    $pdo = get_db();

    // 1. Enforce max 5 accounts per user
    $stmtCount = $pdo->prepare("SELECT COUNT(*) FROM accounts WHERE user_id = :uid");
    $stmtCount->execute([':uid' => $userId]);
    $currentCount = (int)$stmtCount->fetchColumn();

    if ($currentCount >= 5) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Maximum account limit reached (5 accounts per user).']);
        exit;
    }

    // Set interest rate based on account type
    $interestRate = 0.00;
    if ($type === 'savings') $interestRate = 3.50;
    if ($type === 'fd') $interestRate = 6.50;

    // Generate unique account number
    $prefixMap = ['savings' => 'SAV', 'current' => 'CUR', 'fd' => 'FD'];
    $accPrefix = $prefixMap[$type] ?? 'ACC';
    $accountNumber = sprintf("ACC-%s-%05d", $accPrefix, random_int(10000, 99999));

    // Ensure uniqueness
    $stmtCheck = $pdo->prepare("SELECT COUNT(*) FROM accounts WHERE account_number = :acc");
    $stmtCheck->execute([':acc' => $accountNumber]);
    if ((int)$stmtCheck->fetchColumn() > 0) {
        $accountNumber = sprintf("ACC-%s-%05d", $accPrefix, random_int(10000, 99999));
    }

    $stmtInsert = $pdo->prepare(
        "INSERT INTO accounts (user_id, account_number, balance, currency, type, nickname, interest_rate, created_at)
         VALUES (:uid, :acc, :bal, 'USD', :type, :nick, :rate, NOW())"
    );
    $stmtInsert->execute([
        ':uid'  => $userId,
        ':acc'  => $accountNumber,
        ':bal'  => $initialDeposit,
        ':type' => $type,
        ':nick' => $nickname,
        ':rate' => $interestRate
    ]);
    $newAccId = (int)$pdo->lastInsertId();

    // Sync user aggregate balance
    $pdo->prepare("UPDATE users SET balance = (SELECT COALESCE(SUM(balance), 0) FROM accounts WHERE user_id = :u1) WHERE id = :u2")
        ->execute([':u1' => $userId, ':u2' => $userId]);

    log_security_event($userId, 'ACCOUNT_OPENED', 'SUCCESS', "Opened new $type account $accountNumber (ID #$newAccId)", 'medium');

    http_response_code(201);
    echo json_encode([
        'status'         => 'success',
        'message'        => "New $type account opened successfully.",
        'account_id'     => $newAccId,
        'account_number' => $accountNumber,
        'type'           => $type,
        'nickname'       => $nickname,
        'interest_rate'  => $interestRate,
        'balance'        => $initialDeposit
    ]);

} catch (Throwable $e) {
    error_log("Open Account API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to create new account.']);
}
