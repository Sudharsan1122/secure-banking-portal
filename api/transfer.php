<?php
/**
 * Fund Transfer API Endpoint
 * 
 * MODULE 4: MONEY TRANSFER & CONCURRENCY CONTROL
 * MODULE 5: XSS INJECTION DEMONSTRATION & DETECTION
 * MODULE 6: CSRF VALIDATION
 * MODULE 8: SQL INJECTION DEFENSE (PREPARED STATEMENTS)
 * 
 * SECURITY EXECUTION PIPELINE (STRICT ORDER):
 * 1. Session Authentication Check (require_auth)
 * 2. CSRF Token Validation (require_csrf_token - HTTP 403 on mismatch)
 * 3. Input Validation (beneficiary_id or account_number, amount > 0, remark inspection)
 * 4. Begin MySQL ACID Transaction (beginTransaction)
 * 5. Pessimistic Row Locking (SELECT ... FOR UPDATE on sender account)
 * 6. Business Logic Validation (Ensure sender balance >= amount)
 * 7. Atomically Debit Sender and Credit Receiver
 * 8. Record Transaction Log in transactions table
 * 9. Commit Database Transaction
 * 10. Log SIEM Audit Event to security_logs
 * 11. Return JSON Response with new balance and transaction ID
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../security/rate_limit.php';
require_once __DIR__ . '/../security/transfer_service.php';
require_once __DIR__ . '/../config/database.php';

// Pillar A [A10]: Method Enforcement
require_method('POST');

// Pillar A [A9]: Parameter Pollution Guard
guard_parameter_pollution();

// Pillar A [A3]: Enforce Sliding-Window Rate Limit (10 transfers / minute)
enforce_endpoint_rate_limit('/api/transfer.php');

// 1. Session Authentication Check
$currentUser = require_auth();
$senderId = $currentUser['id'];

// Parse input
$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true) ?: $_POST;

$transferParams = [
    'sender_id'       => $senderId,
    'from_account_id' => isset($input['from_account_id']) ? (int)$input['from_account_id'] : null,
    'beneficiary_id'  => isset($input['beneficiary_id']) ? (int)$input['beneficiary_id'] : null,
    'target_account'  => $input['account_number'] ?? '',
    'amount'          => $input['amount'] ?? 0,
    'remark'          => $input['remark'] ?? 'Transfer',
    'category'        => $input['category'] ?? 'Transfer'
];

$result = transfer_funds($transferParams, 'user');

http_response_code($result['code'] ?? 200);
echo json_encode($result);
exit;
