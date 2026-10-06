<?php
/**
 * Create Scheduled / Recurring Transfer API Endpoint
 * 
 * PILLAR B [B2]: SCHEDULED / RECURRING TRANSFERS
 * 
 * Security Controls:
 * 1. Authentication & CSRF token required.
 * 2. Beneficiary 2-Step verification verified check (transfers only allowed to verified payees).
 * 3. Source account IDOR ownership verification.
 * 4. Frequency enum whitelisting (daily, weekly, monthly).
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
$userId = (int)$currentUser['id'];

require_csrf_token();

$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true) ?: $_POST;

$fromAccountId   = (int)($input['from_account_id'] ?? 0);
$toBeneficiaryId = (int)($input['to_beneficiary_id'] ?? 0);
$amountInput     = $input['amount'] ?? 0;
$frequency       = strtolower(trim($input['frequency'] ?? 'monthly'));
$startDateInput  = trim($input['start_date'] ?? date('Y-m-d'));
$remark          = canonicalize_input(trim($input['remark'] ?? 'Recurring Transfer'));
$category        = canonicalize_input(trim($input['category'] ?? 'Transfer'));

// 1. Validate Amount
$amount = validate_amount($amountInput);
if ($amount === null || $amount <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Transfer amount must be a positive number greater than $0.00.']);
    exit;
}

// 2. Validate Frequency
$validFrequencies = ['daily', 'weekly', 'monthly'];
if (!in_array($frequency, $validFrequencies, true)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => "Invalid frequency. Allowed: 'daily', 'weekly', 'monthly'."]);
    exit;
}

// 3. Validate Start Date
$startTime = strtotime($startDateInput);
if (!$startTime) {
    $nextRunAt = date('Y-m-d H:i:s');
} else {
    $nextRunAt = date('Y-m-d 09:00:00', $startTime);
}

detect_xss_payload($remark, $userId);
detect_sqli_payload($remark, $userId);

try {
    $pdo = get_db();

    // 4. Verify Source Account Ownership
    if ($fromAccountId <= 0) {
        $stmtDefAcc = $pdo->prepare("SELECT id FROM accounts WHERE user_id = :uid ORDER BY id ASC LIMIT 1");
        $stmtDefAcc->execute([':uid' => $userId]);
        $fromAccountId = (int)$stmtDefAcc->fetchColumn();
    } else {
        $stmtCheckAcc = $pdo->prepare("SELECT id FROM accounts WHERE id = :id AND user_id = :uid LIMIT 1");
        $stmtCheckAcc->execute([':id' => $fromAccountId, ':uid' => $userId]);
        if (!$stmtCheckAcc->fetch()) {
            http_response_code(403);
            echo json_encode(['status' => 'error', 'message' => 'Access Denied: You do not own the selected source account.']);
            exit;
        }
    }

    // 5. Verify Beneficiary Ownership & 2-Step Verification Status
    $stmtBen = $pdo->prepare("SELECT id, name, account_number, verified FROM beneficiaries WHERE id = :id AND user_id = :uid LIMIT 1");
    $stmtBen->execute([':id' => $toBeneficiaryId, ':uid' => $userId]);
    $beneficiary = $stmtBen->fetch(PDO::FETCH_ASSOC);

    if (!$beneficiary) {
        http_response_code(404);
        echo json_encode(['status' => 'error', 'message' => 'Beneficiary payee not found in your account.']);
        exit;
    }

    if (empty($beneficiary['verified'])) {
        http_response_code(403);
        echo json_encode([
            'status'  => 'error', 
            'message' => 'Selected beneficiary has not completed 2-step verification. Please verify the payee before scheduling transfers.'
        ]);
        exit;
    }

    // 6. Insert Scheduled Transfer Record
    $stmtInsert = $pdo->prepare(
        "INSERT INTO scheduled_transfers (user_id, from_account_id, to_beneficiary_id, amount, remark, category, frequency, next_run_at, status, created_at)
         VALUES (:uid, :from_acc, :to_ben, :amount, :remark, :category, :freq, :next_run, 'active', NOW())"
    );
    $stmtInsert->execute([
        ':uid'      => $userId,
        ':from_acc' => $fromAccountId,
        ':to_ben'   => $toBeneficiaryId,
        ':amount'   => $amount,
        ':remark'   => $remark,
        ':category' => $category,
        ':freq'     => $frequency,
        ':next_run' => $nextRunAt
    ]);

    $schedId = (int)$pdo->lastInsertId();

    log_security_event(
        $userId, 
        'SCHEDULED_TRANSFER_CREATED', 
        'SUCCESS', 
        "Created $frequency scheduled transfer #$schedId of \$$amount to {$beneficiary['name']}", 
        'low'
    );

    http_response_code(201);
    echo json_encode([
        'status'         => 'success',
        'message'        => ucfirst($frequency) . " scheduled transfer created successfully.",
        'schedule_id'    => $schedId,
        'frequency'      => $frequency,
        'amount'         => $amount,
        'next_run_at'    => $nextRunAt,
        'payee'          => safe_html($beneficiary['name'])
    ]);

} catch (Throwable $e) {
    error_log("Schedule Transfer API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to create scheduled transfer.']);
}
