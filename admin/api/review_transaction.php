<?php
/**
 * Admin Transaction Review & Adjudication API Endpoint
 * 
 * PILLAR B [B10]: TRANSACTION REVIEW TRIAGE
 * 
 * Security Controls:
 * 1. RBAC: require_admin() enforcement.
 * 2. CSRF Token verified.
 * 3. Outcome whitelist: 'cleared' | 'escalated'.
 * 4. SIEM Audit Logging.
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../../security/security_headers.php';
require_once __DIR__ . '/../../security/auth.php';
require_once __DIR__ . '/../../security/csrf.php';
require_once __DIR__ . '/../../security/validation.php';
require_once __DIR__ . '/../../security/logger.php';
require_once __DIR__ . '/../../config/database.php';

require_method('POST');
guard_parameter_pollution();

$admin = require_admin();
$adminId = (int)$admin['id'];

require_csrf_token();

$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true) ?: $_POST;

$reviewId = (int)($input['review_id'] ?? 0);
$outcome  = strtolower(trim($input['outcome'] ?? ''));
$notes    = canonicalize_input(trim($input['notes'] ?? 'Reviewed by SOC Administrator.'));

if ($reviewId <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Valid review ID is required.']);
    exit;
}

if (!in_array($outcome, ['cleared', 'escalated'], true)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => "Invalid outcome. Allowed values: 'cleared', 'escalated'."]);
    exit;
}

try {
    $pdo = get_db();

    $stmtCheck = $pdo->prepare("SELECT id, transaction_id, outcome FROM transaction_reviews WHERE id = :id LIMIT 1");
    $stmtCheck->execute([':id' => $reviewId]);
    $review = $stmtCheck->fetch(PDO::FETCH_ASSOC);

    if (!$review) {
        http_response_code(404);
        echo json_encode(['status' => 'error', 'message' => 'Transaction review case not found.']);
        exit;
    }

    $stmtUpdate = $pdo->prepare(
        "UPDATE transaction_reviews 
         SET reviewed_by = :admin_id,
             reviewed_at = NOW(),
             outcome     = :outcome,
             notes       = :notes
         WHERE id = :id"
    );
    $stmtUpdate->execute([
        ':admin_id' => $adminId,
        ':outcome'  => $outcome,
        ':notes'    => $notes,
        ':id'       => $reviewId
    ]);

    log_security_event(
        $adminId,
        'TRANSACTION_REVIEW_COMPLETED',
        'SUCCESS',
        "Admin '{$admin['username']}' marked review #$reviewId (Txn #{$review['transaction_id']}) as '$outcome'",
        $outcome === 'escalated' ? 'high' : 'low'
    );

    echo json_encode([
        'status'         => 'success',
        'message'        => "Transaction review case #$reviewId marked as '$outcome'.",
        'review_id'      => $reviewId,
        'transaction_id' => (int)$review['transaction_id'],
        'outcome'        => $outcome
    ]);

} catch (Throwable $e) {
    error_log("Transaction Review Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to adjudicate transaction review case.']);
}
