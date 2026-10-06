<?php
/**
 * Pause / Resume / Cancel Scheduled Transfer API Endpoint
 * 
 * PILLAR B [B2]: SCHEDULED TRANSFERS MANAGEMENT
 * 
 * Enforces:
 * - Authentication & CSRF token
 * - Strict IDOR verification (transfer must belong to session user)
 * - Action whitelist ('pause', 'resume', 'cancel')
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

$schedId = (int)($input['id'] ?? 0);
$action  = strtolower(trim($input['action'] ?? 'pause'));

$validActions = ['pause', 'resume', 'cancel'];
if (!in_array($action, $validActions, true)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => "Invalid action. Supported: 'pause', 'resume', 'cancel'."]);
    exit;
}

try {
    $pdo = get_db();

    // Check ownership
    $stmt = $pdo->prepare("SELECT id, status FROM scheduled_transfers WHERE id = :id AND user_id = :uid LIMIT 1");
    $stmt->execute([':id' => $schedId, ':uid' => $userId]);
    $sched = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$sched) {
        log_security_event($userId, 'ACCESS_VIOLATION', 'BLOCKED', "IDOR attempt: User $userId tried to modify scheduled transfer ID $schedId", 'high');
        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => 'Access Denied: Scheduled transfer record not found in your account.']);
        exit;
    }

    $newStatus = match ($action) {
        'pause'  => 'paused',
        'resume' => 'active',
        'cancel' => 'cancelled'
    };

    $pdo->prepare("UPDATE scheduled_transfers SET status = :status WHERE id = :id")
        ->execute([':status' => $newStatus, ':id' => $schedId]);

    log_security_event($userId, 'SCHEDULED_TRANSFER_' . strtoupper($action), 'SUCCESS', "Scheduled transfer #$schedId updated to status '$newStatus'");

    echo json_encode([
        'status'     => 'success',
        'message'    => "Scheduled transfer successfully updated to '$newStatus'.",
        'id'         => $schedId,
        'new_status' => $newStatus
    ]);

} catch (Throwable $e) {
    error_log("Scheduled Action API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to update scheduled transfer status.']);
}
