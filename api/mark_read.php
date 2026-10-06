<?php
/**
 * Mark Notification As Read API Endpoint
 * 
 * PILLAR B [B7]: NOTIFICATION CENTER
 * 
 * Enforces:
 * 1. Authentication & CSRF token check.
 * 2. IDOR Prevention: User can only mark their own notifications as read.
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

$notifId = $input['id'] ?? null;
$markAll = !empty($input['all']) || $notifId === 'all';

try {
    $pdo = get_db();

    if ($markAll) {
        $stmt = $pdo->prepare("UPDATE notifications SET read_at = NOW() WHERE user_id = :uid AND read_at IS NULL");
        $stmt->execute([':uid' => $userId]);
        $affected = $stmt->rowCount();

        echo json_encode([
            'status'   => 'success',
            'message'  => "All unread notifications marked as read.",
            'affected' => $affected
        ]);
        exit;
    }

    $id = (int)$notifId;
    if ($id <= 0) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Valid notification ID or all=true required.']);
        exit;
    }

    // IDOR Check: Ensure notification belongs to user
    $checkStmt = $pdo->prepare("SELECT id FROM notifications WHERE id = :id AND user_id = :uid LIMIT 1");
    $checkStmt->execute([':id' => $id, ':uid' => $userId]);
    if (!$checkStmt->fetch()) {
        log_security_event($userId, 'ACCESS_VIOLATION', 'BLOCKED', "IDOR attempt on notification ID $id", 'high');
        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => 'Access Denied: Notification not found in your account.']);
        exit;
    }

    $pdo->prepare("UPDATE notifications SET read_at = NOW() WHERE id = :id")->execute([':id' => $id]);

    echo json_encode([
        'status'  => 'success',
        'message' => 'Notification marked as read.',
        'id'      => $id
    ]);

} catch (Throwable $e) {
    error_log("Mark Read API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to update notification status.']);
}
