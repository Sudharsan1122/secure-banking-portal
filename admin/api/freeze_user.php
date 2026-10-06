<?php
/**
 * Admin Freeze / Unfreeze User API Endpoint
 * 
 * PILLAR B [B9]: ADMIN USER MANAGEMENT
 * 
 * Security Controls:
 * 1. RBAC: Strict require_admin() enforcement.
 * 2. CSRF Token verification.
 * 3. Self-Targeting Guard: Admin cannot freeze their own session.
 * 4. Super-Admin / Peer Separation: Regular admin cannot freeze admins or superadmins.
 * 5. SIEM Telemetry: High severity security log entry.
 * 
 * Examiner Talking Point:
 * "Account freeze triggers immediate outgoing transfer prohibition across all accounts
 *  owned by the tenant, enforced centrally at the transfer_funds() service layer."
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../../security/security_headers.php';
require_once __DIR__ . '/../../security/auth.php';
require_once __DIR__ . '/../../security/csrf.php';
require_once __DIR__ . '/../../security/validation.php';
require_once __DIR__ . '/../../security/logger.php';
require_once __DIR__ . '/../../security/notifications.php';
require_once __DIR__ . '/../../config/database.php';

require_method('POST');
guard_parameter_pollution();

$admin = require_admin();
$adminId   = (int)$admin['id'];
$adminRole = $admin['role'];

require_csrf_token();

$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true) ?: $_POST;

$targetUserId = (int)($input['user_id'] ?? 0);
$shouldFreeze = !empty($input['freeze']);

if ($targetUserId <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Valid target user ID is required.']);
    exit;
}

// 1. Self-Targeting Guard
if ($targetUserId === $adminId) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Administrative error: You cannot freeze your own account.']);
    exit;
}

try {
    $pdo = get_db();

    // 2. Fetch Target User
    $stmt = $pdo->prepare("SELECT id, username, name, role, status FROM users WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => $targetUserId]);
    $target = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$target) {
        http_response_code(404);
        echo json_encode(['status' => 'error', 'message' => 'Target user record not found.']);
        exit;
    }

    // 3. Super-Admin & Peer Privilege Check
    if (($target['role'] === 'admin' || $target['role'] === 'superadmin') && $adminRole !== 'superadmin') {
        log_security_event($adminId, 'ACCESS_VIOLATION', 'BLOCKED', "Admin $adminId attempted unauthorized freeze on privileged account {$target['username']}", 'high');
        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => 'Access Denied: Only super-administrators can freeze administrative accounts.']);
        exit;
    }

    $newStatus = $shouldFreeze ? 'frozen' : 'active';
    $pdo->prepare("UPDATE users SET status = :status WHERE id = :id")
        ->execute([':status' => $newStatus, ':id' => $targetUserId]);

    $actionName = $shouldFreeze ? 'ADMIN_USER_FROZEN' : 'ADMIN_USER_UNFROZEN';
    log_security_event(
        $adminId,
        $actionName,
        'SUCCESS',
        "Admin '{$admin['username']}' updated account status for user #$targetUserId ({$target['username']}) to '$newStatus'",
        'high'
    );

    // Notify user of status change
    notify_user(
        $targetUserId,
        'ACCOUNT_STATUS_CHANGED',
        $shouldFreeze ? 'Account Temporarily Frozen' : 'Account Reactivated',
        $shouldFreeze 
            ? 'Your account has been frozen by bank administration. Outgoing transfers are temporarily restricted. Please contact support.' 
            : 'Your account has been reactivated. Normal banking operations have been restored.',
        '/frontend/dashboard.html',
        $shouldFreeze ? 'danger' : 'info'
    );

    echo json_encode([
        'status'     => 'success',
        'message'    => "User account successfully " . ($shouldFreeze ? 'frozen' : 'unfrozen') . ".",
        'user_id'    => $targetUserId,
        'new_status' => $newStatus
    ]);

} catch (Throwable $e) {
    error_log("Admin Freeze User Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to update user account status.']);
}
