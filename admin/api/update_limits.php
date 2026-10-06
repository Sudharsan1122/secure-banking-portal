<?php
/**
 * Admin Velocity Limits Modification API Endpoint
 * 
 * PILLAR B [B9]: ADMIN VELOCITY LIMIT ADJUSTMENT
 * 
 * Security Controls:
 * 1. RBAC: require_admin() check.
 * 2. CSRF Token required.
 * 3. Validation: Positive decimal limits.
 * 4. SIEM Audit Logging.
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
$adminId = (int)$admin['id'];

require_csrf_token();

$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true) ?: $_POST;

$targetUserId  = (int)($input['user_id'] ?? 0);
$limitSingle   = validate_amount($input['limit_single'] ?? 0);
$limitDaily    = validate_amount($input['limit_daily'] ?? 0);
$limitMonthly  = validate_amount($input['limit_monthly'] ?? 0);

if ($targetUserId <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Valid target user ID is required.']);
    exit;
}

if ($limitSingle === null || $limitSingle <= 0 ||
    $limitDaily === null || $limitDaily <= 0 ||
    $limitMonthly === null || $limitMonthly <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'All velocity limits (Single, Daily, Monthly) must be positive values greater than $0.00.']);
    exit;
}

// Consistency check: Single <= Daily <= Monthly
if ($limitSingle > $limitDaily || $limitDaily > $limitMonthly) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Hierarchy constraint violated: Single Limit cannot exceed Daily Limit, and Daily Limit cannot exceed Monthly Limit.']);
    exit;
}

try {
    $pdo = get_db();

    // Verify target user exists
    $stmt = $pdo->prepare("SELECT id, username FROM users WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => $targetUserId]);
    $target = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$target) {
        http_response_code(404);
        echo json_encode(['status' => 'error', 'message' => 'Target user record not found.']);
        exit;
    }

    $pdo->prepare(
        "UPDATE users 
         SET limit_single = :single, limit_daily = :daily, limit_monthly = :monthly 
         WHERE id = :id"
    )->execute([
        ':single'  => $limitSingle,
        ':daily'   => $limitDaily,
        ':monthly' => $limitMonthly,
        ':id'      => $targetUserId
    ]);

    log_security_event(
        $adminId,
        'ADMIN_LIMITS_UPDATED',
        'SUCCESS',
        "Admin updated limits for user #$targetUserId: Single=\$$limitSingle, Daily=\$$limitDaily, Monthly=\$$limitMonthly",
        'medium'
    );

    notify_user(
        $targetUserId,
        'VELOCITY_LIMITS_UPDATED',
        'Transfer Velocity Limits Updated',
        sprintf("Your transfer velocity limits were updated by an administrator: Single: $%.2f | Daily: $%.2f | Monthly: $%.2f", $limitSingle, $limitDaily, $limitMonthly),
        '/frontend/profile.html',
        'info'
    );

    echo json_encode([
        'status'        => 'success',
        'message'       => 'Velocity limits updated successfully.',
        'user_id'       => $targetUserId,
        'limit_single'  => $limitSingle,
        'limit_daily'   => $limitDaily,
        'limit_monthly' => $limitMonthly
    ]);

} catch (Throwable $e) {
    error_log("Update Limits API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to update user velocity limits.']);
}
