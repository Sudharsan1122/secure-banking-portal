<?php
/**
 * Admin Force Password Reset API Endpoint
 * 
 * PILLAR B [B9]: ADMIN USER MANAGEMENT
 * 
 * Security Controls:
 * 1. RBAC: Strict require_admin() verification.
 * 2. CSRF Token required.
 * 3. Role Hierarchy: Cannot force reset equal/higher privileged accounts without superadmin role.
 * 4. Cryptographic Reset Token: 256-bit CSPRNG token, SHA-256 hashed before persistence.
 * 5. High-Severity Audit Log & In-portal Notification.
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

if ($targetUserId <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Valid target user ID is required.']);
    exit;
}

try {
    $pdo = get_db();

    // 1. Fetch Target User
    $stmt = $pdo->prepare("SELECT id, username, name, role, email FROM users WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => $targetUserId]);
    $target = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$target) {
        http_response_code(404);
        echo json_encode(['status' => 'error', 'message' => 'Target user record not found.']);
        exit;
    }

    // 2. Role Hierarchy Guard
    if (($target['role'] === 'admin' || $target['role'] === 'superadmin') && $adminRole !== 'superadmin' && $targetUserId !== $adminId) {
        log_security_event($adminId, 'ACCESS_VIOLATION', 'BLOCKED', "Admin $adminId attempted unauthorized password reset on admin {$target['username']}", 'high');
        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => 'Access Denied: Only super-administrators can force password reset on administrative accounts.']);
        exit;
    }

    // 3. Invalidate prior active tokens
    $pdo->prepare("UPDATE password_resets SET used = 1 WHERE user_id = :uid AND used = 0")
        ->execute([':uid' => $targetUserId]);

    // 4. Generate 256-bit CSPRNG Token and store SHA-256 hash
    $rawToken = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $rawToken);

    $insertStmt = $pdo->prepare(
        "INSERT INTO password_resets (user_id, token_hash, expires_at, used, created_at)
         VALUES (:uid, :hash, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0, NOW())"
    );
    $insertStmt->execute([
        ':uid'  => $targetUserId,
        ':hash' => $tokenHash
    ]);

    log_security_event(
        $adminId,
        'ADMIN_FORCE_PASSWORD_RESET',
        'SUCCESS',
        "Admin '{$admin['username']}' forced password reset for user #$targetUserId ({$target['username']})",
        'high'
    );

    // Notify user
    notify_user(
        $targetUserId,
        'PASSWORD_RESET_REQUIRED',
        'Administrative Password Reset Initiated',
        'An administrator has generated a mandatory password reset for your account. Please follow the instructions to set a new password.',
        '/frontend/reset_password.html?token=' . $rawToken,
        'warning'
    );

    echo json_encode([
        'status'      => 'success',
        'message'     => "Password reset initiated for user '{$target['username']}'.",
        'user_id'     => $targetUserId,
        'reset_token' => $rawToken,
        'reset_url'   => "/frontend/reset_password.html?token=" . $rawToken
    ]);

} catch (Throwable $e) {
    error_log("Force Reset API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to initiate forced password reset.']);
}
