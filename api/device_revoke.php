<?php
/**
 * Revoke Trusted Device API Endpoint
 * 
 * PILLAR B [B8]: DEVICE REVOCATION & SESSION TERMINATION
 * 
 * Enforces:
 * 1. CSRF token check.
 * 2. Strict IDOR verification (device must belong to authenticated user).
 * 3. Immediate revocation flag persistence.
 * 4. If the revoked device is the current active device, terminates the session.
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/devices.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../config/database.php';

require_method('POST');
guard_parameter_pollution();

$currentUser = require_auth();
$userId = (int)$currentUser['id'];

require_csrf_token();

$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true) ?: $_POST;

$deviceId = (int)($input['device_id'] ?? 0);

if ($deviceId <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Valid device ID is required.']);
    exit;
}

try {
    $pdo = get_db();

    // Check ownership
    $stmt = $pdo->prepare("SELECT id, fingerprint, user_agent, last_ip, is_revoked FROM user_devices WHERE id = :id AND user_id = :uid LIMIT 1");
    $stmt->execute([':id' => $deviceId, ':uid' => $userId]);
    $device = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$device) {
        log_security_event($userId, 'ACCESS_VIOLATION', 'BLOCKED', "IDOR attempt to revoke device ID $deviceId", 'high');
        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => 'Access Denied: Device not found in your account.']);
        exit;
    }

    // Revoke device
    $pdo->prepare("UPDATE user_devices SET is_revoked = 1 WHERE id = :id")->execute([':id' => $deviceId]);

    log_security_event(
        $userId, 
        'DEVICE_REVOKED', 
        'SUCCESS', 
        "User revoked trusted device ID #$deviceId ({$device['last_ip']})", 
        'medium'
    );

    // Check if the revoked device is the current session's device
    $currentMeta = get_current_device_meta();
    $isCurrent = ($currentMeta['fingerprint'] === $device['fingerprint']);

    if ($isCurrent) {
        logout_user();
        echo json_encode([
            'status'         => 'success',
            'message'        => 'Current device revoked. Session terminated for security.',
            'logged_out'     => true,
            'redirect'       => 'login.html?msg=revoked'
        ]);
        exit;
    }

    echo json_encode([
        'status'     => 'success',
        'message'    => 'Device access revoked successfully.',
        'device_id'  => $deviceId,
        'logged_out' => false
    ]);

} catch (Throwable $e) {
    error_log("Device Revocation Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to revoke device.']);
}
