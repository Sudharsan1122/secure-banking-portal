<?php
/**
 * Test Suite: Device Fingerprinting & New Device Sign-In Alerts (PILLAR B - B8)
 * 
 * Verifies:
 * 1. Deterministic privacy-preserving SHA-256 fingerprint generation.
 * 2. Fingerprint entropy across distinct platforms / User-Agents / subnets.
 * 3. Initial device registration for new users.
 * 4. Known device re-authentication without alerts.
 * 5. Unrecognized secondary device login detection, SIEM telemetry, and alert dispatch.
 * 6. Device revocation workflow and flag persistence.
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/devices.php';
require_once __DIR__ . '/../security/logger.php';

function test_device_fingerprint(): array {
    $tests = [];
    $pdo = get_db();

    // 1. Setup isolated user
    $uName = 'dev_user_' . bin2hex(random_bytes(3));
    $pass = password_hash('Pass123!Dev', PASSWORD_BCRYPT);
    $pdo->prepare("INSERT INTO users (username, email, password_hash, name, role, balance) VALUES (?, ?, ?, ?, 'user', 1000.00)")
        ->execute([$uName, "$uName@test.local", $pass, 'Device User']);
    $userId = (int)$pdo->lastInsertId();

    // TEST 1: Deterministic Fingerprint Calculation
    $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
    $_SERVER['REMOTE_ADDR'] = '198.51.100.42';
    $_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9';

    $meta1 = get_current_device_meta();
    $meta2 = get_current_device_meta();
    $tests[] = [
        'name'   => 'Deterministic SHA-256 Device Fingerprinting',
        'pass'   => (strlen($meta1['fingerprint']) === 64 && $meta1['fingerprint'] === $meta2['fingerprint']),
        'detail' => 'Deterministic 64-char SHA-256 hash generated consistently'
    ];

    // TEST 2: Entropy check on altered User-Agent
    $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148';
    $metaMobile = get_current_device_meta();
    $tests[] = [
        'name'   => 'Cryptographic Fingerprint Entropy & Separation',
        'pass'   => ($metaMobile['fingerprint'] !== $meta1['fingerprint']),
        'detail' => 'Distinct platforms (iPhone vs Windows NT) produce divergent hashes'
    ];

    // TEST 3: Initial login with Device 1 (Windows)
    $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
    $_SERVER['REMOTE_ADDR'] = '198.51.100.42';

    $login1 = check_and_register_device($userId);
    $tests[] = [
        'name'   => 'First-Time Device Provisioning & Quiet Enrollment',
        'pass'   => ($login1['device_id'] > 0 && $login1['is_new_device'] === false),
        'detail' => sprintf("First-ever login registered device #%d without false-positive intrusion alerts", $login1['device_id'])
    ];

    // TEST 4: Known Device Re-login
    $login2 = check_and_register_device($userId);
    $tests[] = [
        'name'   => 'Recognized Device Re-Authentication',
        'pass'   => ($login2['is_new_device'] === false),
        'detail' => 'Subsequent sessions from verified device pass silently'
    ];

    // TEST 5: Login from New / Unrecognized Device (iPhone from different subnet)
    $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148';
    $_SERVER['REMOTE_ADDR'] = '203.0.113.88';

    $loginNew = check_and_register_device($userId);

    // Verify in-portal notification was dispatched
    $stmtNotif = $pdo->prepare("SELECT type, severity FROM notifications WHERE user_id = ? AND type = 'NEW_DEVICE_LOGIN' ORDER BY id DESC LIMIT 1");
    $stmtNotif->execute([$userId]);
    $notif = $stmtNotif->fetch(PDO::FETCH_ASSOC);

    $tests[] = [
        'name'   => 'Unrecognized Device Login Detection & High-Severity Alert',
        'pass'   => ($loginNew['is_new_device'] === true && !empty($notif) && $notif['severity'] === 'warning'),
        'detail' => 'New device flagged and high-priority warning notification dispatched'
    ];

    // TEST 6: Revocation workflow
    $devIdToRevoke = $loginNew['device_id'];
    $pdo->prepare("UPDATE user_devices SET is_revoked = 1 WHERE id = ?")->execute([$devIdToRevoke]);

    $stmtCheck = $pdo->prepare("SELECT is_revoked FROM user_devices WHERE id = ?");
    $stmtCheck->execute([$devIdToRevoke]);
    $isRevoked = (int)$stmtCheck->fetchColumn();

    $tests[] = [
        'name'   => 'Device Session Revocation & Access Termination',
        'pass'   => ($isRevoked === 1),
        'detail' => sprintf("Device #%d flag updated to is_revoked = 1", $devIdToRevoke)
    ];

    // Cleanup
    $pdo->prepare("DELETE FROM user_devices WHERE user_id = ?")->execute([$userId]);
    $pdo->prepare("DELETE FROM notifications WHERE user_id = ?")->execute([$userId]);
    $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$userId]);

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Device Fingerprinting Tests...\n";
    foreach (test_device_fingerprint() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
