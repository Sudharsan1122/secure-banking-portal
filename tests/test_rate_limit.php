<?php
/**
 * Test Suite: Sliding-Window Rate Limiting & Exponential Account Lockout
 * 
 * Verifies:
 * 1. Sliding window increments attempts per IP/endpoint.
 * 2. Rate limit threshold rejection with Retry-After calculation.
 * 3. Tier 1 exponential lockout (5 failed logins -> 5 min lock).
 * 4. Tier 2 exponential lockout (10 failed logins -> 30 min lock).
 * 5. Tier 3 exponential lockout (15 failed logins -> permanent admin lock).
 * 6. Admin manual unlock functionality.
 */

require_once __DIR__ . '/../security/rate_limit.php';
require_once __DIR__ . '/../config/database.php';

function test_rate_limit(): array {
    $tests = [];
    $testIp = '198.51.100.' . random_int(1, 250); // Safe dummy RFC 5737 test IP

    // Test 1: Sliding Window Initial Requests Allowed
    $r1 = check_endpoint_rate_limit('/api/transfer.php', $testIp);
    $tests[] = [
        'name'   => 'Sliding-Window Initial Request Allowed',
        'pass'   => ($r1['allowed'] === true && $r1['attempts'] === 1),
        'detail' => "Attempt 1/10 allowed on /api/transfer.php"
    ];

    // Test 2: Trigger Endpoint Rate Limit (10 per min on transfer)
    for ($i = 0; $i < 11; $i++) {
        $lastRes = check_endpoint_rate_limit('/api/transfer.php', $testIp);
    }
    $tests[] = [
        'name'   => 'Rate Limit Throttling Triggered with Retry-After Header',
        'pass'   => ($lastRes['allowed'] === false && $lastRes['retry_after'] > 0),
        'detail' => "Blocked with Retry-After: {$lastRes['retry_after']}s"
    ];

    // Test 3: Account Lockout Tier 1 (5 failed attempts -> 5 min lock)
    // Create a temporary test user to test lockouts without affecting demo accounts
    $pdo = get_db();
    $testUser = 'test_lockout_' . bin2hex(random_bytes(3));
    $pdo->prepare("INSERT INTO users (name, email, phone, username, password_hash, created_at) VALUES ('Test User', :e, '555', :u, 'hash', NOW())")
        ->execute([':e' => "$testUser@example.com", ':u' => $testUser]);
    $userId = (int)$pdo->lastInsertId();

    for ($i = 1; $i <= 5; $i++) {
        $resTier1 = record_failed_login_attempt($userId, $testUser);
    }
    $lockTier1 = check_account_lockout($userId);

    $tests[] = [
        'name'   => 'Exponential Lockout Tier 1 (5 Failed Logins -> 5 Minute Cooldown)',
        'pass'   => ($lockTier1 !== null && $lockTier1['failed_count'] === 5 && $lockTier1['seconds_remaining'] <= 300),
        'detail' => "Lock active for {$lockTier1['seconds_remaining']}s ({$lockTier1['lock_reason']})"
    ];

    // Test 4: Account Lockout Tier 2 (10 failed attempts -> 30 min lock)
    for ($i = 6; $i <= 10; $i++) {
        $resTier2 = record_failed_login_attempt($userId, $testUser);
    }
    $lockTier2 = check_account_lockout($userId);

    $tests[] = [
        'name'   => 'Exponential Lockout Tier 2 (10 Failed Logins -> 30 Minute Lockout)',
        'pass'   => ($lockTier2 !== null && $lockTier2['failed_count'] === 10 && $lockTier2['seconds_remaining'] > 300),
        'detail' => "Lock active for {$lockTier2['seconds_remaining']}s"
    ];

    // Test 5: Account Lockout Tier 3 (15 failed attempts -> Permanent Admin Lock)
    for ($i = 11; $i <= 15; $i++) {
        $resTier3 = record_failed_login_attempt($userId, $testUser);
    }
    $lockTier3 = check_account_lockout($userId);

    $tests[] = [
        'name'   => 'Exponential Lockout Tier 3 (15 Failed Logins -> Permanent Admin Lock)',
        'pass'   => ($lockTier3 !== null && $lockTier3['is_permanent'] === true),
        'detail' => "Permanent lockout enforced: {$lockTier3['lock_reason']}"
    ];

    // Test 6: Admin Manual Account Unlock
    $unlocked = admin_unlock_account(1, $userId); // admin user id 1 unlocks
    $lockAfterUnlock = check_account_lockout($userId);

    $tests[] = [
        'name'   => 'Administrator Account Unlock Functionality',
        'pass'   => ($unlocked === true && $lockAfterUnlock === null),
        'detail' => 'Lock cleared and failed login counter reset to 0'
    ];

    // Clean up temporary test user
    $pdo->prepare("DELETE FROM users WHERE id = :id")->execute([':id' => $userId]);

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Rate Limiting & Account Lockout Tests...\n";
    foreach (test_rate_limit() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
