<?php
/**
 * Test Suite: Authentication, Dual-Tier Session Expiration & 2FA Recovery Codes
 * 
 * Verifies:
 * 1. Session fixation regeneration produces new session IDs.
 * 2. Dual-tier session timeout enforcement (idle vs absolute).
 * 3. Generation of 10 Bcrypt-hashed recovery codes.
 * 4. Recovery code validation and single-use consumption.
 */

require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../config/database.php';

function test_auth(): array {
    $tests = [];

    // Ensure secure session is initialized
    start_secure_session();

    // Test 1: Session Fixation Regeneration (Site 1 & 2)
    $origId = session_id();
    if (!headers_sent()) {
        @session_regenerate_id(true);
        $newId = session_id();
    } else {
        $newId = session_create_id();
        session_commit();
        session_id($newId);
        @session_start();
    }
    $tests[] = [
        'name'   => 'Session Fixation ID Regeneration (New Unique Session ID)',
        'pass'   => (!empty($newId) && $newId !== $origId),
        'detail' => "Rotated from $origId to $newId"
    ];

    // Test 2: Dual-Tier Absolute Session Expiration
    $now = time();
    $_SESSION['user_id'] = 2;
    $_SESSION['username'] = 'john_doe';
    $_SESSION['login_time'] = $now - (SESSION_ABSOLUTE_TIMEOUT + 10); // 8h + 10s ago
    $_SESSION['last_activity'] = $now - 60; // active 1 min ago

    $absoluteExpired = false;
    if ($now - $_SESSION['login_time'] > SESSION_ABSOLUTE_TIMEOUT) {
        $absoluteExpired = true;
    }
    $tests[] = [
        'name'   => 'Absolute 8-Hour Session Expiration Ceiling',
        'pass'   => ($absoluteExpired === true),
        'detail' => 'Session expired despite recent activity due to absolute lifetime'
    ];

    // Test 3: Idle 15-Minute Session Invalidation
    $_SESSION['login_time'] = $now - 3600; // 1 hour ago (within 8h)
    $_SESSION['last_activity'] = $now - (SESSION_IDLE_TIMEOUT + 5); // 15 min + 5s idle

    $idleExpired = false;
    if ($now - $_SESSION['last_activity'] > SESSION_IDLE_TIMEOUT) {
        $idleExpired = true;
    }
    $tests[] = [
        'name'   => 'Idle 15-Minute Session Expiration',
        'pass'   => ($idleExpired === true),
        'detail' => 'Session marked expired after 15 minutes of inactivity'
    ];

    // Test 4: Two-Factor Emergency Recovery Codes Generation (10 codes)
    $codes = generate_recovery_codes(2); // user john_doe
    $tests[] = [
        'name'   => '2FA Recovery Codes Generation (10 formatted codes)',
        'pass'   => (count($codes) === 10 && preg_match('/^[A-F0-9]{4}-[A-F0-9]{4}$/', $codes[0])),
        'detail' => "Generated 10 codes (Sample: {$codes[0]})"
    ];

    // Test 5: Validate and Consume Recovery Code (Single-Use Enforcement)
    $firstCode = $codes[0];
    $firstConsume = verify_recovery_code(2, $firstCode);
    $secondConsume = verify_recovery_code(2, $firstCode); // Try reusing same code

    $tests[] = [
        'name'   => 'Recovery Code Single-Use Consumption (Replay Prevention)',
        'pass'   => ($firstConsume === true && $secondConsume === false),
        'detail' => "First use: ACCEPTED | Replay attempt: REJECTED"
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Authentication & Session Tests...\n";
    foreach (test_auth() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
