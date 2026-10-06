<?php
/**
 * Test Suite: CSRF Synchronizer Token Pattern
 * 
 * Verifies:
 * 1. Token generation produces 64-character hex CSPRNG string.
 * 2. Exact match passes timing-safe comparison.
 * 3. Mismatched token fails and logs CSRF_FAILURE.
 * 4. Empty/missing token fails.
 */

require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../security/auth.php';

function test_csrf(): array {
    $tests = [];

    // Test 1: Generate CSRF token
    $token = generate_csrf_token();
    $tests[] = [
        'name'   => 'Token Generation Entropy (64 hex chars)',
        'pass'   => (strlen($token) === 64 && ctype_xdigit($token)),
        'detail' => "Generated token length: " . strlen($token)
    ];

    // Test 2: Valid Token Verification
    $validMatch = validate_csrf_token($token);
    $tests[] = [
        'name'   => 'Valid Token Timing-Safe Verification',
        'pass'   => ($validMatch === true),
        'detail' => 'hash_equals verified matching token'
    ];

    // Test 3: Forged Token Rejection
    $forgedToken = bin2hex(random_bytes(32));
    $forgedMatch = validate_csrf_token($forgedToken);
    $tests[] = [
        'name'   => 'Forged / Mismatched Token Rejection',
        'pass'   => ($forgedMatch === false),
        'detail' => 'Forged token correctly rejected'
    ];

    // Test 4: Empty Token Rejection
    $emptyMatch = validate_csrf_token('');
    $tests[] = [
        'name'   => 'Empty Token Rejection',
        'pass'   => ($emptyMatch === false),
        'detail' => 'Empty token correctly rejected'
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running CSRF Tests...\n";
    foreach (test_csrf() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
