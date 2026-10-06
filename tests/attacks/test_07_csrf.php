<?php
/**
 * Regression Test: 07 - Cross-Site Request Forgery (CSRF) on Money Transfer
 * 
 * OWASP: A01:2021 – Broken Access Control
 * CWE: CWE-352 (Cross-Site Request Forgery)
 */

require_once __DIR__ . '/../../security/csrf.php';

function test_07_csrf(): array {
    $tests = [];

    // Test 1: Rejection of Missing CSRF Token
    $missingValidation = validate_csrf_token(null);
    $tests[] = [
        'name'   => 'Rejection of Missing CSRF Token on State-Changing Action',
        'pass'   => ($missingValidation === false),
        'detail' => 'Null/absent token safely rejected'
    ];

    // Test 2: Rejection of Blank / Empty Token
    $emptyValidation = validate_csrf_token('');
    $tests[] = [
        'name'   => 'Rejection of Empty String CSRF Token',
        'pass'   => ($emptyValidation === false),
        'detail' => 'Empty token safely rejected'
    ];

    // Test 3: Rejection of Attacker-Forged 64-char Hex Token
    $forgedToken = bin2hex(random_bytes(32));
    $forgedValidation = validate_csrf_token($forgedToken);
    $tests[] = [
        'name'   => 'Rejection of Externally Forged / Cross-Origin CSRF Token',
        'pass'   => ($forgedValidation === false),
        'detail' => 'CSPRNG forged token failed validation'
    ];

    // Test 4: Genuine Token Match using Timing-Safe Verification
    $validToken = generate_csrf_token();
    $validMatch = validate_csrf_token($validToken);
    $tests[] = [
        'name'   => 'Timing-Safe Verification of Legitimate Session-Bound CSRF Token',
        'pass'   => ($validMatch === true),
        'detail' => 'hash_equals validated legitimate synchronizer token'
    ];

    // Test 5: Verify Token Length & Entropy
    $tests[] = [
        'name'   => 'CSPRNG Entropy Assessment (256-bit / 64 Hex Characters)',
        'pass'   => (strlen($validToken) === 64 && ctype_xdigit($validToken)),
        'detail' => "Token length: " . strlen($validToken) . " hex characters"
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running 07-CSRF Tests...\n";
    $allPass = true;
    foreach (test_07_csrf() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
        if (!$t['pass']) $allPass = false;
    }
    exit($allPass ? 0 : 1);
}
