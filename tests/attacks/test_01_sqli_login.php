<?php
/**
 * Regression Test: 01 - SQL Injection on Login (Authentication Bypass)
 * 
 * OWASP: A03:2021 – Injection
 * CWE: CWE-89 (SQL Injection)
 */

require_once __DIR__ . '/../../security/validation.php';
require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../security/auth.php';

function test_01_sqli_login(): array {
    $tests = [];
    $pdo = get_db();

    // Test 1: Injection detector catches classic auth bypass payload
    $payload1 = "admin' OR '1'='1' -- ";
    $detected1 = detect_sqli($payload1);
    $tests[] = [
        'name'   => 'Heuristic SQLi Pattern Detection on Login Bypass Payload',
        'pass'   => ($detected1 === true),
        'detail' => "Payload '$payload1' detected = " . ($detected1 ? 'YES' : 'NO')
    ];

    // Test 2: UNION SELECT payload detection
    $payload2 = "user' UNION SELECT 1, 'admin', 'hash', 'admin' -- ";
    $detected2 = detect_sqli($payload2);
    $tests[] = [
        'name'   => 'UNION-Based SQLi Signature Detection',
        'pass'   => ($detected2 === true),
        'detail' => "UNION payload detected = " . ($detected2 ? 'YES' : 'NO')
    ];

    // Test 3: Native Prepared Statement Safety (Literal String Binding)
    $stmt = $pdo->prepare("SELECT id, username, password_hash FROM users WHERE username = :u");
    $stmt->execute([':u' => $payload1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $tests[] = [
        'name'   => 'Prepared Statement Literal Handling (Zero Row Matches for Injected Query)',
        'pass'   => ($row === false),
        'detail' => "Query returned: " . ($row === false ? 'No records (Secure)' : 'Row matched (VULNERABLE)')
    ];

    // Test 4: Password Verification With Bcrypt
    $stmt = $pdo->prepare("SELECT id, password_hash FROM users WHERE username = :u");
    $stmt->execute([':u' => 'john_doe']);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    $bypassAuth = false;
    if ($user) {
        $bypassAuth = password_verify($payload1, $user['password_hash']);
    }
    $tests[] = [
        'name'   => 'Bcrypt Work Factor Rejection of Non-Matching Injected Secret',
        'pass'   => ($bypassAuth === false),
        'detail' => "password_verify with SQLi string returned false"
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running 01-SQLi-Login Tests...\n";
    $allPass = true;
    foreach (test_01_sqli_login() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
        if (!$t['pass']) $allPass = false;
    }
    exit($allPass ? 0 : 1);
}
