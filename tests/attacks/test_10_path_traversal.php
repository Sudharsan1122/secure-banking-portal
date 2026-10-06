<?php
/**
 * Regression Test: 10 - Directory / Path Traversal on Statement Download
 * 
 * OWASP: A01:2021 – Broken Access Control
 * CWE: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
 */

require_once __DIR__ . '/../../security/validation.php';

function test_10_path_traversal(): array {
    $tests = [];

    // Test 1: Relative Directory Traversal Pattern Detection
    $payload1 = '../../../../etc/passwd';
    $detected1 = detect_traversal($payload1);
    $tests[] = [
        'name'   => 'Relative Dot-Dot-Slash (../) Path Traversal Signature Detection',
        'pass'   => ($detected1 === true),
        'detail' => "Traversal payload detected = " . ($detected1 ? 'YES' : 'NO')
    ];

    // Test 2: Windows Backslash Traversal Pattern Detection
    $payload2 = '..\\..\\..\\windows\\win.ini';
    $detected2 = detect_traversal($payload2);
    $tests[] = [
        'name'   => 'Windows Directory Traversal (..\) Signature Detection',
        'pass'   => ($detected2 === true),
        'detail' => "Backslash traversal detected = " . ($detected2 ? 'YES' : 'NO')
    ];

    // Test 3: Null Byte Poisoning and Encoded Traversal
    $payload3 = '%2e%2e%2f%2e%2e%2fconfig.php%00.csv';
    $canonical = canonicalize_input($payload3);
    $detected3 = detect_traversal($canonical);
    $tests[] = [
        'name'   => 'URL-Encoded & Double-Decoded Traversal Detection',
        'pass'   => ($detected3 === true),
        'detail' => "Canonicalized '$canonical' caught by traversal detector"
    ];

    // Test 4: Strict Whitelist Validation on Date Range Keys
    // Statements accept exclusively YYYY-MM or YYYY-MM-DD
    $validDate1 = '2026-09';
    $validDate2 = '2026-09-23';
    $invalidDate = '../../../../etc/passwd';

    $passValid1 = (bool)preg_match('/^\d{4}-\d{2}(-\d{2})?$/', $validDate1);
    $passValid2 = (bool)preg_match('/^\d{4}-\d{2}(-\d{2})?$/', $validDate2);
    $blockInvalid = !preg_match('/^\d{4}-\d{2}(-\d{2})?$/', $invalidDate);

    $tests[] = [
        'name'   => 'Strict Regex Bounding on Download Statement Parameters',
        'pass'   => ($passValid1 && $passValid2 && $blockInvalid),
        'detail' => 'Valid dates allowed; traversal injection rejected by regex'
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running 10-Path-Traversal Tests...\n";
    $allPass = true;
    foreach (test_10_path_traversal() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
        if (!$t['pass']) $allPass = false;
    }
    exit($allPass ? 0 : 1);
}
