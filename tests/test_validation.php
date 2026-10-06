<?php
/**
 * Test Suite: Input Validation, Canonicalization, and HPP Defense
 * 
 * Verifies:
 * 1. Input canonicalization (null-bytes, entity decoding, Unicode NFKC).
 * 2. HTTP Parameter Pollution detection.
 * 3. Strict allowlists for usernames, emails, and phone numbers.
 * 4. Password complexity evaluation.
 * 5. XSS and SQLi payload signature detection.
 */

require_once __DIR__ . '/../security/validation.php';

function test_validation(): array {
    $tests = [];

    // Test 1: Canonicalization strips null-bytes
    $poisoned = "admin\0.pdf";
    $cleaned = canonicalize_input($poisoned);
    $tests[] = [
        'name'   => 'Null-Byte Stripping in Canonicalization',
        'pass'   => ($cleaned === 'admin.pdf'),
        'detail' => "Input '$poisoned' -> Output '$cleaned'"
    ];

    // Test 2: HTML entity single-decode
    $encoded = "&lt;script&gt;";
    $decoded = canonicalize_input($encoded);
    $tests[] = [
        'name'   => 'HTML Entity Decoding in Canonicalization',
        'pass'   => ($decoded === '<script>'),
        'detail' => "Entity decoded to raw tag for pattern analysis"
    ];

    // Test 3: HTTP Parameter Pollution Detection
    $_SERVER['QUERY_STRING'] = 'amount=10&account=123&amount=5000';
    $hppDetected = detect_parameter_pollution();
    $tests[] = [
        'name'   => 'HTTP Parameter Pollution Detection (Duplicate Keys)',
        'pass'   => ($hppDetected === true),
        'detail' => "Detected duplicate key 'amount' in query string"
    ];

    // Test 4: Legitimate query string passes HPP check
    $_SERVER['QUERY_STRING'] = 'action=transfer&amount=10&token=abc';
    $hppClean = detect_parameter_pollution();
    $tests[] = [
        'name'   => 'Clean Query String Passes HPP Check',
        'pass'   => ($hppClean === false),
        'detail' => "Zero false positives on unique query parameters"
    ];

    // Test 5: Username Allow-list
    $validUser = validate_username('john_doe123');
    $invalidUser = validate_username('admin<script>');
    $tests[] = [
        'name'   => 'Username Allow-list Regex',
        'pass'   => ($validUser === true && $invalidUser === false),
        'detail' => "Valid: 'john_doe123' | Blocked: 'admin<script>'"
    ];

    // Test 6: Password Policy Enforcement
    $weakPass = validate_password_strength('password');
    $strongPass = validate_password_strength('SecureP@ssw0rd!');
    $tests[] = [
        'name'   => 'Password Complexity Policy (8+ chars, upper, lower, digit, symbol)',
        'pass'   => (!$weakPass['is_valid'] && $strongPass['is_valid']),
        'detail' => "Weak rejected (" . implode(', ', $weakPass['errors']) . "), Strong accepted"
    ];

    // Test 7: XSS Signature Inspection
    $xssDetected = detect_xss_payload("<img src=x onerror=alert(1)>");
    $tests[] = [
        'name'   => 'XSS Payload Signature Detection',
        'pass'   => ($xssDetected === true),
        'detail' => "Caught onerror= event handler"
    ];

    // Test 8: SQLi Signature Inspection
    $sqliDetected = detect_sqli_payload("admin' UNION SELECT 1,2,3--");
    $tests[] = [
        'name'   => 'SQL Injection Payload Signature Detection',
        'pass'   => ($sqliDetected === true),
        'detail' => "Caught UNION SELECT and comment signature"
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Validation & Canonicalization Tests...\n";
    foreach (test_validation() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
