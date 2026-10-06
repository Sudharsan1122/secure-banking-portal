<?php
/**
 * Regression Test: 04 - Reflected XSS via Search Query Parameter
 * 
 * OWASP: A03:2021 – Injection
 * CWE: CWE-79 (Cross-Site Scripting)
 */

require_once __DIR__ . '/../../security/validation.php';

function test_04_reflected_xss(): array {
    $tests = [];

    // Test 1: Reflected Query In SVG / Animate Payload
    $payload1 = "<svg/onload=alert('REFLECTED_XSS')>";
    $detected1 = detect_xss($payload1);
    $tests[] = [
        'name'   => 'SVG/Onload Vector Detection in Search Query Parameter',
        'pass'   => ($detected1 === true),
        'detail' => "SVG vector detected = " . ($detected1 ? 'YES' : 'NO')
    ];

    // Test 2: Javascript URI Scheme Payload
    $payload2 = "javascript:alert(document.domain)";
    $detected2 = detect_xss($payload2);
    $tests[] = [
        'name'   => 'Pseudo-Protocol Javascript URI Vector Detection',
        'pass'   => ($detected2 === true),
        'detail' => "javascript: URI detected = " . ($detected2 ? 'YES' : 'NO')
    ];

    // Test 3: Safe Echo Rendering in Search Form Value Attribute
    // Simulating: input name="q" value="safe_html($searchQuery)"
    $inputVal = 'test" autofocus onfocus="alert(1)';
    $renderedVal = safe_html($inputVal);
    $escapedQuotes = str_contains($renderedVal, '&quot;');
    $tests[] = [
        'name'   => 'Input Value Attribute Quoting & Event Handler Defusal',
        'pass'   => $escapedQuotes,
        'detail' => "Rendered attribute value: " . $renderedVal
    ];

    // Test 4: Canonicalization Before Filtering
    // URL-encoded or mixed-case payloads
    $mixedPayload = "%3Cscript%3Ealert(1)%3C/script%3E";
    $decoded = urldecode($mixedPayload);
    $canonical = canonicalize_input($decoded);
    $detectedCanonical = detect_xss($canonical);
    $tests[] = [
        'name'   => 'Recursive URL-Decoded Canonicalization Prior to XSS Analysis',
        'pass'   => ($detectedCanonical === true),
        'detail' => "Decoded '$canonical' caught by XSS filter"
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running 04-Reflected-XSS Tests...\n";
    $allPass = true;
    foreach (test_04_reflected_xss() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
        if (!$t['pass']) $allPass = false;
    }
    exit($allPass ? 0 : 1);
}
