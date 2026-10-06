<?php
/**
 * Regression Test: 09 - DOM-Based XSS via Client-Side Sinks / location.hash
 * 
 * OWASP: A03:2021 – Injection
 * CWE: CWE-79 (Cross-Site Scripting - DOM Based)
 */

function test_09_dom_xss(): array {
    $tests = [];
    $jsDir = __DIR__ . '/../../js';

    $jsFiles = glob("$jsDir/*.js");
    $dangerousSinksFound = [];
    $textContentUsage = 0;

    foreach ($jsFiles as $file) {
        $content = file_get_contents($file);
        $base = basename($file);

        // Check for eval()
        if (preg_match('/\beval\s*\(/i', $content)) {
            $dangerousSinksFound[] = "$base: eval()";
        }
        // Check for document.write
        if (preg_match('/document\.write\s*\(/i', $content)) {
            $dangerousSinksFound[] = "$base: document.write()";
        }
        // Check for innerHTML receiving location.hash or search directly
        if (preg_match('/innerHTML\s*=\s*.*(?:location\.hash|location\.search|location\.href)/i', $content)) {
            $dangerousSinksFound[] = "$base: innerHTML receiving raw location source";
        }

        // Count safe DOM textContent occurrences
        $textContentUsage += substr_count($content, 'textContent');
    }

    // Test 1: Zero Dangerous Evaluation Sinks (eval, document.write)
    $tests[] = [
        'name'   => 'Zero Dangerous Dynamic Evaluation Sinks (eval, document.write) in Frontend Scripts',
        'pass'   => empty($dangerousSinksFound),
        'detail' => empty($dangerousSinksFound) ? "Audited " . count($jsFiles) . " JS files: 0 dangerous sinks" : implode(', ', $dangerousSinksFound)
    ];

    // Test 2: Safe DOM Text Content Rendering
    $tests[] = [
        'name'   => 'Widespread Utilization of textContent DOM Sinks for Data Binding',
        'pass'   => ($textContentUsage > 15),
        'detail' => "Detected $textContentUsage occurrences of element.textContent"
    ];

    // Test 3: CSP 2.0 Elimination of 'unsafe-eval'
    $headersFile = __DIR__ . '/../../security/security_headers.php';
    $headersContent = file_get_contents($headersFile);
    $hasUnsafeEval = str_contains($headersContent, "'unsafe-eval'");
    $tests[] = [
        'name'   => 'Content-Security-Policy Strict Elimination of unsafe-eval',
        'pass'   => (!$hasUnsafeEval),
        'detail' => "'unsafe-eval' omitted from CSP directive"
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running 09-DOM-XSS Tests...\n";
    $allPass = true;
    foreach (test_09_dom_xss() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
        if (!$t['pass']) $allPass = false;
    }
    exit($allPass ? 0 : 1);
}
