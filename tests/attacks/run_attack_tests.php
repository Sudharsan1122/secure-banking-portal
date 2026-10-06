<?php
/**
 * Master Attack & Vulnerability Regression Test Runner
 * 
 * Runs all 12 Web Application Vulnerability Mitigation Regression Suites:
 * - 01: SQL Injection (Login)
 * - 02: SQL Injection (Search)
 * - 03: Stored XSS
 * - 04: Reflected XSS
 * - 05: IDOR (Account Access)
 * - 06: IDOR (Transaction Details)
 * - 07: CSRF
 * - 08: Clickjacking
 * - 09: DOM XSS
 * - 10: Path Traversal
 * - 11: Broken Access Control (BAC)
 * - 12: Malicious File Upload
 */

$startTime = microtime(true);

$suites = [
    '01. SQLi Login Bypass'        => __DIR__ . '/test_01_sqli_login.php',
    '02. SQLi Transaction Search'  => __DIR__ . '/test_02_sqli_search.php',
    '03. Stored XSS in Remarks'    => __DIR__ . '/test_03_stored_xss.php',
    '04. Reflected XSS in Query'   => __DIR__ . '/test_04_reflected_xss.php',
    '05. IDOR Account Access'      => __DIR__ . '/test_05_idor_account.php',
    '06. IDOR Transaction Details' => __DIR__ . '/test_06_idor_transaction.php',
    '07. Cross-Site Request Forgery' => __DIR__ . '/test_07_csrf.php',
    '08. Clickjacking Defense'     => __DIR__ . '/test_08_clickjacking.php',
    '09. DOM-Based XSS'            => __DIR__ . '/test_09_dom_xss.php',
    '10. Directory Path Traversal' => __DIR__ . '/test_10_path_traversal.php',
    '11. Broken Access Control'    => __DIR__ . '/test_11_bac.php',
    '12. Malicious File Upload'    => __DIR__ . '/test_12_file_upload.php',
];

echo "================================================================================\n";
echo " SECURE BANKING PORTAL — 12 VULNERABILITY MITIGATION REGRESSION SUITE\n";
echo "================================================================================\n\n";

$totalTests = 0;
$totalPassed = 0;
$totalFailed = 0;
$suiteResults = [];

foreach ($suites as $name => $file) {
    if (!file_exists($file)) {
        echo "[ERROR] Missing test suite file: $file\n";
        continue;
    }

    require_once $file;

    // Determine function name
    $func = 'test_' . str_replace('.php', '', basename($file));
    $func = str_replace('test_test_', 'test_', $func);

    echo "[SUITE] $name\n";
    echo str_repeat('-', 80) . "\n";

    if (!function_exists($func)) {
        echo "  [ERROR] Function $func() not found in $file\n\n";
        continue;
    }

    $tests = $func();
    $suitePassed = 0;
    $suiteFailed = 0;

    foreach ($tests as $t) {
        $totalTests++;
        $status = $t['pass'] ? 'PASS' : 'FAIL';
        if ($t['pass']) {
            $totalPassed++;
            $suitePassed++;
        } else {
            $totalFailed++;
            $suiteFailed++;
        }

        printf("  [%s] %s\n         %s\n", $status, $t['name'], $t['detail']);
    }

    $suiteResults[$name] = [
        'total'  => count($tests),
        'passed' => $suitePassed,
        'failed' => $suiteFailed,
        'status' => ($suiteFailed === 0) ? 'PASS' : 'FAIL'
    ];

    echo "\n";
}

$elapsed = round(microtime(true) - $startTime, 3);

echo "================================================================================\n";
echo " 12 VULNERABILITIES DEFENSE VERIFICATION SUMMARY\n";
echo "================================================================================\n";
printf(" %-36s | %-6s | %-6s | %-6s\n", "Attack Mitigation Suite", "Total", "Pass", "Status");
echo str_repeat('-', 80) . "\n";

foreach ($suiteResults as $name => $r) {
    printf(" %-36s | %-6d | %-6d | %-6s\n", $name, $r['total'], $r['passed'], $r['status']);
}

echo "================================================================================\n";
printf(" FINAL RESULTS: Total Tests: %d | Passed: %d | Failed: %d\n", $totalTests, $totalPassed, $totalFailed);
$successRate = ($totalTests > 0) ? round(($totalPassed / $totalTests) * 100, 1) : 0;
printf(" Defense Success Rate: %s%% | Execution Time: %ss\n", $successRate, $elapsed);
echo "================================================================================\n";

exit($totalFailed === 0 ? 0 : 1);
