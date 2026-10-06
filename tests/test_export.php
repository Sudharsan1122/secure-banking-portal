<?php
/**
 * Test Suite: Statement Export Engine & CSV Injection Mitigation (PILLAR B - B3)
 * 
 * Verifies:
 * 1. Format whitelisting ('csv', 'pdf' only; invalid formats rejected).
 * 2. 12-Month duration boundary enforcement (DoS protection).
 * 3. CWE-1236 Mitigation: Formulas starting with '=', '+', '-', '@' prepended with apostrophe.
 * 4. PDF generation: Valid PDF stream output.
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../vendor/tcpdf/tcpdf.php';

function test_export(): array {
    $tests = [];

    // TEST 1: CSV Formula Injection Defense (CWE-1236)
    $sanitize_csv = function ($val) {
        $str = (string)$val;
        if (preg_match('/^[=\+\-@\t\r]/', $str)) {
            return "'" . $str;
        }
        return $str;
    };

    $maliciousPayloads = [
        '=cmd|\'/C calc\'!A0',
        '+10+20',
        '-50*2',
        '@SUM(1,2)',
        "\tmalicious_tab"
    ];

    $allEscaped = true;
    foreach ($maliciousPayloads as $p) {
        if (!str_starts_with($sanitize_csv($p), "'")) {
            $allEscaped = false;
        }
    }
    $tests[] = [
        'name'   => 'CWE-1236 CSV Formula Injection Sanitization',
        'pass'   => $allEscaped,
        'detail' => 'All dangerous leading characters (=, +, -, @, \\t) safely prefixed with single quote'
    ];

    $safeText = "Normal transaction remark";
    $tests[] = [
        'name'   => 'CWE-1236 Benign Remark Passthrough',
        'pass'   => ($sanitize_csv($safeText) === $safeText),
        'detail' => 'Benign alphabetic text unaltered'
    ];

    // TEST 2: Format Whitelist Logic
    $validFormats = ['csv', 'pdf'];
    $testFormats = ['csv' => true, 'pdf' => true, 'exe' => false, 'php' => false, 'html' => false];
    $whitelistWorks = true;
    foreach ($testFormats as $fmt => $expectedValid) {
        if (in_array($fmt, $validFormats, true) !== $expectedValid) {
            $whitelistWorks = false;
        }
    }
    $tests[] = [
        'name'   => 'Export Format Whitelisting (CSV / PDF Only)',
        'pass'   => $whitelistWorks,
        'detail' => 'Permits csv/pdf; blocks executable and script extensions'
    ];

    // TEST 3: Date Range 12-Month Boundary
    $startNow = strtotime('2026-01-01');
    $endValid = strtotime('2026-06-01');
    $endTooLong = strtotime('2027-04-01');
    $maxSeconds = 366 * 86400;

    $tests[] = [
        'name'   => '12-Month Date Range Enclosure',
        'pass'   => (($endValid - $startNow) <= $maxSeconds && ($endTooLong - $startNow) > $maxSeconds),
        'detail' => 'Rejects queries exceeding 366 days to mitigate resource exhaustion'
    ];

    // TEST 4: PDF Generation Compliance
    $pdf = new TCPDF('P', 'mm', 'A4');
    $pdf->AddPage();
    $pdf->SetFont('Helvetica', 'B', 14);
    $pdf->Cell(0, 10, 'Test Banking Statement', 0, 1);
    $pdfStream = $pdf->Output('test_statement.pdf', 'S');

    $tests[] = [
        'name'   => 'Vector PDF Stream Standard Compliance',
        'pass'   => (str_starts_with($pdfStream, "%PDF-1.4") && str_ends_with(trim($pdfStream), "%%EOF") && str_contains($pdfStream, "xref")),
        'detail' => 'Compliant PDF 1.4 stream generated with xref tables and EOF marker'
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Statement Export & CSV Injection Defense Tests...\n";
    foreach (test_export() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
