<?php
/**
 * Master Test Runner: Secure Banking Portal Security Suite
 * 
 * Executes all automated test suites across:
 * - PILLAR A: Security Depth (A1–A13)
 * - PILLAR C: Observability & SOC (C1–C8)
 * - PILLAR B: Real-World Banking Features (B1–B10)
 */

ob_start();

require_once __DIR__ . '/../security/auth.php';
start_secure_session();

// Terminal ANSI formatting
$green  = "\033[32m";
$red    = "\033[31m";
$yellow = "\033[33m";
$cyan   = "\033[36m";
$bold   = "\033[1m";
$reset  = "\033[0m";

echo "\n" . str_repeat('=', 80) . "\n";
echo " {$bold}{$cyan}SECURE BANKING PORTAL — MASTER COMPREHENSIVE TEST RUNNER{$reset}\n";
echo " Covering: Pillar A (Security Depth), Pillar C (SOC/Observability), Pillar B (Banking)\n";
echo " Running against PHP " . PHP_VERSION . " on " . PHP_OS . "\n";
echo str_repeat('=', 80) . "\n\n";

$suites = [
    // ---------------- PILLAR A: SECURITY CONTROLS ----------------
    [
        'name' => 'Pillar A [Baseline]: CSRF Synchronizer Token Pattern',
        'file' => __DIR__ . '/test_csrf.php',
        'func' => 'test_csrf'
    ],
    [
        'name' => 'Pillar A [A9, A10, A11]: Input Canonicalization & HPP Defense',
        'file' => __DIR__ . '/test_validation.php',
        'func' => 'test_validation'
    ],
    [
        'name' => 'Pillar A [A6, A7, A13]: Dual-Tier Sessions, Fixation & 2FA Recovery',
        'file' => __DIR__ . '/test_auth.php',
        'func' => 'test_auth'
    ],
    [
        'name' => 'Pillar A [A3, A4]: Sliding-Window Rate Limit & Exponential Lockout',
        'file' => __DIR__ . '/test_rate_limit.php',
        'func' => 'test_rate_limit'
    ],
    [
        'name' => 'Pillar A [A5]: Secure Token-Based Password Reset (Hashed Tokens)',
        'file' => __DIR__ . '/test_password_reset.php',
        'func' => 'test_password_reset'
    ],
    [
        'name' => 'Pillar A [A12]: Cryptographic Audit Log Hash Chain & Tamper Detection',
        'file' => __DIR__ . '/test_hash_chain.php',
        'func' => 'test_hash_chain'
    ],
    [
        'name' => 'Pillar A [A8]: Secure Avatar Upload & File Upload Defense Pipeline',
        'file' => __DIR__ . '/test_avatar_upload.php',
        'func' => 'test_avatar_upload'
    ],

    // ---------------- PILLAR C: OBSERVABILITY & SOC ----------------
    [
        'name' => 'Pillar C [C1]: Server-Sent Events (SSE) Real-Time Security Feed',
        'file' => __DIR__ . '/test_sse.php',
        'func' => 'test_sse'
    ],
    [
        'name' => 'Pillar C [C2]: 4-Tier Threat Severity Levels & Schema Mapping',
        'file' => __DIR__ . '/test_severity.php',
        'func' => 'test_severity'
    ],
    [
        'name' => 'Pillar C [C3]: Heuristic Anomaly Detection (6 Behavioral Rules)',
        'file' => __DIR__ . '/test_anomaly.php',
        'func' => 'test_anomaly'
    ],
    [
        'name' => 'Pillar C [C4]: Dynamic User Security Posture Scoring (0-100)',
        'file' => __DIR__ . '/test_security_score.php',
        'func' => 'test_security_score'
    ],
    [
        'name' => 'Pillar C [C5]: Prometheus-Compatible Metrics Scrape Exporter',
        'file' => __DIR__ . '/test_metrics.php',
        'func' => 'test_metrics'
    ],
    [
        'name' => 'Pillar C [C6]: CSV Formula Injection Defense (CWE-1236)',
        'file' => __DIR__ . '/test_export_csv_safe.php',
        'func' => 'test_export_csv_safe'
    ],
    [
        'name' => 'Pillar C [C7]: Automated SIEM Alerting Engine & Deduplication',
        'file' => __DIR__ . '/test_alert_engine.php',
        'func' => 'test_alert_engine'
    ],
    [
        'name' => 'Pillar C [C8/A12]: Cryptographic Audit Log Chain Continuity & Health',
        'file' => __DIR__ . '/test_chain_still_valid.php',
        'func' => 'test_chain_still_valid'
    ],

    // ---------------- PILLAR B: REAL-WORLD BANKING FEATURES ----------------
    [
        'name' => 'Pillar B [B1]: Transaction Categories & Analytics Aggregation',
        'file' => __DIR__ . '/test_categories.php',
        'func' => 'test_categories'
    ],
    [
        'name' => 'Pillar B [B2]: Scheduled & Recurring Transfers Engine',
        'file' => __DIR__ . '/test_scheduled.php',
        'func' => 'test_scheduled'
    ],
    [
        'name' => 'Pillar B [B3]: Statement Export Engine (CSV/PDF) & Injection Guard',
        'file' => __DIR__ . '/test_export.php',
        'func' => 'test_export'
    ],
    [
        'name' => 'Pillar B [B4]: Beneficiary 2-Step Verification & Brute-Force Guard',
        'file' => __DIR__ . '/test_beneficiary_verify.php',
        'func' => 'test_beneficiary_verify'
    ],
    [
        'name' => 'Pillar B [B5]: Multi-Tier Transaction Velocity Limits (Single/Daily/Monthly)',
        'file' => __DIR__ . '/test_velocity_limits.php',
        'func' => 'test_velocity_limits'
    ],
    [
        'name' => 'Pillar B [B6]: Multi-Account Management & IDOR Account Isolation',
        'file' => __DIR__ . '/test_multi_account.php',
        'func' => 'test_multi_account'
    ],
    [
        'name' => 'Pillar B [B7]: In-Portal Notification Center & Tenant Isolation',
        'file' => __DIR__ . '/test_notifications.php',
        'func' => 'test_notifications'
    ],
    [
        'name' => 'Pillar B [B8]: Privacy-Preserving Device Fingerprinting & Alerts',
        'file' => __DIR__ . '/test_device_fingerprint.php',
        'func' => 'test_device_fingerprint'
    ],
    [
        'name' => 'Pillar B [B9]: Admin User Management, Account Freezing & Limit Control',
        'file' => __DIR__ . '/test_admin_users.php',
        'func' => 'test_admin_users'
    ],
    [
        'name' => 'Pillar B [B10]: Heuristic Transaction Monitoring & Triage Adjudication',
        'file' => __DIR__ . '/test_transaction_monitor.php',
        'func' => 'test_transaction_monitor'
    ],
    [
        'name' => 'Pillar F: Code Quality, Static Analysis & Defensive Standards',
        'file' => __DIR__ . '/test_code_quality.php',
        'func' => 'test_code_quality'
    ]
];

$suiteSummary = [];
$totalTests = 0;
$totalPassed = 0;
$totalFailed = 0;

$startTime = microtime(true);

foreach ($suites as $suite) {
    echo "{$bold}[SUITE]{$reset} {$suite['name']}\n";
    echo str_repeat('-', 80) . "\n";

    if (!file_exists($suite['file'])) {
        echo "  {$red}[ERROR]{$reset} Test file not found: {$suite['file']}\n\n";
        continue;
    }

    require_once $suite['file'];
    $func = $suite['func'];

    if (!function_exists($func)) {
        echo "  {$red}[ERROR]{$reset} Test function $func() not found.\n\n";
        continue;
    }

    $results = $func();
    $passed = 0;
    $failed = 0;

    foreach ($results as $r) {
        $totalTests++;
        if ($r['pass']) {
            $passed++;
            $totalPassed++;
            printf("  %s[PASS]%s %s\n", $green, $reset, $r['name']);
            if (!empty($r['detail'])) {
                printf("         %s%s%s\n", "\033[90m", $r['detail'], $reset);
            }
        } else {
            $failed++;
            $totalFailed++;
            printf("  %s[FAIL]%s %s\n", $red, $reset, $r['name']);
            if (!empty($r['detail'])) {
                printf("         %s%s%s\n", $red, $r['detail'], $reset);
            }
        }
    }

    $suiteSummary[] = [
        'name'   => $suite['name'],
        'total'  => count($results),
        'passed' => $passed,
        'failed' => $failed,
        'status' => ($failed === 0 ? "{$green}PASS{$reset}" : "{$red}FAIL{$reset}")
    ];

    echo "\n";
}

$executionTime = round((microtime(true) - $startTime), 3);

// Output Grand Summary Table
echo str_repeat('=', 80) . "\n";
echo " {$bold}SUMMARY BY TEST SUITE{$reset}\n";
echo str_repeat('-', 80) . "\n";
printf(" %-58s | %-6s | %-6s | %-6s\n", "Test Suite", "Total", "Pass", "Status");
echo str_repeat('-', 80) . "\n";

foreach ($suiteSummary as $s) {
    // Strip ansi for padding calculations
    $cleanName = preg_replace('/\033\[[0-9;]*m/', '', $s['name']);
    if (strlen($cleanName) > 56) {
        $cleanName = substr($cleanName, 0, 53) . '...';
    }
    printf(" %-58s | %-6d | %-6d | %s\n", $cleanName, $s['total'], $s['passed'], $s['status']);
}

echo str_repeat('=', 80) . "\n";
echo " {$bold}FINAL RESULTS:{$reset} Total Tests: {$totalTests} | Passed: {$green}{$totalPassed}{$reset} | Failed: " . ($totalFailed > 0 ? "{$red}{$totalFailed}{$reset}" : "0") . "\n";
echo " Success Rate: " . ($totalTests > 0 ? round(($totalPassed / $totalTests) * 100, 1) : 0) . "% | Execution Time: {$executionTime}s\n";
echo str_repeat('=', 80) . "\n\n";

// Flush buffer
ob_end_flush();

// Exit code
exit($totalFailed === 0 ? 0 : 1);
