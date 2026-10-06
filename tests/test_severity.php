<?php
/**
 * Test Suite: 4-Tier Threat Severity Levels (Pillar C [C2])
 * 
 * Verifies:
 * 1. Critical threat event types map to 'critical' (SQLi, SSRF, Hash Tampering, Escalation).
 * 2. High severity threat event types map to 'high' (CSRF, XSS, Account Locked, Traversal).
 * 3. Medium threat event types map to 'medium' (Rate Limit Exceeded, OTP Failed, Password Changed).
 * 4. Routine application events map to 'low' (Login Success, Logout, Transfer Success).
 * 5. Unknown arbitrary event types default safely to 'low'.
 * 6. Database schema default for security_logs.severity is 'low'.
 */

require_once __DIR__ . '/../config/severity_map.php';
require_once __DIR__ . '/../config/database.php';

function test_severity(): array {
    $tests = [];

    // Test 1: Critical Severity Event Mapping
    $criticalEvents = ['SQLI_BLOCKED', 'SSRF_BLOCKED', 'HASH_CHAIN_TAMPERED', 'ADMIN_PRIVILEGE_ESCALATION'];
    $allCritPass = true;
    foreach ($criticalEvents as $ev) {
        if (get_event_severity($ev) !== 'critical') {
            $allCritPass = false;
        }
    }
    $tests[] = [
        'name'   => 'Critical Severity Triage Mapping (Zero-Day & RCE Indicators)',
        'pass'   => $allCritPass,
        'detail' => 'Mapped: ' . implode(', ', $criticalEvents) . ' -> critical'
    ];

    // Test 2: High Severity Mapping
    $highEvents = ['CSRF_FAILURE', 'XSS_BLOCKED', 'ACCOUNT_LOCKED', 'DIRECTORY_TRAVERSAL', 'ANOMALY_DETECTED'];
    $allHighPass = true;
    foreach ($highEvents as $ev) {
        if (get_event_severity($ev) !== 'high') {
            $allHighPass = false;
        }
    }
    $tests[] = [
        'name'   => 'High Severity Triage Mapping (Direct Policy Violations)',
        'pass'   => $allHighPass,
        'detail' => 'Mapped: ' . implode(', ', $highEvents) . ' -> high'
    ];

    // Test 3: Medium Severity Mapping
    $mediumEvents = ['LOGIN_FAILED', 'RATE_LIMIT_EXCEEDED', 'OTP_FAILED', 'PASSWORD_CHANGED', 'OFF_HOURS_ADMIN_ACTION'];
    $allMedPass = true;
    foreach ($mediumEvents as $ev) {
        if (get_event_severity($ev) !== 'medium') {
            $allMedPass = false;
        }
    }
    $tests[] = [
        'name'   => 'Medium Severity Triage Mapping (Behavioral Shifts & Mismatches)',
        'pass'   => $allMedPass,
        'detail' => 'Mapped: ' . implode(', ', $mediumEvents) . ' -> medium'
    ];

    // Test 4: Low Severity Mapping
    $lowEvents = ['LOGIN_SUCCESS', 'LOGOUT', 'TRANSFER_SUCCESS', 'HEARTBEAT', 'AUDIT_LOG_EXPORTED'];
    $allLowPass = true;
    foreach ($lowEvents as $ev) {
        if (get_event_severity($ev) !== 'low') {
            $allLowPass = false;
        }
    }
    $tests[] = [
        'name'   => 'Low Severity Triage Mapping (Operational Activities)',
        'pass'   => $allLowPass,
        'detail' => 'Mapped: ' . implode(', ', $lowEvents) . ' -> low'
    ];

    // Test 5: Fallback for Unknown Event Types
    $unknownSev = get_event_severity('CUSTOM_UNDEFINED_PROBE_EVENT');
    $tests[] = [
        'name'   => 'Safe Default Fallback for Unclassified Events',
        'pass'   => ($unknownSev === 'low'),
        'detail' => "Unrecognized event mapped to default: '$unknownSev'"
    ];

    // Test 6: Database Column Schema Default
    $pdo = get_db();
    $stmt = $pdo->query(
        "SELECT COLUMN_DEFAULT, DATA_TYPE, COLUMN_TYPE 
         FROM INFORMATION_SCHEMA.COLUMNS 
         WHERE TABLE_SCHEMA = DATABASE() 
           AND TABLE_NAME = 'security_logs' 
           AND COLUMN_NAME = 'severity'"
    );
    $colMeta = $stmt->fetch(PDO::FETCH_ASSOC);

    $defaultVal = trim($colMeta['COLUMN_DEFAULT'] ?? '', "'\"");
    $dbDefaultMatches = ($colMeta && strtolower($defaultVal) === 'low');
    $tests[] = [
        'name'   => 'Database ENUM Schema Default Constraint (low)',
        'pass'   => ($dbDefaultMatches === true),
        'detail' => "Column type: {$colMeta['COLUMN_TYPE']}, Default: '{$defaultVal}'"
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Threat Severity Tests...\n";
    foreach (test_severity() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
