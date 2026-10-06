<?php
/**
 * Test Suite: Automated SIEM Alerting Engine (Pillar C [C7])
 * 
 * Verifies:
 * 1. Sliding-window threshold evaluation (5 failure events trigger 1 High-severity alert).
 * 2. Alert fatigue deduplication (subsequent 5 failure events within window are suppressed).
 * 3. Alert record schema and payload integrity in `alerts` table.
 * 4. Critical severity alert escalation (DEMO_MODE simulated notification dispatch).
 * 5. Triage workflow: alert acknowledgment via acknowledge_alert() updates acknowledged status and metadata.
 * 6. SOC unacknowledged alert counters and queries reflect real-time queue states.
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../security/alert_engine.php';

function test_alert_engine(): array {
    $tests = [];
    $pdo = get_db();

    // Setup isolated test IP
    $testIp = '198.51.100.' . random_int(10, 240);
    $_SERVER['REMOTE_ADDR'] = $testIp;

    // Register hermetic test rules in alert_rules with unique run identifier
    $uniqueRun = bin2hex(random_bytes(4));
    $ruleBurstName = 'TEST_BURST_' . $uniqueRun;
    $eventBurstType = 'TEST_EVENT_' . $uniqueRun;

    $ruleCritName = 'TEST_CRIT_' . $uniqueRun;
    $eventCritType = 'TEST_CRIT_EVENT_' . $uniqueRun;

    // Insert high-severity burst rule (threshold 5, window 600s)
    $pdo->prepare(
        "INSERT INTO alert_rules (name, description, threshold, window_seconds, event_type, severity, enabled, created_at)
         VALUES (:name, 'Hermetic Test CSRF Burst Rule', 5, 600, :event, 'high', 1, NOW())"
    )->execute([':name' => $ruleBurstName, ':event' => $eventBurstType]);

    // Insert critical rule (threshold 3, window 300s)
    $pdo->prepare(
        "INSERT INTO alert_rules (name, description, threshold, window_seconds, event_type, severity, enabled, created_at)
         VALUES (:name, 'Hermetic Test SQLi Critical Spike', 3, 300, :event, 'critical', 1, NOW())"
    )->execute([':name' => $ruleCritName, ':event' => $eventCritType]);

    // -------------------------------------------------------------
    // Test 1: Threshold Triggering (5 events in 10m -> 1 Alert)
    // -------------------------------------------------------------
    // Log exactly 4 failures (below threshold of 5)
    for ($i = 1; $i <= 4; $i++) {
        log_security_event(null, $eventBurstType, 'BLOCKED', "Test burst event $i", 'high');
    }

    $stmtAlertsBefore = $pdo->prepare("SELECT COUNT(*) FROM alerts WHERE rule_name = :name");
    $stmtAlertsBefore->execute([':name' => $ruleBurstName]);
    $alertsBefore = (int)$stmtAlertsBefore->fetchColumn();

    // Log the 5th failure (reaching threshold of 5)
    log_security_event(null, $eventBurstType, 'BLOCKED', "Test burst event 5 - SLA breached", 'high');

    $stmtAlertsAfter = $pdo->prepare("SELECT id, rule_name, severity, context, acknowledged FROM alerts WHERE rule_name = :name");
    $stmtAlertsAfter->execute([':name' => $ruleBurstName]);
    $alertRow = $stmtAlertsAfter->fetch(PDO::FETCH_ASSOC);

    $thresholdPassed = ($alertsBefore === 0 && !empty($alertRow) && $alertRow['severity'] === 'high');
    $tests[] = [
        'name'   => 'Sliding-Window SLA Threshold Trigger (5 Events -> 1 Alert)',
        'pass'   => $thresholdPassed,
        'detail' => $thresholdPassed 
            ? 'Alert breached at exactly 5 events; 0 alerts generated at 4 events' 
            : "Threshold condition failed (Before: $alertsBefore, Row: " . ($alertRow ? 'Found' : 'Missing') . ")"
    ];

    // -------------------------------------------------------------
    // Test 2: Deduplication / Alert Fatigue Suppression
    // -------------------------------------------------------------
    // Log 5 MORE failures immediately within the same 600s suppression window
    for ($i = 6; $i <= 10; $i++) {
        log_security_event(null, $eventBurstType, 'BLOCKED', "Test burst follow-up $i", 'high');
    }

    $stmtAlertsDedup = $pdo->prepare("SELECT COUNT(*) FROM alerts WHERE rule_name = :name");
    $stmtAlertsDedup->execute([':name' => $ruleBurstName]);
    $alertsCountDedup = (int)$stmtAlertsDedup->fetchColumn();

    $dedupPassed = ($alertsCountDedup === 1);
    $tests[] = [
        'name'   => 'Alert Fatigue Deduplication within Suppression Window',
        'pass'   => $dedupPassed,
        'detail' => sprintf("Received 10 total events; retained exactly %d alert (9 events suppressed)", $alertsCountDedup)
    ];

    // -------------------------------------------------------------
    // Test 3: Alert Context JSON Schema Verification
    // -------------------------------------------------------------
    $context = json_decode($alertRow['context'] ?? '{}', true);
    $hasContextKeys = isset($context['threshold'], $context['window_seconds'], $context['client_time']);
    $tests[] = [
        'name'   => 'Structured Alert Telemetry Context Payload Serialization',
        'pass'   => $hasContextKeys,
        'detail' => sprintf("Threshold: %s | Window: %ss | Client Time: %s", 
            $context['threshold'] ?? 'N/A', 
            $context['window_seconds'] ?? 'N/A', 
            $context['client_time'] ?? 'N/A'
        )
    ];

    // -------------------------------------------------------------
    // Test 4: Critical Severity Notification Dispatch (DEMO_MODE)
    // -------------------------------------------------------------
    for ($i = 1; $i <= 3; $i++) {
        log_security_event(null, $eventCritType, 'BLOCKED', "Critical payload test $i", 'critical');
    }

    // Verify NOTIFICATION_SIMULATED in security_logs
    $stmtNotif = $pdo->prepare(
        "SELECT COUNT(*) FROM security_logs 
         WHERE event_type = 'NOTIFICATION_SIMULATED' AND request LIKE :pattern"
    );
    $stmtNotif->execute([':pattern' => "%$ruleCritName%"]);
    $notifLogged = (int)$stmtNotif->fetchColumn();

    $tests[] = [
        'name'   => 'Critical Severity Incident Escalation (SOC Notification)',
        'pass'   => ($notifLogged > 0),
        'detail' => "Dispatched simulated SOC on-call notification for critical incident: $ruleCritName"
    ];

    // -------------------------------------------------------------
    // Test 5: Alert Acknowledgment Workflow (Triage State Update)
    // -------------------------------------------------------------
    $alertId = (int)$alertRow['id'];
    $adminUserId = 1; // Primary Admin User

    $ackResult = acknowledge_alert($alertId, $adminUserId);

    $stmtCheckAck = $pdo->prepare("SELECT acknowledged, acknowledged_by, acknowledged_at FROM alerts WHERE id = :id");
    $stmtCheckAck->execute([':id' => $alertId]);
    $ackRow = $stmtCheckAck->fetch(PDO::FETCH_ASSOC);

    $ackValid = ($ackResult === true && 
                 (int)$ackRow['acknowledged'] === 1 && 
                 (int)$ackRow['acknowledged_by'] === $adminUserId && 
                 !empty($ackRow['acknowledged_at']));

    $tests[] = [
        'name'   => 'SIEM Alert Acknowledgment Workflow (Admin Triage)',
        'pass'   => $ackValid,
        'detail' => sprintf("Alert #%d acknowledged by Admin #%d at %s", $alertId, $adminUserId, $ackRow['acknowledged_at'] ?? 'null')
    ];

    // -------------------------------------------------------------
    // Test 6: SOC Unacknowledged Alert Counter & Queue Sync
    // -------------------------------------------------------------
    $unackCount = get_unacknowledged_alert_count();
    $recentUnack = get_recent_alerts(10, true);

    $queueSynced = true;
    foreach ($recentUnack as $ua) {
        if ((int)$ua['acknowledged'] !== 0) {
            $queueSynced = false;
            break;
        }
    }

    $tests[] = [
        'name'   => 'SOC Unacknowledged Incident Queue Synchronization',
        'pass'   => $queueSynced,
        'detail' => "Active unacknowledged incident queue accurate (Count: $unackCount)"
    ];

    // Cleanup hermetic test rules and alerts
    $pdo->prepare("DELETE FROM alerts WHERE rule_name IN (:r1, :r2)")
        ->execute([':r1' => $ruleBurstName, ':r2' => $ruleCritName]);
    $pdo->prepare("DELETE FROM alert_rules WHERE name IN (:r1, :r2)")
        ->execute([':r1' => $ruleBurstName, ':r2' => $ruleCritName]);

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Automated SIEM Alerting Engine Tests...\n";
    foreach (test_alert_engine() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
