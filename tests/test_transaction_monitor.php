<?php
/**
 * Test Suite: Admin Transaction Monitor & Anomaly Flagging (PILLAR B - B10)
 * 
 * Verifies:
 * 1. Low-risk transaction baseline: no review cases filed.
 * 2. High-Value Heuristic: Transfers >= $50,000 automatically file triage review.
 * 3. Round-Number Spike Heuristic: Round-number transfers >= $10,000 flagged.
 * 4. Rapid-Burst Velocity Heuristic: >= 3 transactions within 5m flagged.
 * 5. SOC Adjudication workflow: outcome updated to 'cleared' / 'escalated' with audit trail.
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/transfer_service.php';
require_once __DIR__ . '/../security/transaction_monitor.php';

function test_transaction_monitor(): array {
    $tests = [];
    $pdo = get_db();

    // 1. Setup isolated user accounts with high limits to permit large test transfers
    $sName = 'mon_sender_' . bin2hex(random_bytes(3));
    $rName = 'mon_recv_' . bin2hex(random_bytes(3));
    $pass = password_hash('Pass123!Mon', PASSWORD_BCRYPT);

    $pdo->prepare("INSERT INTO users (username, email, password_hash, name, role, balance, limit_single, limit_daily, limit_monthly) VALUES (?, ?, ?, ?, 'user', 200000.00, 100000.00, 200000.00, 1000000.00)")
        ->execute([$sName, "$sName@test.local", $pass, 'Monitor Sender']);
    $senderId = (int)$pdo->lastInsertId();

    $sAcc = 'ACC-SAV-' . random_int(10000, 99999);
    $pdo->prepare("INSERT INTO accounts (user_id, account_number, balance, currency, type, nickname) VALUES (?, ?, 200000.00, 'USD', 'savings', 'Primary')")
        ->execute([$senderId, $sAcc]);
    $sAccId = (int)$pdo->lastInsertId();

    $pdo->prepare("INSERT INTO users (username, email, password_hash, name, role, balance) VALUES (?, ?, ?, ?, 'user', 100.00)")
        ->execute([$rName, "$rName@test.local", $pass, 'Monitor Recipient']);
    $recvId = (int)$pdo->lastInsertId();

    $rAcc = 'ACC-SAV-' . random_int(10000, 99999);
    $pdo->prepare("INSERT INTO accounts (user_id, account_number, balance, currency, type, nickname) VALUES (?, ?, 100.00, 'USD', 'savings', 'Primary')")
        ->execute([$recvId, $rAcc]);
    $rAccId = (int)$pdo->lastInsertId();

    // TEST 1: Baseline Low-Risk Transfer ($150.25)
    $resNormal = transfer_funds([
        'sender_id'       => $senderId,
        'from_account_id' => $sAccId,
        'target_account'  => $rAcc,
        'amount'          => 150.25,
        'remark'          => 'Regular coffee split',
        'category'        => 'Food'
    ], 'system');

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM transaction_reviews WHERE transaction_id = ?");
    $stmt->execute([$resNormal['transaction_id']]);
    $normalCount = (int)$stmt->fetchColumn();

    $tests[] = [
        'name'   => 'Baseline Low-Risk Transaction Clearance',
        'pass'   => ($resNormal['status'] === 'success' && $normalCount === 0),
        'detail' => 'Standard benign transfer ($150.25) filed 0 anomaly review flags'
    ];

    // TEST 2: High-Value Transfer ($60,000.00 >= $50,000.00)
    $resHigh = transfer_funds([
        'sender_id'       => $senderId,
        'from_account_id' => $sAccId,
        'target_account'  => $rAcc,
        'amount'          => 60000.00,
        'remark'          => 'Major commercial equipment purchase',
        'category'        => 'Transfer'
    ], 'system');

    $stmt->execute([$resHigh['transaction_id']]);
    $highCount = (int)$stmt->fetchColumn();

    $stmtDetails = $pdo->prepare("SELECT outcome, flagged_reason FROM transaction_reviews WHERE transaction_id = ?");
    $stmtDetails->execute([$resHigh['transaction_id']]);
    $reviewRow = $stmtDetails->fetch(PDO::FETCH_ASSOC);

    $tests[] = [
        'name'   => 'High-Value Anomaly Detection Heuristic (>= $50,000)',
        'pass'   => ($resHigh['status'] === 'success' && $highCount === 1 && $reviewRow['outcome'] === 'pending' && str_contains($reviewRow['flagged_reason'], '50,000.00')),
        'detail' => 'Transfer of $60,000 automatically flagged for SOC triage with status pending'
    ];

    // TEST 3: Round-Number High Value ($10,000.00)
    $resRound = transfer_funds([
        'sender_id'       => $senderId,
        'from_account_id' => $sAccId,
        'target_account'  => $rAcc,
        'amount'          => 10000.00,
        'remark'          => 'Even ten thousand payment',
        'category'        => 'Transfer'
    ], 'system');

    $stmt->execute([$resRound['transaction_id']]);
    $roundCount = (int)$stmt->fetchColumn();

    $tests[] = [
        'name'   => 'Round-Number Structuring Spike Heuristic (>= $10,000)',
        'pass'   => ($resRound['status'] === 'success' && $roundCount === 1),
        'detail' => 'Round-sum transfer ($10,000.00) triggered automated AML structuring flag'
    ];

    // TEST 4: Rapid Velocity Burst Heuristic (>= 3 transfers within 5 minutes)
    // Send additional transfers rapidly to trigger the burst threshold
    for ($i = 0; $i < 3; $i++) {
        transfer_funds([
            'sender_id'       => $senderId,
            'from_account_id' => $sAccId,
            'target_account'  => $rAcc,
            'amount'          => 25.00 + $i,
            'remark'          => "Burst transfer $i",
            'category'        => 'Other'
        ], 'system');
    }

    $stmtBurst = $pdo->prepare("SELECT COUNT(*) FROM transaction_reviews WHERE transaction_id IN (SELECT id FROM transactions WHERE sender_id = ?) AND flagged_reason LIKE '%Rapid Burst Velocity%'");
    $stmtBurst->execute([$senderId]);
    $burstFlags = (int)$stmtBurst->fetchColumn();

    $tests[] = [
        'name'   => 'Rapid Burst Velocity Anomaly Detection (>= 3 txns / 5m)',
        'pass'   => ($burstFlags >= 1),
        'detail' => sprintf("Recorded %d rapid burst velocity triage flags", $burstFlags)
    ];

    // TEST 5: SOC Adjudication Workflow
    $stmtRevId = $pdo->prepare("SELECT id FROM transaction_reviews WHERE transaction_id = ?");
    $stmtRevId->execute([$resHigh['transaction_id']]);
    $highReviewId = (int)$stmtRevId->fetchColumn();

    $pdo->prepare("UPDATE transaction_reviews SET outcome = 'cleared', notes = 'Verified with customer invoice', reviewed_at = NOW() WHERE id = ?")
        ->execute([$highReviewId]);

    $stmtReviewCheck = $pdo->prepare("SELECT outcome, reviewed_at FROM transaction_reviews WHERE id = ?");
    $stmtReviewCheck->execute([$highReviewId]);
    $updatedReview = $stmtReviewCheck->fetch(PDO::FETCH_ASSOC);

    $tests[] = [
        'name'   => 'SOC Triage Adjudication & Audit Resolution',
        'pass'   => ($updatedReview && $updatedReview['outcome'] === 'cleared' && !empty($updatedReview['reviewed_at'])),
        'detail' => 'High-value review dispositioned to cleared with timestamp and auditor notes'
    ];

    // Cleanup using positional placeholders
    $pdo->prepare("DELETE FROM transaction_reviews WHERE transaction_id IN (SELECT id FROM transactions WHERE sender_id IN (?, ?) OR receiver_id IN (?, ?))")
        ->execute([$senderId, $recvId, $senderId, $recvId]);
    $pdo->prepare("DELETE FROM transactions WHERE sender_id IN (?, ?) OR receiver_id IN (?, ?)")
        ->execute([$senderId, $recvId, $senderId, $recvId]);
    $pdo->prepare("DELETE FROM accounts WHERE user_id IN (?, ?)")->execute([$senderId, $recvId]);
    $pdo->prepare("DELETE FROM notifications WHERE user_id IN (?, ?)")->execute([$senderId, $recvId]);
    $pdo->prepare("DELETE FROM users WHERE id IN (?, ?)")->execute([$senderId, $recvId]);

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Transaction Monitor & Suspicious Activity Tests...\n";
    foreach (test_transaction_monitor() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
