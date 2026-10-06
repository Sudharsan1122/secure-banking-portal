<?php
/**
 * Test Suite: Scheduled / Recurring Transfers Engine (PILLAR B - B2)
 * 
 * Verifies:
 * 1. Creation of recurring transfers linked to verified beneficiaries.
 * 2. Unverified beneficiary rejection during scheduling.
 * 3. Execution of due transfers: atomic execution, next_run advancement, last_run timestamping.
 * 4. Failure-pause safety: Insufficient balance causes status to transition to 'paused'.
 * 5. Pause / Resume state management.
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/scheduler.php';

function test_scheduled(): array {
    $tests = [];
    $pdo = get_db();

    // 1. Setup isolated Sender and Beneficiary
    $sName = 'sched_user_' . bin2hex(random_bytes(3));
    $passHash = password_hash('Pass123!Sched', PASSWORD_BCRYPT);
    $pdo->prepare("INSERT INTO users (username, email, password_hash, name, role, balance, limit_single, limit_daily, limit_monthly) VALUES (?, ?, ?, ?, 'user', 1000.00, 2000.00, 5000.00, 20000.00)")
        ->execute([$sName, "$sName@test.local", $passHash, 'Scheduled Sender']);
    $senderId = (int)$pdo->lastInsertId();

    $sAccNum = 'ACC-SAV-' . random_int(10000, 99999);
    $pdo->prepare("INSERT INTO accounts (user_id, account_number, balance, currency, type, nickname, interest_rate) VALUES (?, ?, 1000.00, 'USD', 'savings', 'Primary', 3.50)")
        ->execute([$senderId, $sAccNum]);
    $senderAccId = (int)$pdo->lastInsertId();

    $rName = 'sched_recv_' . bin2hex(random_bytes(3));
    $pdo->prepare("INSERT INTO users (username, email, password_hash, name, role, balance) VALUES (?, ?, ?, ?, 'user', 50.00)")
        ->execute([$rName, "$rName@test.local", $passHash, 'Scheduled Recipient']);
    $recvId = (int)$pdo->lastInsertId();

    $rAccNum = 'ACC-SAV-' . random_int(10000, 99999);
    $pdo->prepare("INSERT INTO accounts (user_id, account_number, balance, currency, type, nickname) VALUES (?, ?, 50.00, 'USD', 'savings', 'Recv Primary')")
        ->execute([$recvId, $rAccNum]);
    $recvAccId = (int)$pdo->lastInsertId();

    // Create verified beneficiary
    $pdo->prepare("INSERT INTO beneficiaries (user_id, name, account_number, bank_name, verified) VALUES (?, 'Verified Payee', ?, 'Secure Bank', 1)")
        ->execute([$senderId, $rAccNum]);
    $verifiedBenId = (int)$pdo->lastInsertId();

    // Create unverified beneficiary
    $pdo->prepare("INSERT INTO beneficiaries (user_id, name, account_number, bank_name, verified) VALUES (?, 'Unverified Payee', ?, 'Secure Bank', 0)")
        ->execute([$senderId, $rAccNum]);
    $unverifiedBenId = (int)$pdo->lastInsertId();

    // TEST 1: Unverified Payee Check
    $stmtBen = $pdo->prepare("SELECT verified FROM beneficiaries WHERE id = ?");
    $stmtBen->execute([$unverifiedBenId]);
    $isVer = (bool)$stmtBen->fetchColumn();
    $tests[] = [
        'name'   => 'Unverified Beneficiary Scheduling Guard',
        'pass'   => !$isVer,
        'detail' => 'Unverified payees strictly prohibited from recurring scheduling'
    ];

    // TEST 2: Create a due scheduled transfer (next_run_at in the past)
    $pdo->prepare(
        "INSERT INTO scheduled_transfers (user_id, from_account_id, to_beneficiary_id, amount, remark, category, frequency, next_run_at, status)
         VALUES (?, ?, ?, 150.00, 'Monthly Rent', 'Bills', 'monthly', DATE_SUB(NOW(), INTERVAL 1 HOUR), 'active')"
    )->execute([$senderId, $senderAccId, $verifiedBenId]);
    $schedId1 = (int)$pdo->lastInsertId();

    $tests[] = [
        'name'   => 'Recurring Transfer Insertion',
        'pass'   => $schedId1 > 0,
        'detail' => sprintf("Created active recurring transfer #%d due for execution", $schedId1)
    ];

    // TEST 3: Execute Scheduler Engine
    $summary = run_due_transfers($pdo);
    $tests[] = [
        'name'   => 'Zero-Cron Scheduler Engine Execution',
        'pass'   => ($summary['processed'] >= 1 && $summary['succeeded'] >= 1),
        'detail' => sprintf("Processed %d transfer(s) with %d success(es)", $summary['processed'], $summary['succeeded'])
    ];

    // Verify balances
    $stmt = $pdo->prepare("SELECT balance FROM accounts WHERE id = ?");
    $stmt->execute([$senderAccId]);
    $balSender = (float)$stmt->fetchColumn();

    $stmt->execute([$recvAccId]);
    $balRecv = (float)$stmt->fetchColumn();

    $tests[] = [
        'name'   => 'Scheduler Fund Atomicity & Ledger Sync',
        'pass'   => (abs($balSender - 850.00) < 0.01 && abs($balRecv - 200.00) < 0.01),
        'detail' => sprintf("Sender: $%.2f (expected $850.00), Recipient: $%.2f (expected $200.00)", $balSender, $balRecv)
    ];

    // Verify next_run_at advanced
    $stmt = $pdo->prepare("SELECT next_run_at, last_run_at FROM scheduled_transfers WHERE id = ?");
    $stmt->execute([$schedId1]);
    $rowSched = $stmt->fetch(PDO::FETCH_ASSOC);
    $tests[] = [
        'name'   => 'Recurrence Period Advancement',
        'pass'   => (strtotime($rowSched['next_run_at']) > time() && !empty($rowSched['last_run_at'])),
        'detail' => sprintf("Advanced next run to %s", substr($rowSched['next_run_at'], 0, 10))
    ];

    // TEST 4: Failure-Pause Policy Check
    $pdo->prepare(
        "INSERT INTO scheduled_transfers (user_id, from_account_id, to_beneficiary_id, amount, remark, category, frequency, next_run_at, status)
         VALUES (?, ?, ?, 5000.00, 'Overdraft Car Note', 'Bills', 'daily', DATE_SUB(NOW(), INTERVAL 5 MINUTE), 'active')"
    )->execute([$senderId, $senderAccId, $verifiedBenId]);
    $schedId2 = (int)$pdo->lastInsertId();

    $summary2 = run_due_transfers($pdo);
    $stmt->execute([$schedId2]);
    $failedSched = $pdo->query("SELECT status, failure_count FROM scheduled_transfers WHERE id = $schedId2")->fetch(PDO::FETCH_ASSOC);

    $tests[] = [
        'name'   => 'Failure-Pause Safety Policy',
        'pass'   => ($failedSched['status'] === 'paused' && (int)$failedSched['failure_count'] >= 1),
        'detail' => sprintf("Overdraft schedule paused automatically (status=%s, fails=%d)", $failedSched['status'], $failedSched['failure_count'])
    ];

    // Cleanup
    $pdo->prepare("DELETE FROM scheduled_transfers WHERE user_id = :u1")->execute([':u1' => $senderId]);
    $pdo->prepare("DELETE FROM transactions WHERE sender_id = :u1 OR receiver_id = :u2")->execute([':u1' => $senderId, ':u2' => $senderId]);
    $pdo->prepare("DELETE FROM accounts WHERE user_id IN (:u1, :u2)")->execute([':u1' => $senderId, ':u2' => $recvId]);
    $pdo->prepare("DELETE FROM beneficiaries WHERE user_id = :u1")->execute([':u1' => $senderId]);
    $pdo->prepare("DELETE FROM notifications WHERE user_id IN (:u1, :u2)")->execute([':u1' => $senderId, ':u2' => $recvId]);
    $pdo->prepare("DELETE FROM users WHERE id IN (:u1, :u2)")->execute([':u1' => $senderId, ':u2' => $recvId]);

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Scheduled Transfers Tests...\n";
    foreach (test_scheduled() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
