<?php
/**
 * Test Suite: Transaction Velocity Limits (Pillar B [B5])
 * 
 * Verifies:
 * 1. Single transaction limit enforcement (amount > limit_single rejected).
 * 2. Daily velocity limit enforcement (SUM(today) + amount > limit_daily rejected).
 * 3. Monthly velocity limit enforcement (SUM(30d) + amount > limit_monthly rejected).
 * 4. Normal transfers within limits succeed without impediment.
 * 5. Rejection events logged to security_logs as TRANSFER_LIMIT_* with severity 'medium'.
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/transfer_service.php';
require_once __DIR__ . '/../security/logger.php';

function test_velocity_limits(): array {
    $tests = [];
    $pdo = get_db();

    // 1. Setup Sender & Receiver with strict velocity limits for testing
    $unameSender = 'velo_send_' . bin2hex(random_bytes(3));
    $unameRecv   = 'velo_recv_' . bin2hex(random_bytes(3));

    // Sender has $5,000 balance, single limit $1,000, daily limit $2,000, monthly limit $5,000
    $pdo->prepare(
        "INSERT INTO users (name, email, phone, username, password_hash, balance, limit_single, limit_daily, limit_monthly, created_at)
         VALUES ('Velo Sender', :e, '555', :u, 'hash', 5000.00, 1000.00, 2000.00, 5000.00, NOW())"
    )->execute([':e' => "$unameSender@test.com", ':u' => $unameSender]);
    $senderId = (int)$pdo->lastInsertId();

    $accSenderNum = 'ACC-TEST-' . random_int(10000, 99999);
    $pdo->prepare("INSERT INTO accounts (user_id, account_number, balance, type, created_at) VALUES (:uid, :acc, 5000.00, 'savings', NOW())")
        ->execute([':uid' => $senderId, ':acc' => $accSenderNum]);
    $senderAccId = (int)$pdo->lastInsertId();

    $pdo->prepare(
        "INSERT INTO users (name, email, phone, username, password_hash, balance, created_at)
         VALUES ('Velo Recv', :e, '555', :u, 'hash', 100.00, NOW())"
    )->execute([':e' => "$unameRecv@test.com", ':u' => $unameRecv]);
    $recvId = (int)$pdo->lastInsertId();

    $accRecvNum = 'ACC-TEST-' . random_int(10000, 99999);
    $pdo->prepare("INSERT INTO accounts (user_id, account_number, balance, type, created_at) VALUES (:uid, :acc, 100.00, 'savings', NOW())")
        ->execute([':uid' => $recvId, ':acc' => $accRecvNum]);
    $recvAccId = (int)$pdo->lastInsertId();

    // -------------------------------------------------------------
    // Test 1: Single Transaction Limit Exceeded ($1,500 > $1,000)
    // -------------------------------------------------------------
    $resSingle = transfer_funds([
        'sender_id'       => $senderId,
        'from_account_id' => $senderAccId,
        'target_account'  => $accRecvNum,
        'amount'          => 1500.00,
        'remark'          => 'Exceed single limit',
        'category'        => 'Transfer'
    ], 'system');

    $tests[] = [
        'name'   => 'Single Transaction Velocity Limit Enforcement ($1,500 > $1,000)',
        'pass'   => ($resSingle['status'] === 'error' && str_contains($resSingle['message'], 'single transaction limit')),
        'detail' => $resSingle['message'] ?? 'Failed'
    ];

    // -------------------------------------------------------------
    // Test 2: Valid Transfer within Single & Daily Limits ($800 <= $1,000)
    // -------------------------------------------------------------
    $resValid1 = transfer_funds([
        'sender_id'       => $senderId,
        'from_account_id' => $senderAccId,
        'target_account'  => $accRecvNum,
        'amount'          => 800.00,
        'remark'          => 'Valid transfer 1',
        'category'        => 'Transfer'
    ], 'system');

    $tests[] = [
        'name'   => 'Compliant Transfer Execution within Velocity Limits ($800 <= $1,000)',
        'pass'   => ($resValid1['status'] === 'success' && (float)$resValid1['new_balance'] === 4200.00),
        'detail' => sprintf("Transfer completed. New Balance: $%.2f", $resValid1['new_balance'] ?? 0)
    ];

    // -------------------------------------------------------------
    // Test 3: Daily Limit Breach ($800 already spent + $800 + $500 = $2,100 > $2,000)
    // -------------------------------------------------------------
    // Execute a second valid transfer of $800 (Total spent today: $1,600)
    $resValid2 = transfer_funds([
        'sender_id'       => $senderId,
        'from_account_id' => $senderAccId,
        'target_account'  => $accRecvNum,
        'amount'          => 800.00,
        'remark'          => 'Valid transfer 2',
        'category'        => 'Transfer'
    ], 'system');

    // Attempt third transfer of $500 ($1,600 + $500 = $2,100 > $2,000 daily limit)
    $resDaily = transfer_funds([
        'sender_id'       => $senderId,
        'from_account_id' => $senderAccId,
        'target_account'  => $accRecvNum,
        'amount'          => 500.00,
        'remark'          => 'Breach daily limit',
        'category'        => 'Transfer'
    ], 'system');

    $tests[] = [
        'name'   => 'Daily Aggregate Velocity Limit Enforcement ($2,100 > $2,000)',
        'pass'   => ($resDaily['status'] === 'error' && str_contains($resDaily['message'], 'daily limit')),
        'detail' => $resDaily['message'] ?? 'Failed'
    ];

    // -------------------------------------------------------------
    // Test 4: Monthly Aggregate Velocity Limit Enforcement
    // -------------------------------------------------------------
    // Seed $3,000 historical transfer in past 15 days
    $pdo->prepare(
        "INSERT INTO transactions (sender_id, receiver_id, amount, remark, category, status, created_at)
         VALUES (:uid, :rid, 3000.00, 'Past transfer', 'Bills', 'completed', DATE_SUB(NOW(), INTERVAL 15 DAY))"
    )->execute([':uid' => $senderId, ':rid' => $recvId]);

    // Current 30-day total: $800 + $800 + $3,000 = $4,600.
    // Sender monthly limit is $5,000. Try transferring $600 ($4,600 + $600 = $5,200 > $5,000)
    // First temporarily raise daily limit so monthly limit check fires:
    $pdo->prepare("UPDATE users SET limit_daily = 10000.00 WHERE id = :uid")->execute([':uid' => $senderId]);

    $resMonthly = transfer_funds([
        'sender_id'       => $senderId,
        'from_account_id' => $senderAccId,
        'target_account'  => $accRecvNum,
        'amount'          => 600.00,
        'remark'          => 'Breach monthly limit',
        'category'        => 'Transfer'
    ], 'system');

    $tests[] = [
        'name'   => 'Rolling 30-Day Aggregate Limit Enforcement ($5,200 > $5,000)',
        'pass'   => ($resMonthly['status'] === 'error' && str_contains($resMonthly['message'], '30-day volume limit')),
        'detail' => $resMonthly['message'] ?? 'Failed'
    ];

    // -------------------------------------------------------------
    // Test 5: Verify Security Telemetry Logging
    // -------------------------------------------------------------
    $stmtLogs = $pdo->prepare(
        "SELECT event_type, severity FROM security_logs 
         WHERE user_id = :uid AND event_type IN ('TRANSFER_LIMIT_SINGLE', 'TRANSFER_LIMIT_DAILY', 'TRANSFER_LIMIT_MONTHLY')"
    );
    $stmtLogs->execute([':uid' => $senderId]);
    $loggedLimitEvents = $stmtLogs->fetchAll(PDO::FETCH_ASSOC);

    $allMedium = true;
    foreach ($loggedLimitEvents as $le) {
        if ($le['severity'] !== 'medium') {
            $allMedium = false;
        }
    }

    $tests[] = [
        'name'   => 'SIEM Velocity Breach Telemetry & Severity Classification',
        'pass'   => (count($loggedLimitEvents) >= 3 && $allMedium),
        'detail' => sprintf("Recorded %d velocity limit breach events with 'medium' severity", count($loggedLimitEvents))
    ];

    // -------------------------------------------------------------
    // Cleanup Test Users and Transactions
    // -------------------------------------------------------------
    $pdo->prepare("DELETE FROM transactions WHERE sender_id = :u1 OR receiver_id = :u2")->execute([':u1' => $senderId, ':u2' => $senderId]);
    $pdo->prepare("DELETE FROM accounts WHERE user_id IN (:u1, :u2)")->execute([':u1' => $senderId, ':u2' => $recvId]);
    $pdo->prepare("DELETE FROM notifications WHERE user_id IN (:u1, :u2)")->execute([':u1' => $senderId, ':u2' => $recvId]);
    $pdo->prepare("DELETE FROM users WHERE id IN (:u1, :u2)")->execute([':u1' => $senderId, ':u2' => $recvId]);

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Transaction Velocity Limits Tests...\n";
    foreach (test_velocity_limits() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
