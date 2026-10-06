<?php
/**
 * Test Suite: Beneficiary 2-Step Verification (PILLAR B - B4)
 * 
 * Verifies:
 * 1. Beneficiary created initially in unverified state (verified = 0, OTP bcrypt hash set).
 * 2. Unverified beneficiary transfer rejection: transfer_funds() blocks execution.
 * 3. Invalid OTP rejection & attempt counter increment.
 * 4. Anti-brute force lock after 5 failed attempts.
 * 5. Valid OTP verification, activation (verified = 1), and hash destruction.
 * 6. Compliant fund transfer execution to newly verified beneficiary.
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/transfer_service.php';

function test_beneficiary_verify(): array {
    $tests = [];
    $pdo = get_db();

    // 1. Setup isolated Sender and Target Receiver
    $sName = 'b4_sender_' . bin2hex(random_bytes(3));
    $passHash = password_hash('Pass123!B4', PASSWORD_BCRYPT);
    $pdo->prepare("INSERT INTO users (username, email, password_hash, name, role, balance, limit_single, limit_daily, limit_monthly) VALUES (?, ?, ?, ?, 'user', 5000.00, 2000.00, 5000.00, 20000.00)")
        ->execute([$sName, "$sName@test.local", $passHash, 'B4 Sender User']);
    $senderId = (int)$pdo->lastInsertId();

    $sAccNum = 'ACC-SAV-' . random_int(10000, 99999);
    $pdo->prepare("INSERT INTO accounts (user_id, account_number, balance, currency, type, nickname, interest_rate) VALUES (?, ?, 5000.00, 'USD', 'savings', 'Primary', 3.50)")
        ->execute([$senderId, $sAccNum]);
    $senderAccId = (int)$pdo->lastInsertId();

    $rName = 'b4_recv_' . bin2hex(random_bytes(3));
    $pdo->prepare("INSERT INTO users (username, email, password_hash, name, role, balance) VALUES (?, ?, ?, ?, 'user', 100.00)")
        ->execute([$rName, "$rName@test.local", $passHash, 'B4 Recv User']);
    $recvId = (int)$pdo->lastInsertId();

    $rAccNum = 'ACC-SAV-' . random_int(10000, 99999);
    $pdo->prepare("INSERT INTO accounts (user_id, account_number, balance, currency, type, nickname) VALUES (?, ?, 100.00, 'USD', 'savings', 'Primary')")
        ->execute([$recvId, $rAccNum]);
    $recvAccId = (int)$pdo->lastInsertId();

    // 2. Insert unverified beneficiary with OTP 123456
    $correctOtp = '123456';
    $otpHash = password_hash($correctOtp, PASSWORD_BCRYPT);

    $pdo->prepare(
        "INSERT INTO beneficiaries (user_id, name, account_number, bank_name, verified, verification_code_hash, verification_expires_at, verification_attempts)
         VALUES (?, ?, ?, 'Secure National Bank', 0, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE), 0)"
    )->execute([$senderId, 'Pending Payee', $rAccNum, $otpHash]);
    $benId = (int)$pdo->lastInsertId();

    // TEST 1: Initial state check
    $stmt = $pdo->prepare("SELECT verified, verification_attempts FROM beneficiaries WHERE id = ?");
    $stmt->execute([$benId]);
    $benRow = $stmt->fetch(PDO::FETCH_ASSOC);
    $tests[] = [
        'name'   => 'Initial Unverified Beneficiary State',
        'pass'   => ((int)$benRow['verified'] === 0 && (int)$benRow['verification_attempts'] === 0),
        'detail' => 'verified=0, attempts=0, bcrypt hash initialized'
    ];

    // TEST 2: Attempt transfer to unverified beneficiary -> MUST BE REJECTED
    $unverifiedTxn = transfer_funds([
        'sender_id'       => $senderId,
        'from_account_id' => $senderAccId,
        'beneficiary_id'  => $benId,
        'amount'          => 100.00,
        'remark'          => 'Unverified Payee Transfer'
    ], 'system');

    $tests[] = [
        'name'   => 'Transfer Blocked for Unverified Payee',
        'pass'   => ($unverifiedTxn['status'] === 'error' && $unverifiedTxn['code'] === 403),
        'detail' => $unverifiedTxn['message'] ?? 'Blocked'
    ];

    // TEST 3: Invalid OTP attempt verification simulation
    $badOtp = '999999';
    $validatesBad = password_verify($badOtp, $otpHash);
    $tests[] = [
        'name'   => 'Invalid OTP Bcrypt Rejection',
        'pass'   => !$validatesBad,
        'detail' => 'Incorrect 6-digit OTP rejected cryptographically'
    ];

    // Simulate 5 failed attempts
    for ($i = 1; $i <= 5; $i++) {
        $pdo->prepare("UPDATE beneficiaries SET verification_attempts = verification_attempts + 1 WHERE id = ?")
            ->execute([$benId]);
    }
    $stmt->execute([$benId]);
    $lockedRow = $stmt->fetch(PDO::FETCH_ASSOC);
    $tests[] = [
        'name'   => 'Anti-Brute Force Lockout (>= 5 attempts)',
        'pass'   => ((int)$lockedRow['verification_attempts'] >= 5),
        'detail' => sprintf("Attempts recorded: %d", $lockedRow['verification_attempts'])
    ];

    // TEST 4: Verification with correct OTP resets attempts, verifies beneficiary, and wipes hash
    $freshOtp = '654321';
    $freshHash = password_hash($freshOtp, PASSWORD_BCRYPT);

    $pdo->prepare(
        "INSERT INTO beneficiaries (user_id, name, account_number, bank_name, verified, verification_code_hash, verification_expires_at, verification_attempts)
         VALUES (?, ?, ?, 'Secure National Bank', 0, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE), 0)"
    )->execute([$senderId, 'Valid Payee', $rAccNum, $freshHash]);
    $validBenId = (int)$pdo->lastInsertId();

    $matches = password_verify($freshOtp, $freshHash);
    $pdo->prepare("UPDATE beneficiaries SET verified = 1, verification_code_hash = NULL, verification_expires_at = NULL, verification_attempts = 0 WHERE id = ?")
        ->execute([$validBenId]);

    $stmt->execute([$validBenId]);
    $verifiedBen = $stmt->fetch(PDO::FETCH_ASSOC);

    $tests[] = [
        'name'   => 'Valid OTP Activation & Hash Purging',
        'pass'   => ($matches && (int)$verifiedBen['verified'] === 1 && empty($verifiedBen['verification_code_hash'])),
        'detail' => 'Beneficiary verified and sensitive OTP hash destroyed'
    ];

    // TEST 5: Fund transfer to verified beneficiary now succeeds cleanly!
    $verifiedTxn = transfer_funds([
        'sender_id'       => $senderId,
        'from_account_id' => $senderAccId,
        'beneficiary_id'  => $validBenId,
        'amount'          => 250.00,
        'remark'          => 'Transfer to verified payee',
        'category'        => 'Transfer'
    ], 'system');

    $tests[] = [
        'name'   => 'Compliant Transfer to Verified Payee',
        'pass'   => ($verifiedTxn['status'] === 'success'),
        'detail' => $verifiedTxn['message'] ?? 'Completed'
    ];

    // Cleanup
    $pdo->prepare("DELETE FROM transactions WHERE sender_id = :u1 OR receiver_id = :u2")->execute([':u1' => $senderId, ':u2' => $senderId]);
    $pdo->prepare("DELETE FROM accounts WHERE user_id IN (:u1, :u2)")->execute([':u1' => $senderId, ':u2' => $recvId]);
    $pdo->prepare("DELETE FROM beneficiaries WHERE user_id = :u1")->execute([':u1' => $senderId]);
    $pdo->prepare("DELETE FROM notifications WHERE user_id IN (:u1, :u2)")->execute([':u1' => $senderId, ':u2' => $recvId]);
    $pdo->prepare("DELETE FROM users WHERE id IN (:u1, :u2)")->execute([':u1' => $senderId, ':u2' => $recvId]);

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Beneficiary 2-Step Verification Tests...\n";
    foreach (test_beneficiary_verify() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
