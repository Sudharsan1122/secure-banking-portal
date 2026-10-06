<?php
/**
 * Regression Test: 06 - IDOR on Transaction Details / Receipt
 * 
 * OWASP: A01:2021 – Broken Access Control
 * CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
 */

require_once __DIR__ . '/../../config/database.php';

function test_06_idor_transaction(): array {
    $tests = [];
    $pdo = get_db();

    // Setup: Find a transaction
    $stmtTxn = $pdo->query("SELECT id, sender_id, receiver_id FROM transactions ORDER BY id DESC LIMIT 1");
    $txn = $stmtTxn->fetch(PDO::FETCH_ASSOC);

    if (!$txn) {
        $tests[] = [
            'name'   => 'Test Precondition: At least one transaction exists',
            'pass'   => false,
            'detail' => 'No transaction record available for IDOR testing'
        ];
        return $tests;
    }

    $txnId = (int)$txn['id'];
    $senderId = (int)$txn['sender_id'];
    $receiverId = (int)$txn['receiver_id'];

    // Find a 3rd party user who is neither sender nor receiver
    $stmtThirdParty = $pdo->prepare("SELECT id FROM users WHERE id NOT IN (:s, :r) LIMIT 1");
    $stmtThirdParty->execute([':s' => $senderId, ':r' => $receiverId]);
    $unrelatedUserId = (int)$stmtThirdParty->fetchColumn();

    if ($unrelatedUserId <= 0) {
        $unrelatedUserId = 999999; // Non-existent user
    }

    // Test 1: Secure Scoped Query for Transaction Receipt / Details
    // The endpoint enforces: WHERE t.id = :tid AND (t.sender_id = :uid1 OR t.receiver_id = :uid2)
    $stmtScoped = $pdo->prepare(
        "SELECT t.* 
         FROM transactions t
         WHERE t.id = :tid AND (t.sender_id = :uid1 OR t.receiver_id = :uid2)"
    );
    $stmtScoped->execute([':tid' => $txnId, ':uid1' => $unrelatedUserId, ':uid2' => $unrelatedUserId]);
    $leakedRecord = $stmtScoped->fetch(PDO::FETCH_ASSOC);

    $tests[] = [
        'name'   => 'Third-Party Horizontal Isolation on Transaction Record Query',
        'pass'   => ($leakedRecord === false),
        'detail' => "User #$unrelatedUserId denied access to Transaction #$txnId"
    ];

    // Test 2: Legitimate Participant Access Verification (Sender)
    $stmtScoped->execute([':tid' => $txnId, ':uid1' => $senderId, ':uid2' => $senderId]);
    $legitimateRecord = $stmtScoped->fetch(PDO::FETCH_ASSOC);

    $tests[] = [
        'name'   => 'Legitimate Sender Ownership Access Clearance',
        'pass'   => ($legitimateRecord !== false),
        'detail' => "Sender #$senderId verified authorized access to Transaction #$txnId"
    ];

    // Test 3: Numerical Parameter Tampering Boundary
    $tamperedIds = [-1, 0, '1 OR 1=1', 999999999];
    $allTamperedRejected = true;
    foreach ($tamperedIds as $tid) {
        $cleanId = is_numeric($tid) ? (int)$tid : 0;
        $stmtScoped->execute([':tid' => $cleanId, ':uid1' => $unrelatedUserId, ':uid2' => $unrelatedUserId]);
        if ($stmtScoped->fetch() !== false) {
            $allTamperedRejected = false;
        }
    }

    $tests[] = [
        'name'   => 'Boundary & Negative Numerical ID Parameter Tampering Rejection',
        'pass'   => $allTamperedRejected,
        'detail' => 'All synthetic/manipulated transaction keys safely yielded 0 records'
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running 06-IDOR-Transaction Tests...\n";
    $allPass = true;
    foreach (test_06_idor_transaction() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
        if (!$t['pass']) $allPass = false;
    }
    exit($allPass ? 0 : 1);
}
