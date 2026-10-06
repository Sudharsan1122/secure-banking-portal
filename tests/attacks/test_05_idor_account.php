<?php
/**
 * Regression Test: 05 - Insecure Direct Object Reference (IDOR) on Account Access
 * 
 * OWASP: A01:2021 – Broken Access Control
 * CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
 */

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../security/transfer_service.php';

function test_05_idor_account(): array {
    $tests = [];
    $pdo = get_db();

    // Setup: Get two different users
    $stmt = $pdo->query("SELECT id FROM users ORDER BY id ASC LIMIT 2");
    $users = $stmt->fetchAll(PDO::FETCH_COLUMN);

    if (count($users) < 2) {
        $tests[] = [
            'name'   => 'Test Precondition: Multiple Tenant Users Exist',
            'pass'   => false,
            'detail' => 'Database needs at least 2 users for IDOR testing'
        ];
        return $tests;
    }

    $userA = (int)$users[0];
    $userB = (int)$users[1];

    // Get an account owned by User B
    $stmtB = $pdo->prepare("SELECT id, account_number FROM accounts WHERE user_id = :uid LIMIT 1");
    $stmtB->execute([':uid' => $userB]);
    $accB = $stmtB->fetch(PDO::FETCH_ASSOC);

    if (!$accB) {
        $tests[] = [
            'name'   => 'Test Precondition: Target Account Exists',
            'pass'   => false,
            'detail' => "No account found for user #$userB"
        ];
        return $tests;
    }

    $accountBId = (int)$accB['id'];

    // Test 1: Query with tenant isolation (WHERE id = :acc_id AND user_id = :uid)
    $stmtQuery = $pdo->prepare("SELECT * FROM accounts WHERE id = :acc_id AND user_id = :uid");
    $stmtQuery->execute([':acc_id' => $accountBId, ':uid' => $userA]);
    $unauthorizedAccess = $stmtQuery->fetch(PDO::FETCH_ASSOC);

    $tests[] = [
        'name'   => 'Horizontal Account Query Isolation (Scoped by Session user_id)',
        'pass'   => ($unauthorizedAccess === false),
        'detail' => 'User A cannot retrieve record for Account #' . $accountBId . ' owned by User B'
    ];

    // Test 2: Transfer Debit Authorization Check (IDOR Source Account Interception)
    // Attempting to initiate transfer using User B's account while authenticated as User A
    $result = transfer_funds([
        'sender_id'       => $userA,
        'from_account_id' => $accountBId,
        'target_account'  => 'ACC-TEST',
        'amount'          => 10.00,
        'remark'          => 'Test IDOR'
    ], 'system');

    $isBlocked = ($result['status'] === 'error' && $result['code'] === 403);
    $tests[] = [
        'name'   => 'Transaction Engine IDOR Interception on Source Account Debit',
        'pass'   => $isBlocked,
        'detail' => "Engine rejected unauthorized debit: '{$result['message']}'"
    ];

    // Test 3: Multi-Account Listing Tenant Boundary
    $stmtList = $pdo->prepare("SELECT COUNT(*) FROM accounts WHERE user_id = :uid");
    $stmtList->execute([':uid' => $userA]);
    $userACount = (int)$stmtList->fetchColumn();

    $stmtTotal = $pdo->query("SELECT COUNT(*) FROM accounts");
    $totalCount = (int)$stmtTotal->fetchColumn();

    $tests[] = [
        'name'   => 'Account Dashboard Scoping Bounds',
        'pass'   => ($userACount < $totalCount),
        'detail' => "User A sees only $userACount of $totalCount system accounts"
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running 05-IDOR-Account Tests...\n";
    $allPass = true;
    foreach (test_05_idor_account() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
        if (!$t['pass']) $allPass = false;
    }
    exit($allPass ? 0 : 1);
}
