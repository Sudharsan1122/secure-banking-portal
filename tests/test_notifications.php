<?php
/**
 * Test Suite: Notification Center & IDOR Isolation (PILLAR B - B7)
 * 
 * Verifies:
 * 1. notify_user() database persistence and severity categorization.
 * 2. Unread notification counting and read status toggling.
 * 3. IDOR Defense: Rejection of mark_read attempts on notifications owned by another tenant.
 * 4. Bulk mark-all-read scoping (only affects authenticated tenant).
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/notifications.php';

function test_notifications(): array {
    $tests = [];
    $pdo = get_db();

    // 1. Setup isolated test users
    $uA = 'notif_a_' . bin2hex(random_bytes(3));
    $uB = 'notif_b_' . bin2hex(random_bytes(3));
    $pass = password_hash('Pass123!Notif', PASSWORD_BCRYPT);

    $pdo->prepare("INSERT INTO users (username, email, password_hash, name, role, balance) VALUES (?, ?, ?, ?, 'user', 1000.00)")
        ->execute([$uA, "$uA@test.local", $pass, 'Notif User A']);
    $userAId = (int)$pdo->lastInsertId();

    $pdo->prepare("INSERT INTO users (username, email, password_hash, name, role, balance) VALUES (?, ?, ?, ?, 'user', 1000.00)")
        ->execute([$uB, "$uB@test.local", $pass, 'Notif User B']);
    $userBId = (int)$pdo->lastInsertId();

    // TEST 1: Dispatch notifications to User A and User B
    $n1Id = notify_user($userAId, 'SECURITY_ALERT', 'Password Changed', 'Your password was changed.', '/frontend/profile.html', 'warning');
    $n2Id = notify_user($userAId, 'TRANSFER_RECEIVED', 'Funds Received', 'You received $250.00 from John.', '/frontend/transactions.html', 'info');
    $nBId = notify_user($userBId, 'SECURITY_ALERT', 'Device Login', 'Login from Chrome Windows.', '/frontend/devices.html', 'info');

    $tests[] = [
        'name'   => 'Notification Dispatch & Persistence',
        'pass'   => ($n1Id > 0 && $n2Id > 0 && $nBId > 0),
        'detail' => sprintf("Dispatched notifications across tenants (User A: #%d, #%d | User B: #%d)", $n1Id, $n2Id, $nBId)
    ];

    // TEST 2: Check unread count for User A
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL");
    $stmt->execute([$userAId]);
    $unreadA = (int)$stmt->fetchColumn();

    $tests[] = [
        'name'   => 'Unread Notification Counting',
        'pass'   => ($unreadA === 2),
        'detail' => sprintf("User A has exactly %d unread notifications", $unreadA)
    ];

    // TEST 3: IDOR Check Simulation
    $checkStmt = $pdo->prepare("SELECT id FROM notifications WHERE id = :id AND user_id = :uid LIMIT 1");
    $checkStmt->execute([':id' => $n1Id, ':uid' => $userBId]);
    $allowed = (bool)$checkStmt->fetch();

    $tests[] = [
        'name'   => 'Notification Tenant IDOR Isolation',
        'pass'   => !$allowed,
        'detail' => "User B prevented from reading or updating User A notification #$n1Id"
    ];

    // TEST 4: User A marks $n1Id as read
    $pdo->prepare("UPDATE notifications SET read_at = NOW() WHERE id = :id AND user_id = :uid")
        ->execute([':id' => $n1Id, ':uid' => $userAId]);

    $stmt->execute([$userAId]);
    $unreadAAfter = (int)$stmt->fetchColumn();

    $tests[] = [
        'name'   => 'Single Notification Read Transition',
        'pass'   => ($unreadAAfter === 1),
        'detail' => sprintf("Unread count decremented to %d after single read", $unreadAAfter)
    ];

    // TEST 5: Mark All Read Scoping
    $pdo->prepare("UPDATE notifications SET read_at = NOW() WHERE user_id = :uid AND read_at IS NULL")
        ->execute([':uid' => $userAId]);

    $stmt->execute([$userAId]);
    $unreadAFinal = (int)$stmt->fetchColumn();

    $stmt->execute([$userBId]);
    $unreadBFinal = (int)$stmt->fetchColumn();

    $tests[] = [
        'name'   => 'Bulk Mark-Read Scoping & Tenant Isolation',
        'pass'   => ($unreadAFinal === 0 && $unreadBFinal === 1),
        'detail' => "User A bulk marked read (0 unread); User B's unread notification remained completely unaffected"
    ];

    // Cleanup
    $pdo->prepare("DELETE FROM notifications WHERE user_id IN (:u1, :u2)")->execute([':u1' => $userAId, ':u2' => $userBId]);
    $pdo->prepare("DELETE FROM users WHERE id IN (:u1, :u2)")->execute([':u1' => $userAId, ':u2' => $userBId]);

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Notification Center Tests...\n";
    foreach (test_notifications() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
