<?php
/**
 * User Accounts Directory API Endpoint
 * 
 * PILLAR B [B6]: MULTI-ACCOUNT SUPPORT (SAVINGS, CURRENT, FD)
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../config/database.php';

require_method('GET');
guard_parameter_pollution();

$currentUser = require_auth();
$userId = $currentUser['id'];

try {
    $pdo = get_db();

    $requestedAccountId = isset($_GET['account_id']) && is_numeric($_GET['account_id']) ? (int)$_GET['account_id'] : null;
    if ($requestedAccountId !== null && $requestedAccountId > 0) {
        $chkStmt = $pdo->prepare("SELECT user_id FROM accounts WHERE id = :id");
        $chkStmt->execute([':id' => $requestedAccountId]);
        $ownerId = $chkStmt->fetchColumn();
        if ($ownerId !== false && (int)$ownerId !== $userId) {
            require_once __DIR__ . '/../security/logger.php';
            log_security_event($userId, 'ACCESS_VIOLATION', 'BLOCKED', "IDOR attempt: User $userId tried to access account #$requestedAccountId owned by User $ownerId", 'high');
            http_response_code(403);
            echo json_encode(['status' => 'error', 'message' => 'Access Denied: You do not own this account.']);
            exit;
        }
    }

    $stmt = $pdo->prepare(
        "SELECT id, account_number, balance, currency, type, nickname, interest_rate, created_at 
         FROM accounts 
         WHERE user_id = :uid 
         ORDER BY id ASC"
    );
    $stmt->execute([':uid' => $userId]);
    $accounts = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $formatted = [];
    $totalBalance = 0.0;

    foreach ($accounts as $acc) {
        $bal = (float)$acc['balance'];
        $totalBalance += $bal;

        $formatted[] = [
            'id'             => (int)$acc['id'],
            'account_number' => safe_html($acc['account_number']),
            'balance'        => $bal,
            'currency'       => safe_html($acc['currency']),
            'type'           => safe_html($acc['type']),
            'nickname'       => safe_html($acc['nickname'] ?? ucfirst($acc['type']) . ' Account'),
            'interest_rate'  => (float)$acc['interest_rate'],
            'created_at'     => $acc['created_at']
        ];
    }

    echo json_encode([
        'status'        => 'success',
        'total_balance' => round($totalBalance, 2),
        'count'         => count($formatted),
        'data'          => $formatted
    ]);

} catch (Throwable $e) {
    error_log("Accounts API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to fetch user accounts.']);
}
