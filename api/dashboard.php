<?php
/**
 * Dashboard Data API Endpoint
 * 
 * MODULE 3: DASHBOARD
 * 
 * SECURITY PRINCIPLES IMPLEMENTED:
 * 1. Authentication Enforcement: require_auth() guarantees only verified sessions
 *    can access financial account summaries.
 * 2. Prepared Queries: Fetch user account and transactions safely without parameter concatenation.
 * 3. Output Sanitization: Escapes remarks with safe_html() (htmlspecialchars) while also
 *    preserving the raw remark field so that client-side JavaScript DOM rendering can be
 *    evaluated (preventing DOM XSS via textContent).
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/scheduler.php';
require_once __DIR__ . '/../config/database.php';

$currentUser = require_auth();
$userId = $currentUser['id'];

// Trigger zero-cron lazy scheduler for due recurring transfers
trigger_lazy_scheduler();

try {
    $pdo = get_db();

    // Fetch user profile and primary account
    $userStmt = $pdo->prepare(
        "SELECT u.id, u.name, u.email, u.phone, u.username, u.role, 
                a.account_number, a.balance, a.currency
         FROM users u
         LEFT JOIN accounts a ON a.user_id = u.id
         WHERE u.id = :id
         LIMIT 1"
    );
    $userStmt->execute([':id' => $userId]);
    $userData = $userStmt->fetch();

    if (!$userData) {
        http_response_code(404);
        echo json_encode(['status' => 'error', 'message' => 'Account record not found.']);
        exit;
    }

    // Fetch recent 5 transactions (both sent and received)
    $txnStmt = $pdo->prepare(
        "SELECT t.id, t.sender_id, t.receiver_id, t.amount, t.remark, t.status, t.created_at,
                s.name AS sender_name, s.username AS sender_username,
                r.name AS receiver_name, r.username AS receiver_username
         FROM transactions t
         JOIN users s ON t.sender_id = s.id
         JOIN users r ON t.receiver_id = r.id
         WHERE t.sender_id = :uid_sender OR t.receiver_id = :uid_receiver
         ORDER BY t.created_at DESC, t.id DESC
         LIMIT 5"
    );
    $txnStmt->execute([
        ':uid_sender'   => $userId,
        ':uid_receiver' => $userId
    ]);
    $rawTxns = $txnStmt->fetchAll();

    // Fetch all accounts owned by user
    $accStmt = $pdo->prepare(
        "SELECT id, account_number, balance, currency, type, nickname, interest_rate, created_at 
         FROM accounts 
         WHERE user_id = :uid 
         ORDER BY id ASC"
    );
    $accStmt->execute([':uid' => $userId]);
    $accounts = $accStmt->fetchAll(PDO::FETCH_ASSOC);

    $formattedAccounts = [];
    $totalBalance = 0.0;
    foreach ($accounts as $acc) {
        $bal = (float)$acc['balance'];
        $totalBalance += $bal;
        $formattedAccounts[] = [
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

    // Sanitize and structure transaction list
    $transactions = [];
    foreach ($rawTxns as $t) {
        $isDebit = ((int)$t['sender_id'] === $userId);
        
        /**
         * MODULE 5: XSS PROTECTION DEMONSTRATION
         * Notice: $t['remark'] is stored raw in the database.
         * We provide both:
         * 1) 'escaped_remark': Sanitized with htmlspecialchars($remark, ENT_QUOTES, 'UTF-8')
         * 2) 'raw_remark': For DOM XSS testing in educational demonstration
         */
        $safeRemark = safe_html($t['remark']);

        $transactions[] = [
            'id'             => (int)$t['id'],
            'type'           => $isDebit ? 'DEBIT' : 'CREDIT',
            'amount'         => (float)$t['amount'],
            'counterparty'   => $isDebit ? $t['receiver_name'] : $t['sender_name'],
            'counterparty_username' => $isDebit ? $t['receiver_username'] : $t['sender_username'],
            'remark'         => $safeRemark,
            'raw_remark'     => $t['remark'], // Demo comparison for XSS lab
            'status'         => $t['status'],
            'created_at'     => $t['created_at']
        ];
    }

    // Return dashboard payload
    http_response_code(200);
    echo json_encode([
        'status' => 'success',
        'data'   => [
            'user' => [
                'id'             => (int)$userData['id'],
                'name'           => safe_html($userData['name']),
                'email'          => safe_html($userData['email']),
                'phone'          => safe_html($userData['phone']),
                'username'       => safe_html($userData['username']),
                'role'           => $userData['role'],
                'account_number' => safe_html($userData['account_number']),
                'balance'        => (float)$userData['balance'],
                'total_balance'  => round($totalBalance, 2),
                'currency'       => safe_html($userData['currency'] ?? 'USD')
            ],
            'accounts'            => $formattedAccounts,
            'recent_transactions' => $transactions,
            'csrf_token'          => get_csrf_token()
        ]
    ]);

} catch (Throwable $e) {
    error_log('Dashboard API Error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to load dashboard data.']);
}
