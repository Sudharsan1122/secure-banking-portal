<?php
/**
 * List Scheduled Transfers API Endpoint
 * 
 * PILLAR B [B2]: SCHEDULED / RECURRING TRANSFERS
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../config/database.php';

require_method('GET');
guard_parameter_pollution();

$currentUser = require_auth();
$userId = (int)$currentUser['id'];

try {
    $pdo = get_db();

    $stmt = $pdo->prepare(
        "SELECT st.id, st.amount, st.remark, st.category, st.frequency, st.next_run_at, 
                st.last_run_at, st.status, st.failure_count, st.created_at,
                a.account_number AS source_account, a.nickname AS source_nickname,
                b.name AS payee_name, b.account_number AS payee_account
         FROM scheduled_transfers st
         JOIN accounts a ON st.from_account_id = a.id
         JOIN beneficiaries b ON st.to_beneficiary_id = b.id
         WHERE st.user_id = :uid
         ORDER BY st.created_at DESC"
    );
    $stmt->execute([':uid' => $userId]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $transfers = [];
    foreach ($rows as $r) {
        $transfers[] = [
            'id'              => (int)$r['id'],
            'amount'          => (float)$r['amount'],
            'remark'          => safe_html($r['remark']),
            'category'        => safe_html($r['category']),
            'frequency'       => safe_html($r['frequency']),
            'next_run_at'     => $r['next_run_at'],
            'last_run_at'     => $r['last_run_at'],
            'status'          => safe_html($r['status']),
            'failure_count'   => (int)$r['failure_count'],
            'source_account'  => safe_html($r['source_account']),
            'source_nickname' => safe_html($r['source_nickname'] ?? 'Checking Account'),
            'payee_name'      => safe_html($r['payee_name']),
            'payee_account'   => safe_html($r['payee_account']),
            'created_at'      => $r['created_at']
        ];
    }

    echo json_encode([
        'status' => 'success',
        'data'   => $transfers
    ]);

} catch (Throwable $e) {
    error_log("Scheduled List API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to fetch scheduled transfers.']);
}
