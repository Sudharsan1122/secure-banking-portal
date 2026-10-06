<?php
/**
 * Transactions History API Endpoint
 * 
 * MODULE 5: XSS PROTECTION DEMONSTRATION
 * MODULE 8: SQL INJECTION PREVENTION
 * 
 * SECURITY PRINCIPLES IMPLEMENTED:
 * 1. Output Encoding: Demonstrates how user-controlled data (e.g. transaction remarks)
 *    must be escaped using htmlspecialchars() before insertion into HTML contexts.
 * 2. Parameterized Filters: Any search/filter keywords are bound via PDO parameters,
 *    never concatenated directly into the WHERE clause.
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../config/database.php';

$currentUser = require_auth();
$userId = $currentUser['id'];

$search   = trim($_GET['search'] ?? '');
$category = trim($_GET['category'] ?? '');
$limit    = min(100, max(1, (int)($_GET['limit'] ?? 50)));

// Detect potential injection vectors in query parameters
detect_sqli_payload($search, $userId);
detect_xss_payload($search, $userId);

try {
    $pdo = get_db();

    $sql = "SELECT t.id, t.sender_id, t.receiver_id, t.amount, t.remark, t.category, t.status, t.created_at,
                   s.name AS sender_name, s.username AS sender_username,
                   r.name AS receiver_name, r.username AS receiver_username
            FROM transactions t
            JOIN users s ON t.sender_id = s.id
            JOIN users r ON t.receiver_id = r.id
            WHERE (t.sender_id = :uid_sender OR t.receiver_id = :uid_receiver)";

    $params = [
        ':uid_sender'   => $userId,
        ':uid_receiver' => $userId
    ];

    if (!empty($search)) {
        $sql .= " AND (t.remark LIKE :search OR s.name LIKE :search OR r.name LIKE :search)";
        $params[':search'] = '%' . $search . '%';
    }

    if (!empty($category) && $category !== 'all') {
        $sql .= " AND t.category = :category";
        $params[':category'] = $category;
    }

    $sql .= " ORDER BY t.created_at DESC, t.id DESC LIMIT :limit";

    // Bind parameters cleanly
    $stmt = $pdo->prepare($sql);
    foreach ($params as $key => $val) {
        $stmt->bindValue($key, $val);
    }
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->execute();

    $rows = $stmt->fetchAll();

    $transactions = [];
    foreach ($rows as $row) {
        $isDebit = ((int)$row['sender_id'] === $userId);

        /**
         * ===============================================================
         * MODULE 5: ACADEMIC COMPARISON — VULNERABLE VS SECURE
         * ===============================================================
         * VULNERABLE CODE (Direct Output / Reflected/Stored XSS):
         *   echo "<td>" . $row['remark'] . "</td>";
         *   // If attacker submitted '<script>alert(document.cookie)</script>',
         *   // the browser executes arbitrary JavaScript in the victim's session!
         * 
         * SECURE CODE (Defense via Contextual HTML Escaping):
         *   $safeRemark = htmlspecialchars($row['remark'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
         *   echo "<td>" . $safeRemark . "</td>";
         *   // Neutralizes special HTML characters:
         *   // '<' becomes '&lt;', '>' becomes '&gt;', '"' becomes '&quot;'
         * ===============================================================
         */
        $safeRemark = safe_html($row['remark']);

        $transactions[] = [
            'id'                     => (int)$row['id'],
            'type'                   => $isDebit ? 'DEBIT' : 'CREDIT',
            'amount'                 => (float)$row['amount'],
            'counterparty'           => $isDebit ? safe_html($row['receiver_name']) : safe_html($row['sender_name']),
            'counterparty_username'  => $isDebit ? safe_html($row['receiver_username']) : safe_html($row['sender_username']),
            'category'               => safe_html($row['category'] ?? 'Transfer'),
            'remark'                 => $safeRemark,
            'raw_remark'             => $row['remark'], // Provided for DOM XSS demonstration
            'status'                 => $row['status'],
            'created_at'             => $row['created_at']
        ];
    }

    echo json_encode([
        'status' => 'success',
        'count'  => count($transactions),
        'data'   => $transactions
    ]);

} catch (Throwable $e) {
    error_log('Transactions API Error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to fetch transaction records.']);
}
