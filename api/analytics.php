<?php
/**
 * User Financial Analytics & Categorization Telemetry API Endpoint
 * 
 * PILLAR B [B1]: TRANSACTION CATEGORIES & ANALYTICS
 * 
 * Aggregates user spend by category, 6-month income vs. expense comparison,
 * and top 3 expenditure drivers for interactive Chart.js visualization.
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

    // 1. Spending by Category (Current User as Sender, Completed Transactions)
    $stmtCat = $pdo->prepare(
        "SELECT c.id, c.name, c.icon, c.color, COALESCE(SUM(t.amount), 0) AS total_amount, COUNT(t.id) AS txn_count
         FROM categories c
         JOIN transactions t ON t.category = c.name
         WHERE t.sender_id = :uid AND t.status = 'completed'
         GROUP BY c.id, c.name, c.icon, c.color
         ORDER BY total_amount DESC"
    );
    $stmtCat->execute([':uid' => $userId]);
    $catRows = $stmtCat->fetchAll(PDO::FETCH_ASSOC);

    // Calculate aggregate debit volume for percentages
    $totalDebits = 0.0;
    foreach ($catRows as $r) {
        $totalDebits += (float)$r['total_amount'];
    }

    $categorySpend = [];
    foreach ($catRows as $r) {
        $tot = (float)$r['total_amount'];
        $pct = ($totalDebits > 0) ? round(($tot / $totalDebits) * 100, 1) : 0.0;
        $categorySpend[] = [
            'id'         => (int)$r['id'],
            'name'       => safe_html($r['name']),
            'icon'       => safe_html($r['icon']),
            'color'      => safe_html($r['color']),
            'total'      => $tot,
            'percentage' => $pct,
            'count'      => (int)$r['txn_count']
        ];
    }

    // Top 3 spending categories
    $top3Categories = array_slice($categorySpend, 0, 3);

    // 2. 6-Month Income vs Expense Trend
    // Generate chronological map of past 6 months
    $months = [];
    for ($i = 5; $i >= 0; $i--) {
        $time = strtotime("-$i months");
        $key = date('Y-m', $time);
        $label = date('M Y', $time);
        $months[$key] = [
            'label'   => $label,
            'income'  => 0.0,
            'expense' => 0.0
        ];
    }

    // Fetch monthly expenses
    $stmtExp = $pdo->prepare(
        "SELECT DATE_FORMAT(created_at, '%Y-%m') AS mkey, SUM(amount) AS total
         FROM transactions
         WHERE sender_id = :uid AND status = 'completed' AND created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
         GROUP BY mkey"
    );
    $stmtExp->execute([':uid' => $userId]);
    while ($row = $stmtExp->fetch(PDO::FETCH_ASSOC)) {
        if (isset($months[$row['mkey']])) {
            $months[$row['mkey']]['expense'] = (float)$row['total'];
        }
    }

    // Fetch monthly income
    $stmtInc = $pdo->prepare(
        "SELECT DATE_FORMAT(created_at, '%Y-%m') AS mkey, SUM(amount) AS total
         FROM transactions
         WHERE receiver_id = :uid AND status = 'completed' AND created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
         GROUP BY mkey"
    );
    $stmtInc->execute([':uid' => $userId]);
    while ($row = $stmtInc->fetch(PDO::FETCH_ASSOC)) {
        if (isset($months[$row['mkey']])) {
            $months[$row['mkey']]['income'] = (float)$row['total'];
        }
    }

    $trendLabels = [];
    $incomeData  = [];
    $expenseData = [];
    foreach ($months as $m) {
        $trendLabels[] = $m['label'];
        $incomeData[]  = $m['income'];
        $expenseData[] = $m['expense'];
    }

    // 3. Overall Totals
    $stmtTotalIn = $pdo->prepare(
        "SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE receiver_id = :uid AND status = 'completed'"
    );
    $stmtTotalIn->execute([':uid' => $userId]);
    $totalCredits = (float)$stmtTotalIn->fetchColumn();

    echo json_encode([
        'status' => 'success',
        'data'   => [
            'summary' => [
                'total_spent'    => round($totalDebits, 2),
                'total_received' => round($totalCredits, 2),
                'net_flow'       => round($totalCredits - $totalDebits, 2)
            ],
            'categories' => $categorySpend,
            'top_categories' => $top3Categories,
            'trend' => [
                'labels'   => $trendLabels,
                'income'   => $incomeData,
                'expenses' => $expenseData
            ]
        ]
    ]);

} catch (Throwable $e) {
    error_log("Analytics API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to generate financial analytics.']);
}
