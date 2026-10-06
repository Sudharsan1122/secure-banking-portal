<?php
/**
 * Admin Real-Time Transaction Monitor & Heuristic Triage
 * 
 * PILLAR B [B10]: ADMIN TRANSACTION MONITOR & SUSPICIOUS ACTIVITY REVIEW
 * 
 * Provides centralized SOC oversight across all transaction flows with automated
 * heuristic flagging (velocity bursts, round numbers, $50K thresholds) and triage workflow.
 */

require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/_admin_nav.php';

$admin = require_admin();
$csrfToken = get_csrf_token();
$cspNonce  = get_csp_nonce();

$filter = strtolower(trim($_GET['filter'] ?? 'all'));
$search = trim($_GET['q'] ?? '');
$page   = max(1, (int)($_GET['page'] ?? 1));
$perPage = 20;
$offset = ($page - 1) * $perPage;

$transactions = [];
$totalTxns = 0;
$totalPages = 1;

try {
    $pdo = get_db();

    $whereClauses = [];
    $params = [];

    if ($search !== '') {
        $whereClauses[] = "(t.id = :qid OR s.username LIKE :q1 OR r.username LIKE :q2 OR t.remark LIKE :q3)";
        $params[':qid'] = is_numeric($search) ? (int)$search : 0;
        $wildcard = "%$search%";
        $params[':q1'] = $wildcard;
        $params[':q2'] = $wildcard;
        $params[':q3'] = $wildcard;
    }

    if ($filter === 'flagged') {
        $whereClauses[] = "tr.id IS NOT NULL";
    } elseif ($filter === 'pending') {
        $whereClauses[] = "tr.outcome = 'pending'";
    } elseif ($filter === 'cleared') {
        $whereClauses[] = "tr.outcome = 'cleared'";
    } elseif ($filter === 'escalated') {
        $whereClauses[] = "tr.outcome = 'escalated'";
    }

    $whereSql = !empty($whereClauses) ? "WHERE " . implode(" AND ", $whereClauses) : "";

    $countStmt = $pdo->prepare(
        "SELECT COUNT(DISTINCT t.id)
         FROM transactions t
         JOIN users s ON t.sender_id = s.id
         JOIN users r ON t.receiver_id = r.id
         LEFT JOIN transaction_reviews tr ON tr.transaction_id = t.id
         $whereSql"
    );
    $countStmt->execute($params);
    $totalTxns = (int)$countStmt->fetchColumn();
    $totalPages = max(1, (int)ceil($totalTxns / $perPage));

    $query = "SELECT t.id, t.sender_id, t.receiver_id, t.amount, t.remark, t.category, t.status, t.created_at,
                     s.name AS sender_name, s.username AS sender_username,
                     r.name AS receiver_name, r.username AS receiver_username,
                     tr.id AS review_id, tr.flagged_reason, tr.outcome AS review_outcome, tr.notes AS review_notes,
                     u_rev.username AS reviewer_username
              FROM transactions t
              JOIN users s ON t.sender_id = s.id
              JOIN users r ON t.receiver_id = r.id
              LEFT JOIN transaction_reviews tr ON tr.transaction_id = t.id
              LEFT JOIN users u_rev ON tr.reviewed_by = u_rev.id
              $whereSql
              ORDER BY t.created_at DESC, t.id DESC
              LIMIT $perPage OFFSET $offset";

    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $transactions = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (Throwable $e) {
    error_log("Admin Transactions Load Error: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Transaction Monitor & Anomaly Triage — SecureBank SOC</title>
    <link rel="stylesheet" href="../css/style.css">
    <meta name="csrf-token" content="<?= safe_html($csrfToken) ?>">
</head>
<body class="soc-body">
    <?php render_admin_nav('transactions', $admin, $csrfToken, $cspNonce); ?>

    <main class="admin-shell">
        <!-- Page Hero -->
        <div class="admin-page-hero">
            <div>
                <h1 class="admin-page-title">Transaction Monitoring & Anomaly Triage</h1>
                <p class="admin-page-subtitle">Centralized heuristic AML tracking, velocity burst detection, and compliance auditor disposition workflow.</p>
            </div>
            <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                <span class="admin-badge admin-badge-active">
                    <?= $totalTxns ?> Matched Transactions
                </span>
                <span class="admin-badge admin-badge-user">
                    Page <?= $page ?> of <?= $totalPages ?>
                </span>
            </div>
        </div>

        <!-- Filter & Search Toolbar -->
        <form method="GET" action="transactions.php" class="admin-toolbar">
            <div class="admin-search-wrap">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
                    <circle cx="11" cy="11" r="8"/>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </svg>
                <input type="text" name="q" value="<?= safe_html($search) ?>" 
                       placeholder="Search by Txn ID, @sender, @receiver, or transfer remark..." 
                       class="admin-search-input">
            </div>

            <div style="display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap;">
                <select name="filter" class="admin-select">
                    <option value="all" <?= $filter === 'all' ? 'selected' : '' ?>>All Transactions</option>
                    <option value="flagged" <?= $filter === 'flagged' ? 'selected' : '' ?>>Flagged Anomaly Cases</option>
                    <option value="pending" <?= $filter === 'pending' ? 'selected' : '' ?>>Pending SOC Triage</option>
                    <option value="cleared" <?= $filter === 'cleared' ? 'selected' : '' ?>>Cleared by Compliance</option>
                    <option value="escalated" <?= $filter === 'escalated' ? 'selected' : '' ?>>Escalated (AML / Freeze)</option>
                </select>

                <button type="submit" class="btn btn-primary btn-sm">Filter</button>
                <?php if ($search !== '' || $filter !== 'all'): ?>
                    <a href="transactions.php" class="btn btn-outline btn-sm">Reset</a>
                <?php endif; ?>
            </div>
        </form>

        <!-- Transactions Table Card -->
        <div class="admin-table-wrap">
            <div class="admin-table-container">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>Txn ID</th>
                            <th>Timestamp</th>
                            <th>Transfer Flow</th>
                            <th>Category</th>
                            <th>Amount</th>
                            <th>Remark / Memo</th>
                            <th>Execution</th>
                            <th>Heuristic Review</th>
                            <th>Triage Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($transactions)): ?>
                            <tr>
                                <td colspan="9" style="text-align: center; padding: 3rem 1.5rem; color: #64748B;">
                                    <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                                        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color: #94A3B8;">
                                            <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
                                        </svg>
                                        <div style="font-weight: 600; color: #0F172A;">No transactions match criteria</div>
                                        <div style="font-size: 0.8125rem;">Try adjusting the status filter or clearing your search term.</div>
                                    </div>
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($transactions as $t): ?>
                                <tr>
                                    <td style="font-family: var(--font-mono); font-size: 0.8125rem; color: #64748B;">
                                        #<?= (int)$t['id'] ?>
                                    </td>
                                    <td style="font-family: var(--font-mono); font-size: 0.775rem; color: #64748B; white-space: nowrap;">
                                        <?= safe_html($t['created_at']) ?>
                                    </td>
                                    <td>
                                        <div style="font-size: 0.8125rem; display: flex; align-items: center; gap: 6px;">
                                            <span style="color: #1E5EFF; font-weight: 600; font-family: var(--font-mono);">@<?= safe_html($t['sender_username']) ?></span>
                                            <span style="color: #94A3B8;">&rarr;</span>
                                            <span style="color: #0F172A; font-weight: 600; font-family: var(--font-mono);">@<?= safe_html($t['receiver_username']) ?></span>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="admin-badge admin-badge-user" style="text-transform: capitalize;">
                                            <?= safe_html($t['category'] ?? 'transfer') ?>
                                        </span>
                                    </td>
                                    <td style="font-family: var(--font-mono); font-weight: 700; color: #0F172A; font-size: 0.9375rem;">
                                        $<?= number_format((float)$t['amount'], 2) ?>
                                    </td>
                                    <td style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.8125rem; color: #64748B;" title="<?= safe_html($t['remark'] ?? '') ?>">
                                        <?= safe_html($t['remark'] ?? '-') ?>
                                    </td>
                                    <td>
                                        <span class="admin-badge <?= $t['status'] === 'success' ? 'admin-badge-active' : 'admin-badge-critical' ?>">
                                            <?= strtoupper(safe_html($t['status'])) ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php if (!empty($t['review_id'])): ?>
                                            <?php 
                                                $outcome = $t['review_outcome'];
                                                $outcomeClass = 'admin-badge-pending';
                                                if ($outcome === 'cleared') $outcomeClass = 'admin-badge-cleared';
                                                elseif ($outcome === 'escalated') $outcomeClass = 'admin-badge-escalated';
                                            ?>
                                            <div>
                                                <span class="admin-badge <?= $outcomeClass ?>">
                                                    <?= strtoupper(safe_html($outcome)) ?>
                                                </span>
                                                <div style="font-size: 0.75rem; color: #B45309; margin-top: 3px; font-weight: 500;">
                                                    <?= safe_html($t['flagged_reason']) ?>
                                                </div>
                                            </div>
                                            <?php if (!empty($t['reviewer_username'])): ?>
                                                <div style="font-size: 0.7rem; color: #94A3B8; margin-top: 2px;">
                                                    By @<?= safe_html($t['reviewer_username']) ?>: <em><?= safe_html($t['review_notes']) ?></em>
                                                </div>
                                            <?php endif; ?>
                                        <?php else: ?>
                                            <span class="admin-badge admin-badge-low" style="font-size: 0.7rem;">✓ Standard / Low Risk</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if (!empty($t['review_id']) && $t['review_outcome'] === 'pending'): ?>
                                            <div class="admin-btn-group">
                                                <button class="admin-action-btn admin-action-btn-primary" 
                                                        data-action="adjudicate"
                                                        data-review-id="<?= (int)$t['review_id'] ?>"
                                                        data-outcome="cleared"
                                                        title="Approve and mark cleared">
                                                    ✓ Clear
                                                </button>
                                                <button class="admin-action-btn admin-action-btn-danger" 
                                                        data-action="adjudicate"
                                                        data-review-id="<?= (int)$t['review_id'] ?>"
                                                        data-outcome="escalated"
                                                        title="Escalate suspicious structuring or freeze account">
                                                    🚨 Escalate
                                                </button>
                                            </div>
                                        <?php elseif (!empty($t['review_id'])): ?>
                                            <span style="font-size: 0.75rem; color: #64748B;">Adjudicated</span>
                                        <?php else: ?>
                                            <span style="font-size: 0.75rem; color: #94A3B8;">—</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <!-- Pagination Bar -->
            <?php if ($totalPages > 1): ?>
                <div class="admin-pagination">
                    <div style="font-size: 0.8125rem; color: #64748B;">
                        Showing page <strong><?= $page ?></strong> of <strong><?= $totalPages ?></strong> (<?= $totalTxns ?> total transactions)
                    </div>
                    <div class="admin-pagination-links">
                        <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                            <a href="transactions.php?page=<?= $p ?>&q=<?= urlencode($search) ?>&filter=<?= urlencode($filter) ?>" 
                               class="admin-page-link <?= $p === $page ? 'active' : '' ?>">
                                <?= $p ?>
                            </a>
                        <?php endfor; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </main>

    <div id="toastContainer" class="toast-container"></div>

    <script src="../js/admin_transactions.js" nonce="<?= htmlspecialchars($cspNonce) ?>"></script>
</body>
</html>
