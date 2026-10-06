<?php
/**
 * Admin User Management Interface
 * 
 * PILLAR B [B9]: ADMIN USER DIRECTORY, ACCOUNT FREEZING, VELOCITY LIMIT CONFIGURATION
 * 
 * SECURITY PRINCIPLES IMPLEMENTED:
 * 1. Role-Based Access Control (RBAC): Enforced via require_admin().
 * 2. Super-Admin Role Separation: Only superadmins can freeze administrative peers.
 * 3. Search & Pagination: Bounded SQL offset/limit to prevent memory exhaustion DoS.
 * 4. Prepared Statements: All search terms sanitized and bound via PDO parameters.
 * 5. Contextual Escaping: All fields escaped with safe_html() to prevent Stored XSS.
 */

require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/_admin_nav.php';

$adminUser = require_admin();
$adminId   = (int)$adminUser['id'];
$adminRole = $adminUser['role'];
$csrfToken = get_csrf_token();
$cspNonce  = get_csp_nonce();

// Pagination & Filter Parameters
$searchQuery = trim($_GET['q'] ?? '');
$statusFilter = strtolower(trim($_GET['status'] ?? 'all'));
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 15;
$offset = ($page - 1) * $perPage;

$users = [];
$totalUsers = 0;
$totalPages = 1;

try {
    $pdo = get_db();

    // Construct dynamic filtered query
    $whereClauses = [];
    $params = [];

    if ($searchQuery !== '') {
        $whereClauses[] = "(u.name LIKE :q1 OR u.username LIKE :q2 OR u.email LIKE :q3)";
        $wildcard = "%$searchQuery%";
        $params[':q1'] = $wildcard;
        $params[':q2'] = $wildcard;
        $params[':q3'] = $wildcard;
    }

    if ($statusFilter === 'active' || $statusFilter === 'frozen') {
        $whereClauses[] = "u.status = :status";
        $params[':status'] = $statusFilter;
    }

    $whereSql = !empty($whereClauses) ? "WHERE " . implode(" AND ", $whereClauses) : "";

    // Count total matches
    $countStmt = $pdo->prepare("SELECT COUNT(*) FROM users u $whereSql");
    $countStmt->execute($params);
    $totalUsers = (int)$countStmt->fetchColumn();
    $totalPages = max(1, (int)ceil($totalUsers / $perPage));

    // Fetch paginated page
    $selectSql = "SELECT u.id, u.name, u.email, u.phone, u.username, u.role, u.status, u.balance,
                         u.limit_single, u.limit_daily, u.limit_monthly, u.created_at,
                         a.account_number, a.currency
                  FROM users u
                  LEFT JOIN accounts a ON a.user_id = u.id AND a.type = 'savings'
                  $whereSql
                  GROUP BY u.id
                  ORDER BY u.id ASC
                  LIMIT $perPage OFFSET $offset";

    $stmt = $pdo->prepare($selectSql);
    $stmt->execute($params);
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (Throwable $e) {
    error_log('Admin Users Load Error: ' . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Directory & Privilege Controls — SecureBank SOC</title>
    <link rel="stylesheet" href="../css/style.css">
    <meta name="csrf-token" content="<?= safe_html($csrfToken) ?>">
</head>
<body class="soc-body">
    <?php render_admin_nav('users', $adminUser, $csrfToken, $cspNonce); ?>

    <main class="admin-shell">
        <!-- Page Hero -->
        <div class="admin-page-hero">
            <div>
                <h1 class="admin-page-title">User Directory & Privilege Controls</h1>
                <p class="admin-page-subtitle">Manage customer accounts, velocity thresholds, account freeze enforcement, and credential provisioning.</p>
            </div>
            <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                <span class="admin-badge admin-badge-active">
                    <?= $totalUsers ?> Registered Accounts
                </span>
                <span class="admin-badge admin-badge-user">
                    Page <?= $page ?> of <?= $totalPages ?>
                </span>
            </div>
        </div>

        <!-- Filter & Search Toolbar -->
        <form method="GET" action="users.php" class="admin-toolbar">
            <div class="admin-search-wrap">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
                    <circle cx="11" cy="11" r="8"/>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </svg>
                <input type="text" name="q" value="<?= safe_html($searchQuery) ?>" 
                       placeholder="Search by full name, @username, or email address..." 
                       class="admin-search-input">
            </div>

            <div style="display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap;">
                <select name="status" class="admin-select">
                    <option value="all" <?= $statusFilter === 'all' ? 'selected' : '' ?>>All Account Statuses</option>
                    <option value="active" <?= $statusFilter === 'active' ? 'selected' : '' ?>>Active Only</option>
                    <option value="frozen" <?= $statusFilter === 'frozen' ? 'selected' : '' ?>>Frozen Only</option>
                </select>

                <button type="submit" class="btn btn-primary btn-sm">Filter</button>
                <?php if ($searchQuery !== '' || $statusFilter !== 'all'): ?>
                    <a href="users.php" class="btn btn-outline btn-sm">Reset</a>
                <?php endif; ?>
            </div>
        </form>

        <!-- Users Table Card -->
        <div class="admin-table-wrap">
            <div class="admin-table-container">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>Account ID</th>
                            <th>Customer Identity</th>
                            <th>Primary Account</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Ledger Balance</th>
                            <th>Velocity Limits</th>
                            <th>Enrolled</th>
                            <th>Administrative Controls</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($users)): ?>
                            <tr>
                                <td colspan="9" style="text-align: center; padding: 3rem 1.5rem; color: #64748B;">
                                    <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                                        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color: #94A3B8;">
                                            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                                        </svg>
                                        <div style="font-weight: 600; color: #0F172A;">No matching accounts located</div>
                                        <div style="font-size: 0.8125rem;">Try modifying your search keywords or resetting the status filter.</div>
                                    </div>
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($users as $u): ?>
                                <?php 
                                    $isSelf = ((int)$u['id'] === $adminId);
                                    $isTargetAdmin = ($u['role'] === 'admin');
                                    $isFrozen = ($u['status'] === 'frozen');
                                    $canModify = (!$isSelf && (!$isTargetAdmin || $adminRole === 'superadmin'));
                                    
                                    $nameStr = trim($u['name'] ?? '');
                                    $initials = strtoupper(substr($nameStr !== '' ? $nameStr : $u['username'], 0, 2));
                                ?>
                                <tr>
                                    <td style="font-family: var(--font-mono); font-size: 0.8125rem; color: #64748B;">
                                        #<?= (int)$u['id'] ?>
                                    </td>
                                    <td>
                                        <div class="admin-user-cell">
                                            <div class="admin-avatar-sm"><?= $initials ?></div>
                                            <div>
                                                <div style="font-weight: 600; color: #0F172A;"><?= safe_html($u['name']) ?></div>
                                                <div style="font-size: 0.775rem; color: #64748B; font-family: var(--font-mono);">
                                                    @<?= safe_html($u['username']) ?> &bull; <?= safe_html($u['email']) ?>
                                                </div>
                                            </div>
                                        </div>
                                    </td>
                                    <td style="font-family: var(--font-mono); font-size: 0.8125rem; color: #334155;">
                                        <?= safe_html($u['account_number'] ?? 'N/A') ?>
                                    </td>
                                    <td>
                                        <span class="admin-badge <?= $u['role'] === 'admin' ? 'admin-badge-admin' : 'admin-badge-user' ?>">
                                            <?= strtoupper(safe_html($u['role'])) ?>
                                        </span>
                                    </td>
                                    <td>
                                        <span class="admin-badge <?= $isFrozen ? 'admin-badge-frozen' : 'admin-badge-active' ?>">
                                            <?= $isFrozen ? '❄️ FROZEN' : 'ACTIVE' ?>
                                        </span>
                                    </td>
                                    <td style="font-weight: 700; color: #0F172A; font-family: var(--font-mono); font-size: 0.9375rem;">
                                        $<?= number_format((float)$u['balance'], 2) ?>
                                    </td>
                                    <td>
                                        <div style="font-family: var(--font-mono); font-size: 0.75rem; color: #64748B; line-height: 1.45;">
                                            <div><span style="color: #94A3B8;">1x:</span> $<?= number_format((float)($u['limit_single'] ?? 100000), 0) ?></div>
                                            <div><span style="color: #94A3B8;">Day:</span> $<?= number_format((float)($u['limit_daily'] ?? 200000), 0) ?></div>
                                            <div><span style="color: #94A3B8;">Mo:</span> $<?= number_format((float)($u['limit_monthly'] ?? 100000), 0) ?></div>
                                        </div>
                                    </td>
                                    <td style="font-family: var(--font-mono); font-size: 0.75rem; color: #64748B;">
                                        <?= substr($u['created_at'], 0, 10) ?>
                                    </td>
                                    <td>
                                        <div class="admin-btn-group">
                                            <?php if ($canModify): ?>
                                                <button class="admin-action-btn <?= $isFrozen ? 'admin-action-btn-primary' : 'admin-action-btn-danger' ?>" 
                                                        data-action="freeze"
                                                        data-user-id="<?= (int)$u['id'] ?>"
                                                        data-frozen="<?= $isFrozen ? 'false' : 'true' ?>"
                                                        title="<?= $isFrozen ? 'Restore normal transaction capability' : 'Freeze outgoing transfers' ?>">
                                                    <?= $isFrozen ? 'Unfreeze' : 'Freeze' ?>
                                                </button>

                                                <button class="admin-action-btn" 
                                                        data-action="limits"
                                                        data-user-id="<?= (int)$u['id'] ?>"
                                                        data-single="<?= (float)($u['limit_single'] ?? 100000) ?>"
                                                        data-daily="<?= (float)($u['limit_daily'] ?? 200000) ?>"
                                                        data-monthly="<?= (float)($u['limit_monthly'] ?? 1000000) ?>"
                                                        title="Adjust velocity limits">
                                                    Limits
                                                </button>

                                                <button class="admin-action-btn" 
                                                        data-action="reset"
                                                        data-user-id="<?= (int)$u['id'] ?>"
                                                        data-username="<?= safe_html($u['username']) ?>"
                                                        title="Force cryptographic password reset">
                                                    Reset
                                                </button>
                                            <?php elseif ($isSelf): ?>
                                                <span class="admin-badge admin-badge-active" style="font-size: 0.7rem;">Your Session</span>
                                            <?php else: ?>
                                                <span class="admin-badge admin-badge-user" style="font-size: 0.7rem;">Peer Protected</span>
                                            <?php endif; ?>
                                        </div>
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
                        Showing page <strong><?= $page ?></strong> of <strong><?= $totalPages ?></strong> (<?= $totalUsers ?> total accounts)
                    </div>
                    <div class="admin-pagination-links">
                        <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                            <a href="users.php?page=<?= $p ?>&q=<?= urlencode($searchQuery) ?>&status=<?= urlencode($statusFilter) ?>" 
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

    <script src="../js/admin_users.js" nonce="<?= htmlspecialchars($cspNonce) ?>"></script>
</body>
</html>
