<?php
/**
 * Shared Executive Topbar & Navigation Component for Admin Portal
 * 
 * Provides unified, enterprise-grade fintech navigation across all SOC consoles:
 * - SIEM Dashboard (C1, C2, C3, C4, C5, C6)
 * - Alert Rules (C7)
 * - Audit Hash Chain (A12)
 * - User Directory (B9)
 * - Transactions & AML Review (B10)
 */

function render_admin_nav(string $activeTab, array $adminUser, string $csrfToken, string $cspNonce, int $unackCount = 0): void {
    $username = safe_html($adminUser['username'] ?? 'Admin');
    $initials = strtoupper(substr($username, 0, 2));
    if (strlen($initials) < 2) {
        $initials = 'AD';
    }
?>
<header class="admin-topbar">
    <div class="admin-topbar-inner">
        <div class="admin-brand-group">
            <div class="admin-logo-box">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9 12l2 2 4-4"/>
                </svg>
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
                <span class="admin-brand-name">SecureBank</span>
                <span class="admin-badge-soc">SOC SIEM</span>
            </div>
        </div>

        <nav class="admin-nav-tabs">
            <a href="security-dashboard.php" class="admin-tab-link <?= $activeTab === 'dashboard' ? 'active' : '' ?>">
                <svg class="admin-tab-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                <span>SIEM Dashboard</span>
            </a>
            <a href="alerts.php" class="admin-tab-link <?= $activeTab === 'alerts' ? 'active' : '' ?>">
                <svg class="admin-tab-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                <span>Alert Rules</span>
                <?php if ($unackCount > 0): ?>
                    <span style="background: #FEF2F2; color: #991B1B; border: 1px solid #FECACA; padding: 1px 7px; border-radius: 9999px; font-size: 0.7rem; font-weight: 700;"><?= $unackCount ?></span>
                <?php endif; ?>
            </a>
            <a href="verify_log_chain.php" class="admin-tab-link <?= $activeTab === 'chain' ? 'active' : '' ?>">
                <svg class="admin-tab-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                <span>Audit Chain</span>
            </a>
            <a href="users.php" class="admin-tab-link <?= $activeTab === 'users' ? 'active' : '' ?>">
                <svg class="admin-tab-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                <span>User Directory</span>
            </a>
            <a href="transactions.php" class="admin-tab-link <?= $activeTab === 'transactions' ? 'active' : '' ?>">
                <svg class="admin-tab-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
                <span>Transactions</span>
            </a>
        </nav>

        <div style="display: flex; align-items: center; gap: 12px;">
            <a href="../frontend/dashboard.html" class="btn btn-ghost btn-sm" style="font-size: 0.8125rem; color: #475569; font-weight: 500;">
                Client Portal ↗
            </a>
            <div class="admin-user-pill">
                <div class="admin-avatar-circle"><?= $initials ?></div>
                <div style="line-height: 1.2;">
                    <div style="font-size: 0.8125rem; font-weight: 700; color: #0F172A;"><?= $username ?></div>
                    <div style="font-size: 0.65rem; color: #64748B; text-transform: uppercase; font-weight: 600;">Superadmin</div>
                </div>
            </div>
            <button id="adminLogoutBtn" class="btn btn-outline btn-sm" style="padding: 6px 12px; font-size: 0.775rem;">
                Sign Out
            </button>
        </div>
    </div>
</header>
<script nonce="<?= htmlspecialchars($cspNonce) ?>">
document.getElementById('adminLogoutBtn')?.addEventListener('click', async () => {
    try {
        await fetch('../api/logout.php', { method: 'POST' });
    } finally {
        window.location.href = '../frontend/login.html';
    }
});
</script>
<?php
}
