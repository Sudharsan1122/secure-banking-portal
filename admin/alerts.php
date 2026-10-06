<?php
/**
 * SIEM Alert Rules Management Console
 * 
 * PILLAR C [C7]: ALERT RULES CONFIGURATION (SUPER-ADMIN ONLY)
 */

require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/_admin_nav.php';

$admin = require_role('admin');
$pdo = get_db();
$csrfToken = get_csrf_token();

// Handle Rule Updates (Super-Admin: id=1 only)
$actionMessage = '';
$actionError = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ((int)$admin['id'] !== 1) {
        $actionError = "Forbidden: Only Primary Super-Administrator (ID: 1) is permitted to modify SIEM alert policies.";
    } else {
        $action = $_POST['action'] ?? '';
        $ruleId = (int)($_POST['rule_id'] ?? 0);

        if ($action === 'toggle' && $ruleId > 0) {
            $stmt = $pdo->prepare("UPDATE alert_rules SET enabled = NOT enabled WHERE id = :id");
            $stmt->execute([':id' => $ruleId]);
            log_security_event($admin['id'], 'ALERT_RULE_MODIFIED', 'SUCCESS', "Toggled enabled state for rule #$ruleId", 'medium');
            $actionMessage = "Rule state updated successfully.";
        } elseif ($action === 'update' && $ruleId > 0) {
            $threshold = max(1, (int)($_POST['threshold'] ?? 1));
            $window = max(10, (int)($_POST['window_seconds'] ?? 60));
            $stmt = $pdo->prepare("UPDATE alert_rules SET threshold = :t, window_seconds = :w WHERE id = :id");
            $stmt->execute([':t' => $threshold, ':w' => $window, ':id' => $ruleId]);
            log_security_event($admin['id'], 'ALERT_RULE_MODIFIED', 'SUCCESS', "Updated threshold ($threshold) / window ({$window}s) for rule #$ruleId", 'medium');
            $actionMessage = "Rule parameters updated successfully.";
        }
    }
}

// Fetch all rules
$stmt = $pdo->query("SELECT * FROM alert_rules ORDER BY id ASC");
$rules = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Fetch recent active alerts
$stmtAlerts = $pdo->query("SELECT * FROM alerts ORDER BY id DESC LIMIT 15");
$recentAlerts = $stmtAlerts->fetchAll(PDO::FETCH_ASSOC);
$unackCount = 0;
foreach ($recentAlerts as $a) {
    if (empty($a['acknowledged'])) {
        $unackCount++;
    }
}
$cspNonce = get_csp_nonce();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIEM Alert Rules & Incidents — SecureBank SOC</title>
    <link rel="stylesheet" href="../css/style.css">
    <meta name="csrf-token" content="<?= safe_html($csrfToken) ?>">
</head>
<body class="soc-body">
    <?php render_admin_nav('alerts', $admin, $csrfToken, $cspNonce, $unackCount); ?>

    <main class="admin-shell">
        <div class="admin-page-hero">
            <div>
                <h1 class="admin-page-title">Automated SIEM Detection Policies</h1>
                <p class="admin-page-subtitle">
                    Real-time heuristic & signature threshold rules. Configured sliding windows trigger automated alerts and incident escalation.
                </p>
            </div>
            <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                <span class="admin-badge admin-badge-active">
                    <span style="display: inline-block; width: 6px; height: 6px; border-radius: 9999px; background: #1E5EFF;"></span>
                    SIEM Engine Active
                </span>
                <span class="admin-badge admin-badge-user">
                    <?= count($rules) ?> Configured Rules
                </span>
            </div>
        </div>

        <?php if (!empty($actionMessage)): ?>
            <div style="background: #EFF6FF; color: #1E5EFF; border: 1px solid #BFDBFE; padding: 12px 16px; border-radius: 8px; margin-bottom: 1.5rem; font-size: 0.875rem; font-weight: 500; display: flex; align-items: center; gap: 8px;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                <?= htmlspecialchars($actionMessage) ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($actionError)): ?>
            <div style="background: #FEF2F2; color: #991B1B; border: 1px solid #FECACA; padding: 12px 16px; border-radius: 8px; margin-bottom: 1.5rem; font-size: 0.875rem; font-weight: 500; display: flex; align-items: center; gap: 8px;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <?= htmlspecialchars($actionError) ?>
            </div>
        <?php endif; ?>

        <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem;" class="admin-alerts-layout">
            <!-- Left Column: Detection Rules -->
            <div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <h2 style="font-size: 1.125rem; font-weight: 700; color: #0F172A; margin: 0;">Configured Detection Rules (<?= count($rules) ?>)</h2>
                    <span style="font-size: 0.8125rem; color: #64748B;">Automated Sliding-Window Heuristics</span>
                </div>

                <?php foreach ($rules as $r): ?>
                    <?php 
                        $sevClass = 'admin-badge-low';
                        if ($r['severity'] === 'medium') $sevClass = 'admin-badge-medium';
                        elseif ($r['severity'] === 'high') $sevClass = 'admin-badge-high';
                        elseif ($r['severity'] === 'critical') $sevClass = 'admin-badge-critical';
                    ?>
                    <div class="admin-rule-card">
                        <div class="admin-rule-header">
                            <div class="admin-rule-title">
                                <span><?= htmlspecialchars($r['name']) ?></span>
                                <?php if ($r['enabled']): ?>
                                    <span class="admin-badge admin-badge-active">Active</span>
                                <?php else: ?>
                                    <span class="admin-badge admin-badge-user">Disabled</span>
                                <?php endif; ?>
                            </div>
                            <span class="admin-badge <?= $sevClass ?>">
                                <?= strtoupper(htmlspecialchars($r['severity'])) ?>
                            </span>
                        </div>
                        <div class="admin-rule-desc"><?= htmlspecialchars($r['description']) ?></div>
                        
                        <div class="admin-rule-meta">
                            <span>Target Event: <code style="font-family: var(--font-mono); font-size: 0.775rem; background: #FFFFFF; border: 1px solid #CBD5E1; padding: 2px 6px; border-radius: 4px; color: #1E5EFF;"><?= htmlspecialchars($r['event_type']) ?></code></span>
                            <span>Threshold: <strong style="color: #0F172A; font-family: var(--font-mono);">≥ <?= (int)$r['threshold'] ?></strong> events</span>
                            <span>Window: <strong style="color: #0F172A; font-family: var(--font-mono);"><?= (int)$r['window_seconds'] ?>s</strong> (<?= round($r['window_seconds'] / 60, 1) ?>m)</span>
                        </div>

                        <?php if ((int)$admin['id'] === 1): ?>
                            <div class="admin-rule-actions">
                                <form method="POST" style="margin: 0;">
                                    <input type="hidden" name="csrf_token" value="<?= safe_html($csrfToken) ?>">
                                    <input type="hidden" name="action" value="toggle">
                                    <input type="hidden" name="rule_id" value="<?= $r['id'] ?>">
                                    <button type="submit" class="admin-action-btn <?= $r['enabled'] ? '' : 'admin-action-btn-primary' ?>">
                                        <?= $r['enabled'] ? '⏸ Disable Policy' : '▶ Enable Policy' ?>
                                    </button>
                                </form>

                                <form method="POST" style="margin: 0; display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">
                                    <input type="hidden" name="csrf_token" value="<?= safe_html($csrfToken) ?>">
                                    <input type="hidden" name="action" value="update">
                                    <input type="hidden" name="rule_id" value="<?= $r['id'] ?>">
                                    <label style="font-size: 0.8rem; color: #64748B; font-weight: 500;">Threshold:</label>
                                    <input type="number" name="threshold" value="<?= (int)$r['threshold'] ?>" min="1" max="100" style="width: 60px; height: 32px; padding: 0 8px; background: #FFFFFF; border: 1px solid #CBD5E1; color: #0F172A; border-radius: 6px; font-family: var(--font-mono); font-size: 0.8125rem;">
                                    <label style="font-size: 0.8rem; color: #64748B; font-weight: 500;">Window (s):</label>
                                    <input type="number" name="window_seconds" value="<?= (int)$r['window_seconds'] ?>" min="10" max="3600" step="10" style="width: 70px; height: 32px; padding: 0 8px; background: #FFFFFF; border: 1px solid #CBD5E1; color: #0F172A; border-radius: 6px; font-family: var(--font-mono); font-size: 0.8125rem;">
                                    <button type="submit" class="admin-action-btn admin-action-btn-primary">Save Changes</button>
                                </form>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Right Column: Recent Incidents -->
            <div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <h2 style="font-size: 1.125rem; font-weight: 700; color: #0F172A; margin: 0;">Recent Incidents</h2>
                    <span class="admin-badge <?= $unackCount > 0 ? 'admin-badge-critical' : 'admin-badge-active' ?>">
                        <?= $unackCount ?> Unacknowledged
                    </span>
                </div>

                <div class="admin-card" style="padding: 1.25rem;">
                    <?php if (empty($recentAlerts)): ?>
                        <div style="text-align: center; padding: 2rem 1rem; color: #64748B;">
                            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color: #94A3B8; margin-bottom: 8px;">
                                <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
                            </svg>
                            <p style="margin: 0; font-size: 0.875rem;">No alerts recorded in database yet.</p>
                            <p style="margin: 4px 0 0; font-size: 0.775rem; color: #94A3B8;">All heuristic thresholds within safe baselines.</p>
                        </div>
                    <?php else: ?>
                        <div style="display: flex; flex-direction: column; gap: 0.875rem;">
                            <?php foreach ($recentAlerts as $a): ?>
                                <?php 
                                    $aSev = 'admin-badge-low';
                                    if ($a['severity'] === 'medium') $aSev = 'admin-badge-medium';
                                    elseif ($a['severity'] === 'high') $aSev = 'admin-badge-high';
                                    elseif ($a['severity'] === 'critical') $aSev = 'admin-badge-critical';
                                ?>
                                <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 12px; transition: all 0.15s ease;">
                                    <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 6px;">
                                        <strong style="color: #0F172A; font-size: 0.875rem;"><?= htmlspecialchars($a['rule_name']) ?></strong>
                                        <span class="admin-badge <?= $aSev ?>" style="font-size: 0.675rem;">
                                            <?= strtoupper(htmlspecialchars($a['severity'])) ?>
                                        </span>
                                    </div>
                                    <div style="display: flex; align-items: center; gap: 6px; font-size: 0.75rem; color: #64748B; font-family: var(--font-mono); margin-bottom: 6px;">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                                        <?= htmlspecialchars($a['triggered_at']) ?>
                                    </div>
                                    <div style="font-size: 0.775rem;">
                                        <?= $a['acknowledged'] ? '<span class="admin-badge admin-badge-active" style="font-size: 0.7rem;">✓ Acknowledged</span>' : '<span class="admin-badge admin-badge-medium" style="font-size: 0.7rem;">● Pending Triage</span>' ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </main>
</body>
</html>
