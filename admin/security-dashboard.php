<?php
/**
 * Security Operations Center (SOC) Advanced Monitoring Dashboard
 * 
 * PILLAR C INTEGRATION:
 * C1 — Real-Time Security Feed (SSE) with Graceful Polling Fallback
 * C2 — 4-Tier Threat Severity Levels (Low, Medium, High, Critical)
 * C3 — Heuristic Anomaly Detection & Suspicious Activity Panel
 * C4 — Dynamic User Security Posture Scores & Distribution Histogram
 * C5 — Prometheus Metrics Exporter Link
 * C6 — Audit Log Export (CSV & JSON with CWE-1236 Formula Defense)
 * C7 — Automated Alerting Engine & Incident Triage
 */

require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../security/alert_engine.php';
require_once __DIR__ . '/../security/anomaly_detector.php';
require_once __DIR__ . '/../security/security_score.php';
require_once __DIR__ . '/_admin_nav.php';

// Enforce admin role
$adminUser = require_admin();

$pdo = get_db();

// Handle AJAX Telemetry Polling (every 10s for non-SSE panels)
if (isset($_GET['action']) && $_GET['action'] === 'fetch_telemetry') {
    header('Content-Type: application/json; charset=utf-8');

    // 1. Severity Distribution
    $stmtSev = $pdo->query("SELECT severity, COUNT(*) as cnt FROM security_logs GROUP BY severity");
    $sevCounts = ['low' => 0, 'medium' => 0, 'high' => 0, 'critical' => 0];
    while ($r = $stmtSev->fetch(PDO::FETCH_ASSOC)) {
        $sevCounts[$r['severity']] = (int)$r['cnt'];
    }

    // 2. Active Sessions Estimate (past 15m)
    $stmtAct = $pdo->query("SELECT COUNT(DISTINCT user_id) FROM security_logs WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 15 MINUTE) AND user_id IS NOT NULL");
    $activeSessions = max(1, (int)$stmtAct->fetchColumn());

    // 3. Telemetry Payload
    $metrics = get_security_metrics();
    $metrics['active_sessions'] = $activeSessions;
    $metrics['severity'] = $sevCounts;

    $scoreDist = get_security_score_distribution();
    $anomalies = get_recent_anomalies(15);
    $alerts = get_recent_alerts(15);
    $unackCount = get_unacknowledged_alert_count();
    $chainStatus = verify_log_chain();

    echo json_encode([
        'status'       => 'success',
        'metrics'      => $metrics,
        'scores'       => $scoreDist,
        'anomalies'    => $anomalies,
        'alerts'       => $alerts,
        'unack_alerts' => $unackCount,
        'chain_valid'  => $chainStatus['verified'],
        'time'         => date('H:i:s')
    ]);
    exit;
}

// Initial Page Load Data
$metrics = get_security_metrics();
$stmtSev = $pdo->query("SELECT severity, COUNT(*) as cnt FROM security_logs GROUP BY severity");
$sevCounts = ['low' => 0, 'medium' => 0, 'high' => 0, 'critical' => 0];
while ($r = $stmtSev->fetch(PDO::FETCH_ASSOC)) {
    $sevCounts[$r['severity']] = (int)$r['cnt'];
}

$stmtAct = $pdo->query("SELECT COUNT(DISTINCT user_id) FROM security_logs WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 15 MINUTE) AND user_id IS NOT NULL");
$activeSessions = max(1, (int)$stmtAct->fetchColumn());

$scoreDist = get_security_score_distribution();
$anomalies = get_recent_anomalies(15);
$alerts = get_recent_alerts(15);
$unackCount = get_unacknowledged_alert_count();
$chainStatus = verify_log_chain();
$csrfToken = get_csrf_token();
$cspNonce = get_csp_nonce();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIEM & SOC Command Center — Secure Banking Portal</title>
    <link rel="stylesheet" href="../css/style.css">
    <meta name="csrf-token" content="<?= safe_html($csrfToken) ?>">
    <style nonce="<?= htmlspecialchars($cspNonce) ?>">
        /* SOC Theme & Layout Enhancements */
        :root {
            --sev-critical: #E5484D;
            --sev-high: #F5A623;
            --sev-medium: #F5A623;
            --sev-low: #1E5EFF;
        }
        body { background: var(--bg-app); color: var(--text-primary); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        .soc-container { max-width: 1440px; margin: 1.5rem auto; padding: 0 1.5rem; }
        
        /* Status Badges */
        .status-badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 9999px; font-weight: 700; font-size: 0.8rem; }
        .status-live { background: #EFF6FF; color: #1E5EFF; border: 1px solid #BFDBFE; }
        .status-reconnecting { background: #FFFBEB; color: #B45309; border: 1px solid #FDE68A; }
        .status-polling { background: #EFF6FF; color: #1E5EFF; border: 1px solid #BFDBFE; }
        .status-offline { background: #FEF2F2; color: #991B1B; border: 1px solid #FECACA; }
        
        .alert-pill-badge { background: #FEF2F2; color: #991B1B; border: 1px solid #FECACA; padding: 2px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; }
        
        /* Metric Grids */
        .metrics-grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1rem; }
        .metrics-grid-severity { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
        
        .soc-card { background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 1.25rem; box-shadow: 0 1px 2px rgba(15,23,42,0.04); }
        .soc-card-title { font-size: 0.8rem; text-transform: uppercase; color: #64748B; font-weight: 700; letter-spacing: 0.05em; }
        .soc-card-value { font-size: 2rem; font-weight: 800; margin: 0.25rem 0; color: #0F172A; }
        
        .sev-card-critical { border-left: 4px solid var(--sev-critical); }
        .sev-card-high { border-left: 4px solid var(--sev-high); }
        .sev-card-medium { border-left: 4px solid var(--sev-medium); }
        .sev-card-low { border-left: 4px solid var(--sev-low); }

        /* Severity Pills */
        .severity-pill { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
        .pill-critical { background: #FEF2F2; color: #991B1B; border: 1px solid #FECACA; }
        .pill-high { background: #FFF7ED; color: #C2410C; border: 1px solid #FFEDD5; }
        .pill-medium { background: #FFFBEB; color: #B45309; border: 1px solid #FEF3C7; }
        .pill-low { background: #EFF6FF; color: #1E5EFF; border: 1px solid #BFDBFE; }

        /* Two Column Main Feed & Alerts */
        .grid-two-column { display: grid; grid-template-columns: 1.2fr 0.8fr; gap: 1.5rem; margin-bottom: 1.5rem; }
        @media (max-width: 1024px) {
            .metrics-grid-4, .metrics-grid-severity, .grid-two-column { grid-template-columns: 1fr; }
        }

        /* Feed container */
        .feed-container { background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; height: 560px; overflow-y: auto; padding: 1rem; }
        .feed-event-row { background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 0.5rem; border-left: 4px solid #94A3B8; }
        .feed-event-row.severity-critical { border-left-color: var(--sev-critical); }
        .feed-event-row.severity-high { border-left-color: var(--sev-high); }
        .feed-event-row.severity-medium { border-left-color: var(--sev-medium); }
        .feed-event-row.severity-low { border-left-color: var(--sev-low); }

        .event-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem; font-size: 0.85rem; }
        .event-time { font-family: monospace; color: #64748B; }
        .event-type { font-weight: 700; color: #0F172A; }
        .event-meta { font-size: 0.8rem; font-family: monospace; color: #475569; }
        .event-details { margin: 0.25rem 0 0; font-size: 0.8rem; color: #64748B; word-break: break-all; font-family: monospace; }

        /* Score Histogram Bar */
        .hist-bar-container { display: flex; height: 18px; border-radius: 4px; overflow: hidden; background: #E2E8F0; margin: 0.5rem 0; }
        .hist-segment { height: 100%; transition: width 0.3s ease; }

        /* Modal */
        .soc-modal { display: none; position: fixed; inset: 0; background: rgba(15,23,42,0.5); z-index: 1000; align-items: center; justify-content: center; }
        .soc-modal-content { background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; width: 500px; max-width: 90%; padding: 1.5rem; box-shadow: 0 10px 25px rgba(0,0,0,0.1); }
    </style>
</head>
<body class="soc-body">
    <?php render_admin_nav('dashboard', $adminUser, $csrfToken, $cspNonce, $unackCount); ?>

    <main class="admin-shell">
        <!-- Executive Page Hero -->
        <div class="admin-page-hero">
            <div>
                <div class="admin-breadcrumb">
                    <span>Admin Operations</span>
                    <span>/</span>
                    <span style="color: #1E5EFF; font-weight: 600;">SIEM Command Center</span>
                </div>
                <h1 class="admin-page-title">Security Operations Center (SOC)</h1>
                <p class="admin-page-desc">Real-time threat observability, continuous cryptographic ledger audit, and automated SIEM threat triage.</p>
            </div>
            <div class="admin-actions-bar">
                <span id="sse-status-badge" class="status-badge status-live">● LIVE (SSE)</span>
                <?php if ($unackCount > 0): ?>
                    <span class="alert-pill-badge" id="activeAlertsBadge"><?= $unackCount ?> ACTIVE INCIDENTS</span>
                <?php else: ?>
                    <span class="status-badge status-live" id="activeAlertsBadge">0 ACTIVE ALERTS</span>
                <?php endif; ?>
                <button id="openExportModalBtn" class="btn btn-primary btn-sm">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    <span>Export Audit Logs</span>
                </button>
                <a href="verify_log_chain.php" class="btn btn-outline btn-sm">
                    <?= $chainStatus['verified'] ? '✓ Chain Intact' : '✕ Chain Tampered' ?>
                </a>
            </div>
        </div>

        <!-- Row 1: 4 Executive KPI Cards -->
        <div class="admin-kpi-grid">
            <div class="admin-kpi-card">
                <div class="admin-kpi-top">
                    <span class="admin-kpi-title">Logins Monitored</span>
                    <div class="admin-kpi-icon" style="background: #EFF6FF; color: #1E5EFF;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
                    </div>
                </div>
                <div class="admin-kpi-val" id="valTotalLogins"><?= (int)$metrics['total_logins'] ?></div>
                <div class="admin-kpi-sub">Primary credential authentications tracked</div>
            </div>

            <div class="admin-kpi-card">
                <div class="admin-kpi-top">
                    <span class="admin-kpi-title">Failed Logins (Brute Force)</span>
                    <div class="admin-kpi-icon" style="background: #FEF2F2; color: #B91C1C;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    </div>
                </div>
                <div class="admin-kpi-val" id="valFailedLogins" style="color: #B91C1C;"><?= (int)$metrics['failed_logins'] ?></div>
                <div class="admin-kpi-sub">Sliding-window lockout active</div>
            </div>

            <div class="admin-kpi-card">
                <div class="admin-kpi-top">
                    <span class="admin-kpi-title">Threats Intercepted</span>
                    <div class="admin-kpi-icon" style="background: #FFFBEB; color: #B45309;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </div>
                </div>
                <div class="admin-kpi-val" id="valBlockedThreats" style="color: #B45309;">
                    <?= (int)($metrics['blocked_sqli'] + $metrics['blocked_xss'] + $metrics['blocked_csrf'] + $metrics['blocked_traversal'] + $metrics['blocked_ssrf']) ?>
                </div>
                <div class="admin-kpi-sub">SQLi, XSS, CSRF, Path Traversal, SSRF</div>
            </div>

            <div class="admin-kpi-card">
                <div class="admin-kpi-top">
                    <span class="admin-kpi-title">Active Sessions</span>
                    <div class="admin-kpi-icon" style="background: #EFF6FF; color: #1E5EFF;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>
                    </div>
                </div>
                <div class="admin-kpi-val" id="valActiveSessions" style="color: #1E5EFF;"><?= $activeSessions ?></div>
                <div class="admin-kpi-sub">Dual-tier 15m idle / 8h absolute ceiling</div>
            </div>
        </div>

        <!-- Row 2: Severity Distribution Cards (C2) -->
        <div class="metrics-grid-severity">
            <div class="soc-card sev-card-critical">
                <div class="soc-card-title" style="color: #991B1B;">CRITICAL THREATS</div>
                <div class="soc-card-value" id="cntSevCritical" style="color: #991B1B;"><?= $sevCounts['critical'] ?></div>
                <span style="font-size: 0.75rem; color: #64748B;">SQLi, SSRF, Hash Tamper, Escalation</span>
            </div>
            <div class="soc-card sev-card-high">
                <div class="soc-card-title" style="color: #C2410C;">HIGH SEVERITY</div>
                <div class="soc-card-value" id="cntSevHigh" style="color: #C2410C;"><?= $sevCounts['high'] ?></div>
                <span style="font-size: 0.75rem; color: #64748B;">CSRF, XSS, Traversal, Anomalies</span>
            </div>
            <div class="soc-card sev-card-medium">
                <div class="soc-card-title" style="color: #B45309;">MEDIUM SEVERITY</div>
                <div class="soc-card-value" id="cntSevMedium" style="color: #B45309;"><?= $sevCounts['medium'] ?></div>
                <span style="font-size: 0.75rem; color: #64748B;">Rate limits, Failed OTPs, Password age</span>
            </div>
            <div class="soc-card sev-card-low">
                <div class="soc-card-title" style="color: #1E5EFF;">LOW SEVERITY</div>
                <div class="soc-card-value" id="cntSevLow" style="color: #1E5EFF;"><?= $sevCounts['low'] ?></div>
                <span style="font-size: 0.75rem; color: #64748B;">Routine successful transactions</span>
            </div>
        </div>

        <!-- Row 3: User Security Posture Scores (C4) -->
        <div class="soc-card" style="margin-bottom: 1.5rem;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h3 style="margin: 0; font-size: 1.1rem; color: #0F172A;">User Security Posture Distribution (C4)</h3>
                    <p style="margin: 2px 0 0; font-size: 0.85rem; color: #64748B;">
                        Dynamic 0–100 hygiene scoring measuring MFA adoption, password age, and recovery safeguards across all registered accounts.
                    </p>
                </div>
                <div style="text-align: right;">
                    <span style="font-size: 0.85rem; color: #64748B;">Average Score:</span>
                    <strong style="font-size: 1.5rem; color: #1E5EFF; margin-left: 6px;" id="avgScoreVal"><?= $scoreDist['average_score'] ?> / 100</strong>
                </div>
            </div>

            <!-- Distribution Histogram Bar -->
            <?php
                $tot = max(1, $scoreDist['total_users']);
                $pctRisk = round(($scoreDist['histogram']['at_risk'] / $tot) * 100, 1);
                $pctMod  = round(($scoreDist['histogram']['moderate'] / $tot) * 100, 1);
                $pctStr  = round(($scoreDist['histogram']['strong'] / $tot) * 100, 1);
                $pctExc  = round(($scoreDist['histogram']['exceptional'] / $tot) * 100, 1);
            ?>
            <div class="hist-bar-container" title="At Risk (<40): <?= $pctRisk ?>% | Moderate (40-69): <?= $pctMod ?>% | Strong (70-89): <?= $pctStr ?>% | Exceptional (90-100): <?= $pctExc ?>%">
                <div class="hist-segment" style="width: <?= $pctRisk ?>%; background: #F87171;"></div>
                <div class="hist-segment" style="width: <?= $pctMod ?>%; background: #FBBF24;"></div>
                <div class="hist-segment" style="width: <?= $pctStr ?>%; background: #60A5FA;"></div>
                <div class="hist-segment" style="width: <?= $pctExc ?>%; background: #1E5EFF;"></div>
            </div>

            <div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: #475569; margin-top: 0.25rem;">
                <span><span style="color:#F87171;">■</span> At Risk (0-39): <strong style="color: #0F172A;"><?= $scoreDist['histogram']['at_risk'] ?></strong> users</span>
                <span><span style="color:#FBBF24;">■</span> Moderate (40-69): <strong style="color: #0F172A;"><?= $scoreDist['histogram']['moderate'] ?></strong> users</span>
                <span><span style="color:#60A5FA;">■</span> Strong (70-89): <strong style="color: #0F172A;"><?= $scoreDist['histogram']['strong'] ?></strong> users</span>
                <span><span style="color:#1E5EFF;">■</span> Exceptional (90-100): <strong style="color: #0F172A;"><?= $scoreDist['histogram']['exceptional'] ?></strong> users</span>
            </div>
        </div>

        <!-- Row 4: Two Columns (Left: SSE Feed, Right: Suspicious Activity & Active Alerts) -->
        <div class="grid-two-column">
            <!-- Left Column: Live EventSource SSE Feed (C1 & C2) -->
            <div class="soc-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                    <div>
                        <h3 style="margin: 0; font-size: 1.1rem; color: #0F172A;">Real-Time Security Event Stream (C1)</h3>
                        <span style="font-size: 0.8rem; color: #64748B;" id="feed-count-badge">Streaming live telemetry via SSE</span>
                    </div>
                    <div style="display: flex; gap: 0.5rem; align-items: center;">
                        <label for="severity-filter" style="font-size: 0.8rem; color: #64748B;">Severity:</label>
                        <select id="severity-filter" style="background: #FFFFFF; border: 1px solid #CBD5E1; color: #0F172A; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem;">
                            <option value="all">All Levels</option>
                            <option value="critical">Critical Only</option>
                            <option value="high">High Only</option>
                            <option value="medium">Medium Only</option>
                            <option value="low">Low Only</option>
                        </select>
                    </div>
                </div>

                <!-- Feed Container (Managed by /js/soc_feed.js) -->
                <div class="feed-container" id="soc-feed-container">
                    <p style="color: #64748B; font-size: 0.85rem; text-align: center; margin-top: 2rem;">Connecting to real-time SSE event pipeline...</p>
                </div>
            </div>

            <!-- Right Column: Suspicious Activity (C3) & SIEM Alerts (C7) -->
            <div>
                <!-- Top Right: Active SIEM Alerts (C7) -->
                <div class="soc-card" style="margin-bottom: 1.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                        <h3 style="margin: 0; font-size: 1.05rem; color: #0F172A;">Active SIEM Incidents (C7)</h3>
                        <a href="alerts.php" style="font-size: 0.8rem; color: #1E5EFF; font-weight: 500;">Manage Rules →</a>
                    </div>
                    <div id="alertsPanelContainer" style="max-height: 250px; overflow-y: auto;">
                        <?php if (empty($alerts)): ?>
                            <p style="color: #64748B; font-size: 0.85rem;">No active alert incidents logged.</p>
                        <?php else: ?>
                            <?php foreach ($alerts as $a): ?>
                                <div style="border-bottom: 1px solid #E2E8F0; padding: 0.5rem 0; display: flex; justify-content: space-between; align-items: center;">
                                    <div>
                                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                                            <strong style="font-size: 0.85rem; color: #0F172A;"><?= htmlspecialchars($a['rule_name']) ?></strong>
                                            <span class="severity-pill pill-<?= htmlspecialchars($a['severity']) ?>"><?= strtoupper(htmlspecialchars($a['severity'])) ?></span>
                                        </div>
                                        <div style="font-size: 0.75rem; color: #64748B; margin-top: 2px;">
                                            <?= htmlspecialchars($a['triggered_at']) ?>
                                        </div>
                                    </div>
                                    <div>
                                        <?php if ($a['acknowledged']): ?>
                                            <span style="font-size: 0.75rem; color: #1E5EFF; font-weight: 600;">✓ Acknowledged</span>
                                        <?php else: ?>
                                            <button class="btn btn-outline btn-sm btn-ack-alert" data-id="<?= $a['id'] ?>" style="font-size: 0.75rem; padding: 2px 8px;">
                                                 Acknowledge
                                            </button>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Bottom Right: Heuristic Suspicious Activity Panel (C3) -->
                <div class="soc-card">
                    <h3 style="margin: 0 0 0.75rem; font-size: 1.05rem; color: #0F172A;">Heuristic Anomaly Detections (C3)</h3>
                    <div id="anomaliesPanelContainer" style="max-height: 240px; overflow-y: auto;">
                        <?php if (empty($anomalies)): ?>
                            <p style="color: #64748B; font-size: 0.85rem;">Zero statistical anomalies detected across active sessions.</p>
                        <?php else: ?>
                            <?php foreach ($anomalies as $anom): ?>
                                <?php $ctx = json_decode($anom['request'], true); ?>
                                <div style="border-bottom: 1px solid #E2E8F0; padding: 0.5rem 0;">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <strong style="font-size: 0.85rem; color: #C2410C;">
                                            <?= htmlspecialchars($ctx['anomaly_rule'] ?? 'ANOMALY') ?>
                                        </strong>
                                        <span class="severity-pill pill-<?= htmlspecialchars($anom['severity']) ?>"><?= strtoupper(htmlspecialchars($anom['severity'])) ?></span>
                                    </div>
                                    <div style="font-size: 0.8rem; color: #334155; margin: 2px 0;">
                                        <?= htmlspecialchars($ctx['description'] ?? $anom['request']) ?>
                                    </div>
                                    <div style="font-size: 0.75rem; color: #64748B; display: flex; justify-content: space-between;">
                                        <span>User: <?= htmlspecialchars($anom['username'] ?? 'Anonymous') ?> (IP: <?= htmlspecialchars($anom['ip_address']) ?>)</span>
                                        <span><?= htmlspecialchars($anom['timestamp']) ?></span>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Row 5: Actions, Audit Export (C6) & Prometheus Link (C5) -->
        <div class="soc-card" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
            <div style="display: flex; gap: 1rem; align-items: center;">
                <button id="openExportModalBtn" class="btn btn-primary btn-sm">📥 Export SIEM Audit Log (C6)</button>
                <a href="metrics.php" target="_blank" class="btn btn-secondary btn-sm">📊 Prometheus /metrics Endpoint (C5)</a>
                <a href="verify_log_chain.php" class="btn btn-outline btn-sm">
                    <?= $chainStatus['verified'] ? '✓ Hash Chain Valid (A12)' : '✕ Chain Tampered (A12)' ?>
                </a>
            </div>
            <div style="font-size: 0.85rem; color: #94a3b8;" id="lastPolledTimestamp">
                Auto-refreshing non-stream telemetry every 10 seconds
            </div>
        </div>
    </main>

    <!-- Audit Log Export Modal (C6) -->
    <div id="exportModal" class="soc-modal">
        <div class="soc-modal-content">
            <h3 style="margin-top: 0; color: #0F172A;">Export SIEM Audit Logs</h3>
            <p style="color: #64748B; font-size: 0.85rem; margin-bottom: 1rem;">
                Select date range and format. CSV exports include automated formula injection defense (CWE-1236).
            </p>
            <form id="exportForm" action="export_logs.php" method="GET" target="_blank">
                <div style="margin-bottom: 0.75rem;">
                    <label style="font-size: 0.85rem; color: #334155; display: block; font-weight: 500;">Format:</label>
                    <select name="format" style="width: 100%; padding: 8px; background: #FFFFFF; border: 1px solid #CBD5E1; color: #0F172A; border-radius: 6px; font-size: 0.85rem;">
                        <option value="csv">CSV (Spreadsheet Safe with Formula Escaping)</option>
                        <option value="json">JSON (Structured SIEM Feed)</option>
                    </select>
                </div>
                <div style="display: flex; gap: 0.5rem; margin-bottom: 0.75rem;">
                    <div style="flex: 1;">
                        <label style="font-size: 0.85rem; color: #334155; display: block; font-weight: 500;">From Date:</label>
                        <input type="date" name="from" value="<?= date('Y-m-d', strtotime('-30 days')) ?>" style="width: 100%; padding: 8px; background: #FFFFFF; border: 1px solid #CBD5E1; color: #0F172A; border-radius: 6px; font-size: 0.85rem;">
                    </div>
                    <div style="flex: 1;">
                        <label style="font-size: 0.85rem; color: #334155; display: block; font-weight: 500;">To Date:</label>
                        <input type="date" name="to" value="<?= date('Y-m-d') ?>" style="width: 100%; padding: 8px; background: #FFFFFF; border: 1px solid #CBD5E1; color: #0F172A; border-radius: 6px; font-size: 0.85rem;">
                    </div>
                </div>
                <div style="margin-bottom: 1.25rem;">
                    <label style="font-size: 0.85rem; color: #334155; display: block; font-weight: 500;">Severity Filter:</label>
                    <select name="severity" style="width: 100%; padding: 8px; background: #FFFFFF; border: 1px solid #CBD5E1; color: #0F172A; border-radius: 6px; font-size: 0.85rem;">
                        <option value="">All Severities</option>
                        <option value="critical">Critical Only</option>
                        <option value="high,critical">High & Critical</option>
                        <option value="medium,high,critical">Medium, High & Critical</option>
                    </select>
                </div>
                <div style="display: flex; justify-content: flex-end; gap: 0.5rem;">
                    <button type="button" id="closeExportModalBtn" class="btn btn-outline btn-sm">Cancel</button>
                    <button type="submit" class="btn btn-primary btn-sm">Download Export</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Scripts -->
    <script src="../js/soc_feed.js" nonce="<?= htmlspecialchars($cspNonce) ?>"></script>
    <script src="../js/admin_soc.js" nonce="<?= htmlspecialchars($cspNonce) ?>"></script>
</body>
</html>
