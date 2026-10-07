<?php
/**
 * Cryptographic Audit Log Chain Verifier & Tamper Demonstration
 * 
 * PILLAR A [A12]: AUDIT LOG TAMPER-PROOFING (HASH CHAIN VERIFICATION)
 * PILLAR C: OBSERVABILITY & NON-REPUDIATION VERIFICATION
 */

require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/_admin_nav.php';

// Enforce Administrator Authorization
$admin = require_admin();

$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

// POST: Simulate or repair tamper for academic demonstration
if ($method === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    require_csrf_token();
    $rawInput = file_get_contents('php://input');
    $input = json_decode($rawInput, true) ?: $_POST;
    $action = $input['action'] ?? '';

    try {
        $pdo = get_db();

        // 1. Simulate SQL Tampering (Manipulate a row's payload directly without updating hash)
        if ($action === 'simulate_tamper') {
            $stmt = $pdo->query("SELECT id FROM security_logs ORDER BY id DESC LIMIT 1");
            $lastId = $stmt->fetchColumn();

            if ($lastId) {
                $tamperStmt = $pdo->prepare("UPDATE security_logs SET request = 'TAMPERED_BY_SQL_INJECTION_DEMO' WHERE id = :id");
                $tamperStmt->execute([':id' => $lastId]);

                echo json_encode([
                    'status'  => 'success',
                    'message' => "Simulated direct database tampering on log row #$lastId. Run verification to observe broken chain detection!"
                ]);
                exit;
            }
        }

        // 2. Repair Hash Chain (Recompute hashes from beginning)
        if ($action === 'repair_chain') {
            $stmt = $pdo->query("SELECT * FROM security_logs ORDER BY id ASC");
            $rows = $stmt->fetchAll();

            $prevHash = defined('GENESIS_HASH') ? GENESIS_HASH : '0000000000000000000000000000000000000000000000000000000000000000';

            foreach ($rows as $index => $r) {
                $hashMaterial = sprintf(
                    '%s|%s|%s|%s|%s|%s|%s|%s',
                    $prevHash,
                    $r['timestamp'],
                    $r['user_id'] !== null ? (string)$r['user_id'] : 'NULL',
                    $r['event_type'],
                    $r['severity'],
                    $r['ip_address'],
                    $r['status'],
                    $r['request']
                );
                $currHash = hash('sha256', $hashMaterial);

                $updateStmt = $pdo->prepare("UPDATE security_logs SET prev_hash = :prev, curr_hash = :curr WHERE id = :id");
                $updateStmt->execute([':prev' => $prevHash, ':curr' => $currHash, ':id' => $r['id']]);

                $prevHash = $currHash;
            }

            echo json_encode([
                'status'  => 'success',
                'message' => 'Cryptographic hash chain successfully repaired across ' . count($rows) . ' records.'
            ]);
            exit;
        }

        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Unknown action.']);

    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
    exit;
}

// GET: Run verification
$result = verify_log_chain();

// Check if JSON response is expected (API client or curl)
$isJson = isset($_GET['format']) && $_GET['format'] === 'json' ||
          (!str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'text/html') && isset($_SERVER['HTTP_ACCEPT']));

if ($isJson) {
    header('Content-Type: application/json; charset=utf-8');
    if ($result['verified']) {
        http_response_code(200);
        echo json_encode([
            'status'         => 'valid',
            'success'        => true,
            'chain_status'   => 'VERIFIED_INTACT',
            'total_records'  => $result['total_records'],
            'latest_hash'    => $result['latest_hash'] ?? 'N/A',
            'message'        => 'All audit log records verified against cryptographic SHA-256 hash chain.'
        ]);
    } else {
        http_response_code(409);
        echo json_encode([
            'status'        => 'error',
            'chain_status'  => 'TAMPERING_DETECTED',
            'broken_id'     => $result['broken_id'] ?? null,
            'reason'        => $result['reason'] ?? 'Cryptographic digest mismatch detected.',
            'message'       => 'CRITICAL ALERT: Audit log tampering detected! Database row integrity compromised.'
        ]);
    }
    exit;
}

// Otherwise, render full HTML verification console
$csrfToken = get_csrf_token();
$cspNonce  = get_csp_nonce();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cryptographic Hash Chain Integrity — SecureBank SOC</title>
    <link rel="stylesheet" href="../css/style.css">
    <meta name="csrf-token" content="<?= safe_html($csrfToken) ?>">
</head>
<body class="soc-body">
    <?php render_admin_nav('chain', $admin, $csrfToken, $cspNonce); ?>

    <main class="soc-container" style="max-width: 1200px; margin: 1.5rem auto; padding: 0 1.5rem;">
        <!-- Executive Page Hero -->
        <div class="admin-page-hero">
            <div>
                <div class="admin-breadcrumb">
                    <span>Admin Operations</span>
                    <span>/</span>
                    <span style="color: #1E5EFF; font-weight: 600;">Cryptographic Verification</span>
                </div>
                <h1 class="admin-page-title">Audit Log Hash Chain Integrity (A12)</h1>
                <p class="admin-page-desc">Sequential SHA-256 non-repudiation pointers mathematically proving database zero-tamper integrity.</p>
            </div>
            <div class="admin-actions-bar">
                <span class="badge badge-info" style="font-size: 0.8125rem; padding: 6px 12px;">
                    Audited Blocks: <?= (int)($result['total_records'] ?? 0) ?>
                </span>
                <a href="verify_log_chain.php" class="btn btn-outline btn-sm">
                    🔄 Re-Verify Ledger
                </a>
            </div>
        </div>

        <!-- Chain Integrity Status Hero Card -->
        <div class="admin-card" style="margin-bottom: 1.5rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; border-bottom: 1px solid #E2E8F0; padding-bottom: 1.25rem;">
                <div style="display: flex; align-items: center; gap: 14px;">
                    <div style="width: 48px; height: 48px; border-radius: 12px; background: <?= $result['verified'] ? '#EFF6FF' : '#FEF2F2' ?>; color: <?= $result['verified'] ? '#1E5EFF' : '#991B1B' ?>; display: flex; align-items: center; justify-content: center;">
                        <?php if ($result['verified']): ?>
                            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                        <?php else: ?>
                            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                        <?php endif; ?>
                    </div>
                    <div>
                        <div style="font-size: 1.15rem; font-weight: 700; color: #0F172A;">
                            <?= $result['verified'] ? 'Cryptographic Hash Chain Fully Verified' : 'CRITICAL ALERT: Audit Log Tampering Detected' ?>
                        </div>
                        <div style="font-size: 0.85rem; color: #64748B; margin-top: 2px;">
                            <?= $result['verified'] ? 'All sequential SHA-256 pointers validate perfectly from genesis anchor to tip.' : 'Cryptographic digest mismatch found. Database row was modified outside application boundary.' ?>
                        </div>
                    </div>
                </div>
                <div>
                    <?php if ($result['verified']): ?>
                        <span class="badge-chain-intact">✓ 100% INTACT & VALID</span>
                    <?php else: ?>
                        <span class="badge-chain-tampered">✕ CORRUPTED / TAMPERED</span>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Ledger Telemetry Summary -->
            <div class="soc-summary-box" style="margin: 1.25rem 0 0;">
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem;">
                    <div>
                        <span style="font-size: 0.75rem; text-transform: uppercase; color: #64748B; font-weight: 700;">Ledger Anchor Status</span>
                        <div style="font-size: 0.95rem; font-weight: 700; color: #0F172A; margin-top: 2px;">
                            <?= $result['verified'] ? '<span style="color: #1E5EFF;">MATHEMATICALLY INTACT</span>' : '<span style="color: #991B1B;">BROKEN POINTER DETECTED</span>' ?>
                        </div>
                    </div>
                    <div>
                        <span style="font-size: 0.75rem; text-transform: uppercase; color: #64748B; font-weight: 700;">Audited Block Count</span>
                        <div style="font-size: 0.95rem; font-weight: 700; color: #0F172A; margin-top: 2px;">
                            <?= (int)($result['total_records'] ?? 0) ?> Sequential Records
                        </div>
                    </div>
                    <div>
                        <span style="font-size: 0.75rem; text-transform: uppercase; color: #64748B; font-weight: 700;">Tip Block Hash Digest</span>
                        <div style="font-size: 0.85rem; font-family: monospace; color: #1E5EFF; margin-top: 2px; word-break: break-all;">
                            <?= htmlspecialchars(substr($result['latest_hash'] ?? 'N/A', 0, 32)) ?>...
                        </div>
                    </div>
                </div>
                <?php if (!$result['verified']): ?>
                    <div style="margin-top: 1rem; padding: 0.75rem; background: #FEF2F2; border-radius: 6px; border: 1px solid #FECACA; color: #991B1B;">
                        <strong>Tampered Block:</strong> Row #<?= (int)($result['broken_id'] ?? 0) ?> &bull; <strong>Discrepancy:</strong> <?= htmlspecialchars($result['reason'] ?? '') ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Visual Blockchain Flow Diagram -->
        <div class="admin-card" style="margin-bottom: 1.5rem;">
            <div class="admin-card-header">
                <div>
                    <h3 class="admin-card-title">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: #1E5EFF;"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                        Cryptographic Hash Chain Structure (A12)
                    </h3>
                    <p class="admin-card-subtitle">Every logged audit event cryptographically incorporates the prior event's SHA-256 digest.</p>
                </div>
            </div>

            <div class="admin-chain-flow">
                <!-- Block 1: Genesis -->
                <div class="admin-chain-block">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-weight: 700; font-size: 0.8rem; color: #0F172A;">BLOCK #1 (GENESIS)</span>
                        <span class="badge badge-info" style="font-size: 0.7rem;">Root Anchor</span>
                    </div>
                    <div style="font-size: 0.75rem; color: #64748B;">Prev Hash: <code style="font-size: 0.7rem; color: #0F172A;">00000000...00</code></div>
                    <div style="font-size: 0.75rem; color: #64748B; margin-top: 4px;">Payload: <code>SYSTEM_INIT / GENESIS</code></div>
                    <div style="font-size: 0.75rem; color: #1E5EFF; margin-top: 4px; font-weight: 600;">✓ Root Integrity Certified</div>
                </div>

                <div class="admin-chain-arrow">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
                </div>

                <!-- Block N-1 -->
                <div class="admin-chain-block">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-weight: 700; font-size: 0.8rem; color: #0F172A;">BLOCK #<?= max(1, (int)($result['total_records'] ?? 2) - 1) ?></span>
                        <span class="badge badge-neutral" style="font-size: 0.7rem;">Chained Audit Row</span>
                    </div>
                    <div style="font-size: 0.75rem; color: #64748B;">Prev Hash: <code>H(Block #<?= max(1, (int)($result['total_records'] ?? 2) - 2) ?>)</code></div>
                    <div style="font-size: 0.75rem; color: #64748B; margin-top: 4px;">Payload: <code>FINANCIAL_TXN / AUTH</code></div>
                    <div style="font-size: 0.75rem; color: #1E5EFF; margin-top: 4px; font-weight: 600;">✓ Non-Repudiation Bound</div>
                </div>

                <div class="admin-chain-arrow">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
                </div>

                <!-- Block N (Tip) -->
                <div class="admin-chain-block" style="border-color: #1E5EFF; background: #FFFFFF;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-weight: 700; font-size: 0.8rem; color: #1E5EFF;">BLOCK #<?= (int)($result['total_records'] ?? 1) ?> (TIP)</span>
                        <span class="badge badge-info" style="font-size: 0.7rem;">Head of Ledger</span>
                    </div>
                    <div style="font-size: 0.75rem; color: #64748B;">Curr Hash: <code style="font-size: 0.7rem; color: #1E5EFF;"><?= htmlspecialchars(substr($result['latest_hash'] ?? 'N/A', 0, 16)) ?>...</code></div>
                    <div style="font-size: 0.75rem; color: #64748B; margin-top: 4px;">Payload: <code>ACTIVE_SESSION_TELEMETRY</code></div>
                    <div style="font-size: 0.75rem; color: #1E5EFF; margin-top: 4px; font-weight: 600;">✓ Sequential Pointer Valid</div>
                </div>
            </div>
        </div>

        <!-- Interactive Testing & Demonstration Console -->
        <div class="admin-card">
            <div class="admin-card-header">
                <div>
                    <h3 class="admin-card-title">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: #64748B;"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
                        Academic Security Demonstration Console
                    </h3>
                    <p class="admin-card-subtitle">Simulate real database row manipulation to observe tamper detection in real-time, then repair the sequential cryptographic chain.</p>
                </div>
            </div>

            <div style="display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;">
                <button id="btnTamper" class="btn btn-outline btn-sm">
                    ⚠️ Simulate Row Edit (Attack Demo)
                </button>
                <button id="btnRepair" class="btn btn-primary btn-sm">
                    🛠️ Repair & Recalculate Hash Chain
                </button>
                <a href="verify_log_chain.php" class="btn btn-outline btn-sm">
                    🔄 Run Verification Audit
                </a>
            </div>
            <div id="actionResult" style="margin-top: 1rem; display: none;" class="alert"></div>
        </div>
    </main>

    <script src="../js/admin_verify_chain.js" nonce="<?= htmlspecialchars($cspNonce) ?>"></script>
</body>
</html>
