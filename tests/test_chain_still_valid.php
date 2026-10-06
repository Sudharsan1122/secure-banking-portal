<?php
/**
 * Test Suite: Cryptographic Audit Log Non-Repudiation Health (Pillar C [C8/A12])
 * 
 * Verifies:
 * 1. Post-Pillar C cryptographic hash chain integrity (verify_log_chain() returns true).
 * 2. Strict sequential pointer linkage (every row's prev_hash binds to preceding curr_hash).
 * 3. Individual block payload integrity (recalculated SHA-256 matches stored curr_hash for 100% of rows).
 * 4. Genesis block baseline compliance (first block binds to 64-zero genesis hash).
 * 5. Dynamic tamper detection validation across new Pillar C columns (severity, anomaly context).
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/logger.php';

function test_chain_still_valid(): array {
    $tests = [];
    $pdo = get_db();

    // -------------------------------------------------------------
    // Test 1: Full Chain Verification via Core Engine
    // -------------------------------------------------------------
    $result = verify_log_chain();
    $tests[] = [
        'name'   => 'Master Cryptographic Hash-Chain Verification (verify_log_chain)',
        'pass'   => ($result['verified'] === true),
        'detail' => $result['verified'] 
            ? sprintf("Validated %d consecutive blocks without gaps or discrepancies", $result['total_records'])
            : sprintf("Verification failed at block #%s: %s", $result['broken_id'] ?? 'unknown', $result['reason'] ?? $result['error'] ?? 'unknown')
    ];

    // -------------------------------------------------------------
    // Test 2: Genesis Block Hash Anchor Verification
    // -------------------------------------------------------------
    $stmtFirst = $pdo->query("SELECT id, prev_hash, curr_hash FROM security_logs ORDER BY id ASC LIMIT 1");
    $firstRow = $stmtFirst->fetch(PDO::FETCH_ASSOC);

    $expectedGenesis = defined('GENESIS_HASH') ? GENESIS_HASH : str_repeat('0', 64);
    $genesisValid = ($firstRow && $firstRow['prev_hash'] === $expectedGenesis);

    $tests[] = [
        'name'   => 'Genesis Block Cryptographic Anchor (64-Zero Seed)',
        'pass'   => $genesisValid,
        'detail' => $firstRow ? "Root Block #{$firstRow['id']} anchors to: " . substr($firstRow['prev_hash'], 0, 16) . "..." : "No log records found"
    ];

    // -------------------------------------------------------------
    // Test 3: Exhaustive Re-computation of All Ledger Blocks
    // -------------------------------------------------------------
    $stmtAll = $pdo->query("SELECT * FROM security_logs ORDER BY id ASC");
    $allRows = $stmtAll->fetchAll(PDO::FETCH_ASSOC);

    $mismatches = 0;
    $pointerBreaks = 0;
    $expectedPrev = $expectedGenesis;

    foreach ($allRows as $r) {
        if ($r['prev_hash'] !== $expectedPrev) {
            $pointerBreaks++;
        }

        $material = sprintf(
            '%s|%s|%s|%s|%s|%s|%s|%s',
            $r['prev_hash'],
            $r['timestamp'],
            $r['user_id'] !== null ? (string)$r['user_id'] : 'NULL',
            $r['event_type'],
            $r['severity'] ?: 'low',
            $r['ip_address'],
            $r['status'],
            mb_substr($r['request'] ?? '', 0, 1000)
        );
        $recalculated = hash('sha256', $material);

        if ($r['curr_hash'] !== $recalculated) {
            $mismatches++;
        }

        $expectedPrev = $r['curr_hash'];
    }

    $exhaustiveValid = ($pointerBreaks === 0 && $mismatches === 0 && count($allRows) > 0);
    $tests[] = [
        'name'   => 'Exhaustive Independent SHA-256 Block Ledger Audit',
        'pass'   => $exhaustiveValid,
        'detail' => sprintf("Audited %d blocks: %d pointer breaks, %d hash discrepancies", count($allRows), $pointerBreaks, $mismatches)
    ];

    // -------------------------------------------------------------
    // Test 4: Threat Severity Integration within Chained Blocks
    // -------------------------------------------------------------
    $stmtSev = $pdo->query("SELECT COUNT(*) FROM security_logs WHERE severity IN ('low', 'medium', 'high', 'critical')");
    $validSevCount = (int)$stmtSev->fetchColumn();

    $allSeveritiesValid = ($validSevCount === count($allRows));
    $tests[] = [
        'name'   => 'Audit Log Severity Tier Schema Compliance',
        'pass'   => $allSeveritiesValid,
        'detail' => "All $validSevCount entries bound to valid 4-tier severity levels (low/med/high/crit)"
    ];

    // -------------------------------------------------------------
    // Test 5: Live Tamper Detection & Auto-Recovery Sanity
    // -------------------------------------------------------------
    if (count($allRows) > 0) {
        $sample = $allRows[count($allRows) - 1];
        $sampleId = (int)$sample['id'];
        $origReq = $sample['request'];

        // Inject simulated tamper
        $pdo->prepare("UPDATE security_logs SET request = 'TAMPERED_CONTENT_TEST' WHERE id = :id")->execute([':id' => $sampleId]);
        $tamperCheck = verify_log_chain();
        $caught = ($tamperCheck['verified'] === false && $tamperCheck['broken_id'] === $sampleId);

        // Restore original
        $pdo->prepare("UPDATE security_logs SET request = :orig WHERE id = :id")->execute([':orig' => $origReq, ':id' => $sampleId]);
        $restoredCheck = verify_log_chain();
        $restored = ($restoredCheck['verified'] === true);

        $tests[] = [
            'name'   => 'Dynamic Anti-Tamper Verification & Restoration Safety',
            'pass'   => ($caught && $restored),
            'detail' => 'Tamper detected at target block and chain validated cleanly upon payload restoration'
        ];
    }

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Post-Pillar C Cryptographic Audit Log Health Tests...\n";
    foreach (test_chain_still_valid() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
