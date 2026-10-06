<?php
/**
 * Test Suite: User Security Posture Scoring Engine (Pillar C [C4])
 * 
 * Verifies:
 * 1. High-hygiene user (MFA enabled, fresh password, recovery codes) achieves score >= 50.
 * 2. Low-hygiene user (no MFA, stale password > 90d, failed logins) achieves score < 40 ("At Risk").
 * 3. Rubric breakdown contains complete itemized criteria and actionable recommendations.
 * 4. compute_security_score() updates and persists users.security_score in database.
 * 5. get_security_score_distribution() returns valid histogram bins and aggregate average.
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/security_score.php';

function test_security_score(): array {
    $tests = [];
    $pdo = get_db();

    // -------------------------------------------------------------
    // Setup Test Users: User A (High Hygiene) & User B (Low Hygiene)
    // -------------------------------------------------------------
    $userA_name = 'score_high_' . bin2hex(random_bytes(3));
    $userB_name = 'score_low_' . bin2hex(random_bytes(3));

    // User A: MFA enabled, password rotated today, phone & email
    $pdo->prepare(
        "INSERT INTO users (name, email, phone, username, password_hash, mfa_secret, password_changed_at, failed_login_count, created_at)
         VALUES ('High Posture User', :e, '1234567890', :u, 'hash', 'JBSWY3DPEHPK3PXP', NOW(), 0, NOW())"
    )->execute([':e' => "$userA_name@banktest.com", ':u' => $userA_name]);
    $userA_id = (int)$pdo->lastInsertId();

    // Add recovery codes for User A (+15 pts)
    $pdo->prepare("INSERT INTO recovery_codes (user_id, code_hash, used) VALUES (:uid, 'dummyhash', 0)")
        ->execute([':uid' => $userA_id]);

    // User B: No MFA, stale password (120 days ago), failed logins, no recovery codes, no phone
    $staleDate = date('Y-m-d H:i:s', time() - (120 * 86400));
    $pdo->prepare(
        "INSERT INTO users (name, email, phone, username, password_hash, mfa_secret, password_changed_at, failed_login_count, created_at)
         VALUES ('Low Posture User', :e, '', :u, 'hash', NULL, :stale, 3, NOW())"
    )->execute([
        ':e'     => "$userB_name@banktest.com", 
        ':u'     => $userB_name,
        ':stale' => $staleDate
    ]);
    $userB_id = (int)$pdo->lastInsertId();

    // -------------------------------------------------------------
    // Test 1: High-Hygiene Posture Score (MFA + fresh password >= 50)
    // -------------------------------------------------------------
    $scoreA = compute_security_score($userA_id);
    $tests[] = [
        'name'   => 'High Security Posture (MFA + Fresh Password >= 50)',
        'pass'   => ($scoreA >= 50),
        'detail' => "User A scored $scoreA/100 (Threshold: >= 50)"
    ];

    // -------------------------------------------------------------
    // Test 2: Low-Hygiene Posture Score (No MFA + Stale Password < 40)
    // -------------------------------------------------------------
    $scoreB = compute_security_score($userB_id);
    $tests[] = [
        'name'   => 'Low Security Posture (No MFA + Stale Password < 40)',
        'pass'   => ($scoreB < 40),
        'detail' => "User B scored $scoreB/100 (Threshold: < 40, At Risk)"
    ];

    // -------------------------------------------------------------
    // Test 3: Rubric Itemization & Actionable Recommendations
    // -------------------------------------------------------------
    $breakdownB = get_security_score_breakdown($userB_id);
    $hasRecommendations = !empty($breakdownB['recommendations']) && count($breakdownB['recommendations']) >= 2;
    $hasItems = !empty($breakdownB['items']) && count($breakdownB['items']) >= 5;
    $tests[] = [
        'name'   => 'Rubric Breakdown & Actionable Guidance Generation',
        'pass'   => ($hasRecommendations && $hasItems && $breakdownB['level'] === 'At Risk'),
        'detail' => sprintf("Generated %d rubric items and %d recommendations for 'At Risk' profile", count($breakdownB['items']), count($breakdownB['recommendations']))
    ];

    // -------------------------------------------------------------
    // Test 4: Database Score Persistence (users.security_score)
    // -------------------------------------------------------------
    $stmtCheck = $pdo->prepare("SELECT security_score, security_score_updated_at FROM users WHERE id = :uid");
    $stmtCheck->execute([':uid' => $userA_id]);
    $rowA = $stmtCheck->fetch();

    $persistedValid = ($rowA && (int)$rowA['security_score'] === $scoreA && !empty($rowA['security_score_updated_at']));
    $tests[] = [
        'name'   => 'Database Posture Score Persistence & Timestamping',
        'pass'   => $persistedValid,
        'detail' => "Persisted score {$rowA['security_score']} with timestamp {$rowA['security_score_updated_at']}"
    ];

    // -------------------------------------------------------------
    // Test 5: SOC Security Score Histogram Distribution
    // -------------------------------------------------------------
    $dist = get_security_score_distribution();
    $distValid = isset($dist['average_score'], $dist['histogram']['at_risk'], $dist['histogram']['strong']) &&
                 $dist['total_users'] >= 2;

    $tests[] = [
        'name'   => 'SOC Security Posture Histogram Aggregator',
        'pass'   => $distValid,
        'detail' => sprintf("Average: %.1f | At Risk: %d, Moderate: %d, Strong: %d, Exceptional: %d",
            $dist['average_score'],
            $dist['histogram']['at_risk'],
            $dist['histogram']['moderate'],
            $dist['histogram']['strong'],
            $dist['histogram']['exceptional']
        )
    ];

    // -------------------------------------------------------------
    // Cleanup Test Users
    // -------------------------------------------------------------
    $pdo->prepare("DELETE FROM recovery_codes WHERE user_id = :uid")->execute([':uid' => $userA_id]);
    $pdo->prepare("DELETE FROM users WHERE id IN (:u1, :u2)")->execute([':u1' => $userA_id, ':u2' => $userB_id]);

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running User Security Posture Scoring Tests...\n";
    foreach (test_security_score() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
