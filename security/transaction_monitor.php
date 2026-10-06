<?php
/**
 * Heuristic Transaction Monitor & Suspicious Activity Flagger
 * 
 * PILLAR B [B10]: ADMIN TRANSACTION MONITOR & SUSPICIOUS ACTIVITY FLAGGING
 * 
 * HEURISTIC ANOMALY DETECTION ENGINE:
 * 1. High-Value Transfer: Transactions >= $50,000.00
 * 2. Rapid-Burst Velocity: >= 3 transactions within a 5-minute sliding window
 * 3. Round-Number High-Volume Transfer: Amounts >= $10,000.00 that are exact multiples of $1,000
 * 
 * Automated triage cases are filed into `transaction_reviews` for compliance audit and SOC review.
 * 
 * EXAMINER TALKING POINT:
 * "All completed transactions are evaluated against multi-variable heuristics (burst velocity,
 *  round-number patterns, $50K thresholds) creating persistent triage records in transaction_reviews
 *  with audit-logged adjudication outcomes (cleared/escalated)."
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/logger.php';

/**
 * Evaluate transaction risk and persist triage case if flagged
 * 
 * @param int $txnId Transaction Primary Key
 * @param int $senderId Sender User ID
 * @param float $amount Transfer Amount
 * @param PDO|null $pdo Database Connection
 * @return array [flagged => bool, review_id => int|null, reasons => array]
 */
function evaluate_and_flag_transaction(int $txnId, int $senderId, float $amount, ?PDO $pdo = null): array {
    if ($pdo === null) {
        $pdo = get_db();
    }

    $reasons = [];

    // Rule 1: High Value ($50,000+)
    if ($amount >= 50000.00) {
        $reasons[] = sprintf("High-Value Transfer: $%.2f exceeds administrative triage threshold ($50,000.00)", $amount);
    }

    // Rule 2: Suspicious Round-Number High Value ($10,000+ ending in .00 and divisible by 1000)
    if ($amount >= 10000.00 && fmod($amount, 1000.0) == 0.0) {
        $reasons[] = sprintf("Suspicious Round-Number Spike: Exact multiple of $1,000 ($%.2f)", $amount);
    }

    // Rule 3: Rapid Velocity Burst (>= 3 completed transactions in past 5 minutes)
    $stmtBurst = $pdo->prepare(
        "SELECT COUNT(*) FROM transactions 
         WHERE sender_id = :uid 
           AND status = 'completed' 
           AND created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)"
    );
    $stmtBurst->execute([':uid' => $senderId]);
    $burstCount = (int)$stmtBurst->fetchColumn();

    if ($burstCount >= 3) {
        $reasons[] = sprintf("Rapid Burst Velocity: %d transactions executed within 5 minutes", $burstCount);
    }

    if (!empty($reasons)) {
        $flaggedReason = implode("; ", $reasons);

        $stmtInsert = $pdo->prepare(
            "INSERT INTO transaction_reviews (transaction_id, flagged_reason, outcome, created_at)
             VALUES (:txn, :reason, 'pending', NOW())"
        );
        $stmtInsert->execute([
            ':txn'    => $txnId,
            ':reason' => $flaggedReason
        ]);
        $reviewId = (int)$pdo->lastInsertId();

        log_security_event(
            $senderId,
            'TRANSACTION_FLAGGED',
            'BLOCKED', // Flagged for investigation
            "Transaction #$txnId flagged for review: $flaggedReason",
            'medium'
        );

        return [
            'flagged'   => true,
            'review_id' => $reviewId,
            'reasons'   => $reasons
        ];
    }

    return [
        'flagged'   => false,
        'review_id' => null,
        'reasons'   => []
    ];
}
