<?php
/**
 * In-Portal User Notification Service
 * 
 * PILLAR B [B7]: NOTIFICATION CENTER
 * 
 * WHY IN-PORTAL NOTIFICATIONS:
 * Real-world banks notify users in real-time about transactions, device logins,
 * and security events to enable rapid user-driven fraud detection.
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/logger.php';

/**
 * Dispatch an in-portal notification to a user
 * 
 * @param int $userId Target user ID
 * @param string $type Notification type identifier
 * @param string $title Short title
 * @param string $body Detailed message
 * @param string|null $link Relative in-portal URL (e.g. /frontend/transactions.html)
 * @param string $severity 'info' | 'warning' | 'danger'
 * @return int Inserted notification ID
 */
function notify_user(
    int $userId,
    string $type,
    string $title,
    string $body,
    ?string $link = null,
    string $severity = 'info'
): int {
    $allowedSeverities = ['info', 'warning', 'danger'];
    if (!in_array($severity, $allowedSeverities, true)) {
        $severity = 'info';
    }

    // Sanitize link: only allow relative URLs starting with /
    $safeLink = null;
    if (!empty($link)) {
        $trimmedLink = trim($link);
        if (str_starts_with($trimmedLink, '/') && !str_starts_with($trimmedLink, '//')) {
            $safeLink = $trimmedLink;
        }
    }

    try {
        $pdo = get_db();
        $stmt = $pdo->prepare(
            "INSERT INTO notifications (user_id, type, title, body, link, severity, read_at, created_at)
             VALUES (:uid, :type, :title, :body, :link, :severity, NULL, NOW())"
        );
        $stmt->execute([
            ':uid'      => $userId,
            ':type'     => mb_substr($type, 0, 64),
            ':title'    => mb_substr($title, 0, 128),
            ':body'     => $body,
            ':link'     => $safeLink,
            ':severity' => $severity
        ]);

        return (int)$pdo->lastInsertId();
    } catch (Throwable $e) {
        error_log("Failed to create user notification: " . $e->getMessage());
        return 0;
    }
}
