<?php
/**
 * User Notifications Directory API Endpoint
 * 
 * PILLAR B [B7]: NOTIFICATION CENTER
 * 
 * Delivers unread count and latest 30 user notifications.
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../config/database.php';

require_method('GET');
guard_parameter_pollution();

$currentUser = require_auth();
$userId = (int)$currentUser['id'];

try {
    $pdo = get_db();

    // 1. Fetch unread count
    $stmtCount = $pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = :uid AND read_at IS NULL");
    $stmtCount->execute([':uid' => $userId]);
    $unreadCount = (int)$stmtCount->fetchColumn();

    // 2. Fetch recent notifications
    $stmt = $pdo->prepare(
        "SELECT id, type, title, body, link, severity, read_at, created_at 
         FROM notifications 
         WHERE user_id = :uid 
         ORDER BY created_at DESC, id DESC 
         LIMIT 30"
    );
    $stmt->execute([':uid' => $userId]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $formatted = [];
    foreach ($rows as $r) {
        $formatted[] = [
            'id'         => (int)$r['id'],
            'type'       => safe_html($r['type']),
            'title'      => safe_html($r['title']),
            'body'       => safe_html($r['body']),
            'link'       => safe_html($r['link'] ?? ''),
            'severity'   => safe_html($r['severity']),
            'is_read'    => !empty($r['read_at']),
            'read_at'    => $r['read_at'],
            'created_at' => $r['created_at']
        ];
    }

    echo json_encode([
        'status'       => 'success',
        'unread_count' => $unreadCount,
        'count'        => count($formatted),
        'data'         => $formatted
    ]);

} catch (Throwable $e) {
    error_log("Notifications API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to load notifications.']);
}
