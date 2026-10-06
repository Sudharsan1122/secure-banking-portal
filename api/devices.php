<?php
/**
 * User Devices Directory API Endpoint
 * 
 * PILLAR B [B8]: DEVICE FINGERPRINTING & ACTIVE SESSIONS
 * 
 * Lists all registered devices for the authenticated user, identifying the current active session device.
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/devices.php';
require_once __DIR__ . '/../config/database.php';

require_method('GET');
guard_parameter_pollution();

$currentUser = require_auth();
$userId = (int)$currentUser['id'];

try {
    $pdo = get_db();

    $currentMeta = get_current_device_meta();
    $currentFp   = $currentMeta['fingerprint'];

    $stmt = $pdo->prepare(
        "SELECT id, fingerprint, user_agent, last_ip, last_seen, first_seen, is_revoked 
         FROM user_devices 
         WHERE user_id = :uid 
         ORDER BY last_seen DESC"
    );
    $stmt->execute([':uid' => $userId]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $devices = [];
    foreach ($rows as $r) {
        $ua = $r['user_agent'] ?? '';
        
        // Parse platform / browser for friendly display
        $platform = 'Unknown Platform';
        if (str_contains($ua, 'Windows')) $platform = 'Windows';
        elseif (str_contains($ua, 'Macintosh')) $platform = 'macOS';
        elseif (str_contains($ua, 'Linux')) $platform = 'Linux';
        elseif (str_contains($ua, 'iPhone') || str_contains($ua, 'iPad')) $platform = 'iOS';
        elseif (str_contains($ua, 'Android')) $platform = 'Android';

        $browser = 'Web Browser';
        if (str_contains($ua, 'Chrome') && !str_contains($ua, 'Edg')) $browser = 'Google Chrome';
        elseif (str_contains($ua, 'Edg')) $browser = 'Microsoft Edge';
        elseif (str_contains($ua, 'Firefox')) $browser = 'Mozilla Firefox';
        elseif (str_contains($ua, 'Safari') && !str_contains($ua, 'Chrome')) $browser = 'Apple Safari';

        $isCurrent = ($r['fingerprint'] === $currentFp && empty($r['is_revoked']));

        $devices[] = [
            'id'                 => (int)$r['id'],
            'platform'           => $platform,
            'browser'            => $browser,
            'user_agent'         => safe_html($ua),
            'ip_address'         => safe_html($r['last_ip']),
            'last_login_at'      => $r['last_seen'],
            'created_at'         => $r['first_seen'],
            'is_current_device'  => $isCurrent,
            'is_revoked'         => (bool)$r['is_revoked']
        ];
    }

    echo json_encode([
        'status' => 'success',
        'count'  => count($devices),
        'data'   => $devices
    ]);

} catch (Throwable $e) {
    error_log("Devices API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to load device history.']);
}
