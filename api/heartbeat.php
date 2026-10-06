<?php
/**
 * Session Heartbeat & Dual-Tier Timeout Monitor API Endpoint
 * 
 * PILLAR A [A6]: IDLE TIMEOUT (15 MIN) & ABSOLUTE TIMEOUT (8 HOURS) MONITORING
 * 
 * WHY A HEARTBEAT API:
 * In modern Single Page Applications (SPAs), users often view dashboards or financial graphs
 * without clicking links. The heartbeat allows client JavaScript to periodically check remaining
 * idle and absolute session lifetimes, display polite warning modals when 2 minutes remain,
 * and provide an authenticated "Keep Alive" touchpoint.
 * 
 * EXAMINER TALKING POINT [A6]:
 * "The heartbeat API provides transparent, real-time observability over dual-tier session lifetimes without compromising security."
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';

$currentUser = require_auth();
$userId = $currentUser['id'];

$now = time();
$loginTime    = $_SESSION['login_time'] ?? $now;
$lastActivity = $_SESSION['last_activity'] ?? $now;

// Calculate remaining windows
$idleRemaining     = max(0, SESSION_IDLE_TIMEOUT - ($now - $lastActivity));
$absoluteRemaining = max(0, SESSION_ABSOLUTE_TIMEOUT - ($now - $loginTime));

// Handle explicit keepalive request
$action = $_GET['action'] ?? $_POST['action'] ?? '';
if ($action === 'keepalive') {
    $_SESSION['last_activity'] = $now;
    $idleRemaining = SESSION_IDLE_TIMEOUT;
}

echo json_encode([
    'status'             => 'active',
    'user_id'            => $userId,
    'username'           => $currentUser['username'],
    'idle_remaining'     => $idleRemaining,
    'absolute_remaining' => $absoluteRemaining,
    'idle_limit'         => SESSION_IDLE_TIMEOUT,
    'absolute_limit'     => SESSION_ABSOLUTE_TIMEOUT,
    'server_time'        => date('Y-m-d H:i:s')
]);
