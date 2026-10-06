<?php
/**
 * Acknowledge SIEM Alert API Endpoint
 * 
 * PILLAR C [C7]: ALERT ACKNOWLEDGMENT & INCIDENT LIFECYCLE
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/alert_engine.php';
require_once __DIR__ . '/../security/logger.php';

require_method('POST');
$admin = require_role('admin');

$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true) ?: $_POST;

$alertId = isset($input['alert_id']) ? (int)$input['alert_id'] : 0;

if ($alertId <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Valid alert_id is required.']);
    exit;
}

$success = acknowledge_alert($alertId, $admin['id']);

if ($success) {
    log_security_event($admin['id'], 'ALERT_ACKNOWLEDGED', 'SUCCESS', "Admin {$admin['username']} acknowledged alert #$alertId", 'low');
    echo json_encode([
        'status'  => 'success',
        'message' => "Alert #$alertId acknowledged successfully."
    ]);
} else {
    http_response_code(400);
    echo json_encode([
        'status'  => 'error',
        'message' => "Alert #$alertId not found or already acknowledged."
    ]);
}
