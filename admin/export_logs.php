<?php
/**
 * SIEM Audit Log Export Endpoint (CSV / JSON with Formula Injection Defense)
 * 
 * PILLAR C [C6]: AUDIT LOG EXPORT ENGINE (STREAMING & CWE-1236 DEFENSE)
 */

require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/csv_safe.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../config/database.php';

require_method('GET');
guard_parameter_pollution();

// Authenticate Administrator
$admin = require_role('admin');

$format = strtolower(canonicalize_input($_GET['format'] ?? 'csv'));
if (!in_array($format, ['csv', 'json'], true)) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['status' => 'error', 'message' => "Invalid format specified. Allowed formats: 'csv', 'json'."]);
    exit;
}

// Extract filter parameters
$fromDate = canonicalize_input($_GET['from'] ?? date('Y-m-d', strtotime('-30 days')));
$toDate   = canonicalize_input($_GET['to'] ?? date('Y-m-d'));
$severity = canonicalize_input($_GET['severity'] ?? '');
$eventType = canonicalize_input($_GET['event_type'] ?? '');
$userId   = isset($_GET['user_id']) && is_numeric($_GET['user_id']) ? (int)$_GET['user_id'] : null;

// Validate date formats
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $fromDate) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $toDate)) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['status' => 'error', 'message' => 'Invalid date format. Expected YYYY-MM-DD.']);
    exit;
}

// Construct filtered query
$sql = "SELECT sl.id, sl.timestamp, sl.user_id, u.username, sl.event_type, sl.severity, sl.ip_address, sl.status, sl.request 
        FROM security_logs sl 
        LEFT JOIN users u ON sl.user_id = u.id 
        WHERE DATE(sl.timestamp) BETWEEN :from AND :to ";
$params = [
    ':from' => $fromDate,
    ':to'   => $toDate
];

if (!empty($severity)) {
    $sevList = array_map('trim', explode(',', strtolower($severity)));
    $validSevs = ['low', 'medium', 'high', 'critical'];
    $allowedSevs = array_intersect($sevList, $validSevs);
    if (!empty($allowedSevs)) {
        $inPlaceholders = [];
        foreach ($allowedSevs as $idx => $s) {
            $key = ":sev_$idx";
            $inPlaceholders[] = $key;
            $params[$key] = $s;
        }
        $sql .= "AND sl.severity IN (" . implode(',', $inPlaceholders) . ") ";
    }
}

if (!empty($eventType)) {
    $sql .= "AND sl.event_type = :event_type ";
    $params[':event_type'] = $eventType;
}

if ($userId !== null) {
    $sql .= "AND sl.user_id = :uid ";
    $params[':uid'] = $userId;
}

$sql .= "ORDER BY sl.id ASC";

try {
    $pdo = get_db();
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    // Audit the export action
    $filterContext = [
        'format'     => $format,
        'from'       => $fromDate,
        'to'         => $toDate,
        'severity'   => $severity ?: 'all',
        'event_type' => $eventType ?: 'all'
    ];
    log_security_event(
        $admin['id'],
        'AUDIT_LOG_EXPORTED',
        'SUCCESS',
        json_encode($filterContext, JSON_UNESCAPED_SLASHES),
        'low'
    );

    // -------------------------------------------------------------
    // Format 1: CSV Streaming with Formula Injection Neutralization
    // -------------------------------------------------------------
    if ($format === 'csv') {
        $filename = sprintf("audit_log_%s.csv", date('Ymd_His'));
        header('Content-Type: text/csv; charset=utf-8');
        header("Content-Disposition: attachment; filename=\"$filename\"");
        header('Pragma: no-cache');
        header('Expires: 0');

        $outputHandle = fopen('php://output', 'w');

        // CSV Headers
        $headers = ['id', 'timestamp', 'user_id', 'username', 'event_type', 'severity', 'ip_address', 'status', 'request_summary'];
        fputcsv($outputHandle, $headers);

        // Stream rows directly
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $safeRow = [
                $row['id'],
                $row['timestamp'],
                $row['user_id'] ?? 'NULL',
                csv_escape($row['username'] ?? 'Anonymous'),
                csv_escape($row['event_type']),
                csv_escape($row['severity']),
                csv_escape($row['ip_address']),
                csv_escape($row['status']),
                csv_escape($row['request']) // Critical formula escaping applied here
            ];
            fputcsv($outputHandle, $safeRow);
        }

        fclose($outputHandle);
        exit;
    }

    // -------------------------------------------------------------
    // Format 2: JSON Export
    // -------------------------------------------------------------
    if ($format === 'json') {
        $filename = sprintf("audit_log_%s.json", date('Ymd_His'));
        header('Content-Type: application/json; charset=utf-8');
        header("Content-Disposition: attachment; filename=\"$filename\"");

        $events = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode([
            'exported_at' => date('c'),
            'exported_by' => $admin['username'],
            'filters'     => $filterContext,
            'count'       => count($events),
            'events'      => $events
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

} catch (Throwable $e) {
    error_log("Audit Log Export Error: " . $e->getMessage());
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['status' => 'error', 'message' => 'An error occurred generating audit log export.']);
    exit;
}
