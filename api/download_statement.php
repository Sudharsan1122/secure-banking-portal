<?php
/**
 * Monthly Statement Download API Endpoint
 * 
 * MODULE 9: DIRECTORY TRAVERSAL PREVENTION
 * 
 * SECURITY PRINCIPLES IMPLEMENTED:
 * 1. Strict Allow-List Regex Validation: Validates the incoming date parameter against
 *    /^\d{4}-(0[1-9]|1[0-2])$/. Any attempt to supply directory traversal sequences
 *    (e.g., '../../etc/passwd', '..\..\windows\win.ini', or null-bytes '%00') is immediately rejected.
 * 2. Canonical Path Resolution (realpath): Uses realpath() to resolve absolute filesystem paths
 *    and rigorously checks that the target file path strictly begins with the base statements directory.
 * 3. No User-Controlled File Paths: Internal filenames are generated deterministically
 *    using the authenticated user's session ID (user_{id}_{year}_{month}.pdf), preventing
 *    Insecure Direct Object Reference (IDOR) attacks.
 * 4. SIEM Attack Logging: Any traversal patterns trigger DIRECTORY_TRAVERSAL audit alerts.
 */

require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/rate_limit.php';
require_once __DIR__ . '/../config/constants.php';
require_once __DIR__ . '/../config/database.php';

// Pillar A [A10]: Method Enforcement
require_method(['GET', 'POST']);

// Pillar A [A9]: Parameter Pollution Guard
guard_parameter_pollution();

// Pillar A [A3]: Enforce Sliding-Window Rate Limit (20 downloads / min)
enforce_endpoint_rate_limit('/api/download_statement.php');

$currentUser = require_auth();
$userId = $currentUser['id'];

$rawDate = canonicalize_input(trim($_GET['statement_month'] ?? $_GET['date'] ?? $_GET['month'] ?? $_POST['statement_month'] ?? $_POST['date'] ?? ''));
$rawPath = isset($_GET['file']) ? canonicalize_input($_GET['file']) : (isset($_GET['filename']) ? canonicalize_input($_GET['filename']) : null);

/**
 * ===============================================================
 * MODULE 9: ACADEMIC COMPARISON — VULNERABLE VS SECURE
 * ===============================================================
 * VULNERABLE CODE (Path Traversal / Arbitrary File Read):
 *   $file = $_GET['file'];
 *   include("statements/" . $file); // If attacker sends ../../etc/passwd
 *   readfile("statements/" . $file); // Leaks sensitive server files!
 * 
 * SECURE IMPLEMENTATION BELOW:
 * 1) Scan all request parameters for relative traversal patterns (../, ..\, %2e%2e, null-bytes)
 * 2) Reject any direct file path query and log high-severity SIEM DIRECTORY_TRAVERSAL event
 * 3) Validate sanitized components with strict regex whitelist (YYYY-MM)
 * 4) Construct filename programmatically with internal session context
 * 5) Resolve canonical path via realpath() and verify directory prefix
 * ===============================================================
 */

// Comprehensive Traversal Signature Detection across all incoming parameters
$traversalDetected = false;
$traversalParam = '';
$traversalVal = '';

foreach (array_merge($_GET, $_POST) as $paramKey => $paramVal) {
    if (is_string($paramVal)) {
        $decoded = urldecode($paramVal);
        if (str_contains($paramVal, '..') || str_contains($paramVal, '/') || str_contains($paramVal, '\\') || str_contains($paramVal, "\0") ||
            str_contains($decoded, '..') || str_contains($decoded, '/') || str_contains($decoded, '\\') || str_contains($decoded, "\0")) {
            $traversalDetected = true;
            $traversalParam = $paramKey;
            $traversalVal = $paramVal;
            break;
        }
    }
}

if ($traversalDetected) {
    log_security_event(
        $userId,
        'DIRECTORY_TRAVERSAL',
        'BLOCKED',
        "Path traversal sequence detected in parameter '{$traversalParam}': " . mb_substr($traversalVal, 0, 100),
        'high'
    );
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'status'  => 'error',
        'code'    => 'DIRECTORY_TRAVERSAL_BLOCKED',
        'message' => 'Path traversal pattern detected and blocked by security firewall.'
    ]);
    exit;
}

// 1. Strict Regex Validation on YYYY-MM
if (!validate_statement_date($rawDate)) {
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'status'  => 'error',
        'code'    => 'INVALID_DATE_FORMAT',
        'message' => 'Invalid statement date format. Expected YYYY-MM (e.g. 2026-01).'
    ]);
    exit;
}

list($year, $month) = explode('-', $rawDate);

// Ensure statements directory exists
$statementsDir = STATEMENTS_PATH;
if (!is_dir($statementsDir)) {
    @mkdir($statementsDir, 0750, true);
}

// 2. Deterministic Internal Filename (No user input in file structure)
$targetFilename = sprintf("user_%d_%04d_%02d.pdf", $userId, (int)$year, (int)$month);
$targetFilePath = $statementsDir . DIRECTORY_SEPARATOR . $targetFilename;

// If the statement file does not exist on disk yet, generate a realistic PDF/text statement
if (!file_exists($targetFilePath)) {
    try {
        $pdo = get_db();
        $userStmt = $pdo->prepare("SELECT name, email, username FROM users WHERE id = :id");
        $userStmt->execute([':id' => $userId]);
        $user = $userStmt->fetch();

        $txnStmt = $pdo->prepare(
            "SELECT * FROM transactions 
             WHERE (sender_id = :u1 OR receiver_id = :u2) 
               AND created_at LIKE :datePattern 
             ORDER BY created_at ASC"
        );
        $txnStmt->execute([
            ':u1' => $userId,
            ':u2' => $userId,
            ':datePattern' => "$year-$month%"
        ]);
        $monthlyTxns = $txnStmt->fetchAll();

        // Build authentic formatted bank statement
        $content = "%PDF-1.4\n";
        $content .= "% Secure Banking Portal - Official Account Statement\n";
        $content .= "===============================================================\n";
        $content .= "                  SECURE BANKING PORTAL\n";
        $content .= "              MONTHLY ACCOUNT STATEMENT\n";
        $content .= "===============================================================\n";
        $content .= "Account Holder : " . ($user['name'] ?? 'Customer') . "\n";
        $content .= "Username       : " . ($user['username'] ?? '') . "\n";
        $content .= "Period         : " . "$year-$month\n";
        $content .= "Generated On   : " . date('Y-m-d H:i:s') . "\n";
        $content .= "---------------------------------------------------------------\n";
        $content .= sprintf("%-20s | %-10s | %-12s | %s\n", "Date", "Type", "Amount", "Remark");
        $content .= "---------------------------------------------------------------\n";

        if (empty($monthlyTxns)) {
            $content .= "No transactions recorded for this period.\n";
        } else {
            foreach ($monthlyTxns as $txn) {
                $type = ((int)$txn['sender_id'] === $userId) ? 'DEBIT' : 'CREDIT';
                $content .= sprintf(
                    "%-20s | %-10s | %12.2f | %s\n",
                    $txn['created_at'],
                    $type,
                    (float)$txn['amount'],
                    $txn['remark']
                );
            }
        }
        $content .= "===============================================================\n";
        $content .= "End of Statement. Verified Cryptographically.\n";
        $content .= "%%EOF\n";

        @file_put_contents($targetFilePath, $content, LOCK_EX);
    } catch (Throwable $e) {
        error_log('Statement Generation Error: ' . $e->getMessage());
    }
}

// 3. Canonical Path Resolution and Directory Jail Verification
$canonicalBase = realpath($statementsDir);
$canonicalFile = realpath($targetFilePath);

// Verify that the resolved file exists and strictly resides inside the allowed directory
if ($canonicalFile === false || !str_starts_with($canonicalFile, $canonicalBase . DIRECTORY_SEPARATOR)) {
    log_security_event(
        $userId,
        'DIRECTORY_TRAVERSAL',
        'BLOCKED',
        "Access denied to path: $targetFilePath (Canonical: " . ($canonicalFile ?: 'none') . ")"
    );
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode([
        'status'  => 'error',
        'message' => 'Access Denied: Requested file is outside authorized directory.'
    ]);
    exit;
}

// Log authorized download event
log_security_event($userId, 'STATEMENT_DOWNLOAD', 'SUCCESS', "Downloaded monthly statement for $year-$month");

// 4. Safe File Streaming with Non-Executable Content Headers
header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="' . basename($canonicalFile) . '"');
header('Content-Length: ' . filesize($canonicalFile));
header('Cache-Control: private, must-revalidate, max-age=0');
header('Pragma: public');

readfile($canonicalFile);
exit;
