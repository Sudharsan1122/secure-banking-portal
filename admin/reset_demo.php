<?php
/**
 * Demo Environment Reset Controller
 * 
 * CRITICAL CONSTRAINT:
 * Respects DEMO_MODE flag from .env. Only accessible when DEMO_MODE=true.
 * Resets account balances, clears lockouts, and flushes rate limits for testing convenience.
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../config/constants.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/logger.php';

// Verify DEMO_MODE is active
if (!defined('DEMO_MODE') || !DEMO_MODE) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Demo reset utility is strictly disabled in production mode.']);
    exit;
}

$admin = require_role('admin');

try {
    $pdo = get_db();

    // 1. Reset Demo User Balances and Clear Lockouts
    $pdo->exec("UPDATE users SET balance = 100000.00 WHERE id = 1");
    $pdo->exec("UPDATE users SET balance = 15500.00, failed_login_count = 0, locked_until = NULL, lock_reason = NULL WHERE id = 2");
    $pdo->exec("UPDATE users SET balance = 5250.00, failed_login_count = 0, locked_until = NULL, lock_reason = NULL WHERE id = 3");

    // 2. Reset Accounts Table Balances
    $pdo->exec("UPDATE accounts SET balance = 100000.00 WHERE user_id = 1");
    $pdo->exec("UPDATE accounts SET balance = 15500.00 WHERE user_id = 2");
    $pdo->exec("UPDATE accounts SET balance = 5250.00 WHERE user_id = 3");

    // 3. Flush Rate Limits Table
    $pdo->exec("TRUNCATE TABLE rate_limits");

    // 4. Log Action to SIEM
    log_security_event($admin['id'], 'DEMO_ENVIRONMENT_RESET', 'SUCCESS', "Admin {$admin['username']} executed demo environment reset", 'low');

    echo json_encode([
        'status'  => 'success',
        'message' => 'Demo environment successfully reset. Balances restored, lockouts cleared, and rate limits flushed.'
    ]);

} catch (Throwable $e) {
    error_log("Demo Reset Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'An error occurred during demo reset.']);
}
