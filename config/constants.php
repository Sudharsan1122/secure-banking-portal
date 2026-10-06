<?php
/**
 * Application Constants & Security Configuration (Distinction-Grade Edition)
 * 
 * SECURITY PRINCIPLE:
 * Centralize all security parameters, timeouts, and environmental configuration
 * to prevent hardcoded credentials across endpoints and ensure consistent security posture.
 */

// Prevent direct script execution
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    http_response_code(403);
    exit('Access Denied');
}

require_once __DIR__ . '/env.php';

// Application Timezone Synchronization (align PHP CLI and web server with database timezone)
date_default_timezone_set(getenv('APP_TIMEZONE') ?: 'Asia/Kolkata');

// Database Connection Parameters (Default XAMPP / LAMP stack settings)
define('DB_HOST', getenv('DB_HOST') ?: '127.0.0.1');
define('DB_PORT', getenv('DB_PORT') ?: '3306');
define('DB_NAME', getenv('DB_NAME') ?: 'secure_banking');
define('DB_USER', getenv('DB_USER') ?: 'root');
define('DB_PASS', getenv('DB_PASS') !== false ? getenv('DB_PASS') : '');
define('DB_CHARSET', 'utf8mb4');

// Application Metadata & Modes
define('APP_NAME', 'Secure Banking Portal');
define('APP_VERSION', '2.0.0');
define('APP_DEBUG', filter_var(getenv('APP_DEBUG') ?: false, FILTER_VALIDATE_BOOLEAN));
define('DEMO_MODE', filter_var(getenv('DEMO_MODE') ?: true, FILTER_VALIDATE_BOOLEAN));
define('METRICS_TOKEN', getenv('METRICS_TOKEN') ?: 'sec_metrics_token_9876543210');

// Paths
define('APP_ROOT', dirname(__DIR__));
define('STATEMENTS_PATH', APP_ROOT . DIRECTORY_SEPARATOR . 'statements');
define('LOGS_PATH', APP_ROOT . DIRECTORY_SEPARATOR . 'logs');
define('UPLOADS_PATH', APP_ROOT . DIRECTORY_SEPARATOR . 'uploads');
define('AVATARS_PATH', UPLOADS_PATH . DIRECTORY_SEPARATOR . 'avatars');

// Pillar A: Authentication & Session Security Constants
define('SESSION_IDLE_TIMEOUT', 900);           // 15 minutes idle timeout
define('SESSION_ABSOLUTE_TIMEOUT', 28800);     // 8 hours absolute lifetime
define('OTP_EXPIRATION_SECONDS', 300);         // 5 minutes OTP validity
define('PASSWORD_RESET_EXPIRY', 900);          // 15 minutes token validity

// Pillar A: Account Lockout Tiers (Exponential Backoff)
define('LOCKOUT_TIER1_ATTEMPTS', 5);           // 5 failed -> 5 min lock
define('LOCKOUT_TIER1_DURATION', 300);         // 5 minutes in seconds
define('LOCKOUT_TIER2_ATTEMPTS', 10);          // 10 failed -> 30 min lock
define('LOCKOUT_TIER2_DURATION', 1800);        // 30 minutes in seconds
define('LOCKOUT_TIER3_ATTEMPTS', 15);          // 15 failed -> permanent admin lock

// Pillar A: Sliding-Window Rate Limits per Sensitive Endpoint
// Format: [max_attempts, window_in_seconds]
define('RATE_LIMIT_RULES', [
    '/api/login.php'              => [5, 900],    // 5 attempts per 15 min
    '/api/verify_otp.php'         => [3, 300],    // 3 attempts per 5 min
    '/api/transfer.php'           => [10, 60],    // 10 transfers per min
    '/api/register.php'           => [3, 3600],   // 3 registrations per hour
    '/api/download_statement.php' => [20, 60],    // 20 downloads per min
    '/api/request_reset.php'      => [3, 3600],   // 3 password resets per hour
    '/api/avatar.php'             => [10, 300],   // 10 avatar uploads per 5 min
]);

// Pillar A: Audit Log Hash Chain Genesis Seed
define('GENESIS_HASH', '0000000000000000000000000000000000000000000000000000000000000000');

// Password Policy Constraints
define('PASSWORD_MIN_LENGTH', 8);

// Allowed Whitelist for External Service Checker (SSRF Defense)
define('SSRF_WHITELIST_HOSTS', [
    'api.bankpartner.example',
    'rates.openexchangerates.org',
    'api.exchangerate.host',
    'api.github.com'
]);

// CORS Configuration
define('ALLOWED_CORS_ORIGINS', [
    'http://localhost',
    'http://127.0.0.1',
    'http://localhost:80',
    'http://localhost:8080',
    'https://bank.example'
]);

// Create upload paths if they do not exist
if (!is_dir(AVATARS_PATH)) {
    @mkdir(AVATARS_PATH, 0750, true);
}
