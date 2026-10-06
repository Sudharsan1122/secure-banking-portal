<?php
/**
 * Logout API Endpoint
 * 
 * Securely invalidates server session, destroys the session cookie, and records audit log.
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';

logout_user();

echo json_encode([
    'status'  => 'success',
    'message' => 'You have been successfully logged out.'
]);
