<?php
/**
 * User Security Posture Score API Endpoint
 * 
 * PILLAR C [C4]: PROFILE SECURITY SCORE & ACTIONABLE HYGIENE BREAKDOWN
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/security_score.php';

require_method('GET');
$user = require_auth();

// Compute or refresh current user's security posture score
$score = compute_security_score($user['id']);
$breakdown = get_security_score_breakdown($user['id']);

echo json_encode([
    'status' => 'success',
    'data'   => $breakdown
]);
