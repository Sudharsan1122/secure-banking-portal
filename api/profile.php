<?php
/**
 * User Profile & Password Change API Endpoint
 * 
 * SECURITY PRINCIPLES IMPLEMENTED:
 * 1. Step-Up Verification: Password changes require verification of the existing password
 *    using password_verify() to defeat session-riding password resets.
 * 2. Strict Complexity: Enforces password policy on new credentials.
 * 3. CSRF Verification: Enforced on all update actions.
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../config/database.php';

$currentUser = require_auth();
$userId = $currentUser['id'];
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

try {
    $pdo = get_db();

    // GET: Retrieve user profile
    if ($method === 'GET') {
        $stmt = $pdo->prepare(
            "SELECT u.id, u.name, u.email, u.phone, u.username, u.role, u.created_at,
                    a.account_number, a.balance, a.currency
             FROM users u
             LEFT JOIN accounts a ON a.user_id = u.id
             WHERE u.id = :id 
             LIMIT 1"
        );
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch();

        if (!$user) {
            http_response_code(404);
            echo json_encode(['status' => 'error', 'message' => 'User not found']);
            exit;
        }

        echo json_encode([
            'status' => 'success',
            'data'   => [
                'id'             => (int)$user['id'],
                'name'           => safe_html($user['name']),
                'email'          => safe_html($user['email']),
                'phone'          => safe_html($user['phone']),
                'username'       => safe_html($user['username']),
                'role'           => $user['role'],
                'account_number' => safe_html($user['account_number']),
                'balance'        => (float)$user['balance'],
                'currency'       => safe_html($user['currency'] ?? 'USD'),
                'created_at'     => $user['created_at']
            ],
            'csrf_token' => get_csrf_token()
        ]);
        exit;
    }

    // POST: Update Password / Profile
    if ($method === 'POST') {
        require_csrf_token();

        $rawInput = file_get_contents('php://input');
        $input = json_decode($rawInput, true) ?: $_POST;
        $action = $input['action'] ?? 'change_password';

        if ($action === 'change_password') {
            $currentPassword = $input['current_password'] ?? '';
            $newPassword     = $input['new_password'] ?? '';

            if (empty($currentPassword) || empty($newPassword)) {
                http_response_code(400);
                echo json_encode(['status' => 'error', 'message' => 'Current password and new password are required.']);
                exit;
            }

            // Retrieve current password hash
            $passStmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = :id LIMIT 1");
            $passStmt->execute([':id' => $userId]);
            $currentHash = $passStmt->fetchColumn();

            if (!$currentHash || !password_verify($currentPassword, $currentHash)) {
                log_security_event($userId, 'PASSWORD_CHANGE_FAILED', 'BLOCKED', 'Incorrect current password provided');
                http_response_code(401);
                echo json_encode(['status' => 'error', 'message' => 'Incorrect current password.']);
                exit;
            }

            // Validate new password strength
            $strength = validate_password_strength($newPassword);
            if (!$strength['is_valid']) {
                http_response_code(400);
                echo json_encode(['status' => 'error', 'message' => 'Password policy not met.', 'errors' => $strength['errors']]);
                exit;
            }

            // Hash new password
            $newHash = password_hash($newPassword, PASSWORD_BCRYPT);
            $update = $pdo->prepare("UPDATE users SET password_hash = :hash, password_changed_at = NOW() WHERE id = :id");
            $update->execute([':hash' => $newHash, ':id' => $userId]);

            // PILLAR A [A7] CALL SITE 3: Regenerate session ID upon credential modification
            session_regenerate_id(true);

            // Issue fresh CSRF token bound to regenerated session
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

            log_security_event($userId, 'PASSWORD_CHANGE_SUCCESS', 'SUCCESS', 'User successfully changed password', 'high');

            echo json_encode([
                'status'     => 'success',
                'message'    => 'Password updated successfully.',
                'csrf_token' => $_SESSION['csrf_token']
            ]);
            exit;
        }

        // PILLAR A [A13]: Generate 10 Emergency 2FA Recovery Codes
        if ($action === 'generate_recovery_codes') {
            $codes = generate_recovery_codes($userId);
            echo json_encode([
                'status'         => 'success',
                'message'        => '10 emergency recovery codes generated. Store them in a secure password vault.',
                'recovery_codes' => $codes
            ]);
            exit;
        }

        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Unknown action requested.']);
        exit;
    }

    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']);

} catch (Throwable $e) {
    error_log('Profile API Error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Error handling profile operation.']);
}
