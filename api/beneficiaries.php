<?php
/**
 * Beneficiaries Management API Endpoint
 * 
 * MODULE 6: CSRF PROTECTION ON STATE-CHANGING ACTIONS
 * MODULE 8: SQL INJECTION PREVENTION VIA PDO
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

    // GET: List all saved beneficiaries for authenticated user
    if ($method === 'GET') {
        $stmt = $pdo->prepare(
            "SELECT id, name, account_number, bank_name, verified, created_at 
             FROM beneficiaries 
             WHERE user_id = :user_id 
             ORDER BY name ASC"
        );
        $stmt->execute([':user_id' => $userId]);
        $rows = $stmt->fetchAll();

        $beneficiaries = [];
        foreach ($rows as $b) {
            $beneficiaries[] = [
                'id'             => (int)$b['id'],
                'name'           => safe_html($b['name']),
                'account_number' => safe_html($b['account_number']),
                'bank_name'      => safe_html($b['bank_name']),
                'verified'       => (bool)($b['verified'] ?? false),
                'created_at'     => $b['created_at']
            ];
        }

        echo json_encode([
            'status' => 'success',
            'data'   => $beneficiaries
        ]);
        exit;
    }

    // POST: Add new beneficiary (Requires CSRF Token)
    if ($method === 'POST') {
        require_csrf_token();

        $rawInput = file_get_contents('php://input');
        $input = json_decode($rawInput, true) ?: $_POST;

        $name          = trim($input['name'] ?? '');
        $accountNumber = trim($input['account_number'] ?? '');
        $bankName      = trim($input['bank_name'] ?? 'Secure National Bank');

        detect_xss_payload($name, $userId);
        detect_sqli_payload($name, $userId);

        if (empty($name) || mb_strlen($name) < 2 || mb_strlen($name) > 100) {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => 'Beneficiary name must be between 2 and 100 characters.']);
            exit;
        }

        if (empty($accountNumber) || !preg_match('/^[A-Za-z0-9\-]{5,25}$/', $accountNumber)) {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => 'Invalid account number format.']);
            exit;
        }

        // Check if beneficiary already added
        $checkStmt = $pdo->prepare("SELECT id FROM beneficiaries WHERE user_id = :uid AND account_number = :acc LIMIT 1");
        $checkStmt->execute([':uid' => $userId, ':acc' => $accountNumber]);
        if ($checkStmt->fetch()) {
            http_response_code(409);
            echo json_encode(['status' => 'error', 'message' => 'This beneficiary account is already registered in your list.']);
            exit;
        }

        // Generate 6-digit OTP and store bcrypt hash with 10-minute expiry [B4]
        $otp = (string)random_int(100000, 999999);
        $otpHash = password_hash($otp, PASSWORD_BCRYPT);

        // Insert new unverified beneficiary
        $insert = $pdo->prepare(
            "INSERT INTO beneficiaries (user_id, name, account_number, bank_name, verified, verification_code_hash, verification_expires_at, verification_attempts, created_at) 
             VALUES (:uid, :name, :acc, :bank, 0, :hash, DATE_ADD(NOW(), INTERVAL 10 MINUTE), 0, NOW())"
        );
        $insert->execute([
            ':uid'  => $userId,
            ':name' => $name,
            ':acc'  => $accountNumber,
            ':bank' => $bankName,
            ':hash' => $otpHash
        ]);

        $bId = (int)$pdo->lastInsertId();

        log_security_event($userId, 'BENEFICIARY_OTP_SENT', 'SUCCESS', "Generated 2-step verification OTP for beneficiary '$name' ($accountNumber)", 'medium');

        require_once __DIR__ . '/../security/notifications.php';
        notify_user(
            $userId,
            'BENEFICIARY_ADDED',
            'Verify New Beneficiary',
            "New beneficiary $name added. Enter verification code: $otp (valid for 10 minutes).",
            '/frontend/verify_beneficiary.html?id=' . $bId,
            'medium'
        );

        http_response_code(201);
        echo json_encode([
            'status'                => 'success',
            'message'               => 'Beneficiary added. 2-Step OTP verification required before transfers can be initiated.',
            'id'                    => $bId,
            'requires_verification' => true,
            'demo_otp'              => (defined('DEMO_MODE') && DEMO_MODE) ? $otp : null
        ]);
        exit;
    }

    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']);

} catch (Throwable $e) {
    error_log('Beneficiaries API Error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Server error processing beneficiaries request.']);
}
