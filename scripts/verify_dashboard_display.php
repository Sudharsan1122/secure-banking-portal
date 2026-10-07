<?php
/**
 * Test Admin Dashboard Display
 */

// 1. Login as admin
$ch = curl_init('http://127.0.0.1:8080/api/login.php');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['username' => 'admin', 'password' => 'Admin@1234']));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
curl_setopt($ch, CURLOPT_HEADER, true);
$resp = curl_exec($ch);

preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $resp, $matches);
$cookie = implode('; ', $matches[1]);

// 2. Fetch MFA code
require_once __DIR__ . '/../config/database.php';
$pdo = get_db();
$code = $pdo->query("SELECT code FROM otp_codes WHERE user_id = 1 ORDER BY id DESC LIMIT 1")->fetchColumn();

// 3. Verify MFA
$ch = curl_init('http://127.0.0.1:8080/api/verify_otp.php');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['otp' => $code]));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'Cookie: ' . $cookie]);
curl_setopt($ch, CURLOPT_HEADER, true);
$respMfa = curl_exec($ch);
preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $respMfa, $matchesMfa);
if (!empty($matchesMfa[1])) {
    $cookie = implode('; ', $matchesMfa[1]);
}

// 4. Fetch Admin Dashboard HTML
$ch = curl_init('http://127.0.0.1:8080/admin/security-dashboard.php');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Cookie: ' . $cookie]);
$dashHtml = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

echo "Admin Dashboard HTTP Status: $code" . PHP_EOL;

echo "Contains XSS_BLOCKED in feed: " . (str_contains($dashHtml, 'XSS_BLOCKED') ? 'YES' : 'NO') . PHP_EOL;
echo "Contains SQLI_BLOCKED in feed: " . (str_contains($dashHtml, 'SQLI_BLOCKED') ? 'YES' : 'NO') . PHP_EOL;
echo "Contains DIRECTORY_TRAVERSAL in feed: " . (str_contains($dashHtml, 'DIRECTORY_TRAVERSAL') ? 'YES' : 'NO') . PHP_EOL;
echo "Contains MALICIOUS_UPLOAD in alerts: " . (str_contains($dashHtml, 'MALICIOUS_UPLOAD') ? 'YES' : 'NO') . PHP_EOL;
echo "Contains BAC_VIOLATION in alerts: " . (str_contains($dashHtml, 'BAC_VIOLATION') ? 'YES' : 'NO') . PHP_EOL;
echo "Contains TRAVERSAL_SPIKE in alerts: " . (str_contains($dashHtml, 'TRAVERSAL_SPIKE') ? 'YES' : 'NO') . PHP_EOL;
echo "Contains CSRF_BURST in alerts: " . (str_contains($dashHtml, 'CSRF_BURST') ? 'YES' : 'NO') . PHP_EOL;
echo "Contains IDOR_VIOLATION in alerts: " . (str_contains($dashHtml, 'IDOR_VIOLATION') ? 'YES' : 'NO') . PHP_EOL;
echo "Contains XSS_ATTACK in alerts: " . (str_contains($dashHtml, 'XSS_ATTACK') ? 'YES' : 'NO') . PHP_EOL;
echo "Contains SQLI_SPIKE in alerts: " . (str_contains($dashHtml, 'SQLI_SPIKE') ? 'YES' : 'NO') . PHP_EOL;
