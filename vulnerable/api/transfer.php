<?php
// ⚠️ VULNERABILITY 7: CSRF (Cross-Site Request Forgery)
// Missing CSRF token validation!
require 'db.php';
session_start();

$amount = $_POST['amount'] ?? 0;
$receiver = $_POST['receiver'] ?? '';
$remark = $_POST['remark'] ?? ''; // ⚠️ VULNERABILITY 3: STORED XSS (Not sanitized before DB insert)
$sender = $_SESSION['user_id'] ?? 1; // Fallback to 1 for easy demo

$sql = "INSERT INTO transactions (sender_id, receiver_id, amount, remark) VALUES ($sender, $receiver, $amount, '$remark')";
$conn->query($sql);

echo "Transfer of $amount successful!";
