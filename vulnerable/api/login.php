<?php
// ⚠️ VULNERABILITY 1: SQL INJECTION (Authentication Bypass)
require 'db.php';
session_start();

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

// INSECURE: Direct concatenation!
$query = "SELECT * FROM users WHERE username = '$username' AND password_hash = '$password'";
$result = $conn->query($query);

if ($result && $result->num_rows > 0) {
    $user = $result->fetch_assoc();
    $_SESSION['user_id'] = $user['id'];
    echo json_encode(['status' => 'success', 'message' => 'Login successful', 'redirect' => '../frontend/dashboard.html?user_id=' . $user['id']]);
} else {
    echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
}
