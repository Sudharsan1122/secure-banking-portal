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
    $_SESSION['username'] = $user['username'];
    $_SESSION['role'] = $user['role'];
    header('Location: ../frontend/dashboard.html?user_id=' . $user['id']);
    exit;
} else {
    echo "<h2>Login Failed</h2><p>Invalid credentials</p><p><a href='../frontend/login.html'>Try Again</a></p>";
}
