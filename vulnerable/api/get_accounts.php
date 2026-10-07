<?php
// ⚠️ VULNERABILITY 5: IDOR (Insecure Direct Object Reference)
require 'db.php';

// INSECURE: Trusting client-supplied user_id instead of $_SESSION['user_id']
$user_id = $_GET['user_id'] ?? 1; 

$sql = "SELECT * FROM accounts WHERE user_id = $user_id";
$result = $conn->query($sql);

$accounts = [];
while($row = $result->fetch_assoc()) {
    $accounts[] = $row;
}
echo json_encode($accounts);
