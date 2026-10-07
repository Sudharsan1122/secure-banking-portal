<?php
// Insecure database connection for demonstration
$conn = new mysqli('127.0.0.1', 'root', '', 'secure_bank');
if ($conn->connect_error) { die("Connection failed: " . $conn->connect_error); }
