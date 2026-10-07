<?php
// ⚠️ VULNERABILITY 11: BROKEN ACCESS CONTROL
session_start();

// INSECURE: Missing check if user role is actually 'admin'
// if ($_SESSION['role'] !== 'admin') { die("Forbidden"); }

echo "<h1>Admin Dashboard (Vulnerable)</h1>";
echo "<p>Welcome to the admin panel. If you are seeing this without logging in as an admin, Broken Access Control exists!</p>";
echo "<button>Delete All Users</button>";
