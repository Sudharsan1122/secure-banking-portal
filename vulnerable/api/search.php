<?php
// ⚠️ VULNERABILITY 2 & 4: SQL INJECTION & REFLECTED XSS
require 'db.php';

$query = $_GET['q'] ?? '';

// INSECURE XSS: Reflecting input directly without htmlspecialchars()
echo "<h2>Search Results for: " . $query . "</h2>";

// INSECURE SQLi: Direct concatenation!
$sql = "SELECT * FROM transactions WHERE remark LIKE '%$query%'";
$result = $conn->query($sql);

if ($result) {
    while($row = $result->fetch_assoc()) {
        // ⚠️ VULNERABILITY 3: STORED XSS (Outputting remark directly)
        echo "<div>Transaction: " . $row['amount'] . " - Remark: " . $row['remark'] . "</div>";
    }
} else {
    echo "Error: " . $conn->error;
}
