<?php
// ⚠️ VULNERABILITY 2 & 4: SQL INJECTION & REFLECTED XSS
require 'db.php';

$query = $_GET['q'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Search Results — InsecureBank</title>
    <link rel="stylesheet" href="../css/vuln_style.css">
</head>
<body style="padding: 1.5rem; background: #070b14;">
    <div style="max-width: 800px; margin: 0 auto;">
        <!-- Insecure Reflection (triggers Reflected XSS) -->
        <h2 style="margin-bottom: 1rem; color: #fff;">Search Results for: <?= $query ?></h2>
        
        <?php
        // Insecure SQLi concatenation
        $sql = "SELECT * FROM transactions WHERE remark LIKE '%$query%' LIMIT 20";
        $result = $conn->query($sql);
        ?>
        
        <?php if ($result && $result->num_rows > 0): ?>
            <div style="display: grid; gap: 0.75rem;">
                <?php while($row = $result->fetch_assoc()): ?>
                    <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); padding: 1rem; border-radius: var(--radius-sm); display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <div style="font-size: 0.75rem; color: var(--text-dim); font-weight: 600;">TRANSACTION #<?= $row['id'] ?></div>
                            <!-- Insecure Stored XSS reflection -->
                            <div style="color: #fff; margin-top: 0.25rem;">Remark: <?= $row['remark'] ?></div>
                        </div>
                        <div style="font-weight: 700; color: var(--color-success); font-family: var(--font-mono);">
                            $<?= number_format((float)$row['amount'], 2) ?>
                        </div>
                    </div>
                <?php endwhile; ?>
            </div>
        <?php elseif ($result): ?>
            <div style="color: var(--text-muted); padding: 1rem; background: var(--bg-card); border-radius: var(--radius-sm);">No transactions matched your search query.</div>
        <?php else: ?>
            <div style="color: var(--color-danger); padding: 1rem; background: rgba(244,63,94,0.1); border-radius: var(--radius-sm);">Database Query Error: <?= htmlspecialchars($conn->error) ?></div>
        <?php endif; ?>
        
        <div style="margin-top: 1.5rem;">
            <a href="../frontend/search.html" class="btn-payload" style="text-decoration: none;">&larr; Back to Search Filter</a>
        </div>
    </div>
</body>
</html>
