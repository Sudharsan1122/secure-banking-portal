<?php
// ⚠️ VULNERABILITY 7: CSRF & VULNERABILITY 3: STORED XSS
require 'db.php';
session_start();

$amount = (float)($_POST['amount'] ?? 0);
$receiver = (int)($_POST['receiver'] ?? 2);
$remark = $_POST['remark'] ?? ''; // Unsanitized
$sender = (int)($_SESSION['user_id'] ?? 1);

$sql = "INSERT INTO transactions (sender_id, receiver_id, amount, remark) VALUES ($sender, $receiver, $amount, '$remark')";
$success = $conn->query($sql);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Transfer Status — InsecureBank</title>
    <link rel="stylesheet" href="../css/vuln_style.css">
</head>
<body style="padding: 2rem;">
    <div class="vuln-container" style="max-width: 600px;">
        <div class="lab-panel">
            <div class="panel-title" style="color: var(--color-success);">
                <span>💸</span> Transfer Status
            </div>
            <?php if ($success): ?>
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--color-success); padding: 1.25rem; border-radius: var(--radius-sm); margin: 1.25rem 0;">
                    <div style="font-weight: 700; color: #a7f3d0;">Transfer Processed (No CSRF Token Required)!</div>
                    <div style="font-size: 0.9rem; color: #fff; margin-top: 0.5rem;">
                        Transferred <b>$<?= number_format($amount, 2) ?></b> from Customer #<?= $sender ?> to Customer #<?= $receiver ?>.
                    </div>
                    <div style="font-size: 0.85rem; color: var(--text-dim); margin-top: 0.5rem;">
                        Raw Stored Remark: <code><?= htmlspecialchars($remark) ?></code>
                    </div>
                </div>
            <?php else: ?>
                <div style="background: rgba(244, 63, 94, 0.1); border: 1px solid var(--color-danger); padding: 1.25rem; border-radius: var(--radius-sm); margin: 1.25rem 0; color: #fda4af;">
                    Database Error: <?= htmlspecialchars($conn->error) ?>
                </div>
            <?php endif; ?>
            <div style="display: flex; gap: 0.75rem; margin-top: 1.5rem;">
                <a href="../frontend/transfer.html" class="btn-launch-exploit" style="text-decoration: none;">New Transfer</a>
                <a href="../frontend/search.html" class="btn-payload" style="text-decoration: none;">Inspect Search (Triggers Stored XSS)</a>
            </div>
        </div>
    </div>
</body>
</html>
