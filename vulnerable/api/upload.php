<?php
// ⚠️ VULNERABILITY 12: MALICIOUS FILE UPLOAD (Unrestricted)
$target_dir = "../../uploads/";
if (!is_dir($target_dir)) { @mkdir($target_dir, 0777, true); }

$origName = basename($_FILES["avatar"]["name"] ?? '');
if (empty($origName)) {
    die("Please select a file to upload. <a href='../frontend/upload.html'>Back</a>");
}

$target_file = $target_dir . $origName;
$web_path = "../../uploads/" . $origName;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Upload Result — InsecureBank</title>
    <link rel="stylesheet" href="../css/vuln_style.css">
</head>
<body style="padding: 2rem;">
    <div class="vuln-container" style="max-width: 600px;">
        <div class="lab-panel">
            <div class="panel-title" style="color: var(--color-danger);">
                <span>💣</span> Upload Result
            </div>
            <?php if (move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file)): ?>
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--color-success); padding: 1rem; border-radius: var(--radius-sm); margin: 1rem 0; color: #a7f3d0;">
                    ✅ The file <b><?= htmlspecialchars($origName) ?></b> was successfully saved to the server!
                </div>
                <p style="margin-bottom: 1rem; color: var(--text-muted); font-size: 0.85rem;">
                    Server path: <code><?= htmlspecialchars($target_file) ?></code>
                </p>
                <div style="display: flex; gap: 0.75rem; margin-top: 1.5rem;">
                    <a href="<?= htmlspecialchars($web_path) ?>" target="_blank" class="btn-launch-exploit" style="background: var(--color-danger); text-decoration: none;">
                        🔥 Execute Uploaded Script
                    </a>
                    <a href="../frontend/upload.html" class="btn-payload" style="text-decoration: none; padding: 0.75rem 1rem;">
                        Back to Lab
                    </a>
                </div>
            <?php else: ?>
                <div style="background: rgba(244, 63, 94, 0.1); border: 1px solid var(--color-danger); padding: 1rem; border-radius: var(--radius-sm); color: #fda4af; margin: 1rem 0;">
                    ❌ Failed to save uploaded file. Check directory permissions.
                </div>
                <a href="../frontend/upload.html" class="btn-payload" style="display: inline-block; margin-top: 1rem; text-decoration: none;">Back</a>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
