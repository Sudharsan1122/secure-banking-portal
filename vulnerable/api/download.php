<?php
// ⚠️ VULNERABILITY 10: DIRECTORY / PATH TRAVERSAL
$file = $_GET['file'] ?? '';

// INSECURE: Directly using user input in file path
$path = "../../statements/" . $file;

if (file_exists($path)) {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($path).'"');
    readfile($path);
} else {
    echo "File not found: " . $path;
}
