<?php
// ⚠️ VULNERABILITY 12: MALICIOUS FILE UPLOAD (Unrestricted)
$target_dir = "../../uploads/";
$target_file = $target_dir . basename($_FILES["avatar"]["name"]);

// INSECURE: No extension checking, no MIME checking, keeps original filename
if (move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file)) {
    echo "The file ". basename( $_FILES["avatar"]["name"]). " has been uploaded.";
    echo "<br>Access it here: <a href='$target_file'>$target_file</a>";
} else {
    echo "Sorry, there was an error uploading your file.";
}
