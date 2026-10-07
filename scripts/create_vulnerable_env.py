import os

VULN_DIR = 'vulnerable'

files = {
    f'{VULN_DIR}/index.html': '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Insecure Bank - Vulnerable Training Portal</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #ffebee; color: #b71c1c; padding: 2rem; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { border-bottom: 2px solid #b71c1c; padding-bottom: 10px; }
        ul { list-style: none; padding: 0; }
        li { margin: 10px 0; padding: 15px; background: #ffcdd2; border-left: 4px solid #b71c1c; border-radius: 4px; }
        a { color: #b71c1c; text-decoration: none; font-weight: bold; font-size: 1.1em; display: block; }
        a:hover { text-decoration: underline; }
        .badge { display: inline-block; padding: 3px 8px; background: #b71c1c; color: white; border-radius: 12px; font-size: 0.8em; margin-left: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ Insecure Bank (Vulnerable Training Portal)</h1>
        <p>This is the intentionally vulnerable version of the Secure Banking Portal. <b>Do not expose this to the internet.</b> It contains 12 active vulnerabilities for demonstration and training purposes.</p>
        
        <h2>Attack Vectors Sandbox</h2>
        <ul>
            <li><a href="frontend/login.html">1. Login Bypass <span class="badge">SQLi</span></a> (Try username: <code>admin' OR '1'='1' -- </code>)</li>
            <li><a href="frontend/dashboard.html">2. Account IDOR <span class="badge">Broken Access Control</span></a> (Change <code>?user_id=1</code> in URL)</li>
            <li><a href="frontend/transfer.html">3. Money Transfer <span class="badge">CSRF</span> <span class="badge">Clickjacking</span></a> (No CSRF tokens, no X-Frame-Options)</li>
            <li><a href="frontend/search.html">4. Transaction Search <span class="badge">SQLi</span> <span class="badge">Reflected XSS</span></a> (Try search: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>)</li>
            <li><a href="frontend/statements.html">5. Statement Download <span class="badge">Path Traversal</span></a> (Try download: <code>../../../../windows/win.ini</code>)</li>
            <li><a href="frontend/upload.html">6. Avatar Upload <span class="badge">File Upload</span></a> (Upload a <code>.php</code> reverse shell file)</li>
            <li><a href="api/admin.php">7. Admin Dashboard <span class="badge">Broken Access Control</span></a> (Directly accessible without admin role)</li>
        </ul>
    </div>
</body>
</html>''',

    f'{VULN_DIR}/api/db.php': '''<?php
// Insecure database connection for demonstration
$conn = new mysqli('127.0.0.1', 'root', '', 'secure_bank');
if ($conn->connect_error) { die("Connection failed: " . $conn->connect_error); }
''',

    f'{VULN_DIR}/api/login.php': '''<?php
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
    echo json_encode(['status' => 'success', 'message' => 'Login successful', 'redirect' => '../frontend/dashboard.html?user_id=' . $user['id']]);
} else {
    echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
}
''',

    f'{VULN_DIR}/api/search.php': '''<?php
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
''',

    f'{VULN_DIR}/api/transfer.php': '''<?php
// ⚠️ VULNERABILITY 7: CSRF (Cross-Site Request Forgery)
// Missing CSRF token validation!
require 'db.php';
session_start();

$amount = $_POST['amount'] ?? 0;
$receiver = $_POST['receiver'] ?? '';
$remark = $_POST['remark'] ?? ''; // ⚠️ VULNERABILITY 3: STORED XSS (Not sanitized before DB insert)
$sender = $_SESSION['user_id'] ?? 1; // Fallback to 1 for easy demo

$sql = "INSERT INTO transactions (sender_id, receiver_id, amount, remark) VALUES ($sender, $receiver, $amount, '$remark')";
$conn->query($sql);

echo "Transfer of $amount successful!";
''',

    f'{VULN_DIR}/api/get_accounts.php': '''<?php
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
''',

    f'{VULN_DIR}/api/download.php': '''<?php
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
''',

    f'{VULN_DIR}/api/upload.php': '''<?php
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
''',

    f'{VULN_DIR}/api/admin.php': '''<?php
// ⚠️ VULNERABILITY 11: BROKEN ACCESS CONTROL
session_start();

// INSECURE: Missing check if user role is actually 'admin'
// if ($_SESSION['role'] !== 'admin') { die("Forbidden"); }

echo "<h1>Admin Dashboard (Vulnerable)</h1>";
echo "<p>Welcome to the admin panel. If you are seeing this without logging in as an admin, Broken Access Control exists!</p>";
echo "<button>Delete All Users</button>";
''',

    f'{VULN_DIR}/frontend/login.html': '''<!DOCTYPE html>
<html>
<body>
    <h2>Insecure Login (Test SQLi here)</h2>
    <form action="../api/login.php" method="POST">
        Username: <input type="text" name="username" value="admin' OR '1'='1' -- "><br><br>
        Password: <input type="password" name="password"><br><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>''',

    f'{VULN_DIR}/frontend/dashboard.html': '''<!DOCTYPE html>
<html>
<body>
    <h2>Insecure Dashboard (Test IDOR & DOM XSS here)</h2>
    
    <!-- ⚠️ VULNERABILITY 9: DOM XSS -->
    <div id="greeting"></div>
    <script>
        // INSECURE DOM XSS: Reading from URL hash and setting innerHTML directly
        let hash = decodeURIComponent(window.location.hash.substring(1));
        if(hash) {
            document.getElementById('greeting').innerHTML = "Welcome, " + hash;
        } else {
            document.getElementById('greeting').innerHTML = "Welcome, User";
        }
    </script>
    
    <p>Try appending <code>#&lt;img src=x onerror=alert('DOM_XSS')&gt;</code> to the URL.</p>

    <hr>
    <h3>Your Accounts (IDOR Test)</h3>
    <p>Try changing <code>?user_id=1</code> in the URL to <code>?user_id=2</code> to see someone else's accounts.</p>
    <div id="accounts"></div>
    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const userId = urlParams.get('user_id') || 1;
        fetch('../api/get_accounts.php?user_id=' + userId)
            .then(res => res.json())
            .then(data => {
                document.getElementById('accounts').innerText = JSON.stringify(data, null, 2);
            });
    </script>
</body>
</html>''',

    f'{VULN_DIR}/frontend/transfer.html': '''<!DOCTYPE html>
<html>
<head>
    <!-- ⚠️ VULNERABILITY 8: CLICKJACKING (Missing X-Frame-Options) -->
</head>
<body>
    <h2>Insecure Transfer (Test CSRF & Clickjacking here)</h2>
    <form action="../api/transfer.php" method="POST">
        Receiver ID: <input type="text" name="receiver" value="2"><br><br>
        Amount: <input type="text" name="amount" value="1000"><br><br>
        Remark: <input type="text" name="remark" value="<script>alert('Stored XSS')</script>"><br><br>
        <!-- No CSRF Token! -->
        <button type="submit">Transfer Money</button>
    </form>
</body>
</html>''',

    f'{VULN_DIR}/frontend/search.html': '''<!DOCTYPE html>
<html>
<body>
    <h2>Insecure Search (Test Reflected XSS & SQLi here)</h2>
    <form action="../api/search.php" method="GET">
        Search Remark: <input type="text" name="q" value="<script>alert('Reflected XSS')</script>"><br><br>
        <button type="submit">Search</button>
    </form>
</body>
</html>''',

    f'{VULN_DIR}/frontend/statements.html': '''<!DOCTYPE html>
<html>
<body>
    <h2>Insecure Statement Download (Test Path Traversal here)</h2>
    <form action="../api/download.php" method="GET">
        Filename: <input type="text" name="file" value="../../../../Windows/win.ini"><br><br>
        <button type="submit">Download</button>
    </form>
</body>
</html>''',

    f'{VULN_DIR}/frontend/upload.html': '''<!DOCTYPE html>
<html>
<body>
    <h2>Insecure File Upload (Test RCE here)</h2>
    <form action="../api/upload.php" method="POST" enctype="multipart/form-data">
        Select image to upload (Try a .php file!):
        <input type="file" name="avatar" id="avatar"><br><br>
        <button type="submit" name="submit">Upload File</button>
    </form>
</body>
</html>'''
}

for filepath, content in files.items():
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

print(f"Created {len(files)} files in {VULN_DIR}/ successfully.")
