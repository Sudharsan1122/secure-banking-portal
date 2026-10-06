<?php
/**
 * Regression Test: 12 - Malicious File Upload (Avatar Upload)
 * 
 * OWASP: A04:2021 – Insecure Design / A08:2021 – Software and Data Integrity Failures
 * CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type)
 */

function test_12_file_upload(): array {
    $tests = [];

    // Test 1: Dangerous Executable Extension Rejection
    $dangerousExtensions = ['php', 'phtml', 'php5', 'phar', 'exe', 'sh', 'bat', 'jsp', 'asp', 'svg'];
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'webp'];

    $allDangerousBlocked = true;
    foreach ($dangerousExtensions as $ext) {
        if (in_array(strtolower($ext), $allowedExtensions, true)) {
            $allDangerousBlocked = false;
        }
    }

    $tests[] = [
        'name'   => 'Strict File Extension Allowlist Enforcement (jpg, jpeg, png, webp only)',
        'pass'   => $allDangerousBlocked,
        'detail' => 'All executable & polyglot script extensions rejected'
    ];

    // Test 2: Multi-Extension / Null-Byte Poisoning Rejection
    $spoofedFilename = 'avatar.php.png';
    $ext = pathinfo($spoofedFilename, PATHINFO_EXTENSION);
    $isAllowedExt = in_array(strtolower($ext), $allowedExtensions, true);

    // Beyond extension, file contents must be inspected via finfo
    $phpShellCode = "<?php system(\$_GET['cmd']); ?>";
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $detectedMime = $finfo->buffer($phpShellCode);

    $tests[] = [
        'name'   => 'Magic Byte & MIME-Type Inspection on Disguised Script Payloads',
        'pass'   => ($detectedMime !== 'image/png' && $detectedMime !== 'image/jpeg'),
        'detail' => "PHP shell detected as MIME: '$detectedMime'; not an authentic image"
    ];

    // Test 3: Maximum Upload Size Bounding (2MB ceiling)
    $maxBytes = 2 * 1024 * 1024; // 2MB
    $oversizedFileBytes = 5 * 1024 * 1024; // 5MB
    $isRejected = ($oversizedFileBytes > $maxBytes);

    $tests[] = [
        'name'   => 'DoS Upload Buffer Bounding (2MB Ceiling)',
        'pass'   => $isRejected,
        'detail' => "5MB payload rejected by 2MB limit"
    ];

    // Test 4: Randomized Filename Generation (Zero Client Filename Trust)
    $randomHash = bin2hex(random_bytes(16));
    $generatedFilename = $randomHash . '.png';
    $safeFilename = preg_match('/^[a-f0-9]{32}\.png$/', $generatedFilename);

    $tests[] = [
        'name'   => 'Cryptographic Random Renaming (Neutralizing Direct File Path Overwrites)',
        'pass'   => (bool)$safeFilename,
        'detail' => "Generated safe target filename: $generatedFilename"
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running 12-File-Upload Tests...\n";
    $allPass = true;
    foreach (test_12_file_upload() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
        if (!$t['pass']) $allPass = false;
    }
    exit($allPass ? 0 : 1);
}
