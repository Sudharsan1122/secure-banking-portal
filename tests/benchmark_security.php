<?php
/**
 * Empirical Security Performance Benchmark Script
 * 
 * Measures the exact microsecond and millisecond overhead of key security controls:
 * 1. Bcrypt Cost Factor Latency Curve (cost 10, 11, 12, 13, 14)
 * 2. CSPRNG Nonce Generation (CSP 2.0)
 * 3. Input Canonicalization & Unicode NFKC Normalization
 * 4. Timing-Safe CSRF Token Generation & Verification (hash_equals)
 * 5. Pessimistic Row Locking Concurrency in Database Transactions
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/csrf.php';

$results = [];

// 1. Bcrypt Cost Factor Benchmark
$password = 'SecureP@ssw0rd!2026';
$costs = [10, 11, 12, 13];
$bcryptResults = [];

foreach ($costs as $cost) {
    $iterations = ($cost <= 11) ? 5 : 2;
    $times = [];
    for ($i = 0; $i < $iterations; $i++) {
        $start = microtime(true);
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => $cost]);
        $end = microtime(true);
        $times[] = ($end - $start) * 1000; // in milliseconds
    }
    $avgMs = array_sum($times) / count($times);
    $bcryptResults[$cost] = round($avgMs, 2);
}
$results['bcrypt'] = $bcryptResults;

// 2. CSPRNG Nonce Generation Latency
$nonceIterations = 1000;
$startNonce = microtime(true);
for ($i = 0; $i < $nonceIterations; $i++) {
    $nonce = base64_encode(random_bytes(32));
}
$endNonce = microtime(true);
$avgNonceUs = (($endNonce - $startNonce) / $nonceIterations) * 1000000; // microseconds
$results['nonce_us'] = round($avgNonceUs, 3);

// 3. Input Canonicalization Latency
$dirtyString = "   Hello <script>alert(1)</script> \0 \u{0041}\u{030A} &amp; &lt;   ";
$canonIterations = 1000;
$startCanon = microtime(true);
for ($i = 0; $i < $canonIterations; $i++) {
    $clean = canonicalize_input($dirtyString);
}
$endCanon = microtime(true);
$avgCanonUs = (($endCanon - $startCanon) / $canonIterations) * 1000000; // microseconds
$results['canonicalization_us'] = round($avgCanonUs, 3);

// 4. CSRF Token Generation & Validation Latency
$csrfIterations = 1000;
$startCsrf = microtime(true);
for ($i = 0; $i < $csrfIterations; $i++) {
    $token = bin2hex(random_bytes(32));
    $valid = hash_equals($token, $token);
}
$endCsrf = microtime(true);
$avgCsrfUs = (($endCsrf - $startCsrf) / $csrfIterations) * 1000000; // microseconds
$results['csrf_us'] = round($avgCsrfUs, 3);

// 5. Database Row-Locking Concurrency Benchmark
$pdo = get_db();
$sName = 'bench_user_' . bin2hex(random_bytes(3));
$pdo->prepare("INSERT INTO users (username, email, password_hash, name, role, balance) VALUES (?, ?, 'hash', 'Bench User', 'user', 1000.00)")
    ->execute([$sName, "$sName@test.local"]);
$uid = (int)$pdo->lastInsertId();

$accNum = 'ACC-BENCH-' . random_int(10000, 99999);
$pdo->prepare("INSERT INTO accounts (user_id, account_number, balance, type) VALUES (?, ?, 1000.00, 'savings')")
    ->execute([$uid, $accNum]);
$accId = (int)$pdo->lastInsertId();

$dbIterations = 20;
$dbTimes = [];
for ($i = 0; $i < $dbIterations; $i++) {
    $startDb = microtime(true);
    $pdo->beginTransaction();
    $stmt = $pdo->prepare("SELECT balance FROM accounts WHERE id = ? FOR UPDATE");
    $stmt->execute([$accId]);
    $bal = (float)$stmt->fetchColumn();
    $pdo->prepare("UPDATE accounts SET balance = balance + 1.00 WHERE id = ?")->execute([$accId]);
    $pdo->commit();
    $endDb = microtime(true);
    $dbTimes[] = ($endDb - $startDb) * 1000; // ms
}
$avgDbMs = array_sum($dbTimes) / count($dbTimes);
$results['row_lock_ms'] = round($avgDbMs, 3);

// Cleanup
$pdo->prepare("DELETE FROM accounts WHERE user_id = ?")->execute([$uid]);
$pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$uid]);

echo json_encode($results, JSON_PRETTY_PRINT) . "\n";
