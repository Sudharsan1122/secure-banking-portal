<?php
echo "Connecting to MySQL on 127.0.0.1:3306 with root...\n";
try {
    $pdo = new PDO('mysql:host=127.0.0.1;port=3306;charset=utf8mb4', 'root', '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);
    echo "Connected successfully to MySQL server!\n";

    echo "Reading database/banking.sql...\n";
    $sql = file_get_contents(__DIR__ . '/../database/banking.sql');
    if (!$sql) {
        die("Could not read banking.sql!\n");
    }

    echo "Executing banking.sql statements...\n";
    $pdo->exec($sql);
    echo "Imported database/banking.sql successfully!\n";

    // Verify tables
    $pdo->exec("USE secure_banking");
    $stmt = $pdo->query("SHOW TABLES");
    $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
    echo "Tables in secure_banking: " . implode(', ', $tables) . "\n";

    // Verify user count
    $userCount = $pdo->query("SELECT count(*) FROM users")->fetchColumn();
    echo "Total users in database: " . $userCount . "\n";
} catch (Throwable $e) {
    echo "ERROR: " . $e->getMessage() . "\n";
}
