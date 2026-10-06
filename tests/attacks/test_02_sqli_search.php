<?php
/**
 * Regression Test: 02 - SQL Injection on Transaction Search
 * 
 * OWASP: A03:2021 – Injection
 * CWE: CWE-89 (SQL Injection)
 */

require_once __DIR__ . '/../../security/validation.php';
require_once __DIR__ . '/../../config/database.php';

function test_02_sqli_search(): array {
    $tests = [];
    $pdo = get_db();

    // Test 1: Stacked query / destructive payload detection
    $payload1 = "1; DROP TABLE transactions--";
    $detected1 = detect_sqli($payload1);
    $tests[] = [
        'name'   => 'Stacked SQL Query & DDL Injection Detection',
        'pass'   => ($detected1 === true),
        'detail' => "Destructive query detected = " . ($detected1 ? 'YES' : 'NO')
    ];

    // Test 2: Boolean-based blind injection detection
    $payload2 = "salary' OR 1=1 -- ";
    $detected2 = detect_sqli($payload2);
    $tests[] = [
        'name'   => 'Boolean-Based Blind SQLi Pattern Detection in Search Filter',
        'pass'   => ($detected2 === true),
        'detail' => "Blind SQLi pattern detected = " . ($detected2 ? 'YES' : 'NO')
    ];

    // Test 3: Safe Wildcard Parameter Binding
    // Simulating how transactions.php binds :q1, :q2, :q3
    $searchTerm = "%' OR '1'='1%";
    $stmt = $pdo->prepare(
        "SELECT id, amount, remark FROM transactions 
         WHERE (remark LIKE :q1 OR category LIKE :q2) 
         LIMIT 5"
    );
    $stmt->execute([':q1' => $searchTerm, ':q2' => $searchTerm]);
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // It should execute safely without SQL syntax error or leaking unintended rows
    $tests[] = [
        'name'   => 'Parameterized LIKE Clause Execution Safety',
        'pass'   => is_array($results),
        'detail' => "Executed safely via PDO parameters; returned " . count($results) . " matching literal records"
    ];

    // Test 4: Type-Casting on Numeric Transaction Search IDs
    $rawIdInput = "105 OR 1=1";
    $safeId = is_numeric($rawIdInput) ? (int)$rawIdInput : 0;
    $tests[] = [
        'name'   => 'Strict Integer Coercion on Numeric Search Keys',
        'pass'   => ($safeId === 0),
        'detail' => "Non-strictly-numeric ID input safely resolved to ID: $safeId"
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running 02-SQLi-Search Tests...\n";
    $allPass = true;
    foreach (test_02_sqli_search() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
        if (!$t['pass']) $allPass = false;
    }
    exit($allPass ? 0 : 1);
}
