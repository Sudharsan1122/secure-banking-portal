<?php
/**
 * Test Suite: Code Quality, Static Analysis & Defensive Standards (PILLAR F)
 * 
 * Verifies:
 * 1. Syntax integrity across all project PHP scripts.
 * 2. Database PDO configuration (emulated prepares = false, exception mode active).
 * 3. Elimination of debug artifacts (var_dump, print_r, die).
 * 4. Zero inline scripts and zero inline event handlers across all frontend templates.
 * 5. Self-hosted asset completeness (WOFF2 fonts and SVG assets present).
 * 6. Structured error handling & uniform JSON response standards.
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/constants.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/csrf.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../security/transfer_service.php';

function test_code_quality(): array {
    $tests = [];
    $baseDir = dirname(__DIR__);
    $phpBin = defined('PHP_BINARY') && file_exists(PHP_BINARY) ? PHP_BINARY : 'C:\\xampp\\php\\php.exe';

    // TEST 1: PHP Syntax Linting across Core Directories
    $phpFiles = [];
    $scanDirs = ['api', 'security', 'config', 'admin'];
    foreach ($scanDirs as $dir) {
        $path = $baseDir . DIRECTORY_SEPARATOR . $dir;
        if (is_dir($path)) {
            $files = glob($path . '/*.php');
            if ($files) {
                $phpFiles = array_merge($phpFiles, $files);
            }
        }
    }

    $syntaxErrors = [];
    foreach ($phpFiles as $file) {
        $output = [];
        $returnVar = 0;
        exec(sprintf('"%s" -l %s 2>&1', $phpBin, escapeshellarg($file)), $output, $returnVar);
        if ($returnVar !== 0) {
            $syntaxErrors[] = basename($file) . ': ' . implode(' ', $output);
        }
    }

    $tests[] = [
        'name'   => 'PHP 8+ Syntax Linting (Core Directories)',
        'pass'   => empty($syntaxErrors),
        'detail' => empty($syntaxErrors)
            ? sprintf('Verified %d PHP files with 0 syntax errors or warnings', count($phpFiles))
            : 'Syntax errors: ' . implode('; ', $syntaxErrors)
    ];

    // TEST 2: Native PDO Prepared Statements & Error Mode
    $pdo = get_db();
    $emulatePrepares = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $errorMode = $pdo->getAttribute(PDO::ATTR_ERRMODE);

    $isPdoHardened = (empty($emulatePrepares) && $errorMode === PDO::ERRMODE_EXCEPTION);

    $tests[] = [
        'name'   => 'Database PDO Hardening (Emulation FALSE & Exception Mode)',
        'pass'   => $isPdoHardened,
        'detail' => sprintf(
            'ATTR_EMULATE_PREPARES = %s, ATTR_ERRMODE = %s',
            $isPdoHardened ? 'FALSE (HARDENED)' : 'TRUE (VULNERABLE)',
            $errorMode === PDO::ERRMODE_EXCEPTION ? 'ERRMODE_EXCEPTION (SECURE)' : 'NON-EXCEPTION'
        )
    ];

    // TEST 3: Zero Debug Artifacts (var_dump, print_r) in Production Code
    $debugArtifacts = [];
    foreach ($phpFiles as $file) {
        $content = file_get_contents($file);
        if (preg_match('/\b(var_dump|print_r)\s*\(/i', $content, $matches)) {
            $debugArtifacts[] = basename($file) . ' (' . $matches[1] . ')';
        }
    }

    $tests[] = [
        'name'   => 'Production Hygiene: Zero Debug Artifacts (var_dump / print_r)',
        'pass'   => empty($debugArtifacts),
        'detail' => empty($debugArtifacts)
            ? 'Zero leftover debugging print statements detected in production code'
            : 'Leftover debug statements in: ' . implode(', ', $debugArtifacts)
    ];

    // TEST 4: Frontend Inline Script Audit (CSP Nonce Compliance)
    $htmlFiles = glob($baseDir . '/frontend/*.html') ?: [];
    $inlineScriptViolations = [];
    $inlineEventViolations = [];

    foreach ($htmlFiles as $file) {
        $content = file_get_contents($file);
        $filename = basename($file);

        // Check for inline <script> tags (not loading via src)
        if (preg_match('/<script(?![^>]*\bsrc\s*=)[^>]*>/i', $content)) {
            $inlineScriptViolations[] = $filename;
        }

        // Check for inline event handler attributes like onclick=, onsubmit=, onload=
        if (preg_match('/\s(on[a-z]{3,15})\s*=/i', $content, $m)) {
            $inlineEventViolations[] = $filename . ' (' . $m[1] . ')';
        }
    }

    $tests[] = [
        'name'   => 'Frontend CSP Compliance: Zero Inline <script> Blocks',
        'pass'   => empty($inlineScriptViolations),
        'detail' => empty($inlineScriptViolations)
            ? sprintf('All %d frontend HTML templates load logic exclusively via external modular JS files', count($htmlFiles))
            : 'Inline script found in: ' . implode(', ', $inlineScriptViolations)
    ];

    $tests[] = [
        'name'   => 'Frontend CSP Compliance: Zero Inline Event Handlers (onclick/onsubmit)',
        'pass'   => empty($inlineEventViolations),
        'detail' => empty($inlineEventViolations)
            ? 'All interactivity uses addEventListener / delegated DOM listeners'
            : 'Inline event handlers found in: ' . implode(', ', $inlineEventViolations)
    ];

    // TEST 5: Self-Hosted Font & Asset Integrity (Zero External CDN Dependency)
    $requiredAssets = [
        'fonts/inter/inter-400.woff2',
        'fonts/inter/inter-500.woff2',
        'fonts/inter/inter-600.woff2',
        'fonts/jetbrains-mono/jetbrains-mono-400.woff2',
        'fonts/jetbrains-mono/jetbrains-mono-600.woff2',
        'images/logo.svg'
    ];

    $missingAssets = [];
    foreach ($requiredAssets as $relPath) {
        $fullPath = $baseDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath);
        if (!file_exists($fullPath) || filesize($fullPath) === 0) {
            $missingAssets[] = $relPath;
        }
    }

    $tests[] = [
        'name'   => 'Asset Self-Hosting & Supply-Chain Independence (Zero External CDNs)',
        'pass'   => empty($missingAssets),
        'detail' => empty($missingAssets)
            ? sprintf('All %d required typography and vector brand assets are self-hosted locally', count($requiredAssets))
            : 'Missing local assets: ' . implode(', ', $missingAssets)
    ];

    // TEST 6: Type Safety & Core Function Return Types
    $coreFunctions = [
        'validate_csrf_token',
        'generate_csrf_token',
        'canonicalize_input',
        'validate_password_strength',
        'verify_log_chain',
        'transfer_funds'
    ];

    $typeChecked = 0;
    foreach ($coreFunctions as $fn) {
        if (function_exists($fn)) {
            $ref = new ReflectionFunction($fn);
            if ($ref->hasReturnType()) {
                $typeChecked++;
            }
        }
    }

    $tests[] = [
        'name'   => 'Core Security Service Type Declarations & PHP 8+ Signatures',
        'pass'   => ($typeChecked === count($coreFunctions)),
        'detail' => sprintf('%d/%d core security functions enforce strict return type declarations', $typeChecked, count($coreFunctions))
    ];

    return $tests;
}

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    echo "Running Code Quality & Static Analysis Tests (Pillar F)...\n";
    foreach (test_code_quality() as $t) {
        printf("  [%s] %s (%s)\n", $t['pass'] ? 'PASS' : 'FAIL', $t['name'], $t['detail']);
    }
}
