<?php
/**
 * Database Connection Provider (PDO Singleton)
 * 
 * SECURITY PRINCIPLES IMPLEMENTED:
 * 1. Native Prepared Statements: PDO::ATTR_EMULATE_PREPARES is set to FALSE.
 *    This ensures queries are prepared on the MySQL server itself, eliminating
 *    SQL injection even if odd character sets or quoting tricks are attempted.
 * 2. Strict Exception Mode: PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
 *    Forces execution failures to be trapped in try/catch blocks instead of
 *    silently continuing and causing logical vulnerabilities.
 * 3. Error Abstraction: Catch database errors and log them internally; never
 *    echo raw database exception messages (which disclose table names, column
 *    structures, or database usernames) to the client.
 */

require_once __DIR__ . '/constants.php';

class Database {
    private static ?PDO $instance = null;

    /**
     * Get or create the singleton PDO instance
     * @return PDO
     * @throws RuntimeException
     */
    public static function getConnection(): PDO {
        if (self::$instance === null) {
            $ports = [DB_PORT];
            if (DB_PORT === '3306' && !in_array('3307', $ports, true)) {
                $ports[] = '3307'; // Automatic fallback for XAMPP port reallocation
            }

            $lastException = null;
            foreach ($ports as $port) {
                $dsn = sprintf(
                    'mysql:host=%s;port=%s;dbname=%s;charset=%s',
                    DB_HOST,
                    $port,
                    DB_NAME,
                    DB_CHARSET
                );

                $options = [
                    PDO::ATTR_EMULATE_PREPARES   => false,
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_TIMEOUT            => 2,
                ];

                try {
                    self::$instance = new PDO($dsn, DB_USER, DB_PASS, $options);
                    self::$instance->exec("SET time_zone = '" . date('P') . "'");
                    break;
                } catch (PDOException $e) {
                    $lastException = $e;
                }
            }

            if (self::$instance === null && $lastException !== null) {
                error_log('Database Connection Failed: ' . $lastException->getMessage());
                throw new RuntimeException('A database connectivity error occurred. Please verify MySQL service and credentials in config/constants.php.');
            }
        }

        return self::$instance;
    }

    /**
     * Prevent cloning of singleton
     */
    private function __clone() {}

    /**
     * Prevent unserializing
     */
    public function __wakeup() {
        throw new Exception("Cannot unserialize singleton");
    }
}

/**
 * Procedural helper for quick access across API endpoints
 */
function get_db(): PDO {
    return Database::getConnection();
}
