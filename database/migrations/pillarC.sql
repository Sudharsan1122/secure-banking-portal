-- ===============================================================
-- Database Migration: Pillar C — Observability & SOC Infrastructure
-- ===============================================================
USE `secure_banking`;

-- 1. Ensure security_logs severity column and performance indexes exist
ALTER TABLE `security_logs`
  ADD COLUMN IF NOT EXISTS `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low' AFTER `event_type`;

-- Add indexes if not exists (using helper procedure or direct ignore)
-- MySQL 8.0+ supports IF NOT EXISTS on indexes, MariaDB supports CREATE OR REPLACE / IGNORE
SET @dbname = DATABASE();
SET @tablename = "security_logs";

-- Index: idx_severity
SET @preparedStatement = (SELECT IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND INDEX_NAME = 'idx_severity') > 0,
  "SELECT 1",
  "CREATE INDEX idx_severity ON security_logs (severity)"
));
PREPARE createIdx FROM @preparedStatement;
EXECUTE createIdx;
DEALLOCATE PREPARE createIdx;

-- Index: idx_event_timestamp
SET @preparedStatement = (SELECT IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND INDEX_NAME = 'idx_event_timestamp') > 0,
  "SELECT 1",
  "CREATE INDEX idx_event_timestamp ON security_logs (event_type, timestamp)"
));
PREPARE createIdx FROM @preparedStatement;
EXECUTE createIdx;
DEALLOCATE PREPARE createIdx;

-- Index: idx_ip_event
SET @preparedStatement = (SELECT IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND INDEX_NAME = 'idx_ip_event') > 0,
  "SELECT 1",
  "CREATE INDEX idx_ip_event ON security_logs (ip_address, event_type)"
));
PREPARE createIdx FROM @preparedStatement;
EXECUTE createIdx;
DEALLOCATE PREPARE createIdx;

-- 2. Create Alerts Table (C7: Automated Alerting Engine)
CREATE TABLE IF NOT EXISTS `alerts` (
  `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
  `rule_name` VARCHAR(64) NOT NULL,
  `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
  `triggered_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `context` JSON NOT NULL,
  `acknowledged` BOOLEAN DEFAULT FALSE,
  `acknowledged_by` INT NULL,
  `acknowledged_at` TIMESTAMP NULL,
  CONSTRAINT `fk_alerts_acknowledged_by` FOREIGN KEY (`acknowledged_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  INDEX `idx_ack` (`acknowledged`),
  INDEX `idx_severity_time` (`severity`, `triggered_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Create Alert Rules Table (C7: Rule Configuration)
CREATE TABLE IF NOT EXISTS `alert_rules` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(64) UNIQUE NOT NULL,
  `description` TEXT,
  `enabled` BOOLEAN DEFAULT TRUE,
  `threshold` INT NOT NULL,
  `window_seconds` INT NOT NULL,
  `event_type` VARCHAR(64) NOT NULL,
  `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_rule_event_enabled` (`event_type`, `enabled`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Seed Standard SIEM Detection Rules
INSERT INTO `alert_rules` (`name`, `description`, `enabled`, `threshold`, `window_seconds`, `event_type`, `severity`)
VALUES
  ('CSRF_BURST', 'Multiple CSRF token mismatches within 10 minutes indicating cross-site attack attempt', 1, 5, 600, 'CSRF_FAILURE', 'high'),
  ('BRUTE_FORCE_IP', 'Concentrated failed logins from single IP address within 10 minutes', 1, 20, 600, 'LOGIN_FAILED', 'high'),
  ('LARGE_TRANSFER', 'High-value funds transfer exceeding risk threshold (>= ₹1,00,000 / $10,000)', 1, 1, 60, 'TRANSFER_SUCCESS', 'high'),
  ('SQLI_SPIKE', 'Repeated SQL injection payload signatures intercepted within 5 minutes', 1, 3, 300, 'SQLI_BLOCKED', 'critical'),
  ('TRAVERSAL_SPIKE', 'Repeated directory traversal path manipulations detected within 5 minutes', 1, 3, 300, 'DIRECTORY_TRAVERSAL', 'high'),
  ('CHAIN_TAMPER', 'Cryptographic audit log integrity validation failure or hash chain corruption', 1, 1, 60, 'HASH_CHAIN_TAMPERED', 'critical'),
  ('ADMIN_OFF_HOURS', 'Privileged administrative diagnostic or configuration action between 00:00 and 06:00', 1, 1, 60, 'OFF_HOURS_ADMIN_ACTION', 'medium')
ON DUPLICATE KEY UPDATE
  `threshold` = VALUES(`threshold`),
  `window_seconds` = VALUES(`window_seconds`),
  `severity` = VALUES(`severity`);

-- 5. Add Security Posture Scoring to Users (C4: Dynamic Posture Scores)
ALTER TABLE `users`
  ADD COLUMN IF NOT EXISTS `security_score` TINYINT UNSIGNED DEFAULT 0,
  ADD COLUMN IF NOT EXISTS `security_score_updated_at` TIMESTAMP NULL;

-- ===============================================================
-- ROLLBACK SECTION (FOR ACADEMIC REVERSAL / CLEANUP)
-- ===============================================================
/*
USE `secure_banking`;
DROP TABLE IF EXISTS `alerts`;
DROP TABLE IF EXISTS `alert_rules`;
ALTER TABLE `users`
  DROP COLUMN IF EXISTS `security_score`,
  DROP COLUMN IF EXISTS `security_score_updated_at`;
ALTER TABLE `security_logs`
  DROP INDEX IF EXISTS `idx_severity`,
  DROP INDEX IF EXISTS `idx_event_timestamp`,
  DROP INDEX IF EXISTS `idx_ip_event`;
*/
