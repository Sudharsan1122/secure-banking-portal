-- ===============================================================
-- Secure Banking Portal Database Schema (Distinction-Grade Edition)
-- Project: Secure Banking Portal: A Web Application for Secure Transactions and Vulnerability Mitigation
-- Database: secure_banking
-- Engine: InnoDB (Supports ACID Transactions, Foreign Keys, and Row-Level Locking)
-- Charset: utf8mb4 / Collation: utf8mb4_unicode_ci
-- ===============================================================

CREATE DATABASE IF NOT EXISTS `secure_banking` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `secure_banking`;

DROP TABLE IF EXISTS `transaction_reviews`;
DROP TABLE IF EXISTS `user_devices`;
DROP TABLE IF EXISTS `notifications`;
DROP TABLE IF EXISTS `scheduled_transfers`;
DROP TABLE IF EXISTS `categories`;
DROP TABLE IF EXISTS `alerts`;
DROP TABLE IF EXISTS `alert_rules`;
DROP TABLE IF EXISTS `security_logs`;
DROP TABLE IF EXISTS `rate_limits`;
DROP TABLE IF EXISTS `recovery_codes`;
DROP TABLE IF EXISTS `password_resets`;
DROP TABLE IF EXISTS `login_attempts`;
DROP TABLE IF EXISTS `otp_codes`;
DROP TABLE IF EXISTS `transactions`;
DROP TABLE IF EXISTS `beneficiaries`;
DROP TABLE IF EXISTS `accounts`;
DROP TABLE IF EXISTS `users`;

-- ---------------------------------------------------------------
-- 1. Table: users
-- Core credentials, identity attributes, role, balance, lockout, avatar, and MFA
-- ---------------------------------------------------------------
CREATE TABLE `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(150) NOT NULL UNIQUE,
    `phone` VARCHAR(20) NOT NULL,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `balance` DECIMAL(12,2) NOT NULL DEFAULT 0.00,
    `limit_single` DECIMAL(12,2) NOT NULL DEFAULT 100000.00,
    `limit_daily` DECIMAL(12,2) NOT NULL DEFAULT 200000.00,
    `limit_monthly` DECIMAL(12,2) NOT NULL DEFAULT 1000000.00,
    `role` ENUM('user', 'admin') NOT NULL DEFAULT 'user',
    `status` ENUM('active', 'frozen') NOT NULL DEFAULT 'active',
    `mfa_secret` VARCHAR(64) DEFAULT NULL,
    `failed_login_count` INT NOT NULL DEFAULT 0,
    `locked_until` DATETIME DEFAULT NULL,
    `lock_reason` VARCHAR(255) DEFAULT NULL,
    `avatar_path` VARCHAR(255) DEFAULT NULL,
    `password_changed_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `security_score` TINYINT UNSIGNED DEFAULT 0,
    `security_score_updated_at` TIMESTAMP NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_username` (`username`),
    INDEX `idx_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 2. Table: accounts
-- Bank accounts linked to users with currency and individual balances
-- ---------------------------------------------------------------
CREATE TABLE `accounts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `account_number` VARCHAR(20) NOT NULL UNIQUE,
    `balance` DECIMAL(12,2) NOT NULL DEFAULT 0.00,
    `currency` VARCHAR(3) NOT NULL DEFAULT 'USD',
    `type` ENUM('savings', 'current', 'fd') NOT NULL DEFAULT 'savings',
    `nickname` VARCHAR(64) NULL,
    `interest_rate` DECIMAL(5,2) DEFAULT 0.00,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_accounts_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    INDEX `idx_acc_num` (`account_number`),
    INDEX `idx_user_account` (`user_id`, `type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 3. Table: beneficiaries
-- Registered payees for transfers with 2-step OTP verification
-- ---------------------------------------------------------------
CREATE TABLE `beneficiaries` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `account_number` VARCHAR(20) NOT NULL,
    `bank_name` VARCHAR(100) NOT NULL,
    `verified` BOOLEAN NOT NULL DEFAULT FALSE,
    `verification_code_hash` VARCHAR(255) NULL,
    `verification_expires_at` TIMESTAMP NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_beneficiaries_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    INDEX `idx_user_beneficiary` (`user_id`),
    INDEX `idx_verified` (`user_id`, `verified`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 4. Table: categories
-- System and custom transaction classification categories
-- ---------------------------------------------------------------
CREATE TABLE `categories` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(32) UNIQUE NOT NULL,
    `icon` VARCHAR(32) DEFAULT '📁',
    `is_system` BOOLEAN DEFAULT TRUE,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `categories` (`name`, `icon`, `is_system`) VALUES
('Food', '🍔', TRUE),
('Bills', '📄', TRUE),
('Salary', '💼', TRUE),
('Transfer', '💸', TRUE),
('Shopping', '🛍️', TRUE),
('Transport', '🚗', TRUE),
('Entertainment', '🎬', TRUE),
('Utilities', '💡', TRUE),
('Other', '📦', TRUE);

-- ---------------------------------------------------------------
-- 5. Table: transactions
-- Records all fund transfers with sender, receiver, amounts, and raw remarks
-- ---------------------------------------------------------------
CREATE TABLE `transactions` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `sender_id` INT NOT NULL,
    `receiver_id` INT NOT NULL,
    `amount` DECIMAL(12,2) NOT NULL,
    `remark` TEXT DEFAULT NULL,
    `category` VARCHAR(32) DEFAULT 'Uncategorized',
    `status` ENUM('completed', 'pending', 'failed') NOT NULL DEFAULT 'completed',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_txn_sender` FOREIGN KEY (`sender_id`) REFERENCES `users` (`id`),
    CONSTRAINT `fk_txn_receiver` FOREIGN KEY (`receiver_id`) REFERENCES `users` (`id`),
    INDEX `idx_sender` (`sender_id`),
    INDEX `idx_receiver` (`receiver_id`),
    INDEX `idx_category` (`category`),
    INDEX `idx_user_category_date` (`sender_id`, `category`, `created_at`),
    INDEX `idx_txn_time` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 6. Table: scheduled_transfers
-- Recurring and future scheduled transfers
-- ---------------------------------------------------------------
CREATE TABLE `scheduled_transfers` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `from_account_id` INT NOT NULL,
    `to_beneficiary_id` INT NOT NULL,
    `amount` DECIMAL(12,2) NOT NULL,
    `remark` VARCHAR(255) DEFAULT 'Scheduled Transfer',
    `category` VARCHAR(32) DEFAULT 'Transfer',
    `frequency` ENUM('daily', 'weekly', 'monthly') NOT NULL,
    `next_run_at` TIMESTAMP NOT NULL,
    `last_run_at` TIMESTAMP NULL,
    `status` ENUM('active', 'paused', 'cancelled', 'completed') DEFAULT 'active',
    `failure_count` INT DEFAULT 0,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_sched_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_sched_account` FOREIGN KEY (`from_account_id`) REFERENCES `accounts` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_sched_beneficiary` FOREIGN KEY (`to_beneficiary_id`) REFERENCES `beneficiaries` (`id`) ON DELETE CASCADE,
    INDEX `idx_next_run` (`status`, `next_run_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 7. Table: notifications
-- In-portal security alerts and operational notifications
-- ---------------------------------------------------------------
CREATE TABLE `notifications` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `type` VARCHAR(64) NOT NULL,
    `title` VARCHAR(128) NOT NULL,
    `body` TEXT,
    `link` VARCHAR(255),
    `severity` ENUM('info', 'warning', 'danger') DEFAULT 'info',
    `read_at` TIMESTAMP NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_notif_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    INDEX `idx_user_unread` (`user_id`, `read_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 8. Table: user_devices
-- Recognized client devices and browser fingerprint signatures
-- ---------------------------------------------------------------
CREATE TABLE `user_devices` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `fingerprint` CHAR(64) NOT NULL,
    `user_agent` VARCHAR(255),
    `last_ip` VARCHAR(45),
    `first_seen` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `last_seen` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `trusted` BOOLEAN DEFAULT FALSE,
    CONSTRAINT `fk_device_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    UNIQUE KEY `uk_user_fp` (`user_id`, `fingerprint`),
    INDEX `idx_user_device` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 9. Table: transaction_reviews
-- Admin review workbench for suspicious transaction triage
-- ---------------------------------------------------------------
CREATE TABLE `transaction_reviews` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `transaction_id` INT NOT NULL,
    `flagged_reason` VARCHAR(255) NOT NULL,
    `reviewed_by` INT NULL,
    `reviewed_at` TIMESTAMP NULL,
    `outcome` ENUM('pending', 'cleared', 'escalated') DEFAULT 'pending',
    `notes` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_review_txn` FOREIGN KEY (`transaction_id`) REFERENCES `transactions` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_review_admin` FOREIGN KEY (`reviewed_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
    INDEX `idx_outcome` (`outcome`),
    INDEX `idx_review_txn` (`transaction_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 5. Table: otp_codes
-- Temporary 6-digit MFA verification tokens with 5-minute validity window
-- ---------------------------------------------------------------
CREATE TABLE `otp_codes` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `code` VARCHAR(10) NOT NULL,
    `expires_at` DATETIME NOT NULL,
    `used` BOOLEAN NOT NULL DEFAULT 0,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_otp_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    INDEX `idx_otp_validation` (`user_id`, `code`, `used`, `expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 6. Table: login_attempts
-- Tracks authentication attempts for IP and username-based rate-limiting
-- ---------------------------------------------------------------
CREATE TABLE `login_attempts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `success` BOOLEAN NOT NULL DEFAULT 0,
    `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_rate_limit` (`ip_address`, `timestamp`),
    INDEX `idx_user_attempts` (`username`, `timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 7. Table: rate_limits
-- Sliding window rate limiting across endpoints
-- ---------------------------------------------------------------
CREATE TABLE `rate_limits` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `ip_address` VARCHAR(45) NOT NULL,
    `endpoint` VARCHAR(100) NOT NULL,
    `window_start` INT NOT NULL,
    `attempts` INT NOT NULL DEFAULT 1,
    UNIQUE KEY `uniq_rate_limits` (`ip_address`, `endpoint`, `window_start`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 8. Table: password_resets
-- Token-based password reset tracking (SHA-256 tokens)
-- ---------------------------------------------------------------
CREATE TABLE `password_resets` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `token_hash` VARCHAR(64) NOT NULL,
    `expires_at` DATETIME NOT NULL,
    `used` BOOLEAN NOT NULL DEFAULT 0,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_pwd_reset_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    INDEX `idx_token_hash` (`token_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 9. Table: recovery_codes
-- Emergency one-time recovery codes for 2FA
-- ---------------------------------------------------------------
CREATE TABLE `recovery_codes` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `code_hash` VARCHAR(255) NOT NULL,
    `used` BOOLEAN NOT NULL DEFAULT 0,
    `used_at` DATETIME DEFAULT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_recovery_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    INDEX `idx_recovery_user` (`user_id`, `used`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 10. Table: security_logs
-- SIEM audit trail with cryptographic hash chain (prev_hash, curr_hash)
-- and 4-tier threat severity levels (low, medium, high, critical)
-- ---------------------------------------------------------------
CREATE TABLE `security_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT DEFAULT NULL,
    `event_type` VARCHAR(50) NOT NULL,
    `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
    `ip_address` VARCHAR(45) NOT NULL,
    `request` TEXT DEFAULT NULL,
    `status` VARCHAR(20) NOT NULL,
    `prev_hash` VARCHAR(64) NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    `curr_hash` VARCHAR(64) NOT NULL DEFAULT '',
    `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_event_type` (`event_type`),
    INDEX `idx_severity` (`severity`),
    INDEX `idx_log_time` (`timestamp`),
    INDEX `idx_user_log` (`user_id`),
    INDEX `idx_event_timestamp` (`event_type`, `timestamp`),
    INDEX `idx_ip_event` (`ip_address`, `event_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------
-- 11. Table: alerts (Automated SIEM Alert Incidents)
-- ---------------------------------------------------------------
CREATE TABLE `alerts` (
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

-- ---------------------------------------------------------------
-- 12. Table: alert_rules (Configurable SIEM Threshold Rules)
-- ---------------------------------------------------------------
CREATE TABLE `alert_rules` (
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

-- ---------------------------------------------------------------
-- DROP TABLE cleanup block at top of file synchronization
-- ---------------------------------------------------------------

-- ===============================================================
-- SEED DATA
-- Default Credentials:
-- 1. Admin: admin / Admin@1234 (Role: admin, Balance: $100,000.00)
-- 2. User: john_doe / User@1234 (Role: user, Balance: $15,500.00)
-- 3. User: alice_smith / User@1234 (Role: user, Balance: $5,250.00)
-- ===============================================================

INSERT INTO `users` (`id`, `name`, `email`, `phone`, `username`, `password_hash`, `balance`, `role`, `mfa_secret`, `created_at`) VALUES
(1, 'System Administrator', 'admin@securebank.local', '+1-555-0100', 'admin', '$2y$10$pXqws7tk6NdDSEDdJu7IteEZwuJYOqe5jO08jJaHOzKkJXJAFO6RC', 100000.00, 'admin', 'JBSWY3DPEHPK3PXP', NOW()),
(2, 'John Doe', 'john.doe@example.com', '+1-555-0199', 'john_doe', '$2y$10$ES6suhD8SVv02jbVh13PZOgi4WyV9cih8mXiELDVzLDetM6bBfDvK', 15500.00, 'user', 'JBSWY3DPEHPK3PXQ', NOW()),
(3, 'Alice Smith', 'alice.smith@example.com', '+1-555-0144', 'alice_smith', '$2y$10$ES6suhD8SVv02jbVh13PZOgi4WyV9cih8mXiELDVzLDetM6bBfDvK', 5250.00, 'user', 'JBSWY3DPEHPK3PXR', NOW());

INSERT INTO `accounts` (`id`, `user_id`, `account_number`, `balance`, `currency`, `created_at`) VALUES
(1, 1, 'ACC-ADMIN-0001', 100000.00, 'USD', NOW()),
(2, 2, 'ACC-USER-1002', 15500.00, 'USD', NOW()),
(3, 3, 'ACC-USER-1003', 5250.00, 'USD', NOW());

INSERT INTO `beneficiaries` (`id`, `user_id`, `name`, `account_number`, `bank_name`, `created_at`) VALUES
(1, 2, 'Alice Smith', 'ACC-USER-1003', 'Secure National Bank', NOW()),
(2, 2, 'Electric Utility Corp', 'ACC-CORP-9901', 'First Commercial Bank', NOW()),
(3, 3, 'John Doe', 'ACC-USER-1002', 'Secure National Bank', NOW());

INSERT INTO `transactions` (`id`, `sender_id`, `receiver_id`, `amount`, `remark`, `status`, `created_at`) VALUES
(1, 1, 2, 2500.00, 'Initial Account Funding', 'completed', DATE_SUB(NOW(), INTERVAL 3 DAY)),
(2, 2, 3, 350.00, 'Project Milestone Payment #1', 'completed', DATE_SUB(NOW(), INTERVAL 2 DAY)),
(3, 2, 3, 120.50, 'Dinner reimbursement', 'completed', DATE_SUB(NOW(), INTERVAL 1 DAY)),
(4, 3, 2, 50.00, 'Shared taxi split', 'completed', DATE_SUB(NOW(), INTERVAL 5 HOUR));

-- Initial block in tamper-proof hash chain
INSERT INTO `security_logs` (`id`, `user_id`, `event_type`, `severity`, `ip_address`, `request`, `status`, `prev_hash`, `curr_hash`, `timestamp`) VALUES
(1, 1, 'SYSTEM_INITIALIZED', 'low', '127.0.0.1', 'System security audit log initialized', 'SUCCESS', '0000000000000000000000000000000000000000000000000000000000000000', SHA2('GENESIS_BLOCK_SECURE_BANKING_2026', 256), NOW());

-- Seed standard SIEM detection rules
INSERT INTO `alert_rules` (`name`, `description`, `enabled`, `threshold`, `window_seconds`, `event_type`, `severity`) VALUES
('CSRF_BURST', 'CSRF token validation failure on state-changing transaction endpoint', 1, 1, 300, 'CSRF_FAILURE', 'high'),
('BRUTE_FORCE_IP', 'Concentrated failed logins from single IP address within sliding window', 1, 5, 300, 'LOGIN_FAILED', 'high'),
('LARGE_TRANSFER', 'High-value funds transfer exceeding risk threshold (>= $10,000)', 1, 1, 60, 'TRANSFER_SUCCESS', 'high'),
('SQLI_SPIKE', 'SQL injection payload signature intercepted by security validation firewall', 1, 1, 300, 'SQLI_BLOCKED', 'critical'),
('TRAVERSAL_SPIKE', 'Directory path traversal sequence detected on download statement endpoint', 1, 1, 300, 'DIRECTORY_TRAVERSAL', 'high'),
('CHAIN_TAMPER', 'Cryptographic audit log integrity validation failure or hash chain corruption', 1, 1, 60, 'HASH_CHAIN_TAMPERED', 'critical'),
('ADMIN_OFF_HOURS', 'Privileged administrative diagnostic or configuration action during off-hours', 1, 1, 60, 'OFF_HOURS_ADMIN_ACTION', 'medium'),
('XSS_ATTACK', 'Cross-Site Scripting signature detected in user input parameters or remarks', 1, 1, 300, 'XSS_BLOCKED', 'high'),
('IDOR_VIOLATION', 'Insecure direct object reference or unauthorized resource inspection attempt', 1, 1, 300, 'ACCESS_VIOLATION', 'high'),
('BAC_VIOLATION', 'Privileged administrative endpoint accessed without required authorization', 1, 1, 300, 'UNAUTHORIZED_ACCESS', 'critical'),
('MALICIOUS_UPLOAD', 'Disguised executable or prohibited file upload intercepted by magic-byte guard', 1, 1, 300, 'MALICIOUS_UPLOAD_BLOCKED', 'high'),
('RATE_LIMIT_EXCEEDED', 'Endpoint rate limit exceeded (HTTP 429 Too Many Requests)', 1, 1, 300, 'RATE_LIMIT_EXCEEDED', 'medium');

