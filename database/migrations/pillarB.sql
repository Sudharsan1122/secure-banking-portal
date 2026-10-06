-- ===============================================================
-- PILLAR B MIGRATION: Real-World Banking Features
-- Database: secure_banking
-- Objectives: B1-B10 (Categories, Schedules, Verification, Limits, Multi-Account, Notifications, Devices, Reviews)
-- ===============================================================

USE `secure_banking`;

-- ---------------------------------------------------------------
-- 1. B1: Transaction Categories & Category Seed
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `categories` (
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
('Other', '📦', TRUE)
ON DUPLICATE KEY UPDATE `icon` = VALUES(`icon`);

-- Alter transactions table to add category and supporting indexes
-- Check if column exists first or alter safely
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.COLUMNS 
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'transactions' AND COLUMN_NAME = 'category';

SET @stmt = IF(@col_exists = 0, 
    'ALTER TABLE `transactions` ADD COLUMN `category` VARCHAR(32) DEFAULT "Uncategorized" AFTER `remark`, ADD INDEX `idx_category` (`category`), ADD INDEX `idx_user_category_date` (`sender_id`, `category`, `created_at`)', 
    'SELECT "transactions.category already exists"'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- ---------------------------------------------------------------
-- 2. B5: Velocity Limits & Account Status on users
-- ---------------------------------------------------------------
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.COLUMNS 
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'limit_single';

SET @stmt = IF(@col_exists = 0, 
    'ALTER TABLE `users` 
        ADD COLUMN `limit_single` DECIMAL(12,2) DEFAULT 100000.00 AFTER `balance`,
        ADD COLUMN `limit_daily` DECIMAL(12,2) DEFAULT 200000.00 AFTER `limit_single`,
        ADD COLUMN `limit_monthly` DECIMAL(12,2) DEFAULT 1000000.00 AFTER `limit_daily`,
        ADD COLUMN `status` ENUM("active", "frozen") DEFAULT "active" AFTER `role`',
    'SELECT "users velocity limits already exist"'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- ---------------------------------------------------------------
-- 3. B6: Multi-Account Attributes on accounts
-- ---------------------------------------------------------------
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.COLUMNS 
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'accounts' AND COLUMN_NAME = 'type';

SET @stmt = IF(@col_exists = 0, 
    'ALTER TABLE `accounts` 
        ADD COLUMN `type` ENUM("savings", "current", "fd") DEFAULT "savings" AFTER `currency`,
        ADD COLUMN `nickname` VARCHAR(64) NULL AFTER `type`,
        ADD COLUMN `interest_rate` DECIMAL(5,2) DEFAULT 0.00 AFTER `nickname`,
        ADD INDEX `idx_user_account` (`user_id`, `type`)',
    'SELECT "accounts multi-account columns already exist"'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- ---------------------------------------------------------------
-- 4. B4: Beneficiary 2-Step Verification on beneficiaries
-- ---------------------------------------------------------------
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM information_schema.COLUMNS 
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'beneficiaries' AND COLUMN_NAME = 'verified';

SET @stmt = IF(@col_exists = 0, 
    'ALTER TABLE `beneficiaries` 
        ADD COLUMN `verified` BOOLEAN DEFAULT FALSE AFTER `bank_name`,
        ADD COLUMN `verification_code_hash` VARCHAR(255) NULL AFTER `verified`,
        ADD COLUMN `verification_expires_at` TIMESTAMP NULL AFTER `verification_code_hash`,
        ADD INDEX `idx_verified` (`user_id`, `verified`)',
    'SELECT "beneficiaries verification columns already exist"'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- Mark any pre-existing seeded beneficiaries as verified
UPDATE `beneficiaries` SET `verified` = TRUE WHERE `verified` IS NULL OR `verified` = FALSE;

-- ---------------------------------------------------------------
-- 5. B2: Scheduled / Recurring Transfers
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `scheduled_transfers` (
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
-- 6. B7: Notification Center
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `notifications` (
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
-- 7. B8: Device Fingerprints & Recognition
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `user_devices` (
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
-- 8. B10: Transaction Reviews & Suspicious Activity Flags
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `transaction_reviews` (
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

-- ===============================================================
-- ROLLBACK SECTION (COMMENTED)
-- ===============================================================
/*
DROP TABLE IF EXISTS `transaction_reviews`;
DROP TABLE IF EXISTS `user_devices`;
DROP TABLE IF EXISTS `notifications`;
DROP TABLE IF EXISTS `scheduled_transfers`;
ALTER TABLE `beneficiaries` DROP COLUMN `verification_expires_at`, DROP COLUMN `verification_code_hash`, DROP COLUMN `verified`;
ALTER TABLE `accounts` DROP COLUMN `interest_rate`, DROP COLUMN `nickname`, DROP COLUMN `type`;
ALTER TABLE `users` DROP COLUMN `status`, DROP COLUMN `limit_monthly`, DROP COLUMN `limit_daily`, DROP COLUMN `limit_single`;
ALTER TABLE `transactions` DROP COLUMN `category`;
DROP TABLE IF EXISTS `categories`;
*/
