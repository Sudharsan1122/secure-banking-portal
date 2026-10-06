-- ===============================================================
-- Database Upgrade Script: Pillar A & Distinction-Grade Extensions
-- ===============================================================
USE `secure_banking`;

-- 1. Rate limits table for sliding-window multi-endpoint throttling
CREATE TABLE IF NOT EXISTS `rate_limits` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `ip_address` VARCHAR(45) NOT NULL,
    `endpoint` VARCHAR(100) NOT NULL,
    `window_start` INT NOT NULL,
    `attempts` INT NOT NULL DEFAULT 1,
    UNIQUE KEY `uniq_rate_limits` (`ip_address`, `endpoint`, `window_start`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Enhance users table with lockout tracking, avatar, and password age
ALTER TABLE `users`
    ADD COLUMN IF NOT EXISTS `failed_login_count` INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS `locked_until` DATETIME DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS `lock_reason` VARCHAR(255) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS `avatar_path` VARCHAR(255) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS `password_changed_at` DATETIME DEFAULT CURRENT_TIMESTAMP;

-- 3. Password reset tokens table (SHA-256 hashed, single use, 15 min expiry)
CREATE TABLE IF NOT EXISTS `password_resets` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `token_hash` VARCHAR(64) NOT NULL,
    `expires_at` DATETIME NOT NULL,
    `used` BOOLEAN NOT NULL DEFAULT 0,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_pwd_reset_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    INDEX `idx_token_hash` (`token_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Two-factor recovery codes table (hashed with BCRYPT)
CREATE TABLE IF NOT EXISTS `recovery_codes` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `code_hash` VARCHAR(255) NOT NULL,
    `used` BOOLEAN NOT NULL DEFAULT 0,
    `used_at` DATETIME DEFAULT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_recovery_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    INDEX `idx_recovery_user` (`user_id`, `used`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Audit log hash-chaining and severity classification
ALTER TABLE `security_logs`
    ADD COLUMN IF NOT EXISTS `prev_hash` VARCHAR(64) NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    ADD COLUMN IF NOT EXISTS `curr_hash` VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low';
