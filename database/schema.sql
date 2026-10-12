-- ==============================================================
-- Bank-to-Bank Suspicious Transaction Detection System
-- Database Schema (MySQL 8.0+)
-- ==============================================================

CREATE DATABASE IF NOT EXISTS `bank_detection_db`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE `bank_detection_db`;

-- Drop tables in reverse order of foreign key dependencies
DROP TABLE IF EXISTS `audit_logs`;
DROP TABLE IF EXISTS `suspicious_alerts`;
DROP TABLE IF EXISTS `transaction_analysis_results`;
DROP TABLE IF EXISTS `transactions`;
DROP TABLE IF EXISTS `accounts`;
DROP TABLE IF EXISTS `banks`;
DROP TABLE IF EXISTS `users`;

-- 1. Users Table (Role-based access control: admin, analyst)
CREATE TABLE `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `email` VARCHAR(100) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `full_name` VARCHAR(100) NOT NULL,
    `role` ENUM('admin', 'analyst') NOT NULL DEFAULT 'analyst',
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_users_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Banks Table (Participating financial institutions)
CREATE TABLE `banks` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `bank_name` VARCHAR(100) NOT NULL,
    `bank_code` VARCHAR(20) NOT NULL UNIQUE,
    `swift_ifsc` VARCHAR(20) NOT NULL UNIQUE,
    `headquarters` VARCHAR(100) NOT NULL DEFAULT 'India',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Accounts Table (Fictional customer bank accounts)
CREATE TABLE `accounts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `account_number` VARCHAR(30) NOT NULL UNIQUE,
    `account_holder_name` VARCHAR(100) NOT NULL,
    `bank_id` INT NOT NULL,
    `account_type` ENUM('SAVINGS', 'CURRENT', 'BUSINESS', 'ESCROW') NOT NULL DEFAULT 'SAVINGS',
    `balance` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
    `status` ENUM('ACTIVE', 'DORMANT', 'FROZEN', 'UNDER_REVIEW') NOT NULL DEFAULT 'ACTIVE',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_accounts_bank` FOREIGN KEY (`bank_id`) REFERENCES `banks` (`id`) ON DELETE RESTRICT,
    INDEX `idx_accounts_bank_id` (`bank_id`),
    INDEX `idx_accounts_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Transactions Table (Bank-to-bank transfer log)
CREATE TABLE `transactions` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `transaction_ref` VARCHAR(40) NOT NULL UNIQUE,
    `sender_account_id` INT NOT NULL,
    `receiver_account_id` INT NOT NULL,
    `amount` DECIMAL(15, 2) NOT NULL,
    `transaction_time` DATETIME NOT NULL,
    `status` ENUM('COMPLETED', 'FLAGGED', 'UNDER_REVIEW', 'BLOCKED') NOT NULL DEFAULT 'COMPLETED',
    `description` VARCHAR(255) NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_tx_sender` FOREIGN KEY (`sender_account_id`) REFERENCES `accounts` (`id`) ON DELETE RESTRICT,
    CONSTRAINT `fk_tx_receiver` FOREIGN KEY (`receiver_account_id`) REFERENCES `accounts` (`id`) ON DELETE RESTRICT,
    INDEX `idx_tx_time` (`transaction_time`),
    INDEX `idx_tx_sender` (`sender_account_id`),
    INDEX `idx_tx_receiver` (`receiver_account_id`),
    INDEX `idx_tx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Transaction Analysis Results Table (Risk score & explainability breakdown)
CREATE TABLE `transaction_analysis_results` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `transaction_id` INT NOT NULL UNIQUE,
    `risk_score` INT NOT NULL,
    `risk_category` ENUM('LOW', 'MEDIUM', 'HIGH') NOT NULL,
    `rule_flags` TEXT NOT NULL,
    `ml_probability` DECIMAL(5, 4) NOT NULL DEFAULT 0.0000,
    `explanation` TEXT NOT NULL,
    `recommendation` TEXT NOT NULL,
    `analyzed_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_analysis_tx` FOREIGN KEY (`transaction_id`) REFERENCES `transactions` (`id`) ON DELETE CASCADE,
    INDEX `idx_analysis_risk_category` (`risk_category`),
    INDEX `idx_analysis_risk_score` (`risk_score`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Suspicious Alerts Table (Operational queue for analysts and compliance admins)
CREATE TABLE `suspicious_alerts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `alert_ref` VARCHAR(40) NOT NULL UNIQUE,
    `transaction_id` INT NOT NULL,
    `risk_level` ENUM('LOW', 'MEDIUM', 'HIGH') NOT NULL,
    `detection_reason` TEXT NOT NULL,
    `status` ENUM('PENDING_REVIEW', 'UNDER_INVESTIGATION', 'RESOLVED', 'FALSE_POSITIVE') NOT NULL DEFAULT 'PENDING_REVIEW',
    `admin_remarks` TEXT NULL,
    `reviewed_by` INT NULL,
    `reviewed_at` DATETIME NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_alerts_tx` FOREIGN KEY (`transaction_id`) REFERENCES `transactions` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_alerts_reviewer` FOREIGN KEY (`reviewed_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
    INDEX `idx_alerts_status` (`status`),
    INDEX `idx_alerts_risk_level` (`risk_level`),
    INDEX `idx_alerts_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Audit Logs Table (Accountability & action tracking)
CREATE TABLE `audit_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NULL,
    `action` VARCHAR(100) NOT NULL,
    `details` TEXT NULL,
    `ip_address` VARCHAR(45) NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
    INDEX `idx_audit_user` (`user_id`),
    INDEX `idx_audit_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
