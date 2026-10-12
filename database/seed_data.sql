-- ==============================================================
-- Bank-to-Bank Suspicious Transaction Detection System
-- Initial Seed Data (Fictional Demo Environment)
-- ==============================================================

USE `bank_detection_db`;

-- 1. Insert Default Users (Admin: Admin@123, Analyst: Analyst@123)
INSERT INTO `users` (`username`, `email`, `password_hash`, `full_name`, `role`, `is_active`) VALUES
('admin', 'admin@bankguard.local', 'scrypt:32768:8:1$3dsNizNPYCyN5bB7$726235681cc777f4f8db77c18cff466721aeecf20100d59d37c2494669442e8e188a7d92fa9d7690bcd1b4eb000f710fff0a7180da42875e18ef18a25befe0dc', 'Chief Compliance Officer', 'admin', 1),
('analyst', 'analyst@bankguard.local', 'scrypt:32768:8:1$tDWMVadZV0IKVIyE$67c1f90b2e294360d45bd2e486c526a59383f79c0135afa01c55cad1e301d131163bb88618e7c7e9b0113224d328682a7b681734c41d6279a63fd21b1b9f8516', 'Financial Crime Analyst', 'analyst', 1);

-- 2. Insert Fictional Banks
INSERT INTO `banks` (`bank_name`, `bank_code`, `swift_ifsc`, `headquarters`) VALUES
('State Bank of India (Demo)', 'SBI', 'SBIN0001001', 'Mumbai, India'),
('HDFC Bank (Demo)', 'HDFC', 'HDFC0002002', 'Mumbai, India'),
('ICICI Bank (Demo)', 'ICICI', 'ICIC0003003', 'Mumbai, India'),
('Axis Bank (Demo)', 'AXIS', 'UTIB0004004', 'Mumbai, India'),
('Punjab National Bank (Demo)', 'PNB', 'PUNB0005005', 'New Delhi, India');

-- 3. Insert Fictional Bank Accounts
INSERT INTO `accounts` (`account_number`, `account_holder_name`, `bank_id`, `account_type`, `balance`, `status`) VALUES
('ACC-1001', 'Aarav Sharma', 1, 'SAVINGS', 550000.00, 'ACTIVE'),
('ACC-1002', 'Bhavna Patel', 2, 'CURRENT', 1250000.00, 'ACTIVE'),
('ACC-1003', 'Chetan Verma', 3, 'BUSINESS', 880000.00, 'ACTIVE'),
('ACC-1004', 'Divya Nair', 4, 'SAVINGS', 420000.00, 'ACTIVE'),
('ACC-1005', 'Eshan Gupta', 5, 'CURRENT', 960000.00, 'ACTIVE'),
('ACC-1006', 'Farhan Ali', 1, 'BUSINESS', 2450000.00, 'ACTIVE'),
('ACC-1007', 'Geeta Rao', 2, 'SAVINGS', 310000.00, 'ACTIVE'),
('ACC-1008', 'Harish Mehra', 3, 'CURRENT', 620000.00, 'ACTIVE'),
('ACC-1009', 'Isha Reddy', 4, 'SAVINGS', 1950000.00, 'ACTIVE'),
('ACC-1010', 'Jatin Kapoor', 5, 'BUSINESS', 3500000.00, 'ACTIVE');

-- 4. Insert Baseline Historical Transactions (Normal activities for baseline statistics)
INSERT INTO `transactions` (`transaction_ref`, `sender_account_id`, `receiver_account_id`, `amount`, `transaction_time`, `status`, `description`) VALUES
('TXN-SEED-001', 1, 2, 12500.00, DATE_SUB(NOW(), INTERVAL 5 DAY), 'COMPLETED', 'Consulting fees invoice #401'),
('TXN-SEED-002', 2, 3, 25000.00, DATE_SUB(NOW(), INTERVAL 4 DAY), 'COMPLETED', 'Hardware procurement'),
('TXN-SEED-003', 3, 4, 8500.00, DATE_SUB(NOW(), INTERVAL 3 DAY), 'COMPLETED', 'Monthly office supplies'),
('TXN-SEED-004', 5, 1, 15000.00, DATE_SUB(NOW(), INTERVAL 3 DAY), 'COMPLETED', 'Vendor settlement payment'),
('TXN-SEED-005', 6, 7, 30000.00, DATE_SUB(NOW(), INTERVAL 2 DAY), 'COMPLETED', 'Logistics invoice settlement'),
('TXN-SEED-006', 7, 8, 5500.00, DATE_SUB(NOW(), INTERVAL 2 DAY), 'COMPLETED', 'Retail purchase payment'),
('TXN-SEED-007', 9, 10, 42000.00, DATE_SUB(NOW(), INTERVAL 1 DAY), 'COMPLETED', 'Quarterly subscription charges'),
('TXN-SEED-008', 4, 5, 18000.00, DATE_SUB(NOW(), INTERVAL 1 DAY), 'COMPLETED', 'Freelance contract fee');

-- 5. Insert Analysis Results for Historical Baseline
INSERT INTO `transaction_analysis_results` (`transaction_id`, `risk_score`, `risk_category`, `rule_flags`, `ml_probability`, `explanation`, `recommendation`) VALUES
(1, 10, 'LOW', '[]', 0.0450, 'Transaction amount and frequency are within regular historical limits.', 'No action required.'),
(2, 15, 'LOW', '[]', 0.0720, 'Normal business B2B vendor payment.', 'No action required.'),
(3, 8, 'LOW', '[]', 0.0310, 'Standard utility transaction.', 'No action required.'),
(4, 12, 'LOW', '[]', 0.0510, 'Routine inter-bank transfer.', 'No action required.'),
(5, 18, 'LOW', '[]', 0.0890, 'Normal commercial disbursement.', 'No action required.'),
(6, 6, 'LOW', '[]', 0.0210, 'Low-value retail settlement.', 'No action required.'),
(7, 22, 'LOW', '[]', 0.1150, 'Standard contract renewal.', 'No action required.'),
(8, 14, 'LOW', '[]', 0.0630, 'Regular professional fee payment.', 'No action required.');
