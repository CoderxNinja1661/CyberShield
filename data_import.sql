-- ============================================================================
-- PROJECT: CYBERSHIELD – CYBERSECURITY THREAT & RISK INTELLIGENCE
-- FILE: data_import.sql
-- TARGET DBMS: MySQL 8.0+
-- DESCRIPTION: Bulk-imports all 7 provided cybersecurity CSV datasets
--              (118,500 records total) from D:/BA Project/files/ (or
--              D:/BA Project/CyberShield/datasets/) in parent-to-child
--              referential order without modifying original source files.
-- EXECUTION ORDER: Run after database_creation.sql
-- ============================================================================

USE CyberShield_DB;

SET GLOBAL local_infile = 1;

-- ----------------------------------------------------------------------------
-- 1. Import users.csv (5,000 organizational user accounts)
-- ----------------------------------------------------------------------------
LOAD DATA LOCAL INFILE 'D:/BA Project/files/users.csv'
INTO TABLE users
CHARACTER SET utf8mb4
FIELDS TERMINATED BY ','
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\r\n'
IGNORE 1 LINES
(user_id, username, department, account_type, account_status, created_date, country);

-- ----------------------------------------------------------------------------
-- 2. Import ip_addresses.csv (500 IP threat intelligence records)
-- ----------------------------------------------------------------------------
LOAD DATA LOCAL INFILE 'D:/BA Project/files/ip_addresses.csv'
INTO TABLE ip_addresses
CHARACTER SET utf8mb4
FIELDS TERMINATED BY ','
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\r\n'
IGNORE 1 LINES
(ip_id, ip_address, country, city, ip_type, reputation_score, risk_category);

-- ----------------------------------------------------------------------------
-- 3. Import login_logs.csv (50,000 authentication attempt records)
-- ----------------------------------------------------------------------------
LOAD DATA LOCAL INFILE 'D:/BA Project/files/login_logs.csv'
INTO TABLE login_logs
CHARACTER SET utf8mb4
FIELDS TERMINATED BY ','
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\r\n'
IGNORE 1 LINES
(login_id, user_id, ip_id, login_time, status, device_type, browser, operating_system, failure_reason);

-- ----------------------------------------------------------------------------
-- 4. Import network_events.csv (20,000 network traffic & perimeter events)
-- ----------------------------------------------------------------------------
LOAD DATA LOCAL INFILE 'D:/BA Project/files/network_events.csv'
INTO TABLE network_events
CHARACTER SET utf8mb4
FIELDS TERMINATED BY ','
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\r\n'
IGNORE 1 LINES
(event_id, ip_id, event_time, event_type, protocol, source_port, destination_port, bytes_transferred, severity, event_status);

-- ----------------------------------------------------------------------------
-- 5. Import transactions.csv (10,000 financial transaction records in INR)
-- ----------------------------------------------------------------------------
LOAD DATA LOCAL INFILE 'D:/BA Project/files/transactions.csv'
INTO TABLE transactions
CHARACTER SET utf8mb4
FIELDS TERMINATED BY ','
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\r\n'
IGNORE 1 LINES
(transaction_id, user_id, ip_id, transaction_time, amount, payment_type, transaction_status, risk_indicator);

-- ----------------------------------------------------------------------------
-- 6. Import security_alerts.csv (3,000 SIEM security alert & incident records)
--    Maps blank resolution_time on open/investigating alerts to SQL NULL.
-- ----------------------------------------------------------------------------
LOAD DATA LOCAL INFILE 'D:/BA Project/files/security_alerts.csv'
INTO TABLE security_alerts
CHARACTER SET utf8mb4
FIELDS TERMINATED BY ','
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\r\n'
IGNORE 1 LINES
(alert_id, user_id, ip_id, event_time, alert_type, severity, description, resolution_status, @v_resolution_time)
SET resolution_time = NULLIF(TRIM(@v_resolution_time), '');

-- ----------------------------------------------------------------------------
-- 7. Import user_sessions.csv (30,000 authenticated user session records)
-- ----------------------------------------------------------------------------
LOAD DATA LOCAL INFILE 'D:/BA Project/files/user_sessions.csv'
INTO TABLE user_sessions
CHARACTER SET utf8mb4
FIELDS TERMINATED BY ','
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\r\n'
IGNORE 1 LINES
(session_id, user_id, login_id, start_time, end_time, session_status, duration_minutes);

-- ----------------------------------------------------------------------------
-- 8. Post-Import Row Count Reconciliation (Expected Total: 118,500)
-- ----------------------------------------------------------------------------
SELECT 'users' AS table_name, COUNT(*) AS imported_rows, 5000 AS expected_rows, (COUNT(*) - 5000) AS variance FROM users
UNION ALL
SELECT 'ip_addresses', COUNT(*), 500, (COUNT(*) - 500) FROM ip_addresses
UNION ALL
SELECT 'login_logs', COUNT(*), 50000, (COUNT(*) - 50000) FROM login_logs
UNION ALL
SELECT 'network_events', COUNT(*), 20000, (COUNT(*) - 20000) FROM network_events
UNION ALL
SELECT 'transactions', COUNT(*), 10000, (COUNT(*) - 10000) FROM transactions
UNION ALL
SELECT 'security_alerts', COUNT(*), 3000, (COUNT(*) - 3000) FROM security_alerts
UNION ALL
SELECT 'user_sessions', COUNT(*), 30000, (COUNT(*) - 30000) FROM user_sessions
UNION ALL
SELECT 'TOTAL_RECORDS',
    (SELECT COUNT(*) FROM users) +
    (SELECT COUNT(*) FROM ip_addresses) +
    (SELECT COUNT(*) FROM login_logs) +
    (SELECT COUNT(*) FROM network_events) +
    (SELECT COUNT(*) FROM transactions) +
    (SELECT COUNT(*) FROM security_alerts) +
    (SELECT COUNT(*) FROM user_sessions),
    118500,
    ((SELECT COUNT(*) FROM users) +
     (SELECT COUNT(*) FROM ip_addresses) +
     (SELECT COUNT(*) FROM login_logs) +
     (SELECT COUNT(*) FROM network_events) +
     (SELECT COUNT(*) FROM transactions) +
     (SELECT COUNT(*) FROM security_alerts) +
     (SELECT COUNT(*) FROM user_sessions)) - 118500;
