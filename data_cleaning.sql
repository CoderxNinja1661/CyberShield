-- ============================================================================
-- PROJECT: CYBERSHIELD – CYBERSECURITY THREAT & RISK INTELLIGENCE
-- FILE: data_cleaning.sql
-- TARGET DBMS: MySQL 8.0+
-- DESCRIPTION: Comprehensive data validation, quality auditing, and
--              non-destructive cleaning covering:
--                1. Missing value identification
--                2. Duplicate incident & primary key identification
--                3. Data type & string standardization
--                4. Date and time standardization (Jan 1 - Jun 30, 2026)
--                5. Invalid record detection
--                6. Referential integrity validation (Foreign Keys)
--                7. Threat & alert category validation
--                8. Severity classification validation
--                9. Risk score validation (0-100 scale)
-- EXECUTION ORDER: Run after data_import.sql
-- ============================================================================

USE CyberShield_DB;

-- ============================================================================
-- PART 1: DATA VALIDATION & QUALITY AUDIT CHECKS
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1.1 Duplicate Incident & Primary Key Identification
-- ----------------------------------------------------------------------------
SELECT 'users_duplicate_pk' AS validation_check, COUNT(*) AS violation_count
FROM (SELECT user_id FROM users GROUP BY user_id HAVING COUNT(*) > 1) t
UNION ALL
SELECT 'ip_addresses_duplicate_pk', COUNT(*)
FROM (SELECT ip_id FROM ip_addresses GROUP BY ip_id HAVING COUNT(*) > 1) t
UNION ALL
SELECT 'login_logs_duplicate_pk', COUNT(*)
FROM (SELECT login_id FROM login_logs GROUP BY login_id HAVING COUNT(*) > 1) t
UNION ALL
SELECT 'network_events_duplicate_pk', COUNT(*)
FROM (SELECT event_id FROM network_events GROUP BY event_id HAVING COUNT(*) > 1) t
UNION ALL
SELECT 'transactions_duplicate_pk', COUNT(*)
FROM (SELECT transaction_id FROM transactions GROUP BY transaction_id HAVING COUNT(*) > 1) t
UNION ALL
SELECT 'security_alerts_duplicate_pk', COUNT(*)
FROM (SELECT alert_id FROM security_alerts GROUP BY alert_id HAVING COUNT(*) > 1) t
UNION ALL
SELECT 'user_sessions_duplicate_pk', COUNT(*)
FROM (SELECT session_id FROM user_sessions GROUP BY session_id HAVING COUNT(*) > 1) t
UNION ALL
SELECT 'duplicate_alert_events_same_user_ip_ts_type', COUNT(*)
FROM (
    SELECT user_id, ip_id, event_time, alert_type
    FROM security_alerts
    GROUP BY user_id, ip_id, event_time, alert_type
    HAVING COUNT(*) > 1
) dup_alerts;

-- ----------------------------------------------------------------------------
-- 1.2 Missing Value Identification Across All 7 Tables
--     Note: resolution_time is legitimately NULL for Unresolved/Investigating
--     alerts (Rule 6 & Rule 10).
-- ----------------------------------------------------------------------------
SELECT 'users_missing_required' AS validation_check, COUNT(*) AS violation_count
FROM users
WHERE user_id IS NULL OR TRIM(username) = '' OR TRIM(department) = ''
   OR TRIM(account_type) = '' OR TRIM(account_status) = '' OR created_date IS NULL
UNION ALL
SELECT 'ip_addresses_missing_required', COUNT(*)
FROM ip_addresses
WHERE ip_id IS NULL OR TRIM(ip_address) = '' OR TRIM(country) = ''
   OR reputation_score IS NULL OR TRIM(risk_category) = ''
UNION ALL
SELECT 'login_logs_missing_required', COUNT(*)
FROM login_logs
WHERE login_id IS NULL OR user_id IS NULL OR ip_id IS NULL
   OR login_time IS NULL OR TRIM(status) = '' OR TRIM(device_type) = ''
UNION ALL
SELECT 'network_events_missing_required', COUNT(*)
FROM network_events
WHERE event_id IS NULL OR ip_id IS NULL OR event_time IS NULL
   OR TRIM(event_type) = '' OR TRIM(severity) = '' OR TRIM(protocol) = ''
UNION ALL
SELECT 'transactions_missing_required', COUNT(*)
FROM transactions
WHERE transaction_id IS NULL OR user_id IS NULL OR ip_id IS NULL
   OR transaction_time IS NULL OR amount IS NULL OR TRIM(risk_indicator) = ''
UNION ALL
SELECT 'security_alerts_missing_required', COUNT(*)
FROM security_alerts
WHERE alert_id IS NULL OR user_id IS NULL OR ip_id IS NULL
   OR event_time IS NULL OR TRIM(alert_type) = '' OR TRIM(severity) = ''
   OR (resolution_status = 'Resolved' AND resolution_time IS NULL)
UNION ALL
SELECT 'user_sessions_missing_required', COUNT(*)
FROM user_sessions
WHERE session_id IS NULL OR user_id IS NULL OR login_id IS NULL
   OR start_time IS NULL OR end_time IS NULL OR duration_minutes IS NULL;

-- ----------------------------------------------------------------------------
-- 1.3 Referential Integrity Validation (Orphan Foreign Key Check)
-- ----------------------------------------------------------------------------
SELECT 'login_logs_orphan_user_fk' AS validation_check, COUNT(*) AS violation_count
FROM login_logs l LEFT JOIN users u ON l.user_id = u.user_id WHERE u.user_id IS NULL
UNION ALL
SELECT 'login_logs_orphan_ip_fk', COUNT(*)
FROM login_logs l LEFT JOIN ip_addresses ip ON l.ip_id = ip.ip_id WHERE ip.ip_id IS NULL
UNION ALL
SELECT 'network_events_orphan_ip_fk', COUNT(*)
FROM network_events n LEFT JOIN ip_addresses ip ON n.ip_id = ip.ip_id WHERE ip.ip_id IS NULL
UNION ALL
SELECT 'transactions_orphan_user_fk', COUNT(*)
FROM transactions t LEFT JOIN users u ON t.user_id = u.user_id WHERE u.user_id IS NULL
UNION ALL
SELECT 'transactions_orphan_ip_fk', COUNT(*)
FROM transactions t LEFT JOIN ip_addresses ip ON t.ip_id = ip.ip_id WHERE ip.ip_id IS NULL
UNION ALL
SELECT 'security_alerts_orphan_user_fk', COUNT(*)
FROM security_alerts a LEFT JOIN users u ON a.user_id = u.user_id WHERE u.user_id IS NULL
UNION ALL
SELECT 'security_alerts_orphan_ip_fk', COUNT(*)
FROM security_alerts a LEFT JOIN ip_addresses ip ON a.ip_id = ip.ip_id WHERE ip.ip_id IS NULL
UNION ALL
SELECT 'user_sessions_orphan_user_fk', COUNT(*)
FROM user_sessions s LEFT JOIN users u ON s.user_id = u.user_id WHERE u.user_id IS NULL
UNION ALL
SELECT 'user_sessions_orphan_login_fk', COUNT(*)
FROM user_sessions s LEFT JOIN login_logs l ON s.login_id = l.login_id WHERE l.login_id IS NULL;

-- ----------------------------------------------------------------------------
-- 1.4 Date & Time Standardization & Chronological Integrity Validation
-- ----------------------------------------------------------------------------
SELECT 'logins_outside_observation_window' AS validation_check, COUNT(*) AS violation_count
FROM login_logs WHERE login_time < '2026-01-01 00:00:00' OR login_time > '2026-06-30 23:59:59'
UNION ALL
SELECT 'network_events_outside_window', COUNT(*)
FROM network_events WHERE event_time < '2026-01-01 00:00:00' OR event_time > '2026-06-30 23:59:59'
UNION ALL
SELECT 'transactions_outside_window', COUNT(*)
FROM transactions WHERE transaction_time < '2026-01-01 00:00:00' OR transaction_time > '2026-06-30 23:59:59'
UNION ALL
SELECT 'security_alerts_outside_window', COUNT(*)
FROM security_alerts WHERE event_time < '2026-01-01 00:00:00' OR event_time > '2026-06-30 23:59:59'
UNION ALL
SELECT 'alerts_negative_resolution_time', COUNT(*)
FROM security_alerts WHERE resolution_time IS NOT NULL AND resolution_time < event_time
UNION ALL
SELECT 'sessions_negative_duration', COUNT(*)
FROM user_sessions WHERE end_time < start_time OR duration_minutes <= 0;

-- ----------------------------------------------------------------------------
-- 1.5 Threat Category, Severity Classification & Risk Score Validation
-- ----------------------------------------------------------------------------
SELECT 'invalid_network_threat_category' AS validation_check, COUNT(*) AS violation_count
FROM network_events
WHERE event_type NOT IN ('Normal Traffic', 'Repeated Connection Attempt', 'Port Scan', 'Suspicious Outbound Connection', 'High Volume Data Transfer')
UNION ALL
SELECT 'invalid_alert_threat_category', COUNT(*)
FROM security_alerts
WHERE alert_type NOT IN ('Suspicious IP Activity', 'Unusual Login Time', 'High-Volume Network Activity', 'Unusual Transaction Behavior', 'Repeated Login Failures')
UNION ALL
SELECT 'invalid_network_severity_class', COUNT(*)
FROM network_events
WHERE severity NOT IN ('Low', 'Medium', 'High', 'Critical')
UNION ALL
SELECT 'invalid_alert_severity_class', COUNT(*)
FROM security_alerts
WHERE severity NOT IN ('Low', 'Medium', 'High', 'Critical')
UNION ALL
SELECT 'invalid_ip_reputation_score_range', COUNT(*)
FROM ip_addresses
WHERE reputation_score < 0 OR reputation_score > 100
UNION ALL
SELECT 'ip_risk_tier_score_mismatch', COUNT(*)
FROM ip_addresses
WHERE (risk_category = 'Normal' AND reputation_score >= 30)
   OR (risk_category = 'Suspicious' AND (reputation_score < 30 OR reputation_score >= 70))
   OR (risk_category = 'High-Risk' AND reputation_score < 70);

-- ============================================================================
-- PART 2: NON-DESTRUCTIVE DATA CLEANING & STANDARDIZATION
-- ============================================================================

DROP TEMPORARY TABLE IF EXISTS tmp_cleaning_reconciliation;
CREATE TEMPORARY TABLE tmp_cleaning_reconciliation (
    table_name       VARCHAR(30),
    stage            VARCHAR(10),
    record_count     INT,
    formatting_flags INT
);

INSERT INTO tmp_cleaning_reconciliation
SELECT 'users', 'BEFORE', COUNT(*),
       SUM(CASE WHEN username <> LOWER(TRIM(username)) OR department <> TRIM(department) THEN 1 ELSE 0 END)
FROM users
UNION ALL
SELECT 'ip_addresses', 'BEFORE', COUNT(*),
       SUM(CASE WHEN ip_address <> TRIM(ip_address) OR risk_category <> TRIM(risk_category) THEN 1 ELSE 0 END)
FROM ip_addresses
UNION ALL
SELECT 'login_logs', 'BEFORE', COUNT(*),
       SUM(CASE WHEN status <> TRIM(status) OR (status = 'Success' AND failure_reason <> 'None') THEN 1 ELSE 0 END)
FROM login_logs
UNION ALL
SELECT 'network_events', 'BEFORE', COUNT(*),
       SUM(CASE WHEN protocol <> UPPER(TRIM(protocol)) OR severity <> TRIM(severity) THEN 1 ELSE 0 END)
FROM network_events
UNION ALL
SELECT 'transactions', 'BEFORE', COUNT(*),
       SUM(CASE WHEN amount <= 0 OR risk_indicator <> TRIM(risk_indicator) THEN 1 ELSE 0 END)
FROM transactions
UNION ALL
SELECT 'security_alerts', 'BEFORE', COUNT(*),
       SUM(CASE WHEN resolution_status <> 'Resolved' AND resolution_time IS NOT NULL THEN 1 ELSE 0 END)
FROM security_alerts
UNION ALL
SELECT 'user_sessions', 'BEFORE', COUNT(*),
       SUM(CASE WHEN duration_minutes <= 0 OR end_time < start_time THEN 1 ELSE 0 END)
FROM user_sessions;

SET SQL_SAFE_UPDATES = 0;

-- Standardize strings and casing in users
UPDATE users
SET username       = LOWER(TRIM(username)),
    department     = TRIM(department),
    account_type   = TRIM(account_type),
    account_status = TRIM(account_status),
    country        = TRIM(country);

-- Standardize strings in ip_addresses
UPDATE ip_addresses
SET ip_address    = TRIM(ip_address),
    country       = TRIM(country),
    city          = TRIM(city),
    ip_type       = TRIM(ip_type),
    risk_category = TRIM(risk_category);

-- Standardize status and failure_reason in login_logs
UPDATE login_logs
SET status         = TRIM(status),
    device_type    = TRIM(device_type),
    browser        = TRIM(browser),
    operating_system = TRIM(operating_system),
    failure_reason = CASE
        WHEN TRIM(status) = 'Success' THEN 'None'
        WHEN TRIM(failure_reason) = '' OR failure_reason IS NULL THEN 'Unspecified Failure'
        ELSE TRIM(failure_reason)
    END;

-- Standardize protocol uppercase and event fields in network_events
UPDATE network_events
SET protocol     = UPPER(TRIM(protocol)),
    event_type   = TRIM(event_type),
    severity     = TRIM(severity),
    event_status = TRIM(event_status);

-- Enforce NULL resolution_time when alert is not Resolved (Rule 10)
UPDATE security_alerts
SET alert_type        = TRIM(alert_type),
    severity          = TRIM(severity),
    resolution_status = TRIM(resolution_status),
    resolution_time   = CASE
        WHEN TRIM(resolution_status) IN ('Unresolved', 'Investigating') THEN NULL
        ELSE resolution_time
    END;

-- Reconcile session duration_minutes with timestamp difference
UPDATE user_sessions
SET session_status   = TRIM(session_status),
    duration_minutes = GREATEST(1, TIMESTAMPDIFF(MINUTE, start_time, end_time))
WHERE duration_minutes <> GREATEST(1, TIMESTAMPDIFF(MINUTE, start_time, end_time));

SET SQL_SAFE_UPDATES = 1;

INSERT INTO tmp_cleaning_reconciliation
SELECT 'users', 'AFTER', COUNT(*),
       SUM(CASE WHEN username <> LOWER(TRIM(username)) OR department <> TRIM(department) THEN 1 ELSE 0 END)
FROM users
UNION ALL
SELECT 'ip_addresses', 'AFTER', COUNT(*),
       SUM(CASE WHEN ip_address <> TRIM(ip_address) OR risk_category <> TRIM(risk_category) THEN 1 ELSE 0 END)
FROM ip_addresses
UNION ALL
SELECT 'login_logs', 'AFTER', COUNT(*),
       SUM(CASE WHEN status <> TRIM(status) OR (status = 'Success' AND failure_reason <> 'None') THEN 1 ELSE 0 END)
FROM login_logs
UNION ALL
SELECT 'network_events', 'AFTER', COUNT(*),
       SUM(CASE WHEN protocol <> UPPER(TRIM(protocol)) OR severity <> TRIM(severity) THEN 1 ELSE 0 END)
FROM network_events
UNION ALL
SELECT 'transactions', 'AFTER', COUNT(*),
       SUM(CASE WHEN amount <= 0 OR risk_indicator <> TRIM(risk_indicator) THEN 1 ELSE 0 END)
FROM transactions
UNION ALL
SELECT 'security_alerts', 'AFTER', COUNT(*),
       SUM(CASE WHEN resolution_status <> 'Resolved' AND resolution_time IS NOT NULL THEN 1 ELSE 0 END)
FROM security_alerts
UNION ALL
SELECT 'user_sessions', 'AFTER', COUNT(*),
       SUM(CASE WHEN duration_minutes <= 0 OR end_time < start_time THEN 1 ELSE 0 END)
FROM user_sessions;

-- Output Before vs After Cleaning Reconciliation
SELECT 
    b.table_name,
    b.record_count AS rows_before_cleaning,
    a.record_count AS rows_after_cleaning,
    (a.record_count - b.record_count) AS rows_removed,
    b.formatting_flags AS issues_before,
    a.formatting_flags AS issues_after
FROM tmp_cleaning_reconciliation b
JOIN tmp_cleaning_reconciliation a
  ON b.table_name = a.table_name
 AND b.stage = 'BEFORE'
 AND a.stage = 'AFTER'
ORDER BY b.table_name;
