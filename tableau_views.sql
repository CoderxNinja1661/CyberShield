-- ============================================================================
-- PROJECT: CYBERSHIELD – CYBERSECURITY THREAT & RISK INTELLIGENCE
-- FILE: tableau_views.sql
-- TARGET DBMS: MySQL 8.0+
-- DESCRIPTION: Creates 9 reusable analytical SQL views for Tableau Desktop
--              and Microsoft Excel BI reporting:
--                1. vw_daily_security_kpis
--                2. vw_login_analysis
--                3. vw_ip_threat_summary
--                4. vw_user_risk_scores
--                5. vw_transaction_fraud_analysis
--                6. vw_network_threat_analysis
--                7. vw_security_alert_summary
--                8. vw_hourly_attack_trends
--                9. vw_executive_security_overview
--              Note: Exposes anonymized user_id alongside department and
--              privilege attributes so dashboards protect personal identity.
-- EXECUTION ORDER: Run after data_cleaning.sql
-- ============================================================================

USE CyberShield_DB;

-- ----------------------------------------------------------------------------
-- View 1: vw_ip_threat_summary (500 rows - 1 per IP address)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_ip_threat_summary AS
WITH ip_logins AS (
    SELECT ip_id,
           COUNT(*) AS total_logins,
           SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed_logins,
           COUNT(DISTINCT user_id) AS distinct_users_targeted
    FROM login_logs
    GROUP BY ip_id
),
ip_net AS (
    SELECT ip_id,
           COUNT(*) AS total_network_events,
           SUM(CASE WHEN severity IN ('High', 'Critical') THEN 1 ELSE 0 END) AS critical_high_net_events,
           SUM(CASE WHEN event_type = 'Port Scan' THEN 1 ELSE 0 END) AS port_scan_events,
           SUM(bytes_transferred) AS total_bytes_transferred
    FROM network_events
    GROUP BY ip_id
),
ip_txns AS (
    SELECT ip_id,
           COUNT(*) AS total_transactions,
           SUM(CASE WHEN risk_indicator = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious_transactions,
           SUM(CASE WHEN risk_indicator = 'Suspicious' THEN amount ELSE 0.00 END) AS suspicious_txn_value_inr
    FROM transactions
    GROUP BY ip_id
),
ip_alerts AS (
    SELECT ip_id,
           COUNT(*) AS total_alerts,
           SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_alerts,
           SUM(CASE WHEN resolution_status <> 'Resolved' THEN 1 ELSE 0 END) AS unresolved_alerts
    FROM security_alerts
    GROUP BY ip_id
)
SELECT 
    ip.ip_id,
    ip.ip_address,
    ip.country,
    ip.city,
    ip.ip_type,
    ip.reputation_score,
    ip.risk_category,
    COALESCE(l.total_logins, 0) AS total_logins,
    COALESCE(l.failed_logins, 0) AS failed_logins,
    ROUND(COALESCE(l.failed_logins, 0) * 100.0 / NULLIF(COALESCE(l.total_logins, 0), 0), 2) AS failed_login_rate_pct,
    COALESCE(l.distinct_users_targeted, 0) AS distinct_users_targeted,
    COALESCE(n.total_network_events, 0) AS total_network_events,
    COALESCE(n.critical_high_net_events, 0) AS critical_high_net_events,
    COALESCE(n.port_scan_events, 0) AS port_scan_events,
    COALESCE(n.total_bytes_transferred, 0) AS total_bytes_transferred,
    COALESCE(t.total_transactions, 0) AS total_transactions,
    COALESCE(t.suspicious_transactions, 0) AS suspicious_transactions,
    COALESCE(t.suspicious_txn_value_inr, 0.00) AS suspicious_txn_value_inr,
    COALESCE(a.total_alerts, 0) AS total_alerts,
    COALESCE(a.critical_alerts, 0) AS critical_alerts,
    COALESCE(a.unresolved_alerts, 0) AS unresolved_alerts,
    (COALESCE(l.total_logins, 0) + COALESCE(n.total_network_events, 0) + COALESCE(t.total_transactions, 0) + COALESCE(a.total_alerts, 0)) AS total_events_per_ip
FROM ip_addresses ip
LEFT JOIN ip_logins l ON ip.ip_id = l.ip_id
LEFT JOIN ip_net n    ON ip.ip_id = n.ip_id
LEFT JOIN ip_txns t   ON ip.ip_id = t.ip_id
LEFT JOIN ip_alerts a ON ip.ip_id = a.ip_id;

-- ----------------------------------------------------------------------------
-- View 2: vw_user_risk_scores (5,000 rows - 5-Factor Composite Risk Model)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_user_risk_scores AS
WITH u_logins AS (
    SELECT l.user_id,
           COUNT(*) AS total_logins,
           SUM(CASE WHEN l.status = 'Failed' THEN 1 ELSE 0 END) AS failed_logins,
           SUM(CASE WHEN HOUR(l.login_time) BETWEEN 0 AND 4 THEN 1 ELSE 0 END) AS off_hour_logins,
           COUNT(DISTINCT l.ip_id) AS distinct_ips_used,
           MAX(ip.reputation_score) AS max_login_ip_rep
    FROM login_logs l
    JOIN ip_addresses ip ON l.ip_id = ip.ip_id
    GROUP BY l.user_id
),
u_txns AS (
    SELECT t.user_id,
           COUNT(*) AS total_transactions,
           SUM(CASE WHEN t.risk_indicator = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious_txn_count,
           SUM(CASE WHEN t.risk_indicator = 'Suspicious' THEN t.amount ELSE 0.00 END) AS suspicious_txn_amount_inr,
           MAX(ip.reputation_score) AS max_txn_ip_rep
    FROM transactions t
    JOIN ip_addresses ip ON t.ip_id = ip.ip_id
    GROUP BY t.user_id
),
u_alerts AS (
    SELECT a.user_id,
           COUNT(*) AS total_alerts,
           SUM(CASE WHEN a.resolution_status <> 'Resolved' THEN 1 ELSE 0 END) AS unresolved_alerts,
           SUM(CASE WHEN a.alert_type IN ('High-Volume Network Activity', 'Suspicious IP Activity') THEN 1 ELSE 0 END) AS net_alert_events,
           MAX(ip.reputation_score) AS max_alert_ip_rep
    FROM security_alerts a
    JOIN ip_addresses ip ON a.ip_id = ip.ip_id
    GROUP BY a.user_id
),
u_components AS (
    SELECT 
        u.user_id,
        u.username,
        u.department,
        u.account_type,
        u.account_status,
        u.country,
        COALESCE(l.total_logins, 0) AS total_logins,
        COALESCE(l.failed_logins, 0) AS failed_logins,
        COALESCE(l.off_hour_logins, 0) AS off_hour_logins,
        COALESCE(l.distinct_ips_used, 0) AS distinct_ips_used,
        GREATEST(COALESCE(l.max_login_ip_rep, 0), COALESCE(t.max_txn_ip_rep, 0), COALESCE(a.max_alert_ip_rep, 0)) AS max_ip_reputation,
        COALESCE(t.total_transactions, 0) AS total_transactions,
        COALESCE(t.suspicious_txn_count, 0) AS suspicious_txn_count,
        COALESCE(t.suspicious_txn_amount_inr, 0.00) AS suspicious_txn_amount_inr,
        COALESCE(a.total_alerts, 0) AS total_alerts,
        COALESCE(a.unresolved_alerts, 0) AS unresolved_alerts,
        LEAST(25.0, ROUND((COALESCE(l.failed_logins, 0) / 25.0) * 25.0, 1)) AS failed_login_score,
        LEAST(25.0, ROUND((GREATEST(COALESCE(l.max_login_ip_rep, 0), COALESCE(t.max_txn_ip_rep, 0), COALESCE(a.max_alert_ip_rep, 0)) / 100.0) * 25.0, 1)) AS ip_reputation_score_component,
        LEAST(10.0, ROUND((COALESCE(l.off_hour_logins, 0) / 15.0) * 10.0, 1)) AS unusual_hour_score,
        LEAST(20.0, ROUND(((COALESCE(a.total_alerts, 0) + COALESCE(a.net_alert_events, 0)) / 10.0) * 20.0, 1)) AS network_risk_score,
        LEAST(20.0, ROUND((COALESCE(t.suspicious_txn_count, 0) / 5.0) * 20.0, 1)) AS transaction_risk_score
    FROM users u
    LEFT JOIN u_logins l ON u.user_id = l.user_id
    LEFT JOIN u_txns t   ON u.user_id = t.user_id
    LEFT JOIN u_alerts a ON u.user_id = a.user_id
)
SELECT 
    user_id,
    username,
    department,
    account_type,
    account_status,
    country,
    total_logins,
    failed_logins,
    off_hour_logins,
    distinct_ips_used,
    max_ip_reputation,
    total_transactions,
    suspicious_txn_count,
    suspicious_txn_amount_inr,
    total_alerts,
    unresolved_alerts,
    failed_login_score,
    ip_reputation_score_component,
    unusual_hour_score,
    network_risk_score,
    transaction_risk_score,
    LEAST(100.0, ROUND(failed_login_score + ip_reputation_score_component + unusual_hour_score + network_risk_score + transaction_risk_score, 1)) AS composite_risk_score,
    CASE 
        WHEN LEAST(100.0, ROUND(failed_login_score + ip_reputation_score_component + unusual_hour_score + network_risk_score + transaction_risk_score, 1)) >= 80.0 THEN 'Critical'
        WHEN LEAST(100.0, ROUND(failed_login_score + ip_reputation_score_component + unusual_hour_score + network_risk_score + transaction_risk_score, 1)) >= 60.0 THEN 'High'
        WHEN LEAST(100.0, ROUND(failed_login_score + ip_reputation_score_component + unusual_hour_score + network_risk_score + transaction_risk_score, 1)) >= 30.0 THEN 'Medium'
        ELSE 'Low'
    END AS calculated_risk_category
FROM u_components;

-- ----------------------------------------------------------------------------
-- View 3: vw_daily_security_kpis (181 daily rows: 2026-01-01 to 2026-06-30)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_daily_security_kpis AS
WITH d_logins AS (
    SELECT DATE(login_time) AS activity_date,
           COUNT(*) AS total_logins,
           SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) AS successful_logins,
           SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed_logins
    FROM login_logs
    GROUP BY DATE(login_time)
),
d_net AS (
    SELECT DATE(event_time) AS activity_date,
           COUNT(*) AS network_event_count,
           SUM(CASE WHEN severity IN ('High', 'Critical') THEN 1 ELSE 0 END) AS high_crit_network_events
    FROM network_events
    GROUP BY DATE(event_time)
),
d_txns AS (
    SELECT DATE(transaction_time) AS activity_date,
           COUNT(*) AS transaction_count,
           SUM(CASE WHEN risk_indicator = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious_txn_count,
           SUM(amount) AS total_txn_amount_inr,
           SUM(CASE WHEN risk_indicator = 'Suspicious' THEN amount ELSE 0.00 END) AS suspicious_txn_amount_inr
    FROM transactions
    GROUP BY DATE(transaction_time)
),
d_alerts AS (
    SELECT DATE(event_time) AS activity_date,
           COUNT(*) AS alert_count,
           SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_alert_count,
           SUM(CASE WHEN resolution_status <> 'Resolved' THEN 1 ELSE 0 END) AS unresolved_alert_count
    FROM security_alerts
    GROUP BY DATE(event_time)
)
SELECT 
    dl.activity_date,
    dl.total_logins,
    dl.successful_logins,
    dl.failed_logins,
    ROUND(dl.failed_logins * 100.0 / NULLIF(dl.total_logins, 0), 2) AS failed_login_rate_pct,
    COALESCE(dn.network_event_count, 0) AS network_event_count,
    COALESCE(dn.high_crit_network_events, 0) AS high_crit_network_events,
    COALESCE(dt.transaction_count, 0) AS transaction_count,
    COALESCE(dt.suspicious_txn_count, 0) AS suspicious_txn_count,
    COALESCE(dt.total_txn_amount_inr, 0.00) AS total_txn_amount_inr,
    COALESCE(dt.suspicious_txn_amount_inr, 0.00) AS suspicious_txn_amount_inr,
    COALESCE(da.alert_count, 0) AS alert_count,
    COALESCE(da.critical_alert_count, 0) AS critical_alert_count,
    COALESCE(da.unresolved_alert_count, 0) AS unresolved_alert_count,
    (dl.total_logins + COALESCE(dn.network_event_count, 0) + COALESCE(da.alert_count, 0)) AS total_security_events
FROM d_logins dl
LEFT JOIN d_net dn    ON dl.activity_date = dn.activity_date
LEFT JOIN d_txns dt   ON dl.activity_date = dt.activity_date
LEFT JOIN d_alerts da ON dl.activity_date = da.activity_date;

-- ----------------------------------------------------------------------------
-- View 4: vw_login_analysis (50,000 rows - Enriched Authentication Logs)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_login_analysis AS
SELECT 
    l.login_id,
    l.login_time,
    DATE(l.login_time) AS login_date,
    HOUR(l.login_time) AS login_hour,
    DAYNAME(l.login_time) AS day_of_week,
    u.user_id,
    u.username,
    u.department,
    u.account_type,
    u.country AS user_country,
    ip.ip_id,
    ip.ip_address,
    ip.country AS ip_country,
    ip.ip_type,
    ip.reputation_score,
    ip.risk_category AS ip_risk_category,
    l.status,
    l.device_type,
    l.browser,
    l.operating_system,
    l.failure_reason
FROM login_logs l
JOIN users u ON l.user_id = u.user_id
JOIN ip_addresses ip ON l.ip_id = ip.ip_id;

-- ----------------------------------------------------------------------------
-- View 5: vw_transaction_fraud_analysis (10,000 rows - Enriched INR Txns)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_transaction_fraud_analysis AS
SELECT 
    t.transaction_id,
    t.transaction_time,
    DATE(t.transaction_time) AS transaction_date,
    HOUR(t.transaction_time) AS transaction_hour,
    u.user_id,
    u.username,
    u.department,
    u.account_type,
    u.country AS user_country,
    ur.composite_risk_score AS user_risk_score,
    ur.calculated_risk_category AS user_risk_category,
    ip.ip_id,
    ip.ip_address,
    ip.country AS ip_country,
    ip.ip_type,
    ip.reputation_score,
    ip.risk_category AS ip_risk_category,
    t.amount,
    t.payment_type,
    t.transaction_status,
    t.risk_indicator,
    CASE WHEN t.risk_indicator = 'Suspicious' THEN t.amount ELSE 0.00 END AS suspicious_amount_inr
FROM transactions t
JOIN users u ON t.user_id = u.user_id
JOIN ip_addresses ip ON t.ip_id = ip.ip_id
JOIN vw_user_risk_scores ur ON t.user_id = ur.user_id;

-- ----------------------------------------------------------------------------
-- View 6: vw_network_threat_analysis (20,000 rows - Enriched Network Flows)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_network_threat_analysis AS
SELECT 
    n.event_id,
    n.event_time,
    DATE(n.event_time) AS event_date,
    HOUR(n.event_time) AS event_hour,
    ip.ip_id,
    ip.ip_address,
    ip.country,
    ip.city,
    ip.ip_type,
    ip.reputation_score,
    ip.risk_category AS ip_risk_category,
    n.event_type,
    n.protocol,
    n.source_port,
    n.destination_port,
    n.bytes_transferred,
    ROUND(n.bytes_transferred / 1048576.0, 4) AS megabytes_transferred,
    n.severity,
    n.event_status
FROM network_events n
JOIN ip_addresses ip ON n.ip_id = ip.ip_id;

-- ----------------------------------------------------------------------------
-- View 7: vw_security_alert_summary (3,000 rows - Enriched SIEM Incidents)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_security_alert_summary AS
SELECT 
    a.alert_id,
    a.event_time,
    DATE(a.event_time) AS alert_date,
    HOUR(a.event_time) AS alert_hour,
    u.user_id,
    u.username,
    u.department,
    u.account_type,
    ur.composite_risk_score AS user_risk_score,
    ur.calculated_risk_category AS user_risk_category,
    ip.ip_id,
    ip.ip_address,
    ip.country AS ip_country,
    ip.ip_type,
    ip.reputation_score,
    ip.risk_category AS ip_risk_category,
    a.alert_type,
    a.severity,
    a.description,
    a.resolution_status,
    a.resolution_time,
    CASE 
        WHEN a.resolution_time IS NOT NULL THEN ROUND(TIMESTAMPDIFF(SECOND, a.event_time, a.resolution_time) / 60.0, 1)
        ELSE NULL
    END AS resolution_minutes
FROM security_alerts a
JOIN users u ON a.user_id = u.user_id
JOIN ip_addresses ip ON a.ip_id = ip.ip_id
JOIN vw_user_risk_scores ur ON a.user_id = ur.user_id;

-- ----------------------------------------------------------------------------
-- View 8: vw_hourly_attack_trends (168 rows - Day-of-Week x Hour Matrix)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_hourly_attack_trends AS
WITH login_grid AS (
    SELECT 
        WEEKDAY(login_time) + 1 AS day_of_week_num,
        DAYNAME(login_time) AS day_of_week_name,
        HOUR(login_time) AS hour_of_day,
        COUNT(*) AS total_logins,
        SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed_logins
    FROM login_logs
    GROUP BY WEEKDAY(login_time) + 1, DAYNAME(login_time), HOUR(login_time)
),
net_grid AS (
    SELECT 
        WEEKDAY(event_time) + 1 AS day_of_week_num,
        HOUR(event_time) AS hour_of_day,
        COUNT(*) AS network_events,
        SUM(CASE WHEN severity IN ('High', 'Critical') THEN 1 ELSE 0 END) AS high_crit_network_events
    FROM network_events
    GROUP BY WEEKDAY(event_time) + 1, HOUR(event_time)
),
txn_grid AS (
    SELECT 
        WEEKDAY(transaction_time) + 1 AS day_of_week_num,
        HOUR(transaction_time) AS hour_of_day,
        SUM(CASE WHEN risk_indicator = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious_transactions
    FROM transactions
    GROUP BY WEEKDAY(transaction_time) + 1, HOUR(transaction_time)
),
alert_grid AS (
    SELECT 
        WEEKDAY(event_time) + 1 AS day_of_week_num,
        HOUR(event_time) AS hour_of_day,
        COUNT(*) AS security_alerts,
        SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_alerts
    FROM security_alerts
    GROUP BY WEEKDAY(event_time) + 1, HOUR(event_time)
)
SELECT 
    lg.day_of_week_num,
    lg.day_of_week_name,
    lg.hour_of_day,
    lg.total_logins,
    lg.failed_logins,
    ROUND(lg.failed_logins * 100.0 / NULLIF(lg.total_logins, 0), 2) AS failed_login_rate_pct,
    COALESCE(ng.network_events, 0) AS network_events,
    COALESCE(ng.high_crit_network_events, 0) AS high_crit_network_events,
    COALESCE(tg.suspicious_transactions, 0) AS suspicious_transactions,
    COALESCE(ag.security_alerts, 0) AS security_alerts,
    COALESCE(ag.critical_alerts, 0) AS critical_alerts,
    (lg.failed_logins + COALESCE(ng.high_crit_network_events, 0) + COALESCE(tg.suspicious_transactions, 0) + COALESCE(ag.security_alerts, 0)) AS total_suspicious_events
FROM login_grid lg
LEFT JOIN net_grid ng   ON lg.day_of_week_num = ng.day_of_week_num AND lg.hour_of_day = ng.hour_of_day
LEFT JOIN txn_grid tg   ON lg.day_of_week_num = tg.day_of_week_num AND lg.hour_of_day = tg.hour_of_day
LEFT JOIN alert_grid ag ON lg.day_of_week_num = ag.day_of_week_num AND lg.hour_of_day = ag.hour_of_day
ORDER BY lg.day_of_week_num, lg.hour_of_day;

-- ----------------------------------------------------------------------------
-- View 9: vw_executive_security_overview (Single-Row Executive KPI View)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_executive_security_overview AS
SELECT 
    (SELECT COUNT(*) FROM security_alerts) AS total_security_incidents,
    (SELECT COUNT(*) FROM network_events WHERE event_type <> 'Normal Traffic') AS total_anomalous_network_threats,
    (SELECT COUNT(*) FROM login_logs WHERE status = 'Failed') AS total_failed_login_threats,
    (SELECT COUNT(*) FROM security_alerts WHERE severity = 'Critical') AS critical_security_alerts,
    (SELECT COUNT(*) FROM network_events WHERE severity = 'Critical') AS critical_network_threats,
    (SELECT COUNT(*) FROM vw_user_risk_scores WHERE calculated_risk_category = 'Critical') AS critical_risk_users,
    (SELECT COUNT(*) FROM vw_user_risk_scores WHERE calculated_risk_category = 'High') AS high_risk_users,
    (SELECT COUNT(*) FROM ip_addresses WHERE risk_category = 'High-Risk') AS high_risk_ips,
    (SELECT COUNT(*) FROM security_alerts WHERE resolution_status = 'Resolved') AS resolved_incidents,
    (SELECT COUNT(*) FROM security_alerts WHERE resolution_status <> 'Resolved') AS pending_incidents,
    (SELECT ROUND(AVG(TIMESTAMPDIFF(SECOND, event_time, resolution_time) / 60.0), 2) FROM security_alerts WHERE resolution_time IS NOT NULL) AS avg_resolution_time_mins,
    (SELECT ROUND(SUM(CASE WHEN resolution_status = 'Resolved' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) FROM security_alerts) AS incident_resolution_rate_pct,
    (SELECT ROUND(SUM(amount), 2) FROM transactions WHERE risk_indicator = 'Suspicious') AS suspicious_txn_exposure_inr;
