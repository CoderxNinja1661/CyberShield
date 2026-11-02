-- ============================================================================
-- PROJECT: CYBERSHIELD – CYBERSECURITY THREAT & RISK INTELLIGENCE
-- FILE: threat_analysis.sql
-- TARGET DBMS: MySQL 8.0+
-- DESCRIPTION: Analytical SQL queries for Module A (Cyber Threat Analysis)
--              and Module D (Network Security Analytics) using only actual
--              dataset attack/threat categories:
--                - Network Threat Categories: Repeated Connection Attempt,
--                  Port Scan, Suspicious Outbound Connection, High Volume
--                  Data Transfer (vs Normal Traffic baseline)
--                - SIEM Alert Threat Categories: Suspicious IP Activity,
--                  Unusual Login Time, High-Volume Network Activity,
--                  Unusual Transaction Behavior, Repeated Login Failures
--                - Authentication Threat Categories: Invalid Password,
--                  Account Locked, MFA Timeout, Blocked IP Reputation,
--                  Expired Credentials, Unauthorized Geo-Location
-- EXECUTION ORDER: Run after data_cleaning.sql
-- ============================================================================

USE CyberShield_DB;

-- ----------------------------------------------------------------------------
-- Query T1: Total Detected Threats & Multi-Domain Threat Telemetry Summary
--           Distinguishes observed anomalous events from normal baseline traffic
-- ----------------------------------------------------------------------------
SELECT 'Anomalous Network Threat Events (Non-Normal)' AS threat_domain,
       COUNT(*) AS detected_threat_count,
       SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_count,
       SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high_count
FROM network_events
WHERE event_type <> 'Normal Traffic'
UNION ALL
SELECT 'SIEM Security Alerts Triggered',
       COUNT(*),
       SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END),
       SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END)
FROM security_alerts
UNION ALL
SELECT 'Failed Authentication / Unauthorized Access Attempts',
       COUNT(*),
       SUM(CASE WHEN failure_reason IN ('Blocked IP Reputation', 'Unauthorized Geo-Location') THEN 1 ELSE 0 END),
       SUM(CASE WHEN failure_reason IN ('Account Locked', 'Invalid Password') THEN 1 ELSE 0 END)
FROM login_logs
WHERE status = 'Failed'
UNION ALL
SELECT 'Suspicious Financial Transactions Flagged',
       COUNT(*),
       SUM(CASE WHEN transaction_status = 'Flagged' THEN 1 ELSE 0 END),
       SUM(CASE WHEN transaction_status IN ('Failed', 'Reversed') THEN 1 ELSE 0 END)
FROM transactions
WHERE risk_indicator = 'Suspicious';

-- ----------------------------------------------------------------------------
-- Query T2: Network Threat & Attack Category Distribution
--           (Actual categories present in network_events.csv)
-- ----------------------------------------------------------------------------
SELECT 
    event_type AS attack_or_traffic_category,
    CASE WHEN event_type = 'Normal Traffic' THEN 'Baseline Traffic' ELSE 'Detected Network Threat' END AS classification,
    COUNT(*) AS event_count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS pct_of_all_network_events,
    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_events,
    SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high_events,
    SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) AS medium_events,
    SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) AS low_events,
    SUM(CASE WHEN event_status = 'Blocked' THEN 1 ELSE 0 END) AS blocked_count,
    SUM(CASE WHEN event_status = 'Quarantined' THEN 1 ELSE 0 END) AS quarantined_count,
    SUM(CASE WHEN event_status = 'Flagged' THEN 1 ELSE 0 END) AS flagged_count,
    ROUND(SUM(bytes_transferred) / 1048576.0, 2) AS total_volume_mb
FROM network_events
GROUP BY event_type
ORDER BY event_count DESC;

-- ----------------------------------------------------------------------------
-- Query T3: SIEM Alert Threat Category & Severity Distribution
--           (Actual categories present in security_alerts.csv)
-- ----------------------------------------------------------------------------
SELECT 
    alert_type AS threat_alert_category,
    COUNT(*) AS total_alerts,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS share_pct,
    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_alerts,
    SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high_alerts,
    SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) AS medium_alerts,
    SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) AS low_alerts,
    COUNT(DISTINCT user_id) AS distinct_users_impacted,
    COUNT(DISTINCT ip_id) AS distinct_source_ips
FROM security_alerts
GROUP BY alert_type
ORDER BY critical_alerts DESC, high_alerts DESC;

-- ----------------------------------------------------------------------------
-- Query T4: Authentication Threat & Unauthorized Access Failure Breakdown
--           (Brute-force password failures, lockouts, geo-anomalies, IP blocks)
-- ----------------------------------------------------------------------------
SELECT 
    failure_reason AS unauthorized_access_vector,
    COUNT(*) AS failed_attempt_count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM login_logs WHERE status = 'Failed'), 2) AS pct_of_failed_logins,
    COUNT(DISTINCT user_id) AS targeted_users,
    COUNT(DISTINCT ip_id) AS originating_ips,
    SUM(CASE WHEN HOUR(login_time) BETWEEN 0 AND 4 THEN 1 ELSE 0 END) AS graveyard_hour_attempts
FROM login_logs
WHERE status = 'Failed'
GROUP BY failure_reason
ORDER BY failed_attempt_count DESC;

-- ----------------------------------------------------------------------------
-- Query T5: Brute-Force Attack Burst Detection (Hourly >= 10 Failed Attempts)
--           Separates blocked brute-force bursts from bursts followed by login
-- ----------------------------------------------------------------------------
WITH brute_force_windows AS (
    SELECT 
        l.user_id,
        l.ip_id,
        DATE(l.login_time) AS attack_date,
        HOUR(l.login_time) AS attack_hour,
        MIN(l.login_time) AS window_start,
        MAX(l.login_time) AS window_end,
        COUNT(*) AS total_attempts,
        SUM(CASE WHEN l.status = 'Failed' THEN 1 ELSE 0 END) AS failed_attempts,
        SUM(CASE WHEN l.status = 'Success' THEN 1 ELSE 0 END) AS successful_attempts
    FROM login_logs l
    GROUP BY l.user_id, l.ip_id, DATE(l.login_time), HOUR(l.login_time)
    HAVING SUM(CASE WHEN l.status = 'Failed' THEN 1 ELSE 0 END) >= 10
)
SELECT 
    bf.user_id,
    u.department,
    u.account_type,
    bf.ip_id,
    ip.ip_address,
    ip.country AS source_country,
    ip.ip_type,
    ip.reputation_score,
    bf.window_start,
    bf.window_end,
    bf.failed_attempts,
    bf.successful_attempts,
    CASE 
        WHEN bf.successful_attempts > 0 THEN 'Critical: Brute-Force Followed by Successful Login'
        ELSE 'High: Sustained Brute-Force Burst Blocked'
    END AS threat_outcome
FROM brute_force_windows bf
JOIN users u ON bf.user_id = u.user_id
JOIN ip_addresses ip ON bf.ip_id = ip.ip_id
ORDER BY bf.successful_attempts DESC, bf.failed_attempts DESC
LIMIT 30;

-- ----------------------------------------------------------------------------
-- Query T6: Monthly Threat Trends Over Time (Jan 2026 - Jun 2026)
--           Includes Month-over-Month (MoM) change using LAG() window function
-- ----------------------------------------------------------------------------
WITH monthly_threats AS (
    SELECT 
        DATE_FORMAT(activity_date, '%Y-%m') AS month_year,
        SUM(failed_logins) AS failed_login_threats,
        SUM(high_crit_net) AS high_crit_network_threats,
        SUM(suspicious_txns) AS suspicious_txn_threats,
        SUM(alerts_cnt) AS security_alerts_triggered,
        SUM(crit_alerts_cnt) AS critical_alerts_triggered,
        SUM(failed_logins + high_crit_net + suspicious_txns + alerts_cnt) AS total_detected_threats
    FROM (
        SELECT DATE(login_time) AS activity_date, COUNT(*) AS failed_logins, 0 AS high_crit_net, 0 AS suspicious_txns, 0 AS alerts_cnt, 0 AS crit_alerts_cnt
        FROM login_logs WHERE status = 'Failed' GROUP BY DATE(login_time)
        UNION ALL
        SELECT DATE(event_time), 0, COUNT(*), 0, 0, 0
        FROM network_events WHERE severity IN ('High', 'Critical') GROUP BY DATE(event_time)
        UNION ALL
        SELECT DATE(transaction_time), 0, 0, COUNT(*), 0, 0
        FROM transactions WHERE risk_indicator = 'Suspicious' GROUP BY DATE(transaction_time)
        UNION ALL
        SELECT DATE(event_time), 0, 0, 0, COUNT(*), SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END)
        FROM security_alerts GROUP BY DATE(event_time)
    ) combined
    GROUP BY DATE_FORMAT(activity_date, '%Y-%m')
)
SELECT 
    month_year,
    failed_login_threats,
    high_crit_network_threats,
    suspicious_txn_threats,
    security_alerts_triggered,
    critical_alerts_triggered,
    total_detected_threats,
    LAG(total_detected_threats) OVER (ORDER BY month_year) AS prev_month_threats,
    ROUND(
        (total_detected_threats - LAG(total_detected_threats) OVER (ORDER BY month_year)) * 100.0 /
        NULLIF(LAG(total_detected_threats) OVER (ORDER BY month_year), 0),
        2
    ) AS mom_threat_growth_pct
FROM monthly_threats
ORDER BY month_year;

-- ----------------------------------------------------------------------------
-- Query T7: Threat Distribution by Geographical Location (Country & City)
-- ----------------------------------------------------------------------------
SELECT 
    ip.country,
    ip.city,
    COUNT(DISTINCT ip.ip_id) AS monitored_ips,
    SUM(CASE WHEN ip.risk_category = 'High-Risk' THEN 1 ELSE 0 END) AS high_risk_ips,
    SUM(CASE WHEN ip.risk_category = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious_ips,
    ROUND(AVG(ip.reputation_score), 1) AS avg_reputation_score,
    COALESCE(SUM(l_agg.failed_logins), 0) AS failed_login_attempts,
    COALESCE(SUM(n_agg.anomalous_net_events), 0) AS anomalous_network_events,
    COALESCE(SUM(n_agg.high_crit_net_events), 0) AS high_crit_network_events,
    COALESCE(SUM(a_agg.total_alerts), 0) AS security_alerts,
    COALESCE(SUM(a_agg.critical_alerts), 0) AS critical_alerts
FROM ip_addresses ip
LEFT JOIN (
    SELECT ip_id, SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed_logins
    FROM login_logs GROUP BY ip_id
) l_agg ON ip.ip_id = l_agg.ip_id
LEFT JOIN (
    SELECT ip_id,
           SUM(CASE WHEN event_type <> 'Normal Traffic' THEN 1 ELSE 0 END) AS anomalous_net_events,
           SUM(CASE WHEN severity IN ('High', 'Critical') THEN 1 ELSE 0 END) AS high_crit_net_events
    FROM network_events GROUP BY ip_id
) n_agg ON ip.ip_id = n_agg.ip_id
LEFT JOIN (
    SELECT ip_id,
           COUNT(*) AS total_alerts,
           SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_alerts
    FROM security_alerts GROUP BY ip_id
) a_agg ON ip.ip_id = a_agg.ip_id
GROUP BY ip.country, ip.city
ORDER BY high_crit_network_events DESC, failed_login_attempts DESC;

-- ----------------------------------------------------------------------------
-- Query T8: Network Security Analytics — Protocol & Destination Port Profile
-- ----------------------------------------------------------------------------
SELECT 
    n.protocol,
    n.destination_port,
    COUNT(*) AS total_network_records,
    SUM(CASE WHEN n.event_type <> 'Normal Traffic' THEN 1 ELSE 0 END) AS suspicious_network_activities,
    SUM(CASE WHEN n.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_severity_events,
    SUM(CASE WHEN n.severity = 'High' THEN 1 ELSE 0 END) AS high_severity_events,
    SUM(CASE WHEN n.event_status IN ('Blocked', 'Quarantined') THEN 1 ELSE 0 END) AS blocked_or_quarantined,
    ROUND(SUM(n.bytes_transferred) / 1048576.0, 2) AS total_traffic_mb,
    ROUND(AVG(n.bytes_transferred) / 1024.0, 2) AS avg_packet_flow_kb
FROM network_events n
GROUP BY n.protocol, n.destination_port
ORDER BY suspicious_network_activities DESC, total_network_records DESC;

-- ----------------------------------------------------------------------------
-- Query T9: Source IP Threat Analysis & Anonymizer Network Footprint
--           Supported by actual reputation_score and risk_category evidence
-- ----------------------------------------------------------------------------
SELECT 
    ip.ip_id,
    ip.ip_address,
    ip.country,
    ip.city,
    ip.ip_type,
    ip.reputation_score,
    ip.risk_category,
    COUNT(n.event_id) AS total_network_events,
    SUM(CASE WHEN n.event_type = 'Port Scan' THEN 1 ELSE 0 END) AS port_scans,
    SUM(CASE WHEN n.event_type = 'Repeated Connection Attempt' THEN 1 ELSE 0 END) AS repeated_connection_probes,
    SUM(CASE WHEN n.event_type = 'Suspicious Outbound Connection' THEN 1 ELSE 0 END) AS suspicious_outbound_conns,
    SUM(CASE WHEN n.event_type = 'High Volume Data Transfer' THEN 1 ELSE 0 END) AS high_volume_transfers,
    ROUND(SUM(n.bytes_transferred) / 1048576.0, 2) AS total_megabytes_transferred
FROM ip_addresses ip
JOIN network_events n ON ip.ip_id = n.ip_id
WHERE ip.risk_category IN ('High-Risk', 'Suspicious')
GROUP BY ip.ip_id, ip.ip_address, ip.country, ip.city, ip.ip_type, ip.reputation_score, ip.risk_category
ORDER BY ip.reputation_score DESC, total_network_events DESC
LIMIT 25;

-- ----------------------------------------------------------------------------
-- Query T10: Threat Activity by Hour of Day (00:00 - 23:00 Heatmap Matrix)
-- ----------------------------------------------------------------------------
SELECT 
    HOUR(n.event_time) AS hour_of_day,
    COUNT(*) AS total_network_events,
    SUM(CASE WHEN n.event_type <> 'Normal Traffic' THEN 1 ELSE 0 END) AS anomalous_network_threats,
    SUM(CASE WHEN n.severity IN ('High', 'Critical') THEN 1 ELSE 0 END) AS high_crit_network_threats,
    ROUND(SUM(n.bytes_transferred) / 1048576.0, 2) AS hourly_traffic_mb
FROM network_events n
GROUP BY HOUR(n.event_time)
ORDER BY hour_of_day ASC;
