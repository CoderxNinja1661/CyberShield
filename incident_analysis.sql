-- ============================================================================
-- PROJECT: CYBERSHIELD – CYBERSECURITY THREAT & RISK INTELLIGENCE
-- FILE: incident_analysis.sql
-- TARGET DBMS: MySQL 8.0+
-- DESCRIPTION: Analytical SQL queries for:
--                - Module B: Security Incident Intelligence
--                - Module E: User Activity Intelligence (with anonymized IDs)
--                - Module F: Security Operations Performance (MTTR, closure
--                  rates, alert backlogs, recurring incidents)
--              Strictly keeps Incident/Alert Severity, Alert Type, and
--              Resolution Status separate (Rules 2, 3, 10).
-- EXECUTION ORDER: Run after risk_analysis.sql
-- ============================================================================

USE CyberShield_DB;

-- ----------------------------------------------------------------------------
-- Query I1: Security Operations Executive Scorecard
--           Total alerts, Critical/High alerts, Resolved vs Investigating vs
--           Unresolved, Closure Rate %, and Mean Time To Resolve (MTTR)
-- ----------------------------------------------------------------------------
SELECT 
    COUNT(*) AS total_security_alerts,
    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_alerts,
    SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high_priority_alerts,
    SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) AS medium_alerts,
    SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) AS low_alerts,
    SUM(CASE WHEN resolution_status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_incidents,
    SUM(CASE WHEN resolution_status = 'Investigating' THEN 1 ELSE 0 END) AS investigating_incidents,
    SUM(CASE WHEN resolution_status = 'Unresolved' THEN 1 ELSE 0 END) AS unresolved_incidents,
    SUM(CASE WHEN resolution_status <> 'Resolved' THEN 1 ELSE 0 END) AS total_pending_backlog,
    ROUND(SUM(CASE WHEN resolution_status = 'Resolved' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS incident_closure_rate_pct,
    ROUND(AVG(CASE WHEN resolution_status = 'Resolved' AND resolution_time IS NOT NULL
                   THEN TIMESTAMPDIFF(SECOND, event_time, resolution_time) / 60.0 END), 2) AS avg_resolution_time_minutes,
    ROUND(AVG(CASE WHEN resolution_status = 'Resolved' AND resolution_time IS NOT NULL
                   THEN TIMESTAMPDIFF(SECOND, event_time, resolution_time) / 3600.0 END), 2) AS avg_resolution_time_hours
FROM security_alerts;

-- ----------------------------------------------------------------------------
-- Query I2: Incident Resolution Performance (MTTR & Closure Rate) by Severity
--           and Alert Type (Keeps Severity and Resolution Status Separate)
-- ----------------------------------------------------------------------------
SELECT 
    severity AS alert_severity,
    alert_type AS incident_category,
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN resolution_status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_count,
    SUM(CASE WHEN resolution_status = 'Investigating' THEN 1 ELSE 0 END) AS investigating_count,
    SUM(CASE WHEN resolution_status = 'Unresolved' THEN 1 ELSE 0 END) AS unresolved_count,
    ROUND(SUM(CASE WHEN resolution_status = 'Resolved' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS closure_rate_pct,
    ROUND(AVG(CASE WHEN resolution_time IS NOT NULL THEN TIMESTAMPDIFF(SECOND, event_time, resolution_time) / 60.0 END), 2) AS mttr_minutes,
    MIN(CASE WHEN resolution_time IS NOT NULL THEN ROUND(TIMESTAMPDIFF(SECOND, event_time, resolution_time) / 60.0, 1) END) AS fastest_resolution_min,
    MAX(CASE WHEN resolution_time IS NOT NULL THEN ROUND(TIMESTAMPDIFF(SECOND, event_time, resolution_time) / 60.0, 1) END) AS slowest_resolution_min
FROM security_alerts
GROUP BY severity, alert_type
ORDER BY FIELD(severity, 'Critical', 'High', 'Medium', 'Low'), total_incidents DESC;

-- ----------------------------------------------------------------------------
-- Query I3: Department-Wise Incident Distribution, Pending Backlog & MTTR
--           Identifies departments with the longest incident resolution times
-- ----------------------------------------------------------------------------
SELECT 
    u.department,
    COUNT(a.alert_id) AS total_incidents,
    ROUND(COUNT(a.alert_id) * 100.0 / (SELECT COUNT(*) FROM security_alerts), 2) AS share_of_all_incidents_pct,
    SUM(CASE WHEN a.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_incidents,
    SUM(CASE WHEN a.severity = 'High' THEN 1 ELSE 0 END) AS high_incidents,
    SUM(CASE WHEN a.resolution_status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_incidents,
    SUM(CASE WHEN a.resolution_status = 'Investigating' THEN 1 ELSE 0 END) AS investigating_incidents,
    SUM(CASE WHEN a.resolution_status = 'Unresolved' THEN 1 ELSE 0 END) AS unresolved_incidents,
    ROUND(SUM(CASE WHEN a.resolution_status = 'Resolved' THEN 1 ELSE 0 END) * 100.0 / COUNT(a.alert_id), 2) AS closure_rate_pct,
    ROUND(AVG(CASE WHEN a.resolution_time IS NOT NULL THEN TIMESTAMPDIFF(SECOND, a.event_time, a.resolution_time) / 60.0 END), 2) AS avg_mttr_minutes
FROM security_alerts a
JOIN users u ON a.user_id = u.user_id
GROUP BY u.department
ORDER BY total_incidents DESC;

-- ----------------------------------------------------------------------------
-- Query I4: Monthly Security Incident & Resolution Time Trend (Jan-Jun 2026)
-- ----------------------------------------------------------------------------
SELECT 
    DATE_FORMAT(event_time, '%Y-%m') AS incident_month,
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_incidents,
    SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high_incidents,
    SUM(CASE WHEN resolution_status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_incidents,
    SUM(CASE WHEN resolution_status <> 'Resolved' THEN 1 ELSE 0 END) AS pending_incidents,
    ROUND(SUM(CASE WHEN resolution_status = 'Resolved' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS monthly_closure_rate_pct,
    ROUND(AVG(CASE WHEN resolution_time IS NOT NULL THEN TIMESTAMPDIFF(SECOND, event_time, resolution_time) / 60.0 END), 2) AS monthly_avg_mttr_minutes
FROM security_alerts
GROUP BY DATE_FORMAT(event_time, '%Y-%m')
ORDER BY incident_month ASC;

-- ----------------------------------------------------------------------------
-- Query I5: Daily Incident Trend & 7-Day Moving Average
-- ----------------------------------------------------------------------------
WITH daily_alerts AS (
    SELECT 
        DATE(event_time) AS incident_date,
        COUNT(*) AS total_alerts,
        SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_alerts,
        SUM(CASE WHEN resolution_status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_alerts,
        SUM(CASE WHEN resolution_status <> 'Resolved' THEN 1 ELSE 0 END) AS open_alerts
    FROM security_alerts
    GROUP BY DATE(event_time)
)
SELECT 
    incident_date,
    total_alerts,
    critical_alerts,
    resolved_alerts,
    open_alerts,
    SUM(total_alerts) OVER (ORDER BY incident_date ASC ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS cumulative_alerts,
    ROUND(AVG(total_alerts) OVER (ORDER BY incident_date ASC ROWS BETWEEN 6 PRECEDING AND CURRENT ROW), 2) AS rolling_7day_avg_alerts
FROM daily_alerts
ORDER BY incident_date ASC;

-- ----------------------------------------------------------------------------
-- Query I6: Recurring / Repeated Security Incidents by Anonymized User Account
--           (Accounts triggering >= 15 SIEM alerts across the 6-month window)
-- ----------------------------------------------------------------------------
SELECT 
    a.user_id AS anonymized_user_id,
    u.department,
    u.account_type,
    u.account_status,
    COUNT(a.alert_id) AS recurring_incident_count,
    COUNT(DISTINCT a.alert_type) AS distinct_alert_categories,
    SUM(CASE WHEN a.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_alerts,
    SUM(CASE WHEN a.severity = 'High' THEN 1 ELSE 0 END) AS high_alerts,
    SUM(CASE WHEN a.resolution_status <> 'Resolved' THEN 1 ELSE 0 END) AS open_unresolved_alerts,
    MIN(a.event_time) AS first_incident_timestamp,
    MAX(a.event_time) AS latest_incident_timestamp
FROM security_alerts a
JOIN users u ON a.user_id = u.user_id
GROUP BY a.user_id, u.department, u.account_type, u.account_status
HAVING COUNT(a.alert_id) >= 15
ORDER BY recurring_incident_count DESC, critical_alerts DESC
LIMIT 30;

-- ----------------------------------------------------------------------------
-- Query I7: User Activity Intelligence — Login & Session Behavior by Department
-- ----------------------------------------------------------------------------
SELECT 
    u.department,
    COUNT(DISTINCT u.user_id) AS monitored_users,
    SUM(CASE WHEN u.account_status = 'Locked' THEN 1 ELSE 0 END) AS locked_accounts,
    SUM(CASE WHEN u.account_status = 'Suspended' THEN 1 ELSE 0 END) AS suspended_accounts,
    COALESCE(SUM(l_agg.total_logins), 0) AS total_login_attempts,
    COALESCE(SUM(l_agg.successful_logins), 0) AS successful_logins,
    COALESCE(SUM(l_agg.failed_logins), 0) AS failed_logins,
    ROUND(COALESCE(SUM(l_agg.failed_logins), 0) * 100.0 / NULLIF(COALESCE(SUM(l_agg.total_logins), 0), 0), 2) AS failure_rate_pct,
    COALESCE(SUM(l_agg.graveyard_logins), 0) AS graveyard_hour_logins,
    COALESCE(SUM(s_agg.session_count), 0) AS authenticated_sessions,
    ROUND(COALESCE(AVG(s_agg.avg_session_min), 0), 1) AS avg_session_duration_min
FROM users u
LEFT JOIN (
    SELECT user_id,
           COUNT(*) AS total_logins,
           SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) AS successful_logins,
           SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed_logins,
           SUM(CASE WHEN HOUR(login_time) BETWEEN 0 AND 4 THEN 1 ELSE 0 END) AS graveyard_logins
    FROM login_logs GROUP BY user_id
) l_agg ON u.user_id = l_agg.user_id
LEFT JOIN (
    SELECT user_id,
           COUNT(*) AS session_count,
           AVG(duration_minutes) AS avg_session_min
    FROM user_sessions GROUP BY user_id
) s_agg ON u.user_id = s_agg.user_id
GROUP BY u.department
ORDER BY failed_logins DESC;

-- ----------------------------------------------------------------------------
-- Query I8: System / Endpoint Device & Operating System Incident Distribution
-- ----------------------------------------------------------------------------
SELECT 
    l.device_type AS endpoint_system_type,
    l.operating_system,
    l.browser,
    COUNT(l.login_id) AS total_access_attempts,
    SUM(CASE WHEN l.status = 'Success' THEN 1 ELSE 0 END) AS successful_logins,
    SUM(CASE WHEN l.status = 'Failed' THEN 1 ELSE 0 END) AS failed_logins,
    ROUND(SUM(CASE WHEN l.status = 'Failed' THEN 1 ELSE 0 END) * 100.0 / COUNT(l.login_id), 2) AS failure_rate_pct,
    COUNT(DISTINCT l.user_id) AS distinct_users
FROM login_logs l
GROUP BY l.device_type, l.operating_system, l.browser
ORDER BY failed_logins DESC
LIMIT 25;

-- ----------------------------------------------------------------------------
-- Query I9: Potential Account Compromise Indicators
--           (Anonymized users with >= 10 consecutive failed logins or high-risk
--           graveyard logins followed by suspicious financial transactions)
-- ----------------------------------------------------------------------------
SELECT 
    ur.user_id AS anonymized_user_id,
    ur.department,
    ur.account_type,
    ur.account_status,
    ur.failed_logins,
    ur.off_hour_logins AS graveyard_hour_logins,
    ur.distinct_ips_used,
    ur.max_ip_reputation,
    ur.suspicious_txn_count,
    ur.suspicious_txn_amount_inr,
    ur.total_alerts,
    ur.unresolved_alerts,
    ur.composite_risk_score,
    ur.calculated_risk_category
FROM vw_user_risk_scores ur
WHERE ur.calculated_risk_category IN ('Critical', 'High')
ORDER BY ur.composite_risk_score DESC, ur.suspicious_txn_amount_inr DESC
LIMIT 35;
