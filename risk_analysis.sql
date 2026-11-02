-- ============================================================================
-- PROJECT: CYBERSHIELD – CYBERSECURITY THREAT & RISK INTELLIGENCE
-- FILE: risk_analysis.sql
-- TARGET DBMS: MySQL 8.0+
-- DESCRIPTION: Analytical SQL queries for Module C (Risk Intelligence) and
--              Financial Fraud Risk Exposure following the Data Dictionary's
--              exact 5-Factor Composite User Risk Scoring Model (0-100) and
--              IP Reputation Risk Classification (0-100):
--                - User Risk Tiers: Critical (80-100), High (60-79.9),
--                  Medium (30-59.9), Low (0-29.9)
--                - IP Risk Tiers: High-Risk (70-98), Suspicious (30-69),
--                  Normal (2-29)
-- EXECUTION ORDER: Run after threat_analysis.sql
-- ============================================================================

USE CyberShield_DB;

-- ----------------------------------------------------------------------------
-- Query R1: 5-Factor Composite User Risk Score Distribution (All 5,000 Users)
--           Factors:
--             S1 Failed Logins (max 25 pts)
--             S2 Max IP Reputation (max 25 pts)
--             S3 Graveyard-Hour 00:00-04:59 Logins (max 10 pts)
--             S4 Security & Network Alerts (max 20 pts)
--             S5 Suspicious Financial Transactions (max 20 pts)
-- ----------------------------------------------------------------------------
WITH user_risk_cte AS (
    SELECT 
        u.user_id,
        u.department,
        u.account_type,
        u.account_status,
        COALESCE(l.failed_logins, 0) AS failed_logins,
        COALESCE(l.off_hour_logins, 0) AS off_hour_logins,
        GREATEST(COALESCE(l.max_ip_rep, 0), COALESCE(t.max_ip_rep, 0), COALESCE(a.max_ip_rep, 0)) AS max_ip_reputation,
        COALESCE(t.suspicious_txns, 0) AS suspicious_txns,
        COALESCE(t.suspicious_inr, 0.00) AS suspicious_inr,
        COALESCE(a.total_alerts, 0) AS total_alerts,
        COALESCE(a.unresolved_alerts, 0) AS unresolved_alerts,
        LEAST(100.0, ROUND(
            LEAST(25.0, ROUND((COALESCE(l.failed_logins, 0) / 25.0) * 25.0, 1)) +
            LEAST(25.0, ROUND((GREATEST(COALESCE(l.max_ip_rep, 0), COALESCE(t.max_ip_rep, 0), COALESCE(a.max_ip_rep, 0)) / 100.0) * 25.0, 1)) +
            LEAST(10.0, ROUND((COALESCE(l.off_hour_logins, 0) / 15.0) * 10.0, 1)) +
            LEAST(20.0, ROUND(((COALESCE(a.total_alerts, 0) + COALESCE(a.net_alerts, 0)) / 10.0) * 20.0, 1)) +
            LEAST(20.0, ROUND((COALESCE(t.suspicious_txns, 0) / 5.0) * 20.0, 1)),
        1)) AS composite_risk_score
    FROM users u
    LEFT JOIN (
        SELECT l2.user_id,
               SUM(CASE WHEN l2.status = 'Failed' THEN 1 ELSE 0 END) AS failed_logins,
               SUM(CASE WHEN HOUR(l2.login_time) BETWEEN 0 AND 4 THEN 1 ELSE 0 END) AS off_hour_logins,
               MAX(ip2.reputation_score) AS max_ip_rep
        FROM login_logs l2 JOIN ip_addresses ip2 ON l2.ip_id = ip2.ip_id
        GROUP BY l2.user_id
    ) l ON u.user_id = l.user_id
    LEFT JOIN (
        SELECT t2.user_id,
               SUM(CASE WHEN t2.risk_indicator = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious_txns,
               SUM(CASE WHEN t2.risk_indicator = 'Suspicious' THEN t2.amount ELSE 0.00 END) AS suspicious_inr,
               MAX(ip2.reputation_score) AS max_ip_rep
        FROM transactions t2 JOIN ip_addresses ip2 ON t2.ip_id = ip2.ip_id
        GROUP BY t2.user_id
    ) t ON u.user_id = t.user_id
    LEFT JOIN (
        SELECT a2.user_id,
               COUNT(*) AS total_alerts,
               SUM(CASE WHEN a2.resolution_status <> 'Resolved' THEN 1 ELSE 0 END) AS unresolved_alerts,
               SUM(CASE WHEN a2.alert_type IN ('High-Volume Network Activity', 'Suspicious IP Activity') THEN 1 ELSE 0 END) AS net_alerts,
               MAX(ip2.reputation_score) AS max_ip_rep
        FROM security_alerts a2 JOIN ip_addresses ip2 ON a2.ip_id = ip2.ip_id
        GROUP BY a2.user_id
    ) a ON u.user_id = a.user_id
)
SELECT 
    CASE 
        WHEN composite_risk_score >= 80.0 THEN 'Critical'
        WHEN composite_risk_score >= 60.0 THEN 'High'
        WHEN composite_risk_score >= 30.0 THEN 'Medium'
        ELSE 'Low'
    END AS vulnerability_risk_tier,
    COUNT(*) AS account_count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS pct_of_monitored_users,
    ROUND(AVG(composite_risk_score), 2) AS avg_risk_score,
    MIN(composite_risk_score) AS min_risk_score,
    MAX(composite_risk_score) AS max_risk_score,
    SUM(failed_logins) AS total_failed_logins,
    SUM(total_alerts) AS total_security_alerts,
    SUM(unresolved_alerts) AS open_unresolved_alerts,
    SUM(suspicious_txns) AS suspicious_transactions,
    ROUND(SUM(suspicious_inr), 2) AS suspicious_exposure_inr
FROM user_risk_cte
GROUP BY vulnerability_risk_tier
ORDER BY FIELD(vulnerability_risk_tier, 'Critical', 'High', 'Medium', 'Low');

-- ----------------------------------------------------------------------------
-- Query R2: Risk Exposure & Vulnerability Tier Distribution by Department
-- ----------------------------------------------------------------------------
SELECT 
    department,
    COUNT(*) AS total_users,
    SUM(CASE WHEN calculated_risk_category = 'Critical' THEN 1 ELSE 0 END) AS critical_risk_users,
    SUM(CASE WHEN calculated_risk_category = 'High' THEN 1 ELSE 0 END) AS high_risk_users,
    SUM(CASE WHEN calculated_risk_category = 'Medium' THEN 1 ELSE 0 END) AS medium_risk_users,
    SUM(CASE WHEN calculated_risk_category = 'Low' THEN 1 ELSE 0 END) AS low_risk_users,
    ROUND(AVG(composite_risk_score), 2) AS avg_department_risk_score,
    SUM(failed_logins) AS dept_failed_logins,
    SUM(total_alerts) AS dept_security_alerts,
    SUM(unresolved_alerts) AS dept_unresolved_alerts,
    SUM(suspicious_txn_count) AS dept_suspicious_txns,
    ROUND(SUM(suspicious_txn_amount_inr), 2) AS dept_suspicious_exposure_inr
FROM vw_user_risk_scores
GROUP BY department
ORDER BY critical_risk_users DESC, high_risk_users DESC, dept_suspicious_exposure_inr DESC;

-- ----------------------------------------------------------------------------
-- Query R3: Risk Level by Account Privilege Tier & System Device Profile
-- ----------------------------------------------------------------------------
SELECT 
    account_type AS privilege_level,
    account_status,
    COUNT(*) AS account_count,
    SUM(CASE WHEN calculated_risk_category = 'Critical' THEN 1 ELSE 0 END) AS critical_risk_count,
    SUM(CASE WHEN calculated_risk_category = 'High' THEN 1 ELSE 0 END) AS high_risk_count,
    ROUND(AVG(composite_risk_score), 2) AS avg_risk_score,
    SUM(failed_logins) AS total_failed_logins,
    SUM(unresolved_alerts) AS unresolved_alerts,
    ROUND(SUM(suspicious_txn_amount_inr), 2) AS suspicious_exposure_inr
FROM vw_user_risk_scores
GROUP BY account_type, account_status
ORDER BY critical_risk_count DESC, avg_risk_score DESC;

-- ----------------------------------------------------------------------------
-- Query R4: Highest-Risk Assets / Accounts Ranking (Anonymized User IDs)
--           Uses Window Functions: ROW_NUMBER(), RANK(), DENSE_RANK()
-- ----------------------------------------------------------------------------
SELECT 
    ROW_NUMBER() OVER (ORDER BY composite_risk_score DESC, failed_logins DESC) AS asset_priority_order,
    RANK() OVER (ORDER BY composite_risk_score DESC) AS risk_rank,
    DENSE_RANK() OVER (ORDER BY composite_risk_score DESC) AS dense_risk_rank,
    user_id AS anonymized_user_id,
    department,
    account_type,
    account_status,
    composite_risk_score,
    calculated_risk_category AS risk_tier,
    failed_logins,
    off_hour_logins,
    max_ip_reputation,
    total_alerts,
    unresolved_alerts,
    suspicious_txn_count,
    suspicious_txn_amount_inr
FROM vw_user_risk_scores
ORDER BY composite_risk_score DESC, failed_logins DESC
LIMIT 30;

-- ----------------------------------------------------------------------------
-- Query R5: IP Reputation & Infrastructure Risk Score Histogram (10-Point Bins)
-- ----------------------------------------------------------------------------
SELECT 
    CONCAT(FLOOR(reputation_score / 10) * 10, '-', FLOOR(reputation_score / 10) * 10 + 9) AS reputation_score_bin,
    risk_category AS ip_risk_tier,
    COUNT(*) AS ip_count,
    ROUND(AVG(reputation_score), 1) AS avg_score_in_bin,
    SUM(failed_logins) AS associated_failed_logins,
    SUM(critical_high_net_events) AS associated_high_crit_net_events,
    SUM(total_alerts) AS associated_alerts,
    ROUND(SUM(suspicious_txn_value_inr), 2) AS associated_suspicious_inr
FROM vw_ip_threat_summary
GROUP BY FLOOR(reputation_score / 10), CONCAT(FLOOR(reputation_score / 10) * 10, '-', FLOOR(reputation_score / 10) * 10 + 9), risk_category
ORDER BY FLOOR(reputation_score / 10) DESC;

-- ----------------------------------------------------------------------------
-- Query R6: Unresolved Vulnerability & Open Risk Exposure Analysis by Severity
-- ----------------------------------------------------------------------------
SELECT 
    a.severity AS alert_severity,
    a.resolution_status,
    COUNT(a.alert_id) AS alert_count,
    COUNT(DISTINCT a.user_id) AS impacted_users,
    COUNT(DISTINCT a.ip_id) AS involved_ips,
    SUM(CASE WHEN u.account_type IN ('Administrator', 'Privileged User') THEN 1 ELSE 0 END) AS privileged_account_exposures,
    ROUND(AVG(ur.composite_risk_score), 2) AS avg_affected_user_risk_score
FROM security_alerts a
JOIN users u ON a.user_id = u.user_id
JOIN vw_user_risk_scores ur ON a.user_id = ur.user_id
WHERE a.resolution_status IN ('Unresolved', 'Investigating')
GROUP BY a.severity, a.resolution_status
ORDER BY FIELD(a.severity, 'Critical', 'High', 'Medium', 'Low'), a.resolution_status;

-- ----------------------------------------------------------------------------
-- Query R7: Financial Fraud & Payment Rail Risk Exposure Comparison (INR)
-- ----------------------------------------------------------------------------
SELECT 
    t.payment_type,
    COUNT(t.transaction_id) AS total_transactions,
    SUM(CASE WHEN t.risk_indicator = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious_transactions,
    ROUND(SUM(CASE WHEN t.risk_indicator = 'Suspicious' THEN 1 ELSE 0 END) * 100.0 / COUNT(t.transaction_id), 2) AS suspicious_rate_pct,
    ROUND(SUM(t.amount), 2) AS total_transaction_value_inr,
    ROUND(SUM(CASE WHEN t.risk_indicator = 'Suspicious' THEN t.amount ELSE 0.00 END), 2) AS suspicious_exposure_inr,
    ROUND(
        SUM(CASE WHEN t.risk_indicator = 'Suspicious' THEN t.amount ELSE 0.00 END) * 100.0 /
        (SELECT SUM(amount) FROM transactions WHERE risk_indicator = 'Suspicious'),
        2
    ) AS share_of_total_fraud_exposure_pct,
    SUM(CASE WHEN t.risk_indicator = 'Suspicious' AND t.transaction_status = 'Completed' THEN 1 ELSE 0 END) AS completed_suspicious_txns,
    SUM(CASE WHEN t.risk_indicator = 'Suspicious' AND t.transaction_status = 'Flagged' THEN 1 ELSE 0 END) AS flagged_suspicious_txns,
    SUM(CASE WHEN t.risk_indicator = 'Suspicious' AND t.transaction_status = 'Reversed' THEN 1 ELSE 0 END) AS reversed_suspicious_txns
FROM transactions t
GROUP BY t.payment_type
ORDER BY suspicious_exposure_inr DESC;
