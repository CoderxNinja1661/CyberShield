-- ============================================================================
-- PROJECT: CYBERSHIELD – CYBERSECURITY THREAT & RISK INTELLIGENCE
-- FILE: database_creation.sql
-- TARGET DBMS: MySQL 8.0+
-- DESCRIPTION: Creates the CyberShield_DB relational database, defines all
--              7 normalized InnoDB tables supported by the actual dataset
--              fields, establishes Primary Keys, Foreign Keys, CHECK domain
--              constraints, and creates composite analytical indexes.
-- ============================================================================

DROP DATABASE IF EXISTS CyberShield_DB;

CREATE DATABASE CyberShield_DB
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;

USE CyberShield_DB;

-- Also ensure compatibility if scripts reference lowercase cybershield_db on case-insensitive Windows MySQL
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS security_alerts;
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS network_events;
DROP TABLE IF EXISTS login_logs;
DROP TABLE IF EXISTS ip_addresses;
DROP TABLE IF EXISTS users;

SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================================
-- 1. MASTER ENTITY TABLES
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table 1: users (User_Activity / Monitored Organizational Accounts - 5,000 rows)
-- ----------------------------------------------------------------------------
CREATE TABLE users (
    user_id        VARCHAR(12)  NOT NULL,
    username       VARCHAR(60)  NOT NULL,
    department     VARCHAR(40)  NOT NULL,
    account_type   VARCHAR(30)  NOT NULL,
    account_status VARCHAR(20)  NOT NULL,
    created_date   DATE         NOT NULL,
    country        VARCHAR(40)  NOT NULL,
    CONSTRAINT pk_users PRIMARY KEY (user_id),
    CONSTRAINT uq_users_username UNIQUE (username),
    CONSTRAINT chk_users_account_type CHECK (account_type IN ('Regular Employee', 'Manager', 'Privileged User', 'Administrator')),
    CONSTRAINT chk_users_account_status CHECK (account_status IN ('Active', 'Locked', 'Suspended'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------------------------------------------------------
-- Table 2: ip_addresses (Threat_Details / IP Intelligence Registry - 500 rows)
-- ----------------------------------------------------------------------------
CREATE TABLE ip_addresses (
    ip_id            VARCHAR(10)  NOT NULL,
    ip_address       VARCHAR(45)  NOT NULL,
    country          VARCHAR(40)  NOT NULL,
    city             VARCHAR(50)  NOT NULL,
    ip_type          VARCHAR(35)  NOT NULL,
    reputation_score INT          NOT NULL,
    risk_category    VARCHAR(20)  NOT NULL,
    CONSTRAINT pk_ip_addresses PRIMARY KEY (ip_id),
    CONSTRAINT uq_ip_addresses_ip UNIQUE (ip_address),
    CONSTRAINT chk_ip_reputation_range CHECK (reputation_score BETWEEN 0 AND 100),
    CONSTRAINT chk_ip_risk_category CHECK (risk_category IN ('Normal', 'Suspicious', 'High-Risk'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================================
-- 2. TELEMETRY, INCIDENT & RISK FACT TABLES
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table 3: login_logs (Authentication & User Activity Telemetry - 50,000 rows)
-- ----------------------------------------------------------------------------
CREATE TABLE login_logs (
    login_id         VARCHAR(15)  NOT NULL,
    user_id          VARCHAR(12)  NOT NULL,
    ip_id            VARCHAR(10)  NOT NULL,
    login_time       DATETIME     NOT NULL,
    status           VARCHAR(15)  NOT NULL,
    device_type      VARCHAR(25)  NOT NULL,
    browser          VARCHAR(25)  NOT NULL,
    operating_system VARCHAR(30)  NOT NULL,
    failure_reason   VARCHAR(45)  NOT NULL,
    CONSTRAINT pk_login_logs PRIMARY KEY (login_id),
    CONSTRAINT fk_login_user FOREIGN KEY (user_id) REFERENCES users (user_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_login_ip   FOREIGN KEY (ip_id)   REFERENCES ip_addresses (ip_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT chk_login_status CHECK (status IN ('Success', 'Failed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------------------------------------------------------
-- Table 4: network_events (Network_Activity & Attack_Categories - 20,000 rows)
-- ----------------------------------------------------------------------------
CREATE TABLE network_events (
    event_id          VARCHAR(15)  NOT NULL,
    ip_id             VARCHAR(10)  NOT NULL,
    event_time        DATETIME     NOT NULL,
    event_type        VARCHAR(45)  NOT NULL,
    protocol          VARCHAR(15)  NOT NULL,
    source_port       INT          NOT NULL,
    destination_port  INT          NOT NULL,
    bytes_transferred BIGINT       NOT NULL,
    severity          VARCHAR(15)  NOT NULL,
    event_status      VARCHAR(20)  NOT NULL,
    CONSTRAINT pk_network_events PRIMARY KEY (event_id),
    CONSTRAINT fk_net_ip FOREIGN KEY (ip_id) REFERENCES ip_addresses (ip_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT chk_net_ports CHECK (source_port BETWEEN 1 AND 65535 AND destination_port BETWEEN 1 AND 65535),
    CONSTRAINT chk_net_bytes CHECK (bytes_transferred >= 0),
    CONSTRAINT chk_net_severity CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    CONSTRAINT chk_net_status CHECK (event_status IN ('Allowed', 'Flagged', 'Blocked', 'Quarantined'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------------------------------------------------------
-- Table 5: transactions (Financial Risk & Fraud Telemetry in INR - 10,000 rows)
-- ----------------------------------------------------------------------------
CREATE TABLE transactions (
    transaction_id     VARCHAR(15)    NOT NULL,
    user_id            VARCHAR(12)    NOT NULL,
    ip_id              VARCHAR(10)    NOT NULL,
    transaction_time   DATETIME       NOT NULL,
    amount             DECIMAL(12,2)  NOT NULL,
    payment_type       VARCHAR(25)    NOT NULL,
    transaction_status VARCHAR(20)    NOT NULL,
    risk_indicator     VARCHAR(20)    NOT NULL,
    CONSTRAINT pk_transactions PRIMARY KEY (transaction_id),
    CONSTRAINT fk_txn_user FOREIGN KEY (user_id) REFERENCES users (user_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_txn_ip   FOREIGN KEY (ip_id)   REFERENCES ip_addresses (ip_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT chk_txn_amount CHECK (amount >= 0.00),
    CONSTRAINT chk_txn_risk_indicator CHECK (risk_indicator IN ('Normal', 'Suspicious'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------------------------------------------------------
-- Table 6: security_alerts (Security_Incidents & Security_Alerts - 3,000 rows)
-- ----------------------------------------------------------------------------
CREATE TABLE security_alerts (
    alert_id          VARCHAR(15)   NOT NULL,
    user_id           VARCHAR(12)   NOT NULL,
    ip_id             VARCHAR(10)   NOT NULL,
    event_time        DATETIME      NOT NULL,
    alert_type        VARCHAR(45)   NOT NULL,
    severity          VARCHAR(15)   NOT NULL,
    description       VARCHAR(255)  NOT NULL,
    resolution_status VARCHAR(20)   NOT NULL,
    resolution_time   DATETIME      NULL,
    CONSTRAINT pk_security_alerts PRIMARY KEY (alert_id),
    CONSTRAINT fk_alert_user FOREIGN KEY (user_id) REFERENCES users (user_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_alert_ip   FOREIGN KEY (ip_id)   REFERENCES ip_addresses (ip_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT chk_alert_severity CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    CONSTRAINT chk_alert_resolution_status CHECK (resolution_status IN ('Resolved', 'Investigating', 'Unresolved')),
    CONSTRAINT chk_alert_resolution_time CHECK (resolution_time IS NULL OR resolution_time >= event_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------------------------------------------------------
-- Table 7: user_sessions (Authenticated Session Telemetry - 30,000 rows)
-- ----------------------------------------------------------------------------
CREATE TABLE user_sessions (
    session_id       VARCHAR(15)  NOT NULL,
    user_id          VARCHAR(12)  NOT NULL,
    login_id         VARCHAR(15)  NOT NULL,
    start_time       DATETIME     NOT NULL,
    end_time         DATETIME     NOT NULL,
    session_status   VARCHAR(20)  NOT NULL,
    duration_minutes INT          NOT NULL,
    CONSTRAINT pk_user_sessions PRIMARY KEY (session_id),
    CONSTRAINT fk_session_user  FOREIGN KEY (user_id)  REFERENCES users (user_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_session_login FOREIGN KEY (login_id) REFERENCES login_logs (login_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT chk_session_timestamps CHECK (end_time >= start_time),
    CONSTRAINT chk_session_duration CHECK (duration_minutes > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================================
-- 3. COMPOSITE ANALYTICAL INDEXES
-- ============================================================================

CREATE INDEX idx_users_dept_status       ON users (department, account_status);
CREATE INDEX idx_users_country           ON users (country);
CREATE INDEX idx_ip_risk_reputation      ON ip_addresses (risk_category, reputation_score);
CREATE INDEX idx_ip_country              ON ip_addresses (country);
CREATE INDEX idx_login_user_time         ON login_logs (user_id, login_time);
CREATE INDEX idx_login_ip_status         ON login_logs (ip_id, status);
CREATE INDEX idx_login_time_status       ON login_logs (login_time, status);
CREATE INDEX idx_net_ip_time             ON network_events (ip_id, event_time);
CREATE INDEX idx_net_severity_type       ON network_events (severity, event_type);
CREATE INDEX idx_net_time                ON network_events (event_time);
CREATE INDEX idx_txn_user_time           ON transactions (user_id, transaction_time);
CREATE INDEX idx_txn_ip_risk             ON transactions (ip_id, risk_indicator);
CREATE INDEX idx_txn_time_risk           ON transactions (transaction_time, risk_indicator);
CREATE INDEX idx_alert_user_sev          ON security_alerts (user_id, severity);
CREATE INDEX idx_alert_ip_status         ON security_alerts (ip_id, resolution_status);
CREATE INDEX idx_alert_time_sev          ON security_alerts (event_time, severity);
CREATE INDEX idx_session_user_time       ON user_sessions (user_id, start_time);
CREATE INDEX idx_session_login           ON user_sessions (login_id);

-- Verify created schema and tables
SHOW TABLES;
