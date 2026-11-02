# CyberShield – Cyber Attack & Fraud Pattern Analytics

> **SYNTHETIC DATA & DECISION-SUPPORT DISCLOSURE:**  
> All **118,500 records** contained in this repository are **100% synthetic historical telemetry** covering a six-month observation window (**January 1, 2026 to June 30, 2026**). No real person, employee, IP owner, or financial institution is represented. CyberShield is an **analytical and decision-support platform** designed for MCA academic evaluation and Security Operations Center (SOC) pattern discovery—it is **not** a real-time Intrusion Prevention System (IPS) and does not claim that simulated events are confirmed real-world cyberattacks.

---

## 1. Project Overview

**CyberShield** is an industry-grade Business & Cybersecurity Analytics project built strictly using three core enterprise technologies:

1. **MySQL 8.0** (`cybershield_db` — 7 relational tables, 14 SQL scripts, 35 analytical queries, 8 BI views, and a 5-factor rule-based User Risk Scoring engine).
2. **Microsoft Excel** (`CyberShield_Security_Analytics.xlsx` — 17 worksheets containing all 118,500 raw records, live `XLOOKUP`, `IFS`, `SUMIFS`, `COUNTIFS`, `MAXIFS`, `AVERAGEIF` formulas, Pivot matrices, an Executive KPI Dashboard, and an interactive What-If Mitigation Simulator).
3. **Tableau Desktop** (8 pre-computed Tableau view CSV exports in `tableau/tableau_data/` + a comprehensive step-by-step build guide in `tableau/Tableau_Dashboard_Build_Guide.docx` for constructing 5 interactive dark-navy SOC dashboards).

### Key Analytical Questions Answered
- **Authentication & Brute-Force Threats:** Which accounts and departments face repeated failed login attempts, rapid brute-force bursts, and graveyard-hour (`00:00–04:59`) anomalies?
- **IP Threat Intelligence:** Which source IP addresses, anonymizer networks (`Tor Exit Nodes`, `Anonymous Proxies`), and countries originate the highest density of failed logins and network probes?
- **Network Perimeter Anomalies:** Which IPs conduct `Port Scan` and `Repeated Connection Attempt` probes against SSH (`22`) and RDP (`3389`), or trigger high-volume outbound data transfers (`> 50 MB`)?
- **Financial Fraud Exposure (INR):** How much Indian Rupee (`INR`) transaction value is exposed to `Suspicious` transactions and high-risk IP addresses across `Wire Transfer`, `RTGS`, and `Corporate Card` rails?
- **SOC Alert Triage & User Risk Ranking:** What is the Mean Time To Resolve (`MTTR`) across `Critical`, `High`, `Medium`, and `Low` alerts, and which employees rank highest on the 0–100 composite risk score?

---

## 2. Software Requirements

| Software Component | Required Version | Purpose in CyberShield |
|---|---|---|
| **MySQL Server & MySQL Workbench** | **MySQL 8.0+** | Hosting `cybershield_db`, executing scripts `01` to `14`, and serving the 8 SQL views |
| **Microsoft Excel** | **Excel 2021 / Microsoft 365** | Opening `CyberShield_Security_Analytics.xlsx` (supports `XLOOKUP`, `IFS`, `MAXIFS`) |
| **Tableau Desktop** | **Tableau Desktop 2022.1+** | Building the 5 interactive dashboards from MySQL views or `tableau/tableau_data/*.csv` |
| **Microsoft Word** | **Word 2019 / 365** | Viewing `Project_Report.docx`, `Tableau_Dashboard_Build_Guide.docx`, `SQL_Query_Documentation.docx`, and `Viva_Questions.docx` |

---

## 3. Complete Project Folder Structure

```text
CyberShield/
│
├── datasets/                                   # 7 Relational Synthetic CSV Datasets (118,500 rows)
│   ├── users.csv                               # 5,000 organizational user accounts
│   ├── ip_addresses.csv                        # 500 synthetic IP intelligence records
│   ├── login_logs.csv                          # 50,000 authentication events
│   ├── network_events.csv                      # 20,000 firewall/IDS network flow events
│   ├── transactions.csv                        # 10,000 financial transactions in INR
│   ├── security_alerts.csv                     # 3,000 SIEM security alerts
│   └── user_sessions.csv                       # 30,000 authenticated user sessions
│
├── sql/                                        # 14 Sequential MySQL 8.0 Scripts (35 Queries + 8 Views)
│   ├── 01_create_database.sql
│   ├── 02_create_tables.sql
│   ├── 03_create_constraints_indexes.sql
│   ├── 04_import_csv_data.sql
│   ├── 05_data_validation.sql
│   ├── 06_data_cleaning.sql
│   ├── 07_exploratory_analysis.sql
│   ├── 08_login_attack_analysis.sql
│   ├── 09_ip_threat_analysis.sql
│   ├── 10_network_analysis.sql
│   ├── 11_fraud_analysis.sql
│   ├── 12_advanced_sql_analysis.sql
│   ├── 13_create_views.sql
│   └── 14_kpi_summary.sql
│
├── excel/                                      # 4 Populated Microsoft Excel Workbooks
│   ├── CyberShield_Security_Analytics.xlsx     # Main 17-sheet analytical & dashboard workbook
│   ├── Data_Dictionary.xlsx                    # 57-column relational data dictionary & FK map
│   ├── Dataset_Quality_Report.xlsx             # 10-rule automated validation & quality audit
│   └── Synthetic_Scenario_Reference.xlsx       # Ground-truth catalog of 7 injected attack scenarios
│
├── tableau/                                    # Tableau Desktop Data Exports & Build Specification
│   ├── tableau_data/                           # 8 Pre-exported SQL View CSVs for Tableau Desktop
│   │   ├── vw_daily_security_kpis.csv          # 181 daily rows
│   │   ├── vw_login_analysis.csv               # 50,000 enriched login rows
│   │   ├── vw_ip_threat_summary.csv            # 500 per-IP summary rows
│   │   ├── vw_user_risk_scores.csv             # 5,000 user risk model rows
│   │   ├── vw_transaction_fraud_analysis.csv   # 10,000 enriched transaction rows (INR)
│   │   ├── vw_network_threat_analysis.csv      # 20,000 enriched network event rows
│   │   ├── vw_security_alert_summary.csv       # 3,000 enriched SIEM alert rows
│   │   └── vw_hourly_attack_trends.csv         # 168 (7x24) hour-by-day attack matrix rows
│   ├── Tableau_Dashboard_Build_Guide.docx      # Step-by-step guide for all 5 Tableau dashboards
│   └── dashboard_screenshots/                  # Folder for exported Tableau dashboard images
│
├── documentation/                              # Academic Submission Documentation
│   ├── Project_Report.docx                     # 28-section MCA Academic Project Report
│   ├── SQL_Query_Documentation.docx            # Reference guide for all 14 scripts & 35 queries
│   ├── Viva_Questions.docx                     # 55 Viva-Voce questions & detailed answers
│   ├── Project_Architecture.png                # High-res 4-stage system architecture diagram
│   └── README.md                               # Copy of this beginner documentation guide
│
├── screenshots/                                # Evidence Folders for Academic Demonstration
│   ├── mysql_execution/
│   ├── excel_dashboard/
│   └── tableau_dashboard/
│
└── README.md                                   # Master Project Guide
```

---

## 4. Dataset Descriptions & Verified Statistics

All seven datasets cover **January 1, 2026 (`2026-01-01 00:00:00`) to June 30, 2026 (`2026-06-30 23:59:59`)** with **zero missing required values, zero duplicate primary keys, and 100% foreign-key referential integrity**:

| # | Dataset File | Exact Rows | Primary Key | Foreign Keys | Key Verified Metrics |
|---:|---|---:|---|---|---|
| 1 | `users.csv` | **5,000** | `user_id` (`USR00001..USR05000`) | None (Master) | 7 Departments (`Finance`, `IT`, `HR`, `Marketing`, `Operations`, `Administration`, `Customer Support`); 4 Account Types |
| 2 | `ip_addresses.csv` | **500** | `ip_id` (`IP0001..IP0500`) | None (Master) | **360 Normal** (score 2–29), **90 Suspicious** (score 30–69), **50 High-Risk** (score 70–98) |
| 3 | `login_logs.csv` | **50,000** | `login_id` (`LGN000001..LGN050000`) | `user_id`, `ip_id` | **39,505 Success** (`79.01%`), **10,495 Failed** (`20.99%`) |
| 4 | `network_events.csv` | **20,000** | `event_id` (`NET000001..NET020000`) | `ip_id` | 16,000 Baseline + 2,000 Port Scans/Probes + 2,000 High-Volume Spikes (`5 MB–120 MB`) |
| 5 | `transactions.csv` | **10,000** | `transaction_id` (`TXN000001..TXN010000`) | `user_id`, `ip_id` | Total Value: **INR 93,05,72,473.86**; **1,800 Suspicious** totaling **INR 74,61,52,558.32** |
| 6 | `security_alerts.csv` | **3,000** | `alert_id` (`ALT000001..ALT003000`) | `user_id`, `ip_id` | **400 Critical**, **807 High**, **997 Medium**, **796 Low**; **1,936 Resolved** (`MTTR = 206.55 mins`), **1,064 Open** |
| 7 | `user_sessions.csv` | **30,000** | `session_id` (`SES000001..SES030000`) | `user_id`, `login_id` | 30,000 sessions matched 1:1 to valid successful logins (`duration_minutes` 5–240) |
| | **TOTAL** | **118,500** | | | **100% Relationally Validated** |

---

## 5. Step-by-Step Guide: Importing CSV Files & Running SQL in MySQL Workbench 8.0

### Step 5.1: Enable `local_infile` in MySQL Workbench 8.0
Because `04_import_csv_data.sql` uses high-speed `LOAD DATA LOCAL INFILE` to import all 118,500 rows in seconds, enable local file loading once:
1. Open **MySQL Workbench 8.0**.
2. On the home screen, right-click your **Local instance MySQL80** connection tile and click **Edit Connection...**.
3. Switch to the **Advanced** tab.
4. In the **Others:** text box at the bottom, add the following line on its own row:
   ```text
   OPT_LOCAL_INFILE=1
   ```
5. Click **Close**, then open the connection and run:
   ```sql
   SET GLOBAL local_infile = 1;
   ```

### Step 5.2: Execute the 14 SQL Scripts in Exact Order
In MySQL Workbench, use **File -> Open SQL Script...** and execute the scripts inside `D:\BA Project\CyberShield\sql\` in this exact sequence (click the lightning bolt icon to run each script):

1. **`01_create_database.sql`** — Creates `cybershield_db` with `utf8mb4_0900_ai_ci` encoding.
2. **`02_create_tables.sql`** — Creates all 7 InnoDB tables (`users`, `ip_addresses`, `login_logs`, `network_events`, `transactions`, `security_alerts`, `user_sessions`).
3. **`03_create_constraints_indexes.sql`** — Adds 9 Foreign Keys, 11 `CHECK` constraints, and 16 analytical indexes.
4. **`04_import_csv_data.sql`** — Bulk-imports all 7 CSV files from `D:/BA Project/CyberShield/datasets/` and verifies that total rows equal **118,500**. *(Note: If you move the project folder to a different drive/path, update the `D:/BA Project/CyberShield/datasets/` path in `04_import_csv_data.sql` using forward slashes `/`.)*
5. **`05_data_validation.sql`** — Runs 5 multi-table audit queries confirming **0 duplicate PKs, 0 missing required fields, 0 orphan FKs, and 0 invalid timestamps**.
6. **`06_data_cleaning.sql`** — Runs non-destructive standardization (`TRIM`, casing, `NULL` resolution times for open alerts) and outputs the **Before vs. After** row count reconciliation table.
7. **`07_exploratory_analysis.sql`** — Executes Queries **Q01–Q06** (total logins, status breakdown, daily trends, country & department EDA, weekday vs. weekend).
8. **`08_login_attack_analysis.sql`** — Executes Queries **Q07–Q12** (top 10 failed-login IPs, repeated failures, graveyard hours `00:00–04:59`, multi-IP users, brute-force bursts).
9. **`09_ip_threat_analysis.sql`** — Executes Queries **Q13–Q16** (multi-domain suspicious IPs, persistent IP-user pairs, IP risk distribution, Tor/Proxy contribution).
10. **`10_network_analysis.sql`** — Executes Queries **Q17–Q20** (severity disposition, port scan probes, `>50 MB` outbound transfers, protocol risk).
11. **`11_fraud_analysis.sql`** — Executes Queries **Q21–Q24** (high-value INR anomalies `>3x` normal average, high-risk IP transactions, payment rail exposure, top 20 users by fraud exposure).
12. **`12_advanced_sql_analysis.sql`** — Executes Queries **Q25–Q32** (5-factor user risk model with `ROW_NUMBER`/`RANK`/`DENSE_RANK`, cumulative running totals, `LAG` Month-over-Month changes, consecutive failed login streaks, MTTR, hourly attack distribution).
13. **`13_create_views.sql`** — Creates the 8 analytical views (`vw_ip_threat_summary`, `vw_user_risk_scores`, `vw_daily_security_kpis`, `vw_login_analysis`, `vw_transaction_fraud_analysis`, `vw_network_threat_analysis`, `vw_security_alert_summary`, `vw_hourly_attack_trends`).
14. **`14_kpi_summary.sql`** — Executes Queries **Q33–Q35** (consolidated executive KPI scorecard, user risk tier distribution, and view row-count verification).

---

## 6. How to Open & Use the Microsoft Excel Workbook

1. Navigate to `D:\BA Project\CyberShield\excel\` and open **`CyberShield_Security_Analytics.xlsx`** in Microsoft Excel.
2. Click **Enable Editing** if prompted by Protected View.
3. Explore the **17 Worksheets** in order:
   - **`Read Me`**: Navigation directory of all 17 tabs.
   - **`Raw Users` to `Raw User Sessions` (Sheets 2–8)**: All 118,500 records embedded directly inside the workbook.
   - **`Data Cleaning` (Sheet 9)**: Live `COUNTA`, `COUNTBLANK`, `COUNTIF`, and `IF` audit checks across all 7 raw sheets.
   - **`Login Analysis`, `IP Analysis`, `Network Analysis`, `User Risk Analysis`, `Fraud Analysis` (Sheets 10–14)**: Domain analytics powered by live `COUNTIF`, `COUNTIFS`, `SUMIF`, `SUMIFS`, `AVERAGEIF`, `MAXIFS`, `XLOOKUP`, `IFS`, and `ROUND` formulas.
   - **`Pivot Analysis` (Sheet 15)**: Cross-tabulated matrices (Alert Type × Severity and Department × User Risk Tier).
   - **`KPI Dashboard` (Sheet 16)**: Executive Security Command Center displaying the 6 KPI Cards and monthly/country/hourly chart tables.
   - **`What-If Analysis` (Sheet 17)**: Change the **Simulated Target Setting** percentages in cells **`C5:C8`** (e.g., change MFA coverage from `65%` to `80%`) and watch the projected reductions in Failed Logins, Network Incidents, Suspicious INR Exposure, and MTTR recalculate live!
4. To force a full formula recalculation at any time in Excel, press **`Ctrl + Alt + F9`**.

---

## 7. How to Connect Tableau Desktop & Build the 5 Dashboards

Full worksheet-by-worksheet instructions are documented in **`D:\BA Project\CyberShield\tableau\Tableau_Dashboard_Build_Guide.docx`**. Below is the quick-start workflow:

### Option A: Connect Tableau to MySQL 8.0 Views (Live Database)
1. Open **Tableau Desktop** -> under **Connect -> To a Server**, click **MySQL**.
2. Enter Server: `localhost`, Port: `3306`, Database: `cybershield_db`, Username: `root`, and your password, then click **Sign In**.
3. Drag any of the 8 views (`vw_daily_security_kpis`, `vw_login_analysis`, `vw_ip_threat_summary`, `vw_user_risk_scores`, `vw_transaction_fraud_analysis`, `vw_network_threat_analysis`, `vw_security_alert_summary`, `vw_hourly_attack_trends`) onto the canvas.

### Option B: Connect Tableau to the Pre-Exported View CSVs (No Database Required)
1. Open **Tableau Desktop** -> under **Connect -> To a File**, click **Text file**.
2. Navigate to **`D:\BA Project\CyberShield\tableau\tableau_data\`** and select `vw_daily_security_kpis.csv` (or any of the other 7 CSV files in that folder).
3. Follow Section 2 and Section 4 of `Tableau_Dashboard_Build_Guide.docx` to create the 8 Calculated Fields and assemble:
   - **Dashboard 1:** Executive Security Overview
   - **Dashboard 2:** Login & Identity Threat Intelligence
   - **Dashboard 3:** IP Threat Intelligence & Network Monitoring
   - **Dashboard 4:** Financial Fraud Analytics (INR)
   - **Dashboard 5:** Security Alerts & Risk Intelligence

---

## 8. How to Capture Screenshots for Your MCA Report & Presentation

Save your execution screenshots into the pre-created folders under `D:\BA Project\CyberShield\screenshots\`:
1. **MySQL Screenshots (`screenshots/mysql_execution/`)**: Run `04_import_csv_data.sql` (row count union query), `05_data_validation.sql`, `12_advanced_sql_analysis.sql` (Query 25 user risk ranking), and `14_kpi_summary.sql` (Query 33 executive scorecard). Press `Win + Shift + S` to capture the query + result grid and save as PNG files.
2. **Excel Screenshots (`screenshots/excel_dashboard/`)**: Open `CyberShield_Security_Analytics.xlsx`, navigate to `KPI Dashboard`, `User Risk Analysis`, `Fraud Analysis`, and `What-If Analysis`, zoom to `90%–100%`, and capture screenshots.
3. **Tableau Screenshots (`screenshots/tableau_dashboard/` and `tableau/dashboard_screenshots/`)**: In Tableau Desktop, open each of the 5 dashboards and click **Dashboard -> Export Image...** to save crisp PNG exports.

---

## 9. Common Errors & Troubleshooting Solutions

| Error / Issue | Cause | Step-by-Step Solution |
|---|---|---|
| **`ERROR 3948 (42000): Loading local data is disabled`** | MySQL 8.0 disables `LOAD DATA LOCAL INFILE` by default. | Run `SET GLOBAL local_infile = 1;` in Workbench AND add `OPT_LOCAL_INFILE=1` under **Edit Connection -> Advanced -> Others**. |
| **`ERROR 2 (HY000): File 'D:/BA Project/.../users.csv' not found`** | Project folder was moved to another path or backslashes `\` were used. | Edit `04_import_csv_data.sql` and replace `D:/BA Project/CyberShield/datasets/` with your exact folder path using forward slashes `/`. |
| **`ERROR 1452: Cannot add or update a child row: a foreign key constraint fails`** | Child table (`login_logs`, `user_sessions`) was imported before parent table (`users`, `ip_addresses`). | Always import in the exact order in `04_import_csv_data.sql`: `users` -> `ip_addresses` -> `login_logs` -> `network_events` -> `transactions` -> `security_alerts` -> `user_sessions`. |
| **Excel shows `#NAME?` on `XLOOKUP` or `IFS`** | Workbook opened in an older Excel version prior to Excel 2019/2021. | Open in **Microsoft 365 / Excel 2021+**, or use the cached formula values already embedded in every cell. |
| **Tableau shows incorrect Failed Login Rate when using `AVG`** | Averaging daily percentages weights low-volume days equally to high-volume days. | Always use the aggregate ratio formula: `SUM(IF [status] = 'Failed' THEN 1 ELSE 0 END) / COUNT([login_id])`. |

