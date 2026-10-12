# Bank-to-Bank Suspicious Transaction Detection System

A web-based anti-money laundering (AML) and financial crime detection platform built for BCA Final Year Academic Project demonstration.

---

## 1. Project Abstract

In modern digital banking ecosystems, inter-bank fund transfers occur with high velocity and volume. Traditional rule-based monitoring mechanisms often fail to capture sophisticated financial crime typologies such as structuring (smurfing), high-frequency velocity bursts, multi-hop rapid fund movements, and circular laundering patterns ($A \to B \to C \to D \to A$). 

This project implements a **Hybrid Suspicious Transaction Detection System** that combines explainable heuristic rules, **NetworkX** graph cycle analysis, and a **Scikit-Learn Random Forest Classifier** to compute a transparent, explainable risk score (0 to 100) and actionable investigation alerts for banking compliance officers.

> **Academic Project Disclaimer:**  
> This system is an academic demonstration developed strictly for educational evaluation. It uses synthetic financial transactions and fictional account ledgers. It does not connect to real banking networks or process real customer financial information.

---

## 2. Problem Statement

Financial crime detection systems in banks face several critical challenges:
1. **High False Positive Rates:** Purely rule-based systems generate excessive alerts on legitimate large transactions.
2. **Detection Blindspots:** Complex relational patterns—such as circular layering where funds travel through multiple intermediary accounts and return to the originator—evade standard threshold filters.
3. **Black-Box Limitations:** Complex machine learning models often lack transparency, making it difficult for compliance officers to justify regulatory Suspicious Activity Reports (SAR).

This project addresses these challenges through a hybrid architecture combining explainable rule logic, graph network analysis, and supervised machine learning probability scoring.

---

## 3. Project Objectives

1. Develop a web-based AML monitoring application using **Python Flask** and **MySQL**.
2. Automate detection of unusual banking transaction patterns (amounts, timing, account history, velocity).
3. Detect complex financial crime typologies:
   - High-value anomalies exceeding thresholds.
   - High-velocity transaction bursts within short time windows.
   - Structuring patterns clustered just below regulatory thresholds (e.g., INR 45,000–49,999).
   - Rapid forwarding / pass-through movements across intermediate accounts.
   - Multi-hop circular fund movements ($A \to B \to C \to D \to A$) using directed graph algorithms.
4. Calculate a composite **Risk Score (0–100)** with categorized risk bands (LOW, MEDIUM, HIGH) and human-readable audit explanations.
5. Provide an interactive operations dashboard with **Chart.js** data visualizations and CSV report exports.

---

## 4. System Architecture

```
+-----------------------------------------------------------------------+
|                         Frontend Web Interface                        |
|       (HTML5, CSS3, Bootstrap 5.3, Chart.js, Vanilla JavaScript)      |
+-----------------------------------------------------------------------+
                                   |
                             HTTP / REST API
                                   |
+-----------------------------------------------------------------------+
|                          Flask Web Backend                            |
|          Session Authentication | CSRF Guard | Role Authorization     |
+-----------------------------------------------------------------------+
            |                                           |
+---------------------------+               +---------------------------+
|  Hybrid Detection Engine  |               |    MySQL 8.0 Database     |
| - Rule Heuristics Engine  |               | - Users & Audit Logs      |
| - NetworkX Graph Cycles   |               | - Participating Banks     |
| - Scikit-Learn RF Model   |               | - Accounts & Ledgers      |
| - Composite Score (0-100) |               | - Transactions & Alerts   |
+---------------------------+               +---------------------------+
```

### Risk Score Calculation Formula

The system derives the composite risk score through a weighted hybrid model:

$$\text{Composite Risk Score} = \min\Big(100, \text{round}\big(0.55 \times \text{RuleScore} + 0.45 \times (\text{ML\_Probability} \times 100)\big)\Big)$$

- **RuleScore (0–100):** Additive penalty score from triggered compliance heuristics.
- **ML_Probability (0.0–1.0):** Output from the trained Random Forest Classifier.
- **Circular Override:** If a closed directed cycle ($A \to B \to \dots \to A$) is detected via NetworkX, the score is floored at a minimum of 75 (guaranteed HIGH risk).

---

## 5. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Frontend** | HTML5, CSS3, JavaScript | User interface layout and dynamic interactions |
| **Styling** | Bootstrap 5.3.3 & Custom CSS | Dark navy financial dashboard design |
| **Charts** | Chart.js 4.4 | Trendlines, risk donuts, and volume charts |
| **Backend** | Python 3.10+ / Flask 3.1 | Core web routing, session auth, API endpoints |
| **Database** | MySQL Server 8.0+ | Relational schema, transactions, and audit trail |
| **DB Connector** | mysql-connector-python | Parameterized SQL query execution |
| **Machine Learning** | Scikit-learn (Random Forest) | Transaction feature classification |
| **Data Processing**| Pandas & NumPy | Feature matrix extraction and data modeling |
| **Graph Analytics**| NetworkX | Directed cycle detection in account transaction graphs |
| **Configuration**  | python-dotenv | Secure environment variable management |

---

## 6. Database Design & Relational Schema

The database consists of 7 normalized relational tables in `bank_detection_db`:

1. `users`: System login credentials with role-based access (`admin` vs `analyst`) and scrypt password hashes.
2. `banks`: Participating institutions (SBI, HDFC, ICICI, Axis, PNB).
3. `accounts`: Customer bank ledgers, balances, and account types (Savings, Current, Business).
4. `transactions`: Fund transfer logs with unique references and timestamps.
5. `transaction_analysis_results`: Stored risk scores, rule flags, ML probabilities, and explanation logs.
6. `suspicious_alerts`: Operational case review queue with workflow dispositions (`PENDING_REVIEW`, `UNDER_INVESTIGATION`, `RESOLVED`, `FALSE_POSITIVE`).
7. `audit_logs`: Timestamped user actions and IP records for compliance accountability.

---

## 7. Installation and Setup Instructions (Windows 11)

### Prerequisites

- **Python 3.10 or newer** installed with pip.
- **MySQL Server 8.0+** running locally (e.g. MySQL Community Server or XAMPP).
- **VS Code** (or preferred code editor).

### Step 1: Open the Project Directory

Open a terminal or PowerShell in the project directory:

```powershell
cd "c:\Users\HP\Desktop\Bank-to-bank suspicious transfer detection\Bank-to-Bank-Suspicious-Transfer-Detection-System"
```

### Step 2: (Optional) Create and Activate Virtual Environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Packages

```powershell
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables

Edit the `.env` file in the project folder with your local MySQL password:

```env
FLASK_APP=app.py
FLASK_ENV=development
FLASK_DEBUG=1
SECRET_KEY=bca_final_year_project_secure_session_key_2026_x89f

DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_actual_mysql_password_here
DB_NAME=bank_detection_db
```

### Step 5: Initialize the MySQL Database

Run the database setup script to create the schema and seed sample accounts:

```powershell
python init_db.py
```

### Step 6: Train the Machine Learning Model

Generate synthetic transaction data and train the Scikit-learn Random Forest model:

```powershell
python train_model.py
```

This creates:
- `data/sample_transactions.csv` (3,000 synthetic transaction records)
- `models/suspicious_transaction_model.joblib` (Trained classifier)
- `models/model_features.joblib` (Feature column names)

### Step 7: Run the Flask Web Application

```powershell
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 8. Safe Fictional Demo Credentials

| Role | Username | Default Password | Permissions |
|---|---|---|---|
| **Administrator** | `admin` | `Admin@123` | Full system access, Admin control panel, Threshold configs, Audit logs |
| **AML Analyst** | `analyst` | `Analyst@123` | Transaction creation, monitoring, alert queue review, CSV export |

*(Quick-click autofill buttons are provided on the login page for convenience during viva evaluation).*

---

## 9. Demonstrating Test Scenarios in Viva / Presentation

On the **"New Transfer"** page (`/transfer`), a dedicated **One-Click Demonstration Panel** is provided:

1. **Scenario 1: Normal Transaction**
   - Transfer: INR 8,500 between regular accounts.
   - Result: Risk Score 0–15 (LOW Risk). No flags.
2. **Scenario 2: Unusually High-Value Transaction**
   - Transfer: INR 350,000 exceeding the INR 200,000 threshold.
   - Result: Flagged with `HIGH_VALUE_THRESHOLD`. Risk Score elevated for human review.
3. **Scenario 3: Structuring / Smurfing Pattern**
   - Transfer: Repeated transactions of INR 48,500 clustered just under INR 50,000.
   - Result: Flagged with `STRUCTURING_PATTERN`.
4. **Scenario 4: High Velocity Burst**
   - Transfer: 4 rapid transfers within 10 minutes.
   - Result: Flagged with `HIGH_VELOCITY_BURST`.
5. **Scenario 5: Circular Transfer Loop ($A \to B \to C \to D \to A$)**
   - Transfer: Closes a multi-party fund routing chain.
   - Result: NetworkX graph cycle detected. Flagged with `CIRCULAR_TRANSFER_CYCLE`. Risk Score: 75+ (HIGH Risk). Complete visual path displayed.

---

## 10. Running Automated Tests

Run the test suites from the project directory:

```powershell
# 1. Detection Engine and Heuristics Test Suite
python tests/test_detection.py

# 2. Flask Routes and Security Isolation Test Suite
python tests/test_routes.py
```

---

## 11. Project Structure

```
Bank-to-Bank-Suspicious-Transfer-Detection-System/
│
├── app.py                      # Flask main server application & routes
├── config.py                   # Configuration & environment loader
├── database.py                 # MySQL database connector & connection pooling
├── detection.py                # Hybrid detection engine (Rules + NetworkX + ML)
├── feature_engineering.py      # Feature extraction module (Pandas / NumPy)
├── train_model.py              # ML dataset generation & training pipeline
├── init_db.py                  # Database setup & initialization utility
├── requirements.txt            # Python dependencies
├── .env.example                # Example environment variable template
├── .env                        # Local environment settings (gitignored)
├── .gitignore                  # Git exclusion rules
├── README.md                   # Comprehensive academic project documentation
│
├── database/
│   ├── schema.sql              # MySQL DDL table schema definitions
│   └── seed_data.sql           # Initial baseline bank, account, and user records
│
├── models/
│   ├── suspicious_transaction_model.joblib  # Trained Random Forest binary
│   └── model_features.joblib               # Serialized feature column names
│
├── data/
│   └── sample_transactions.csv # Synthetic transaction dataset
│
├── templates/
│   ├── base.html               # Base layout with sidebar, navbar, flash messages
│   ├── login.html              # Security login portal with demo autofill
│   ├── dashboard.html          # Operational dashboard with KPI cards & Chart.js
│   ├── admin.html              # Administrator control panel & audit logs
│   ├── transactions.html       # Searchable, filterable transactions log
│   ├── transfer.html           # Fund transfer form & viva demonstration buttons
│   ├── transaction_detail.html # Explainable risk breakdown & circular path graph
│   ├── alerts.html             # Operational alerts review & disposition queue
│   ├── accounts.html           # Participating bank accounts directory
│   └── reports.html            # Reports summary & CSV export triggers
│
├── static/
│   ├── css/
│   │   └── style.css           # Custom financial security theme styles
│   └── js/
│       └── app.js              # Chart.js rendering & client-side interactions
│
└── tests/
    ├── test_detection.py       # Unit tests for heuristics & NetworkX cycles
    └── test_routes.py          # Integration tests for routes & CSRF guards
```

---

## 12. Project Limitations & Future Scope

### Limitations
- **Academic Simulation:** Relies on synthetic transaction generation rather than confidential live banking data.
- **Synchronous Graph Traversal:** Simple cycle search is bounded by a maximum hop depth of 5 to maintain interactive response times.

### Future Scope
- Integration with distributed stream processing (e.g., Apache Kafka) for real-time high-throughput transaction pipelines.
- Deep Graph Neural Networks (GNN) for automated community detection and mule account cluster classification.
- Biometric and two-factor authentication (2FA) for compliance officer actions.

---

## 13. Project Team Contributions

- **Student Name:** [Your Name Here]
- **Roll Number / Enrolment No:** [Your Roll Number Here]
- **Course:** Bachelor of Computer Applications (BCA)
- **Institution:** [Your College / University Name Here]
- **Project Mentor / Guide:** [Guide Name Here]
