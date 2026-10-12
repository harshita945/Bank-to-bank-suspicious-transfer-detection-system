"""
Bank-to-Bank Suspicious Transaction Detection System
Flask Main Application Module.

Provides authentication, transaction management, real-time hybrid risk detection,
alerts management, operational dashboards, Chart.js analytics, and CSV exports.
"""

import csv
from datetime import datetime, timedelta
from functools import wraps
import io
import json
import logging
import secrets
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, Response, abort
)
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
import database as db
from detection import evaluate_transaction, detect_circular_transfers

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# Ensure session secret key is set
app.secret_key = Config.SECRET_KEY


# ==============================================================
# Helper & Security Decorators
# ==============================================================

def generate_csrf_token():
    """Generate or retrieve a CSRF token for the active session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(24)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf_token


def verify_csrf_token():
    """Verify CSRF token for state-modifying requests."""
    token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
    if not token or token != session.get("_csrf_token"):
        abort(400, description="Invalid or missing CSRF token.")


def login_required(f):
    """Ensure user is logged in before accessing protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Ensure user has admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        if session.get("user_role") != "admin":
            flash("Unauthorized: Administrator privileges required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function


def log_audit(action, details=None):
    """Record an audit trail log in the database."""
    try:
        user_id = session.get("user_id")
        ip = request.remote_addr
        db.query_db(
            "INSERT INTO audit_logs (user_id, action, details, ip_address, created_at) "
            "VALUES (%s, %s, %s, %s, NOW())",
            (user_id, action, details, ip),
            commit=True
        )
    except Exception as e:
        logger.warning("Failed to record audit log: %s", e)


# ==============================================================
# Authentication Routes
# ==============================================================

@app.route("/")
def index():
    """Landing route: redirects to dashboard or login."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login with secure password verification."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        verify_csrf_token()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html")

        try:
            user = db.query_db(
                "SELECT * FROM users WHERE username = %s AND is_active = 1",
                (username,),
                one=True
            )

            if user and check_password_hash(user["password_hash"], password):
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["full_name"] = user["full_name"]
                session["user_role"] = user["role"]
                session.permanent = True

                log_audit("USER_LOGIN", f"User {username} successfully logged in.")
                flash(f"Welcome back, {user['full_name']}! Signed in as {user['role'].upper()}.", "success")
                next_page = request.args.get("next")
                return redirect(next_page or url_for("dashboard"))
            else:
                flash("Invalid credentials. Please verify your username and password.", "danger")
        except Exception as e:
            logger.error("Login database error: %s", e)
            flash(f"Database error: {str(e)}. Please check MySQL connection in .env.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Clear session and log out."""
    log_audit("USER_LOGOUT", f"User {session.get('username')} logged out.")
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("login"))


# ==============================================================
# Dashboard & Analytics Routes
# ==============================================================

@app.route("/dashboard")
@login_required
def dashboard():
    """Main operational dashboard for monitoring transactions and alerts."""
    try:
        # 1. Metric counters
        stats = {
            "total_tx": 0,
            "total_amount": 0.0,
            "suspicious_count": 0,
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0,
            "pending_alerts": 0
        }

        # Query summary totals
        summary_query = """
            SELECT 
                COUNT(*) as total_tx,
                COALESCE(SUM(amount), 0) as total_amount
            FROM transactions
        """
        row_sum = db.query_db(summary_query, one=True)
        if row_sum:
            stats["total_tx"] = row_sum["total_tx"]
            stats["total_amount"] = float(row_sum["total_amount"])

        # Query risk distribution from analysis results
        risk_query = """
            SELECT risk_category, COUNT(*) as cnt
            FROM transaction_analysis_results
            GROUP BY risk_category
        """
        risk_rows = db.query_db(risk_query)
        for r in risk_rows:
            cat = r["risk_category"]
            if cat == "HIGH":
                stats["high_risk"] = r["cnt"]
            elif cat == "MEDIUM":
                stats["medium_risk"] = r["cnt"]
            elif cat == "LOW":
                stats["low_risk"] = r["cnt"]

        stats["suspicious_count"] = stats["high_risk"] + stats["medium_risk"]

        # Pending alerts count
        alert_count_row = db.query_db(
            "SELECT COUNT(*) as pending FROM suspicious_alerts WHERE status IN ('PENDING_REVIEW', 'UNDER_INVESTIGATION')",
            one=True
        )
        if alert_count_row:
            stats["pending_alerts"] = alert_count_row["pending"]

        # 2. Recent transactions (latest 8)
        recent_tx_query = """
            SELECT 
                t.id, t.transaction_ref, t.amount, t.transaction_time, t.status,
                sa.account_number as sender_acc, sb.bank_code as sender_bank,
                ra.account_number as receiver_acc, rb.bank_code as receiver_bank,
                tar.risk_score, tar.risk_category
            FROM transactions t
            JOIN accounts sa ON t.sender_account_id = sa.id
            JOIN banks sb ON sa.bank_id = sb.id
            JOIN accounts ra ON t.receiver_account_id = ra.id
            JOIN banks rb ON ra.bank_id = rb.id
            LEFT JOIN transaction_analysis_results tar ON t.id = tar.transaction_id
            ORDER BY t.transaction_time DESC, t.id DESC
            LIMIT 8
        """
        recent_transactions = db.query_db(recent_tx_query)

        # 3. Recent unresolved alerts (latest 6)
        recent_alerts_query = """
            SELECT 
                a.id, a.alert_ref, a.risk_level, a.detection_reason, a.status, a.created_at,
                t.transaction_ref, t.amount
            FROM suspicious_alerts a
            JOIN transactions t ON a.transaction_id = t.id
            ORDER BY a.created_at DESC
            LIMIT 6
        """
        recent_alerts = db.query_db(recent_alerts_query)

        return render_template(
            "dashboard.html",
            stats=stats,
            recent_transactions=recent_transactions,
            recent_alerts=recent_alerts
        )

    except Exception as e:
        logger.error("Dashboard error: %s", e)
        flash(f"Error loading dashboard: {str(e)}. Ensure MySQL is running and schema is imported.", "danger")
        return render_template("dashboard.html", stats={}, recent_transactions=[], recent_alerts=[])


@app.route("/admin")
@admin_required
def admin_dashboard():
    """Dedicated administrative overview with system configuration and logs."""
    try:
        users = db.query_db("SELECT id, username, email, full_name, role, is_active, created_at FROM users ORDER BY id ASC")
        banks = db.query_db("SELECT * FROM banks ORDER BY id ASC")
        accounts_count = db.query_db("SELECT COUNT(*) as total FROM accounts", one=True)["total"]
        audit_logs = db.query_db(
            "SELECT al.*, u.username FROM audit_logs al LEFT JOIN users u ON al.user_id = u.id ORDER BY al.created_at DESC LIMIT 15"
        )

        thresholds = {
            "high_amount": Config.HIGH_AMOUNT_THRESHOLD,
            "velocity_window": Config.VELOCITY_WINDOW_MINUTES,
            "velocity_count": Config.VELOCITY_COUNT_THRESHOLD,
            "structuring_lower": Config.STRUCTURING_LOWER_BOUND,
            "structuring_upper": Config.STRUCTURING_UPPER_BOUND,
            "rapid_forward_window": Config.RAPID_FORWARD_WINDOW_MINUTES,
            "circular_depth": Config.CIRCULAR_DEPTH_LIMIT
        }

        return render_template(
            "admin.html",
            users=users,
            banks=banks,
            accounts_count=accounts_count,
            audit_logs=audit_logs,
            thresholds=thresholds
        )
    except Exception as e:
        logger.error("Admin dashboard error: %s", e)
        flash(f"Admin error: {str(e)}", "danger")
        return redirect(url_for("dashboard"))


# ==============================================================
# Transaction Management & Execution
# ==============================================================

@app.route("/transactions")
@login_required
def transactions():
    """Searchable, filterable, and paginated transaction history."""
    search = request.args.get("search", "").strip()
    bank_filter = request.args.get("bank", "").strip()
    risk_filter = request.args.get("risk", "").strip()
    status_filter = request.args.get("status", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    page = max(1, int(request.args.get("page", 1)))
    per_page = 15
    offset = (page - 1) * per_page

    where_clauses = ["1=1"]
    params = []

    if search:
        where_clauses.append("(t.transaction_ref LIKE %s OR sa.account_number LIKE %s OR ra.account_number LIKE %s OR sa.account_holder_name LIKE %s)")
        like_term = f"%{search}%"
        params.extend([like_term, like_term, like_term, like_term])

    if bank_filter:
        where_clauses.append("(sb.bank_code = %s OR rb.bank_code = %s)")
        params.extend([bank_filter, bank_filter])

    if risk_filter:
        where_clauses.append("tar.risk_category = %s")
        params.append(risk_filter)

    if status_filter:
        where_clauses.append("t.status = %s")
        params.append(status_filter)

    if date_from:
        where_clauses.append("DATE(t.transaction_time) >= %s")
        params.append(date_from)

    if date_to:
        where_clauses.append("DATE(t.transaction_time) <= %s")
        params.append(date_to)

    where_sql = " AND ".join(where_clauses)

    count_sql = f"""
        SELECT COUNT(*) as total
        FROM transactions t
        JOIN accounts sa ON t.sender_account_id = sa.id
        JOIN banks sb ON sa.bank_id = sb.id
        JOIN accounts ra ON t.receiver_account_id = ra.id
        JOIN banks rb ON ra.bank_id = rb.id
        LEFT JOIN transaction_analysis_results tar ON t.id = tar.transaction_id
        WHERE {where_sql}
    """
    total_records = db.query_db(count_sql, tuple(params), one=True)["total"]
    total_pages = max(1, (total_records + per_page - 1) // per_page)

    query = f"""
        SELECT 
            t.id, t.transaction_ref, t.amount, t.transaction_time, t.status, t.description,
            sa.account_number as sender_acc, sa.account_holder_name as sender_name, sb.bank_code as sender_bank,
            ra.account_number as receiver_acc, ra.account_holder_name as receiver_name, rb.bank_code as receiver_bank,
            tar.risk_score, tar.risk_category, tar.rule_flags
        FROM transactions t
        JOIN accounts sa ON t.sender_account_id = sa.id
        JOIN banks sb ON sa.bank_id = sb.id
        JOIN accounts ra ON t.receiver_account_id = ra.id
        JOIN banks rb ON ra.bank_id = rb.id
        LEFT JOIN transaction_analysis_results tar ON t.id = tar.transaction_id
        WHERE {where_sql}
        ORDER BY t.transaction_time DESC, t.id DESC
        LIMIT %s OFFSET %s
    """
    params.extend([per_page, offset])
    tx_list = db.query_db(query, tuple(params))

    banks = db.query_db("SELECT bank_code, bank_name FROM banks ORDER BY bank_name ASC")

    return render_template(
        "transactions.html",
        transactions=tx_list,
        banks=banks,
        current_page=page,
        total_pages=total_pages,
        total_records=total_records,
        search=search,
        bank_filter=bank_filter,
        risk_filter=risk_filter,
        status_filter=status_filter,
        date_from=date_from,
        date_to=date_to
    )


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    """
    Transaction entry form. Validates inputs, executes financial updates,
    and invokes the hybrid ML + rule detection engine.
    """
    accounts = db.query_db("""
        SELECT a.id, a.account_number, a.account_holder_name, a.balance, b.bank_name, b.bank_code 
        FROM accounts a 
        JOIN banks b ON a.bank_id = b.id 
        WHERE a.status = 'ACTIVE' 
        ORDER BY b.bank_name, a.account_number
    """)

    if request.method == "POST":
        verify_csrf_token()

        sender_id = request.form.get("sender_account_id")
        receiver_id = request.form.get("receiver_account_id")
        amount_str = request.form.get("amount", "").strip()
        description = request.form.get("description", "").strip()
        custom_time = request.form.get("transaction_time")

        # 1. Backend Validation
        if not sender_id or not receiver_id or not amount_str:
            flash("All fields (Sender, Receiver, and Amount) are mandatory.", "danger")
            return render_template("transfer.html", accounts=accounts)

        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be greater than zero.")
        except ValueError:
            flash("Please enter a valid positive numerical amount.", "danger")
            return render_template("transfer.html", accounts=accounts)

        if str(sender_id) == str(receiver_id):
            flash("Transfers between an account and itself are prohibited.", "danger")
            return render_template("transfer.html", accounts=accounts)

        # Parse transaction timestamp
        if custom_time:
            try:
                tx_time = datetime.fromisoformat(custom_time)
            except ValueError:
                tx_time = datetime.now()
        else:
            tx_time = datetime.now()

        try:
            # 2. Retrieve sender and receiver details
            sender_acc = db.query_db("SELECT * FROM accounts WHERE id = %s", (sender_id,), one=True)
            receiver_acc = db.query_db("SELECT * FROM accounts WHERE id = %s", (receiver_id,), one=True)

            if not sender_acc or not receiver_acc:
                flash("Selected account records could not be found.", "danger")
                return render_template("transfer.html", accounts=accounts)

            if sender_acc["balance"] < amount:
                flash(f"Insufficient funds in sender account {sender_acc['account_number']}. Available: INR {sender_acc['balance']:,.2f}.", "danger")
                return render_template("transfer.html", accounts=accounts)

            # Generate unique reference
            tx_ref = f"TXN-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3).upper()}"

            # 3. Retrieve Historical Context for Detection Engine
            sender_history = db.query_db(
                "SELECT id, amount, transaction_time, receiver_account_id FROM transactions "
                "WHERE sender_account_id = %s ORDER BY transaction_time DESC LIMIT 25",
                (sender_id,)
            )

            # Recent transactions across system for circular graph analysis & velocity
            cutoff_48h = tx_time - timedelta(hours=48)
            recent_transactions = db.query_db(
                "SELECT t.amount, t.transaction_time, t.sender_account_id, t.receiver_account_id, "
                "sa.account_number as sender_account_number, ra.account_number as receiver_account_number "
                "FROM transactions t "
                "JOIN accounts sa ON t.sender_account_id = sa.id "
                "JOIN accounts ra ON t.receiver_account_id = ra.id "
                "WHERE t.transaction_time >= %s",
                (cutoff_48h,)
            )

            candidate_tx = {
                "transaction_ref": tx_ref,
                "sender_account_id": sender_id,
                "receiver_account_id": receiver_id,
                "sender_account_number": sender_acc["account_number"],
                "receiver_account_number": receiver_acc["account_number"],
                "sender_bank_id": sender_acc["bank_id"],
                "receiver_bank_id": receiver_acc["bank_id"],
                "amount": amount,
                "transaction_time": tx_time
            }

            # 4. Invoke Hybrid Detection Engine
            detection_result = evaluate_transaction(
                candidate_tx=candidate_tx,
                sender_history=sender_history,
                recent_transactions=recent_transactions
            )

            risk_score = detection_result["risk_score"]
            risk_category = detection_result["risk_category"]
            rule_flags = detection_result["rule_flags"]
            ml_prob = detection_result["ml_probability"]
            reasons = detection_result["reasons"]
            circular_path = detection_result["circular_path"]
            recommendation = detection_result["recommendation"]

            tx_status = "FLAGGED" if risk_category in ["HIGH", "MEDIUM"] else "COMPLETED"

            # 5. Persist Transaction & Balances (Atomic DB Transaction)
            with db.get_db_cursor(commit=True) as (conn, cursor):
                # Update balances
                cursor.execute("UPDATE accounts SET balance = balance - %s WHERE id = %s", (amount, sender_id))
                cursor.execute("UPDATE accounts SET balance = balance + %s WHERE id = %s", (amount, receiver_id))

                # Insert transaction
                cursor.execute(
                    """
                    INSERT INTO transactions 
                    (transaction_ref, sender_account_id, receiver_account_id, amount, transaction_time, status, description, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    """,
                    (tx_ref, sender_id, receiver_id, amount, tx_time, tx_status, description or "Interbank Transfer")
                )
                tx_id = cursor.lastrowid

                # Insert analysis results
                reasons_text = "\n".join(reasons)
                cursor.execute(
                    """
                    INSERT INTO transaction_analysis_results
                    (transaction_id, risk_score, risk_category, rule_flags, ml_probability, explanation, recommendation, analyzed_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    """,
                    (tx_id, risk_score, risk_category, json.dumps(rule_flags), ml_prob, reasons_text, recommendation)
                )

                # Generate alert if MEDIUM or HIGH risk
                if risk_category in ["HIGH", "MEDIUM"]:
                    alert_ref = f"ALT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}"
                    primary_reason = reasons[0] if reasons else "Elevated risk indicators detected."
                    cursor.execute(
                        """
                        INSERT INTO suspicious_alerts
                        (alert_ref, transaction_id, risk_level, detection_reason, status, admin_remarks, created_at)
                        VALUES (%s, %s, %s, %s, 'PENDING_REVIEW', NULL, NOW())
                        """,
                        (alert_ref, tx_id, risk_category, primary_reason)
                    )

            log_audit("TRANSACTION_CREATED", f"Created transaction {tx_ref} (INR {amount:,.2f}), Risk: {risk_category} ({risk_score})")

            return redirect(url_for("analysis_result", tx_id=tx_id))

        except Exception as e:
            logger.error("Transaction processing error: %s", e)
            flash(f"Transfer failed: {str(e)}", "danger")
            return render_template("transfer.html", accounts=accounts)

    return render_template("transfer.html", accounts=accounts)


@app.route("/transfer/preset/<scenario_id>", methods=["POST"])
@login_required
def transfer_preset(scenario_id):
    """
    Demonstration Trigger: Executes predefined academic test scenarios
    illustrating standard patterns, structuring, velocity, circular transfer, etc.
    """
    verify_csrf_token()
    now = datetime.now()

    # Retrieve accounts ACC-1001 through ACC-1004
    accs = db.query_db("SELECT id, account_number, balance FROM accounts ORDER BY id ASC LIMIT 5")
    if len(accs) < 4:
        flash("Not enough demo accounts available in the database to run presets.", "danger")
        return redirect(url_for("transfer"))

    a1, a2, a3, a4 = accs[0], accs[1], accs[2], accs[3]

    try:
        if scenario_id == "normal":
            # Scenario 1: Normal transaction
            data = {"sender_id": a1["id"], "receiver_id": a2["id"], "amount": 8500.00, "desc": "Standard invoice payment"}
            _execute_transfer_direct(data["sender_id"], data["receiver_id"], data["amount"], now, data["desc"])
            flash("Demonstration: Executed Normal Transaction (INR 8,500).", "success")

        elif scenario_id == "high_value":
            # Scenario 2: Unusually high-value transaction
            data = {"sender_id": a2["id"], "receiver_id": a3["id"], "amount": 350000.00, "desc": "Large high-value settlement"}
            _execute_transfer_direct(data["sender_id"], data["receiver_id"], data["amount"], now, data["desc"])
            flash("Demonstration: Executed High-Value Transaction (INR 350,000).", "warning")

        elif scenario_id == "structuring":
            # Scenario 3: Structuring transfers (amounts just below reporting threshold)
            for i in range(2):
                amt = 48500.00 + (i * 300)
                _execute_transfer_direct(a3["id"], a4["id"], amt, now - timedelta(minutes=(15 - i * 5)), f"Structured batch transfer #{i+1}")
            flash("Demonstration: Executed Structuring Pattern (repeated ~INR 48,500 transfers).", "warning")

        elif scenario_id == "velocity":
            # Scenario 4: Frequent velocity burst (4 transactions within 10 minutes)
            for i in range(4):
                _execute_transfer_direct(a1["id"], a3["id"], 25000.00, now - timedelta(minutes=(10 - i * 2)), f"Rapid velocity transfer #{i+1}")
            flash("Demonstration: Executed High-Velocity Burst (4 transfers in 10 mins).", "warning")

        elif scenario_id == "circular":
            # Scenario 5: Circular Transfer A -> B -> C -> D -> A
            # Pre-seed links A -> B -> C -> D, then execute D -> A
            t_base = now - timedelta(minutes=40)
            _execute_transfer_direct(a1["id"], a2["id"], 100000.00, t_base, "Circular Hop 1: A -> B")
            _execute_transfer_direct(a2["id"], a3["id"], 98000.00, t_base + timedelta(minutes=10), "Circular Hop 2: B -> C")
            _execute_transfer_direct(a3["id"], a4["id"], 96000.00, t_base + timedelta(minutes=20), "Circular Hop 3: C -> D")
            last_tx_id = _execute_transfer_direct(a4["id"], a1["id"], 95000.00, now, "Circular Hop 4 (Closing Loop): D -> A")
            flash("Demonstration: Executed Circular Transfer Network (A -> B -> C -> D -> A).", "danger")
            return redirect(url_for("analysis_result", tx_id=last_tx_id))

        else:
            flash("Unknown preset scenario requested.", "secondary")

    except Exception as e:
        logger.error("Preset scenario error: %s", e)
        flash(f"Failed to execute preset scenario: {str(e)}", "danger")

    return redirect(url_for("transactions"))


def _execute_transfer_direct(sender_id, receiver_id, amount, tx_time, description):
    """Helper to execute transfers and evaluate detection atomically."""
    sender_acc = db.query_db("SELECT * FROM accounts WHERE id = %s", (sender_id,), one=True)
    receiver_acc = db.query_db("SELECT * FROM accounts WHERE id = %s", (receiver_id,), one=True)

    tx_ref = f"TXN-{tx_time.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}"

    sender_history = db.query_db(
        "SELECT id, amount, transaction_time, receiver_account_id FROM transactions "
        "WHERE sender_account_id = %s ORDER BY transaction_time DESC LIMIT 25",
        (sender_id,)
    )

    cutoff_48h = tx_time - timedelta(hours=48)
    recent_transactions = db.query_db(
        "SELECT t.amount, t.transaction_time, t.sender_account_id, t.receiver_account_id, "
        "sa.account_number as sender_account_number, ra.account_number as receiver_account_number "
        "FROM transactions t "
        "JOIN accounts sa ON t.sender_account_id = sa.id "
        "JOIN accounts ra ON t.receiver_account_id = ra.id "
        "WHERE t.transaction_time >= %s",
        (cutoff_48h,)
    )

    candidate_tx = {
        "transaction_ref": tx_ref,
        "sender_account_id": sender_id,
        "receiver_account_id": receiver_id,
        "sender_account_number": sender_acc["account_number"],
        "receiver_account_number": receiver_acc["account_number"],
        "sender_bank_id": sender_acc["bank_id"],
        "receiver_bank_id": receiver_acc["bank_id"],
        "amount": amount,
        "transaction_time": tx_time
    }

    result = evaluate_transaction(candidate_tx, sender_history, recent_transactions)
    risk_score = result["risk_score"]
    risk_category = result["risk_category"]
    rule_flags = result["rule_flags"]
    ml_prob = result["ml_probability"]
    reasons = result["reasons"]
    recommendation = result["recommendation"]

    tx_status = "FLAGGED" if risk_category in ["HIGH", "MEDIUM"] else "COMPLETED"

    with db.get_db_cursor(commit=True) as (conn, cursor):
        cursor.execute("UPDATE accounts SET balance = balance - %s WHERE id = %s", (amount, sender_id))
        cursor.execute("UPDATE accounts SET balance = balance + %s WHERE id = %s", (amount, receiver_id))

        cursor.execute(
            """
            INSERT INTO transactions 
            (transaction_ref, sender_account_id, receiver_account_id, amount, transaction_time, status, description, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """,
            (tx_ref, sender_id, receiver_id, amount, tx_time, tx_status, description)
        )
        tx_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO transaction_analysis_results
            (transaction_id, risk_score, risk_category, rule_flags, ml_probability, explanation, recommendation, analyzed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """,
            (tx_id, risk_score, risk_category, json.dumps(rule_flags), ml_prob, "\n".join(reasons), recommendation)
        )

        if risk_category in ["HIGH", "MEDIUM"]:
            alert_ref = f"ALT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}"
            cursor.execute(
                """
                INSERT INTO suspicious_alerts
                (alert_ref, transaction_id, risk_level, detection_reason, status, admin_remarks, created_at)
                VALUES (%s, %s, %s, %s, 'PENDING_REVIEW', NULL, NOW())
                """,
                (alert_ref, tx_id, risk_category, reasons[0] if reasons else "Elevated risk indicators")
            )

    return tx_id


@app.route("/transaction/<int:tx_id>")
@app.route("/analysis-result/<int:tx_id>")
@login_required
def analysis_result(tx_id):
    """Detailed transaction analysis and explainable risk breakdown page."""
    query = """
        SELECT 
            t.id, t.transaction_ref, t.amount, t.transaction_time, t.status, t.description, t.created_at,
            sa.id as sender_id, sa.account_number as sender_acc, sa.account_holder_name as sender_name,
            sb.bank_name as sender_bank_name, sb.bank_code as sender_bank_code,
            ra.id as receiver_id, ra.account_number as receiver_acc, ra.account_holder_name as receiver_name,
            rb.bank_name as receiver_bank_name, rb.bank_code as receiver_bank_code,
            tar.risk_score, tar.risk_category, tar.rule_flags, tar.ml_probability, tar.explanation, tar.recommendation
        FROM transactions t
        JOIN accounts sa ON t.sender_account_id = sa.id
        JOIN banks sb ON sa.bank_id = sb.id
        JOIN accounts ra ON t.receiver_account_id = ra.id
        JOIN banks rb ON ra.bank_id = rb.id
        LEFT JOIN transaction_analysis_results tar ON t.id = tar.transaction_id
        WHERE t.id = %s
    """
    tx = db.query_db(query, (tx_id,), one=True)
    if not tx:
        flash("Transaction not found.", "warning")
        return redirect(url_for("transactions"))

    # Parse explanation items and rule flags
    explanations = [line.strip() for line in (tx["explanation"] or "").split("\n") if line.strip()]
    try:
        flags = json.loads(tx["rule_flags"]) if tx["rule_flags"] else []
    except Exception:
        flags = []

    # Associated alert if existing
    alert = db.query_db("SELECT * FROM suspicious_alerts WHERE transaction_id = %s", (tx_id,), one=True)

    # Sender's recent transaction context
    sender_history = db.query_db(
        """
        SELECT t.transaction_ref, t.amount, t.transaction_time, t.status, ra.account_number as receiver_acc
        FROM transactions t
        JOIN accounts ra ON t.receiver_account_id = ra.id
        WHERE t.sender_account_id = %s AND t.id != %s
        ORDER BY t.transaction_time DESC LIMIT 5
        """,
        (tx["sender_id"], tx_id)
    )

    return render_template(
        "transaction_detail.html",
        tx=tx,
        explanations=explanations,
        flags=flags,
        alert=alert,
        sender_history=sender_history
    )


# ==============================================================
# Suspicious Alerts Management
# ==============================================================

@app.route("/alerts")
@login_required
def alerts():
    """Suspicious alerts review queue with filtering and status controls."""
    status_filter = request.args.get("status", "").strip()
    risk_filter = request.args.get("risk", "").strip()

    where_clauses = ["1=1"]
    params = []

    if status_filter:
        where_clauses.append("a.status = %s")
        params.append(status_filter)

    if risk_filter:
        where_clauses.append("a.risk_level = %s")
        params.append(risk_filter)

    where_sql = " AND ".join(where_clauses)

    query = f"""
        SELECT 
            a.id, a.alert_ref, a.risk_level, a.detection_reason, a.status, a.admin_remarks, a.created_at, a.reviewed_at,
            t.id as tx_id, t.transaction_ref, t.amount, t.transaction_time,
            sa.account_number as sender_acc, sb.bank_code as sender_bank,
            ra.account_number as receiver_acc, rb.bank_code as receiver_bank,
            u.username as reviewer_username
        FROM suspicious_alerts a
        JOIN transactions t ON a.transaction_id = t.id
        JOIN accounts sa ON t.sender_account_id = sa.id
        JOIN banks sb ON sa.bank_id = sb.id
        JOIN accounts ra ON t.receiver_account_id = ra.id
        JOIN banks rb ON ra.bank_id = rb.id
        LEFT JOIN users u ON a.reviewed_by = u.id
        WHERE {where_sql}
        ORDER BY 
            CASE a.status 
                WHEN 'PENDING_REVIEW' THEN 1 
                WHEN 'UNDER_INVESTIGATION' THEN 2 
                ELSE 3 
            END,
            a.created_at DESC
    """
    alert_list = db.query_db(query, tuple(params))

    return render_template(
        "alerts.html",
        alerts=alert_list,
        status_filter=status_filter,
        risk_filter=risk_filter
    )


@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
@login_required
def update_alert_status(alert_id):
    """Update review status and remarks for a suspicious alert."""
    verify_csrf_token()
    new_status = request.form.get("status")
    remarks = request.form.get("remarks", "").strip()

    allowed_statuses = ["PENDING_REVIEW", "UNDER_INVESTIGATION", "RESOLVED", "FALSE_POSITIVE"]
    if new_status not in allowed_statuses:
        flash("Invalid alert status specified.", "danger")
        return redirect(url_for("alerts"))

    try:
        user_id = session.get("user_id")
        db.query_db(
            """
            UPDATE suspicious_alerts 
            SET status = %s, admin_remarks = %s, reviewed_by = %s, reviewed_at = NOW()
            WHERE id = %s
            """,
            (new_status, remarks, user_id, alert_id),
            commit=True
        )
        log_audit("ALERT_UPDATED", f"Alert #{alert_id} status updated to {new_status} by {session.get('username')}.")
        flash(f"Alert #{alert_id} successfully updated to {new_status}.", "success")
    except Exception as e:
        logger.error("Error updating alert: %s", e)
        flash(f"Error updating alert: {str(e)}", "danger")

    return redirect(url_for("alerts"))


# ==============================================================
# Accounts Management
# ==============================================================

@app.route("/accounts")
@login_required
def accounts():
    """Display fictional demo accounts and balances across participating banks."""
    accounts_list = db.query_db("""
        SELECT 
            a.id, a.account_number, a.account_holder_name, a.account_type, a.balance, a.status, a.created_at,
            b.bank_name, b.bank_code, b.swift_ifsc
        FROM accounts a
        JOIN banks b ON a.bank_id = b.id
        ORDER BY b.bank_name, a.account_number
    """)
    banks = db.query_db("SELECT * FROM banks ORDER BY bank_name")
    return render_template("accounts.html", accounts=accounts_list, banks=banks)


# ==============================================================
# Reports & CSV Export
# ==============================================================

@app.route("/reports")
@login_required
def reports():
    """Operational reports and analytics overview."""
    # Bank-wise summary
    bank_summary = db.query_db("""
        SELECT 
            b.bank_name, b.bank_code,
            COUNT(t.id) as total_tx_count,
            COALESCE(SUM(t.amount), 0) as total_volume,
            COUNT(CASE WHEN tar.risk_category IN ('HIGH', 'MEDIUM') THEN 1 END) as flagged_count
        FROM banks b
        LEFT JOIN accounts a ON b.id = a.bank_id
        LEFT JOIN transactions t ON a.id = t.sender_account_id
        LEFT JOIN transaction_analysis_results tar ON t.id = tar.transaction_id
        GROUP BY b.id, b.bank_name, b.bank_code
        ORDER BY total_volume DESC
    """)

    # Alerts summary by status
    alert_summary = db.query_db("""
        SELECT status, COUNT(*) as cnt 
        FROM suspicious_alerts 
        GROUP BY status
    """)

    return render_template("reports.html", bank_summary=bank_summary, alert_summary=alert_summary)


@app.route("/reports/export-transactions")
@login_required
def export_transactions_csv():
    """Export transactions and risk scores into a clean CSV report."""
    query = """
        SELECT 
            t.transaction_ref, t.transaction_time, t.amount, t.status,
            sa.account_number as sender_account, sb.bank_code as sender_bank,
            ra.account_number as receiver_account, rb.bank_code as receiver_bank,
            tar.risk_score, tar.risk_category, tar.ml_probability
        FROM transactions t
        JOIN accounts sa ON t.sender_account_id = sa.id
        JOIN banks sb ON sa.bank_id = sb.id
        JOIN accounts ra ON t.receiver_account_id = ra.id
        JOIN banks rb ON ra.bank_id = rb.id
        LEFT JOIN transaction_analysis_results tar ON t.id = tar.transaction_id
        ORDER BY t.transaction_time DESC
    """
    rows = db.query_db(query)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Transaction Reference", "Date Time", "Amount (INR)", "Status",
        "Sender Account", "Sender Bank", "Receiver Account", "Receiver Bank",
        "Risk Score", "Risk Category", "ML Probability"
    ])

    for r in rows:
        writer.writerow([
            r["transaction_ref"],
            r["transaction_time"],
            f"{float(r['amount']):.2f}",
            r["status"],
            r["sender_account"],
            r["sender_bank"],
            r["receiver_account"],
            r["receiver_bank"],
            r["risk_score"] or 0,
            r["risk_category"] or "LOW",
            f"{float(r['ml_probability'] or 0):.4f}"
        ])

    log_audit("EXPORT_CSV_TRANSACTIONS", f"Exported {len(rows)} transaction records.")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=transactions_report_{datetime.now().strftime('%Y%m%d')}.csv"}
    )


@app.route("/reports/export-alerts")
@login_required
def export_alerts_csv():
    """Export suspicious alerts list to CSV."""
    query = """
        SELECT 
            a.alert_ref, a.created_at, a.risk_level, a.status, a.detection_reason, a.admin_remarks,
            t.transaction_ref, t.amount,
            sa.account_number as sender_acc, ra.account_number as receiver_acc
        FROM suspicious_alerts a
        JOIN transactions t ON a.transaction_id = t.id
        JOIN accounts sa ON t.sender_account_id = sa.id
        JOIN accounts ra ON t.receiver_account_id = ra.id
        ORDER BY a.created_at DESC
    """
    rows = db.query_db(query)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Alert Reference", "Created At", "Risk Level", "Review Status",
        "Detection Reason", "Admin Remarks", "Transaction Ref", "Amount (INR)",
        "Sender Account", "Receiver Account"
    ])

    for r in rows:
        writer.writerow([
            r["alert_ref"],
            r["created_at"],
            r["risk_level"],
            r["status"],
            r["detection_reason"],
            r["admin_remarks"] or "",
            r["transaction_ref"],
            f"{float(r['amount']):.2f}",
            r["sender_acc"],
            r["receiver_acc"]
        ])

    log_audit("EXPORT_CSV_ALERTS", f"Exported {len(rows)} alert records.")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=suspicious_alerts_report_{datetime.now().strftime('%Y%m%d')}.csv"}
    )


# ==============================================================
# Dynamic Chart.js & System Health APIs
# ==============================================================

@app.route("/api/chart-data")
@login_required
def api_chart_data():
    """API providing data points for Chart.js dashboards."""
    try:
        # 1. Risk distribution count
        risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        risk_rows = db.query_db("SELECT risk_category, COUNT(*) as cnt FROM transaction_analysis_results GROUP BY risk_category")
        for r in risk_rows:
            risk_dist[r["risk_category"]] = r["cnt"]

        # 2. Daily volume & alerts (past 7 days)
        daily_trends = []
        for i in range(6, -1, -1):
            day_dt = datetime.now() - timedelta(days=i)
            day_str = day_dt.strftime("%Y-%m-%d")
            label = day_dt.strftime("%b %d")

            count_row = db.query_db(
                "SELECT COUNT(*) as total, "
                "COUNT(CASE WHEN tar.risk_category IN ('HIGH', 'MEDIUM') THEN 1 END) as flagged "
                "FROM transactions t "
                "LEFT JOIN transaction_analysis_results tar ON t.id = tar.transaction_id "
                "WHERE DATE(t.transaction_time) = %s",
                (day_str,),
                one=True
            )
            daily_trends.append({
                "date": label,
                "total": count_row["total"] if count_row else 0,
                "flagged": count_row["flagged"] if count_row else 0
            })

        # 3. Bank-wise transaction breakdown
        bank_rows = db.query_db("""
            SELECT b.bank_code, COUNT(t.id) as tx_count, COALESCE(SUM(t.amount), 0) as volume
            FROM banks b
            LEFT JOIN accounts a ON b.id = a.bank_id
            LEFT JOIN transactions t ON a.id = t.sender_account_id
            GROUP BY b.id, b.bank_code
            ORDER BY tx_count DESC
        """)
        banks_data = [{"bank": b["bank_code"], "count": b["tx_count"], "volume": float(b["volume"])} for b in bank_rows]

        return jsonify({
            "status": "success",
            "risk_distribution": risk_dist,
            "daily_trends": daily_trends,
            "banks_data": banks_data
        })
    except Exception as e:
        logger.error("Chart data API error: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/health")
def api_health():
    """System health and database connectivity diagnostics."""
    db_connected, msg = db.test_db_connection()
    return jsonify({
        "status": "healthy" if db_connected else "degraded",
        "database_connected": db_connected,
        "database_message": msg,
        "timestamp": datetime.now().isoformat()
    })


# ==============================================================
# Error Handlers
# ==============================================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template("base.html", error_title="404 - Not Found", error_message="The requested resource was not found on this server."), 404


@app.errorhandler(400)
def bad_request_error(error):
    return render_template("base.html", error_title="400 - Bad Request", error_message=str(error.description or "Invalid request parameters.")), 400


@app.errorhandler(500)
def internal_error(error):
    return render_template("base.html", error_title="500 - Server Error", error_message="An unexpected server error occurred. Please contact the administrator."), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
