"""
Database Connection and Helper Module.
Connects to MySQL using mysql-connector-python and configuration from config.py.
Handles connection lifecycle, parameterized queries, and database initialization.
"""

import logging
from contextlib import contextmanager
import mysql.connector
from mysql.connector import errorcode
from config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_raw_connection(include_database=True):
    """
    Establish a raw connection to MySQL Server.
    
    Args:
        include_database (bool): If True, connects to the configured DB_NAME.
                                 If False, connects to the server without selecting a database.
    """
    config_dict = {
        "host": Config.DB_HOST,
        "port": Config.DB_PORT,
        "user": Config.DB_USER,
        "password": Config.DB_PASSWORD,
        "charset": "utf8mb4",
        "use_pure": True,
        "autocommit": False
    }
    if include_database:
        config_dict["database"] = Config.DB_NAME

    return mysql.connector.connect(**config_dict)


@contextmanager
def get_db_cursor(commit=False, dictionary=True):
    """
    Context manager providing a managed MySQL cursor and connection.
    Ensures safe commit/rollback and connection closing.
    
    Usage:
        with get_db_cursor(commit=True) as (conn, cursor):
            cursor.execute("SELECT ...")
    """
    conn = None
    try:
        conn = get_raw_connection(include_database=True)
        cursor = conn.cursor(dictionary=dictionary)
        try:
            yield conn, cursor
            if commit:
                conn.commit()
        except Exception:
            if conn:
                conn.rollback()
            raise
        finally:
            cursor.close()
    finally:
        if conn and conn.is_connected():
            conn.close()


def test_db_connection():
    """
    Test whether the MySQL database is reachable with current credentials.
    Returns:
        tuple (bool, str): (is_successful, message_or_error)
    """
    try:
        conn = get_raw_connection(include_database=False)
        if conn.is_connected():
            conn.close()
            return True, "Successfully connected to MySQL Server."
        return False, "Could not establish connection."
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            return False, "Access denied. Check username and password in .env."
        elif err.errno == errorcode.CR_CONN_HOST_ERROR:
            return False, "Cannot connect to MySQL host. Ensure MySQL service is running."
        else:
            return False, f"MySQL connection error: {err}"
    except Exception as e:
        return False, f"Unexpected error connecting to MySQL: {str(e)}"


def initialize_database(schema_path=None, seed_path=None):
    """
    Execute schema and seed data SQL scripts to initialize the database tables.
    """
    from pathlib import Path

    base_dir = Path(__file__).resolve().parent
    schema_path = schema_path or (base_dir / "database" / "schema.sql")
    seed_path = seed_path or (base_dir / "database" / "seed_data.sql")

    logger.info("Initializing database from %s", schema_path)

    # 1. Connect without selecting database to execute CREATE DATABASE
    conn = get_raw_connection(include_database=False)
    cursor = conn.cursor()

    try:
        # Read and run schema.sql
        if Path(schema_path).exists():
            with open(schema_path, "r", encoding="utf-8") as f:
                schema_sql = f.read()

            for statement in schema_sql.split(";"):
                stmt = statement.strip()
                if stmt:
                    cursor.execute(stmt)
            conn.commit()
            logger.info("Database schema initialized successfully.")

        # Read and run seed_data.sql
        if Path(seed_path).exists():
            with open(seed_path, "r", encoding="utf-8") as f:
                seed_sql = f.read()

            for statement in seed_sql.split(";"):
                stmt = statement.strip()
                if stmt:
                    cursor.execute(stmt)
            conn.commit()
            logger.info("Seed data inserted successfully.")

        return True, "Database initialized successfully with schema and seed data."

    except Exception as e:
        conn.rollback()
        logger.error("Failed to initialize database: %s", str(e))
        return False, f"Database initialization failed: {str(e)}"
    finally:
        cursor.close()
        conn.close()


def query_db(query, args=(), one=False, commit=False):
    """
    Convenience function to execute queries safely.
    
    Args:
        query (str): Parameterized SQL query.
        args (tuple/list): Query parameters.
        one (bool): If True, returns a single dictionary row; otherwise a list.
        commit (bool): If True, commits the transaction.
    """
    with get_db_cursor(commit=commit, dictionary=True) as (conn, cursor):
        cursor.execute(query, args)
        if commit:
            return cursor.lastrowid
        res = cursor.fetchall()
        return (res[0] if res else None) if one else res
