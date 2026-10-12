"""
Database Setup Script for BCA Final Year Project.
Connects to MySQL, creates the database 'bank_detection_db',
and loads schema tables and seed data.

Usage:
    python init_db.py
"""

import sys
import getpass
from config import Config
import database as db


def main():
    print("=" * 65)
    print("Bank-to-Bank Suspicious Transaction Detection System")
    print("Database Initialization Utility")
    print("=" * 65)
    print(f"Target Host: {Config.DB_HOST}:{Config.DB_PORT}")
    print(f"Target User: {Config.DB_USER}")
    print(f"Database:    {Config.DB_NAME}")
    print("-" * 65)

    # Test connection
    connected, msg = db.test_db_connection()
    if not connected:
        print(f"Warning: Connection check failed ({msg}).")
        print("\nIf your MySQL 'root' password is not set in .env:")
        pwd = input("Enter your MySQL root password (or press Enter if blank): ")
        Config.DB_PASSWORD = pwd

    try:
        print("Creating database and tables from database/schema.sql & seed_data.sql...")
        success, message = db.initialize_database()
        if success:
            print("\nSUCCESS!")
            print(message)
            print("-" * 65)
            print("Default Demo Accounts Created:")
            print("  1. Administrator:   username: 'admin'   | password: 'Admin@123'")
            print("  2. AML Analyst:     username: 'analyst' | password: 'Analyst@123'")
            print("=" * 65)
        else:
            print("\nError during initialization:", message)
            sys.exit(1)
    except Exception as e:
        print("\nInitialization encountered an exception:", str(e))
        print("Please verify that MySQL Server service is running and credentials in .env are correct.")
        sys.exit(1)


if __name__ == "__main__":
    main()
