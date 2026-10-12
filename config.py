"""
Configuration Module for Bank-to-Bank Suspicious Transaction Detection System.
Loads environment variables safely using python-dotenv.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load .env file if present
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base application configuration class."""

    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", "academic_bca_secure_default_key_replace_in_env")

    # Flask Session settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 3600 * 4  # 4 hours

    # MySQL Database Settings
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "bank_detection_db")

    # Detection Thresholds
    HIGH_AMOUNT_THRESHOLD = float(os.getenv("HIGH_AMOUNT_THRESHOLD", "200000.00"))
    VELOCITY_WINDOW_MINUTES = int(os.getenv("VELOCITY_WINDOW_MINUTES", "15"))
    VELOCITY_COUNT_THRESHOLD = int(os.getenv("VELOCITY_COUNT_THRESHOLD", "3"))
    STRUCTURING_LOWER_BOUND = float(os.getenv("STRUCTURING_LOWER_BOUND", "45000.00"))
    STRUCTURING_UPPER_BOUND = float(os.getenv("STRUCTURING_UPPER_BOUND", "49999.00"))
    RAPID_FORWARD_WINDOW_MINUTES = int(os.getenv("RAPID_FORWARD_WINDOW_MINUTES", "60"))
    CIRCULAR_DEPTH_LIMIT = int(os.getenv("CIRCULAR_DEPTH_LIMIT", "5"))
    SIMILAR_AMOUNT_TOLERANCE_PCT = float(os.getenv("SIMILAR_AMOUNT_TOLERANCE_PCT", "2.0"))

    # File paths
    MODEL_DIR = BASE_DIR / "models"
    DATA_DIR = BASE_DIR / "data"
    MODEL_PATH = MODEL_DIR / "suspicious_transaction_model.joblib"
    FEATURE_NAMES_PATH = MODEL_DIR / "model_features.joblib"


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    """Testing configuration using isolated or mock environment."""
    DEBUG = False
    TESTING = True
    DB_NAME = "bank_detection_test_db"
