import os
import mysql.connector
from mysql.connector import Error
from fastapi import APIRouter
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

load_dotenv()

MYSQL_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'localhost'),
    'port': int(os.getenv('MYSQL_PORT', 3306)),
    'user': os.getenv('MYSQL_USER', 'root'),
    'password': os.getenv('MYSQL_PASSWORD',),
    'database': os.getenv('MYSQL_DATABASE', ),
    'charset': 'utf8mb4',
    'autocommit': True,
    'use_unicode': True,
    'auth_plugin': 'mysql_native_password'
}

mysql_connection = None

def get_mysql_connection():
    global mysql_connection
    try:
        if mysql_connection is None or not mysql_connection.is_connected():
            config = MYSQL_CONFIG.copy()
            if config['host'] == 'localhost':
                config['host'] = '127.0.0.1'
            if not config['password']:
                del config['password']
            mysql_connection = mysql.connector.connect(**config)
    except Error:
        try:
            config = MYSQL_CONFIG.copy()
            config['host'] = '127.0.0.1'
            config['port'] = 3306
            if not config['password']:
                del config['password']
            mysql_connection = mysql.connector.connect(**config)
        except Error:
            mysql_connection = None
    return mysql_connection

def create_database_and_tables():
    try:
        config = MYSQL_CONFIG.copy()
        config['host'] = '127.0.0.1'
        del config['database']
        if not config['password']:
            del config['password']
        conn = mysql.connector.connect(**config)
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {MYSQL_CONFIG['database']}")
        cursor.execute(f"USE {MYSQL_CONFIG['database']}")
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255),
                profile_picture VARCHAR(255),
                email_notifications BOOLEAN DEFAULT TRUE,
                sms_notifications BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INT AUTO_INCREMENT PRIMARY KEY,
                scan_id VARCHAR(255) UNIQUE NOT NULL,
                url TEXT NOT NULL,
                status ENUM('processing', 'completed', 'error') DEFAULT 'processing',
                is_malicious BOOLEAN DEFAULT FALSE,
                threat_level ENUM('low', 'medium', 'high') DEFAULT 'low',
                malicious_count INT DEFAULT 0,
                suspicious_count INT DEFAULT 0,
                total_engines INT DEFAULT 0,
                ssl_valid BOOLEAN DEFAULT FALSE,
                domain_reputation ENUM('clean', 'malicious', 'unknown') DEFAULT 'unknown',
                detection_details JSON,
                user_email VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP NULL,
                scan_timestamp TIMESTAMP NULL,
                INDEX idx_scan_id (scan_id),
                INDEX idx_user_email (user_email),
                INDEX idx_created_at (created_at)
            )
        """)
        
        # Add user_email column to existing scans table if it doesn't exist
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN user_email VARCHAR(255)")
            logger.info("Added user_email column to scans table")
        except Error as e:
            if "Duplicate column name" in str(e):
                logger.info("user_email column already exists in scans table")
            else:
                logger.error(f"Error adding user_email column: {e}")
        
        # Add indexes if they don't exist
        try:
            cursor.execute("CREATE INDEX idx_user_email ON scans(user_email)")
            logger.info("Added user_email index to scans table")
        except Error as e:
            if "Duplicate key name" in str(e):
                logger.info("user_email index already exists")
            else:
                logger.error(f"Error adding user_email index: {e}")
        
        # Create api_keys table for API management
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_email VARCHAR(255) NOT NULL,
                api_key VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255),
                permissions JSON,
                rate_limits JSON,
                webhook_url VARCHAR(500),
                webhook_settings JSON,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP NULL,
                usage_count INT DEFAULT 0,
                INDEX idx_user_email (user_email),
                INDEX idx_api_key (api_key),
                INDEX idx_is_active (is_active)
            )
        """)
        
        # Create export_history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS export_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_email VARCHAR(255) NOT NULL,
                export_type VARCHAR(50) NOT NULL,
                format VARCHAR(10) NOT NULL,
                file_name VARCHAR(255),
                file_path VARCHAR(500),
                file_size INT,
                status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP NULL,
                INDEX idx_user_email (user_email),
                INDEX idx_created_at (created_at),
                INDEX idx_status (status)
            )
        """)
        
        # Create user_settings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_settings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_email VARCHAR(255) UNIQUE NOT NULL,
                notification_preferences JSON,
                api_settings JSON,
                export_settings JSON,
                privacy_settings JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_user_email (user_email)
            )
        """)
        
        # Create reported_urls table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reported_urls (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(2048) NOT NULL,
                reason TEXT,
                added_by VARCHAR(255),
                report_type ENUM('blacklist', 'whitelist') DEFAULT 'blacklist',
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP NULL,
                reviewed_by VARCHAR(255),
                INDEX idx_url (url(255)),
                INDEX idx_status (status),
                INDEX idx_created_at (created_at)
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Database and tables created successfully")
        
    except Error as e:
        logger.error(f"Failed to create database and tables: {e}")

db_router = APIRouter(prefix="/api", tags=["Database"])

async def startup_event():
    import threading
    def init_db():
        try:
            create_database_and_tables()
        except Exception:
            pass
    threading.Thread(target=init_db, daemon=True).start()
