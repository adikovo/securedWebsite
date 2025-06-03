"""
Password Management Utilities for Communication_LTD Secured System
This module provides password policy enforcement, secure password hashing,
password history tracking, and login attempt monitoring for enhanced security.
"""

import json
import re
import hashlib
import hmac
import os
import time
from datetime import datetime, timedelta
import mysql.connector
from mysql.connector import Error

class PasswordPolicy:
    """
    Enforces password complexity requirements and security policies
    Configuration is loaded from config.json file
    """
    def __init__(self):
        # Load password policy configuration from JSON file
        with open('config.json', 'r') as f:
            config = json.load(f)
            self.policy = config['password_policy']

    def validate_password(self, password):
        if not password or len(password) < self.policy['min_length']:
            return False, "Password must be at least {} characters long".format(self.policy['min_length'])

        # Check for uppercase letter requirement
        if self.policy['require_uppercase'] and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"

        # Check for lowercase letter requirement
        if self.policy['require_lowercase'] and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"

        # Check for digit requirement
        if self.policy['require_digits'] and not re.search(r'\d', password):
            return False, "Password must contain at least one digit"

        # Check for special character requirement
        if self.policy['require_special_chars'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"

        # Check if password is in whitelist (allowed weak passwords for testing)
        if password in self.policy['whitelist']:
            return True, "Password is valid"

        return True, "Password is valid"

class PasswordManager:
    """
    Comprehensive Password Management System
    Handles secure password hashing, verification, history tracking,
    login attempt monitoring, and password reset functionality
    """
    def __init__(self):
        self.policy = PasswordPolicy()
        # Database connection configuration from environment variables
        self.db_config = {
            'host': os.getenv('DB_HOST'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_NAME')
        }

    def _get_db_connection(self):
        """
        Establish database connection using configured credentials
        
        """
        try:
            return mysql.connector.connect(**self.db_config)
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            return None

    def hash_password(self, password):
        """
        Generate secure password hash using PBKDF2 with SHA-256

        """
        # Generate cryptographically secure random salt (32 bytes)
        salt = os.urandom(32)
        
        # Use PBKDF2 with SHA-256, 100,000 iterations for security
        key = hashlib.pbkdf2_hmac(
            'sha256',                    # Hash algorithm
            password.encode('utf-8'),    # Password as bytes
            salt,                        # Random salt
            100000                       # Iteration count (security)
        )
        return key.hex(), salt.hex()

    def verify_password(self, stored_password, stored_salt, provided_password):
        """
        Verify provided password against stored hash and salt
       
        """
        # Convert hex salt back to bytes
        salt = bytes.fromhex(stored_salt)
        
        # Hash the provided password with the same salt and parameters
        key = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000
        )
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(key.hex(), stored_password)

    def get_user_id_by_username(self, username):
        """Get user ID by username"""
        conn = self._get_db_connection()
        if not conn:
            return None

        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
            return result[0] if result else None
        except Error as e:
            print(f"Error getting user ID: {e}")
            return None
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    def check_password_history(self, user_identifier, new_password):
        """Check if password was used in the last 3 passwords"""
        conn = self._get_db_connection()
        if not conn:
            return False, "Database connection error"

        try:
            # Convert username to user_id if needed
            if isinstance(user_identifier, str):
                user_id = self.get_user_id_by_username(user_identifier)
                if not user_id:
                    return False, "User not found"
            else:
                user_id = user_identifier

            cursor = conn.cursor()
            # Get recent password history (limited by policy)
            cursor.execute("""
                SELECT password_hash, password_salt 
                FROM password_history 
                WHERE user_id = %s 
                ORDER BY created_at DESC 
                LIMIT %s
            """, (user_id, self.policy.policy['password_history_size']))
            
            # Check if new password matches any recent password
            for stored_hash, stored_salt in cursor.fetchall():
                if self.verify_password(stored_hash, stored_salt, new_password):
                    return False, f"Password has been used recently. Please choose a different password (last {self.policy.policy['password_history_size']} passwords cannot be reused)."
            
            return True, "Password is not in history"
        except Error as e:
            print(f"Database error in check_password_history: {e}")
            return False, f"Database error: {e}"
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    def save_password_to_history(self, user_identifier, password_hash, password_salt):
        """Save current password to history before changing it"""
        conn = self._get_db_connection()
        if not conn:
            return False

        try:
            # Convert username to user_id if needed
            if isinstance(user_identifier, str):
                user_id = self.get_user_id_by_username(user_identifier)
                if not user_id:
                    return False
            else:
                user_id = user_identifier

            cursor = conn.cursor()
            
            # Insert current password into history
            cursor.execute("""
                INSERT INTO password_history (user_id, password_hash, password_salt)
                VALUES (%s, %s, %s)
            """, (user_id, password_hash, password_salt))
            
            # Clean up old password history (keep only recent N passwords)
            cursor.execute("""
                DELETE FROM password_history 
                WHERE user_id = %s 
                AND id NOT IN (
                    SELECT id FROM (
                        SELECT id FROM password_history 
                        WHERE user_id = %s 
                        ORDER BY created_at DESC 
                        LIMIT %s
                    ) AS recent_passwords
                )
            """, (user_id, user_id, self.policy.policy['password_history_size']))
            
            conn.commit()
            return True
        except Error as e:
            print(f"Error saving password to history: {e}")
            return False
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    def record_login_attempt(self, user_id, ip_address):
        """
        Record login attempt for security monitoring and rate limiting
        
        """
        conn = self._get_db_connection()
        if not conn:
            return False

        try:
            cursor = conn.cursor()
            # Insert login attempt with timestamp
            cursor.execute("""
                INSERT INTO login_attempts (user_id, ip_address)
                VALUES (%s, %s)
            """, (user_id, ip_address))
            conn.commit()
            return True
        except Error as e:
            print(f"Error recording login attempt: {e}")
            return False
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    def check_login_attempts(self, user_id):
        """
        Check if user has exceeded maximum login attempts in time window
        Implements rate limiting to prevent brute force attacks
        
        """
        conn = self._get_db_connection()
        if not conn:
            return False, "Database connection error"

        try:
            cursor = conn.cursor()
            # Count login attempts in last 15 minutes
            cursor.execute("""
                SELECT COUNT(*) 
                FROM login_attempts 
                WHERE user_id = %s 
                AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
            """, (user_id,))
            
            attempts = cursor.fetchone()[0]
            # Check against policy limit
            if attempts >= self.policy.policy['max_login_attempts']:
                return False, "Too many login attempts. Please try again later."
            
            return True, "Login attempts within limit"
        except Error as e:
            return False, f"Database error: {e}"
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    def generate_reset_token(self, user_id):
        """
        Generate secure password reset token using SHA-1 hash
        Token expires after 1 hour for security
        
        """
        # Generate random value using SHA-1 as required by project specifications
        token = hashlib.sha1(os.urandom(32)).hexdigest()
        expires_at = datetime.now() + timedelta(hours=1)
        
        conn = self._get_db_connection()
        if not conn:
            return None

        try:
            cursor = conn.cursor()
            # Store token in database with expiration time
            cursor.execute("""
                INSERT INTO password_reset_tokens (user_id, token, expires_at)
                VALUES (%s, %s, %s)
            """, (user_id, token, expires_at))
            conn.commit()
            return token
        except Error as e:
            print(f"Error generating reset token: {e}")
            return None
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    def verify_reset_token(self, token):
        """
        Verify password reset token and check if it's still valid
        
        """
        conn = self._get_db_connection()
        if not conn:
            return None

        try:
            cursor = conn.cursor()
            # Check if token exists and hasn't expired
            cursor.execute("""
                SELECT user_id 
                FROM password_reset_tokens 
                WHERE token = %s 
                AND expires_at > NOW()
            """, (token,))
            
            result = cursor.fetchone()
            if result:
                return result[0]
            return None
        except Error as e:
            print(f"Error verifying reset token: {e}")
            return None
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close() 