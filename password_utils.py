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
        with open('config.json', 'r') as f:
            config = json.load(f)
            self.policy = config['password_policy']

    def validate_password(self, password):
        if not password or len(password) < self.policy['min_length']:
            return False, "Password must be at least {} characters long".format(self.policy['min_length'])

        if self.policy['require_uppercase'] and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"

        if self.policy['require_lowercase'] and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"

        if self.policy['require_digits'] and not re.search(r'\d', password):
            return False, "Password must contain at least one digit"

        if self.policy['require_special_chars'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"

        # Check against blacklist of common weak passwords
        if 'password_blacklist' in self.policy and password in self.policy['password_blacklist']:
            return False, "This password is too common and predictable. Please choose a more unique password."

        return True, "Password is valid"

class PasswordManager:
    
    def __init__(self):
        self.policy = PasswordPolicy()
        self.db_config = {
            'host': os.getenv('DB_HOST'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_NAME')
        }

    def _get_db_connection(self):
        try:
            return mysql.connector.connect(**self.db_config)
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            return None
    #Generate secure password hash using PBKDF2 with SHA-256
    def hash_password(self, password):
        
        salt = os.urandom(32)
        
        # Use PBKDF2 with SHA-256
        key = hashlib.pbkdf2_hmac(
            'sha256',                    
            password.encode('utf-8'),    
            salt,                        
            100000                       
        )
        return key.hex(), salt.hex()

    def verify_password(self, stored_password, stored_salt, provided_password):
    
        salt = bytes.fromhex(stored_salt)
        
        # Hash the provided password with the same salt and parameters
        key = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000
        )
        
        return hmac.compare_digest(key.hex(), stored_password)

    def get_user_id_by_username(self, username):
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


    #check if password was used in the last 3 passwords
    def check_password_history(self, user_identifier, new_password):

        conn = self._get_db_connection()
        if not conn:
            return False, "Database connection error"

        try:
            if isinstance(user_identifier, str):
                user_id = self.get_user_id_by_username(user_identifier)
                if not user_id:
                    return False, "User not found"
            else:
                user_id = user_identifier

            cursor = conn.cursor()
            cursor.execute("""
                SELECT password_hash, password_salt 
                FROM password_history 
                WHERE user_id = %s 
                ORDER BY created_at DESC 
                LIMIT %s
            """, (user_id, self.policy.policy['password_history_size']))
            
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
        conn = self._get_db_connection()
        if not conn:
            return False

        try:
            if isinstance(user_identifier, str):
                user_id = self.get_user_id_by_username(user_identifier)
                if not user_id:
                    return False
            else:
                user_id = user_identifier

            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO password_history (user_id, password_hash, password_salt)
                VALUES (%s, %s, %s)
            """, (user_id, password_hash, password_salt))
            
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

    #record login attempt for security monitoring and rate limiting
    def record_login_attempt(self, user_id, ip_address):

        conn = self._get_db_connection()
        if not conn:
            return False

        try:
            cursor = conn.cursor()
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

    #check if user has exceeded maximum login attempts in time window
    def check_login_attempts(self, user_id):
        
        conn = self._get_db_connection()
        if not conn:
            return False, "Database connection error"

        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) 
                FROM login_attempts 
                WHERE user_id = %s 
                AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
            """, (user_id,))
            
            attempts = cursor.fetchone()[0]
            if attempts >= self.policy.policy['max_login_attempts']:
                return False, "Too many login attempts. Please try again later."
            
            return True, "Login attempts within limit"
        except Error as e:
            return False, f"Database error: {e}"
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    #generate secure password reset token using SHA-1 hash
    def generate_reset_token(self, user_id):
        
        token = hashlib.sha1(os.urandom(32)).hexdigest()
        expires_at = datetime.now() + timedelta(hours=1)
        
        conn = self._get_db_connection()
        if not conn:
            return None

        try:
            cursor = conn.cursor()
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
                user_id = result[0]
                
                # Delete the token immediately after verification (one-time use)
                cursor.execute("""
                    DELETE FROM password_reset_tokens 
                    WHERE token = %s
                """, (token,))
                conn.commit()
                
                print(f"Reset token used and deleted for user ID: {user_id}")
                return user_id
            return None
        except Error as e:
            print(f"Error verifying reset token: {e}")
            return None
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    def cleanup_expired_tokens(self):
        
        conn = self._get_db_connection()
        if not conn:
            return False

        try:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM password_reset_tokens 
                WHERE expires_at <= NOW()
            """)
            deleted_count = cursor.rowcount
            conn.commit()
            
            if deleted_count > 0:
                print(f"Cleaned up {deleted_count} expired reset tokens")
            return True
        except Error as e:
            print(f"Error cleaning up expired tokens: {e}")
            return False
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close() 