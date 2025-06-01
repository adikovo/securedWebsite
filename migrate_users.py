import mysql.connector
from mysql.connector import Error
from password_utils import PasswordManager
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def migrate_users():
    # Database configuration from .env
    db_config = {
        'host': os.getenv('DB_HOST'),
        'user': os.getenv('DB_USER'),
        'password': os.getenv('DB_PASSWORD'),
        'database': os.getenv('DB_NAME')
    }
    # Initialize password manager
    password_manager = PasswordManager()

    try:
        # Connect to database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Get all users
        cursor.execute("SELECT id, username, password FROM users")
        users = cursor.fetchall()

        for user_id, username, old_password in users:
            # Generate new salt and hash for existing password
            new_hash, new_salt = password_manager.hash_password(old_password)

            # Update user with new salt
            cursor.execute("""
                UPDATE users 
                SET password = %s, password_salt = %s 
                WHERE id = %s
            """, (new_hash, new_salt, user_id))

            # Add to password history
            cursor.execute("""
                INSERT INTO password_history (user_id, password_hash, password_salt)
                VALUES (%s, %s, %s)
            """, (user_id, new_hash, new_salt))

        # Commit changes
        conn.commit()
        print("Successfully migrated users to new secure system")

    except Error as e:
        print(f"Error migrating users: {e}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

if __name__ == "__main__":
    migrate_users() 