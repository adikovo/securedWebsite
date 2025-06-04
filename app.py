"""
Flask Frontend Application for Communication_LTD Secured System
This is the main web interface that handles user authentication, password management,
and customer data entry. It communicates with a Node.js backend for database operations.

"""

from flask import Flask, render_template, request, redirect, url_for, flash, session
import requests
import mysql.connector
from mysql.connector import Error
from password_utils import PasswordManager
import re
import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import html

# Color codes for console output
class Colors:
    RESET = '\033[0m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(32)  # Generate a secure random key

# Node.js backend URL
BACKEND_URL = 'http://localhost:3000'

# Initialize password manager
password_manager = PasswordManager()

def send_email(recipient_email, subject, body):
    """
    Send email using SMTP configuration from environment variables
    Used for password reset functionality
    
    """
    msg = MIMEText(body, "html")
    msg['Subject'] = subject
    msg['From'] = os.getenv('MAIL_USERNAME')
    msg['To'] = recipient_email

    # Connect to SMTP server and send email
    with smtplib.SMTP(os.getenv('MAIL_SERVER'), int(os.getenv('MAIL_PORT'))) as server:
        server.starttls()
        server.login(os.getenv('MAIL_USERNAME'), os.getenv('MAIL_PASSWORD'))
        server.send_message(msg)

def sanitize_input(input_str):
    # Remove any potentially dangerous characters
    return html.escape(input_str)

def validate_input(username, password, email=None):
    if not username or not password or (email and not email):
        return False, "All fields are required"
    
    # Sanitize inputs to prevent XSS
    username = sanitize_input(username)
    password = sanitize_input(password)
    if email:
        email = sanitize_input(email)
    
    return True, (username, password, email) if email else (username, password)

# Home route (redirect to login)
@app.route('/')
def home():
    return redirect(url_for('login'))

#user registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data and sanitize inputs
        username = sanitize_input(request.form['username'])
        email = sanitize_input(request.form['email'])
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return render_template('register.html')

        # Basic input validation
        is_valid, result = validate_input(username, password)
        if not is_valid:
            flash(result, 'error')
            return render_template('register.html')

        # Generate secure password hash with salt using PBKDF2
        password_hash, password_salt = password_manager.hash_password(password)

        try:
            # Send data to Node.js backend for database storage
            r = requests.post(f'{BACKEND_URL}/register', json={
                'username': username,
                'email': email,
                'password': password_hash,
                'password_salt': password_salt
            })

            if r.status_code == 200:
                # Save initial password to history after successful registration
                password_manager.save_password_to_history(username, password_hash, password_salt)
                print(f"{Colors.GREEN}[FLASK SUCCESS] User '{username}' registered and password saved to history{Colors.RESET}")
                flash('Registration successful. Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                error = r.json().get('error', 'Registration failed.')
                print(f"{Colors.RED}[FLASK ERROR] Registration failed for user '{username}': {error}{Colors.RESET}")
                flash(error, 'error')
        except Exception as e:
            print(f"{Colors.RED}[FLASK ERROR] Registration error: {e}{Colors.RESET}")
            flash('Could not connect to backend.', 'error')

    return render_template('register.html')

#user login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        password = request.form['password']
        
        # Validate input data
        is_valid, result = validate_input(username, password)
        if not is_valid:
            flash(result, 'error')
            return render_template('login.html')

        username, password = result

        try:
            # Get user details from Node.js backend (hash + salt for verification)
            r = requests.post(f'{BACKEND_URL}/login', json={'username': username})

            if r.status_code == 200:
                # User exists, check rate limiting BEFORE password verification
                user_data = r.json()
                stored_hash = user_data['password']
                stored_salt = user_data['password_salt']
                user_id = user_data['id']

                # Check if user has exceeded login attempts
                is_allowed, rate_limit_message = password_manager.check_login_attempts(user_id)
                if not is_allowed:
                    print(f"{Colors.YELLOW}[FLASK WARNING] Rate limited login attempt for user '{username}'{Colors.RESET}")
                    flash(rate_limit_message, 'error')
                    return render_template('login.html')

                # Verify password
                if password_manager.verify_password(stored_hash, stored_salt, password):
                    # Successful login - record attempt and create session
                    password_manager.record_login_attempt(user_id, request.remote_addr)
                    session['username'] = username
                    print(f"{Colors.GREEN}[FLASK SUCCESS] User '{username}' logged in successfully{Colors.RESET}")
                    return redirect(url_for('system'))
                else:
                    # Failed login - record attempt for security monitoring
                    password_manager.record_login_attempt(user_id, request.remote_addr)
                    print(f"{Colors.YELLOW}[FLASK WARNING] Invalid password attempt for user '{username}'{Colors.RESET}")
                    flash('Invalid username or password', 'error')
            else:
                # User doesn't exist
                print(f"{Colors.YELLOW}[FLASK WARNING] Login attempt for non-existent user '{username}'{Colors.RESET}")
                flash('Invalid username or password', 'error')

        except Exception as e:
            print(f"{Colors.RED}[FLASK ERROR] Login error: {e}{Colors.RESET}")
            flash('Could not connect to backend.', 'error')

    return render_template('login.html')

#forgot password route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        email = sanitize_input(email)

        # Validate email input
        if not email:
            flash('Email is required', 'error')
            return render_template('forgot_password.html')

        try:
            # Call Node.js to generate password reset token
            r = requests.post(f'{BACKEND_URL}/generate-reset-token', json={'email': email})
            if r.status_code == 200:
                # Token generated successfully
                token = r.json().get('token')
                reset_link = url_for('reset_password', token=token, _external=True)

                # Send the reset link via email
                send_email(email, "Reset your password", f"Click here to reset your password: {reset_link}")
                print(f"{Colors.GREEN}[FLASK SUCCESS] Password reset email sent to '{email}'{Colors.RESET}")
                flash("Password reset link was sent to your email.", 'success')
                return redirect(url_for('login'))
            else:
                # Failed to generate token (email not found, etc.)
                error_msg = r.json().get('error', 'Could not generate reset token.')
                print(f"{Colors.RED}[FLASK ERROR] Failed to generate reset token for '{email}': {error_msg}{Colors.RESET}")
                flash(error_msg, 'error')
        except Exception as e:
            print(f"{Colors.RED}[FLASK ERROR] Forgot password error: {e}{Colors.RESET}")
            flash('An error occurred. Please try again.', 'error')

    return render_template('forgot_password.html')

#reset password route
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        new_password = sanitize_input(new_password)
        confirm_password = sanitize_input(confirm_password)
        
        # Check if passwords match
        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return render_template('reset_password.html')
        
        # Validate password against policy
        is_valid, message = password_manager.policy.validate_password(new_password)
        if not is_valid:
            flash(message, 'error')
            return render_template('reset_password.html')
        
        # Verify token and get user_id
        user_id = password_manager.verify_reset_token(token)
        if not user_id:
            print(f"{Colors.YELLOW}[FLASK WARNING] Invalid or expired reset token used{Colors.RESET}")
            flash('Invalid or expired reset token.', 'error')
            return redirect(url_for('login'))
        
        # Check password history to prevent reuse
        is_allowed, message = password_manager.check_password_history(user_id, new_password)
        if not is_allowed:
            print(f"{Colors.YELLOW}[FLASK WARNING] Password history violation for user ID '{user_id}'{Colors.RESET}")
            flash(message, 'warning')
            return render_template('reset_password.html')
        
        try:
            # Get current password details to save to history
            r = requests.post(f'{BACKEND_URL}/get-user-password', json={'user_id': user_id})
            if r.status_code == 200:
                user_data = r.json()
                current_hash = user_data['password']
                current_salt = user_data['password_salt']
                
                # Save current password to history before resetting
                password_manager.save_password_to_history(user_id, current_hash, current_salt)
            
            # Hash new password with secure salt
            password_hash, password_salt = password_manager.hash_password(new_password)
            
            # Update password in database via backend
            r = requests.post(f'{BACKEND_URL}/reset-password', json={
                'user_id': user_id,
                'password': password_hash,
                'password_salt': password_salt
            })
            if r.status_code == 200:
                print(f"{Colors.GREEN}[FLASK SUCCESS] Password reset successfully for user ID '{user_id}'{Colors.RESET}")
                flash('Password has been reset successfully.', 'success')
                return redirect(url_for('login'))
            else:
                print(f"{Colors.RED}[FLASK ERROR] Failed to reset password for user ID '{user_id}'{Colors.RESET}")
                flash('Failed to reset password.', 'error')
        except Exception as e:
            print(f"{Colors.RED}[FLASK ERROR] Reset password error: {e}{Colors.RESET}")
            flash('Could not connect to backend.', 'error')
    return render_template('reset_password.html')

#change password route
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    username = session.get('username')
    if not username:
        flash('You must be logged in to change your password.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        
        # Validate input
        is_valid, result = validate_input(username, current_password)
        if not is_valid:
            flash(result, 'error')
            return render_template('change_password.html')
        
        current_password, new_password = result[1], sanitize_input(new_password)
        
        # Validate new password against policy
        is_valid, message = password_manager.policy.validate_password(new_password)
        if not is_valid:
            flash(message, 'error')
            return render_template('change_password.html')
        
        try:
            # Verify current password and get current password details
            r = requests.post(f'{BACKEND_URL}/verify-password', json={
                'username': username,
                'password': current_password
            })
            
            if r.status_code == 200:
                # Current password is correct
                user_data = r.json()
                current_hash = user_data['password']
                current_salt = user_data['password_salt']
                
                # Save current password to history before changing
                password_manager.save_password_to_history(username, current_hash, current_salt)
                
                # Hash new password
                password_hash, password_salt = password_manager.hash_password(new_password)
                # Check password history to prevent reuse
                is_allowed, message = password_manager.check_password_history(username, new_password)
                if not is_allowed:
                    print(f"{Colors.YELLOW}[FLASK WARNING] Password history violation for user '{username}'{Colors.RESET}")
                    flash(message, 'warning')
                    return render_template('change_password.html')
                
                
                # Update password in database
                r = requests.post(f'{BACKEND_URL}/change-password', json={
                    'username': username,
                    'password': password_hash,
                    'password_salt': password_salt
                })
                
                if r.status_code == 200:
                    print(f"{Colors.GREEN}[FLASK SUCCESS] Password changed successfully for user '{username}'{Colors.RESET}")
                    flash('Password changed successfully!', 'success')
                    return redirect(url_for('system'))
                else:
                    print(f"{Colors.RED}[FLASK ERROR] Failed to change password for user '{username}'{Colors.RESET}")
                    flash('Failed to change password.', 'error')
            else:
                # Current password is incorrect
                print(f"{Colors.YELLOW}[FLASK WARNING] Incorrect current password for user '{username}'{Colors.RESET}")
                flash('Current password is incorrect.', 'error')
        except Exception as e:
            print(f"{Colors.RED}[FLASK ERROR] Change password error: {e}{Colors.RESET}")
            flash('Could not connect to backend.', 'error')
    return render_template('change_password.html')

#system dashboard route
@app.route('/system', methods=['GET', 'POST'])
def system():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    customer_name = None
    customers = []
    
    if request.method == 'POST':
        # Add new customer
        name = sanitize_input(request.form['name'])
        email = sanitize_input(request.form['email'])
        address = sanitize_input(request.form['address'])
        package_type = sanitize_input(request.form['package_type'])
        
        # Validate all required fields are provided
        if not all([name, email, address, package_type]):
            flash('All fields are required', 'error')
            return render_template('system.html')
        
        try:
            # Send customer data to backend for storage
            r = requests.post(f'{BACKEND_URL}/add-customer', json={
                'name': name,
                'email': email,
                'address': address,
                'package_type': package_type
            })
            if r.status_code == 200:
                customer_name = name
                print(f"{Colors.GREEN}[FLASK SUCCESS] Customer '{name}' added successfully{Colors.RESET}")
            else:
                error_msg = r.json().get('error', 'Failed to add customer.')
                print(f"{Colors.RED}[FLASK ERROR] Failed to add customer '{name}': {error_msg}{Colors.RESET}")
                flash(error_msg, 'error')
        except Exception as e:
            print(f"{Colors.RED}[FLASK ERROR] Add customer error: {e}{Colors.RESET}")
            flash('Could not connect to backend.', 'error')

    elif request.method == 'GET':
        # Handle customer search and list operations
        action = request.args.get('action')
        if action == 'search':
            # Search for customers by name
            query = sanitize_input(request.args.get('query', ''))
            try:
                r = requests.get(f'{BACKEND_URL}/search-customer', params={'name': query})
                if r.status_code == 200:
                    customers = r.json().get('customers', [])
                else:
                    flash("No customer found.")
            except Exception as e:
                flash("Error fetching search results.")

        elif action == 'list':
            # List all customers
            try:
                r = requests.get(f'{BACKEND_URL}/list-customers')
                if r.status_code == 200:
                    customers = r.json().get('customers', [])
                else:
                    flash("Could not fetch customer list.")
            except Exception as e:
                flash("Error connecting to backend.")

    return render_template('system.html', customer_name=customer_name, customers=customers)

#user logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5001) 


