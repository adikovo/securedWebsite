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


load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(32)  # Generate a secure random key

# Node.js backend URL
BACKEND_URL = 'http://localhost:3000'

# Initialize password manager
password_manager = PasswordManager()

def send_email(recipient_email, subject, body):
    msg = MIMEText(body, "html")
    msg['Subject'] = subject
    msg['From'] = os.getenv('MAIL_USERNAME')
    msg['To'] = recipient_email

    with smtplib.SMTP(os.getenv('MAIL_SERVER'), int(os.getenv('MAIL_PORT'))) as server:
        server.starttls()
        server.login(os.getenv('MAIL_USERNAME'), os.getenv('MAIL_PASSWORD'))
        server.send_message(msg)

def sanitize_input(input_str):
    # Remove any potentially dangerous characters
   #return re.sub(r'[<>"\']', '', input_str)
       return html.escape(input_str)

def validate_input(username, password, email=None):
    if not username or not password or (email and not email):
        return False, "All fields are required"
    
    username = sanitize_input(username)
    password = sanitize_input(password)
    if email:
        email = sanitize_input(email)
    
    return True, (username, password, email) if email else (username, password)

# Home route (redirect to login)
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        email = sanitize_input(request.form['email'])
        password = request.form['password']

        # בדיקת קלט בסיסית
        is_valid, result = validate_input(username, password)
        if not is_valid:
            flash(result)
            return render_template('register.html')

        # hash + salt
        password_hash, password_salt = password_manager.hash_password(password)

        try:
            # שליחת הנתונים ל-Node.js
            r = requests.post(f'{BACKEND_URL}/register', json={
                'username': username,
                'email': email,
                'password': password_hash,
                'password_salt': password_salt
            })

            if r.status_code == 200:
                flash('Registration successful. Please log in.')
                return redirect(url_for('login'))
            else:
                error = r.json().get('error', 'Registration failed.')
                flash(error)
        except Exception as e:
            print('[REGISTER ERROR]', e)
            flash('Could not connect to backend.')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        password = request.form['password']
        
        # Validate input
        is_valid, result = validate_input(username, password)
        if not is_valid:
            flash(result)
            return render_template('login.html')

        username, password = result

        try:
            # קבלת פרטי המשתמש מה־Node (hash + salt)
            r = requests.post(f'{BACKEND_URL}/login', json={'username': username})

            if r.status_code == 200:
                user_data = r.json()
                stored_hash = user_data['password']
                stored_salt = user_data['password_salt']
                user_id = user_data['id']

                # אימות הסיסמה
                if password_manager.verify_password(stored_hash, stored_salt, password):
                    password_manager.record_login_attempt(user_id, request.remote_addr)
                    session['username'] = username
                    return redirect(url_for('system'))
                else:
                    password_manager.record_login_attempt(user_id, request.remote_addr)
                    flash('Invalid username or password')
            else:
                flash('Invalid username or password')

        except Exception as e:
            print(f"[ERROR] Login error: {e}")
            flash('Could not connect to backend.')

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        email = sanitize_input(email)

        if not email:
            flash('Email is required')
            return render_template('forgot_password.html')

        try:
            # קריאה ל-Node.js כדי ליצור טוקן איפוס סיסמה
            r = requests.post(f'{BACKEND_URL}/generate-reset-token', json={'email': email})
            if r.status_code == 200:
                token = r.json().get('token')
                reset_link = url_for('reset_password', token=token, _external=True)

                # שלח את הקישור למייל – אבל לצורך בדיקה נציג אותו במסך
            #    //flash(f'Password reset link (dev only): {reset_link}')
                send_email(email, "Reset your password", f"Click here to reset your password: {reset_link}")
                flash("Password reset link was sent to your email.")
                return redirect(url_for('login'))
            else:
                flash(r.json().get('error', 'Could not generate reset token.'))
        except Exception as e:
            print("[ERROR in forgot-password]", e)
            flash('An error occurred. Please try again.')

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['new_password']
        new_password = sanitize_input(new_password)
        
        # Validate password against policy
        is_valid, message = password_manager.policy.validate_password(new_password)
        if not is_valid:
            flash(message)
            return render_template('reset_password.html')
        
        # Verify token and get user_id
        user_id = password_manager.verify_reset_token(token)
        if not user_id:
            flash('Invalid or expired reset token.')
            return redirect(url_for('login'))
        
        # Check password history
        is_allowed, message = password_manager.check_password_history(user_id, new_password)
        if not is_allowed:
            flash(message)
            return render_template('reset_password.html')
        
        # Hash new password
        password_hash, password_salt = password_manager.hash_password(new_password)
        
        try:
            r = requests.post(f'{BACKEND_URL}/reset-password', json={
                'user_id': user_id,
                'password': password_hash,
                'password_salt': password_salt
            })
            if r.status_code == 200:
                flash('Password has been reset successfully.')
                return redirect(url_for('login'))
            else:
                flash('Failed to reset password.')
        except Exception as e:
            flash('Could not connect to backend.')
    return render_template('reset_password.html')

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    username = session.get('username')
    if not username:
        flash('You must be logged in to change your password.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        
        # Validate input
        is_valid, result = validate_input(username, current_password)
        if not is_valid:
            flash(result)
            return render_template('change_password.html')
        
        current_password, new_password = result[1], sanitize_input(new_password)
        
        # Validate new password against policy
        is_valid, message = password_manager.policy.validate_password(new_password)
        if not is_valid:
            flash(message)
            return render_template('change_password.html')
        
        try:
            # Verify current password
            r = requests.post(f'{BACKEND_URL}/verify-password', json={
                'username': username,
                'password': current_password
            })
            
            if r.status_code == 200:
                # Check password history
                is_allowed, message = password_manager.check_password_history(username, new_password)
                if not is_allowed:
                    flash(message)
                    return render_template('change_password.html')
                
                # Hash new password
                password_hash, password_salt = password_manager.hash_password(new_password)
                
                # Update password
                r = requests.post(f'{BACKEND_URL}/change-password', json={
                    'username': username,
                    'password': password_hash,
                    'password_salt': password_salt
                })
                
                if r.status_code == 200:
                    flash('Password changed successfully!')
                    return redirect(url_for('system'))
                else:
                    flash('Failed to change password.')
            else:
                flash('Current password is incorrect.')
        except Exception as e:
            flash('Could not connect to backend.')
    return render_template('change_password.html')

@app.route('/system', methods=['GET', 'POST'])
def system():
    if 'username' not in session:
        return redirect(url_for('login'))
    customer_name = None
    if request.method == 'POST':
        name = sanitize_input(request.form['name'])
        email = sanitize_input(request.form['email'])
        address = sanitize_input(request.form['address'])
        package_type = sanitize_input(request.form['package_type'])
        
        if not all([name, email, address, package_type]):
            flash('All fields are required')
            return render_template('system.html')
        
        try:
            r = requests.post(f'{BACKEND_URL}/add-customer', json={
                'name': name,
                'email': email,
                'address': address,
                'package_type': package_type
            })
            if r.status_code == 200:
                customer_name = name
            else:
                flash(r.json().get('error', 'Failed to add customer.'))
        except Exception as e:
            flash('Could not connect to backend.')
    return render_template('system.html', customer_name=customer_name)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True) 


