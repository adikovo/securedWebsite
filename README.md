# Communication_LTD Secured Information System

A secured web app for managing users and customer data for a telecom company, featuring password policy enforcement, login tracking, reset via email, and protection from XSS & SQLi.

## Architecture Overview

- **Frontend**: Flask (Python) web application with secure templates
- **Backend**: Node.js/Express API server for database operations
- **Database**: MySQL with security features and audit trails
- **Security**: PBKDF2 password hashing, login attempt tracking, password history, email-based password reset

## Complete Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/adikovo/securedWebsite.git
cd securedWebsite
```

### 2. Database Setup

#### Setting Up the MySQL Database  
1.To run the system locally, you need a MySQL database. Follow these steps:  
2.Make sure MySQL is installed on your machine.  
3.Open your preferred MySQL client (e.g., MySQL Workbench, phpMyAdmin, or DBeaver).   
4.Create a new database named communication_ltd_secure (or any name you prefer).  
5.Import the provided secure_database.sql file into the database.  
6.Edit the .env file in the project root and update the database credentials to match your local MySQL setup.  

### 3. Environment Configuration

#### Create Environment File (.env)
Create a `.env` file in the root directory:
```env
# Database Configuration
DB_HOST=localhost
DB_USER=comm_user
DB_PASSWORD=SecurePass123!
DB_NAME=communication_ltd_secure

# Email Configuration (REPLACE WITH YOUR DETAILS)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com     # Replace with your Gmail address
MAIL_PASSWORD=your-app-password        # Replace with your Gmail App Password

# Security Settings (GENERATE YOUR OWN)
FLASK_SECRET_KEY=your-secret-key-here  # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
```

#### Gmail App Password Setup
1. Go to [Google App Passwords](https://myaccount.google.com/apppasswords)
2. Select **"Mail"** as the app
3. Select **"Other"** as the device
4. Enter name: `Communication_LTD_System`
5. Copy the generated 16-character password to `MAIL_PASSWORD`

### 4. Backend (Node.js) Setup

#### Install Dependencies
   ```bash
   npm install
   ```

#### Required Node.js Packages
The system uses these key packages:
- `express` - Web framework
- `mysql2` - MySQL database driver
- `cors` - Cross-origin resource sharing
- `body-parser` - Request body parsing
- `crypto` - Cryptographic functions

#### Start Backend Server
   ```bash
   npm start
   ```
**Backend runs on**: `http://localhost:3000`

### 5. Frontend (Flask) Setup

#### Install Python Dependencies
```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install required packages
pip install flask requests mysql-connector-python python-dotenv
```

#### Required Python Packages
- `flask` - Web framework
- `requests` - HTTP client for backend communication
- `mysql-connector-python` - MySQL database connector
- `python-dotenv` - Environment variable loading

#### Start Flask Application
```bash
python app.py
```
**Frontend runs on**: `http://localhost:5001`
`

## System Features

### Security Features
- **PBKDF2 Password Hashing**: 100,000 iterations with SHA-256
- **Password History**: Prevents reuse of last 3 passwords
- **Login Rate Limiting**: 3 attempts per 15-minute window
- **Password Reset Tokens**: SHA-1 tokens with 1-hour expiration
- **Input Sanitization**: XSS prevention on all user inputs
- **Session Management**: Secure Flask sessions
- **Audit Logging**: Comprehensive security event tracking

### User Management
- **User Registration**: With password confirmation
- **Secure Login**: Multi-factor validation
- **Password Change**: With current password verification
- **Password Reset**: Email-based token system
- **Session Handling**: Automatic logout and security

### Customer Management
- **Add Customers**: Name, email, address, package type
- **Search Customers**: By name with partial matching
- **List All Customers**: Complete customer database view
- **Data Validation**: Input sanitization and validation

## API Endpoints

### Authentication Endpoints
- `POST /register` - User registration
- `POST /login` - User authentication
- `POST /verify-password` - Password verification
- `POST /change-password` - Password update
- `POST /generate-reset-token` - Password reset request
- `POST /reset-password` - Password reset completion

### Customer Management Endpoints
- `POST /add-customer` - Add new customer
- `GET /search-customer?name=query` - Search customers
- `GET /list-customers` - List all customers

### Utility Endpoints
- `POST /get-user-password` - Get user password details (for history)

## Database Schema

### Core Tables
- **users**: User accounts with hashed passwords
- **customers**: Customer information and packages
- **password_history**: Historical password tracking
- **login_attempts**: Security monitoring and rate limiting
- **password_reset_tokens**: Secure password reset system

### Security Tables
- **login_attempts**: IP tracking and attempt monitoring
- **password_history**: Prevents password reuse
- **password_reset_tokens**: Time-limited reset authorization

## Running the Complete System

### Start All Services
```bash
# Terminal 1: Start MySQL (if not running as service)
sudo systemctl start mysql

# Terminal 2: Start Node.js Backend
npm start

# Terminal 3: Start Flask Frontend
python app.py
```

### Access the Application
1. Open browser to `http://localhost:5001`
2. Register a new account or login with existing credentials
3. Use the system dashboard for customer management

## Security Testing

### Test Password Policy
- Try passwords shorter than 10 characters
- Test without uppercase, lowercase, digits, or special characters
- Verify password history enforcement

### Test Rate Limiting
- Make 3 failed login attempts
- Verify 4th attempt is blocked (even with correct password)
- Wait 15 minutes and verify access is restored

### Test Password Reset
- Request password reset via email
- Verify token expiration (1 hour)
- Test token reuse prevention
